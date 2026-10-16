#include "disasm/disassembler.hpp"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <optional>

namespace mh {

namespace {

std::string lower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

// Reads at most `want` bytes from `address`, returning the readable prefix (possibly empty).
std::vector<std::byte> read_window(const MemorySource& memory, std::uint64_t address, std::size_t want) {
    std::vector<std::byte> buffer(want);
    const ReadResult result = memory.read(address, buffer);
    buffer.resize(result.bytes);
    return buffer;
}

// The absolute target of a relative branch or call, if the instruction has one.
std::optional<std::uint64_t> branch_target(const ZydisDecodedInstruction& instruction, const ZydisDecodedOperand* operands,
                                            std::uint64_t address) {
    const ZydisInstructionCategory category = instruction.meta.category;
    if (category != ZYDIS_CATEGORY_CALL && category != ZYDIS_CATEGORY_COND_BR && category != ZYDIS_CATEGORY_UNCOND_BR) {
        return std::nullopt;
    }
    for (std::size_t i = 0; i < instruction.operand_count_visible; ++i) {
        if (operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operands[i].imm.is_relative) {
            ZyanU64 result = 0;
            if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&instruction, &operands[i], address, &result))) {
                return result;
            }
        }
    }
    return std::nullopt;
}

}  // namespace

std::vector<Instruction> disassemble(const MemorySource& memory, std::uint64_t address, std::size_t count,
                                     const DisasmOptions& options) {
    std::vector<Instruction> result;
    if (count == 0) {
        return result;
    }

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, options.wow64 ? ZYDIS_MACHINE_MODE_LEGACY_32 : ZYDIS_MACHINE_MODE_LONG_64,
                     options.wow64 ? ZYDIS_STACK_WIDTH_32 : ZYDIS_STACK_WIDTH_64);
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    std::uint64_t at = address;
    while (result.size() < count) {
        const std::vector<std::byte> window = read_window(memory, at, kMaxInstructionBytes);
        if (window.empty()) {
            break;
        }
        ZydisDecodedInstruction instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        Instruction out;
        out.address = at;
        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, window.data(), window.size(), &instruction, operands))) {
            out.bytes.assign(window.begin(), window.begin() + instruction.length);
            char buffer[256];
            if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&formatter, &instruction, operands,
                                                             instruction.operand_count_visible, buffer, sizeof(buffer), at,
                                                             ZYAN_NULL))) {
                out.text = buffer;
            }
            out.mnemonic = lower(ZydisMnemonicGetString(instruction.mnemonic));
            if (const auto target = branch_target(instruction, operands, at)) {
                out.target = *target;
                out.has_target = true;
            }
        } else {
            // One undecodable byte, so that the next instruction still lines up.
            out.bytes.assign(window.begin(), window.begin() + 1);
            char byte[8];
            std::snprintf(byte, sizeof(byte), "0x%02X", static_cast<unsigned>(std::to_integer<unsigned char>(window[0])));
            out.text = std::string("db ") + byte;
            out.mnemonic = "db";
            out.valid = false;
        }
        at = out.end();
        result.push_back(std::move(out));
    }
    return result;
}

std::vector<Instruction> disassemble_range(const MemorySource& memory, std::uint64_t address, std::uint64_t size,
                                           const DisasmOptions& options) {
    std::vector<Instruction> result;
    const std::uint64_t stop = address + size;
    std::uint64_t at = address;
    while (at < stop) {
        std::vector<Instruction> one = disassemble(memory, at, 1, options);
        if (one.empty()) {
            break;
        }
        at = one.front().end();
        result.push_back(std::move(one.front()));
    }
    return result;
}

}  // namespace mh
