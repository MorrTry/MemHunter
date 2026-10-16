#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "memory/memory_source.hpp"

namespace mh {

// The longest x86/x64 instruction Windows allows.
inline constexpr std::size_t kMaxInstructionBytes = 15;

struct Instruction {
    std::uint64_t address = 0;
    std::vector<std::byte> bytes;
    // "mov rax, [rbx+0x10]", or "db 0xCC" for a byte that does not decode.
    std::string text;
    std::string mnemonic;
    bool valid = true;
    // The absolute address a jump or call leads to; set only for a relative branch.
    std::uint64_t target = 0;
    bool has_target = false;

    std::uint64_t end() const noexcept { return address + bytes.size(); }
};

struct DisasmOptions {
    // Decode as 32-bit code, for a WOW64 process.
    bool wow64 = false;
};

// Decodes up to `count` instructions from `address`, reading the bytes from `memory`. Stops early when the memory
// stops being readable; a byte that does not decode becomes one `db` instruction so that decoding can go on.
std::vector<Instruction> disassemble(const MemorySource& memory, std::uint64_t address, std::size_t count,
                                     const DisasmOptions& options = {});

// Decodes the instructions that start within [address, address + size).
std::vector<Instruction> disassemble_range(const MemorySource& memory, std::uint64_t address, std::uint64_t size,
                                           const DisasmOptions& options = {});

}  // namespace mh
