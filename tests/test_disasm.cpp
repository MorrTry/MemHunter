#include <gtest/gtest.h>

#include <cstdint>
#include <initializer_list>
#include <span>

#include "disasm/disassembler.hpp"
#include "support/fake_memory.hpp"

namespace mh {
namespace {

using testing::FakeMemory;

constexpr std::uint64_t kBase = 0x140001000;

// FakeMemory holds atomics and cannot be moved, so the region is filled in place.
void make_code(FakeMemory& mem, std::initializer_list<std::uint8_t> bytes) {
    mem.add(kBase, FakeMemory::kPage, page::ExecuteRead, MemType::Image);
    const std::span<std::byte> span = mem.bytes_at(kBase, bytes.size());
    std::size_t i = 0;
    for (std::uint8_t byte : bytes) {
        span[i++] = std::byte{byte};
    }
}

TEST(Disassembler, DecodesSimpleInstructions) {
    FakeMemory mem;
    make_code(mem, {0x48, 0x89, 0xD8, 0x90, 0xC3});  // mov rax, rbx; nop; ret
    const auto out = disassemble(mem, kBase, 3);
    ASSERT_EQ(out.size(), 3u);
    EXPECT_EQ(out[0].address, kBase);
    EXPECT_EQ(out[0].mnemonic, "mov");
    EXPECT_EQ(out[0].text, "mov rax, rbx");
    EXPECT_EQ(out[0].bytes.size(), 3u);
    EXPECT_TRUE(out[0].valid);
    EXPECT_EQ(out[1].mnemonic, "nop");
    EXPECT_EQ(out[1].address, kBase + 3);
    EXPECT_EQ(out[2].mnemonic, "ret");
    EXPECT_EQ(out[2].address, kBase + 4);
}

TEST(Disassembler, StopsAtRequestedCount) {
    FakeMemory mem;
    make_code(mem, {0x90, 0x90, 0x90, 0x90, 0x90});
    EXPECT_EQ(disassemble(mem, kBase, 2).size(), 2u);
}

TEST(Disassembler, ResolvesRelativeJumpTarget) {
    FakeMemory mem;
    make_code(mem, {0xEB, 0x05});  // jmp +5
    const auto out = disassemble(mem, kBase, 1);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0].mnemonic, "jmp");
    EXPECT_TRUE(out[0].has_target);
    EXPECT_EQ(out[0].target, kBase + 2 + 5);
}

TEST(Disassembler, ResolvesCallTarget) {
    FakeMemory mem;
    make_code(mem, {0xE8, 0x00, 0x00, 0x00, 0x00});  // call to the next instruction
    const auto out = disassemble(mem, kBase, 1);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0].mnemonic, "call");
    EXPECT_TRUE(out[0].has_target);
    EXPECT_EQ(out[0].target, kBase + 5);
}

TEST(Disassembler, UndecodableByteBecomesDb) {
    FakeMemory mem;
    make_code(mem, {0x06, 0x90});  // 0x06 does not decode in 64-bit mode, then nop
    const auto out = disassemble(mem, kBase, 2);
    ASSERT_EQ(out.size(), 2u);
    EXPECT_FALSE(out[0].valid);
    EXPECT_EQ(out[0].mnemonic, "db");
    EXPECT_EQ(out[0].bytes.size(), 1u);
    EXPECT_EQ(out[0].text, "db 0x06");
    EXPECT_EQ(out[1].mnemonic, "nop");
    EXPECT_EQ(out[1].address, kBase + 1);
}

TEST(Disassembler, DecodesThirtyTwoBitInWow64Mode) {
    FakeMemory mem;
    make_code(mem, {0x55});  // push
    DisasmOptions options;
    options.wow64 = true;
    const auto out = disassemble(mem, kBase, 1, options);
    ASSERT_EQ(out.size(), 1u);
    EXPECT_EQ(out[0].text, "push ebp");
    // The same byte is a 64-bit push in long mode.
    EXPECT_EQ(disassemble(mem, kBase, 1).front().text, "push rbp");
}

TEST(Disassembler, StopsAtUnreadableMemory) {
    FakeMemory mem;
    make_code(mem, {0x90, 0x90});
    EXPECT_TRUE(disassemble(mem, kBase + FakeMemory::kPage, 4).empty());
}

TEST(Disassembler, RangeStopsAtEndAddress) {
    FakeMemory mem;
    make_code(mem, {0x90, 0x90, 0x90, 0x90});
    const auto out = disassemble_range(mem, kBase, 2);  // the two nops that start within [base, base + 2)
    ASSERT_EQ(out.size(), 2u);
    EXPECT_EQ(out.back().address, kBase + 1);
}

}  // namespace
}  // namespace mh
