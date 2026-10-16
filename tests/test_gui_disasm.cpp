#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>

#include "gui/disasm_table.hpp"
#include "gui/session.hpp"
#include "support/fake_memory.hpp"
#include "support/fake_target.hpp"
#include "support/language_guard.hpp"

namespace mh::gui {
namespace {

using mh::testing::FakeMemory;
using mh::testing::FakeTarget;
using mh::testing::LanguageGuard;

constexpr std::uint64_t kBase = 0x140000000;

DisasmLine line(std::uint64_t address) {
    DisasmLine row;
    row.address = address;
    return row;
}

TEST(GuiDisasm, CountsInRussian) {
    LanguageGuard ru{Lang::Russian};
    EXPECT_EQ(count_instructions(0), "0 инструкций");
    EXPECT_EQ(count_instructions(1), "1 инструкция");
    EXPECT_EQ(count_instructions(3), "3 инструкции");
    EXPECT_EQ(count_instructions(5), "5 инструкций");
    EXPECT_EQ(count_instructions(11), "11 инструкций");
    EXPECT_EQ(count_instructions(14), "14 инструкций");
    EXPECT_EQ(count_instructions(21), "21 инструкция");
    EXPECT_EQ(count_instructions(112), "112 инструкций");
}

TEST(GuiDisasm, TableSelectsAndNavigates) {
    DisasmTable table;
    EXPECT_FALSE(table.has_result());
    EXPECT_TRUE(table.rows().empty());
    EXPECT_EQ(table.selected(), nullptr);

    table.assign(kBase, false, {line(kBase), line(kBase + 1), line(kBase + 2)});
    ASSERT_TRUE(table.has_result());
    EXPECT_EQ(table.address(), kBase);
    EXPECT_FALSE(table.wow64());
    ASSERT_EQ(table.rows().size(), 3u);
    ASSERT_NE(table.selected(), nullptr);
    EXPECT_EQ(table.selected()->address, kBase);

    table.move_selection(10);
    EXPECT_EQ(table.selected_row(), 2u);
    table.move_selection(-1);
    EXPECT_EQ(table.selected_row(), 1u);
    table.select_row(7);  // out of range, ignored
    EXPECT_EQ(table.selected_row(), 1u);

    table.assign(kBase, true, {});
    EXPECT_TRUE(table.has_result());
    EXPECT_TRUE(table.wow64());
    EXPECT_TRUE(table.rows().empty());
    EXPECT_EQ(table.selected(), nullptr);

    table.clear();
    EXPECT_FALSE(table.has_result());
    EXPECT_EQ(table.address(), 0u);
}

TEST(GuiDisasm, NeedsAProcess) {
    Session session;
    EXPECT_FALSE(session.disassemble(kBase, 4));
    EXPECT_TRUE(session.notice().error);
}

TEST(GuiDisasm, DecodesCodeAndAnnotatesBranchTarget) {
    FakeMemory memory;
    const std::span<std::byte> code = memory.add_image(kBase, 0x1000, "game.exe", 0, page::ExecuteRead);
    // mov rax, rbx; call kBase+0x100; ret
    const std::uint8_t bytes[] = {0x48, 0x89, 0xD8, 0xE8, 0xF8, 0x00, 0x00, 0x00, 0xC3};
    for (std::size_t i = 0; i < sizeof(bytes); ++i) {
        code[i] = std::byte{bytes[i]};
    }

    Session session;
    session.attach(std::make_unique<FakeTarget>(memory, 100, "game.exe"));
    ASSERT_TRUE(session.disassemble(kBase, 3));

    const DisasmTable& table = session.disasm();
    ASSERT_TRUE(table.has_result());
    EXPECT_FALSE(table.wow64());
    ASSERT_EQ(table.rows().size(), 3u);
    EXPECT_EQ(table.rows()[0].address, kBase);
    EXPECT_EQ(table.rows()[0].text, "mov rax, rbx");
    EXPECT_EQ(table.rows()[0].bytes, "48 89 D8");
    EXPECT_EQ(table.rows()[0].size, 3u);
    EXPECT_FALSE(table.rows()[0].has_target);

    EXPECT_TRUE(table.rows()[1].text.starts_with("call 0x")) << table.rows()[1].text;
    EXPECT_TRUE(table.rows()[1].has_target);
    EXPECT_EQ(table.rows()[1].target_address, kBase + 0x100);
    EXPECT_EQ(table.rows()[1].target, "game.exe+0x100");

    EXPECT_EQ(table.rows()[2].text, "ret");
    EXPECT_EQ(table.selected_row(), 0u);
    EXPECT_FALSE(session.notice().error);
}

TEST(GuiDisasm, SaysWhenNothingCanBeRead) {
    LanguageGuard ru{Lang::Russian};
    FakeMemory memory;
    memory.add(kBase, 0x1000, page::ReadWrite);
    Session session;
    session.attach(std::make_unique<FakeTarget>(memory, 100, "game.exe"));

    EXPECT_FALSE(session.disassemble(kBase + 0x100000, 4));  // outside any region
    EXPECT_TRUE(session.disasm().has_result());
    EXPECT_TRUE(session.disasm().rows().empty());
    EXPECT_TRUE(session.notice().error);
    EXPECT_NE(session.notice().text.find("нечего читать"), std::string::npos) << session.notice().text;
}

}  // namespace
}  // namespace mh::gui
