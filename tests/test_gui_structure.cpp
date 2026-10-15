#include <gtest/gtest.h>

#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <string_view>

#include "common/text.hpp"
#include "gui/session.hpp"
#include "gui/struct_table.hpp"
#include "support/fake_memory.hpp"
#include "support/fake_target.hpp"

namespace mh::gui {
namespace {

using mh::testing::FakeMemory;
using mh::testing::FakeTarget;
using namespace std::chrono_literals;

template <typename T>
void put(FakeMemory& memory, std::uint64_t address, T value) {
    std::memcpy(memory.bytes_at(address, sizeof(T)).data(), &value, sizeof(T));
}

void put_text(FakeMemory& memory, std::uint64_t address, std::string_view text) {
    std::memcpy(memory.bytes_at(address, text.size()).data(), text.data(), text.size());
}

bool contains(std::string_view text, std::string_view part) {
    return text.find(part) != std::string_view::npos;
}

PointerPath path(std::string_view text) {
    return *parse_pointer_path(text, 8);
}

// game.exe+0x1080 -> world, world+0x8 -> player, world+0x10 -> another player, player+0x80 -> inventory.
class StructView : public ::testing::Test {
protected:
    static constexpr std::uint64_t kGame = 0x140000000;
    static constexpr std::uint64_t kHeap = 0x200000;
    static constexpr std::uint64_t kWorld = kHeap + 0x400;
    static constexpr std::uint64_t kPlayer = kHeap + 0x1000;
    static constexpr std::uint64_t kInventory = kHeap + 0x2000;
    static constexpr std::uint64_t kOther = kHeap + 0x3000;
    static constexpr std::string_view kBase = "[[game.exe+0x1080]+0x8]";

    FakeMemory memory;
    StructTable table;
    // The table row() and describe() look at.
    StructTable* shown = &table;
    StructTable::Clock::time_point t0 = StructTable::Clock::time_point{} + 1h;

    void SetUp() override {
        memory.add_image(kGame, 0x2000, "C:\\Games\\game.exe");
        memory.add(kHeap, 0x10000);
        put<std::uint64_t>(memory, kGame + 0x1080, kWorld);
        put<std::uint64_t>(memory, kWorld + 0x8, kPlayer);
        put<std::uint64_t>(memory, kWorld + 0x10, kOther);
        player(kPlayer, 86);
        player(kOther, 50);
        put<std::int32_t>(memory, kInventory, 3);
        put<float>(memory, kInventory + 4, 1.5f);
        table.set_regions(memory.query_regions());
    }

    void player(std::uint64_t at, std::int32_t health) {
        put_text(memory, at, "PLR1");
        put<std::uint32_t>(memory, at + 0x04, 1);
        put_text(memory, at + 0x08, "Stalker_Ivan");
        put<std::int32_t>(memory, at + 0x50, health);
        put<std::int32_t>(memory, at + 0x54, 100);
        put<float>(memory, at + 0x68, 102.5f);
        put<std::uint64_t>(memory, at + 0x80, kInventory);
        put<std::uint64_t>(memory, at + 0x88, kGame + 0x1010);
    }

    std::size_t row(std::uint32_t offset, std::uint32_t node_depth = 0) const {
        const auto& rows = shown->rows();
        for (std::size_t i = 0; i < rows.size(); ++i) {
            if (rows[i].field.offset == offset && rows[i].depth == node_depth) {
                return i;
            }
        }
        ADD_FAILURE() << "no row at " << format_hex(offset);
        return rows.size();
    }

    std::string describe(std::uint32_t depth = 0) const {
        std::string text;
        for (const StructRow& r : shown->rows()) {
            if (r.depth == depth) {
                text += format_hex(r.field.offset) + " " + field_type_name(r.field) + (r.field.name.empty() ? "" : " " + r.field.name) + "\n";
            }
        }
        return text;
    }
};

TEST_F(StructView, OpensAtAChainAndSelectsTheField) {
    table.open(path(kBase), 0xA0, 0x50);
    EXPECT_TRUE(table.active());
    EXPECT_EQ(format_struct_base(table.base()), kBase);
    EXPECT_FALSE(table.selected());
    EXPECT_TRUE(table.due(t0, 500ms));

    table.refresh(memory, t0);
    EXPECT_FALSE(table.due(t0 + 100ms, 500ms));
    EXPECT_TRUE(table.due(t0 + 500ms, 500ms));
    EXPECT_EQ(table.address(0), kPlayer);
    EXPECT_EQ(describe(),
              "0x0 ascii[4]\n0x4 int32\n0x8 ascii[16]\n0x18 bytes[56]\n0x50 int32\n0x54 int32\n0x58 bytes[16]\n0x68 float\n"
              "0x6C bytes[20]\n0x80 pointer\n0x88 pointer\n0x90 bytes[16]\n");
    ASSERT_TRUE(table.selected());
    EXPECT_EQ(table.selected()->field.offset, 0x50u);
    EXPECT_EQ(table.value_text(row(0x50), 0), "86");
    EXPECT_EQ(table.value_text(row(0x8), 0), "\"Stalker_Ivan\"");
    EXPECT_EQ(table.value_text(row(0x88), 0), "game.exe+0x1010");
    EXPECT_EQ(table.field_address(row(0x50), 0), kPlayer + 0x50);
    EXPECT_EQ(table.path_text(row(0x50), 0), "[[game.exe+0x1080]+0x8]+0x50");
}

TEST_F(StructView, MarksChangedFieldsForTwoSeconds) {
    table.open(path(kBase), 0xA0);
    table.refresh(memory, t0);
    EXPECT_FALSE(table.recently_changed(row(0x50), 0, t0));
    put<std::int32_t>(memory, kPlayer + 0x50, 80);
    table.refresh(memory, t0 + 1s);
    EXPECT_TRUE(table.recently_changed(row(0x50), 0, t0 + 1s));
    EXPECT_FALSE(table.recently_changed(row(0x54), 0, t0 + 1s));
    EXPECT_EQ(table.value_text(row(0x50), 0), "80");
    table.refresh(memory, t0 + 2500ms);
    EXPECT_TRUE(table.recently_changed(row(0x50), 0, t0 + 2500ms));
    table.refresh(memory, t0 + 3500ms);
    EXPECT_FALSE(table.recently_changed(row(0x50), 0, t0 + 3500ms));
}

TEST_F(StructView, FollowsTheChainWhenTheStructureMoves) {
    table.open(path(kBase), 0xA0);
    table.refresh(memory, t0);
    const std::string before = describe();
    player(kHeap + 0x5000, 61);
    put<std::uint64_t>(memory, kWorld + 0x8, kHeap + 0x5000);
    table.refresh(memory, t0 + 1s);
    EXPECT_EQ(table.address(0), kHeap + 0x5000);
    EXPECT_EQ(describe(), before);
    EXPECT_EQ(table.value_text(row(0x50), 0), "61");
    EXPECT_TRUE(table.recently_changed(row(0x50), 0, t0 + 1s));
    EXPECT_FALSE(table.recently_changed(row(0x54), 0, t0 + 1s));
}

TEST_F(StructView, AChainThatLeadsNowhereShowsUnknownBytesUntilItIsFound) {
    put<std::uint64_t>(memory, kWorld + 0x8, 0);
    table.open(path(kBase), 0xA0, 0x50);
    table.refresh(memory, t0);
    EXPECT_EQ(table.address(0), std::nullopt);
    EXPECT_EQ(describe(), "0x0 bytes[160]\n");
    EXPECT_EQ(table.value_text(0, 0), "??");
    EXPECT_EQ(table.field_address(0, 0), std::nullopt);

    put<std::uint64_t>(memory, kWorld + 0x8, kPlayer);
    table.refresh(memory, t0 + 500ms);
    EXPECT_EQ(table.address(0), kPlayer);
    ASSERT_TRUE(table.selected());
    EXPECT_EQ(table.selected()->field.offset, 0x50u);
    EXPECT_EQ(table.value_text(row(0x50), 0), "86");
}

TEST_F(StructView, UnreadablePagesStayUnknown) {
    memory.fail_page(kHeap + 0x2000);
    table.open(PointerPath{{}, kHeap + 0x1FC0, {}, 8}, 0x80);
    table.refresh(memory, t0);
    EXPECT_EQ(describe(), "0x0 bytes[64]\n0x40 bytes[64]\n");
    EXPECT_EQ(table.value_text(row(0x0), 0), "00 × 64");
    EXPECT_EQ(table.value_text(row(0x40), 0), "??");
}

TEST_F(StructView, DefinedFieldsReplaceTheGuessesTheyCover) {
    table.open(path(kBase), 0xA0);
    table.refresh(memory, t0);
    ASSERT_TRUE(table.editable(row(0x50)));
    EXPECT_TRUE(table.define(0x50, FieldType::Int32, 0, "health"));
    EXPECT_TRUE(table.define(0x18, FieldType::Int64, 0, "experience"));
    EXPECT_TRUE(table.rename(row(0x8), "name"));
    EXPECT_EQ(describe(),
              "0x0 ascii[4]\n0x4 int32\n0x8 ascii[16] name\n0x18 int64 experience\n0x20 bytes[48]\n0x50 int32 health\n0x54 int32\n"
              "0x58 bytes[16]\n0x68 float\n0x6C bytes[20]\n0x80 pointer\n0x88 pointer\n0x90 bytes[16]\n");
    EXPECT_EQ(table.definition().fields.size(), 3u);
    EXPECT_TRUE(table.definition().fields[0].defined);
    EXPECT_EQ(table.definition().fields[0].name, "name");

    EXPECT_TRUE(table.define(0x4C, FieldType::Int64, 0, "wide"));
    EXPECT_TRUE(contains(describe(), "0x4C int64 wide\n0x54 int32\n"));
    EXPECT_EQ(table.definition().fields.size(), 3u);

    table.forget(row(0x4C));
    EXPECT_TRUE(contains(describe(), "0x50 int32\n"));
    EXPECT_FALSE(contains(describe(), "wide"));

    EXPECT_FALSE(table.define(0x90, FieldType::Bytes, 0, "nothing"));
    EXPECT_TRUE(table.define(0x90, FieldType::Bytes, 0x100, "tail"));
    EXPECT_EQ(table.size(), 0x190u);
    table.set_size(0x20);
    EXPECT_EQ(table.size(), 0x190u);

    const std::string c = table.c_declaration();
    EXPECT_TRUE(contains(c, "    char name[16];  // 0x8\n    int64_t experience;  // 0x18\n    char pad_0020[0x70];\n")) << c;
    EXPECT_TRUE(contains(c, "    uint8_t tail[256];  // 0x90\n};  // 0x190\n")) << c;
}

TEST_F(StructView, WholeLayoutIsDeclaredWhileNothingIsDefined) {
    table.open(path(kBase), 0xA0);
    table.refresh(memory, t0);
    const std::string c = table.c_declaration();
    EXPECT_TRUE(contains(c, "    int32_t field_0050;  // 0x50\n")) << c;
    EXPECT_TRUE(contains(c, "    void* field_0080;  // 0x80\n")) << c;
}

TEST_F(StructView, PointersOpenAsATree) {
    table.open(path(kBase), 0xA0);
    table.refresh(memory, t0);
    const std::size_t pointer = row(0x80);
    EXPECT_TRUE(table.expandable(pointer));
    EXPECT_FALSE(table.expandable(row(0x50)));
    table.toggle(pointer);
    EXPECT_TRUE(table.expanded(pointer));
    EXPECT_TRUE(table.due(t0 + 1ms, 500ms));
    table.refresh(memory, t0 + 1ms);
    EXPECT_EQ(describe(1), "0x0 int32\n0x4 float\n0x8 bytes[248]\n");
    EXPECT_EQ(table.rows()[row(0x80) + 1].depth, 1u);
    EXPECT_EQ(table.rows()[row(0x80) + 1].field.offset, 0u);
    EXPECT_EQ(table.value_text(row(0x4, 1), 0), "1.5");
    EXPECT_FALSE(table.editable(row(0x4, 1)));
    EXPECT_EQ(table.path_text(row(0x4, 1), 0), "[[[game.exe+0x1080]+0x8]+0x80]+0x4");
    EXPECT_EQ(table.field_address(row(0x4, 1), 0), kInventory + 4);

    table.toggle(row(0x80));
    EXPECT_EQ(describe(1), "");
    table.toggle(row(0x80));
    table.refresh(memory, t0 + 2ms);
    EXPECT_TRUE(table.define(0x80, FieldType::Int64, 0, "not a pointer"));
    EXPECT_EQ(describe(1), "");
}

TEST_F(StructView, DissectingAPointerMakesItTheStructure) {
    table.open(path(kBase), 0xA0);
    ASSERT_TRUE(table.add_instance(path("[[game.exe+0x1080]+0x10]")));
    table.refresh(memory, t0);
    EXPECT_TRUE(table.define(0x50, FieldType::Int32, 0, "health"));
    EXPECT_FALSE(table.dissect(row(0x50)));
    ASSERT_TRUE(table.dissect(row(0x80)));
    EXPECT_EQ(format_struct_base(table.base()), "[[[game.exe+0x1080]+0x8]+0x80]");
    EXPECT_EQ(format_struct_base(table.instance(1)), "[[[game.exe+0x1080]+0x10]+0x80]");
    EXPECT_EQ(table.instances(), 2u);
    EXPECT_TRUE(table.definition().fields.empty());
    EXPECT_EQ(table.size(), kDefaultStructSize);
    table.refresh(memory, t0 + 1s);
    EXPECT_EQ(table.address(0), kInventory);
    EXPECT_EQ(table.value_text(row(0x0), 0), "3");
}

TEST_F(StructView, InstancesAreComparedSideBySide) {
    table.open(path(kBase), 0xA0);
    EXPECT_TRUE(table.add_instance(path("[[game.exe+0x1080]+0x10]")));
    EXPECT_FALSE(table.add_instance(path(kBase)));
    table.refresh(memory, t0);
    EXPECT_EQ(table.instances(), 2u);
    EXPECT_EQ(table.value_text(row(0x50), 1), "50");
    EXPECT_TRUE(table.differs(row(0x50)));
    EXPECT_FALSE(table.differs(row(0x54)));
    EXPECT_FALSE(table.differs(row(0x0)));
    EXPECT_EQ(table.path_text(row(0x50), 1), "[[game.exe+0x1080]+0x10]+0x50");

    EXPECT_TRUE(table.add_instance(PointerPath{{}, kHeap + 0x6000, {}, 8}));
    EXPECT_TRUE(table.add_instance(PointerPath{{}, kHeap + 0x7000, {}, 8}));
    EXPECT_FALSE(table.add_instance(PointerPath{{}, kHeap + 0x8000, {}, 8}));
    table.refresh(memory, t0 + 1s);
    EXPECT_EQ(table.value_text(row(0x50), 3), "0");

    table.remove_instance(0);
    EXPECT_EQ(table.instances(), 4u);
    table.remove_instance(1);
    EXPECT_EQ(table.instances(), 3u);
    EXPECT_EQ(table.instance(1), (PointerPath{{}, kHeap + 0x6000, {}, 8}));
    EXPECT_EQ(table.value_text(row(0x50), 1), "0");
}

TEST_F(StructView, FieldsBecomeWatchEntries) {
    table.open(path(kBase), 0xA0);
    table.refresh(memory, t0);
    WatchEntry entry = table.watch_entry(row(0x50), 0);
    EXPECT_EQ(entry.type, WatchType::Int32);
    EXPECT_EQ(entry.address, kPlayer + 0x50);
    EXPECT_EQ(entry.description, "+0x50");
    ASSERT_TRUE(entry.path);
    EXPECT_EQ(format_pointer_path(*entry.path), "[[game.exe+0x1080]+0x8]+0x50");

    EXPECT_TRUE(table.rename(row(0x50), "health"));
    EXPECT_EQ(table.watch_entry(row(0x50), 0).description, "health");
    EXPECT_EQ(table.watch_entry(row(0x80), 0).type, WatchType::Int64);
    entry = table.watch_entry(row(0x8), 0);
    EXPECT_EQ(entry.type, WatchType::Ascii);
    EXPECT_EQ(entry.length, 16u);

    table.open(PointerPath{{}, kPlayer, {}, 8}, 0xA0);
    table.refresh(memory, t0);
    entry = table.watch_entry(row(0x50), 0);
    EXPECT_FALSE(entry.path);
    EXPECT_EQ(entry.address, kPlayer + 0x50);
    EXPECT_EQ(table.path_text(row(0x50), 0), format_address(kPlayer + 0x50));
}

TEST(StructStarts, TheChainOfAFieldLosesItsLastOffset) {
    WatchEntry entry = make_watch_entry(0x201050, WatchType::Int32);
    entry.path = path("[[game.exe+0x1080]+0x8]+0x50");
    StructStart start = struct_start(entry, 8);
    EXPECT_EQ(format_struct_base(start.base), "[[game.exe+0x1080]+0x8]");
    EXPECT_EQ(start.focus, 0x50u);

    entry.path = path("game.exe+0x1080");
    start = struct_start(entry, 4);
    EXPECT_EQ(format_struct_base(start.base), "game.exe+0x1080");
    EXPECT_EQ(start.base.pointer_size, 4u);
    EXPECT_EQ(start.focus, 0u);

    entry.path = path("[game.exe+0x1080]+0x20000");
    start = struct_start(entry, 8);
    EXPECT_EQ(format_struct_base(start.base), "[game.exe+0x1080]+0x20000");
    EXPECT_EQ(start.focus, 0u);

    entry.path.reset();
    start = struct_start(entry, 8);
    EXPECT_EQ(start.base, (PointerPath{{}, 0x201050, {}, 8}));
    EXPECT_EQ(field_type(WatchType::Double), FieldType::Double);
    EXPECT_EQ(field_type(WatchType::Utf16), FieldType::Utf16);
}

class StructSession : public StructView {
protected:
    Session session;
    std::filesystem::path dir = std::filesystem::temp_directory_path() / L"memhunter-gui-struct-тест";

    void SetUp() override {
        StructView::SetUp();
        std::filesystem::remove_all(dir);
        std::filesystem::create_directories(dir);
        session.attach(std::make_unique<FakeTarget>(memory));
        shown = &session.structure();
    }
    void TearDown() override { std::filesystem::remove_all(dir); }
};

TEST_F(StructSession, OpensReadsAndAddsFieldsToTheWatchList) {
    StructField health{0x50, FieldType::Int32, 0, "health", true};
    ASSERT_TRUE(session.open_structure(path(kBase), 0xA0, 0x50, health));
    StructTable& s = session.structure();
    EXPECT_EQ(s.address(0), kPlayer);
    EXPECT_FALSE(session.notice().error);
    ASSERT_TRUE(s.selected());
    EXPECT_EQ(s.selected()->field.name, "health");
    EXPECT_EQ(s.value_text(*s.selected_row(), 0), "86");

    EXPECT_TRUE(session.add_struct_watch(*s.selected_row(), 0));
    EXPECT_FALSE(session.add_struct_watch(*s.selected_row(), 0));
    ASSERT_EQ(session.watch().rows().size(), 1u);
    EXPECT_EQ(session.watch().rows()[0].description, "health");
    EXPECT_TRUE(session.watch().rows()[0].path);
}

TEST_F(StructSession, ANewRunOfTheProgramKeepsChainsOnly) {
    ASSERT_TRUE(session.open_structure(path(kBase), 0xA0));
    ASSERT_TRUE(session.structure().add_instance(PointerPath{{}, kOther, {}, 8}));
    session.attach(std::make_unique<FakeTarget>(memory, 5555, "fake.exe"));
    ASSERT_TRUE(session.structure().active());
    EXPECT_EQ(session.structure().instances(), 1u);
    EXPECT_EQ(session.structure().value_text(0, 0), "");
    session.refresh_structure(t0);
    EXPECT_EQ(session.structure().address(0), kPlayer);

    session.attach(std::make_unique<FakeTarget>(memory, 5555, "fake.exe"));
    EXPECT_TRUE(session.structure().active());
    ASSERT_TRUE(session.open_structure(PointerPath{{}, kPlayer, {}, 8}, 0xA0));
    session.attach(std::make_unique<FakeTarget>(memory, 6666, "fake.exe"));
    EXPECT_FALSE(session.structure().active());

    ASSERT_TRUE(session.open_structure(path(kBase), 0xA0));
    session.attach(std::make_unique<FakeTarget>(memory, 7777, "other.exe"));
    EXPECT_FALSE(session.structure().active());
}

TEST_F(StructSession, SavesAndLoadsTheDefinition) {
    const auto file = dir / L"игрок.mhst";
    EXPECT_FALSE(session.save_structure(file));
    ASSERT_TRUE(session.open_structure(path(kBase), 0xA0));
    EXPECT_FALSE(session.save_structure(file));
    EXPECT_TRUE(session.notice().error);
    StructTable& s = session.structure();
    ASSERT_TRUE(s.define(0x50, FieldType::Int32, 0, "health"));
    ASSERT_TRUE(s.rename(row(0x8), "name"));
    ASSERT_TRUE(session.save_structure(file));
    EXPECT_TRUE(contains(session.notice().text, "игрок.mhst")) << session.notice().text;

    ASSERT_TRUE(session.open_structure(path(kBase), 0xA0));
    EXPECT_TRUE(s.definition().fields.empty());
    ASSERT_TRUE(session.load_structure(file));
    EXPECT_EQ(s.definition().fields.size(), 2u);
    EXPECT_TRUE(contains(describe(), "0x8 ascii[16] name\n"));
    EXPECT_TRUE(contains(describe(), "0x50 int32 health\n"));
    EXPECT_EQ(s.value_text(row(0x50), 0), "86");

    std::ofstream(dir / "bad.mhst") << "size 0x100\n0x50 int33 health\n";
    EXPECT_FALSE(session.load_structure(dir / "bad.mhst"));
    EXPECT_TRUE(session.notice().error);
    EXPECT_TRUE(contains(session.notice().text, "line 2")) << session.notice().text;
    EXPECT_EQ(s.definition().fields.size(), 2u);
    EXPECT_FALSE(session.load_structure(dir / "missing.mhst"));
    EXPECT_TRUE(session.notice().error);
}

TEST_F(StructSession, AChainThatLeadsNowhereIsReported) {
    put<std::uint64_t>(memory, kWorld + 0x8, 0);
    ASSERT_TRUE(session.open_structure(path(kBase), 0xA0));
    EXPECT_TRUE(session.notice().error);
    EXPECT_TRUE(contains(session.notice().text, std::string(kBase))) << session.notice().text;
}

}  // namespace
}  // namespace mh::gui
