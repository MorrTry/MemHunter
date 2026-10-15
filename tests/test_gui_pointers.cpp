#include <gtest/gtest.h>

#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <string_view>
#include <thread>

#include "common/text.hpp"
#include "gui/pointer_list.hpp"
#include "gui/session.hpp"
#include "gui/watch_list.hpp"
#include "support/fake_memory.hpp"
#include "support/fake_target.hpp"

namespace mh::gui {
namespace {

using mh::testing::FakeMemory;
using mh::testing::FakeTarget;
using namespace std::chrono_literals;

void put(FakeMemory& memory, std::uint64_t address, std::uint64_t value, unsigned size = 8) {
    std::memcpy(memory.bytes_at(address, size).data(), &value, size);
}

bool contains(std::string_view text, std::string_view part) {
    return text.find(part) != std::string_view::npos;
}

// game.exe holds S1 -> A and S2 -> B, the heap holds A+0x20 -> B and the int32 at B+0x30.
struct Layout {
    std::uint64_t game;
    std::uint64_t heap;

    std::uint64_t s1() const { return game + 0x1010; }
    std::uint64_t s2() const { return game + 0x1020; }
    std::uint64_t a() const { return heap + 0x4000; }
    std::uint64_t b() const { return heap + 0x8000; }
    std::uint64_t target() const { return b() + 0x30; }

    void build(FakeMemory& memory) const {
        memory.add_image(game, 0x1000, "C:\\Games\\game.exe", 0, page::ReadOnly);
        memory.add_image(game + 0x1000, 0x1000, "C:\\Games\\game.exe", game);
        memory.add(heap, 0x10000);
        put(memory, s1(), a());
        put(memory, a() + 0x20, b());
        put(memory, s2(), b());
        put(memory, target(), 100, 4);
    }
};

constexpr Layout kGame{0x140000000, 0x200000};
// The same program started again: everything lies elsewhere, and S2 is not set.
constexpr Layout kRestarted{0x150000000, 0x300000};

PointerPath long_path() {
    return {"game.exe", 0x1010, {0x20, 0x30}, 8};
}

PointerPath short_path() {
    return {"game.exe", 0x1020, {0x30}, 8};
}

WatchEntry path_entry(PointerPath path, std::string description = {}) {
    WatchEntry entry = make_watch_entry(0, WatchType::Int32, 0, std::move(description));
    entry.path = std::move(path);
    return entry;
}

TEST(GuiWatchPaths, PathEntryFollowsItsChain) {
    FakeMemory memory;
    kGame.build(memory);
    WatchList list;
    list.set_regions(memory.query_regions());
    ASSERT_TRUE(list.add(path_entry(long_path())));
    EXPECT_EQ(list.address_text(0), "P->??");
    list.refresh(memory, 0, 1, WatchList::Clock::now());
    EXPECT_EQ(list.rows()[0].address, kGame.target());
    EXPECT_TRUE(list.resolved(0));
    EXPECT_EQ(list.address_text(0), "P->" + format_address(kGame.target()));
    EXPECT_EQ(list.value_text(0), "100");
    EXPECT_EQ(list.module(0), "");

    const std::uint64_t moved = kGame.heap + 0xA000;
    put(memory, moved + 0x30, 250, 4);
    put(memory, kGame.a() + 0x20, moved);
    const auto now = WatchList::Clock::now();
    list.refresh(memory, 0, 1, now);
    EXPECT_EQ(list.rows()[0].address, moved + 0x30);
    EXPECT_EQ(list.value_text(0), "250");
    EXPECT_TRUE(list.recently_changed(0, now));
}

TEST(GuiWatchPaths, BrokenChainShowsQuestionMarks) {
    FakeMemory memory;
    kGame.build(memory);
    put(memory, kGame.s1(), 0x900000);
    WatchList list;
    list.set_regions(memory.query_regions());
    list.add(path_entry({"other.dll", 0x10, {0x8}, 8}));
    list.add(path_entry(long_path()));
    list.add(make_watch_entry(kGame.target(), WatchType::Int32));
    list.refresh(memory, 0, 3, WatchList::Clock::now());
    for (std::size_t row = 0; row < 2; ++row) {
        EXPECT_FALSE(list.resolved(row));
        EXPECT_FALSE(list.readable(row));
        EXPECT_EQ(list.value_text(row), "??");
        EXPECT_EQ(list.address_text(row), "P->??");
    }
    EXPECT_TRUE(list.resolved(2));
    EXPECT_EQ(list.address_text(2), format_address(kGame.target()));
}

TEST(GuiWatchPaths, SameChainIsNotAddedTwice) {
    WatchList list;
    EXPECT_TRUE(list.add(path_entry(long_path())));
    EXPECT_FALSE(list.add(path_entry(long_path())));
    EXPECT_TRUE(list.add(path_entry(short_path())));
    EXPECT_TRUE(list.add(make_watch_entry(0, WatchType::Int32)));
    EXPECT_EQ(list.rows().size(), 3u);
}

TEST(GuiWatchPaths, ChangingTheTypeAndKeepingChainsKeepThePath) {
    WatchList list;
    list.add(make_watch_entry(0x1000, WatchType::Int32, 0, "plain"));
    list.add(path_entry(long_path(), "health"));
    list.add(make_watch_entry(0x2000, WatchType::Int8));
    list.set_type(1, WatchType::Float, 0);
    ASSERT_TRUE(list.rows()[1].path);
    list.keep_paths();
    ASSERT_EQ(list.rows().size(), 1u);
    EXPECT_EQ(list.rows()[0].description, "health");
    EXPECT_EQ(list.rows()[0].type, WatchType::Float);
    ASSERT_TRUE(list.rows()[0].path);
    EXPECT_EQ(*list.rows()[0].path, long_path());
    EXPECT_EQ(list.selected_row(), 0u);
    list.remove(0);
    list.keep_paths();
    EXPECT_FALSE(list.selected_row());
}

std::shared_ptr<const PointerChains> sample_chains() {
    auto chains = std::make_shared<PointerChains>();
    chains->modules = {"game.exe", "other.dll"};
    chains->chains.resize(3);
    chains->chains[0].base_offset = 0x1020;
    chains->chains[0].offsets[0] = 0x30;
    chains->chains[0].depth = 1;
    chains->chains[1].base_offset = 0x1010;
    chains->chains[1].offsets = {0x20, 0x30};
    chains->chains[1].depth = 2;
    chains->chains[2].module = 1;
    chains->chains[2].base_offset = 0x10;
    chains->chains[2].offsets[0] = 0x8;
    chains->chains[2].depth = 1;
    return chains;
}

PointerSearch sample_search() {
    PointerSearch search;
    search.process = {4321, "game.exe", "", 1, false};
    search.target = make_watch_entry(kGame.target(), WatchType::Int32, 0, "health");
    search.found = 3;
    return search;
}

TEST(GuiPointerList, ShowsWhereEachChainLeadsNow) {
    FakeMemory memory;
    kGame.build(memory);
    PointerList list;
    EXPECT_FALSE(list.has_chains());
    EXPECT_TRUE(list.rows().empty());
    list.assign(sample_chains(), sample_search());
    list.set_modules(ModuleMap(memory.query_regions()));
    ASSERT_TRUE(list.has_chains());
    ASSERT_EQ(list.rows().size(), 3u);
    EXPECT_EQ(list.selected_row(), 0u);
    EXPECT_EQ(list.base_text(1), "game.exe+0x1010");
    EXPECT_EQ(list.offsets_text(1), "0x20, 0x30");
    EXPECT_EQ(list.path_text(1), "[[game.exe+0x1010]+0x20]+0x30");
    EXPECT_FALSE(list.read(1));
    EXPECT_EQ(list.address_text(1), "");
    EXPECT_EQ(list.value_text(1), "");

    list.refresh(memory, 0, 3);
    for (std::size_t row = 0; row < 2; ++row) {
        EXPECT_TRUE(list.read(row));
        EXPECT_EQ(list.address(row), kGame.target());
        EXPECT_EQ(list.address_text(row), format_address(kGame.target()));
        EXPECT_EQ(list.value_text(row), "100");
    }
    EXPECT_FALSE(list.address(2));
    EXPECT_EQ(list.address_text(2), "??");
    EXPECT_EQ(list.value_text(2), "??");

    list.forget_live();
    EXPECT_FALSE(list.read(0));
    list.refresh(memory, 1, 2);
    EXPECT_FALSE(list.read(0));
    EXPECT_TRUE(list.read(1));
}

TEST(GuiPointerList, RowBecomesAnEntryThatFollowsTheChain) {
    FakeMemory memory;
    kGame.build(memory);
    PointerList list;
    list.assign(sample_chains(), sample_search());
    list.set_modules(ModuleMap(memory.query_regions()));
    list.refresh(memory, 0, 3);
    const WatchEntry entry = list.watch_entry(1);
    EXPECT_EQ(entry.address, kGame.target());
    EXPECT_EQ(entry.type, WatchType::Int32);
    EXPECT_EQ(entry.description, "health");
    ASSERT_TRUE(entry.path);
    EXPECT_EQ(*entry.path, long_path());
}

TEST(GuiPointerList, SelectionStaysInTheList) {
    PointerList list;
    list.move_selection(1);
    EXPECT_FALSE(list.selected_row());
    list.assign(sample_chains(), sample_search());
    list.move_selection(5);
    EXPECT_EQ(list.selected_row(), 2u);
    list.move_selection(-1);
    EXPECT_EQ(list.selected_row(), 1u);
    list.select_row(7);
    EXPECT_EQ(list.selected_row(), 1u);
    list.clear();
    EXPECT_FALSE(list.has_chains());
    EXPECT_FALSE(list.selected_row());
}

class GuiPointers : public ::testing::Test {
protected:
    GuiPointers() {
        kGame.build(game_);
        kRestarted.build(restarted_);
        put(restarted_, kRestarted.s2(), 0);
    }

    void wait(Session& session) {
        const auto deadline = std::chrono::steady_clock::now() + 10s;
        while (!session.poll()) {
            ASSERT_LT(std::chrono::steady_clock::now(), deadline);
            std::this_thread::sleep_for(2ms);
        }
    }

    void start(Session& session) { session.attach(std::make_unique<FakeTarget>(game_, 100, "game.exe")); }

    // Chains to the health value of the first run.
    void search(Session& session, WatchEntry entry = make_watch_entry(kGame.target(), WatchType::Int32, 0, "health")) {
        start(session);
        session.add_watch(std::move(entry));
        ASSERT_TRUE(session.start_pointer_scan(0, 5, 0x1000));
        wait(session);
        ASSERT_EQ(session.pointers().rows().size(), 2u);
    }

    void restart(Session& session) { session.attach(std::make_unique<FakeTarget>(restarted_, 200, "GAME.EXE")); }

    FakeMemory game_;
    FakeMemory restarted_;
};

TEST_F(GuiPointers, SearchListsChainsToTheEntry) {
    Session session;
    EXPECT_FALSE(session.start_pointer_scan(0, 5, 0x1000));
    EXPECT_TRUE(session.notice().error);
    start(session);
    EXPECT_FALSE(session.start_pointer_scan(0, 5, 0x1000));
    EXPECT_TRUE(session.notice().error);

    session.add_watch(make_watch_entry(kGame.target(), WatchType::Int32, 0, "health"));
    ASSERT_TRUE(session.start_pointer_scan(0, 5, 0x1000));
    EXPECT_TRUE(session.busy());
    EXPECT_EQ(session.job()->kind(), JobKind::PointerScan);
    EXPECT_FALSE(session.start_pointer_scan(0, 5, 0x1000));
    wait(session);

    const PointerList& pointers = session.pointers();
    ASSERT_EQ(pointers.rows().size(), 2u);
    EXPECT_EQ(pointers.base_text(0), "game.exe+0x1020");
    EXPECT_EQ(pointers.base_text(1), "game.exe+0x1010");
    EXPECT_EQ(pointers.search().target.address, kGame.target());
    EXPECT_EQ(pointers.search().target.description, "health");
    EXPECT_EQ(pointers.search().depth, 5u);
    EXPECT_EQ(pointers.search().max_offset, 0x1000u);
    EXPECT_EQ(pointers.search().process.pid, 100u);
    EXPECT_EQ(pointers.search().found, 2u);
    EXPECT_TRUE(session.notice().text.starts_with("Найдено цепочек: 2 за ")) << session.notice().text;
    EXPECT_FALSE(session.notice().error);
}

TEST_F(GuiPointers, NothingFoundKeepsTheList) {
    Session session;
    search(session);
    ASSERT_TRUE(session.start_pointer_scan(0, 5, 0x10));
    wait(session);
    EXPECT_TRUE(session.notice().text.starts_with("Цепочек не найдено")) << session.notice().text;
    EXPECT_EQ(session.pointers().rows().size(), 2u);
}

TEST_F(GuiPointers, ListStaysWhenAnotherProcessIsOpened) {
    Session session;
    search(session);
    restart(session);
    EXPECT_EQ(session.pointers().rows().size(), 2u);
    EXPECT_EQ(session.pointers().search().process.pid, 100u);
}

TEST_F(GuiPointers, CheckAfterRestartKeepsChainsToTheNewAddress) {
    Session session;
    search(session);
    restart(session);
    PointerCheckForm form;
    form.address = "zzz";
    EXPECT_FALSE(session.start_pointer_check(form));
    EXPECT_TRUE(session.notice().error);

    form.address = format_address(kRestarted.target());
    ASSERT_TRUE(session.start_pointer_check(form));
    EXPECT_EQ(session.job()->kind(), JobKind::PointerCheck);
    wait(session);
    const PointerList& pointers = session.pointers();
    ASSERT_EQ(pointers.rows().size(), 1u);
    EXPECT_EQ(pointers.base_text(0), "game.exe+0x1010");
    EXPECT_EQ(pointers.search().checks, 1u);
    EXPECT_EQ(pointers.search().target.address, kRestarted.target());
    EXPECT_EQ(pointers.search().process.pid, 200u);
    EXPECT_TRUE(session.notice().text.starts_with("Осталось цепочек: 1 из 2")) << session.notice().text;
}

TEST_F(GuiPointers, RunStatisticsStayApartFromTheScans) {
    Session session;
    search(session);
    const PointerRun& run = session.pointer_run();
    EXPECT_EQ(run.kind, JobKind::PointerScan);
    EXPECT_GT(run.threads, 0u);
    EXPECT_GT(run.pointers, 0u);
    EXPECT_GT(run.bytes_read, 0u);
    EXPECT_EQ(session.last_seconds(), 0.0);

    restart(session);
    PointerCheckForm form;
    form.address = format_address(kRestarted.target());
    ASSERT_TRUE(session.start_pointer_check(form));
    wait(session);
    EXPECT_EQ(session.pointer_run().kind, JobKind::PointerCheck);
    EXPECT_GT(session.pointer_run().threads, 0u);
    EXPECT_EQ(session.pointer_run().bytes_read, 0u);
    EXPECT_EQ(session.last_seconds(), 0.0);
}

TEST_F(GuiPointers, CheckByValue) {
    Session session;
    search(session);
    restart(session);
    PointerCheckForm form;
    form.by_value = true;
    form.value = "abc";
    EXPECT_FALSE(session.start_pointer_check(form));
    EXPECT_TRUE(session.notice().error);
    form.value = "100";
    ASSERT_TRUE(session.start_pointer_check(form));
    wait(session);
    ASSERT_EQ(session.pointers().rows().size(), 1u);
    EXPECT_EQ(session.pointers().base_text(0), "game.exe+0x1010");
}

TEST_F(GuiPointers, CheckThatNoChainPassesKeepsTheList) {
    Session session;
    search(session);
    restart(session);
    PointerCheckForm form;
    form.by_value = true;
    form.value = "7";
    ASSERT_TRUE(session.start_pointer_check(form));
    wait(session);
    EXPECT_EQ(session.pointers().rows().size(), 2u);
    EXPECT_EQ(session.pointers().search().checks, 0u);
    EXPECT_TRUE(session.notice().error);
    EXPECT_TRUE(session.notice().text.starts_with("Ни одна цепочка")) << session.notice().text;
}

TEST_F(GuiPointers, OnlyNumbersAreCheckedByValue) {
    Session session;
    search(session, make_watch_entry(kGame.target(), WatchType::Bytes, 4));
    PointerCheckForm form;
    form.by_value = true;
    form.value = "100";
    EXPECT_FALSE(session.start_pointer_check(form));
    EXPECT_TRUE(session.notice().error);
}

TEST_F(GuiPointers, SavedChainsLoadBack) {
    const auto dir = std::filesystem::temp_directory_path() / "memhunter_gui_pointers";
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    Session session;
    EXPECT_FALSE(session.save_pointers(dir / "none.mhp"));
    EXPECT_TRUE(session.notice().error);
    search(session);
    ASSERT_TRUE(session.save_pointers(dir / "health.mhp"));
    EXPECT_TRUE(std::filesystem::exists(dir / "health.mhp"));
    EXPECT_FALSE(std::filesystem::exists(dir / "health.mhp.partial"));

    session.clear_pointers();
    EXPECT_FALSE(session.pointers().has_chains());
    restart(session);
    ASSERT_TRUE(session.load_pointers(dir / "health.mhp"));
    const PointerList& pointers = session.pointers();
    ASSERT_EQ(pointers.rows().size(), 2u);
    EXPECT_EQ(pointers.base_text(1), "game.exe+0x1010");
    EXPECT_EQ(pointers.search().target.address, kGame.target());
    EXPECT_EQ(pointers.search().target.type, WatchType::Int32);
    EXPECT_EQ(pointers.search().process.pid, 100u);
    EXPECT_EQ(pointers.search().depth, 5u);

    EXPECT_FALSE(session.load_pointers(dir / "missing.mhp"));
    EXPECT_TRUE(session.notice().error);
    std::ofstream(dir / "junk.mhp") << "junk";
    EXPECT_FALSE(session.load_pointers(dir / "junk.mhp"));
    EXPECT_TRUE(session.notice().error);
    EXPECT_EQ(session.pointers().rows().size(), 2u);
    std::filesystem::remove_all(dir);
}

TEST_F(GuiPointers, ChainGoesToTheAddressList) {
    Session session;
    search(session);
    ASSERT_TRUE(session.add_pointer_watch(1));
    const WatchList& watch = session.watch();
    ASSERT_EQ(watch.rows().size(), 2u);
    ASSERT_TRUE(watch.rows()[1].path);
    EXPECT_EQ(*watch.rows()[1].path, long_path());
    EXPECT_EQ(watch.rows()[1].description, "health");
    EXPECT_EQ(watch.selected_row(), 1u);
    EXPECT_FALSE(session.add_pointer_watch(1));
    EXPECT_FALSE(session.add_pointer_watch(5));
    EXPECT_EQ(watch.rows().size(), 2u);
}

TEST_F(GuiPointers, ExportFollowsTheChainNow) {
    Session session;
    search(session);
    session.add_pointer_watch(1);
    const std::uint64_t moved = kGame.heap + 0xA000;
    put(game_, moved + 0x30, 250, 4);
    put(game_, kGame.a() + 0x20, moved);

    const auto dir = std::filesystem::temp_directory_path() / "memhunter_gui_pointer_export";
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    const auto read = [](const std::filesystem::path& path) {
        std::ifstream in(path, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    };
    const ProcessSummary& process = session.target()->summary();
    const MemorySource& memory = session.target()->memory();
    const std::string path = "[[game.exe+0x1010]+0x20]+0x30";

    export_watch(dir / "watch.json", process, session.watch(), memory);
    const std::string json = read(dir / "watch.json");
    EXPECT_TRUE(contains(json, "{\"address\": \"" + format_address(moved + 0x30) +
                                   "\", \"type\": \"int32\", \"value\": \"250\", \"description\": \"health\", \"module\": \"\", "
                                   "\"pointer\": \"" + path + "\"}"))
        << json;
    EXPECT_TRUE(contains(json, "{\"address\": \"" + format_address(kGame.target()) +
                                   "\", \"type\": \"int32\", \"value\": \"100\", \"description\": \"health\", \"module\": \"\"}"))
        << json;

    export_watch(dir / "watch.csv", process, session.watch(), memory);
    const std::string csv = read(dir / "watch.csv");
    EXPECT_TRUE(contains(csv, format_address(moved + 0x30) + ",int32,,250,health,," + path + "\n")) << csv;

    export_watch(dir / "watch.txt", process, session.watch(), memory);
    const std::string text = read(dir / "watch.txt");
    EXPECT_TRUE(contains(text, format_address(moved + 0x30) + "  int32  250  health  " + path + "\n")) << text;

    put(game_, kGame.s1(), 0x900000);
    export_watch(dir / "watch.json", process, session.watch(), memory);
    EXPECT_TRUE(contains(read(dir / "watch.json"), "{\"address\": null, \"type\": \"int32\", \"value\": null")) << read(dir / "watch.json");
    std::filesystem::remove_all(dir);
}

TEST_F(GuiPointers, ChainEntriesSurviveARestartOfTheSameProgram) {
    Session session;
    search(session);
    session.add_pointer_watch(1);
    restart(session);
    WatchList& watch = session.watch();
    ASSERT_EQ(watch.rows().size(), 1u);
    ASSERT_TRUE(watch.rows()[0].path);
    watch.refresh(session.target()->memory(), 0, 1, WatchList::Clock::now());
    EXPECT_EQ(watch.rows()[0].address, kRestarted.target());
    EXPECT_EQ(watch.value_text(0), "100");

    session.attach(std::make_unique<FakeTarget>(game_, 300, "other.exe"));
    EXPECT_TRUE(session.watch().empty());
}

}  // namespace
}  // namespace mh::gui
