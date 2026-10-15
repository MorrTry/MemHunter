#include <gtest/gtest.h>

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <string>
#include <thread>
#include <utility>

#include "common/error.hpp"
#include "common/text.hpp"
#include "support/fake_memory.hpp"
#include "tui/app.hpp"
#include "tui/input.hpp"
#include "tui/model.hpp"
#include "tui/scan_task.hpp"
#include "tui/screen.hpp"
#include "tui/view.hpp"

namespace mh::tui {
namespace {

using mh::testing::FakeMemory;
using namespace std::chrono_literals;

constexpr std::uint64_t kBase = 0x10000;
constexpr std::size_t kRows = 10;

Key ch(char32_t c) {
    return Key::character(c);
}

Key key(KeyCode code) {
    return Key::of(code);
}

Command press(State& state, KeyCode code) {
    return handle_key(state, key(code), kRows);
}

void type(State& state, std::string_view text) {
    for (const char c : text) {
        handle_key(state, ch(static_cast<unsigned char>(c)), kRows);
    }
}

ProcessSummary target() {
    ProcessSummary process;
    process.pid = 1234;
    process.name = "target.exe";
    return process;
}

void write_ascii(FakeMemory& memory, std::uint64_t address, std::string_view text) {
    std::memcpy(memory.bytes_at(address, text.size()).data(), text.data(), text.size());
}

void write_utf16(FakeMemory& memory, std::uint64_t address, std::string_view text) {
    const auto bytes = memory.bytes_at(address, text.size() * 2);
    for (std::size_t i = 0; i < text.size(); ++i) {
        bytes[2 * i] = static_cast<std::byte>(text[i]);
        bytes[2 * i + 1] = std::byte{0};
    }
}

bool contains(const std::string& text, std::string_view part) {
    return text.find(part) != std::string::npos;
}

std::string read_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

std::wstring widen(std::string_view ascii) {
    return {ascii.begin(), ascii.end()};
}

// "password" three times as ASCII and once as UTF-16, plus an upper-case copy that only a case-insensitive
// search finds.
class TuiScan : public ::testing::Test {
protected:
    TuiScan() {
        memory_.add(kBase, 64 * 1024);
        write_ascii(memory_, kBase + 0x100, "password");
        write_ascii(memory_, kBase + 0x2000, "password");
        write_utf16(memory_, kBase + 0x4000, "password");
        write_ascii(memory_, kBase + 0x8000, "password");
        write_ascii(memory_, kBase + 0x9000, "PASSWORD");
    }

    void scan(State& state) {
        ScanRequest request = build_request(state);
        begin_scan(state);
        ScanProgress progress;
        ResultSet results = run_scan(memory_, request, progress, std::stop_token{});
        ProgressView view = read_progress(progress, 0.5);
        finish_scan(state, std::move(results), view);
    }

    State scanned() {
        State state(target());
        state.text.set("password");
        scan(state);
        return state;
    }

    FakeMemory memory_;
};

TEST(TuiScreen, TextIsClippedAndControlCharactersAreShownAsDots) {
    Screen screen(10, 2);
    EXPECT_EQ(screen.text(1, 0, "abc\tdef"), 7u);
    EXPECT_EQ(screen.row(0), " abc.def  ");
    EXPECT_EQ(screen.text(6, 1, "123456"), 4u);
    EXPECT_EQ(screen.row(1), "      1234");
    EXPECT_EQ(screen.text(0, 1, "xyz", Style::Inverse, 2), 2u);
    EXPECT_EQ(screen.row(1), "xy    1234");
    EXPECT_EQ(screen.at(1, 1).style, Style::Inverse);
    EXPECT_EQ(screen.at(2, 1).style, Style::Normal);
    EXPECT_EQ(screen.text(10, 0, "x"), 0u);
    EXPECT_EQ(screen.text(0, 2, "x"), 0u);
    screen.put(0, 0, U'\x1b');
    EXPECT_EQ(screen.at(0, 0).ch, U'.');
}

TEST(TuiScreen, WideCharactersTakeTwoCells) {
    EXPECT_EQ(text_width("ab"), 2u);
    EXPECT_EQ(text_width("日本"), 4u);
    Screen screen(5, 1);
    EXPECT_EQ(screen.text(0, 0, "日本語"), 4u);
    EXPECT_EQ(screen.at(0, 0).ch, U'日');
    EXPECT_EQ(screen.at(1, 0).ch, U'\0');
    EXPECT_EQ(screen.row(0), "日本 ");

    // An overdrawn half of a wide character is sent as a space, so the rest of the row keeps its columns.
    screen.put(1, 0, U'x');
    EXPECT_NE(render(screen, nullptr).find(L" x本 "), std::wstring::npos);
}

TEST(TuiScreen, FramesUseSingleOrDoubleLines) {
    Screen screen(6, 3);
    screen.frame(0, 0, 6, 3, theme::kPanel);
    EXPECT_EQ(screen.row(0), "┌────┐");
    EXPECT_EQ(screen.row(1), "│    │");
    EXPECT_EQ(screen.row(2), "└────┘");
    screen.frame(0, 0, 6, 3, theme::kFocusedPanel);
    EXPECT_EQ(screen.row(0), "╔════╗");
    EXPECT_EQ(screen.row(2), "╚════╝");
}

TEST(TuiScreen, RenderSendsOnlyChangedRows) {
    Screen first(8, 3);
    first.text(0, 0, "one");
    const std::wstring full = render(first, nullptr);
    EXPECT_NE(full.find(L"\x1b[2J"), std::wstring::npos);
    for (const wchar_t* row : {L"\x1b[1;1H", L"\x1b[2;1H", L"\x1b[3;1H"}) {
        EXPECT_NE(full.find(row), std::wstring::npos);
    }

    Screen second = first;
    second.text(0, 2, "two");
    const std::wstring diff = render(second, &first);
    EXPECT_EQ(diff.find(L"\x1b[2J"), std::wstring::npos);
    EXPECT_EQ(diff.find(L"\x1b[1;1H"), std::wstring::npos);
    EXPECT_EQ(diff.find(L"\x1b[2;1H"), std::wstring::npos);
    EXPECT_NE(diff.find(L"\x1b[3;1H"), std::wstring::npos);
    EXPECT_NE(diff.find(L"two"), std::wstring::npos);
    EXPECT_TRUE(render(second, &second).empty());

    const Screen resized(9, 3);
    EXPECT_NE(render(resized, &first).find(L"\x1b[2J"), std::wstring::npos);
}

TEST(TuiInput, LineEditEditsAtTheCursor) {
    LineEdit edit("hint");
    EXPECT_TRUE(edit.empty());
    EXPECT_EQ(edit.placeholder(), "hint");
    for (const char32_t c : std::u32string_view(U"helo")) {
        EXPECT_TRUE(edit.handle(ch(c)));
    }
    edit.handle(key(KeyCode::Left));
    edit.handle(ch(U'l'));
    EXPECT_EQ(edit.utf8(), "hello");
    EXPECT_EQ(edit.cursor(), 4u);
    edit.handle(key(KeyCode::Home));
    edit.handle(key(KeyCode::Delete));
    edit.handle(key(KeyCode::End));
    edit.handle(key(KeyCode::Backspace));
    edit.handle(ch(U'é'));
    EXPECT_EQ(edit.utf8(), "ell\xC3\xA9");
    edit.handle(key(KeyCode::Right));
    EXPECT_EQ(edit.cursor(), 4u);
    EXPECT_FALSE(edit.handle(key(KeyCode::Tab)));
    EXPECT_FALSE(edit.handle(key(KeyCode::Enter)));
    EXPECT_FALSE(edit.handle(key(KeyCode::F5)));

    edit.set("日本\xF0\xA0\x80\x80");
    ASSERT_EQ(edit.text().size(), 3u);
    EXPECT_EQ(edit.text()[2], U'\U00020000');
    EXPECT_EQ(edit.cursor(), 3u);
    EXPECT_EQ(edit.utf8(), "日本\xF0\xA0\x80\x80");

    edit.set(std::string(LineEdit::kMaxLength + 10, 'a'));
    EXPECT_EQ(edit.text().size(), LineEdit::kMaxLength);
    EXPECT_TRUE(edit.handle(ch(U'b')));
    EXPECT_EQ(edit.text().size(), LineEdit::kMaxLength);

    edit.clear();
    EXPECT_TRUE(edit.empty());
    EXPECT_EQ(edit.cursor(), 0u);
}

TEST(TuiModel, TabMovesFocusAndSkipsDisabledButtons) {
    State state(target());
    EXPECT_EQ(state.focus, Focus::Text);
    for (const Focus expected : {Focus::Signature, Focus::Encoding, Focus::Case, Focus::Memory, Focus::Results, Focus::Scan}) {
        press(state, KeyCode::Tab);
        EXPECT_EQ(state.focus, expected);
    }
    // Cancel needs a running scan and Save needs matches.
    press(state, KeyCode::Tab);
    EXPECT_EQ(state.focus, Focus::Quit);
    press(state, KeyCode::Tab);
    EXPECT_EQ(state.focus, Focus::Text);
    press(state, KeyCode::BackTab);
    EXPECT_EQ(state.focus, Focus::Quit);
    press(state, KeyCode::BackTab);
    EXPECT_EQ(state.focus, Focus::Scan);

    state.phase = Phase::Scanning;
    state.focus = Focus::Results;
    press(state, KeyCode::Tab);
    EXPECT_EQ(state.focus, Focus::Cancel);
    press(state, KeyCode::Tab);
    EXPECT_EQ(state.focus, Focus::Quit);
    EXPECT_FALSE(is_enabled(state, Focus::Scan));
    EXPECT_FALSE(is_enabled(state, Focus::Save));
}

TEST(TuiModel, SearchFieldsTakeTextAndEnterStartsTheScan) {
    State state(target());
    type(state, "quit");
    EXPECT_EQ(state.text.utf8(), "quit");
    EXPECT_EQ(press(state, KeyCode::Enter), Command::StartScan);
    press(state, KeyCode::Down);
    EXPECT_EQ(state.focus, Focus::Signature);
    type(state, "48 8B");
    EXPECT_EQ(state.signature.utf8(), "48 8B");
    press(state, KeyCode::Up);
    EXPECT_EQ(state.focus, Focus::Text);
    EXPECT_EQ(press(state, KeyCode::F5), Command::StartScan);
    EXPECT_EQ(press(state, KeyCode::Escape), Command::None);
    EXPECT_EQ(press(state, KeyCode::CtrlC), Command::Quit);
    EXPECT_EQ(press(state, KeyCode::F10), Command::Quit);

    state.phase = Phase::Scanning;
    EXPECT_EQ(press(state, KeyCode::Enter), Command::None);
    EXPECT_EQ(press(state, KeyCode::F5), Command::None);
    EXPECT_EQ(press(state, KeyCode::Escape), Command::CancelScan);
    EXPECT_EQ(press(state, KeyCode::CtrlC), Command::CancelScan);
    EXPECT_EQ(press(state, KeyCode::F10), Command::Quit);
}

TEST(TuiModel, SwitchesChangeWithArrowsAndSpace) {
    State state(target());
    state.focus = Focus::Encoding;
    EXPECT_EQ(state.encoding, EncodingChoice::Both);
    press(state, KeyCode::Right);
    EXPECT_EQ(state.encoding, EncodingChoice::Ascii);
    handle_key(state, ch(U' '), kRows);
    EXPECT_EQ(state.encoding, EncodingChoice::Utf16);
    press(state, KeyCode::Left);
    press(state, KeyCode::Left);
    EXPECT_EQ(state.encoding, EncodingChoice::Both);
    type(state, "x");
    EXPECT_TRUE(state.text.empty());

    state.focus = Focus::Case;
    press(state, KeyCode::Right);
    EXPECT_TRUE(state.ignore_case);
    press(state, KeyCode::Left);
    EXPECT_FALSE(state.ignore_case);

    state.focus = Focus::Memory;
    press(state, KeyCode::Left);
    EXPECT_EQ(state.memory, MemoryChoice::Mapped);
    press(state, KeyCode::Right);
    press(state, KeyCode::Right);
    EXPECT_EQ(state.memory, MemoryChoice::Private);
    EXPECT_EQ(press(state, KeyCode::Enter), Command::StartScan);
}

TEST(TuiModel, BuildRequestFollowsTheSearchPanel) {
    State state(target());
    state.threads = 3;
    EXPECT_THROW(build_request(state), Error);

    state.text.set("password");
    ScanRequest request = build_request(state);
    ASSERT_EQ(request.patterns.size(), 2u);
    EXPECT_EQ(request.patterns[0].kind, PatternKind::Ascii);
    EXPECT_EQ(request.patterns[1].kind, PatternKind::Utf16);
    EXPECT_EQ(request.filter.types, type_class::All);
    EXPECT_EQ(request.engine.preview_bytes, kPreviewBytes);
    EXPECT_EQ(request.engine.scan_threads, 3u);

    state.encoding = EncodingChoice::Utf16;
    state.ignore_case = true;
    state.memory = MemoryChoice::Private;
    state.signature.set("48 8B ?? 89");
    request = build_request(state);
    ASSERT_EQ(request.patterns.size(), 2u);
    EXPECT_EQ(request.patterns[0].kind, PatternKind::Utf16);
    EXPECT_TRUE(request.patterns[0].case_insensitive);
    EXPECT_EQ(request.patterns[1].kind, PatternKind::Signature);
    EXPECT_EQ(request.patterns[1].size(), 4u);
    EXPECT_EQ(request.filter.types, type_class::Private);

    state.text.clear();
    state.signature.set("48 zz");
    EXPECT_THROW(build_request(state), Error);
}

TEST_F(TuiScan, FinishedScanFillsTheResultsAndFocusesThem) {
    const State state = scanned();
    EXPECT_EQ(state.phase, Phase::Completed);
    EXPECT_TRUE(state.has_results);
    ASSERT_EQ(state.results.matches.size(), 4u);
    EXPECT_EQ(state.rows.size(), 4u);
    EXPECT_EQ(state.progress.matches, 4u);
    EXPECT_EQ(state.progress.bytes_done, state.progress.bytes_total);
    EXPECT_EQ(state.focus, Focus::Results);
    EXPECT_TRUE(state.message.starts_with("Scan completed: 4 matches in 0.50 s")) << state.message;
    ASSERT_NE(selected_match(state), nullptr);
    EXPECT_EQ(selected_match(state)->address, kBase + 0x100);
    EXPECT_TRUE(is_enabled(state, Focus::Save));
}

TEST_F(TuiScan, ResultsCanBeBrowsedPageByPage) {
    State state = scanned();
    const auto move = [&](KeyCode code) { handle_key(state, key(code), 2); };
    move(KeyCode::Down);
    EXPECT_EQ(state.selected, 1u);
    EXPECT_EQ(state.top, 0u);
    move(KeyCode::Down);
    EXPECT_EQ(state.selected, 2u);
    EXPECT_EQ(state.top, 1u);
    move(KeyCode::End);
    EXPECT_EQ(state.selected, 3u);
    EXPECT_EQ(state.top, 2u);
    move(KeyCode::Down);
    EXPECT_EQ(state.selected, 3u);
    move(KeyCode::Home);
    EXPECT_EQ(state.selected, 0u);
    EXPECT_EQ(state.top, 0u);
    move(KeyCode::Up);
    EXPECT_EQ(state.selected, 0u);
    move(KeyCode::PageDown);
    EXPECT_EQ(state.selected, 2u);
    move(KeyCode::PageUp);
    EXPECT_EQ(state.selected, 0u);
    EXPECT_EQ(selected_match(state)->address, kBase + 0x100);
}

TEST_F(TuiScan, MarkingSelectsWhatIsSaved) {
    State state = scanned();
    EXPECT_EQ(rows_to_save(state), state.rows);
    handle_key(state, ch(U' '), kRows);
    EXPECT_EQ(state.marked_count, 1u);
    EXPECT_EQ(state.selected, 1u);
    handle_key(state, ch(U' '), kRows);
    press(state, KeyCode::Up);
    handle_key(state, ch(U' '), kRows);
    EXPECT_EQ(state.marked_count, 1u);
    EXPECT_EQ(rows_to_save(state), (std::vector<std::size_t>{0}));

    handle_key(state, ch(U'a'), kRows);
    EXPECT_EQ(state.marked_count, 4u);
    handle_key(state, ch(U'a'), kRows);
    EXPECT_EQ(state.marked_count, 0u);
    EXPECT_EQ(rows_to_save(state), state.rows);
}

TEST_F(TuiScan, FilterMatchesKindAddressAndText) {
    State state = scanned();
    handle_key(state, ch(U'/'), kRows);
    ASSERT_EQ(state.prompt, Prompt::Filter);
    type(state, "UTF16");
    EXPECT_EQ(press(state, KeyCode::Enter), Command::None);
    EXPECT_EQ(state.prompt, Prompt::None);
    EXPECT_EQ(state.applied_filter, "UTF16");
    ASSERT_EQ(state.rows.size(), 1u);
    EXPECT_EQ(selected_match(state)->address, kBase + 0x4000);

    handle_key(state, ch(U'/'), kRows);
    EXPECT_EQ(state.filter.utf8(), "UTF16");
    state.filter.clear();
    type(state, format_address(kBase + 0x2000));
    press(state, KeyCode::Enter);
    ASSERT_EQ(state.rows.size(), 1u);
    EXPECT_EQ(selected_match(state)->address, kBase + 0x2000);

    handle_key(state, ch(U'/'), kRows);
    state.filter.set("nothing like this");
    press(state, KeyCode::Escape);
    EXPECT_EQ(state.prompt, Prompt::None);
    EXPECT_EQ(state.rows.size(), 1u);

    handle_key(state, ch(U'/'), kRows);
    state.filter.set("nothing like this");
    press(state, KeyCode::Enter);
    EXPECT_TRUE(state.rows.empty());
    EXPECT_EQ(selected_match(state), nullptr);
    EXPECT_EQ(rows_to_save(state), std::vector<std::size_t>{});

    handle_key(state, ch(U'/'), kRows);
    state.filter.clear();
    press(state, KeyCode::Enter);
    EXPECT_EQ(state.rows.size(), 4u);
}

TEST_F(TuiScan, PreviewToggleSavePromptAndQuit) {
    State state = scanned();
    EXPECT_EQ(state.preview, PreviewMode::Hex);
    handle_key(state, ch(U'v'), kRows);
    EXPECT_EQ(state.preview, PreviewMode::Text);
    press(state, KeyCode::F3);
    EXPECT_EQ(state.preview, PreviewMode::Hex);

    handle_key(state, ch(U's'), kRows);
    ASSERT_EQ(state.prompt, Prompt::Save);
    EXPECT_EQ(state.save_path.utf8(), "memhunter-results.json");
    // Keys go to the prompt, not to the results.
    handle_key(state, ch(U'q'), kRows);
    EXPECT_EQ(state.save_path.utf8(), "memhunter-results.jsonq");
    press(state, KeyCode::Backspace);
    EXPECT_EQ(press(state, KeyCode::Enter), Command::Save);
    EXPECT_EQ(state.prompt, Prompt::None);

    press(state, KeyCode::F2);
    state.save_path.clear();
    EXPECT_EQ(press(state, KeyCode::Enter), Command::None);
    EXPECT_EQ(state.prompt, Prompt::Save);
    EXPECT_FALSE(state.message.empty());
    press(state, KeyCode::Escape);
    EXPECT_EQ(state.prompt, Prompt::None);

    EXPECT_EQ(handle_key(state, ch(U'q'), kRows), Command::Quit);
}

TEST(TuiModel, NothingToSaveOrFilterBeforeAScan) {
    State state(target());
    press(state, KeyCode::F2);
    EXPECT_EQ(state.prompt, Prompt::None);
    EXPECT_EQ(state.message, "Nothing to save yet");
    state.focus = Focus::Results;
    handle_key(state, ch(U'/'), kRows);
    EXPECT_EQ(state.prompt, Prompt::None);
    EXPECT_FALSE(state.message.empty());
    handle_key(state, ch(U' '), kRows);
    press(state, KeyCode::Down);
    EXPECT_EQ(state.selected, 0u);
}

TEST(TuiModel, ScanPhasesAndFocus) {
    State state(target());
    state.focus = Focus::Scan;
    begin_scan(state);
    EXPECT_EQ(state.phase, Phase::Scanning);
    EXPECT_EQ(state.focus, Focus::Cancel);
    EXPECT_FALSE(state.has_results);

    ResultSet cancelled;
    cancelled.stats.status = ScanStatus::Cancelled;
    finish_scan(state, std::move(cancelled), ProgressView{});
    EXPECT_EQ(state.phase, Phase::Cancelled);
    EXPECT_EQ(state.focus, Focus::Text);
    EXPECT_TRUE(state.message.starts_with("Scan cancelled")) << state.message;

    begin_scan(state);
    ResultSet exited;
    exited.stats.status = ScanStatus::TargetExited;
    exited.stats.truncated = true;
    finish_scan(state, std::move(exited), ProgressView{});
    EXPECT_EQ(state.phase, Phase::TargetExited);
    EXPECT_TRUE(contains(state.message, "exited")) << state.message;
    EXPECT_TRUE(contains(state.message, "match limit")) << state.message;

    begin_scan(state);
    state.focus = Focus::Cancel;
    fail_scan(state, "Scan failed: access denied");
    EXPECT_EQ(state.phase, Phase::Failed);
    EXPECT_EQ(state.focus, Focus::Text);
    EXPECT_EQ(state.message, "Scan failed: access denied");
}

TEST(TuiModel, SaveFormatFollowsTheExtension) {
    EXPECT_EQ(format_for_path("a.JSON"), OutputFormat::Json);
    EXPECT_EQ(format_for_path("dir.csv/b.csv"), OutputFormat::Csv);
    EXPECT_EQ(format_for_path("c.txt"), OutputFormat::Text);
    EXPECT_EQ(format_for_path("results"), OutputFormat::Text);
}

TEST_F(TuiScan, SaveWritesTheChosenRows) {
    const auto directory = std::filesystem::temp_directory_path() / ("memhunter-tui-" + std::to_string(GetCurrentProcessId()));
    std::filesystem::create_directories(directory);
    State state = scanned();

    state.save_path.set(wide_to_utf8((directory / "all.json").wstring()));
    save_results(state);
    EXPECT_TRUE(state.message.starts_with("Saved 4 matches to ")) << state.message;
    const std::string json = read_file(directory / "all.json");
    EXPECT_TRUE(contains(json, format_address(kBase + 0x100)));
    EXPECT_TRUE(contains(json, format_address(kBase + 0x8000)));

    press(state, KeyCode::End);
    handle_key(state, ch(U' '), kRows);
    state.save_path.set(wide_to_utf8((directory / "marked.csv").wstring()));
    save_results(state);
    EXPECT_TRUE(state.message.starts_with("Saved 1 marked match to ")) << state.message;
    const std::string csv = read_file(directory / "marked.csv");
    EXPECT_TRUE(contains(csv, format_address(kBase + 0x8000)));
    EXPECT_FALSE(contains(csv, format_address(kBase + 0x100)));

    state.save_path.set(wide_to_utf8((directory / "missing" / "x.txt").wstring()));
    save_results(state);
    EXPECT_TRUE(state.message.starts_with("Cannot create")) << state.message;

    std::error_code ignored;
    std::filesystem::remove_all(directory, ignored);
}

TEST(TuiView, LayoutNeedsTheMinimumSize) {
    EXPECT_TRUE(layout_for(79, 40).too_small);
    EXPECT_TRUE(layout_for(120, 19).too_small);
    const Layout minimum = layout_for(80, 20);
    EXPECT_FALSE(minimum.too_small);
    EXPECT_EQ(minimum.status_y, 19u);
    EXPECT_EQ(minimum.page_rows, 1u);
    EXPECT_EQ(layout_for(80, 24).page_rows, 5u);

    Screen screen(60, 10);
    draw(screen, State(target()));
    EXPECT_TRUE(contains(screen.row(4), "Terminal too small: 80x20 needed, now 60x10")) << screen.row(4);
    EXPECT_TRUE(contains(screen.row(5), "F10"));
}

TEST(TuiView, IdleScreenShowsAllAreas) {
    State state(target());
    state.process.pid = 98765;
    state.process.name = "a-rather-long-process-name.exe";
    Screen screen(80, 24);
    draw(screen, state);
    const std::string top = screen.row(0);
    EXPECT_TRUE(top.starts_with(" MemHunter  pid 98765  Ready")) << top;
    EXPECT_TRUE(contains(top, "[Scan F5]  Cancel Esc   Save F2  [Quit F10]")) << top;
    EXPECT_EQ(screen.at(1, 0).style, Style::Strong);

    EXPECT_TRUE(screen.row(1).starts_with("╔═ Search ")) << screen.row(1);
    EXPECT_TRUE(contains(screen.row(2), "Text      [")) << screen.row(2);
    EXPECT_EQ(screen.at(2, 2).style, Style::Inverse);
    EXPECT_EQ(screen.at(13, 2).style, Style::Inverse);  // the cursor
    EXPECT_TRUE(contains(screen.row(3), "(bytes, e.g. 48 8B ?? 89)")) << screen.row(3);
    EXPECT_TRUE(contains(screen.row(2), "Encoding < ASCII+UTF-16 >")) << screen.row(2);
    EXPECT_TRUE(contains(screen.row(3), "Case < exact >  Memory < all >")) << screen.row(3);

    EXPECT_TRUE(screen.row(5).starts_with("┌─ Progress ")) << screen.row(5);
    EXPECT_TRUE(contains(screen.row(6), "0.0%  Read 0 B of 0 B  Regions 0/0  Matches 0")) << screen.row(6);
    EXPECT_TRUE(screen.row(8).starts_with("┌─ Results ")) << screen.row(8);
    EXPECT_TRUE(contains(screen.row(9), "Address")) << screen.row(9);
    EXPECT_TRUE(contains(screen.row(9), "Preview (hex)")) << screen.row(9);
    bool hint = false;
    for (std::size_t y = 10; y < 15; ++y) {
        hint = hint || contains(screen.row(y), "Type a text or a byte signature above and press Enter");
    }
    EXPECT_TRUE(hint);
    EXPECT_TRUE(screen.row(16).starts_with("┌─ Details ")) << screen.row(16);
    EXPECT_TRUE(contains(screen.row(17), "No match selected"));
    EXPECT_EQ(screen.row(23).rfind(" Speed -  Read errors 0  Time 0.00 s │ Ready", 0), 0u) << screen.row(23);
    EXPECT_TRUE(screen.row(22).starts_with("└─ Enter scan  Tab next field  F3 hex/text  F10 quit ─")) << screen.row(22);
}

TEST(TuiView, ScanningShowsProgressAndTheCancelButton) {
    State state(target());
    state.text.set("abc");
    begin_scan(state);
    state.progress.bytes_total = 200;
    state.progress.bytes_done = 100;
    state.progress.regions_total = 4;
    state.progress.regions_done = 1;
    state.progress.matches = 7;
    Screen screen(80, 24);
    draw(screen, state);
    EXPECT_TRUE(contains(screen.row(0), "Scanning 50%")) << screen.row(0);
    EXPECT_TRUE(contains(screen.row(0), " Scan F5  [Cancel Esc]")) << screen.row(0);
    EXPECT_TRUE(contains(screen.row(6), " 50.0%  Read 100 B of 200 B  Regions 1/4  Matches 7")) << screen.row(6);
    EXPECT_TRUE(contains(screen.row(6), "[████")) << screen.row(6);
    EXPECT_TRUE(contains(screen.row(22), " Esc cancel scan ")) << screen.row(22);
    EXPECT_TRUE(contains(screen.row(23), "│ Scanning")) << screen.row(23);
}

TEST_F(TuiScan, ResultsTableAndDetails) {
    State state = scanned();
    Screen screen(100, 30);
    draw(screen, state);
    const Layout layout = layout_for(100, 30);
    EXPECT_TRUE(screen.row(layout.results_y).starts_with("╔═ Results: 4 matches, row 1/4 ")) << screen.row(layout.results_y);

    const std::size_t first = layout.results_y + 2;
    EXPECT_TRUE(contains(screen.row(first), format_address(kBase + 0x100))) << screen.row(first);
    EXPECT_TRUE(contains(screen.row(first), "ascii")) << screen.row(first);
    EXPECT_TRUE(contains(screen.row(first), "70 61 73 73")) << screen.row(first);
    EXPECT_EQ(screen.at(4, first).style, Style::Inverse);
    EXPECT_EQ(screen.at(4, first + 1).style, Style::Normal);
    EXPECT_TRUE(contains(screen.row(first + 2), "utf16")) << screen.row(first + 2);

    const std::size_t details = layout.details_y;
    EXPECT_TRUE(contains(screen.row(details + 1), format_address(kBase + 0x100))) << screen.row(details + 1);
    EXPECT_TRUE(contains(screen.row(details + 1), "8 bytes")) << screen.row(details + 1);
    EXPECT_TRUE(contains(screen.row(details + 2), format_address(kBase))) << screen.row(details + 2);
    EXPECT_TRUE(contains(screen.row(details + 2), "(+0x100)")) << screen.row(details + 2);
    EXPECT_TRUE(contains(screen.row(details + 3), "+0000")) << screen.row(details + 3);
    EXPECT_TRUE(contains(screen.row(details + 3), "password")) << screen.row(details + 3);
    EXPECT_TRUE(contains(screen.row(details + 4), "+0010")) << screen.row(details + 4);

    // Marked rows carry a star; without focus the selection is bold instead of inverted.
    handle_key(state, ch(U' '), kRows);
    state.focus = Focus::Text;
    state.preview = PreviewMode::Text;
    draw(screen, state);
    EXPECT_EQ(screen.at(2, first).ch, theme::kMarked);
    EXPECT_EQ(screen.at(4, first + 1).style, Style::Strong);
    EXPECT_TRUE(contains(screen.row(layout.results_y + 1), "Preview (text)"));
    EXPECT_TRUE(contains(screen.row(details + 3), "Text")) << screen.row(details + 3);

    state.prompt = Prompt::Filter;
    state.filter.set("utf");
    draw(screen, state);
    EXPECT_TRUE(screen.row(layout.status_y).starts_with(" Filter [utf")) << screen.row(layout.status_y);
    EXPECT_TRUE(contains(screen.row(layout.status_y - 1), " Enter apply the filter  Esc cancel ")) << screen.row(layout.status_y - 1);
}

TEST_F(TuiScan, KeyHintsFitAtTheMinimumWidth) {
    State state = scanned();
    Screen screen(80, 20);
    draw(screen, state);
    const std::string bar = screen.row(18);
    EXPECT_TRUE(contains(bar, " ↑↓ PgUp PgDn  Space mark  a all  / filter  v hex/text  F2 save  q quit ")) << bar;
    EXPECT_TRUE(bar.ends_with("─┘")) << bar;
    // Hex previews end with a whole byte.
    const std::string row = screen.row(10);
    const std::size_t start = row.find("70 61");
    ASSERT_NE(start, std::string::npos) << row;
    const std::string preview = row.substr(start, row.rfind("║") - start);
    const std::size_t end = preview.find_last_not_of(' ');
    EXPECT_EQ((end + 2) % 3, 0u) << row;
    EXPECT_TRUE(state.message.starts_with("Scan completed: 4 matches")) << state.message;
    EXPECT_EQ(count_matches(1), "1 match");

    state.message = "A message that is too long to share the line with the scan counters";
    draw(screen, state);
    EXPECT_TRUE(screen.row(19).starts_with(" A message that is too long")) << screen.row(19);
    EXPECT_EQ(screen.at(1, 19).style, Style::Strong);
    state.message = "Short message";
    draw(screen, state);
    EXPECT_TRUE(screen.row(19).starts_with(" Speed ")) << screen.row(19);
    EXPECT_TRUE(contains(screen.row(19), "│ Short message")) << screen.row(19);
    EXPECT_EQ(count_matches(0), "0 matches");
}

void expect_black_and_white(const std::wstring& out) {
    const std::wstring allowed[] = {widen(theme::kNormalSgr), widen(theme::kStrongSgr), widen(theme::kInverseSgr), L"\x1b[2J"};
    std::wstring printed;
    for (std::size_t i = 0; i < out.size();) {
        if (out[i] != L'\x1b') {
            printed.push_back(out[i++]);
            continue;
        }
        const std::size_t end = out.find_first_of(L"mHJ", i);
        ASSERT_NE(end, std::wstring::npos);
        const std::wstring sequence = out.substr(i, end - i + 1);
        bool known = std::find(std::begin(allowed), std::end(allowed), sequence) != std::end(allowed);
        if (!known && sequence.size() > 5 && sequence.starts_with(L"\x1b[") && sequence.ends_with(L";1H")) {
            const std::wstring row = sequence.substr(2, sequence.size() - 5);
            known = !row.empty() && row.find_first_not_of(L"0123456789") == std::wstring::npos;
        }
        EXPECT_TRUE(known) << "unexpected escape sequence: " << wide_to_utf8(sequence.substr(1));
        i = end + 1;
    }
    for (const wchar_t c : printed) {
        const bool plain = c >= 0x20 && c < 0x7F;
        const bool arrow = c >= 0x2190 && c <= 0x2193;
        const bool box = c >= 0x2500 && c <= 0x259F;
        EXPECT_TRUE(plain || arrow || box) << "unexpected character U+" << std::hex << static_cast<unsigned>(c);
    }
}

TEST(TuiTheme, ColoursAreExactlyWhiteAndBlack) {
    EXPECT_EQ(theme::kNormalSgr, "\x1b[0;38;2;255;255;255;48;2;0;0;0m");
    EXPECT_EQ(theme::kStrongSgr, "\x1b[0;1;38;2;255;255;255;48;2;0;0;0m");
    EXPECT_EQ(theme::kInverseSgr, "\x1b[0;38;2;0;0;0;48;2;255;255;255m");
}

TEST_F(TuiScan, EveryScreenUsesOnlyTheBlackAndWhiteTheme) {
    State state = scanned();
    std::vector<std::wstring> outputs;
    Screen previous(100, 30);
    draw(previous, state);
    outputs.push_back(render(previous, nullptr));
    const auto step = [&](const std::function<void(State&)>& change) {
        change(state);
        Screen next(previous.width(), previous.height());
        draw(next, state);
        outputs.push_back(render(next, &previous));
        previous = next;
    };
    step([](State& s) { handle_key(s, ch(U' '), kRows); });
    step([](State& s) { handle_key(s, ch(U'v'), kRows); });
    step([](State& s) { handle_key(s, ch(U'/'), kRows); });
    step([](State& s) { type(s, "pass"); });
    step([](State& s) { press(s, KeyCode::Enter); });
    step([](State& s) { press(s, KeyCode::F2); });
    step([](State& s) { press(s, KeyCode::Escape); });
    step([](State& s) { s.focus = Focus::Signature; });
    step([](State& s) { begin_scan(s); s.progress.bytes_total = 10; s.progress.bytes_done = 3; });
    step([](State& s) { fail_scan(s, "Scan failed"); });
    for (const auto& [width, height] : {std::pair<std::size_t, std::size_t>{80, 20}, {200, 60}, {40, 10}}) {
        Screen screen(width, height);
        draw(screen, state);
        outputs.push_back(render(screen, nullptr));
    }
    for (const auto& out : outputs) {
        expect_black_and_white(out);
    }
}

TEST(TuiScanTask, RunsInTheBackgroundAndHandsOverTheResult) {
    FakeMemory memory;
    memory.add(kBase, 64 * 1024);
    write_ascii(memory, kBase + 0x1234, "needle");
    State state(target());
    state.text.set("needle");
    ScanTask task(memory, build_request(state), target());
    const auto deadline = std::chrono::steady_clock::now() + 30s;
    while (!task.finished() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(5ms);
    }
    ASSERT_TRUE(task.finished());
    const ProgressView progress = read_progress(task.progress(), task.elapsed_seconds());
    EXPECT_EQ(progress.bytes_done, progress.bytes_total);
    EXPECT_EQ(progress.regions_done, progress.regions_total);
    const double seconds = task.elapsed_seconds();
    std::this_thread::sleep_for(20ms);
    EXPECT_EQ(task.elapsed_seconds(), seconds);

    const ResultSet results = task.take();
    EXPECT_EQ(results.stats.status, ScanStatus::Completed);
    EXPECT_EQ(results.process.pid, 1234u);
    ASSERT_EQ(results.matches.size(), 1u);
    EXPECT_EQ(results.matches[0].address, kBase + 0x1234);
    EXPECT_THROW(task.take(), Error);
}

TEST(TuiScanTask, CancelStopsARunningScan) {
    FakeMemory memory;
    memory.add(kBase, 16 * 1024 * 1024);
    std::atomic<bool> reading{false};
    memory.on_read([&](std::size_t) {
        reading = true;
        std::this_thread::sleep_for(2ms);
    });
    State state(target());
    state.text.set("needle");
    ScanRequest request = build_request(state);
    request.chunk_size = 4096;
    ScanTask task(memory, std::move(request), target());
    EXPECT_THROW(task.take(), Error);
    while (!reading) {
        std::this_thread::sleep_for(1ms);
    }
    const auto cancelled_at = std::chrono::steady_clock::now();
    task.cancel();
    while (!task.finished() && std::chrono::steady_clock::now() - cancelled_at < 30s) {
        std::this_thread::sleep_for(5ms);
    }
    ASSERT_TRUE(task.finished());
    EXPECT_LT(std::chrono::steady_clock::now() - cancelled_at, 5s);
    EXPECT_EQ(task.take().stats.status, ScanStatus::Cancelled);
}

TEST(TuiScanTask, DestroyingARunningTaskStopsAndJoinsIt) {
    FakeMemory memory;
    memory.add(kBase, 16 * 1024 * 1024);
    memory.on_read([](std::size_t) { std::this_thread::sleep_for(2ms); });
    State state(target());
    state.text.set("needle");
    ScanRequest request = build_request(state);
    request.chunk_size = 4096;
    const auto started = std::chrono::steady_clock::now();
    {
        ScanTask task(memory, std::move(request), target());
        std::this_thread::sleep_for(20ms);
    }
    EXPECT_LT(std::chrono::steady_clock::now() - started, 5s);
    EXPECT_LT(memory.read_count(), 4096u);
}

}  // namespace
}  // namespace mh::tui
