#include "tui/model.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <filesystem>

#include "common/error.hpp"
#include "common/text.hpp"

namespace mh::tui {

namespace {

constexpr std::array kFocusOrder{Focus::Text,    Focus::Signature, Focus::Encoding, Focus::Case,  Focus::Memory,
                                 Focus::Results, Focus::Scan,      Focus::Cancel,   Focus::Save,  Focus::Quit};

bool scanning(const State& state) {
    return state.phase == Phase::Scanning;
}

bool has_matches(const State& state) {
    return state.has_results && !state.results.matches.empty();
}

void move_focus(State& state, int step) {
    const auto at = std::find(kFocusOrder.begin(), kFocusOrder.end(), state.focus);
    auto index = static_cast<std::ptrdiff_t>(at - kFocusOrder.begin());
    const auto count = static_cast<std::ptrdiff_t>(kFocusOrder.size());
    for (std::ptrdiff_t tries = 0; tries < count; ++tries) {
        index = (index + step + count) % count;
        if (is_enabled(state, kFocusOrder[static_cast<std::size_t>(index)])) {
            state.focus = kFocusOrder[static_cast<std::size_t>(index)];
            return;
        }
    }
}

template <typename E>
E cycle(E value, int step, int count) {
    return static_cast<E>((static_cast<int>(value) + step + count) % count);
}

void open_save(State& state) {
    if (!has_matches(state)) {
        state.message = "Nothing to save yet";
        return;
    }
    if (state.save_path.empty()) {
        state.save_path.set("memhunter-results.json");
    }
    state.prompt = Prompt::Save;
}

void open_filter(State& state) {
    if (!state.has_results) {
        state.message = "Run a scan first, then filter its results";
        return;
    }
    state.filter.set(state.applied_filter);
    state.prompt = Prompt::Filter;
}

void toggle_preview(State& state) {
    state.preview = state.preview == PreviewMode::Hex ? PreviewMode::Text : PreviewMode::Hex;
}

void select(State& state, std::ptrdiff_t delta, std::size_t page_rows) {
    if (state.rows.empty()) {
        state.selected = 0;
        state.top = 0;
        return;
    }
    const auto last = static_cast<std::ptrdiff_t>(state.rows.size() - 1);
    state.selected = static_cast<std::size_t>(std::clamp(static_cast<std::ptrdiff_t>(state.selected) + delta, std::ptrdiff_t{0}, last));
    state.top = visible_top(state, page_rows);
}

void toggle_mark(State& state, std::size_t row) {
    std::uint8_t& mark = state.marked[state.rows[row]];
    mark ^= 1;
    if (mark != 0) {
        ++state.marked_count;
    } else {
        --state.marked_count;
    }
}

Command handle_results(State& state, const Key& key, std::size_t page_rows) {
    const auto page = static_cast<std::ptrdiff_t>(page_rows);
    switch (key.code) {
        case KeyCode::Up: select(state, -1, page_rows); break;
        case KeyCode::Down: select(state, 1, page_rows); break;
        case KeyCode::PageUp: select(state, -page, page_rows); break;
        case KeyCode::PageDown: select(state, page, page_rows); break;
        case KeyCode::Home: select(state, -static_cast<std::ptrdiff_t>(state.rows.size()), page_rows); break;
        case KeyCode::End: select(state, static_cast<std::ptrdiff_t>(state.rows.size()), page_rows); break;
        case KeyCode::Char:
            switch (key.ch) {
                case U' ':
                    if (!state.rows.empty()) {
                        toggle_mark(state, state.selected);
                        select(state, 1, page_rows);
                    }
                    break;
                case U'a': {
                    const bool all = std::all_of(state.rows.begin(), state.rows.end(), [&](std::size_t r) { return state.marked[r] != 0; });
                    for (std::size_t row = 0; row < state.rows.size(); ++row) {
                        if ((state.marked[state.rows[row]] != 0) == all) {
                            toggle_mark(state, row);
                        }
                    }
                    break;
                }
                case U'/': open_filter(state); break;
                case U'v': toggle_preview(state); break;
                case U's': open_save(state); break;
                case U'q': return Command::Quit;
                default: break;
            }
            break;
        default: break;
    }
    return Command::None;
}

Command handle_prompt(State& state, const Key& key) {
    LineEdit& edit = state.prompt == Prompt::Filter ? state.filter : state.save_path;
    if (key.code == KeyCode::Escape) {
        state.prompt = Prompt::None;
        return Command::None;
    }
    if (key.code != KeyCode::Enter) {
        edit.handle(key);
        return Command::None;
    }
    const Prompt prompt = state.prompt;
    state.prompt = Prompt::None;
    if (prompt == Prompt::Filter) {
        state.applied_filter = state.filter.utf8();
        apply_filter(state);
        return Command::None;
    }
    if (state.save_path.empty()) {
        state.message = "Type a file name to save to";
        state.prompt = Prompt::Save;
        return Command::None;
    }
    return Command::Save;
}

bool matches_filter(const ResultSet& results, const Match& match, std::string_view needle) {
    const PatternInfo& pattern = results.patterns[match.pattern];
    const auto has = [&](std::string_view text) { return to_lower_ascii(text).find(needle) != std::string::npos; };
    return has(pattern.label) || has(to_string(pattern.kind)) || has(format_address(match.address)) || has(results.preview_text(match));
}

std::string seconds_text(double seconds) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "%.2f s", seconds);
    return buffer;
}

}  // namespace

std::string_view to_string(EncodingChoice choice) {
    switch (choice) {
        case EncodingChoice::Ascii: return "ASCII";
        case EncodingChoice::Utf16: return "UTF-16";
        case EncodingChoice::Both: return "ASCII+UTF-16";
    }
    return "?";
}

std::string_view to_string(MemoryChoice choice) {
    switch (choice) {
        case MemoryChoice::All: return "all";
        case MemoryChoice::Private: return "private";
        case MemoryChoice::Image: return "image";
        case MemoryChoice::Mapped: return "mapped";
    }
    return "?";
}

std::string_view to_string(Phase phase) {
    switch (phase) {
        case Phase::Idle: return "Ready";
        case Phase::Scanning: return "Scanning";
        case Phase::Completed: return "Completed";
        case Phase::Cancelled: return "Cancelled";
        case Phase::TargetExited: return "Target exited";
        case Phase::Failed: return "Failed";
    }
    return "?";
}

ProgressView read_progress(const ScanProgress& progress, double seconds) {
    ProgressView view;
    view.bytes_total = progress.bytes_total.load(std::memory_order_relaxed);
    view.bytes_done = progress.bytes_done.load(std::memory_order_relaxed);
    view.regions_total = progress.regions_total.load(std::memory_order_relaxed);
    view.regions_done = progress.regions_done.load(std::memory_order_relaxed);
    view.matches = progress.matches.load(std::memory_order_relaxed);
    view.read_failures = progress.read_failures.load(std::memory_order_relaxed);
    view.seconds = seconds;
    return view;
}

State::State(ProcessSummary target)
    : process(std::move(target)),
      text("text, e.g. password"),
      signature("bytes, e.g. 48 8B ?? 89"),
      filter("address, pattern or text"),
      save_path("results.json, .csv or .txt") {}

bool in_search_panel(Focus focus) noexcept {
    return focus == Focus::Text || focus == Focus::Signature || focus == Focus::Encoding || focus == Focus::Case ||
           focus == Focus::Memory;
}

bool is_enabled(const State& state, Focus focus) {
    switch (focus) {
        case Focus::Scan: return !scanning(state);
        case Focus::Cancel: return scanning(state);
        case Focus::Save: return has_matches(state);
        default: return true;
    }
}

Command handle_key(State& state, const Key& key, std::size_t page_rows) {
    state.message.clear();
    page_rows = std::max<std::size_t>(page_rows, 1);
    switch (key.code) {
        case KeyCode::CtrlC: return scanning(state) ? Command::CancelScan : Command::Quit;
        case KeyCode::F10: return Command::Quit;
        case KeyCode::F5: return scanning(state) ? Command::None : Command::StartScan;
        case KeyCode::F2: open_save(state); return Command::None;
        case KeyCode::F3: toggle_preview(state); return Command::None;
        default: break;
    }
    if (state.prompt != Prompt::None) {
        return handle_prompt(state, key);
    }
    switch (key.code) {
        case KeyCode::Escape: return scanning(state) ? Command::CancelScan : Command::None;
        case KeyCode::Tab: move_focus(state, 1); return Command::None;
        case KeyCode::BackTab: move_focus(state, -1); return Command::None;
        default: break;
    }

    const bool space = key.code == KeyCode::Char && key.ch == U' ';
    switch (state.focus) {
        case Focus::Text:
        case Focus::Signature:
            if (key.code == KeyCode::Enter) {
                return scanning(state) ? Command::None : Command::StartScan;
            }
            if (key.code == KeyCode::Up || key.code == KeyCode::Down) {
                move_focus(state, key.code == KeyCode::Up ? -1 : 1);
                return Command::None;
            }
            (state.focus == Focus::Text ? state.text : state.signature).handle(key);
            return Command::None;
        case Focus::Encoding:
        case Focus::Case:
        case Focus::Memory: {
            if (key.code == KeyCode::Enter) {
                return scanning(state) ? Command::None : Command::StartScan;
            }
            if (key.code == KeyCode::Up || key.code == KeyCode::Down) {
                move_focus(state, key.code == KeyCode::Up ? -1 : 1);
                return Command::None;
            }
            const int step = key.code == KeyCode::Left ? -1 : (key.code == KeyCode::Right || space) ? 1 : 0;
            if (step == 0) {
                return Command::None;
            }
            if (state.focus == Focus::Encoding) {
                state.encoding = cycle(state.encoding, step, 3);
            } else if (state.focus == Focus::Case) {
                state.ignore_case = !state.ignore_case;
            } else {
                state.memory = cycle(state.memory, step, 4);
            }
            return Command::None;
        }
        case Focus::Results: return handle_results(state, key, page_rows);
        case Focus::Scan:
        case Focus::Cancel:
        case Focus::Save:
        case Focus::Quit:
            if (key.code == KeyCode::Left || key.code == KeyCode::Right) {
                move_focus(state, key.code == KeyCode::Left ? -1 : 1);
                return Command::None;
            }
            if (key.code != KeyCode::Enter && !space) {
                return Command::None;
            }
            if (state.focus == Focus::Scan) {
                return Command::StartScan;
            }
            if (state.focus == Focus::Cancel) {
                return Command::CancelScan;
            }
            if (state.focus == Focus::Save) {
                open_save(state);
                return Command::None;
            }
            return Command::Quit;
    }
    return Command::None;
}

ScanRequest build_request(const State& state) {
    ScanRequest request;
    const std::string text = state.text.utf8();
    if (!text.empty()) {
        const std::uint32_t encodings = state.encoding == EncodingChoice::Ascii   ? encoding::Ascii
                                        : state.encoding == EncodingChoice::Utf16 ? encoding::Utf16
                                                                                  : encoding::Both;
        for (auto& pattern : make_text_patterns(text, encodings, state.ignore_case)) {
            request.patterns.push_back(std::move(pattern));
        }
    }
    const std::string signature = state.signature.utf8();
    if (!signature.empty()) {
        request.patterns.push_back(parse_signature(signature));
    }
    if (request.patterns.empty()) {
        throw Error(ErrorCode::InvalidArgument, "Type a text or a byte signature first");
    }
    request.patterns = deduplicate(std::move(request.patterns));
    switch (state.memory) {
        case MemoryChoice::All: request.filter.types = type_class::All; break;
        case MemoryChoice::Private: request.filter.types = type_class::Private; break;
        case MemoryChoice::Image: request.filter.types = type_class::Image; break;
        case MemoryChoice::Mapped: request.filter.types = type_class::Mapped; break;
    }
    request.engine.preview_bytes = kPreviewBytes;
    request.engine.scan_threads = state.threads;
    return request;
}

void begin_scan(State& state) {
    state.phase = Phase::Scanning;
    state.progress = {};
    state.has_results = false;
    state.results = {};
    state.rows.clear();
    state.marked.clear();
    state.marked_count = 0;
    state.selected = 0;
    state.top = 0;
    state.prompt = Prompt::None;
    if (!is_enabled(state, state.focus)) {
        state.focus = Focus::Cancel;
    }
}

void finish_scan(State& state, ResultSet results, const ProgressView& final_progress) {
    const ScanStatus status = results.stats.status;
    state.phase = status == ScanStatus::Completed   ? Phase::Completed
                  : status == ScanStatus::Cancelled ? Phase::Cancelled
                                                    : Phase::TargetExited;
    state.results = std::move(results);
    state.has_results = true;
    state.progress = final_progress;
    state.progress.matches = state.results.matches.size();
    state.marked.assign(state.results.matches.size(), 0);
    state.marked_count = 0;
    apply_filter(state);

    const std::string count = count_matches(state.results.matches.size());
    if (state.phase == Phase::Completed) {
        state.message = "Scan completed: " + count + " in " + seconds_text(final_progress.seconds);
    } else if (state.phase == Phase::Cancelled) {
        state.message = "Scan cancelled: " + count + " in the scanned part";
    } else {
        state.message = "Target exited during the scan: " + count + " before that";
    }
    if (state.results.stats.truncated) {
        state.message += "; match limit reached";
    }
    if (!is_enabled(state, state.focus) || (in_search_panel(state.focus) && !state.rows.empty())) {
        state.focus = state.rows.empty() ? Focus::Text : Focus::Results;
    }
}

void fail_scan(State& state, std::string message) {
    state.phase = Phase::Failed;
    state.message = std::move(message);
    if (!is_enabled(state, state.focus)) {
        state.focus = Focus::Text;
    }
}

void apply_filter(State& state) {
    state.rows.clear();
    const std::string needle = to_lower_ascii(state.applied_filter);
    const auto& matches = state.results.matches;
    for (std::size_t i = 0; i < matches.size(); ++i) {
        if (needle.empty() || matches_filter(state.results, matches[i], needle)) {
            state.rows.push_back(i);
        }
    }
    state.selected = 0;
    state.top = 0;
}

const Match* selected_match(const State& state) {
    return state.selected < state.rows.size() ? &state.results.matches[state.rows[state.selected]] : nullptr;
}

std::size_t visible_top(const State& state, std::size_t page_rows) {
    page_rows = std::max<std::size_t>(page_rows, 1);
    std::size_t top = state.top;
    if (state.selected < top) {
        top = state.selected;
    } else if (state.selected >= top + page_rows) {
        top = state.selected - page_rows + 1;
    }
    const std::size_t max_top = state.rows.size() > page_rows ? state.rows.size() - page_rows : 0;
    return std::min(top, max_top);
}

std::vector<std::size_t> rows_to_save(const State& state) {
    if (state.marked_count == 0) {
        return state.rows;
    }
    std::vector<std::size_t> rows;
    for (std::size_t i = 0; i < state.marked.size(); ++i) {
        if (state.marked[i] != 0) {
            rows.push_back(i);
        }
    }
    return rows;
}

std::string count_matches(std::size_t count) {
    return std::to_string(count) + (count == 1 ? " match" : " matches");
}

OutputFormat format_for_path(std::string_view path) {
    const std::string extension = to_lower_ascii(wide_to_utf8(std::filesystem::path(utf8_to_wide(path)).extension().wstring()));
    if (extension == ".json") {
        return OutputFormat::Json;
    }
    if (extension == ".csv") {
        return OutputFormat::Csv;
    }
    return OutputFormat::Text;
}

}  // namespace mh::tui
