#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "pipeline/scan_session.hpp"
#include "results/export.hpp"
#include "results/result_set.hpp"
#include "tui/input.hpp"

namespace mh::tui {

enum class Focus : std::uint8_t { Text, Signature, Encoding, Case, Memory, Results, Scan, Cancel, Save, Quit };
enum class EncodingChoice : std::uint8_t { Ascii, Utf16, Both };
enum class MemoryChoice : std::uint8_t { All, Private, Image, Mapped };
enum class PreviewMode : std::uint8_t { Hex, Text };
enum class Prompt : std::uint8_t { None, Filter, Save };
enum class Phase : std::uint8_t { Idle, Scanning, Completed, Cancelled, TargetExited, Failed };

// What the application loop has to do after a key press; everything else is a pure state change.
enum class Command : std::uint8_t { None, StartScan, CancelScan, Save, Quit };

inline constexpr std::size_t kPreviewBytes = 48;

std::string_view to_string(EncodingChoice choice);
std::string_view to_string(MemoryChoice choice);
std::string_view to_string(Phase phase);

// Counters of the running scan, copied from ScanProgress once per frame.
struct ProgressView {
    std::uint64_t bytes_total = 0;
    std::uint64_t bytes_done = 0;
    std::uint64_t regions_total = 0;
    std::uint64_t regions_done = 0;
    std::uint64_t matches = 0;
    std::uint64_t read_failures = 0;
    double seconds = 0;
};

ProgressView read_progress(const ScanProgress& progress, double seconds);

struct State {
    explicit State(ProcessSummary target);

    ProcessSummary process;
    unsigned threads = 0;
    Focus focus = Focus::Text;
    LineEdit text;
    LineEdit signature;
    EncodingChoice encoding = EncodingChoice::Both;
    bool ignore_case = false;
    MemoryChoice memory = MemoryChoice::All;
    PreviewMode preview = PreviewMode::Hex;

    Prompt prompt = Prompt::None;
    LineEdit filter;
    LineEdit save_path;
    std::string applied_filter;

    Phase phase = Phase::Idle;
    ProgressView progress;
    bool has_results = false;
    ResultSet results;
    // Indices into results.matches that pass the filter, in address order.
    std::vector<std::size_t> rows;
    std::vector<std::uint8_t> marked;
    std::size_t marked_count = 0;
    std::size_t selected = 0;
    std::size_t top = 0;
    std::string message;
};

bool is_enabled(const State& state, Focus focus);
bool in_search_panel(Focus focus) noexcept;

// `page_rows` is the number of result rows on screen, used for paging and scrolling.
Command handle_key(State& state, const Key& key, std::size_t page_rows);

// Throws Error when there is nothing to search for or the signature is invalid.
ScanRequest build_request(const State& state);

void begin_scan(State& state);
void finish_scan(State& state, ResultSet results, const ProgressView& final_progress);
void fail_scan(State& state, std::string message);
void apply_filter(State& state);

const Match* selected_match(const State& state);
// First row to show so that the selection is visible on a page of `page_rows`.
std::size_t visible_top(const State& state, std::size_t page_rows);
// Marked matches when there are any, otherwise every row that passes the filter.
std::vector<std::size_t> rows_to_save(const State& state);
OutputFormat format_for_path(std::string_view path);
// "1 match", "2 matches".
std::string count_matches(std::size_t count);

}  // namespace mh::tui
