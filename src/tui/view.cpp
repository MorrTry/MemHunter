#include "tui/view.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <string>
#include <utility>

#include "common/text.hpp"
#include "memory/region.hpp"

namespace mh::tui {

namespace {

constexpr std::size_t kDetailsHeight = 7;
constexpr std::size_t kSwitchColumn = 35;
constexpr std::size_t kLabelWidth = 10;
constexpr std::size_t kDumpBytesPerLine = 16;

struct Button {
    std::string_view label;
    std::string_view key;
    Focus focus;
};

constexpr std::array kButtons{Button{"Scan", "F5", Focus::Scan}, Button{"Cancel", "Esc", Focus::Cancel},
                              Button{"Save", "F2", Focus::Save}, Button{"Quit", "F10", Focus::Quit}};

std::string printf_string(const char* format, double value) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), format, value);
    return buffer;
}

double fraction_done(const State& state) {
    const ProgressView& p = state.progress;
    if (p.bytes_total == 0) {
        return state.phase == Phase::Completed ? 1.0 : 0.0;
    }
    return std::min(1.0, static_cast<double>(p.bytes_done) / static_cast<double>(p.bytes_total));
}

void center(Screen& screen, std::size_t y, std::string_view text, Style style = Style::Normal) {
    const std::size_t width = std::min(text_width(text), screen.width());
    screen.text((screen.width() - width) / 2, y, text, style, screen.width());
}

void panel(Screen& screen, std::size_t y, std::size_t height, const std::string& title, bool focused) {
    screen.frame(0, y, screen.width(), height, focused ? theme::kFocusedPanel : theme::kPanel);
    screen.text(2, y, " " + title + " ", Style::Strong, screen.width() - 4);
}

void draw_input(Screen& screen, std::size_t x, std::size_t y, std::size_t width, const LineEdit& edit, bool focused) {
    screen.put(x, y, U'[');
    screen.put(x + width - 1, y, U']');
    const std::size_t inner = width - 2;
    const std::size_t left = x + 1;
    if (edit.empty()) {
        // The cursor stands before the placeholder, and the placeholder is in parentheses, so it cannot be
        // mistaken for typed text.
        const std::string hint = "(" + edit.placeholder() + ")";
        if (focused) {
            screen.put(left, y, U' ', Style::Inverse);
            screen.text(left + 2, y, hint, Style::Normal, inner - 2);
        } else {
            screen.text(left, y, hint, Style::Normal, inner);
        }
        return;
    }
    const std::u32string& text = edit.text();
    const std::size_t offset = edit.cursor() >= inner ? edit.cursor() - inner + 1 : 0;
    std::size_t column = 0;
    for (std::size_t i = offset; i < text.size() && column < inner; ++i) {
        std::string utf8;
        append_utf8(utf8, text[i]);
        const std::size_t used = screen.text(left + column, y, utf8, Style::Normal, inner - column);
        if (used == 0) {
            break;
        }
        if (focused && i == edit.cursor()) {
            screen.restyle(left + column, y, used, Style::Inverse);
        }
        column += used;
    }
    if (focused && edit.cursor() == text.size()) {
        screen.put(left + std::min(column, inner - 1), y, U' ', Style::Inverse);
    }
}

std::size_t draw_switch(Screen& screen, std::size_t x, std::size_t y, std::string_view label, std::string_view value, bool focused) {
    std::size_t used = screen.text(x, y, label, focused ? Style::Strong : Style::Normal) + 1;
    used += screen.text(x + used, y, "< " + std::string(value) + " >", focused ? Style::Inverse : Style::Normal);
    return used;
}

void draw_top_bar(Screen& screen, const State& state) {
    std::size_t buttons_width = 0;
    for (const auto& button : kButtons) {
        buttons_width += button.label.size() + button.key.size() + 4;
    }
    --buttons_width;
    std::size_t x = screen.width() - buttons_width;
    const std::size_t limit = x - 1;
    for (const auto& button : kButtons) {
        const std::string text = std::string(button.label) + " " + std::string(button.key);
        if (is_enabled(state, button.focus)) {
            screen.text(x, 0, "[" + text + "]", state.focus == button.focus ? Style::Inverse : Style::Normal);
        } else {
            screen.text(x, 0, " " + text + " ", Style::Normal);
        }
        x += text.size() + 3;
    }

    // At the minimum width the name, a five-digit pid and the longest state still fit; the process name gets
    // whatever room is left.
    std::string phase(to_string(state.phase));
    if (state.phase == Phase::Scanning) {
        phase += " " + printf_string("%.0f%%", fraction_done(state) * 100);
    }
    const std::pair<std::string, Style> parts[] = {
        {"MemHunter", Style::Strong},
        {"pid " + std::to_string(state.process.pid), Style::Normal},
        {phase, Style::Strong},
        {state.process.name + (state.process.wow64 ? " (32-bit)" : " (64-bit)"), Style::Normal},
    };
    std::size_t left = 1;
    for (const auto& [text, style] : parts) {
        if (left >= limit) {
            break;
        }
        left += screen.text(left, 0, text, style, limit - left) + 2;
    }
}

void draw_search(Screen& screen, const State& state, const Layout& layout) {
    const std::size_t y = layout.search_y;
    panel(screen, y, 4, "Search", in_search_panel(state.focus));
    const std::size_t right = screen.width() - 2 - kSwitchColumn;
    const std::size_t input_x = 2 + kLabelWidth;
    const std::size_t input_width = right - 2 - input_x;

    const auto label = [&](std::size_t row, std::string_view text, Focus focus) {
        screen.text(2, row, text, state.focus == focus ? Style::Inverse : Style::Normal);
    };
    label(y + 1, "Text", Focus::Text);
    draw_input(screen, input_x, y + 1, input_width, state.text, state.focus == Focus::Text);
    label(y + 2, "Signature", Focus::Signature);
    draw_input(screen, input_x, y + 2, input_width, state.signature, state.focus == Focus::Signature);

    draw_switch(screen, right, y + 1, "Encoding", to_string(state.encoding), state.focus == Focus::Encoding);
    const std::size_t used = draw_switch(screen, right, y + 2, "Case", state.ignore_case ? "ignore" : "exact", state.focus == Focus::Case);
    draw_switch(screen, right + used + 2, y + 2, "Memory", to_string(state.memory), state.focus == Focus::Memory);
}

void draw_progress(Screen& screen, const State& state, const Layout& layout) {
    const std::size_t y = layout.progress_y;
    panel(screen, y, 3, "Progress", false);
    const ProgressView& p = state.progress;
    const double fraction = fraction_done(state);
    const std::string info = printf_string("%5.1f%%", fraction * 100) + "  Read " + format_size(p.bytes_done) + " of " +
                             format_size(p.bytes_total) + "  Regions " + std::to_string(p.regions_done) + "/" +
                             std::to_string(p.regions_total) + "  Matches " + std::to_string(p.matches);
    const std::size_t inner = screen.width() - 4;
    const std::size_t info_width = text_width(info);
    const std::size_t bar = inner > info_width + 13 ? inner - info_width - 3 : 10;
    const auto filled = static_cast<std::size_t>(std::lround(fraction * static_cast<double>(bar)));
    screen.put(2, y + 1, U'[');
    screen.fill(3, y + 1, std::min(filled, bar), 1, theme::kBarFilled);
    screen.put(3 + bar, y + 1, U']');
    screen.text(5 + bar, y + 1, info, Style::Normal, inner - bar - 3);
}

std::string results_title(const State& state) {
    std::string title = "Results";
    if (!state.has_results) {
        return title;
    }
    title += ": " + count_matches(state.results.matches.size());
    if (state.results.stats.truncated) {
        title += " (limit reached)";
    }
    if (state.marked_count > 0) {
        title += ", " + std::to_string(state.marked_count) + " marked";
    }
    if (!state.applied_filter.empty()) {
        title += ", filter \"" + state.applied_filter + "\" shows " + std::to_string(state.rows.size());
    }
    if (!state.rows.empty()) {
        title += ", row " + std::to_string(state.selected + 1) + "/" + std::to_string(state.rows.size());
    }
    return title;
}

std::string empty_results_text(const State& state) {
    switch (state.phase) {
        case Phase::Idle: return "Type a text or a byte signature above and press Enter";
        case Phase::Scanning: return "Scanning; results appear when the scan finishes (Esc cancels)";
        case Phase::Failed: return "The scan did not run; see the status line";
        default: break;
    }
    if (state.results.matches.empty()) {
        return "No matches";
    }
    return "No match passes the filter; press / to change it";
}

void draw_results(Screen& screen, const State& state, const Layout& layout) {
    const std::size_t y = layout.results_y;
    const bool focused = state.focus == Focus::Results;
    panel(screen, y, layout.results_height, results_title(state), focused);
    const std::size_t inner = screen.width() - 4;
    const std::size_t address_x = 4;
    const std::size_t kind_x = address_x + 19;
    const std::size_t pattern_width = std::clamp<std::size_t>(inner / 5, 8, 24);
    const std::size_t pattern_x = kind_x + 11;
    const std::size_t length_x = pattern_x + pattern_width + 1;
    const std::size_t preview_x = length_x + 7;
    const std::size_t preview_width = 2 + inner - preview_x;

    const std::size_t header = y + 1;
    screen.text(address_x, header, "Address", Style::Strong);
    screen.text(kind_x, header, "Kind", Style::Strong);
    screen.text(pattern_x, header, "Pattern", Style::Strong);
    screen.text(length_x, header, "   Len", Style::Strong);
    screen.text(preview_x, header, state.preview == PreviewMode::Hex ? "Preview (hex)" : "Preview (text)", Style::Strong, preview_width);

    if (state.rows.empty()) {
        center(screen, header + 1 + (layout.page_rows - 1) / 2, empty_results_text(state));
        return;
    }
    const std::size_t top = visible_top(state, layout.page_rows);
    for (std::size_t i = top; i < std::min(top + layout.page_rows, state.rows.size()); ++i) {
        const std::size_t row = header + 1 + (i - top);
        const Match& match = state.results.matches[state.rows[i]];
        const PatternInfo& pattern = state.results.patterns[match.pattern];
        if (state.marked[state.rows[i]] != 0) {
            screen.put(2, row, theme::kMarked);
        }
        screen.text(address_x, row, format_address(match.address));
        screen.text(kind_x, row, to_string(pattern.kind), Style::Normal, 10);
        screen.text(pattern_x, row, pattern.label, Style::Normal, pattern_width);
        char length[16];
        std::snprintf(length, sizeof(length), "%6u", static_cast<unsigned>(match.length));
        screen.text(length_x, row, length);
        std::string preview = state.preview == PreviewMode::Hex ? state.results.preview_hex(match) : state.results.preview_text(match);
        if (state.preview == PreviewMode::Hex && preview.size() > preview_width) {
            preview.resize(preview_width >= 2 ? (preview_width + 1) / 3 * 3 - 1 : 0);
        }
        screen.text(preview_x, row, preview, Style::Normal, preview_width);
        if (i == state.selected) {
            screen.restyle(2, row, inner, focused ? Style::Inverse : Style::Strong);
        }
    }
}

void draw_details(Screen& screen, const State& state, const Layout& layout) {
    const std::size_t y = layout.details_y;
    panel(screen, y, kDetailsHeight, "Details", false);
    const Match* match = selected_match(state);
    const std::size_t inner = screen.width() - 4;
    if (match == nullptr) {
        screen.text(2, y + 1, "No match selected", Style::Normal, inner);
        return;
    }
    const ResultSet& results = state.results;
    const PatternInfo& pattern = results.patterns[match->pattern];
    screen.text(2, y + 1, "Match", Style::Strong);
    screen.text(11, y + 1,
                format_address(match->address) + "  " + std::string(to_string(pattern.kind)) + " pattern \"" + pattern.label + "\"  " +
                    std::to_string(match->length) + " bytes",
                Style::Normal, inner - 9);
    screen.text(2, y + 2, "Region", Style::Strong);
    if (const Region* region = results.region_of(*match)) {
        std::string text = format_address(region->base) + "  " + format_size(region->size) + "  " + protection_to_string(region->protect) +
                           "  " + std::string(to_string(region->type));
        if (const std::string module = region->module_name(); !module.empty()) {
            text += "  " + module;
        }
        text += "  (+" + format_hex(match->address - region->base) + ")";
        screen.text(11, y + 2, text, Style::Normal, inner - 9);
    } else {
        screen.text(11, y + 2, "unknown", Style::Normal, inner - 9);
    }

    const auto bytes = results.preview(*match);
    if (state.preview == PreviewMode::Hex) {
        for (std::size_t line = 0; line < 3; ++line) {
            const std::size_t offset = line * kDumpBytesPerLine;
            if (offset >= bytes.size()) {
                break;
            }
            const auto chunk = bytes.subspan(offset, std::min(kDumpBytesPerLine, bytes.size() - offset));
            std::string hex = hex_preview(chunk);
            hex.resize(kDumpBytesPerLine * 3 - 1, ' ');
            char label[16];
            std::snprintf(label, sizeof(label), "+%04zX", offset);
            screen.text(2, y + 3 + line, label, Style::Strong);
            screen.text(11, y + 3 + line, hex + "  " + ascii_preview(chunk), Style::Normal, inner - 9);
        }
        return;
    }
    const std::string text = results.preview_text(*match);
    screen.text(2, y + 3, "Text", Style::Strong);
    const std::size_t width = inner - 9;
    std::size_t start = 0;
    for (std::size_t line = 0; line < 3 && start < text.size(); ++line) {
        // Preview text is ASCII (non-ASCII bytes are shown as '.'), so bytes and cells correspond.
        screen.text(11, y + 3 + line, std::string_view(text).substr(start, width), Style::Normal, width);
        start += width;
    }
}

std::string_view hints(const State& state) {
    if (state.prompt == Prompt::Filter) {
        return "Enter apply the filter  Esc cancel";
    }
    if (state.prompt == Prompt::Save) {
        return "Enter save (.json, .csv, any other name: text)  Esc cancel";
    }
    if (state.phase == Phase::Scanning) {
        return "Esc cancel scan  Tab next  F10 quit";
    }
    switch (state.focus) {
        case Focus::Text:
        case Focus::Signature: return "Enter scan  Tab next field  F3 hex/text  F10 quit";
        case Focus::Encoding:
        case Focus::Case:
        case Focus::Memory: return "←→ change  Enter scan  Tab next  F10 quit";
        case Focus::Results: return "↑↓ PgUp PgDn  Space mark  a all  / filter  v hex/text  F2 save  q quit";
        default: return "Enter press  ←→ choose  Tab next  F10 quit";
    }
}

void draw_status(Screen& screen, const State& state, const Layout& layout) {
    const std::size_t y = layout.status_y;
    const std::size_t key_bar = layout.details_y + kDetailsHeight - 1;
    screen.text(2, key_bar, " " + std::string(hints(state)) + " ", Style::Normal, screen.width() - 4);
    if (state.prompt != Prompt::None) {
        const bool filter = state.prompt == Prompt::Filter;
        const std::size_t x = screen.text(0, y, filter ? " Filter " : " Save to ", Style::Strong);
        draw_input(screen, x, y, screen.width() - x - 1, filter ? state.filter : state.save_path, true);
        return;
    }
    const ProgressView& p = state.progress;
    const std::string speed = p.seconds > 0 ? format_rate(static_cast<double>(p.bytes_done) / p.seconds) : "-";
    const std::string stats = " Speed " + speed + "  Read errors " + std::to_string(p.read_failures) + "  Time " +
                              printf_string("%.2f s", p.seconds) + " ";
    // A message that does not fit next to the counters takes the whole line until the next key press.
    if (!state.message.empty() && text_width(stats) + 2 + text_width(state.message) > screen.width()) {
        screen.text(1, y, state.message, Style::Strong, screen.width() - 1);
        return;
    }
    std::size_t x = screen.text(0, y, stats);
    screen.put(x, y, theme::kSeparator);
    x += 2;
    if (x < screen.width()) {
        screen.text(x, y, state.message.empty() ? std::string(to_string(state.phase)) : state.message,
                    state.message.empty() ? Style::Normal : Style::Strong, screen.width() - x);
    }
}

}  // namespace

Layout layout_for(std::size_t width, std::size_t height) {
    Layout layout;
    layout.width = width;
    layout.height = height;
    if (width < theme::kMinWidth || height < theme::kMinHeight) {
        layout.too_small = true;
        return layout;
    }
    layout.status_y = height - 1;
    layout.details_y = layout.status_y - kDetailsHeight;
    layout.results_height = layout.details_y - layout.results_y;
    layout.page_rows = layout.results_height - 3;
    return layout;
}

void draw(Screen& screen, const State& state) {
    screen.fill(0, 0, screen.width(), screen.height(), U' ');
    const Layout layout = layout_for(screen.width(), screen.height());
    if (layout.too_small) {
        if (screen.height() >= 2) {
            const std::size_t y = screen.height() / 2 - 1;
            center(screen, y,
                   "Terminal too small: " + std::to_string(theme::kMinWidth) + "x" + std::to_string(theme::kMinHeight) + " needed, now " +
                       std::to_string(screen.width()) + "x" + std::to_string(screen.height()),
                   Style::Strong);
            center(screen, y + 1, "Enlarge the window, or press F10 to quit");
        }
        return;
    }
    draw_top_bar(screen, state);
    draw_search(screen, state, layout);
    draw_progress(screen, state, layout);
    draw_results(screen, state, layout);
    draw_details(screen, state, layout);
    draw_status(screen, state, layout);
}

}  // namespace mh::tui
