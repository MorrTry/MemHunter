#include "gui/results_table.hpp"

#include <algorithm>
#include <cstdio>

#include "common/text.hpp"
#include "gui/lang.hpp"

namespace mh::gui {

namespace {

const std::string kEmpty;

bool contains_lower(std::string_view text, std::string_view needle) {
    return to_lower_ascii(text).find(needle) != std::string::npos;
}

}  // namespace

std::string_view kind_name(PatternKind kind) {
    switch (kind) {
        case PatternKind::Ascii: return "ASCII";
        case PatternKind::Utf16: return "UTF-16";
        case PatternKind::Bytes: return tr("bytes", "байты");
        case PatternKind::Signature: return tr("signature", "сигнатура");
        case PatternKind::StringsAscii: return tr("ASCII string", "строка ASCII");
        case PatternKind::StringsUtf16: return tr("UTF-16 string", "строка UTF-16");
    }
    return "?";
}

std::string group_digits(std::uint64_t value) {
    const std::string digits = std::to_string(value);
    std::string out;
    for (std::size_t i = 0; i < digits.size(); ++i) {
        if (i != 0 && (digits.size() - i) % 3 == 0) {
            out.push_back(' ');
        }
        out.push_back(digits[i]);
    }
    return out;
}

std::string count_matches(std::uint64_t count) {
    return plural(count, true, "match", "matches", "совпадение", "совпадения", "совпадений");
}

std::string format_seconds(double seconds) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), tr("%.2f s", "%.2f с"), seconds);
    return buffer;
}

void ResultsTable::assign(ResultSet results) {
    results_ = std::move(results);
    has_results_ = true;
    modules_.clear();
    modules_.reserve(results_.regions.size());
    for (const auto& region : results_.regions) {
        modules_.push_back(region.module_name());
    }
    selected_match_.reset();
    rebuild();
}

void ResultsTable::clear() {
    results_ = {};
    has_results_ = false;
    modules_.clear();
    rows_.clear();
    selected_match_.reset();
    selected_row_.reset();
}

void ResultsTable::set_filter(std::string_view filter) {
    if (filter == filter_) {
        return;
    }
    filter_ = std::string(filter);
    rebuild();
}

void ResultsTable::sort_by(Column column, bool descending) {
    if (column == sort_ && descending == descending_) {
        return;
    }
    sort_ = column;
    descending_ = descending;
    rebuild();
}

void ResultsTable::select_row(std::size_t row) {
    if (row >= rows_.size()) {
        return;
    }
    selected_row_ = row;
    selected_match_ = rows_[row];
}

void ResultsTable::move_selection(std::ptrdiff_t delta) {
    if (rows_.empty()) {
        return;
    }
    const auto last = static_cast<std::ptrdiff_t>(rows_.size() - 1);
    const auto from = static_cast<std::ptrdiff_t>(selected_row_.value_or(0));
    select_row(static_cast<std::size_t>(std::clamp(from + delta, std::ptrdiff_t{0}, last)));
}

const Match* ResultsTable::selected_match() const {
    if (!selected_match_ || *selected_match_ >= results_.matches.size()) {
        return nullptr;
    }
    return &results_.matches[*selected_match_];
}

const std::string& ResultsTable::module_of(const Match& match) const {
    return match.region < modules_.size() ? modules_[match.region] : kEmpty;
}

std::string ResultsTable::cell(std::size_t match_index, Column column, PreviewMode preview) const {
    const Match& match = results_.matches[match_index];
    const Region* region = results_.region_of(match);
    switch (column) {
        case Column::Address: return format_address(match.address);
        case Column::Kind: return std::string(kind_name(results_.patterns[match.pattern].kind));
        case Column::Pattern: return results_.patterns[match.pattern].label;
        case Column::Length: return std::to_string(match.length);
        case Column::Protection: return region != nullptr ? protection_to_string(region->protect) : std::string();
        case Column::Type: return region != nullptr ? std::string(to_string(region->type)) : std::string();
        case Column::Module: return module_of(match);
        case Column::Preview: return preview == PreviewMode::Hex ? results_.preview_hex(match) : results_.preview_text(match);
    }
    return {};
}

void ResultsTable::rebuild() {
    rows_.clear();
    const auto& matches = results_.matches;
    const std::string needle = to_lower_ascii(filter_);
    rows_.reserve(needle.empty() ? matches.size() : 0);
    for (std::size_t i = 0; i < matches.size(); ++i) {
        if (!needle.empty()) {
            const Match& match = matches[i];
            const PatternInfo& pattern = results_.patterns[match.pattern];
            const bool hit = contains_lower(format_address(match.address), needle) || contains_lower(pattern.label, needle) ||
                             contains_lower(kind_name(pattern.kind), needle) || contains_lower(to_string(pattern.kind), needle) ||
                             contains_lower(module_of(match), needle) || contains_lower(results_.preview_text(match), needle) ||
                             contains_lower(results_.preview_hex(match), needle);
            if (!hit) {
                continue;
            }
        }
        rows_.push_back(i);
    }

    if (sort_ != Column::Address || descending_) {
        const auto protect = [&](const Match& m) {
            const Region* region = results_.region_of(m);
            return region != nullptr ? region->protect : 0u;
        };
        const auto type = [&](const Match& m) {
            const Region* region = results_.region_of(m);
            return region != nullptr ? static_cast<int>(region->type) : -1;
        };
        const auto less = [&](std::size_t a, std::size_t b) {
            const Match& x = matches[a];
            const Match& y = matches[b];
            switch (sort_) {
                case Column::Address: return x.address < y.address;
                case Column::Kind: return results_.patterns[x.pattern].kind < results_.patterns[y.pattern].kind;
                case Column::Pattern: return results_.patterns[x.pattern].label < results_.patterns[y.pattern].label;
                case Column::Length: return x.length < y.length;
                case Column::Protection: return protect(x) < protect(y);
                case Column::Type: return type(x) < type(y);
                case Column::Module: return module_of(x) < module_of(y);
                case Column::Preview: {
                    const auto p = results_.preview(x);
                    const auto q = results_.preview(y);
                    return std::lexicographical_compare(p.begin(), p.end(), q.begin(), q.end());
                }
            }
            return false;
        };
        // Rows start in address order, so a stable sort keeps equal keys ordered by address.
        if (descending_) {
            std::stable_sort(rows_.begin(), rows_.end(), [&](std::size_t a, std::size_t b) { return less(b, a); });
        } else {
            std::stable_sort(rows_.begin(), rows_.end(), less);
        }
    }

    selected_row_.reset();
    if (selected_match_) {
        const auto at = std::find(rows_.begin(), rows_.end(), *selected_match_);
        if (at != rows_.end()) {
            selected_row_ = static_cast<std::size_t>(at - rows_.begin());
        }
    }
    if (!selected_row_ && !rows_.empty()) {
        select_row(0);
    }
    if (rows_.empty()) {
        selected_match_.reset();
    }
}

}  // namespace mh::gui
