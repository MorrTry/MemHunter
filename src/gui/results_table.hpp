#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "results/result_set.hpp"

namespace mh::gui {

enum class Column : std::uint8_t { Address, Kind, Pattern, Length, Protection, Type, Module, Preview };
inline constexpr std::size_t kColumnCount = 8;

enum class PreviewMode : std::uint8_t { Hex, Text };

std::string_view kind_name(PatternKind kind);

// "1 234 567": thousands separated by spaces.
std::string group_digits(std::uint64_t value);
// "1 совпадение", "3 совпадения", "25 совпадений".
std::string count_matches(std::uint64_t count);
// "0.42 с".
std::string format_seconds(double seconds);

// The results of the last scan as the table shows them: filtered, sorted and with one selected match. Row
// numbers index rows(); match numbers index results().matches.
class ResultsTable {
public:
    void assign(ResultSet results);
    void clear();

    bool has_results() const noexcept { return has_results_; }
    const ResultSet& results() const noexcept { return results_; }
    const std::vector<std::size_t>& rows() const noexcept { return rows_; }

    // Case-insensitive substring of the address, kind, pattern, module or text preview.
    void set_filter(std::string_view filter);
    const std::string& filter() const noexcept { return filter_; }

    void sort_by(Column column, bool descending);
    Column sort_column() const noexcept { return sort_; }
    bool sort_descending() const noexcept { return descending_; }

    // The selection follows the match through filtering and sorting while it stays visible.
    std::optional<std::size_t> selected_row() const noexcept { return selected_row_; }
    void select_row(std::size_t row);
    void move_selection(std::ptrdiff_t delta);
    const Match* selected_match() const;

    std::string cell(std::size_t match, Column column, PreviewMode preview) const;
    const std::string& module_of(const Match& match) const;

private:
    void rebuild();

    ResultSet results_;
    bool has_results_ = false;
    std::vector<std::string> modules_;
    std::vector<std::size_t> rows_;
    std::string filter_;
    Column sort_ = Column::Address;
    bool descending_ = false;
    std::optional<std::size_t> selected_match_;
    std::optional<std::size_t> selected_row_;
};

}  // namespace mh::gui
