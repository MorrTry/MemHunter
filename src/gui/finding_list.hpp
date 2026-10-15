#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "inspect/inspect.hpp"

namespace mh::gui {

// "1 находка", "3 находки", "11 находок".
std::string count_findings(std::uint64_t count);

// What the last inspection of the target found, with only the kinds the user chose to see.
class FindingList {
public:
    // Selects the first shown finding; the chosen kinds stay.
    void assign(InspectReport report);
    void clear();

    bool has_report() const noexcept { return report_.has_value(); }
    // Only while has_report().
    const InspectReport& report() const { return *report_; }

    // Indices into report().findings of the shown findings.
    std::span<const std::size_t> rows() const noexcept { return rows_; }
    const Finding& finding(std::size_t row) const { return report_->findings[rows_[row]]; }

    bool shows(FindingKind kind) const noexcept { return (kinds_ & kind_bit(kind)) != 0; }
    // The selection stays on its finding while that finding is still shown.
    void toggle(FindingKind kind);

    std::optional<std::size_t> selected_row() const noexcept { return selected_; }
    const Finding* selected() const;
    void select_row(std::size_t row);
    void move_selection(std::ptrdiff_t delta);

private:
    void rebuild();

    std::optional<InspectReport> report_;
    std::uint32_t kinds_ = kAllFindingKinds;
    std::vector<std::size_t> rows_;
    std::optional<std::size_t> selected_;
};

}  // namespace mh::gui
