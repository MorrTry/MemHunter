#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "memory/memory_source.hpp"
#include "value/value_scan.hpp"

namespace mh::gui {

inline constexpr std::size_t kShownValues = 10'000;

// "1 адрес", "3 адреса", "25 адресов".
std::string count_addresses(std::uint64_t count);

// The value of a shown candidate as it is now.
struct LiveValue {
    bool read = false;
    bool readable = false;
    std::uint64_t bits = 0;
};

// Candidates of the value scan as the table shows them: the first kShownValues by address, their current
// values for the rows on screen and one selected row.
class ValueTable {
public:
    void assign(std::shared_ptr<const ValueCandidates> candidates);
    void clear();

    bool has_values() const noexcept { return candidates_ != nullptr; }
    const std::shared_ptr<const ValueCandidates>& candidates() const noexcept { return candidates_; }
    std::uint64_t total() const noexcept { return total_; }
    const std::vector<ValueCandidate>& rows() const noexcept { return rows_; }

    // Reads the current values of rows [first, last).
    void refresh(const MemorySource& memory, std::size_t first, std::size_t last);
    const LiveValue& live(std::size_t row) const { return live_[row]; }
    // Read and different from the value of the last scan.
    bool changed(std::size_t row) const;

    // The selection follows the address through later scans while it stays among the shown rows; otherwise
    // the first row is selected.
    std::optional<std::size_t> selected_row() const noexcept { return selected_; }
    void select_row(std::size_t row);
    void move_selection(std::ptrdiff_t delta);
    const ValueCandidate* selected() const;

    std::string previous_text(std::size_t row) const;
    // Empty until read, "??" when unreadable.
    std::string current_text(std::size_t row) const;
    const Region* region(std::size_t row) const;
    std::string module(std::size_t row) const;

private:
    std::shared_ptr<const ValueCandidates> candidates_;
    std::uint64_t total_ = 0;
    std::vector<ValueCandidate> rows_;
    std::vector<LiveValue> live_;
    std::optional<std::size_t> selected_;
};

}  // namespace mh::gui
