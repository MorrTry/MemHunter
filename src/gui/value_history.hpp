#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "gui/search.hpp"
#include "value/value_scan.hpp"

namespace mh::gui {

// The condition of a scan as the history lists it: "int32 = 86" for a first scan, "Уменьшилось" or "от 10 до 20"
// for a next one.
std::string describe_scan(const SearchForm& form, NumberType type, bool first);

struct HistoryStep {
    std::shared_ptr<const ValueCandidates> candidates;
    std::string label;
    std::uint64_t count = 0;
};

// The candidate lists of the value scans since the first one; one of them is current.
class ValueHistory {
public:
    // Drops the steps after the current one and appends the new step as current. While all steps together store
    // more than `budget` bytes, the oldest ones go, never the current one; 0 means no limit.
    void push(std::shared_ptr<const ValueCandidates> candidates, std::string label, std::uint64_t budget);
    void clear();

    bool empty() const noexcept { return steps_.empty(); }
    const std::vector<HistoryStep>& steps() const noexcept { return steps_; }
    std::size_t current() const noexcept { return current_; }
    bool can_undo() const noexcept { return current_ > 0; }
    bool can_redo() const noexcept { return current_ + 1 < steps_.size(); }
    void go_to(std::size_t step);
    // Some of the earliest steps were dropped to stay within the budget.
    bool trimmed() const noexcept { return trimmed_; }

private:
    std::vector<HistoryStep> steps_;
    std::size_t current_ = 0;
    bool trimmed_ = false;
};

}  // namespace mh::gui
