#include "gui/finding_list.hpp"

#include <algorithm>

#include "gui/lang.hpp"
#include "gui/results_table.hpp"

namespace mh::gui {

std::string count_findings(std::uint64_t count) {
    return plural(count, true, "finding", "findings", "находка", "находки", "находок");
}

void FindingList::assign(InspectReport report) {
    report_ = std::move(report);
    selected_.reset();
    rebuild();
    if (!rows_.empty()) {
        selected_ = 0;
    }
}

void FindingList::clear() {
    report_.reset();
    rows_.clear();
    selected_.reset();
}

void FindingList::toggle(FindingKind kind) {
    const std::optional<std::size_t> finding = selected_ ? std::optional<std::size_t>(rows_[*selected_]) : std::nullopt;
    kinds_ ^= kind_bit(kind);
    rebuild();
    selected_.reset();
    if (finding) {
        if (const auto it = std::find(rows_.begin(), rows_.end(), *finding); it != rows_.end()) {
            selected_ = static_cast<std::size_t>(it - rows_.begin());
        }
    }
}

const Finding* FindingList::selected() const {
    return selected_ ? &finding(*selected_) : nullptr;
}

void FindingList::select_row(std::size_t row) {
    if (row < rows_.size()) {
        selected_ = row;
    }
}

void FindingList::move_selection(std::ptrdiff_t delta) {
    if (rows_.empty()) {
        return;
    }
    const auto last = static_cast<std::ptrdiff_t>(rows_.size() - 1);
    const auto from = static_cast<std::ptrdiff_t>(selected_.value_or(0));
    select_row(static_cast<std::size_t>(std::clamp(from + delta, std::ptrdiff_t{0}, last)));
}

void FindingList::rebuild() {
    rows_.clear();
    if (!report_) {
        return;
    }
    for (std::size_t i = 0; i < report_->findings.size(); ++i) {
        if (shows(report_->findings[i].kind)) {
            rows_.push_back(i);
        }
    }
}

}  // namespace mh::gui
