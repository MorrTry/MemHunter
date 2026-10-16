#include "gui/disasm_table.hpp"

#include <algorithm>

#include "gui/lang.hpp"
#include "gui/results_table.hpp"

namespace mh::gui {

std::string count_instructions(std::uint64_t count) {
    return plural(count, true, "instruction", "instructions", "инструкция", "инструкции", "инструкций");
}

void DisasmTable::assign(std::uint64_t address, bool wow64, std::vector<DisasmLine> lines) {
    has_result_ = true;
    address_ = address;
    wow64_ = wow64;
    lines_ = std::move(lines);
    selected_ = lines_.empty() ? std::nullopt : std::optional<std::size_t>(0);
}

void DisasmTable::clear() {
    has_result_ = false;
    address_ = 0;
    wow64_ = false;
    lines_.clear();
    selected_.reset();
}

const DisasmLine* DisasmTable::selected() const {
    return selected_ ? &line(*selected_) : nullptr;
}

void DisasmTable::select_row(std::size_t row) {
    if (row < lines_.size()) {
        selected_ = row;
    }
}

void DisasmTable::move_selection(std::ptrdiff_t delta) {
    if (lines_.empty()) {
        return;
    }
    const auto last = static_cast<std::ptrdiff_t>(lines_.size() - 1);
    const auto from = static_cast<std::ptrdiff_t>(selected_.value_or(0));
    select_row(static_cast<std::size_t>(std::clamp(from + delta, std::ptrdiff_t{0}, last)));
}

}  // namespace mh::gui
