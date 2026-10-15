#include "gui/value_table.hpp"

#include <algorithm>
#include <span>

#include "gui/results_table.hpp"

namespace mh::gui {

std::string count_addresses(std::uint64_t count) {
    const std::uint64_t tens = count % 100;
    const std::uint64_t ones = count % 10;
    const char* word = (tens >= 11 && tens <= 14) ? "адресов" : ones == 1 ? "адрес" : (ones >= 2 && ones <= 4) ? "адреса" : "адресов";
    return group_digits(count) + " " + word;
}

void ValueTable::assign(std::shared_ptr<const ValueCandidates> candidates) {
    const std::optional<std::uint64_t> selected_address =
        selected_ ? std::optional<std::uint64_t>(rows_[*selected_].address) : std::nullopt;
    candidates_ = std::move(candidates);
    total_ = candidates_ ? candidates_->count() : 0;
    rows_ = candidates_ ? candidates_->list(kShownValues) : std::vector<ValueCandidate>{};
    live_.assign(rows_.size(), LiveValue{});
    selected_.reset();
    if (selected_address) {
        const auto it = std::lower_bound(rows_.begin(), rows_.end(), *selected_address,
                                         [](const ValueCandidate& row, std::uint64_t address) { return row.address < address; });
        if (it != rows_.end() && it->address == *selected_address) {
            selected_ = static_cast<std::size_t>(it - rows_.begin());
        }
    }
    if (!selected_ && !rows_.empty()) {
        selected_ = 0;
    }
}

void ValueTable::clear() {
    assign(nullptr);
}

void ValueTable::refresh(const MemorySource& memory, std::size_t first, std::size_t last) {
    if (!candidates_) {
        return;
    }
    const std::size_t size = size_of(candidates_->type);
    last = std::min(last, rows_.size());
    for (std::size_t row = first; row < last; ++row) {
        LiveValue& value = live_[row];
        std::uint64_t bits = 0;
        const ReadResult read = memory.read(rows_[row].address, std::as_writable_bytes(std::span(&bits, 1)).first(size));
        value.read = true;
        value.readable = read.bytes == size;
        value.bits = value.readable ? bits : 0;
    }
}

bool ValueTable::changed(std::size_t row) const {
    return live_[row].read && (!live_[row].readable || live_[row].bits != rows_[row].previous);
}

void ValueTable::select_row(std::size_t row) {
    if (row < rows_.size()) {
        selected_ = row;
    }
}

void ValueTable::move_selection(std::ptrdiff_t delta) {
    if (rows_.empty()) {
        return;
    }
    const auto last = static_cast<std::ptrdiff_t>(rows_.size() - 1);
    const auto from = static_cast<std::ptrdiff_t>(selected_.value_or(0));
    select_row(static_cast<std::size_t>(std::clamp(from + delta, std::ptrdiff_t{0}, last)));
}

const ValueCandidate* ValueTable::selected() const {
    return selected_ ? &rows_[*selected_] : nullptr;
}

std::string ValueTable::previous_text(std::size_t row) const {
    return format_value(candidates_->type, rows_[row].previous);
}

std::string ValueTable::current_text(std::size_t row) const {
    const LiveValue& value = live_[row];
    if (!value.read) {
        return {};
    }
    return value.readable ? format_value(candidates_->type, value.bits) : std::string("??");
}

const Region* ValueTable::region(std::size_t row) const {
    return candidates_->region_of(rows_[row].address);
}

std::string ValueTable::module(std::size_t row) const {
    const Region* found = region(row);
    return found != nullptr ? found->module_name() : std::string();
}

}  // namespace mh::gui
