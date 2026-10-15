#include "gui/pointer_list.hpp"

#include <algorithm>

#include "common/text.hpp"

namespace mh::gui {

void PointerList::assign(std::shared_ptr<const PointerChains> chains, PointerSearch search) {
    chains_ = std::move(chains);
    search_ = std::move(search);
    bases_.clear();
    live_.clear();
    selected_ = rows().empty() ? std::nullopt : std::optional<std::size_t>(0);
}

void PointerList::clear() {
    *this = PointerList{};
}

std::span<const PointerChain> PointerList::rows() const noexcept {
    return chains_ ? std::span<const PointerChain>(chains_->chains) : std::span<const PointerChain>();
}

void PointerList::set_modules(const ModuleMap& modules) {
    bases_ = chains_ ? module_bases(modules, chains_->modules) : std::vector<std::uint64_t>{};
    live_.clear();
}

void PointerList::select_row(std::size_t row) {
    if (row < rows().size()) {
        selected_ = row;
    }
}

void PointerList::move_selection(std::ptrdiff_t delta) {
    const std::size_t count = rows().size();
    if (count == 0) {
        return;
    }
    const auto last = static_cast<std::ptrdiff_t>(count - 1);
    const auto from = static_cast<std::ptrdiff_t>(selected_.value_or(0));
    select_row(static_cast<std::size_t>(std::clamp(from + delta, std::ptrdiff_t{0}, last)));
}

void PointerList::refresh(const MemorySource& memory, std::size_t first, std::size_t last) {
    last = std::min(last, rows().size());
    WatchEntry entry = search_.target;
    for (std::size_t row = first; row < last; ++row) {
        Live live;
        live.address = resolve_chain(memory, bases_, chains_->chains[row], chains_->pointer_size);
        if (live.address) {
            entry.address = *live.address;
            live.bytes = read_watch_value(memory, entry);
        }
        live_[row] = std::move(live);
    }
}

std::optional<std::uint64_t> PointerList::address(std::size_t row) const {
    const auto found = live_.find(row);
    return found != live_.end() ? found->second.address : std::nullopt;
}

std::string PointerList::base_text(std::size_t row) const {
    const PointerChain& chain = chains_->chains[row];
    return format_pointer_base(chains_->modules[chain.module], chain.base_offset);
}

std::string PointerList::offsets_text(std::size_t row) const {
    return format_pointer_offsets(chains_->chains[row].steps());
}

std::string PointerList::path_text(std::size_t row) const {
    return format_pointer_path(path(row));
}

std::string PointerList::address_text(std::size_t row) const {
    const auto found = live_.find(row);
    if (found == live_.end()) {
        return {};
    }
    return found->second.address ? format_address(*found->second.address) : std::string("??");
}

std::string PointerList::value_text(std::size_t row) const {
    const auto found = live_.find(row);
    if (found == live_.end()) {
        return {};
    }
    return found->second.bytes ? format_watch_value(search_.target, *found->second.bytes) : std::string("??");
}

PointerPath PointerList::path(std::size_t row) const {
    return path_of(*chains_, row);
}

WatchEntry PointerList::watch_entry(std::size_t row) const {
    WatchEntry entry = make_watch_entry(address(row).value_or(0), search_.target.type, search_.target.length,
                                        search_.target.description);
    entry.path = path(row);
    return entry;
}

}  // namespace mh::gui
