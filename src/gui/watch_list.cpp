#include "gui/watch_list.hpp"

#include <algorithm>
#include <cstring>

#include "common/text.hpp"
#include "gui/lang.hpp"

namespace mh::gui {

static_assert(static_cast<int>(WatchType::Int8) == static_cast<int>(ValueType::Int8) &&
              static_cast<int>(WatchType::Double) == static_cast<int>(ValueType::Double));

namespace {

bool same_value(const WatchEntry& a, const WatchEntry& b) {
    const bool same_place = a.path || b.path ? a.path == b.path : a.address == b.address;
    return same_place && a.type == b.type && a.length == b.length;
}

// The entry with its length clamped like make_watch_entry does.
WatchEntry normalized(WatchEntry entry) {
    std::optional<PointerPath> path = std::move(entry.path);
    entry = make_watch_entry(entry.address, entry.type, entry.length, std::move(entry.description));
    entry.path = std::move(path);
    return entry;
}

int hex_digit(char c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

}  // namespace

std::string_view to_string(WatchType type) {
    switch (type) {
        case WatchType::Ascii: return "ascii";
        case WatchType::Utf16: return "utf16";
        case WatchType::Bytes: return "bytes";
        default: return mh::to_string(static_cast<ValueType>(type));
    }
}

WatchType watch_type(ValueType type) noexcept {
    return static_cast<WatchType>(type);
}

std::optional<ValueType> value_type(WatchType type) noexcept {
    if (has_length(type)) {
        return std::nullopt;
    }
    return static_cast<ValueType>(type);
}

bool has_length(WatchType type) noexcept {
    return type == WatchType::Ascii || type == WatchType::Utf16 || type == WatchType::Bytes;
}

std::uint32_t max_length(WatchType type) noexcept {
    switch (type) {
        case WatchType::Ascii:
        case WatchType::Bytes: return kMaxWatchBytes;
        case WatchType::Utf16: return kMaxWatchBytes / 2;
        default: return 0;
    }
}

std::size_t WatchEntry::size() const noexcept {
    if (const auto number = value_type(type)) {
        return size_of(*number);
    }
    return type == WatchType::Utf16 ? std::size_t{length} * 2 : length;
}

WatchEntry make_watch_entry(std::uint64_t address, WatchType type, std::uint32_t length, std::string description) {
    length = has_length(type) ? std::clamp<std::uint32_t>(length, 1, max_length(type)) : 0;
    return WatchEntry{.address = address, .type = type, .length = length, .description = std::move(description), .path = {}};
}

WatchEntry watch_entry_for(std::uint64_t address, PatternKind kind, std::uint32_t match_length) {
    if (is_utf16_kind(kind)) {
        return make_watch_entry(address, WatchType::Utf16, match_length / 2);
    }
    const bool text = kind == PatternKind::Ascii || kind == PatternKind::StringsAscii;
    return make_watch_entry(address, text ? WatchType::Ascii : WatchType::Bytes, match_length);
}

std::string type_label(const WatchEntry& entry) {
    switch (entry.type) {
        case WatchType::Ascii: return "ASCII, " + plural(entry.length, false, "character", "characters", "символ", "символа", "символов");
        case WatchType::Utf16: return "UTF-16, " + plural(entry.length, false, "character", "characters", "символ", "символа", "символов");
        case WatchType::Bytes: return plural(entry.length, false, "byte", "bytes", "байт", "байта", "байт");
        default: return std::string(to_string(entry.type));
    }
}

std::string format_watch_value(const WatchEntry& entry, std::span<const std::byte> bytes) {
    bytes = bytes.first(std::min(bytes.size(), entry.size()));
    switch (entry.type) {
        case WatchType::Ascii: {
            const auto end = std::find(bytes.begin(), bytes.end(), std::byte{0});
            return ascii_preview(bytes.first(static_cast<std::size_t>(end - bytes.begin())));
        }
        case WatchType::Utf16: {
            std::size_t units = 0;
            while (units * 2 + 1 < bytes.size() && (bytes[units * 2] != std::byte{0} || bytes[units * 2 + 1] != std::byte{0})) {
                ++units;
            }
            return utf16_preview(bytes.first(units * 2));
        }
        case WatchType::Bytes: return hex_preview(bytes);
        default: {
            std::uint64_t bits = 0;
            std::memcpy(&bits, bytes.data(), std::min(bytes.size(), sizeof(bits)));
            return format_value(*value_type(entry.type), bits);
        }
    }
}

std::optional<std::vector<std::byte>> read_watch_value(const MemorySource& memory, const WatchEntry& entry) {
    std::vector<std::byte> bytes(entry.size());
    if (memory.read(entry.address, bytes).bytes != bytes.size()) {
        return std::nullopt;
    }
    return bytes;
}

std::optional<std::uint64_t> parse_address(std::string_view text) {
    const auto first = text.find_first_not_of(" \t");
    if (first == std::string_view::npos) {
        return std::nullopt;
    }
    text = text.substr(first, text.find_last_not_of(" \t") - first + 1);
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        text.remove_prefix(2);
    }
    if (text.empty()) {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    std::size_t digits = 0;
    for (const char c : text) {
        const int digit = hex_digit(c);
        if (digit < 0) {
            return std::nullopt;
        }
        if (value != 0 || digit != 0) {
            ++digits;
        }
        if (digits > 16) {
            return std::nullopt;
        }
        value = (value << 4) | static_cast<std::uint64_t>(digit);
    }
    return value;
}

bool WatchList::add(WatchEntry entry) {
    entry = normalized(std::move(entry));
    const auto found = std::find_if(entries_.begin(), entries_.end(), [&](const WatchEntry& other) { return same_value(other, entry); });
    if (found != entries_.end()) {
        selected_ = static_cast<std::size_t>(found - entries_.begin());
        return false;
    }
    entries_.push_back(std::move(entry));
    live_.emplace_back();
    selected_ = entries_.size() - 1;
    return true;
}

void WatchList::remove(std::size_t row) {
    if (row >= entries_.size()) {
        return;
    }
    entries_.erase(entries_.begin() + static_cast<std::ptrdiff_t>(row));
    live_.erase(live_.begin() + static_cast<std::ptrdiff_t>(row));
    if (entries_.empty()) {
        selected_.reset();
    } else if (selected_) {
        if (*selected_ > row) {
            --*selected_;
        }
        selected_ = std::min(*selected_, entries_.size() - 1);
    }
}

void WatchList::clear() {
    entries_.clear();
    live_.clear();
    selected_.reset();
}

void WatchList::keep_paths() {
    std::vector<WatchEntry> kept;
    for (WatchEntry& entry : entries_) {
        if (entry.path && !entry.path->module.empty()) {
            kept.push_back(std::move(entry));
        }
    }
    entries_ = std::move(kept);
    live_.assign(entries_.size(), Live{});
    selected_ = entries_.empty() ? std::nullopt : std::optional<std::size_t>(0);
}

std::optional<std::uint64_t> WatchList::locate(const MemorySource& memory, std::size_t row) const {
    const WatchEntry& entry = entries_[row];
    return entry.path ? resolve_pointer_path(memory, modules_, *entry.path) : std::optional<std::uint64_t>(entry.address);
}

std::string WatchList::address_text(std::size_t row) const {
    const WatchEntry& entry = entries_[row];
    if (!entry.path) {
        return format_address(entry.address);
    }
    const Live& live = live_[row];
    return live.read && live.resolved ? "P->" + format_address(entry.address) : std::string("P->??");
}

void WatchList::set_type(std::size_t row, WatchType type, std::uint32_t length) {
    WatchEntry& entry = entries_[row];
    entry.type = type;
    entry.length = length;
    entry = normalized(std::move(entry));
    live_[row] = Live{};
}

void WatchList::set_description(std::size_t row, std::string description) {
    entries_[row].description = std::move(description);
}

void WatchList::select_row(std::size_t row) {
    if (row < entries_.size()) {
        selected_ = row;
    }
}

void WatchList::move_selection(std::ptrdiff_t delta) {
    if (entries_.empty()) {
        return;
    }
    const auto last = static_cast<std::ptrdiff_t>(entries_.size() - 1);
    const auto from = static_cast<std::ptrdiff_t>(selected_.value_or(0));
    select_row(static_cast<std::size_t>(std::clamp(from + delta, std::ptrdiff_t{0}, last)));
}

const WatchEntry* WatchList::selected() const {
    return selected_ ? &entries_[*selected_] : nullptr;
}

void WatchList::refresh(const MemorySource& memory, std::size_t first, std::size_t last, Clock::time_point now) {
    last = std::min(last, entries_.size());
    for (std::size_t row = first; row < last; ++row) {
        Live& live = live_[row];
        WatchEntry& entry = entries_[row];
        std::optional<std::vector<std::byte>> bytes;
        live.resolved = true;
        if (entry.path) {
            const auto address = resolve_pointer_path(memory, modules_, *entry.path);
            live.resolved = address.has_value();
            entry.address = address.value_or(entry.address);
        }
        if (live.resolved) {
            bytes = read_watch_value(memory, entry);
        }
        const bool readable = bytes.has_value();
        if (live.read && (readable != live.readable || (readable && *bytes != live.bytes))) {
            live.changed = now;
        }
        live.read = true;
        live.readable = readable;
        live.bytes = readable ? std::move(*bytes) : std::vector<std::byte>{};
    }
}

std::string WatchList::value_text(std::size_t row) const {
    const Live& live = live_[row];
    if (!live.read) {
        return {};
    }
    return live.readable ? format_watch_value(entries_[row], live.bytes) : std::string("??");
}

bool WatchList::recently_changed(std::size_t row, Clock::time_point now) const {
    const auto& changed = live_[row].changed;
    return changed && now - *changed < kWatchChangeHold;
}

void WatchList::set_regions(std::vector<Region> regions) {
    regions_ = std::move(regions);
    modules_ = ModuleMap(regions_);
}

const Region* WatchList::region(std::size_t row) const {
    const std::uint64_t address = entries_[row].address;
    const auto it = std::upper_bound(regions_.begin(), regions_.end(), address,
                                     [](std::uint64_t a, const Region& region) { return a < region.base; });
    if (it == regions_.begin()) {
        return nullptr;
    }
    const Region& region = *std::prev(it);
    return address < region.end() ? &region : nullptr;
}

std::string WatchList::module(std::size_t row) const {
    const Region* found = live_[row].resolved ? region(row) : nullptr;
    return found != nullptr ? found->module_name() : std::string();
}

}  // namespace mh::gui
