#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "memory/memory_source.hpp"
#include "pattern/pattern.hpp"
#include "pointer/pointer_chain.hpp"
#include "value/value_scan.hpp"

namespace mh::gui {

enum class WatchType : std::uint8_t { Int8, Int16, Int32, Int64, Float, Double, Ascii, Utf16, Bytes };

inline constexpr std::size_t kMaxWatchBytes = 256;
// How long a value that changed stays marked.
inline constexpr std::chrono::seconds kWatchChangeHold{2};

// "int32", "ascii", "utf16", "bytes": the names used in exports.
std::string_view to_string(WatchType type);
WatchType watch_type(ValueType type) noexcept;
std::optional<ValueType> value_type(WatchType type) noexcept;
bool has_length(WatchType type) noexcept;
// In characters for text and in bytes for byte entries.
std::uint32_t max_length(WatchType type) noexcept;

struct WatchEntry {
    std::uint64_t address = 0;
    WatchType type = WatchType::Int32;
    // Characters of text, bytes of a byte entry, 0 for numbers.
    std::uint32_t length = 0;
    std::string description;
    // Set when the entry follows a chain of pointers; the address is then where the chain led at the last refresh.
    std::optional<PointerPath> path;

    std::size_t size() const noexcept;
};

// The length of text and byte entries is clamped to 1..max_length; numbers get 0.
WatchEntry make_watch_entry(std::uint64_t address, WatchType type, std::uint32_t length = 0, std::string description = {});
// What a match of a text, string or byte search becomes: text for the text kinds, bytes for the others.
WatchEntry watch_entry_for(std::uint64_t address, PatternKind kind, std::uint32_t match_length);

// "int32", "ASCII, 8 символов", "UTF-16, 2 символа", "4 байта".
std::string type_label(const WatchEntry& entry);
// Text stops at the first zero character.
std::string format_watch_value(const WatchEntry& entry, std::span<const std::byte> bytes);
// nullopt unless every byte of the value can be read.
std::optional<std::vector<std::byte>> read_watch_value(const MemorySource& memory, const WatchEntry& entry);
// Hexadecimal with or without 0x; spaces around it are ignored.
std::optional<std::uint64_t> parse_address(std::string_view text);

// Addresses the user keeps an eye on, in the order they were added, with their values as last read.
class WatchList {
public:
    using Clock = std::chrono::steady_clock;

    // Selects the entry; false when one with the same address (or chain), type and length is already listed.
    bool add(WatchEntry entry);
    // The selection stays on the same row, or on the last one when the last row goes.
    void remove(std::size_t row);
    void clear();
    // Drops the entries without a chain, which mean nothing in another run of the program.
    void keep_paths();
    void set_type(std::size_t row, WatchType type, std::uint32_t length);
    void set_description(std::size_t row, std::string description);

    const std::vector<WatchEntry>& rows() const noexcept { return entries_; }
    bool empty() const noexcept { return entries_.empty(); }

    std::optional<std::size_t> selected_row() const noexcept { return selected_; }
    void select_row(std::size_t row);
    void move_selection(std::ptrdiff_t delta);
    const WatchEntry* selected() const;

    // Reads the values of rows [first, last), following the chains of their entries first; a value that differs
    // from its previous reading is marked as changed.
    void refresh(const MemorySource& memory, std::size_t first, std::size_t last, Clock::time_point now);
    bool read(std::size_t row) const { return live_[row].read; }
    bool readable(std::size_t row) const { return live_[row].readable; }
    // Where the entry is now: its address, or where its chain leads; nullopt when the chain leads nowhere.
    std::optional<std::uint64_t> locate(const MemorySource& memory, std::size_t row) const;
    // False for an entry whose chain could not be followed at the last refresh.
    bool resolved(std::size_t row) const { return live_[row].resolved; }
    // The address, as "P->0x..." for an entry that follows a chain and "P->??" while the chain leads nowhere.
    std::string address_text(std::size_t row) const;
    // Empty until read, "??" when unreadable.
    std::string value_text(std::size_t row) const;
    // Changed during the last kWatchChangeHold.
    bool recently_changed(std::size_t row, Clock::time_point now) const;

    // The regions for the module column, sorted by address; the modules in them are where chains start.
    void set_regions(std::vector<Region> regions);
    const Region* region(std::size_t row) const;
    std::string module(std::size_t row) const;

private:
    struct Live {
        bool read = false;
        bool readable = false;
        bool resolved = true;
        std::vector<std::byte> bytes;
        std::optional<Clock::time_point> changed;
    };

    std::vector<WatchEntry> entries_;
    std::vector<Live> live_;
    std::vector<Region> regions_;
    ModuleMap modules_;
    std::optional<std::size_t> selected_;
};

}  // namespace mh::gui
