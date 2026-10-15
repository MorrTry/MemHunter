#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

#include "gui/watch_list.hpp"
#include "memory/memory_dump.hpp"
#include "memory/memory_source.hpp"
#include "pointer/pointer_chain.hpp"
#include "structure/struct_file.hpp"
#include "structure/struct_layout.hpp"

namespace mh::gui {

inline constexpr std::size_t kMaxInstances = 4;
// The bytes shown of a structure that a pointer field leads to.
inline constexpr std::uint32_t kPointeeSize = 0x100;
inline constexpr std::uint32_t kMaxTreeDepth = 8;

// A field of the structure, or of a structure a pointer of it leads to (depth 1 and more).
struct StructRow {
    std::uint32_t node = 0;
    std::uint32_t depth = 0;
    StructField field;
};

// Where a structure that holds a known field starts: the chain or the address of the field without its offset.
struct StructStart {
    PointerPath base;
    std::uint32_t focus = 0;
};

StructStart struct_start(const WatchEntry& entry, unsigned pointer_size);
// The field type of a watch entry type, with the same length.
FieldType field_type(WatchType type) noexcept;

// The fields of a structure at a chain or an address, read live, with the same structure at up to three more bases
// beside it. Only the fields of the structure itself (depth 0) can be defined.
class StructTable {
public:
    using Clock = std::chrono::steady_clock;

    bool active() const noexcept { return active_; }
    // Starts over with nothing defined; the field at `focus` gets selected once the structure is read.
    void open(PointerPath base, std::uint32_t size, std::optional<std::uint32_t> focus = std::nullopt);
    void close();
    // Forgets what was read, for another run of the program: bases that are addresses go, and the structure closes
    // when its own base is an address.
    void restart();

    const PointerPath& base() const noexcept { return instances_[0]; }
    std::uint32_t size() const noexcept { return size_; }
    // Not below the end of the last defined field; at most kMaxStructSize.
    void set_size(std::uint32_t size);
    unsigned pointer_size() const noexcept { return base().pointer_size; }

    // The regions of the target: modules for pointer values, readable memory for guessing pointers.
    void set_regions(const std::vector<Region>& regions);

    // Follows the bases, reads every structure of the tree and marks the fields whose bytes changed.
    void refresh(const MemorySource& memory, Clock::time_point now);
    // A refresh is due after kLiveRefresh, or at once after a change of the tree or the bases.
    bool due(Clock::time_point now, Clock::duration interval) const;

    const std::vector<StructRow>& rows() const noexcept { return rows_; }
    std::optional<std::size_t> selected_row() const noexcept { return selected_; }
    void select_row(std::size_t row);
    void move_selection(std::ptrdiff_t delta);
    const StructRow* selected() const;
    // The row of the structure itself that holds the byte at `offset`.
    void select_offset(std::uint32_t offset);

    std::size_t instances() const noexcept { return instance_count_; }
    const PointerPath& instance(std::size_t index) const { return instances_[index]; }
    // False with kMaxInstances bases already, or when the base is shown.
    bool add_instance(PointerPath base);
    // The first base cannot be removed.
    void remove_instance(std::size_t index);

    // Where the structure of the row starts, and where its field is; nullopt while the way there is unknown.
    std::optional<std::uint64_t> address(std::size_t instance) const;
    std::optional<std::uint64_t> field_address(std::size_t row, std::size_t instance) const;
    // Empty until read, "??" when unreadable.
    std::string value_text(std::size_t row, std::size_t instance) const;
    // The instances hold different bytes in the field.
    bool differs(std::size_t row) const;
    // The instance holds other bytes in the field than the first one.
    bool differs(std::size_t row, std::size_t instance) const;
    bool recently_changed(std::size_t row, std::size_t instance, Clock::time_point now) const;

    bool editable(std::size_t row) const;
    // A field of the structure itself; it replaces the defined fields it overlaps and grows the structure when needed.
    // False past kMaxStructSize.
    bool define(std::uint32_t offset, FieldType type, std::uint32_t length, std::string name);
    // Keeps a guessed field as it is, with the name.
    bool rename(std::size_t row, std::string name);
    // The field is guessed again.
    void forget(std::size_t row);
    // Guesses every field that is not defined from the bytes read last.
    void guess_again();
    StructDefinition definition() const;
    void set_definition(StructDefinition definition);

    bool expandable(std::size_t row) const;
    bool expanded(std::size_t row) const;
    void toggle(std::size_t row);
    // Makes the structure the pointer of the row leads to the main one, at every base; false when the chain would
    // be longer than kMaxPathOffsets.
    bool dissect(std::size_t row);

    // The chain to the field; an address when the structure is at an address.
    PointerPath path_to(std::size_t row, std::size_t instance) const;
    std::string path_text(std::size_t row, std::size_t instance) const;
    WatchEntry watch_entry(std::size_t row, std::size_t instance) const;
    // The defined fields, or all of them while none is defined.
    std::string c_declaration() const;

private:
    struct Live {
        std::optional<std::uint64_t> address;
        MemoryDump dump;
        bool read = false;
    };
    struct Node {
        std::uint32_t parent = 0;
        std::uint32_t offset = 0;
        std::uint32_t depth = 0;
        std::uint32_t size = 0;
        std::vector<StructField> layout;
        bool guessed = false;
        std::array<Live, kMaxInstances> live;
        // Offset of the pointer field -> node.
        std::map<std::uint32_t, std::uint32_t> children;
    };
    using ChangeKey = std::tuple<std::uint32_t, std::uint32_t, std::size_t>;

    const MemoryDump& guess_source(const Node& node) const;
    void relayout(std::uint32_t id);
    void erase_node(std::uint32_t id);
    void rebuild_rows();
    PointerPath node_path(std::uint32_t id, std::size_t instance) const;
    const StructRow* row_at(std::size_t row) const;

    bool active_ = false;
    std::array<PointerPath, kMaxInstances> instances_;
    std::size_t instance_count_ = 1;
    std::uint32_t size_ = kDefaultStructSize;
    std::vector<StructField> defined_;
    std::map<std::uint32_t, Node> nodes_;
    std::uint32_t next_node_ = 1;
    std::vector<StructRow> rows_;
    std::optional<std::size_t> selected_;
    std::optional<std::uint32_t> focus_;
    std::map<ChangeKey, Clock::time_point> changed_;
    std::optional<Clock::time_point> refreshed_;
    ModuleMap modules_;
    PointerTargets targets_;
};

}  // namespace mh::gui
