#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "snapshot/snapshot.hpp"

namespace mh {

// Unknown: captured by both snapshots but not comparable, because a block was unreadable on one side or the
// two captures clipped it differently. Added/Removed: captured only by the later/earlier snapshot.
enum class RangeKind : std::uint8_t { Changed, Unchanged, Unknown, Added, Removed };
inline constexpr std::size_t kRangeKindCount = 5;

std::string_view to_string(RangeKind kind);
std::optional<RangeKind> parse_range_kind(std::string_view text);

struct DiffRange {
    std::uint64_t begin = 0;
    std::uint64_t end = 0;
    RangeKind kind = RangeKind::Changed;
};

enum class RegionChangeKind : std::uint8_t { Added, Removed, Modified };

std::string_view to_string(RegionChangeKind kind);

struct RegionChange {
    RegionChangeKind kind = RegionChangeKind::Modified;
    Region before;
    Region after;
};

struct SnapshotDiff {
    std::vector<RegionChange> regions;
    // Sorted and disjoint; neighbouring ranges of the same kind are merged.
    std::vector<DiffRange> ranges;
    std::array<std::uint64_t, kRangeKindCount> bytes{};
    std::array<std::uint64_t, kRangeKindCount> range_counts{};
    // Changed ranges are exact to the byte instead of to the block.
    bool exact = false;
};

// Supplies the contents of block `block` of span `span`; returns false when they are not available.
using BlockReader = std::function<bool(std::size_t span, std::uint64_t block, std::span<std::byte> out)>;

// Throws Error(IncompatibleSnapshot) when the snapshots do not share a block grid.
void check_comparable(const Snapshot& before, const Snapshot& after);

// With both readers, blocks whose hashes differ are compared byte by byte.
SnapshotDiff diff_snapshots(const Snapshot& before, const Snapshot& after, const BlockReader& before_data = {},
                            const BlockReader& after_data = {});

// Changed, added and unknown memory: everything an incremental rescan has to read again.
std::vector<AddressRange> ranges_to_rescan(const SnapshotDiff& diff);

}  // namespace mh
