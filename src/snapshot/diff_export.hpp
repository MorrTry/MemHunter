#pragma once

#include <cstddef>
#include <cstdint>
#include <ostream>
#include <string>
#include <vector>

#include "results/export.hpp"
#include "snapshot/diff.hpp"
#include "snapshot/snapshot.hpp"

namespace mh {

struct SnapshotSide {
    std::string source;
    const Snapshot* snapshot = nullptr;
    bool live = false;
    std::uint64_t file_size = 0;
};

inline constexpr std::uint32_t range_kind_bit(RangeKind kind) {
    return 1u << static_cast<unsigned>(kind);
}

inline constexpr std::uint32_t kDefaultShownRanges =
    range_kind_bit(RangeKind::Changed) | range_kind_bit(RangeKind::Added) | range_kind_bit(RangeKind::Removed);

struct DiffReport {
    SnapshotSide before;
    SnapshotSide after;
    const SnapshotDiff* diff = nullptr;
    std::vector<std::string> warnings;
    std::uint32_t show = kDefaultShownRanges;
    std::size_t limit = 0;
};

// Indices of the ranges selected by report.show, at most report.limit of them (0 = all).
std::vector<std::size_t> diff_rows(const DiffReport& report);

void write_diff(std::ostream& out, OutputFormat format, const DiffReport& report);
void write_snapshot_info(std::ostream& out, OutputFormat format, const SnapshotSide& side);

}  // namespace mh
