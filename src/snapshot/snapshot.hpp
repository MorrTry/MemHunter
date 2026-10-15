#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "memory/region.hpp"
#include "results/result_set.hpp"

namespace mh {

inline constexpr std::uint32_t kSnapshotVersion = 1;
inline constexpr std::uint32_t kDefaultBlockSize = 4096;
inline constexpr std::uint32_t kMaxBlockSize = 1u << 20;

enum class BlockState : std::uint8_t { Unreadable = 0, Hashed = 1 };

// A captured address range. Blocks follow the absolute grid of block_size, so the first and last block of a
// span may be shorter than block_size; two snapshots with the same block size share block boundaries.
struct SnapshotSpan {
    std::uint64_t begin = 0;
    std::uint64_t end = 0;
    std::uint64_t first_block = 0;
    std::uint64_t data_offset = 0;
};

// What a snapshot records: the full region table, the ranges that were read, one hash per block and, only
// when has_data is set, the block contents themselves (stored in the snapshot file, not in this object).
struct Snapshot {
    ProcessSummary process;
    std::uint64_t captured_at = 0;
    std::uint32_t page_size = 4096;
    std::uint32_t block_size = kDefaultBlockSize;
    bool has_data = false;
    std::vector<Region> regions;
    std::vector<SnapshotSpan> spans;
    std::vector<BlockState> states;
    std::vector<std::uint64_t> hashes;

    std::uint64_t block_count() const noexcept { return hashes.size(); }
    std::uint64_t captured_bytes() const noexcept;
    std::uint64_t unreadable_bytes() const;
    AddressRange block_range(std::size_t span, std::uint64_t block) const noexcept;
    std::uint64_t block_data_offset(std::size_t span, std::uint64_t block) const noexcept;
};

std::uint64_t blocks_in_range(std::uint64_t begin, std::uint64_t end, std::uint64_t block_size) noexcept;

// Fills first_block and data_offset from the span bounds and sizes the block tables; spans must be sorted
// and disjoint.
void layout_spans(Snapshot& snapshot, std::span<const AddressRange> ranges);

bool same_process_instance(const ProcessSummary& a, const ProcessSummary& b) noexcept;

// FILETIME units (100 ns since 1601, UTC), the same clock as process creation times.
std::uint64_t filetime_now() noexcept;

}  // namespace mh
