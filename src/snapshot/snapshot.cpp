#include "snapshot/snapshot.hpp"

#include <algorithm>
#include <chrono>

namespace mh {

std::uint64_t blocks_in_range(std::uint64_t begin, std::uint64_t end, std::uint64_t block_size) noexcept {
    if (begin >= end) {
        return 0;
    }
    return (end - 1) / block_size - begin / block_size + 1;
}

std::uint64_t Snapshot::captured_bytes() const noexcept {
    std::uint64_t total = 0;
    for (const auto& span : spans) {
        total += span.end - span.begin;
    }
    return total;
}

std::uint64_t Snapshot::unreadable_bytes() const {
    std::uint64_t total = 0;
    for (std::size_t s = 0; s < spans.size(); ++s) {
        const std::uint64_t count = blocks_in_range(spans[s].begin, spans[s].end, block_size);
        for (std::uint64_t b = 0; b < count; ++b) {
            if (states[spans[s].first_block + b] == BlockState::Unreadable) {
                const AddressRange range = block_range(s, spans[s].first_block + b);
                total += range.end - range.begin;
            }
        }
    }
    return total;
}

AddressRange Snapshot::block_range(std::size_t span, std::uint64_t block) const noexcept {
    const SnapshotSpan& s = spans[span];
    const std::uint64_t first = s.begin / block_size * block_size;
    const std::uint64_t begin = first + (block - s.first_block) * block_size;
    return {std::max(begin, s.begin), std::min(begin + block_size, s.end)};
}

std::uint64_t Snapshot::block_data_offset(std::size_t span, std::uint64_t block) const noexcept {
    return spans[span].data_offset + (block_range(span, block).begin - spans[span].begin);
}

void layout_spans(Snapshot& snapshot, std::span<const AddressRange> ranges) {
    snapshot.spans.clear();
    snapshot.spans.reserve(ranges.size());
    std::uint64_t block = 0;
    std::uint64_t offset = 0;
    for (const auto& range : ranges) {
        snapshot.spans.push_back({range.begin, range.end, block, offset});
        block += blocks_in_range(range.begin, range.end, snapshot.block_size);
        offset += range.end - range.begin;
    }
    snapshot.states.assign(block, BlockState::Unreadable);
    snapshot.hashes.assign(block, 0);
}

bool same_process_instance(const ProcessSummary& a, const ProcessSummary& b) noexcept {
    return a.pid == b.pid && a.creation_time == b.creation_time;
}

std::uint64_t filetime_now() noexcept {
    constexpr std::uint64_t kUnixEpochAsFiletime = 116'444'736'000'000'000ull;
    const auto since_epoch = std::chrono::system_clock::now().time_since_epoch();
    const auto ticks = std::chrono::duration_cast<std::chrono::duration<std::int64_t, std::ratio<1, 10'000'000>>>(since_epoch);
    return kUnixEpochAsFiletime + static_cast<std::uint64_t>(ticks.count());
}

}  // namespace mh
