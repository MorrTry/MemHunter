#include "snapshot/diff.hpp"

#include <algorithm>
#include <limits>

#include "common/error.hpp"
#include "common/text.hpp"
#include "pipeline/work_plan.hpp"

namespace mh {

namespace {

constexpr std::array<std::string_view, kRangeKindCount> kRangeKindNames{"changed", "unchanged", "unknown", "added", "removed"};

std::size_t index(RangeKind kind) {
    return static_cast<std::size_t>(kind);
}

class BlockCursor {
public:
    explicit BlockCursor(const Snapshot& snapshot) : snapshot_(snapshot) { settle(); }

    bool valid() const noexcept { return span_ < snapshot_.spans.size(); }
    std::size_t span() const noexcept { return span_; }
    std::uint64_t block() const noexcept { return block_; }
    const AddressRange& range() const noexcept { return range_; }

    void advance() {
        ++block_;
        settle();
    }

private:
    void settle() {
        while (span_ < snapshot_.spans.size()) {
            const SnapshotSpan& span = snapshot_.spans[span_];
            if (block_ < span.first_block + blocks_in_range(span.begin, span.end, snapshot_.block_size)) {
                range_ = snapshot_.block_range(span_, block_);
                return;
            }
            ++span_;
            if (span_ < snapshot_.spans.size()) {
                block_ = snapshot_.spans[span_].first_block;
            }
        }
    }

    const Snapshot& snapshot_;
    std::size_t span_ = 0;
    std::uint64_t block_ = 0;
    AddressRange range_;
};

class DiffBuilder {
public:
    explicit DiffBuilder(SnapshotDiff& diff) : diff_(diff) {}

    void emit(RangeKind kind, std::uint64_t begin, std::uint64_t end) {
        if (begin >= end) {
            return;
        }
        diff_.bytes[index(kind)] += end - begin;
        if (!diff_.ranges.empty() && diff_.ranges.back().kind == kind && diff_.ranges.back().end == begin) {
            diff_.ranges.back().end = end;
            return;
        }
        diff_.ranges.push_back({begin, end, kind});
    }

private:
    SnapshotDiff& diff_;
};

bool same_attributes(const Region& a, const Region& b) {
    return a.size == b.size && a.protect == b.protect && a.state == b.state && a.type == b.type &&
           a.allocation_base == b.allocation_base && a.mapped_file == b.mapped_file;
}

std::vector<RegionChange> diff_regions(const std::vector<Region>& before, const std::vector<Region>& after) {
    std::vector<RegionChange> changes;
    std::size_t i = 0;
    std::size_t j = 0;
    while (i < before.size() || j < after.size()) {
        if (j == after.size() || (i < before.size() && before[i].base < after[j].base)) {
            changes.push_back({RegionChangeKind::Removed, before[i++], {}});
        } else if (i == before.size() || after[j].base < before[i].base) {
            changes.push_back({RegionChangeKind::Added, {}, after[j++]});
        } else {
            if (!same_attributes(before[i], after[j])) {
                changes.push_back({RegionChangeKind::Modified, before[i], after[j]});
            }
            ++i;
            ++j;
        }
    }
    return changes;
}

// Splits a block whose hashes differ into exact changed and unchanged runs.
void emit_exact(DiffBuilder& out, std::uint64_t base, std::span<const std::byte> a, std::span<const std::byte> b) {
    std::size_t i = 0;
    while (i < a.size()) {
        const bool differs = a[i] != b[i];
        std::size_t j = i + 1;
        while (j < a.size() && (a[j] != b[j]) == differs) {
            ++j;
        }
        out.emit(differs ? RangeKind::Changed : RangeKind::Unchanged, base + i, base + j);
        i = j;
    }
}

}  // namespace

std::string_view to_string(RangeKind kind) {
    return kRangeKindNames[index(kind)];
}

std::optional<RangeKind> parse_range_kind(std::string_view text) {
    for (std::size_t i = 0; i < kRangeKindNames.size(); ++i) {
        if (iequals_ascii(text, kRangeKindNames[i])) {
            return static_cast<RangeKind>(i);
        }
    }
    return std::nullopt;
}

std::string_view to_string(RegionChangeKind kind) {
    switch (kind) {
        case RegionChangeKind::Added: return "added";
        case RegionChangeKind::Removed: return "removed";
        case RegionChangeKind::Modified: return "modified";
    }
    return "?";
}

void check_comparable(const Snapshot& before, const Snapshot& after) {
    if (before.block_size != after.block_size || before.page_size != after.page_size) {
        throw Error(ErrorCode::IncompatibleSnapshot, "the snapshots use different block sizes (" + format_size(before.block_size) +
                                                         " and " + format_size(after.block_size) +
                                                         "); capture both with the same --block-size");
    }
}

SnapshotDiff diff_snapshots(const Snapshot& before, const Snapshot& after, const BlockReader& before_data,
                            const BlockReader& after_data) {
    check_comparable(before, after);
    SnapshotDiff diff;
    diff.regions = diff_regions(before.regions, after.regions);
    diff.exact = before_data && after_data;
    DiffBuilder out(diff);

    std::vector<std::byte> a_bytes(diff.exact ? before.block_size : 0);
    std::vector<std::byte> b_bytes(diff.exact ? after.block_size : 0);
    BlockCursor a(before);
    BlockCursor b(after);
    constexpr AddressRange kNone{std::numeric_limits<std::uint64_t>::max(), std::numeric_limits<std::uint64_t>::max()};
    std::uint64_t position = 0;

    // Invariant: every valid cursor's block ends after `position`, so the clipped ranges below are never empty.
    while (a.valid() || b.valid()) {
        const AddressRange ra = a.valid() ? AddressRange{std::max(a.range().begin, position), a.range().end} : kNone;
        const AddressRange rb = b.valid() ? AddressRange{std::max(b.range().begin, position), b.range().end} : kNone;
        if (ra.begin < rb.begin) {
            position = std::min(ra.end, rb.begin);
            out.emit(RangeKind::Removed, ra.begin, position);
        } else if (rb.begin < ra.begin) {
            position = std::min(rb.end, ra.begin);
            out.emit(RangeKind::Added, rb.begin, position);
        } else {
            position = std::min(ra.end, rb.end);
            const bool aligned = a.range() == b.range();
            const bool readable = before.states[a.block()] == BlockState::Hashed && after.states[b.block()] == BlockState::Hashed;
            if (!aligned || !readable) {
                out.emit(RangeKind::Unknown, ra.begin, position);
            } else if (before.hashes[a.block()] == after.hashes[b.block()]) {
                out.emit(RangeKind::Unchanged, ra.begin, position);
            } else {
                const std::size_t size = ra.end - ra.begin;
                if (diff.exact && before_data(a.span(), a.block(), a_bytes) && after_data(b.span(), b.block(), b_bytes)) {
                    emit_exact(out, ra.begin, std::span(a_bytes).first(size), std::span(b_bytes).first(size));
                } else {
                    out.emit(RangeKind::Changed, ra.begin, position);
                }
            }
        }
        if (a.valid() && a.range().end <= position) {
            a.advance();
        }
        if (b.valid() && b.range().end <= position) {
            b.advance();
        }
    }

    for (const auto& range : diff.ranges) {
        ++diff.range_counts[index(range.kind)];
    }
    return diff;
}

std::vector<AddressRange> ranges_to_rescan(const SnapshotDiff& diff) {
    std::vector<AddressRange> ranges;
    for (const auto& range : diff.ranges) {
        if (range.kind == RangeKind::Changed || range.kind == RangeKind::Added || range.kind == RangeKind::Unknown) {
            ranges.push_back({range.begin, range.end});
        }
    }
    return merge_ranges(std::move(ranges));
}

}  // namespace mh
