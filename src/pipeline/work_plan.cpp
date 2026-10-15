#include "pipeline/work_plan.hpp"

#include <algorithm>

namespace mh {

std::vector<AddressRange> merge_ranges(std::vector<AddressRange> ranges) {
    std::sort(ranges.begin(), ranges.end(), [](const AddressRange& a, const AddressRange& b) { return a.begin < b.begin; });
    std::vector<AddressRange> merged;
    for (const auto& range : ranges) {
        if (range.begin >= range.end) {
            continue;
        }
        if (!merged.empty() && range.begin <= merged.back().end) {
            merged.back().end = std::max(merged.back().end, range.end);
        } else {
            merged.push_back(range);
        }
    }
    return merged;
}

std::vector<AddressRange> intersect_ranges(std::span<const AddressRange> a, std::span<const AddressRange> b) {
    const auto left = merge_ranges({a.begin(), a.end()});
    const auto right = merge_ranges({b.begin(), b.end()});
    std::vector<AddressRange> out;
    std::size_t i = 0;
    std::size_t j = 0;
    while (i < left.size() && j < right.size()) {
        const std::uint64_t begin = std::max(left[i].begin, right[j].begin);
        const std::uint64_t end = std::min(left[i].end, right[j].end);
        if (begin < end) {
            out.push_back({begin, end});
        }
        (left[i].end < right[j].end) ? ++i : ++j;
    }
    return out;
}

std::vector<AddressRange> subtract_ranges(std::span<const AddressRange> from, std::span<const AddressRange> remove) {
    const auto cuts = merge_ranges({remove.begin(), remove.end()});
    std::vector<AddressRange> out;
    for (const auto& range : merge_ranges({from.begin(), from.end()})) {
        std::uint64_t cursor = range.begin;
        for (const auto& cut : cuts) {
            if (cut.end <= cursor || cut.begin >= range.end) {
                continue;
            }
            if (cut.begin > cursor) {
                out.push_back({cursor, cut.begin});
            }
            cursor = std::max(cursor, cut.end);
        }
        if (cursor < range.end) {
            out.push_back({cursor, range.end});
        }
    }
    return out;
}

std::vector<AddressRange> build_spans(std::span<const Region> regions, const RegionFilter& filter) {
    std::vector<AddressRange> spans;
    for (const auto& region : regions) {
        if (!filter.accepts(region)) {
            continue;
        }
        if (!spans.empty() && spans.back().end == region.base) {
            spans.back().end = region.end();
        } else {
            spans.push_back({region.base, region.end()});
        }
    }
    if (!filter.include_ranges.empty()) {
        spans = intersect_ranges(spans, filter.include_ranges);
    }
    if (!filter.exclude_ranges.empty()) {
        spans = subtract_ranges(spans, filter.exclude_ranges);
    }
    return spans;
}

std::vector<ScanTarget> whole_span_targets(std::span<const AddressRange> spans) {
    std::vector<ScanTarget> targets;
    targets.reserve(spans.size());
    for (const auto& span : spans) {
        targets.push_back({span.begin, span.end, span.begin, span.end});
    }
    return targets;
}

std::vector<ScanTarget> changed_range_targets(std::span<const AddressRange> spans, std::span<const AddressRange> changed,
                                              std::size_t look_ahead) {
    const auto sorted_spans = merge_ranges({spans.begin(), spans.end()});
    std::vector<ScanTarget> targets;
    for (const auto& piece : intersect_ranges(sorted_spans, changed)) {
        const auto span = std::prev(std::upper_bound(sorted_spans.begin(), sorted_spans.end(), piece.begin,
                                                     [](std::uint64_t address, const AddressRange& r) { return address < r.begin; }));
        const std::uint64_t own_begin = piece.begin - std::min<std::uint64_t>(look_ahead, piece.begin - span->begin);
        if (!targets.empty() && targets.back().bound_begin == span->begin && own_begin <= targets.back().own_end) {
            targets.back().own_end = std::max(targets.back().own_end, piece.end);
        } else {
            targets.push_back({own_begin, piece.end, span->begin, span->end});
        }
    }
    return targets;
}

std::vector<WorkItem> split_work(std::span<const ScanTarget> targets, std::size_t chunk_size, std::size_t look_behind,
                                 std::size_t look_ahead) {
    chunk_size = std::max<std::size_t>(chunk_size, 1);
    std::vector<WorkItem> work;
    for (const auto& target : targets) {
        for (std::uint64_t begin = target.own_begin; begin < target.own_end;) {
            const std::uint64_t end = begin + std::min<std::uint64_t>(chunk_size, target.own_end - begin);
            WorkItem item;
            item.own_begin = begin;
            item.own_end = end;
            item.read_begin = begin - std::min<std::uint64_t>(look_behind, begin - target.bound_begin);
            item.read_end = end + std::min<std::uint64_t>(look_ahead, target.bound_end - end);
            work.push_back(item);
            begin = end;
        }
    }
    return work;
}

std::uint64_t attribute_regions(std::span<const Region> regions, std::span<WorkItem> work) {
    std::uint64_t touched = 0;
    std::size_t first = 0;
    for (const auto& region : regions) {
        while (first < work.size() && work[first].own_end <= region.base) {
            ++first;
        }
        std::size_t last = work.size();
        for (std::size_t i = first; i < work.size() && work[i].own_begin < region.end(); ++i) {
            last = i;
        }
        if (last != work.size()) {
            ++work[last].regions_finished;
            ++touched;
        }
    }
    return touched;
}

}  // namespace mh
