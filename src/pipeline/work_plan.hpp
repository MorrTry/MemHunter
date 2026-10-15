#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "memory/region.hpp"

namespace mh {

// Matches are reported only when they start inside [own_begin, own_end) and may use bytes up to the
// bounds, which never cross a gap or an unselected region.
struct ScanTarget {
    std::uint64_t own_begin = 0;
    std::uint64_t own_end = 0;
    std::uint64_t bound_begin = 0;
    std::uint64_t bound_end = 0;
};

// One unit of reader work: own range plus the look-behind/look-ahead context actually read from memory.
struct WorkItem {
    std::uint64_t own_begin = 0;
    std::uint64_t own_end = 0;
    std::uint64_t read_begin = 0;
    std::uint64_t read_end = 0;
    // Regions whose last scanned byte lies in the own range: they count as checked once this item is scanned.
    std::uint32_t regions_finished = 0;
};

std::vector<AddressRange> merge_ranges(std::vector<AddressRange> ranges);
std::vector<AddressRange> intersect_ranges(std::span<const AddressRange> a, std::span<const AddressRange> b);
std::vector<AddressRange> subtract_ranges(std::span<const AddressRange> from, std::span<const AddressRange> remove);

// Selected regions that touch each other form one span, so matches may cross region boundaries but never
// gaps; include/exclude address ranges clip the spans.
std::vector<AddressRange> build_spans(std::span<const Region> regions, const RegionFilter& filter);

std::vector<ScanTarget> whole_span_targets(std::span<const AddressRange> spans);

// Targets for rescanning only `changed` ranges: a match must start no earlier than look_ahead bytes before a
// change to be able to overlap it.
std::vector<ScanTarget> changed_range_targets(std::span<const AddressRange> spans, std::span<const AddressRange> changed,
                                              std::size_t look_ahead);

std::vector<WorkItem> split_work(std::span<const ScanTarget> targets, std::size_t chunk_size, std::size_t look_behind,
                                 std::size_t look_ahead);

// Sets regions_finished for `regions` sorted by base and `work` sorted by address; returns how many regions
// the work touches.
std::uint64_t attribute_regions(std::span<const Region> regions, std::span<WorkItem> work);

}  // namespace mh
