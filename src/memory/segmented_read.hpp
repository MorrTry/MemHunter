#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "memory/memory_source.hpp"

namespace mh {

// Readable part of a buffer, as offsets into it.
struct Segment {
    std::size_t begin = 0;
    std::size_t end = 0;
};

// Reads `buffer.size()` bytes at `address`: one bulk read, then page by page after a short read, because a failed
// ReadProcessMemory may report fewer bytes than are actually readable. `segments` receives the readable parts in
// order, merged. Returns false when part of the range could not be read.
bool read_segments(const MemorySource& source, std::uint64_t address, std::span<std::byte> buffer, std::size_t page_size,
                   std::vector<Segment>& segments, std::uint64_t& read_calls);

// Whether [begin, end) lies inside one segment. `cursor` must start at 0 and the ranges must be queried in
// ascending order.
bool segment_covers(std::span<const Segment> segments, std::size_t& cursor, std::size_t begin, std::size_t end);

}  // namespace mh
