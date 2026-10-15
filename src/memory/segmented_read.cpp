#include "memory/segmented_read.hpp"

#include <algorithm>

namespace mh {

namespace {

void add_segment(std::vector<Segment>& segments, std::size_t begin, std::size_t end) {
    if (begin >= end) {
        return;
    }
    if (!segments.empty() && segments.back().end == begin) {
        segments.back().end = end;
    } else {
        segments.push_back({begin, end});
    }
}

}  // namespace

bool read_segments(const MemorySource& source, std::uint64_t address, std::span<std::byte> buffer, std::size_t page_size,
                   std::vector<Segment>& segments, std::uint64_t& read_calls) {
    segments.clear();
    ++read_calls;
    const ReadResult bulk = source.read(address, buffer);
    add_segment(segments, 0, bulk.bytes);
    const std::uint64_t end = address + buffer.size();
    bool failed = false;
    std::uint64_t current = address + bulk.bytes;
    while (current < end) {
        const std::uint64_t page_end = std::min<std::uint64_t>(end, (current / page_size + 1) * page_size);
        const std::size_t offset = current - address;
        const std::size_t length = page_end - current;
        ++read_calls;
        const ReadResult part = source.read(current, buffer.subspan(offset, length));
        add_segment(segments, offset, offset + part.bytes);
        failed = failed || part.bytes < length;
        current = page_end;
    }
    return !failed;
}

bool segment_covers(std::span<const Segment> segments, std::size_t& cursor, std::size_t begin, std::size_t end) {
    while (cursor < segments.size() && segments[cursor].end <= begin) {
        ++cursor;
    }
    return cursor < segments.size() && segments[cursor].begin <= begin && end <= segments[cursor].end;
}

}  // namespace mh
