#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "memory/memory_source.hpp"

namespace mh {

// A copy of a few pages of memory; readable[i] is 0 for a byte that could not be read.
struct MemoryDump {
    std::uint64_t address = 0;
    std::vector<std::byte> bytes;
    std::vector<std::uint8_t> readable;

    bool all_readable(std::uint64_t begin, std::uint64_t end) const;
    bool any_readable() const;
};

// Reads page by page, so an unreadable page leaves the others readable.
MemoryDump read_dump(const MemorySource& memory, std::uint64_t address, std::size_t size);

}  // namespace mh
