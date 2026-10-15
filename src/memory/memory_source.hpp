#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "memory/region.hpp"

namespace mh {

struct ReadResult {
    std::size_t bytes = 0;
    std::uint32_t error = 0;
};

class MemorySource {
public:
    virtual ~MemorySource() = default;

    // Non-free regions sorted by base address.
    virtual std::vector<Region> query_regions() const = 0;

    // Thread-safe. Returns the length of the successfully read prefix; a short read carries a Win32 error code.
    virtual ReadResult read(std::uint64_t address, std::span<std::byte> out) const = 0;

    virtual bool target_alive() const = 0;
    virtual std::size_t page_size() const = 0;
};

}  // namespace mh
