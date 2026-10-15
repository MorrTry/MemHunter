#include "memory/memory_dump.hpp"

#include <algorithm>
#include <span>

namespace mh {

bool MemoryDump::all_readable(std::uint64_t begin, std::uint64_t end) const {
    if (begin < address || end > address + bytes.size() || begin > end) {
        return false;
    }
    return std::all_of(readable.begin() + static_cast<std::ptrdiff_t>(begin - address),
                       readable.begin() + static_cast<std::ptrdiff_t>(end - address), [](std::uint8_t r) { return r != 0; });
}

bool MemoryDump::any_readable() const {
    return std::any_of(readable.begin(), readable.end(), [](std::uint8_t r) { return r != 0; });
}

MemoryDump read_dump(const MemorySource& memory, std::uint64_t address, std::size_t size) {
    MemoryDump dump;
    dump.address = address;
    size = static_cast<std::size_t>(std::min<std::uint64_t>(size, ~std::uint64_t{0} - address));
    dump.bytes.assign(size, std::byte{0});
    dump.readable.assign(size, 0);
    const std::uint64_t page = std::max<std::size_t>(memory.page_size(), 1);
    std::size_t offset = 0;
    while (offset < size) {
        const std::uint64_t at = address + offset;
        const std::size_t piece = static_cast<std::size_t>(std::min<std::uint64_t>(size - offset, page - at % page));
        const ReadResult read = memory.read(at, std::span(dump.bytes).subspan(offset, piece));
        std::fill_n(dump.readable.begin() + static_cast<std::ptrdiff_t>(offset), std::min(read.bytes, piece), std::uint8_t{1});
        offset += piece;
    }
    return dump;
}

}  // namespace mh
