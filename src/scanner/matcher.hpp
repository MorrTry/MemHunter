#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace mh {

struct Hit {
    std::size_t offset = 0;
    std::uint32_t pattern = 0;
    std::uint32_t length = 0;

    friend bool operator==(const Hit&, const Hit&) = default;
};

class Matcher {
public:
    virtual ~Matcher() = default;

    // Appends every hit whose start offset lies in [report_begin, report_end). Bytes outside that window are
    // context only: look-behind decides string boundaries, look-ahead completes matches starting inside the window.
    // base_address is the virtual address of data[0]; it matters for alignment-sensitive scans (UTF-16 strings).
    // Implementations are immutable after construction and safe to call from several threads.
    virtual void scan(std::span<const std::byte> data, std::uint64_t base_address, std::size_t report_begin,
                      std::size_t report_end, std::vector<Hit>& hits) const = 0;

    virtual std::string describe() const = 0;
};

}  // namespace mh
