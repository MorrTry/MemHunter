#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace mh {

// XXH64 (https://github.com/Cyan4973/xxHash, 64-bit variant), chosen for block hashes and file checksums
// because it runs at memory bandwidth on one core and its output is stable across versions.
std::uint64_t xxh64(std::span<const std::byte> data, std::uint64_t seed = 0) noexcept;

}  // namespace mh
