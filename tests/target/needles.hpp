#pragma once

#include <cstddef>
#include <cstdint>

namespace mh::testing {

inline constexpr std::size_t kNeedleSize = 16;
inline constexpr std::size_t kTextNeedleSize = 20;

// Needle contents are derived from (seed, index, position) on demand, so the test target writes each byte
// straight to where it is planted and never keeps another copy that a scan could find.
inline std::uint64_t needle_mix(std::uint64_t seed, std::uint32_t index, std::size_t position) noexcept {
    std::uint64_t z = seed + 0x9E3779B97F4A7C15ull * (static_cast<std::uint64_t>(index) * 4099 + position + 1);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

inline std::uint8_t needle_byte(std::uint64_t seed, std::uint32_t index, std::size_t position) noexcept {
    return static_cast<std::uint8_t>(needle_mix(seed, index, position) >> 17);
}

// Upper-case letters only, so ASCII case folding has something to fold at every position.
inline char needle_letter(std::uint64_t seed, std::uint32_t index, std::size_t position) noexcept {
    return static_cast<char>('A' + needle_mix(seed, index, position) % 26);
}

}  // namespace mh::testing
