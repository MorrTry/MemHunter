#include "snapshot/hash.hpp"

#include <bit>
#include <cstring>

namespace mh {

namespace {

constexpr std::uint64_t kPrime1 = 0x9E3779B185EBCA87ull;
constexpr std::uint64_t kPrime2 = 0xC2B2AE3D27D4EB4Full;
constexpr std::uint64_t kPrime3 = 0x165667B19E3779F9ull;
constexpr std::uint64_t kPrime4 = 0x85EBCA77C2B2AE63ull;
constexpr std::uint64_t kPrime5 = 0x27D4EB2F165667C5ull;

static_assert(std::endian::native == std::endian::little, "XXH64 reads lanes as little-endian words");

std::uint64_t load64(const std::byte* p) noexcept {
    std::uint64_t value;
    std::memcpy(&value, p, sizeof value);
    return value;
}

std::uint32_t load32(const std::byte* p) noexcept {
    std::uint32_t value;
    std::memcpy(&value, p, sizeof value);
    return value;
}

std::uint64_t round(std::uint64_t acc, std::uint64_t lane) noexcept {
    acc += lane * kPrime2;
    acc = std::rotl(acc, 31);
    return acc * kPrime1;
}

std::uint64_t merge_round(std::uint64_t acc, std::uint64_t value) noexcept {
    acc ^= round(0, value);
    return acc * kPrime1 + kPrime4;
}

}  // namespace

std::uint64_t xxh64(std::span<const std::byte> data, std::uint64_t seed) noexcept {
    const std::byte* p = data.data();
    const std::byte* const end = p + data.size();
    std::uint64_t h;

    if (data.size() >= 32) {
        std::uint64_t v1 = seed + kPrime1 + kPrime2;
        std::uint64_t v2 = seed + kPrime2;
        std::uint64_t v3 = seed;
        std::uint64_t v4 = seed - kPrime1;
        const std::byte* const limit = end - 32;
        do {
            v1 = round(v1, load64(p));
            v2 = round(v2, load64(p + 8));
            v3 = round(v3, load64(p + 16));
            v4 = round(v4, load64(p + 24));
            p += 32;
        } while (p <= limit);
        h = std::rotl(v1, 1) + std::rotl(v2, 7) + std::rotl(v3, 12) + std::rotl(v4, 18);
        h = merge_round(h, v1);
        h = merge_round(h, v2);
        h = merge_round(h, v3);
        h = merge_round(h, v4);
    } else {
        h = seed + kPrime5;
    }

    h += data.size();
    while (end - p >= 8) {
        h ^= round(0, load64(p));
        h = std::rotl(h, 27) * kPrime1 + kPrime4;
        p += 8;
    }
    if (end - p >= 4) {
        h ^= static_cast<std::uint64_t>(load32(p)) * kPrime1;
        h = std::rotl(h, 23) * kPrime2 + kPrime3;
        p += 4;
    }
    while (p < end) {
        h ^= static_cast<std::uint64_t>(std::to_integer<std::uint8_t>(*p)) * kPrime5;
        h = std::rotl(h, 11) * kPrime1;
        ++p;
    }

    h ^= h >> 33;
    h *= kPrime2;
    h ^= h >> 29;
    h *= kPrime3;
    h ^= h >> 32;
    return h;
}

}  // namespace mh
