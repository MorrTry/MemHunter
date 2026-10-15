#pragma once

#include <cstdint>
#include <cstring>
#include <vector>

#include "pattern/pattern.hpp"

namespace mh {

struct CompiledPattern {
    std::uint32_t id = 0;
    std::uint32_t size = 0;
    bool exact = true;
    bool folds_case = false;
    std::vector<std::uint8_t> value;
    std::vector<std::uint8_t> and_mask;
    std::vector<std::uint8_t> or_mask;

    CompiledPattern(const Pattern& pattern, std::uint32_t pattern_id)
        : id(pattern_id),
          size(static_cast<std::uint32_t>(pattern.size())),
          exact(pattern.is_exact()),
          value(pattern.value),
          and_mask(pattern.and_mask),
          or_mask(pattern.or_mask) {
        for (const auto bits : or_mask) {
            folds_case |= bits != 0;
        }
    }

    bool fixed_at(std::size_t i) const noexcept { return and_mask[i] == 0xFF; }

    bool matches(const std::uint8_t* data) const noexcept {
        if (exact) {
            return std::memcmp(data, value.data(), size) == 0;
        }
        std::size_t i = 0;
        for (; i + 8 <= size; i += 8) {
            std::uint64_t d;
            std::uint64_t o;
            std::uint64_t a;
            std::uint64_t v;
            std::memcpy(&d, data + i, 8);
            std::memcpy(&o, or_mask.data() + i, 8);
            std::memcpy(&a, and_mask.data() + i, 8);
            std::memcpy(&v, value.data() + i, 8);
            if (((d | o) & a) != v) {
                return false;
            }
        }
        for (; i < size; ++i) {
            if (((data[i] | or_mask[i]) & and_mask[i]) != value[i]) {
                return false;
            }
        }
        return true;
    }
};

inline const std::uint8_t* as_bytes(const std::byte* data) noexcept {
    return reinterpret_cast<const std::uint8_t*>(data);
}

}  // namespace mh
