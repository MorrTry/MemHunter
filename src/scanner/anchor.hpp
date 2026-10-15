#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "scanner/compiled_pattern.hpp"

namespace mh {

struct Anchor {
    std::size_t offset = 0;
    std::size_t length = 0;

    bool empty() const noexcept { return length == 0; }
};

// Rough rarity of a byte value in real process memory: zero padding, 0xFF fill and int3/nop padding are
// everywhere, so anchors built from them produce floods of false candidates.
std::uint32_t byte_rarity(std::uint8_t value) noexcept;

// Picks the window of fixed (non-wildcard) bytes with the best rarity score, at most max_length long.
Anchor choose_anchor(const CompiledPattern& pattern, std::size_t max_length);

// Two fixed positions used by the SIMD prefilter; both equal when the pattern has a single fixed byte.
std::array<std::size_t, 2> choose_filter_positions(const CompiledPattern& pattern);

std::array<std::uint8_t, 256> make_fold_table(bool fold_case) noexcept;

}  // namespace mh
