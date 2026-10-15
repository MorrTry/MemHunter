#include "scanner/anchor.hpp"

#include <algorithm>
#include <tuple>

namespace mh {

std::uint32_t byte_rarity(std::uint8_t value) noexcept {
    switch (value) {
        case 0x00: return 1;
        case 0xFF: return 2;
        case 0xCC:
        case 0x90: return 3;
        default: return value < 0x10 ? 4 : 8;
    }
}

Anchor choose_anchor(const CompiledPattern& pattern, std::size_t max_length) {
    Anchor best;
    std::uint64_t best_score = 0;
    std::size_t i = 0;
    while (i < pattern.size) {
        if (!pattern.fixed_at(i)) {
            ++i;
            continue;
        }
        std::size_t run_end = i;
        while (run_end < pattern.size && pattern.fixed_at(run_end)) {
            ++run_end;
        }
        for (std::size_t start = i; start < run_end; ++start) {
            const std::size_t length = std::min(max_length, run_end - start);
            std::uint64_t score = 0;
            for (std::size_t k = start; k < start + length; ++k) {
                score += byte_rarity(pattern.value[k]);
            }
            if (score > best_score || (score == best_score && length > best.length)) {
                best = {start, length};
                best_score = score;
            }
            if (start + length == run_end) {
                break;
            }
        }
        i = run_end;
    }
    return best;
}

std::array<std::size_t, 2> choose_filter_positions(const CompiledPattern& pattern) {
    std::size_t first = pattern.size;
    for (std::size_t i = 0; i < pattern.size; ++i) {
        if (pattern.fixed_at(i) && (first == pattern.size || byte_rarity(pattern.value[i]) > byte_rarity(pattern.value[first]))) {
            first = i;
        }
    }
    if (first == pattern.size) {
        return {0, 0};
    }
    // Prefer a rare second byte, then one that differs from the first, then the most distant one.
    const auto key = [&](std::size_t k) {
        const std::size_t distance = k > first ? k - first : first - k;
        return std::tuple(byte_rarity(pattern.value[k]), pattern.value[k] != pattern.value[first], distance);
    };
    std::size_t second = first;
    for (std::size_t i = 0; i < pattern.size; ++i) {
        if (i != first && pattern.fixed_at(i) && (second == first || key(i) > key(second))) {
            second = i;
        }
    }
    return {std::min(first, second), std::max(first, second)};
}

std::array<std::uint8_t, 256> make_fold_table(bool fold_case) noexcept {
    std::array<std::uint8_t, 256> table{};
    for (std::size_t b = 0; b < table.size(); ++b) {
        table[b] = static_cast<std::uint8_t>(b);
        if (fold_case && b >= 'A' && b <= 'Z') {
            table[b] = static_cast<std::uint8_t>(b | 0x20);
        }
    }
    return table;
}

}  // namespace mh
