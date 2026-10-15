#include <algorithm>
#include <bit>
#include <stdexcept>

#include "scanner/matchers.hpp"

#if defined(__SSE2__) || defined(_M_X64) || (defined(_M_IX86_FP) && _M_IX86_FP >= 2)
#define MEMHUNTER_HAS_SSE2 1
#include <emmintrin.h>
#else
#define MEMHUNTER_HAS_SSE2 0
#endif

namespace mh {

SimdLevel best_simd_level() noexcept {
    return MEMHUNTER_HAS_SSE2 ? SimdLevel::Sse2 : SimdLevel::Scalar;
}

std::string_view to_string(SimdLevel level) {
    switch (level) {
        case SimdLevel::Scalar: return "scalar";
        case SimdLevel::Sse2: return "sse2";
    }
    return "?";
}

SimdMatcher::SimdMatcher(CompiledPattern pattern, SimdLevel level) : pattern_(std::move(pattern)), level_(level) {
    if (choose_anchor(pattern_, 1).empty()) {
        throw std::invalid_argument("the SIMD prefilter needs at least one fixed byte");
    }
    if (!MEMHUNTER_HAS_SSE2) {
        level_ = SimdLevel::Scalar;
    }
    const auto positions = choose_filter_positions(pattern_);
    first_ = positions[0];
    second_ = positions[1];
    first_value_ = pattern_.value[first_];
    second_value_ = pattern_.value[second_];
    first_or_ = pattern_.or_mask[first_];
    second_or_ = pattern_.or_mask[second_];
}

void SimdMatcher::scan(std::span<const std::byte> data, std::uint64_t, std::size_t report_begin,
                       std::size_t report_end, std::vector<Hit>& hits) const {
    const auto* bytes = as_bytes(data.data());
    const std::size_t size = data.size();
    if (size < pattern_.size) {
        return;
    }
    const std::size_t start_end = std::min(report_end, size - pattern_.size + 1);
    std::size_t start = report_begin;

#if MEMHUNTER_HAS_SSE2
    if (level_ == SimdLevel::Sse2) {
        const __m128i first_value = _mm_set1_epi8(static_cast<char>(first_value_));
        const __m128i second_value = _mm_set1_epi8(static_cast<char>(second_value_));
        const __m128i first_or = _mm_set1_epi8(static_cast<char>(first_or_));
        const __m128i second_or = _mm_set1_epi8(static_cast<char>(second_or_));
        // Lane i tests candidate start + i; the highest load reaches start_end - 1 + second_ < size.
        for (; start + 16 <= start_end; start += 16) {
            const __m128i a = _mm_or_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(bytes + start + first_)), first_or);
            const __m128i b = _mm_or_si128(_mm_loadu_si128(reinterpret_cast<const __m128i*>(bytes + start + second_)), second_or);
            auto mask = static_cast<unsigned>(_mm_movemask_epi8(_mm_and_si128(_mm_cmpeq_epi8(a, first_value), _mm_cmpeq_epi8(b, second_value))));
            while (mask != 0) {
                const std::size_t candidate = start + static_cast<std::size_t>(std::countr_zero(mask));
                if (pattern_.matches(bytes + candidate)) {
                    hits.push_back({candidate, pattern_.id, pattern_.size});
                }
                mask &= mask - 1;
            }
        }
    }
#endif

    for (; start < start_end; ++start) {
        if ((bytes[start + first_] | first_or_) == first_value_ && (bytes[start + second_] | second_or_) == second_value_ &&
            pattern_.matches(bytes + start)) {
            hits.push_back({start, pattern_.id, pattern_.size});
        }
    }
}

std::string SimdMatcher::describe() const {
    return "simd-" + std::string(to_string(level_));
}

}  // namespace mh
