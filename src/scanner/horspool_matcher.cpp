#include <algorithm>
#include <stdexcept>

#include "scanner/matchers.hpp"

namespace mh {

HorspoolMatcher::HorspoolMatcher(CompiledPattern pattern) : pattern_(std::move(pattern)) {
    anchor_ = choose_anchor(pattern_, pattern_.size);
    if (anchor_.empty()) {
        throw std::invalid_argument("Horspool needs at least one fixed byte");
    }
    // With case folding the shift table and comparisons work on folded bytes; that admits a superset of
    // candidates and the final masked verification restores exactness.
    fold_ = make_fold_table(pattern_.folds_case);
    for (std::size_t k = 0; k < anchor_.length; ++k) {
        needle_.push_back(fold_[pattern_.value[anchor_.offset + k]]);
    }
    const auto m = static_cast<std::uint32_t>(needle_.size());
    shift_.fill(m);
    for (std::uint32_t i = 0; i + 1 < m; ++i) {
        shift_[needle_[i]] = m - 1 - i;
    }
}

void HorspoolMatcher::scan(std::span<const std::byte> data, std::uint64_t, std::size_t report_begin,
                           std::size_t report_end, std::vector<Hit>& hits) const {
    const auto* bytes = as_bytes(data.data());
    const std::size_t size = data.size();
    if (size < pattern_.size) {
        return;
    }
    const std::size_t start_end = std::min(report_end, size - pattern_.size + 1);
    if (report_begin >= start_end) {
        return;
    }
    const std::size_t m = needle_.size();
    const std::uint8_t last_needle = needle_[m - 1];
    std::size_t anchor_pos = report_begin + anchor_.offset;
    const std::size_t anchor_end = start_end + anchor_.offset;
    while (anchor_pos < anchor_end) {
        const std::uint8_t last = fold_[bytes[anchor_pos + m - 1]];
        if (last == last_needle) {
            std::size_t k = 0;
            while (k + 1 < m && fold_[bytes[anchor_pos + k]] == needle_[k]) {
                ++k;
            }
            const std::size_t start = anchor_pos - anchor_.offset;
            if (k + 1 >= m && pattern_.matches(bytes + start)) {
                hits.push_back({start, pattern_.id, pattern_.size});
            }
        }
        anchor_pos += shift_[last];
    }
}

std::string HorspoolMatcher::describe() const {
    return "horspool";
}

}  // namespace mh
