#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "results/result_set.hpp"

namespace mh {

enum class SortKey { Address, Pattern, Kind, Length, Region };

std::optional<SortKey> parse_sort_key(std::string_view text);
std::string_view to_string(SortKey key);

struct MatchQuery {
    std::vector<AddressRange> address_ranges;
    std::vector<PatternKind> kinds;
    std::vector<std::uint32_t> patterns;
    std::string text;
    SortKey sort = SortKey::Address;
    bool descending = false;
    std::size_t limit = 0;
};

// Returns indices into results.matches; the result set itself is never copied or reordered.
std::vector<std::size_t> run_query(const ResultSet& results, const MatchQuery& query);

std::vector<std::uint32_t> patterns_with_label(const ResultSet& results, std::string_view label);

}  // namespace mh
