#pragma once

#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <string_view>

#include "pattern/pattern.hpp"
#include "scanner/matchers.hpp"

namespace mh {

enum class Algorithm { Auto, Naive, Horspool, Simd, AhoCorasick };

std::string_view to_string(Algorithm algorithm);
std::optional<Algorithm> parse_algorithm(std::string_view text);

inline constexpr std::size_t kDefaultMaxAnchor = 8;

struct StringIds {
    std::uint32_t ascii = 0;
    std::uint32_t utf16 = 0;
};

struct MatcherSetup {
    std::unique_ptr<Matcher> matcher;
    std::size_t look_behind = 0;
    std::size_t look_ahead = 0;
};

// Pattern ids are indices into `patterns`. An empty pattern list without string extraction yields no matcher.
MatcherSetup build_matcher(std::span<const Pattern> patterns, const std::optional<StringOptions>& strings,
                           StringIds string_ids, Algorithm algorithm);

}  // namespace mh
