#include "scanner/matcher_factory.hpp"

#include <algorithm>

#include "common/error.hpp"
#include "common/text.hpp"

namespace mh {

namespace {

// Up to this many anchored patterns, one SIMD pass per pattern is at least as fast as a single Aho-Corasick pass.
// The measured crossover is about 20 patterns while other processes load the machine and about 40 on an idle one
// (bench/README.md, "Matcher throughput"); a scan usually runs next to a busy target, so the lower one is used.
constexpr std::size_t kSimdPassLimit = 20;

std::unique_ptr<Matcher> combine(std::vector<std::unique_ptr<Matcher>> parts) {
    if (parts.empty()) {
        return nullptr;
    }
    if (parts.size() == 1) {
        return std::move(parts.front());
    }
    return std::make_unique<CompositeMatcher>(std::move(parts));
}

}  // namespace

std::string_view to_string(Algorithm algorithm) {
    switch (algorithm) {
        case Algorithm::Auto: return "auto";
        case Algorithm::Naive: return "naive";
        case Algorithm::Horspool: return "horspool";
        case Algorithm::Simd: return "simd";
        case Algorithm::AhoCorasick: return "aho-corasick";
    }
    return "?";
}

std::optional<Algorithm> parse_algorithm(std::string_view text) {
    for (const auto algorithm : {Algorithm::Auto, Algorithm::Naive, Algorithm::Horspool, Algorithm::Simd, Algorithm::AhoCorasick}) {
        if (iequals_ascii(text, to_string(algorithm))) {
            return algorithm;
        }
    }
    if (iequals_ascii(text, "ac")) {
        return Algorithm::AhoCorasick;
    }
    return std::nullopt;
}

MatcherSetup build_matcher(std::span<const Pattern> patterns, const std::optional<StringOptions>& strings,
                           StringIds string_ids, Algorithm algorithm) {
    MatcherSetup setup;
    std::vector<CompiledPattern> anchored;
    std::vector<CompiledPattern> unanchored;
    for (std::size_t i = 0; i < patterns.size(); ++i) {
        CompiledPattern compiled(patterns[i], static_cast<std::uint32_t>(i));
        setup.look_ahead = std::max<std::size_t>(setup.look_ahead, compiled.size - 1);
        if (algorithm == Algorithm::Naive || choose_anchor(compiled, 1).empty()) {
            unanchored.push_back(std::move(compiled));
        } else {
            anchored.push_back(std::move(compiled));
        }
    }

    Algorithm effective = algorithm;
    if (effective == Algorithm::Auto) {
        effective = anchored.size() <= kSimdPassLimit ? Algorithm::Simd : Algorithm::AhoCorasick;
    }

    std::vector<std::unique_ptr<Matcher>> parts;
    if (!anchored.empty()) {
        switch (effective) {
            case Algorithm::AhoCorasick:
                parts.push_back(std::make_unique<AhoCorasickMatcher>(std::move(anchored), kDefaultMaxAnchor));
                break;
            case Algorithm::Horspool:
                for (auto& pattern : anchored) {
                    parts.push_back(std::make_unique<HorspoolMatcher>(std::move(pattern)));
                }
                break;
            default:
                for (auto& pattern : anchored) {
                    parts.push_back(std::make_unique<SimdMatcher>(std::move(pattern), best_simd_level()));
                }
                break;
        }
    }
    if (!unanchored.empty()) {
        parts.push_back(std::make_unique<NaiveMatcher>(std::move(unanchored)));
    }

    if (strings) {
        if (strings->min_length == 0 || strings->max_length < strings->min_length) {
            throw Error(ErrorCode::InvalidArgument, "string length limits must satisfy 1 <= min-length <= max-length");
        }
        if (strings->max_length > (1u << 20)) {
            throw Error(ErrorCode::InvalidArgument, "max-length is limited to 1048576 characters");
        }
        const std::size_t unit = (strings->encodings & encoding::Utf16) != 0 ? 2 : 1;
        setup.look_behind = std::max(setup.look_behind, unit);
        setup.look_ahead = std::max(setup.look_ahead, strings->max_length * unit);
        parts.push_back(std::make_unique<StringExtractor>(*strings, string_ids.ascii, string_ids.utf16));
    }

    setup.matcher = combine(std::move(parts));
    return setup;
}

}  // namespace mh
