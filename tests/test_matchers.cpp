#include <gtest/gtest.h>

#include <algorithm>
#include <memory>
#include <random>

#include "scanner/anchor.hpp"
#include "scanner/matcher_factory.hpp"
#include "scanner/matchers.hpp"

namespace mh {
namespace {

using Hits = std::vector<std::tuple<std::size_t, std::uint32_t, std::uint32_t>>;

Hits brute_force(std::span<const std::uint8_t> data, std::span<const Pattern> patterns, std::size_t begin, std::size_t end) {
    Hits hits;
    for (std::uint32_t p = 0; p < patterns.size(); ++p) {
        const std::size_t size = patterns[p].size();
        for (std::size_t i = begin; i < end && i + size <= data.size(); ++i) {
            if (patterns[p].matches(data.data() + i)) {
                hits.emplace_back(i, p, static_cast<std::uint32_t>(size));
            }
        }
    }
    std::sort(hits.begin(), hits.end());
    return hits;
}

Hits run(const Matcher& matcher, std::span<const std::uint8_t> data, std::size_t begin, std::size_t end) {
    std::vector<Hit> raw;
    matcher.scan(std::as_bytes(data), 0x10000, begin, end, raw);
    Hits hits;
    for (const auto& h : raw) {
        hits.emplace_back(h.offset, h.pattern, h.length);
    }
    std::sort(hits.begin(), hits.end());
    return hits;
}

std::vector<std::pair<std::string, std::unique_ptr<Matcher>>> all_matchers(std::span<const Pattern> patterns) {
    std::vector<std::pair<std::string, std::unique_ptr<Matcher>>> matchers;
    for (const auto algorithm : {Algorithm::Auto, Algorithm::Naive, Algorithm::Horspool, Algorithm::Simd, Algorithm::AhoCorasick}) {
        matchers.emplace_back(std::string(to_string(algorithm)), build_matcher(patterns, std::nullopt, {}, algorithm).matcher);
    }
    std::vector<std::unique_ptr<Matcher>> scalar;
    std::vector<CompiledPattern> unanchored;
    for (std::uint32_t i = 0; i < patterns.size(); ++i) {
        CompiledPattern compiled(patterns[i], i);
        if (choose_anchor(compiled, 1).empty()) {
            unanchored.push_back(std::move(compiled));
        } else {
            scalar.push_back(std::make_unique<SimdMatcher>(std::move(compiled), SimdLevel::Scalar));
        }
    }
    if (!unanchored.empty()) {
        scalar.push_back(std::make_unique<NaiveMatcher>(std::move(unanchored)));
    }
    matchers.emplace_back("simd-scalar", std::make_unique<CompositeMatcher>(std::move(scalar)));
    return matchers;
}

void expect_all_agree(std::span<const std::uint8_t> data, std::span<const Pattern> patterns, std::size_t begin, std::size_t end,
                      const std::string& context) {
    const Hits expected = brute_force(data, patterns, begin, end);
    for (const auto& [name, matcher] : all_matchers(patterns)) {
        ASSERT_TRUE(matcher) << name;
        EXPECT_EQ(run(*matcher, data, begin, end), expected) << name << " (" << matcher->describe() << ") " << context;
    }
}

Pattern from_bytes(std::span<const std::uint8_t> bytes, std::string label = "p") {
    Pattern pattern;
    pattern.label = std::move(label);
    pattern.value.assign(bytes.begin(), bytes.end());
    pattern.and_mask.assign(bytes.size(), 0xFF);
    pattern.or_mask.assign(bytes.size(), 0x00);
    return pattern;
}

std::vector<std::uint8_t> text(std::string_view s) {
    return {s.begin(), s.end()};
}

TEST(Matchers, OverlappingMatches) {
    const auto data = text("AAAAAA");
    const std::vector<Pattern> patterns{from_bytes(text("AA"))};
    expect_all_agree(data, patterns, 0, data.size(), "overlap");
    EXPECT_EQ(brute_force(data, patterns, 0, data.size()).size(), 5u);
}

TEST(Matchers, MatchesAtBufferEdges) {
    const auto data = text("needle-in-the-middle-needle");
    const std::vector<Pattern> patterns{from_bytes(text("needle")), from_bytes(text("e"))};
    expect_all_agree(data, patterns, 0, data.size(), "edges");
}

TEST(Matchers, ReportWindowUsesLookAheadButNotLookBehind) {
    const auto data = text("xxABCDxxABCDxx");
    const std::vector<Pattern> patterns{from_bytes(text("ABCD"))};
    // A match starting inside the window may extend past its end; one starting before the window is not reported.
    const Hits hits = run(*build_matcher(patterns, std::nullopt, {}, Algorithm::Simd).matcher, data, 3, 9);
    EXPECT_EQ(hits, (Hits{{8, 0, 4}}));
    expect_all_agree(data, patterns, 3, 9, "window");
    expect_all_agree(data, patterns, 2, 3, "single position");
    expect_all_agree(data, patterns, 11, 14, "too short");
}

TEST(Matchers, PatternLongerThanBuffer) {
    const auto data = text("abc");
    const std::vector<Pattern> patterns{from_bytes(text("abcd"))};
    expect_all_agree(data, patterns, 0, data.size(), "short buffer");
    expect_all_agree({}, patterns, 0, 0, "empty buffer");
}

TEST(Matchers, SignatureWithWildcardsAndSingleFixedByte) {
    std::vector<Pattern> patterns;
    patterns.push_back(parse_signature("48 8B ?? ?? 90"));
    patterns.push_back(parse_signature("?? ?? CC"));
    patterns.push_back(parse_signature("4? 8?"));
    std::vector<std::uint8_t> data(4096);
    std::mt19937 rng(7);
    const std::uint8_t alphabet[] = {0x48, 0x8B, 0x90, 0xCC, 0x00, 0x41, 0x8F};
    for (auto& b : data) {
        b = alphabet[rng() % std::size(alphabet)];
    }
    expect_all_agree(data, patterns, 0, data.size(), "signatures");
}

TEST(Matchers, CaseInsensitiveText) {
    const auto patterns = make_text_patterns("Config.JSON", encoding::Both, true);
    std::vector<std::uint8_t> data;
    const auto ascii = [&](std::string_view s) { data.insert(data.end(), s.begin(), s.end()); };
    const auto wide = [&](std::string_view s) {
        for (const char c : s) {
            data.push_back(static_cast<std::uint8_t>(c));
            data.push_back(0);
        }
    };
    ascii("..config.json..CONFIG.JSON..");
    wide("CoNfIg.json");
    ascii("..configXjson");
    wide("config.json");
    expect_all_agree(data, patterns, 0, data.size(), "ignore case");
    EXPECT_EQ(brute_force(data, patterns, 0, data.size()).size(), 4u);
}

TEST(Matchers, RandomizedAgainstBruteForce) {
    std::mt19937_64 rng(12345);
    const std::uint8_t alphabet[] = {0x00, 0xFF, 0x41, 0x61, 0x42, 0x90, 0xCC, 0x48, 0x8B};
    for (int round = 0; round < 150; ++round) {
        std::vector<std::uint8_t> data(rng() % 3000);
        for (auto& b : data) {
            b = rng() % 4 == 0 ? static_cast<std::uint8_t>(rng()) : alphabet[rng() % std::size(alphabet)];
        }
        const std::size_t count = 1 + rng() % (round % 10 == 0 ? 60 : 6);
        std::vector<Pattern> patterns;
        for (std::size_t p = 0; p < count; ++p) {
            const std::size_t length = 1 + rng() % 24;
            std::vector<std::uint8_t> bytes(length);
            if (data.size() > length && rng() % 4 != 0) {
                const std::size_t at = rng() % (data.size() - length);
                std::copy_n(data.begin() + static_cast<std::ptrdiff_t>(at), length, bytes.begin());
            } else {
                for (auto& b : bytes) b = alphabet[rng() % std::size(alphabet)];
            }
            Pattern pattern = from_bytes(bytes, "r" + std::to_string(p));
            for (std::size_t i = 0; i < length; ++i) {
                switch (rng() % 8) {
                    case 0: pattern.and_mask[i] = 0x00; break;
                    case 1: pattern.and_mask[i] = 0xF0; break;
                    case 2: pattern.and_mask[i] = 0x0F; break;
                    case 3:
                        if ((bytes[i] | 0x20) >= 'a' && (bytes[i] | 0x20) <= 'z') pattern.or_mask[i] = 0x20;
                        break;
                    default: break;
                }
                pattern.value[i] = static_cast<std::uint8_t>((bytes[i] | pattern.or_mask[i]) & pattern.and_mask[i]);
            }
            if (std::all_of(pattern.and_mask.begin(), pattern.and_mask.end(), [](std::uint8_t m) { return m == 0; })) {
                pattern.and_mask[0] = 0xFF;
                pattern.value[0] = static_cast<std::uint8_t>(bytes[0] | pattern.or_mask[0]);
            }
            pattern.kind = pattern.is_exact() ? PatternKind::Bytes : PatternKind::Signature;
            patterns.push_back(std::move(pattern));
        }
        const std::size_t begin = data.empty() ? 0 : rng() % (data.size() / 2 + 1);
        const std::size_t end = rng() % 3 == 0 ? data.size() : begin + rng() % (data.size() - begin + 1);
        expect_all_agree(data, patterns, begin, end, "round " + std::to_string(round));
        if (::testing::Test::HasFailure()) {
            break;
        }
    }
}

TEST(Matchers, ManyPatternsUseAhoCorasick) {
    std::mt19937_64 rng(99);
    std::vector<std::uint8_t> data(1 << 16);
    for (auto& b : data) b = static_cast<std::uint8_t>(rng());
    std::vector<Pattern> patterns;
    for (int p = 0; p < 300; ++p) {
        const std::size_t at = rng() % (data.size() - 32);
        patterns.push_back(from_bytes(std::span(data).subspan(at, 4 + rng() % 12), "m" + std::to_string(p)));
    }
    const auto setup = build_matcher(patterns, std::nullopt, {}, Algorithm::Auto);
    EXPECT_NE(setup.matcher->describe().find("aho"), std::string::npos) << setup.matcher->describe();
    expect_all_agree(data, patterns, 0, data.size(), "300 patterns");
}

TEST(Matchers, AutoUsesSimdPassesUpToTheMeasuredLimit) {
    std::vector<Pattern> patterns;
    for (int p = 0; p < 21; ++p) {
        patterns.push_back(from_bytes(text("sig-" + std::to_string(1000 + p)), "s" + std::to_string(p)));
    }
    const auto simd = build_matcher(std::span(patterns).first(20), std::nullopt, {}, Algorithm::Auto);
    EXPECT_EQ(simd.matcher->describe(), "20 x simd-" + std::string(to_string(best_simd_level())));
    const auto ac = build_matcher(patterns, std::nullopt, {}, Algorithm::Auto);
    EXPECT_EQ(ac.matcher->describe().rfind("aho-corasick(21 patterns", 0), 0u) << ac.matcher->describe();
}

TEST(Matchers, LookAheadCoversLongestPattern) {
    std::vector<Pattern> patterns{from_bytes(text("ab")), from_bytes(text("abcdefgh"))};
    const auto setup = build_matcher(patterns, std::nullopt, {}, Algorithm::Auto);
    EXPECT_EQ(setup.look_ahead, 7u);
    EXPECT_EQ(setup.look_behind, 0u);
}

TEST(Matchers, NothingToSearchYieldsNoMatcher) {
    EXPECT_FALSE(build_matcher({}, std::nullopt, {}, Algorithm::Auto).matcher);
}

}  // namespace
}  // namespace mh
