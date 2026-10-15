#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <string_view>
#include <vector>

#include "pattern/pattern.hpp"
#include "scanner/anchor.hpp"
#include "scanner/compiled_pattern.hpp"
#include "scanner/matcher.hpp"

namespace mh {

// Reference implementation: checks every pattern at every position. Used as the test oracle and for
// patterns without a single fully fixed byte.
class NaiveMatcher final : public Matcher {
public:
    explicit NaiveMatcher(std::vector<CompiledPattern> patterns);

    void scan(std::span<const std::byte> data, std::uint64_t base_address, std::size_t report_begin,
              std::size_t report_end, std::vector<Hit>& hits) const override;
    std::string describe() const override;

private:
    std::vector<CompiledPattern> patterns_;
};

// Boyer-Moore-Horspool over the longest fixed run of one pattern, then a full masked verification.
class HorspoolMatcher final : public Matcher {
public:
    explicit HorspoolMatcher(CompiledPattern pattern);

    void scan(std::span<const std::byte> data, std::uint64_t base_address, std::size_t report_begin,
              std::size_t report_end, std::vector<Hit>& hits) const override;
    std::string describe() const override;

private:
    CompiledPattern pattern_;
    Anchor anchor_;
    std::vector<std::uint8_t> needle_;
    std::array<std::uint8_t, 256> fold_{};
    std::array<std::uint32_t, 256> shift_{};
};

enum class SimdLevel { Scalar, Sse2 };

SimdLevel best_simd_level() noexcept;
std::string_view to_string(SimdLevel level);

// Two-byte prefilter (16 candidate positions per step with SSE2), then a full masked verification.
class SimdMatcher final : public Matcher {
public:
    SimdMatcher(CompiledPattern pattern, SimdLevel level);

    void scan(std::span<const std::byte> data, std::uint64_t base_address, std::size_t report_begin,
              std::size_t report_end, std::vector<Hit>& hits) const override;
    std::string describe() const override;

private:
    CompiledPattern pattern_;
    SimdLevel level_;
    std::size_t first_ = 0;
    std::size_t second_ = 0;
    std::uint8_t first_value_ = 0;
    std::uint8_t second_value_ = 0;
    std::uint8_t first_or_ = 0;
    std::uint8_t second_or_ = 0;
};

// One pass over the data for any number of patterns: a dense Aho-Corasick DFA over each pattern's anchor
// (its rarest fixed window) yields candidates that are then verified against the full masked pattern.
class AhoCorasickMatcher final : public Matcher {
public:
    AhoCorasickMatcher(std::vector<CompiledPattern> patterns, std::size_t max_anchor_length);

    void scan(std::span<const std::byte> data, std::uint64_t base_address, std::size_t report_begin,
              std::size_t report_end, std::vector<Hit>& hits) const override;
    std::string describe() const override;

    std::size_t state_count() const noexcept { return output_begin_.empty() ? 0 : output_begin_.size() - 1; }

private:
    struct Output {
        std::uint32_t pattern;
        std::uint32_t anchor_end;
    };

    void report(const std::uint8_t* data, std::size_t size, std::size_t position, std::uint32_t state,
                std::size_t report_begin, std::size_t report_end, std::vector<Hit>& hits) const;

    std::vector<CompiledPattern> patterns_;
    std::array<std::uint16_t, 256> classes_{};
    std::uint32_t class_count_ = 1;
    std::vector<std::uint32_t> table_;
    std::vector<std::uint32_t> output_begin_;
    std::vector<Output> outputs_;
    std::size_t min_anchor_offset_ = 0;
    std::size_t max_anchor_end_ = 0;
};

struct StringOptions {
    std::uint32_t encodings = encoding::Both;
    std::size_t min_length = 4;
    std::size_t max_length = 4096;
};

// Extracts runs of printable characters like Sysinternals strings: ASCII at any address, UTF-16LE at even
// addresses. Runs longer than max_length are reported truncated to max_length.
class StringExtractor final : public Matcher {
public:
    StringExtractor(StringOptions options, std::uint32_t ascii_id, std::uint32_t utf16_id);

    void scan(std::span<const std::byte> data, std::uint64_t base_address, std::size_t report_begin,
              std::size_t report_end, std::vector<Hit>& hits) const override;
    std::string describe() const override;

private:
    void scan_ascii(const std::uint8_t* data, std::size_t size, std::size_t begin, std::size_t end,
                    std::vector<Hit>& hits) const;
    void scan_utf16(const std::uint8_t* data, std::size_t size, std::uint64_t base_address, std::size_t begin,
                    std::size_t end, std::vector<Hit>& hits) const;

    StringOptions options_;
    std::uint32_t ascii_id_;
    std::uint32_t utf16_id_;
};

class CompositeMatcher final : public Matcher {
public:
    explicit CompositeMatcher(std::vector<std::unique_ptr<Matcher>> parts);

    void scan(std::span<const std::byte> data, std::uint64_t base_address, std::size_t report_begin,
              std::size_t report_end, std::vector<Hit>& hits) const override;
    std::string describe() const override;

private:
    std::vector<std::unique_ptr<Matcher>> parts_;
};

}  // namespace mh
