#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mh {

enum class PatternKind : std::uint8_t { Ascii, Utf16, Bytes, Signature, StringsAscii, StringsUtf16 };

std::string_view to_string(PatternKind kind);
std::optional<PatternKind> parse_pattern_kind(std::string_view text);
bool is_utf16_kind(PatternKind kind) noexcept;
bool is_extracted_string(PatternKind kind) noexcept;

namespace encoding {
inline constexpr std::uint32_t Ascii = 1u << 0;
inline constexpr std::uint32_t Utf16 = 1u << 1;
inline constexpr std::uint32_t Both = Ascii | Utf16;
}  // namespace encoding

std::uint32_t parse_encoding_list(std::string_view list);

inline constexpr std::size_t kMaxPatternSize = 4096;

// A byte d at position i matches when ((d | or_mask[i]) & and_mask[i]) == value[i]. This single form covers
// exact bytes (and=FF), wildcards (and=00), nibble masks (F0/0F) and ASCII case folding (or=20 on letters).
struct Pattern {
    std::string label;
    PatternKind kind = PatternKind::Bytes;
    bool case_insensitive = false;
    std::vector<std::uint8_t> value;
    std::vector<std::uint8_t> and_mask;
    std::vector<std::uint8_t> or_mask;

    std::size_t size() const noexcept { return value.size(); }
    bool is_exact() const noexcept;
    bool matches(const std::uint8_t* data) const noexcept;
};

Pattern parse_signature(std::string_view text);
std::vector<Pattern> make_text_patterns(std::string_view utf8, std::uint32_t encodings, bool ignore_case);
std::vector<Pattern> deduplicate(std::vector<Pattern> patterns);

}  // namespace mh
