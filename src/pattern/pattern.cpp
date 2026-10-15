#include "pattern/pattern.hpp"

#include <unordered_set>

#include "common/error.hpp"
#include "common/text.hpp"

namespace mh {

namespace {

int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool is_space(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

bool is_ascii_letter(std::uint32_t c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

std::string quoted(std::string_view text) {
    return "\"" + std::string(text) + "\"";
}

void push_byte(Pattern& pattern, std::uint8_t value, std::uint8_t and_mask, std::uint8_t or_mask) {
    pattern.and_mask.push_back(and_mask);
    pattern.or_mask.push_back(or_mask);
    pattern.value.push_back(static_cast<std::uint8_t>((value | or_mask) & and_mask));
}

void push_text_unit(Pattern& pattern, std::uint8_t byte, bool fold) {
    const bool letter = fold && is_ascii_letter(byte);
    push_byte(pattern, byte, 0xFF, letter ? 0x20 : 0x00);
}

void check_size(const Pattern& pattern) {
    if (pattern.size() > kMaxPatternSize) {
        throw Error(ErrorCode::InvalidPattern, "pattern " + quoted(pattern.label) + " is " + std::to_string(pattern.size()) +
                                                   " bytes long; the limit is " + std::to_string(kMaxPatternSize));
    }
}

}  // namespace

std::string_view to_string(PatternKind kind) {
    switch (kind) {
        case PatternKind::Ascii: return "ascii";
        case PatternKind::Utf16: return "utf16";
        case PatternKind::Bytes: return "bytes";
        case PatternKind::Signature: return "signature";
        case PatternKind::StringsAscii: return "strings-ascii";
        case PatternKind::StringsUtf16: return "strings-utf16";
    }
    return "?";
}

std::optional<PatternKind> parse_pattern_kind(std::string_view text) {
    for (const auto kind : {PatternKind::Ascii, PatternKind::Utf16, PatternKind::Bytes, PatternKind::Signature,
                            PatternKind::StringsAscii, PatternKind::StringsUtf16}) {
        if (iequals_ascii(text, to_string(kind))) {
            return kind;
        }
    }
    return std::nullopt;
}

bool is_utf16_kind(PatternKind kind) noexcept {
    return kind == PatternKind::Utf16 || kind == PatternKind::StringsUtf16;
}

bool is_extracted_string(PatternKind kind) noexcept {
    return kind == PatternKind::StringsAscii || kind == PatternKind::StringsUtf16;
}

std::uint32_t parse_encoding_list(std::string_view list) {
    std::uint32_t mask = 0;
    while (!list.empty()) {
        const auto comma = list.find(',');
        const std::string item = to_lower_ascii(list.substr(0, comma));
        list = comma == std::string_view::npos ? std::string_view{} : list.substr(comma + 1);
        if (item == "ascii") {
            mask |= encoding::Ascii;
        } else if (item == "utf16" || item == "utf-16" || item == "utf16le" || item == "unicode") {
            mask |= encoding::Utf16;
        } else if (item == "both" || item == "all") {
            mask |= encoding::Both;
        } else if (!item.empty()) {
            throw Error(ErrorCode::InvalidArgument, "unknown encoding '" + item + "'; expected ascii, utf16 or both");
        }
    }
    if (mask == 0) {
        throw Error(ErrorCode::InvalidArgument, "empty encoding list");
    }
    return mask;
}

bool Pattern::is_exact() const noexcept {
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (and_mask[i] != 0xFF || or_mask[i] != 0) {
            return false;
        }
    }
    return true;
}

bool Pattern::matches(const std::uint8_t* data) const noexcept {
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (((data[i] | or_mask[i]) & and_mask[i]) != value[i]) {
            return false;
        }
    }
    return true;
}

Pattern parse_signature(std::string_view text) {
    Pattern pattern;
    std::size_t first = 0;
    std::size_t last = text.size();
    while (first < last && is_space(text[first])) ++first;
    while (last > first && is_space(text[last - 1])) --last;
    pattern.label = std::string(text.substr(first, last - first));

    std::size_t i = 0;
    while (i < text.size()) {
        if (is_space(text[i])) {
            ++i;
            continue;
        }
        const std::size_t token_begin = i;
        while (i < text.size() && !is_space(text[i])) {
            ++i;
        }
        const std::string_view token = text.substr(token_begin, i - token_begin);
        if (token == "?" || token == "??") {
            push_byte(pattern, 0, 0x00, 0x00);
            continue;
        }
        for (std::size_t k = 0; k < token.size(); ++k) {
            const char c = token[k];
            if (c != '?' && hex_digit(c) < 0) {
                throw Error(ErrorCode::InvalidPattern,
                            "invalid character '" + std::string(1, c) + "' at column " + std::to_string(token_begin + k + 1) +
                                " in signature " + quoted(pattern.label) + "; use hex digits 0-9 A-F and ?? for any byte");
            }
        }
        if (token.size() % 2 != 0) {
            throw Error(ErrorCode::InvalidPattern,
                        "token \"" + std::string(token) + "\" at column " + std::to_string(token_begin + 1) + " in signature " +
                            quoted(pattern.label) + " has an odd number of digits; write every byte as two hex digits");
        }
        for (std::size_t k = 0; k < token.size(); k += 2) {
            const char high = token[k];
            const char low = token[k + 1];
            std::uint8_t value = 0;
            std::uint8_t mask = 0;
            if (high != '?') {
                value |= static_cast<std::uint8_t>(hex_digit(high) << 4);
                mask |= 0xF0;
            }
            if (low != '?') {
                value |= static_cast<std::uint8_t>(hex_digit(low));
                mask |= 0x0F;
            }
            push_byte(pattern, value, mask, 0x00);
        }
    }

    if (pattern.value.empty()) {
        throw Error(ErrorCode::InvalidPattern, "signature is empty");
    }
    bool has_fixed_bits = false;
    bool has_wildcards = false;
    for (const auto mask : pattern.and_mask) {
        has_fixed_bits |= mask != 0;
        has_wildcards |= mask != 0xFF;
    }
    if (!has_fixed_bits) {
        throw Error(ErrorCode::InvalidPattern,
                    "signature " + quoted(pattern.label) + " consists only of wildcards and would match every address");
    }
    check_size(pattern);
    pattern.kind = has_wildcards ? PatternKind::Signature : PatternKind::Bytes;
    return pattern;
}

std::vector<Pattern> make_text_patterns(std::string_view utf8, std::uint32_t encodings, bool ignore_case) {
    if (utf8.empty()) {
        throw Error(ErrorCode::InvalidPattern, "search string is empty");
    }
    const std::wstring wide = utf8_to_wide(utf8);
    std::vector<Pattern> patterns;
    if ((encodings & encoding::Ascii) != 0) {
        Pattern pattern;
        pattern.label = std::string(utf8);
        pattern.kind = PatternKind::Ascii;
        pattern.case_insensitive = ignore_case;
        for (const char c : utf8) {
            push_text_unit(pattern, static_cast<std::uint8_t>(c), ignore_case);
        }
        check_size(pattern);
        patterns.push_back(std::move(pattern));
    }
    if ((encodings & encoding::Utf16) != 0) {
        Pattern pattern;
        pattern.label = std::string(utf8);
        pattern.kind = PatternKind::Utf16;
        pattern.case_insensitive = ignore_case;
        for (const wchar_t unit : wide) {
            const auto code = static_cast<std::uint32_t>(unit);
            push_text_unit(pattern, static_cast<std::uint8_t>(code & 0xFF), ignore_case && code < 0x80);
            push_byte(pattern, static_cast<std::uint8_t>(code >> 8), 0xFF, 0x00);
        }
        check_size(pattern);
        patterns.push_back(std::move(pattern));
    }
    return patterns;
}

std::vector<Pattern> deduplicate(std::vector<Pattern> patterns) {
    std::unordered_set<std::string> seen;
    std::vector<Pattern> unique;
    unique.reserve(patterns.size());
    for (auto& pattern : patterns) {
        std::string key;
        key.reserve(3 * pattern.size() + 2);
        key.push_back(static_cast<char>(pattern.kind));
        key.push_back(pattern.case_insensitive ? '1' : '0');
        key.append(pattern.value.begin(), pattern.value.end());
        key.append(pattern.and_mask.begin(), pattern.and_mask.end());
        key.append(pattern.or_mask.begin(), pattern.or_mask.end());
        if (seen.insert(std::move(key)).second) {
            unique.push_back(std::move(pattern));
        }
    }
    return unique;
}

}  // namespace mh
