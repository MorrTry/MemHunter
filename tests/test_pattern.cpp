#include <gtest/gtest.h>

#include "common/error.hpp"
#include "pattern/pattern.hpp"

namespace mh {
namespace {

std::vector<std::uint8_t> bytes(std::initializer_list<int> values) {
    std::vector<std::uint8_t> out;
    for (const int v : values) {
        out.push_back(static_cast<std::uint8_t>(v));
    }
    return out;
}

std::string error_of(std::string_view text) {
    try {
        parse_signature(text);
    } catch (const Error& error) {
        EXPECT_EQ(error.code(), ErrorCode::InvalidPattern);
        return error.what();
    }
    ADD_FAILURE() << "no error for '" << text << "'";
    return {};
}

TEST(Signature, SpacedExactBytes) {
    const Pattern p = parse_signature("48 8B 05 90");
    EXPECT_EQ(p.kind, PatternKind::Bytes);
    EXPECT_EQ(p.value, bytes({0x48, 0x8B, 0x05, 0x90}));
    EXPECT_EQ(p.and_mask, bytes({0xFF, 0xFF, 0xFF, 0xFF}));
    EXPECT_TRUE(p.is_exact());
    EXPECT_EQ(p.label, "48 8B 05 90");
}

TEST(Signature, Wildcards) {
    const Pattern p = parse_signature("48 8B ?? ? 90");
    EXPECT_EQ(p.kind, PatternKind::Signature);
    EXPECT_EQ(p.size(), 5u);
    EXPECT_EQ(p.and_mask, bytes({0xFF, 0xFF, 0x00, 0x00, 0xFF}));
    EXPECT_FALSE(p.is_exact());
}

TEST(Signature, CompactAndLowercase) {
    const Pattern a = parse_signature("488b????90");
    const Pattern b = parse_signature("48 8B ?? ?? 90");
    EXPECT_EQ(a.value, b.value);
    EXPECT_EQ(a.and_mask, b.and_mask);
}

TEST(Signature, NibbleWildcards) {
    const Pattern p = parse_signature("4? ?F");
    EXPECT_EQ(p.and_mask, bytes({0xF0, 0x0F}));
    EXPECT_EQ(p.value, bytes({0x40, 0x0F}));
    const std::uint8_t yes[] = {0x4A, 0x3F};
    const std::uint8_t no[] = {0x5A, 0x3F};
    EXPECT_TRUE(p.matches(yes));
    EXPECT_FALSE(p.matches(no));
}

TEST(Signature, SurroundingWhitespaceIsTrimmedFromLabel) {
    EXPECT_EQ(parse_signature("  \tDE AD  ").label, "DE AD");
}

TEST(Signature, Errors) {
    EXPECT_NE(error_of("48 8G").find("column 5"), std::string::npos);
    EXPECT_NE(error_of("48 8").find("odd number of digits"), std::string::npos);
    EXPECT_NE(error_of("?? ??").find("only of wildcards"), std::string::npos);
    EXPECT_NE(error_of("   ").find("empty"), std::string::npos);
    EXPECT_NE(error_of("48 ???").find("odd"), std::string::npos);
    EXPECT_NE(error_of("0x48").find("invalid character 'x'"), std::string::npos);
}

TEST(Signature, SizeLimit) {
    std::string text;
    for (std::size_t i = 0; i <= kMaxPatternSize; ++i) {
        text += "AB";
    }
    EXPECT_NE(error_of(text).find("limit"), std::string::npos);
}

TEST(TextPattern, AsciiAndUtf16) {
    const auto patterns = make_text_patterns("Ab", encoding::Both, false);
    ASSERT_EQ(patterns.size(), 2u);
    EXPECT_EQ(patterns[0].kind, PatternKind::Ascii);
    EXPECT_EQ(patterns[0].value, bytes({'A', 'b'}));
    EXPECT_EQ(patterns[1].kind, PatternKind::Utf16);
    EXPECT_EQ(patterns[1].value, bytes({'A', 0, 'b', 0}));
    EXPECT_TRUE(patterns[1].is_exact());
}

TEST(TextPattern, CyrillicUtf16) {
    const auto patterns = make_text_patterns("\xD0\x96", encoding::Utf16, false);
    ASSERT_EQ(patterns.size(), 1u);
    EXPECT_EQ(patterns[0].value, bytes({0x16, 0x04}));
}

TEST(TextPattern, IgnoreCaseFoldsAsciiLettersOnly) {
    const auto patterns = make_text_patterns("A1-z", encoding::Both, true);
    const auto& ascii = patterns[0];
    const std::uint8_t upper[] = {'A', '1', '-', 'Z'};
    const std::uint8_t lower[] = {'a', '1', '-', 'z'};
    const std::uint8_t other[] = {'a', '1', '\r', 'z'};
    EXPECT_TRUE(ascii.matches(upper));
    EXPECT_TRUE(ascii.matches(lower));
    EXPECT_FALSE(ascii.matches(other));
    EXPECT_FALSE(ascii.is_exact());

    const auto& wide = patterns[1];
    const std::uint8_t wide_mixed[] = {'a', 0, '1', 0, '-', 0, 'Z', 0};
    const std::uint8_t wide_shifted[] = {'a', 0x20, '1', 0, '-', 0, 'Z', 0};
    EXPECT_TRUE(wide.matches(wide_mixed));
    EXPECT_FALSE(wide.matches(wide_shifted));
}

TEST(TextPattern, RejectsEmptyAndInvalidUtf8) {
    EXPECT_THROW(make_text_patterns("", encoding::Both, false), Error);
    EXPECT_THROW(make_text_patterns("\xFF", encoding::Utf16, false), Error);
}

TEST(TextPattern, EncodingList) {
    EXPECT_EQ(parse_encoding_list("ascii"), encoding::Ascii);
    EXPECT_EQ(parse_encoding_list("utf16"), encoding::Utf16);
    EXPECT_EQ(parse_encoding_list("ascii,unicode"), encoding::Both);
    EXPECT_THROW(parse_encoding_list("ebcdic"), Error);
}

TEST(Patterns, DeduplicateKeepsFirstOfIdentical) {
    std::vector<Pattern> patterns;
    patterns.push_back(parse_signature("90 90"));
    patterns.push_back(parse_signature("9090"));
    patterns.push_back(parse_signature("90 ??"));
    auto texts = make_text_patterns("x", encoding::Both, false);
    patterns.insert(patterns.end(), texts.begin(), texts.end());
    const auto unique = deduplicate(patterns);
    ASSERT_EQ(unique.size(), 4u);
    EXPECT_EQ(unique[0].label, "90 90");
}

}  // namespace
}  // namespace mh
