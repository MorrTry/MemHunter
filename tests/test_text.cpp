#include <gtest/gtest.h>

#include "common/error.hpp"
#include "common/text.hpp"

namespace mh {
namespace {

TEST(Text, Utf8RoundTrip) {
    const std::string text = "MemHunter \xD0\x9F\xD1\x80\xD0\xB8\xD0\xB2\xD0\xB5\xD1\x82 \xF0\x9F\x94\x8D";
    EXPECT_EQ(wide_to_utf8(utf8_to_wide(text)), text);
    EXPECT_EQ(utf8_to_wide("\xD0\x96"), std::wstring(1, L'\x0416'));
}

TEST(Text, InvalidUtf8IsRejected) {
    EXPECT_THROW(utf8_to_wide("\xC3\x28"), Error);
}

TEST(Text, ParseUint) {
    EXPECT_EQ(parse_uint("0"), 0u);
    EXPECT_EQ(parse_uint("1234"), 1234u);
    EXPECT_EQ(parse_uint("0x1F"), 31u);
    EXPECT_EQ(parse_uint("0X7ffe0000"), 0x7FFE0000u);
    EXPECT_EQ(parse_uint("18446744073709551615"), 18446744073709551615ull);
    EXPECT_FALSE(parse_uint("18446744073709551616"));
    EXPECT_FALSE(parse_uint(""));
    EXPECT_FALSE(parse_uint("0x"));
    EXPECT_FALSE(parse_uint("12a"));
    EXPECT_FALSE(parse_uint("-1"));
}

TEST(Text, ParseSize) {
    EXPECT_EQ(parse_size("4096"), 4096u);
    EXPECT_EQ(parse_size("64K"), 65536u);
    EXPECT_EQ(parse_size("64k"), 65536u);
    EXPECT_EQ(parse_size("1M"), 1048576u);
    EXPECT_EQ(parse_size("2G"), 2147483648ull);
    EXPECT_EQ(parse_size("1MiB"), 1048576u);
    EXPECT_FALSE(parse_size("1X"));
    EXPECT_FALSE(parse_size("K"));
    EXPECT_FALSE(parse_size("99999999999999T"));
}

TEST(Text, Formatting) {
    EXPECT_EQ(format_address(0x7FF6'1234'0000ull), "0x00007FF612340000");
    EXPECT_EQ(format_size(512), "512 B");
    EXPECT_EQ(format_size(1536), "1.50 KiB");
    EXPECT_EQ(format_size(3ull << 30), "3.00 GiB");
}

TEST(Text, GlobMatch) {
    EXPECT_TRUE(glob_match_ci("*.dll", "KERNEL32.DLL"));
    EXPECT_TRUE(glob_match_ci("game?.exe", "Game1.exe"));
    EXPECT_TRUE(glob_match_ci("*", ""));
    EXPECT_FALSE(glob_match_ci("*.dll", "kernel32.exe"));
    EXPECT_FALSE(glob_match_ci("a?c", "ac"));
    EXPECT_TRUE(glob_match_ci("*a*b*c", "xxaxxbxxc"));
}

TEST(Text, Previews) {
    const std::byte bytes[] = {std::byte{'H'}, std::byte{'i'}, std::byte{0}, std::byte{0xFF}};
    EXPECT_EQ(hex_preview(bytes), "48 69 00 FF");
    EXPECT_EQ(ascii_preview(bytes), "Hi..");
    const std::byte utf16[] = {std::byte{0x1F}, std::byte{0x04}, std::byte{'A'}, std::byte{0}};
    EXPECT_EQ(utf16_preview(utf16), "\xD0\x9F" "A");
}

}  // namespace
}  // namespace mh
