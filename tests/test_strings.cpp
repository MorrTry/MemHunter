#include <gtest/gtest.h>

#include <algorithm>
#include <initializer_list>

#include "scanner/matchers.hpp"

namespace mh {
namespace {

constexpr std::uint32_t kAscii = 7;
constexpr std::uint32_t kUtf16 = 8;

using Bytes = std::vector<std::uint8_t>;

std::vector<Hit> extract(const Bytes& data, StringOptions options, std::uint64_t base = 0x1000, std::size_t begin = 0,
                         std::size_t end = SIZE_MAX) {
    const StringExtractor extractor(options, kAscii, kUtf16);
    std::vector<Hit> hits;
    extractor.scan(std::as_bytes(std::span(data)), base, begin, std::min(end, data.size()), hits);
    std::sort(hits.begin(), hits.end(), [](const Hit& a, const Hit& b) { return a.offset < b.offset; });
    return hits;
}

Bytes ascii(std::string_view text) {
    return {text.begin(), text.end()};
}

Bytes utf16(std::u16string_view text) {
    Bytes out;
    for (const char16_t c : text) {
        out.push_back(static_cast<std::uint8_t>(c & 0xFF));
        out.push_back(static_cast<std::uint8_t>(c >> 8));
    }
    return out;
}

Bytes raw(std::initializer_list<int> values) {
    Bytes out;
    for (const int v : values) {
        out.push_back(static_cast<std::uint8_t>(v));
    }
    return out;
}

Bytes join(std::initializer_list<Bytes> parts) {
    Bytes out;
    for (const auto& part : parts) {
        out.insert(out.end(), part.begin(), part.end());
    }
    return out;
}

TEST(Strings, AsciiRunsRespectMinimumLength) {
    const StringOptions options{encoding::Ascii, 4, 100};
    const Bytes data = join({ascii("ab"), raw({0}), ascii("abcd"), raw({1}), ascii("abc"), raw({'\t'}), ascii("efgh"), raw({0xFF})});
    const auto hits = extract(data, options);
    ASSERT_EQ(hits.size(), 2u);
    EXPECT_EQ(hits[0], (Hit{3, kAscii, 4}));
    EXPECT_EQ(hits[1], (Hit{8, kAscii, 8}));
}

TEST(Strings, LongRunsAreTruncatedOnce) {
    const StringOptions options{encoding::Ascii, 2, 4};
    const Bytes data = join({raw({0}), ascii("abcdefghij"), raw({0}), ascii("xy")});
    const auto hits = extract(data, options);
    ASSERT_EQ(hits.size(), 2u);
    EXPECT_EQ(hits[0], (Hit{1, kAscii, 4}));
    EXPECT_EQ(hits[1], (Hit{12, kAscii, 2}));
}

TEST(Strings, RunStartedBeforeWindowBelongsToEarlierOwner) {
    const StringOptions options{encoding::Ascii, 3, 100};
    const Bytes data = join({raw({0}), ascii("hello"), raw({0}), ascii("world")});
    EXPECT_TRUE(extract(data, options, 0x1000, 3, 6).empty());
    const auto hits = extract(data, options, 0x1000, 1, 2);
    ASSERT_EQ(hits.size(), 1u);
    EXPECT_EQ(hits[0], (Hit{1, kAscii, 5}));
    const auto at_window_start = extract(data, options, 0x1000, 7, 12);
    ASSERT_EQ(at_window_start.size(), 1u);
    EXPECT_EQ(at_window_start[0], (Hit{7, kAscii, 5}));
}

TEST(Strings, Utf16IncludesCyrillicAndRequiresEvenAddresses) {
    const StringOptions options{encoding::Utf16, 4, 100};
    const std::u16string privet{0x041F, 0x0440, 0x0438, 0x0432, 0x0435, 0x0442};
    Bytes data = join({raw({0, 0}), utf16(privet), raw({0, 0})});
    auto hits = extract(data, options, 0x1000);
    ASSERT_EQ(hits.size(), 1u);
    EXPECT_EQ(hits[0], (Hit{2, kUtf16, 12}));

    // Shifted by one byte, the text is only aligned when the buffer itself starts at an odd address.
    data.insert(data.begin(), 0);
    EXPECT_TRUE(extract(data, options, 0x1000).empty());
    hits = extract(data, options, 0x1001);
    ASSERT_EQ(hits.size(), 1u);
    EXPECT_EQ(hits[0], (Hit{3, kUtf16, 12}));
}

TEST(Strings, BothEncodings) {
    const StringOptions options{encoding::Both, 5, 100};
    // Three zero bytes: "i" followed by a single zero byte would already be a one-character UTF-16 string.
    const Bytes data = join({ascii("plain-ascii"), raw({0, 0, 0}), utf16(u"wide-text")});
    const auto hits = extract(data, options);
    ASSERT_EQ(hits.size(), 2u);
    EXPECT_EQ(hits[0], (Hit{0, kAscii, 11}));
    EXPECT_EQ(hits[1], (Hit{14, kUtf16, 18}));
}

TEST(Strings, Describe) {
    const StringExtractor extractor({encoding::Both, 6, 10}, 0, 1);
    EXPECT_EQ(extractor.describe(), "strings(ascii+utf16, min 6)");
}

}  // namespace
}  // namespace mh
