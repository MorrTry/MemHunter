#include <algorithm>
#include <array>

#include "scanner/matchers.hpp"

namespace mh {

namespace {

constexpr std::array<bool, 256> make_printable_ascii() {
    std::array<bool, 256> table{};
    for (std::size_t c = 0x20; c < 0x7F; ++c) {
        table[c] = true;
    }
    table['\t'] = true;
    return table;
}

constexpr auto kPrintableAscii = make_printable_ascii();

// Printable ASCII plus Latin-1, Latin Extended-A/B and Cyrillic. Wider ranges (CJK etc.) turn ordinary
// binary data such as small integer arrays into an avalanche of fake strings.
inline bool printable_utf16(std::uint32_t unit) noexcept {
    return (unit >= 0x20 && unit < 0x7F) || unit == '\t' || (unit >= 0xA0 && unit <= 0x24F) ||
           (unit >= 0x400 && unit <= 0x4FF);
}

inline std::uint32_t unit_at(const std::uint8_t* data, std::size_t offset) noexcept {
    return static_cast<std::uint32_t>(data[offset]) | (static_cast<std::uint32_t>(data[offset + 1]) << 8);
}

}  // namespace

StringExtractor::StringExtractor(StringOptions options, std::uint32_t ascii_id, std::uint32_t utf16_id)
    : options_(options), ascii_id_(ascii_id), utf16_id_(utf16_id) {
    options_.min_length = std::max<std::size_t>(options_.min_length, 1);
    options_.max_length = std::max(options_.max_length, options_.min_length);
}

void StringExtractor::scan(std::span<const std::byte> data, std::uint64_t base_address, std::size_t report_begin,
                           std::size_t report_end, std::vector<Hit>& hits) const {
    const auto* bytes = as_bytes(data.data());
    report_end = std::min(report_end, data.size());
    if (report_begin >= report_end) {
        return;
    }
    if ((options_.encodings & encoding::Ascii) != 0) {
        scan_ascii(bytes, data.size(), report_begin, report_end, hits);
    }
    if ((options_.encodings & encoding::Utf16) != 0) {
        scan_utf16(bytes, data.size(), base_address, report_begin, report_end, hits);
    }
}

void StringExtractor::scan_ascii(const std::uint8_t* data, std::size_t size, std::size_t begin, std::size_t end,
                                 std::vector<Hit>& hits) const {
    std::size_t i = begin;
    // A run that started before the window belongs to whoever owns its first byte.
    if (i > 0 && kPrintableAscii[data[i - 1]]) {
        while (i < size && kPrintableAscii[data[i]]) {
            ++i;
        }
    }
    while (i < end) {
        if (!kPrintableAscii[data[i]]) {
            ++i;
            continue;
        }
        const std::size_t start = i;
        const std::size_t limit = std::min(size, start + options_.max_length);
        std::size_t j = start + 1;
        while (j < limit && kPrintableAscii[data[j]]) {
            ++j;
        }
        if (j - start >= options_.min_length) {
            hits.push_back({start, ascii_id_, static_cast<std::uint32_t>(j - start)});
        }
        i = j;
        while (i < size && kPrintableAscii[data[i]]) {
            ++i;
        }
    }
}

void StringExtractor::scan_utf16(const std::uint8_t* data, std::size_t size, std::uint64_t base_address,
                                 std::size_t begin, std::size_t end, std::vector<Hit>& hits) const {
    std::size_t i = begin + ((base_address + begin) & 1);
    if (i >= 2 && printable_utf16(unit_at(data, i - 2))) {
        while (i + 1 < size && printable_utf16(unit_at(data, i))) {
            i += 2;
        }
    }
    const std::size_t max_bytes = options_.max_length * 2;
    while (i < end && i + 1 < size) {
        if (!printable_utf16(unit_at(data, i))) {
            i += 2;
            continue;
        }
        const std::size_t start = i;
        const std::size_t limit = std::min(size, start + max_bytes);
        std::size_t j = start + 2;
        while (j + 2 <= limit && printable_utf16(unit_at(data, j))) {
            j += 2;
        }
        if ((j - start) / 2 >= options_.min_length) {
            hits.push_back({start, utf16_id_, static_cast<std::uint32_t>(j - start)});
        }
        i = j;
        while (i + 1 < size && printable_utf16(unit_at(data, i))) {
            i += 2;
        }
    }
}

std::string StringExtractor::describe() const {
    std::string text = "strings(";
    if ((options_.encodings & encoding::Ascii) != 0) text += "ascii";
    if (options_.encodings == encoding::Both) text += "+";
    if ((options_.encodings & encoding::Utf16) != 0) text += "utf16";
    return text + ", min " + std::to_string(options_.min_length) + ")";
}

}  // namespace mh
