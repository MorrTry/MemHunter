#include "common/text.hpp"

#include <windows.h>

#include <array>
#include <charconv>
#include <cstdio>
#include <limits>

#include "common/error.hpp"

namespace mh {

std::wstring utf8_to_wide(std::string_view utf8) {
    if (utf8.empty()) {
        return {};
    }
    const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), static_cast<int>(utf8.size()),
                                           nullptr, 0);
    if (length <= 0) {
        throw Error(ErrorCode::InvalidArgument, "text is not valid UTF-8");
    }
    std::wstring wide(static_cast<std::size_t>(length), L'\0');
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, utf8.data(), static_cast<int>(utf8.size()), wide.data(),
                        length);
    return wide;
}

std::string wide_to_utf8(std::wstring_view wide) {
    if (wide.empty()) {
        return {};
    }
    const int length =
        WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    if (length <= 0) {
        return {};
    }
    std::string utf8(static_cast<std::size_t>(length), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.data(), static_cast<int>(wide.size()), utf8.data(), length, nullptr,
                        nullptr);
    return utf8;
}

std::string format_address(std::uint64_t address) {
    std::array<char, 24> buffer{};
    std::snprintf(buffer.data(), buffer.size(), "0x%016llX", static_cast<unsigned long long>(address));
    return buffer.data();
}

std::string format_hex(std::uint64_t value) {
    std::array<char, 24> buffer{};
    std::snprintf(buffer.data(), buffer.size(), "0x%llX", static_cast<unsigned long long>(value));
    return buffer.data();
}

std::string format_size(std::uint64_t bytes) {
    static constexpr std::array<const char*, 5> units{"B", "KiB", "MiB", "GiB", "TiB"};
    if (bytes < 1024) {
        return std::to_string(bytes) + " B";
    }
    double value = static_cast<double>(bytes);
    std::size_t unit = 0;
    while (value >= 1024.0 && unit + 1 < units.size()) {
        value /= 1024.0;
        ++unit;
    }
    std::array<char, 32> buffer{};
    std::snprintf(buffer.data(), buffer.size(), "%.2f %s", value, units[unit]);
    return buffer.data();
}

std::string format_filetime(std::uint64_t filetime) {
    if (filetime == 0) {
        return "-";
    }
    FILETIME utc{static_cast<DWORD>(filetime & 0xFFFF'FFFFu), static_cast<DWORD>(filetime >> 32)};
    SYSTEMTIME universal{};
    SYSTEMTIME local{};
    if (FileTimeToSystemTime(&utc, &universal) == 0 || SystemTimeToTzSpecificLocalTime(nullptr, &universal, &local) == 0) {
        return format_hex(filetime);
    }
    std::array<char, 32> buffer{};
    std::snprintf(buffer.data(), buffer.size(), "%04u-%02u-%02u %02u:%02u:%02u", local.wYear, local.wMonth, local.wDay, local.wHour,
                  local.wMinute, local.wSecond);
    return buffer.data();
}

std::string format_rate(double bytes_per_second) {
    if (!(bytes_per_second > 0.0)) {
        return "0 B/s";
    }
    return format_size(static_cast<std::uint64_t>(bytes_per_second)) + "/s";
}

std::optional<std::uint64_t> parse_uint(std::string_view text) {
    int base = 10;
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        text.remove_prefix(2);
        base = 16;
    }
    if (text.empty()) {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    const auto [end, ec] = std::from_chars(text.data(), text.data() + text.size(), value, base);
    if (ec != std::errc{} || end != text.data() + text.size()) {
        return std::nullopt;
    }
    return value;
}

std::optional<std::uint64_t> parse_size(std::string_view text) {
    if (auto exact = parse_uint(text)) {
        return exact;
    }
    std::size_t digits = 0;
    while (digits < text.size() && text[digits] >= '0' && text[digits] <= '9') {
        ++digits;
    }
    if (digits == 0) {
        return std::nullopt;
    }
    const auto number = parse_uint(text.substr(0, digits));
    if (!number) {
        return std::nullopt;
    }
    const std::string suffix = to_lower_ascii(text.substr(digits));
    unsigned shift = 0;
    if (suffix == "k" || suffix == "kb" || suffix == "kib") {
        shift = 10;
    } else if (suffix == "m" || suffix == "mb" || suffix == "mib") {
        shift = 20;
    } else if (suffix == "g" || suffix == "gb" || suffix == "gib") {
        shift = 30;
    } else if (suffix == "t" || suffix == "tb" || suffix == "tib") {
        shift = 40;
    } else if (suffix != "b") {
        return std::nullopt;
    }
    if (*number > (std::numeric_limits<std::uint64_t>::max() >> shift)) {
        return std::nullopt;
    }
    return *number << shift;
}

std::string to_lower_ascii(std::string_view text) {
    std::string out(text);
    for (char& c : out) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return out;
}

bool iequals_ascii(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        char x = a[i];
        char y = b[i];
        if (x >= 'A' && x <= 'Z') x = static_cast<char>(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z') y = static_cast<char>(y - 'A' + 'a');
        if (x != y) {
            return false;
        }
    }
    return true;
}

bool glob_match_ci(std::string_view pattern, std::string_view text) {
    const auto lower = [](char c) { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c; };
    std::size_t p = 0;
    std::size_t t = 0;
    std::size_t star = std::string_view::npos;
    std::size_t resume = 0;
    while (t < text.size()) {
        if (p < pattern.size() && (pattern[p] == '?' || lower(pattern[p]) == lower(text[t]))) {
            ++p;
            ++t;
        } else if (p < pattern.size() && pattern[p] == '*') {
            star = p++;
            resume = t;
        } else if (star != std::string_view::npos) {
            p = star + 1;
            t = ++resume;
        } else {
            return false;
        }
    }
    while (p < pattern.size() && pattern[p] == '*') {
        ++p;
    }
    return p == pattern.size();
}

std::string hex_preview(std::span<const std::byte> bytes) {
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(bytes.size() * 3);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        const auto value = static_cast<unsigned>(bytes[i]);
        if (i != 0) {
            out.push_back(' ');
        }
        out.push_back(digits[value >> 4]);
        out.push_back(digits[value & 0xF]);
    }
    return out;
}

std::string ascii_preview(std::span<const std::byte> bytes) {
    std::string out;
    out.reserve(bytes.size());
    for (const std::byte b : bytes) {
        const auto c = static_cast<unsigned char>(b);
        out.push_back(c >= 0x20 && c < 0x7F ? static_cast<char>(c) : '.');
    }
    return out;
}

void append_utf8(std::string& out, char32_t cp) {
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

std::string utf16_preview(std::span<const std::byte> bytes) {
    std::string out;
    const std::size_t units = bytes.size() / 2;
    const auto unit_at = [&](std::size_t i) {
        return static_cast<char16_t>(static_cast<unsigned>(bytes[2 * i]) | (static_cast<unsigned>(bytes[2 * i + 1]) << 8));
    };
    for (std::size_t i = 0; i < units; ++i) {
        const char16_t u = unit_at(i);
        if (u >= 0xD800 && u <= 0xDBFF && i + 1 < units) {
            const char16_t low = unit_at(i + 1);
            if (low >= 0xDC00 && low <= 0xDFFF) {
                append_utf8(out, 0x10000 + ((static_cast<char32_t>(u) - 0xD800) << 10) + (low - 0xDC00));
                ++i;
                continue;
            }
        }
        const bool printable = u >= 0x20 && u != 0x7F && !(u >= 0x80 && u < 0xA0) && !(u >= 0xD800 && u <= 0xDFFF);
        if (printable) {
            append_utf8(out, u);
        } else {
            out.push_back('.');
        }
    }
    return out;
}

}  // namespace mh
