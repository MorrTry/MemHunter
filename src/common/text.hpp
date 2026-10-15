#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace mh {

std::wstring utf8_to_wide(std::string_view utf8);
std::string wide_to_utf8(std::wstring_view wide);

std::string format_address(std::uint64_t address);
std::string format_hex(std::uint64_t value);
std::string format_size(std::uint64_t bytes);
std::string format_rate(double bytes_per_second);
// Local time "YYYY-MM-DD HH:MM:SS" for a FILETIME value; "-" for 0.
std::string format_filetime(std::uint64_t filetime);

std::optional<std::uint64_t> parse_uint(std::string_view text);
std::optional<std::uint64_t> parse_size(std::string_view text);

std::string to_lower_ascii(std::string_view text);
bool iequals_ascii(std::string_view a, std::string_view b);
bool glob_match_ci(std::string_view pattern, std::string_view text);

std::string hex_preview(std::span<const std::byte> bytes);
std::string ascii_preview(std::span<const std::byte> bytes);
std::string utf16_preview(std::span<const std::byte> bytes);

void append_utf8(std::string& out, char32_t code_point);

}  // namespace mh
