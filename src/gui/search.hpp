#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "pipeline/scan_session.hpp"
#include "value/value_scan.hpp"

namespace mh::gui {

enum class SearchMode : std::uint8_t { Text, Bytes, Number, Strings };
enum class TextEncoding : std::uint8_t { Both, Ascii, Utf16 };
using NumberType = ValueType;

inline constexpr std::size_t kPreviewBytes = 48;
inline constexpr std::uint64_t kDefaultMaxMatches = 1'000'000;
inline constexpr std::uint32_t kMaxThreads = 64;

// Everything the search panel edits. Only the fields of the selected mode take part in a scan.
struct SearchForm {
    SearchMode mode = SearchMode::Text;

    std::string text;
    TextEncoding text_encoding = TextEncoding::Both;
    bool ignore_case = false;

    // One signature per line; "name=SIG" gives it a label.
    std::string signatures;

    std::string number;
    // Upper bound for Compare::Between.
    std::string number_high;
    NumberType number_type = NumberType::Int32;
    Compare compare = Compare::Exact;
    bool aligned = true;

    std::uint32_t min_length = 6;
    TextEncoding strings_encoding = TextEncoding::Both;

    bool private_memory = true;
    bool image_memory = true;
    bool mapped_memory = true;
    bool writable_only = false;

    std::uint32_t threads = 0;
    std::uint64_t max_matches = kDefaultMaxMatches;
};

std::uint32_t encodings_of(TextEncoding encoding);

// Little-endian bytes of `text` as `type`. Integers accept both the signed and the unsigned range of their size,
// decimal or 0x-hex; floats accept a comma as the decimal separator. Throws Error with a message for the user.
std::vector<std::uint8_t> encode_number(std::string_view text, NumberType type);

// The pattern the number search looks for, as "98 3A 00 00".
std::string number_signature(std::string_view text, NumberType type);

// Whether the comparison takes the number typed in the form.
bool takes_number(Compare compare) noexcept;

// The comparison of the form for values of `type`. Ordered integer comparisons need the signed range; a float
// typed with n decimals matches within half of the last digit ("100" is 99.5 to 100.5), with an exponent only
// exactly. Swapped bounds of Between are put in order. Throws Error with a message for the user.
ValueCondition value_condition(const SearchForm& form, NumberType type);

RegionFilter region_filter(const SearchForm& form);

// The thread count of the form (0 lets the engine choose); throws Error above kMaxThreads.
unsigned thread_count(const SearchForm& form);

// Throws Error with a message for the user when the selected mode has nothing to search for or its input is invalid.
ScanRequest build_request(const SearchForm& form);

}  // namespace mh::gui
