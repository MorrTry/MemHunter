#include "gui/search.hpp"

#include <charconv>
#include <cmath>
#include <cstring>
#include <limits>
#include <span>
#include <system_error>
#include <utility>

#include "common/error.hpp"
#include "common/text.hpp"

namespace mh::gui {

namespace {

constexpr std::uint32_t kMinStringLength = 2;
constexpr std::uint32_t kMaxStringLength = 256;
constexpr std::size_t kMaxExtractedString = 4096;

std::string_view trim(std::string_view text) {
    const auto space = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
    while (!text.empty() && space(text.front())) {
        text.remove_prefix(1);
    }
    while (!text.empty() && space(text.back())) {
        text.remove_suffix(1);
    }
    return text;
}

template <typename T>
std::vector<std::uint8_t> bytes_of(T value) {
    std::vector<std::uint8_t> bytes(sizeof(T));
    std::memcpy(bytes.data(), &value, sizeof(T));
    return bytes;
}

struct IntegerText {
    bool negative = false;
    std::uint64_t magnitude = 0;
    bool overflow = false;
};

IntegerText read_integer(std::string_view text) {
    const std::string original(text);
    IntegerText parsed;
    parsed.negative = text.starts_with('-');
    if (parsed.negative || text.starts_with('+')) {
        text.remove_prefix(1);
    }
    int base = 10;
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        text.remove_prefix(2);
        base = 16;
    }
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), parsed.magnitude, base);
    if (text.empty() || error == std::errc::invalid_argument || end != text.data() + text.size()) {
        throw Error(ErrorCode::InvalidArgument, "«" + original + "» — не целое число. Пример: 15000, -5 или 0x3A98");
    }
    parsed.overflow = error == std::errc::result_out_of_range;
    return parsed;
}

std::uint64_t signed_limit(std::size_t size) {
    return std::uint64_t{1} << (size * 8 - 1);
}

std::uint64_t integer_bits(std::string_view text, std::size_t size) {
    const IntegerText parsed = read_integer(text);
    const unsigned bits = static_cast<unsigned>(size * 8);
    const std::uint64_t unsigned_max = bits == 64 ? std::numeric_limits<std::uint64_t>::max() : (std::uint64_t{1} << bits) - 1;
    const std::uint64_t negative_max = signed_limit(size);
    if (parsed.overflow || (parsed.negative ? parsed.magnitude > negative_max : parsed.magnitude > unsigned_max)) {
        const std::string low = "-" + std::to_string(negative_max);
        throw Error(ErrorCode::InvalidArgument, "Число не помещается в " + std::to_string(size) + " байт: допустимо от " + low +
                                                    " до " + std::to_string(unsigned_max));
    }
    return parsed.negative ? ~parsed.magnitude + 1 : parsed.magnitude;
}

std::int64_t signed_integer(std::string_view text, std::size_t size) {
    const IntegerText parsed = read_integer(text);
    const std::uint64_t limit = signed_limit(size);
    if (parsed.overflow || parsed.magnitude > (parsed.negative ? limit : limit - 1)) {
        throw Error(ErrorCode::InvalidArgument, "Для сравнения число должно быть от -" + std::to_string(limit) + " до " +
                                                    std::to_string(limit - 1));
    }
    return parsed.negative ? static_cast<std::int64_t>(~parsed.magnitude + 1) : static_cast<std::int64_t>(parsed.magnitude);
}

std::vector<std::uint8_t> encode_integer(std::string_view text, std::size_t size) {
    const std::uint64_t value = integer_bits(text, size);
    std::vector<std::uint8_t> bytes(size);
    for (std::size_t i = 0; i < size; ++i) {
        bytes[i] = static_cast<std::uint8_t>(value >> (8 * i));
    }
    return bytes;
}

template <typename T>
T parse_float(std::string_view text) {
    std::string normalized(text);
    for (char& c : normalized) {
        if (c == ',') {
            c = '.';
        }
    }
    T value{};
    const auto [end, error] = std::from_chars(normalized.data(), normalized.data() + normalized.size(), value);
    if (error == std::errc::invalid_argument || end != normalized.data() + normalized.size()) {
        throw Error(ErrorCode::InvalidArgument, "«" + std::string(text) + "» — не дробное число. Пример: 102.5 или -37,25");
    }
    if (error == std::errc::result_out_of_range || !std::isfinite(value)) {
        throw Error(ErrorCode::InvalidArgument, "Число «" + std::string(text) + "» вне диапазона типа");
    }
    return value;
}

template <typename T>
std::vector<std::uint8_t> encode_float(std::string_view text) {
    return bytes_of(parse_float<T>(text));
}

double float_operand(std::string_view text, NumberType type) {
    return type == NumberType::Float ? static_cast<double>(parse_float<float>(text)) : parse_float<double>(text);
}

// Half of the last digit typed: "100" -> 0.5, "99.5" -> 0.05; an exponent asks for the exact value.
double typed_tolerance(std::string_view text) {
    if (text.find_first_of("eE") != std::string_view::npos) {
        return 0;
    }
    const std::size_t point = text.find_first_of(".,");
    const std::size_t decimals = point == std::string_view::npos ? 0 : text.size() - point - 1;
    return 0.5 * std::pow(10.0, -static_cast<double>(decimals));
}

std::string_view operand(std::string_view text, std::string_view missing) {
    text = trim(text);
    if (text.empty()) {
        throw Error(ErrorCode::InvalidArgument, std::string(missing));
    }
    return text;
}

Pattern exact_pattern(std::span<const std::uint8_t> bytes, std::string label) {
    Pattern pattern = parse_signature(hex_preview(std::as_bytes(bytes)));
    pattern.label = std::move(label);
    return pattern;
}

std::vector<Pattern> parse_signature_lines(std::string_view text) {
    std::vector<Pattern> patterns;
    std::size_t line_number = 0;
    while (!text.empty()) {
        const std::size_t end = text.find('\n');
        const std::string_view line = trim(text.substr(0, end));
        text = end == std::string_view::npos ? std::string_view{} : text.substr(end + 1);
        ++line_number;
        if (line.empty()) {
            continue;
        }
        const std::size_t equals = line.find('=');
        const std::string_view label = equals == std::string_view::npos ? std::string_view{} : trim(line.substr(0, equals));
        const std::string_view body = equals == std::string_view::npos ? line : trim(line.substr(equals + 1));
        try {
            Pattern pattern = parse_signature(body);
            if (!label.empty()) {
                pattern.label = std::string(label);
            }
            patterns.push_back(std::move(pattern));
        } catch (const Error& error) {
            throw Error(ErrorCode::InvalidPattern, "Сигнатура в строке " + std::to_string(line_number) + ": " + error.what());
        }
    }
    if (patterns.empty()) {
        throw Error(ErrorCode::InvalidArgument, "Введите хотя бы одну сигнатуру, например 48 8B ?? 89");
    }
    return patterns;
}

}  // namespace

std::uint32_t encodings_of(TextEncoding encoding) {
    switch (encoding) {
        case TextEncoding::Ascii: return encoding::Ascii;
        case TextEncoding::Utf16: return encoding::Utf16;
        case TextEncoding::Both: return encoding::Both;
    }
    return encoding::Both;
}

std::vector<std::uint8_t> encode_number(std::string_view text, NumberType type) {
    text = trim(text);
    if (text.empty()) {
        throw Error(ErrorCode::InvalidArgument, "Введите число");
    }
    switch (type) {
        case NumberType::Float: return encode_float<float>(text);
        case NumberType::Double: return encode_float<double>(text);
        default: return encode_integer(text, size_of(type));
    }
}

std::string number_signature(std::string_view text, NumberType type) {
    const auto bytes = encode_number(text, type);
    return hex_preview(std::as_bytes(std::span(bytes)));
}

bool takes_number(Compare compare) noexcept {
    return compare == Compare::Exact || compare == Compare::Greater || compare == Compare::Less || compare == Compare::Between;
}

ValueCondition value_condition(const SearchForm& form, NumberType type) {
    ValueCondition condition;
    condition.compare = form.compare;
    if (!takes_number(form.compare)) {
        return condition;
    }
    const bool between = form.compare == Compare::Between;
    const std::string_view low = operand(form.number, between ? "Введите оба числа: от и до" : "Введите число");
    const std::string_view high = between ? operand(form.number_high, "Введите оба числа: от и до") : low;
    const std::size_t size = size_of(type);
    if (is_float(type)) {
        condition.number = float_operand(low, type);
        condition.number_high = float_operand(high, type);
        if (form.compare == Compare::Exact) {
            condition.tolerance = typed_tolerance(low);
        }
        if (condition.number > condition.number_high) {
            std::swap(condition.number, condition.number_high);
        }
    } else if (form.compare == Compare::Exact) {
        condition.bits = integer_bits(low, size);
    } else {
        condition.integer = signed_integer(low, size);
        condition.integer_high = signed_integer(high, size);
        if (condition.integer > condition.integer_high) {
            std::swap(condition.integer, condition.integer_high);
        }
    }
    return condition;
}

RegionFilter region_filter(const SearchForm& form) {
    RegionFilter filter;
    filter.types = (form.private_memory ? type_class::Private : 0) | (form.image_memory ? type_class::Image : 0) |
                   (form.mapped_memory ? type_class::Mapped : 0);
    if (filter.types == 0) {
        throw Error(ErrorCode::InvalidArgument, "Отметьте хотя бы один тип памяти");
    }
    if (form.writable_only) {
        filter.protections = protection_class::ReadWrite | protection_class::WriteCopy | protection_class::ExecuteReadWrite |
                             protection_class::ExecuteWriteCopy;
    }
    return filter;
}

unsigned thread_count(const SearchForm& form) {
    if (form.threads > kMaxThreads) {
        throw Error(ErrorCode::InvalidArgument, "Потоков — не больше " + std::to_string(kMaxThreads));
    }
    return form.threads;
}

ScanRequest build_request(const SearchForm& form) {
    ScanRequest request;
    switch (form.mode) {
        case SearchMode::Text:
            if (form.text.empty()) {
                throw Error(ErrorCode::InvalidArgument, "Введите текст для поиска");
            }
            request.patterns = make_text_patterns(form.text, encodings_of(form.text_encoding), form.ignore_case);
            break;
        case SearchMode::Bytes: request.patterns = parse_signature_lines(form.signatures); break;
        case SearchMode::Number: {
            const auto bytes = encode_number(form.number, form.number_type);
            request.patterns.push_back(exact_pattern(bytes, std::string(to_string(form.number_type)) + " " + std::string(trim(form.number))));
            break;
        }
        case SearchMode::Strings:
            if (form.min_length < kMinStringLength || form.min_length > kMaxStringLength) {
                throw Error(ErrorCode::InvalidArgument, "Минимальная длина строки — от " + std::to_string(kMinStringLength) + " до " +
                                                            std::to_string(kMaxStringLength));
            }
            request.strings = StringOptions{encodings_of(form.strings_encoding), form.min_length, kMaxExtractedString};
            break;
    }
    request.patterns = deduplicate(std::move(request.patterns));
    request.filter = region_filter(form);
    if (form.max_matches == 0) {
        throw Error(ErrorCode::InvalidArgument, "Лимит совпадений должен быть больше нуля");
    }
    request.engine.max_matches = form.max_matches;
    request.engine.preview_bytes = kPreviewBytes;
    request.engine.scan_threads = thread_count(form);
    return request;
}

}  // namespace mh::gui
