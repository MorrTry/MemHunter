#include "cli/args.hpp"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <system_error>
#include <utility>

#include "common/error.hpp"
#include "common/text.hpp"

namespace mh::cli {

namespace {

constexpr std::uint64_t kMaxStringLength = std::uint64_t{1} << 20;

[[noreturn]] void invalid(const std::string& message) {
    throw Error(ErrorCode::InvalidArgument, message);
}

std::vector<PatternKind> parse_kind_list(std::string_view list) {
    std::vector<PatternKind> kinds;
    while (!list.empty()) {
        const auto comma = list.find(',');
        const std::string_view item = list.substr(0, comma);
        list = comma == std::string_view::npos ? std::string_view{} : list.substr(comma + 1);
        if (item.empty()) {
            continue;
        }
        if (iequals_ascii(item, "strings")) {
            kinds.push_back(PatternKind::StringsAscii);
            kinds.push_back(PatternKind::StringsUtf16);
        } else if (const auto kind = parse_pattern_kind(item)) {
            kinds.push_back(*kind);
        } else {
            invalid("unknown match kind '" + std::string(item) +
                    "'; expected ascii, utf16, bytes, signature, strings-ascii, strings-utf16 or strings");
        }
    }
    return kinds;
}

OutputFormat parse_format(std::string_view text) {
    const auto format = parse_output_format(text);
    if (!format) {
        invalid("unknown output format '" + std::string(text) + "'; expected text, json or csv");
    }
    return *format;
}

AddressRange parse_range_value(std::string_view text) {
    const auto range = parse_address_range(text);
    if (!range) {
        invalid("invalid address range '" + std::string(text) + "'; expected START-END, e.g. 0x10000-0x20000");
    }
    return *range;
}

bool parse_region_option(ArgReader& reader, const std::string& option, RegionFilter& filter) {
    if (option == "--protection") {
        filter.protections = parse_protection_list(reader.value());
    } else if (option == "--type") {
        filter.types = parse_type_list(reader.value());
    } else if (option == "--min-region-size") {
        filter.min_size = reader.size_value(0, std::numeric_limits<std::uint64_t>::max());
    } else if (option == "--max-region-size") {
        filter.max_size = reader.size_value(1, std::numeric_limits<std::uint64_t>::max());
    } else if (option == "--include") {
        filter.add_include(reader.value());
    } else if (option == "--exclude") {
        filter.add_exclude(reader.value());
    } else {
        return false;
    }
    if (filter.min_size > filter.max_size) {
        invalid("--min-region-size is larger than --max-region-size");
    }
    return true;
}

bool parse_output_option(ArgReader& reader, const std::string& option, OutputOptions& out) {
    if (option == "-f" || option == "--format") {
        out.format = parse_format(reader.value());
    } else if (option == "-o" || option == "--output") {
        out.path = reader.value();
        if (out.path.empty()) {
            invalid("--output needs a file name");
        }
    } else if (option == "--sort") {
        const std::string key = reader.value();
        const auto sort = parse_sort_key(key);
        if (!sort) {
            invalid("unknown sort key '" + key + "'; expected address, pattern, kind, length or region");
        }
        out.query.sort = *sort;
    } else if (option == "--desc") {
        reader.flag();
        out.query.descending = true;
    } else if (option == "--limit") {
        out.query.limit = reader.uint_value(0, std::numeric_limits<std::uint32_t>::max());
        out.limit_given = true;
    } else if (option == "--no-preview") {
        reader.flag();
        out.export_options.include_preview = false;
    } else if (option == "--filter-kind") {
        const auto kinds = parse_kind_list(reader.value());
        out.query.kinds.insert(out.query.kinds.end(), kinds.begin(), kinds.end());
    } else if (option == "--filter-pattern") {
        out.pattern_filters.push_back(reader.value());
    } else if (option == "--filter-range") {
        out.query.address_ranges.push_back(parse_range_value(reader.value()));
    } else if (option == "--grep") {
        out.query.text = reader.value();
    } else if (option == "--no-progress") {
        reader.flag();
        out.progress = false;
    } else if (option == "-q" || option == "--quiet") {
        reader.flag();
        out.quiet = true;
    } else {
        return false;
    }
    return true;
}

std::string_view trim(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t' || text.front() == '\r')) text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t' || text.back() == '\r')) text.remove_suffix(1);
    return text;
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
        invalid("'" + original + "' is not an integer; expected e.g. 100, -5 or 0x64");
    }
    parsed.overflow = error == std::errc::result_out_of_range;
    return parsed;
}

std::uint64_t integer_bits(std::string_view text, ValueType type) {
    const IntegerText parsed = read_integer(text);
    const std::size_t bits = size_of(type) * 8;
    const std::uint64_t unsigned_max = bits == 64 ? std::numeric_limits<std::uint64_t>::max() : (std::uint64_t{1} << bits) - 1;
    const std::uint64_t negative_max = std::uint64_t{1} << (bits - 1);
    if (parsed.overflow || parsed.magnitude > (parsed.negative ? negative_max : unsigned_max)) {
        invalid("'" + std::string(text) + "' does not fit in " + std::string(to_string(type)) + ": expected -" +
                std::to_string(negative_max) + " to " + std::to_string(unsigned_max));
    }
    return (parsed.negative ? ~parsed.magnitude + 1 : parsed.magnitude) & unsigned_max;
}

std::int64_t signed_integer(std::string_view text, ValueType type) {
    const IntegerText parsed = read_integer(text);
    const std::uint64_t limit = std::uint64_t{1} << (size_of(type) * 8 - 1);
    if (parsed.overflow || parsed.magnitude > (parsed.negative ? limit : limit - 1)) {
        invalid("'" + std::string(text) + "' is out of range: comparisons of " + std::string(to_string(type)) + " take -" +
                std::to_string(limit) + " to " + std::to_string(limit - 1));
    }
    return parsed.negative ? static_cast<std::int64_t>(~parsed.magnitude + 1) : static_cast<std::int64_t>(parsed.magnitude);
}

template <typename T>
double parse_float(std::string_view text) {
    std::string normalized(text);
    std::replace(normalized.begin(), normalized.end(), ',', '.');
    T value{};
    const auto [end, error] = std::from_chars(normalized.data(), normalized.data() + normalized.size(), value);
    if (error == std::errc::invalid_argument || end != normalized.data() + normalized.size()) {
        invalid("'" + std::string(text) + "' is not a number; expected e.g. 100, -37.25 or 1e-3");
    }
    if (error == std::errc::result_out_of_range || !std::isfinite(value)) {
        invalid("'" + std::string(text) + "' is out of range for " + (sizeof(T) == 4 ? "float" : "double"));
    }
    return static_cast<double>(value);
}

double float_operand(std::string_view text, ValueType type) {
    return type == ValueType::Float ? parse_float<float>(text) : parse_float<double>(text);
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

ValueType parse_value_type(std::string_view name) {
    for (const ValueType type : {ValueType::Int8, ValueType::Int16, ValueType::Int32, ValueType::Int64, ValueType::Float, ValueType::Double}) {
        if (iequals_ascii(name, to_string(type))) {
            return type;
        }
    }
    invalid("unknown value type '" + std::string(name) + "'; expected int8, int16, int32, int64, float or double");
}

}  // namespace

std::optional<std::string> ArgReader::next_option() {
    inline_value_.reset();
    option_.clear();
    while (!options_ended_ && !done() && args_[index_] == "--") {
        options_ended_ = true;
        ++index_;
    }
    if (done() || options_ended_) {
        return std::nullopt;
    }
    const std::string& token = args_[index_];
    if (token.size() < 2 || token[0] != '-') {
        return std::nullopt;
    }
    ++index_;
    const auto equals = token.find('=');
    if (token.starts_with("--") && equals != std::string::npos) {
        option_ = token.substr(0, equals);
        inline_value_ = token.substr(equals + 1);
    } else {
        option_ = token;
    }
    return option_;
}

std::string ArgReader::positional() {
    if (done()) {
        invalid("missing argument");
    }
    return args_[index_++];
}

std::string ArgReader::value() {
    if (inline_value_) {
        return *std::exchange(inline_value_, std::nullopt);
    }
    if (done()) {
        invalid("option " + option_ + " requires a value");
    }
    return args_[index_++];
}

std::uint64_t ArgReader::uint_value(std::uint64_t min, std::uint64_t max) {
    const std::string text = value();
    const auto number = parse_uint(text);
    if (!number || *number < min || *number > max) {
        invalid("option " + option_ + " expects an integer from " + std::to_string(min) + " to " + std::to_string(max) + ", got '" +
                text + "'");
    }
    return *number;
}

std::uint64_t ArgReader::size_value(std::uint64_t min, std::uint64_t max) {
    const std::string text = value();
    const auto size = parse_size(text);
    if (!size || *size < min || *size > max) {
        invalid("option " + option_ + " expects a size from " + format_size(min) + " to " + format_size(max) +
                " (suffixes K, M, G), got '" + text + "'");
    }
    return *size;
}

void ArgReader::flag() {
    if (inline_value_) {
        invalid("option " + option_ + " does not take a value");
    }
}

void ArgReader::unknown() const {
    invalid("unknown option '" + option_ + "'");
}

Pattern parse_named_signature(std::string_view text) {
    const auto equals = text.find('=');
    if (equals == std::string_view::npos) {
        return parse_signature(text);
    }
    const std::string_view name = trim(text.substr(0, equals));
    if (name.empty()) {
        throw Error(ErrorCode::InvalidPattern, "empty pattern name before '=' in '" + std::string(text) + "'");
    }
    Pattern pattern = parse_signature(text.substr(equals + 1));
    pattern.label = std::string(name);
    return pattern;
}

std::vector<Pattern> read_pattern_file(const std::string& path) {
    std::ifstream in(std::filesystem::path(utf8_to_wide(path)));
    if (!in) {
        throw Error(ErrorCode::Io, "cannot open pattern file '" + path + "'");
    }
    std::vector<Pattern> patterns;
    std::string line;
    std::size_t number = 0;
    while (std::getline(in, line)) {
        ++number;
        const std::string_view text = trim(line);
        if (text.empty() || text.front() == '#') {
            continue;
        }
        try {
            patterns.push_back(parse_named_signature(text));
        } catch (const Error& error) {
            throw Error(error.code(), path + ":" + std::to_string(number) + ": " + error.what());
        }
    }
    if (in.bad()) {
        throw Error(ErrorCode::Io, "cannot read pattern file '" + path + "'");
    }
    return patterns;
}

ScanOptions parse_scan_options(std::vector<std::string> args) {
    ScanOptions options;
    ScanRequest& request = options.request;
    ArgReader reader(std::move(args));
    std::vector<std::string> positionals;
    std::vector<std::string> texts;
    std::vector<Pattern> signatures;
    std::uint32_t encodings = 0;
    bool ignore_case = false;
    bool extract = false;
    bool length_given = false;
    StringOptions strings;

    while (!reader.done()) {
        const auto option = reader.next_option();
        if (!option) {
            if (!reader.done()) {
                positionals.push_back(reader.positional());
            }
            continue;
        }
        const std::string& o = *option;
        if (o == "-s" || o == "--string") {
            texts.push_back(reader.value());
        } else if (o == "-p" || o == "--pattern") {
            signatures.push_back(parse_named_signature(reader.value()));
        } else if (o == "--pattern-file") {
            auto loaded = read_pattern_file(reader.value());
            signatures.insert(signatures.end(), std::make_move_iterator(loaded.begin()), std::make_move_iterator(loaded.end()));
        } else if (o == "--strings") {
            reader.flag();
            extract = true;
        } else if (o == "--encoding") {
            encodings |= parse_encoding_list(reader.value());
        } else if (o == "--ascii") {
            reader.flag();
            encodings |= encoding::Ascii;
        } else if (o == "--unicode" || o == "--utf16") {
            reader.flag();
            encodings |= encoding::Utf16;
        } else if (o == "-i" || o == "--ignore-case") {
            reader.flag();
            ignore_case = true;
        } else if (o == "--min-length") {
            strings.min_length = reader.uint_value(1, kMaxStringLength);
            length_given = true;
        } else if (o == "--max-length") {
            strings.max_length = reader.uint_value(1, kMaxStringLength);
            length_given = true;
        } else if (o == "-j" || o == "--threads") {
            request.engine.scan_threads = static_cast<unsigned>(reader.uint_value(1, 1024));
        } else if (o == "--readers") {
            request.engine.read_threads = static_cast<unsigned>(reader.uint_value(1, 64));
        } else if (o == "--chunk-size") {
            request.chunk_size = reader.size_value(std::uint64_t{64} << 10, std::uint64_t{256} << 20);
        } else if (o == "--algorithm") {
            const std::string name = reader.value();
            const auto algorithm = parse_algorithm(name);
            if (!algorithm) {
                invalid("unknown algorithm '" + name + "'; expected auto, naive, horspool, simd or aho-corasick");
            }
            request.algorithm = *algorithm;
        } else if (o == "--max-matches") {
            request.engine.max_matches = reader.uint_value(0, std::numeric_limits<std::uint64_t>::max());
        } else if (o == "--preview") {
            request.engine.preview_bytes = reader.uint_value(0, 4096);
        } else if (o == "--changed-since") {
            options.changed_since = reader.value();
        } else if (!parse_region_option(reader, o, request.filter) && !parse_output_option(reader, o, options.output)) {
            reader.unknown();
        }
    }

    if (positionals.empty()) {
        invalid("missing target process: give a PID or an executable name");
    }
    if (positionals.size() > 1) {
        invalid("unexpected argument '" + positionals[1] + "'");
    }
    options.target = positionals.front();

    const std::uint32_t chosen = encodings != 0 ? encodings : encoding::Both;
    for (const auto& text : texts) {
        if (text.empty()) {
            throw Error(ErrorCode::InvalidPattern, "--string needs a non-empty value");
        }
        auto made = make_text_patterns(text, chosen, ignore_case);
        request.patterns.insert(request.patterns.end(), std::make_move_iterator(made.begin()), std::make_move_iterator(made.end()));
    }
    request.patterns.insert(request.patterns.end(), std::make_move_iterator(signatures.begin()),
                            std::make_move_iterator(signatures.end()));
    request.patterns = deduplicate(std::move(request.patterns));

    if (extract) {
        if (strings.min_length > strings.max_length) {
            invalid("--min-length (" + std::to_string(strings.min_length) + ") is larger than --max-length (" +
                    std::to_string(strings.max_length) + ")");
        }
        strings.encodings = chosen;
        request.strings = strings;
    } else if (length_given) {
        invalid("--min-length and --max-length apply to --strings");
    }
    if (request.patterns.empty() && !request.strings) {
        invalid("nothing to search for: give --string, --pattern, --pattern-file or --strings");
    }
    return options;
}

RegionsOptions parse_regions_options(std::vector<std::string> args) {
    RegionsOptions options;
    ArgReader reader(std::move(args));
    std::vector<std::string> positionals;
    bool protection_given = false;
    while (!reader.done()) {
        const auto option = reader.next_option();
        if (!option) {
            if (!reader.done()) {
                positionals.push_back(reader.positional());
            }
            continue;
        }
        const std::string& o = *option;
        if (o == "--all") {
            reader.flag();
            options.all = true;
        } else if (o == "-f" || o == "--format") {
            options.format = parse_format(reader.value());
        } else if (o == "-o" || o == "--output") {
            options.path = reader.value();
        } else if (!parse_region_option(reader, o, options.filter)) {
            reader.unknown();
        } else if (o == "--protection") {
            protection_given = true;
        }
    }
    if (positionals.size() != 1) {
        invalid(positionals.empty() ? "missing target process: give a PID or an executable name"
                                    : "unexpected argument '" + positionals[1] + "'");
    }
    if (options.all && protection_given) {
        invalid("--protection cannot be combined with --all, which lists regions of every protection");
    }
    options.target = positionals.front();
    return options;
}

PsOptions parse_ps_options(std::vector<std::string> args) {
    PsOptions options;
    ArgReader reader(std::move(args));
    std::vector<std::string> positionals;
    while (!reader.done()) {
        const auto option = reader.next_option();
        if (!option) {
            if (!reader.done()) {
                positionals.push_back(reader.positional());
            }
            continue;
        }
        if (*option == "-f" || *option == "--format") {
            options.format = parse_format(reader.value());
        } else {
            reader.unknown();
        }
    }
    if (positionals.size() > 1) {
        invalid("unexpected argument '" + positionals[1] + "'");
    }
    if (!positionals.empty()) {
        options.filter = positionals.front();
    }
    return options;
}

SnapshotOptions parse_snapshot_options(std::vector<std::string> args) {
    SnapshotOptions options;
    ArgReader reader(std::move(args));
    std::vector<std::string> positionals;
    bool max_data_given = false;
    while (!reader.done()) {
        const auto option = reader.next_option();
        if (!option) {
            if (!reader.done()) {
                positionals.push_back(reader.positional());
            }
            continue;
        }
        const std::string& o = *option;
        if (o == "-o" || o == "--output") {
            options.path = reader.value();
        } else if (o == "--with-data") {
            reader.flag();
            options.with_data = true;
        } else if (o == "--max-data") {
            options.max_data = reader.size_value(1, std::numeric_limits<std::uint64_t>::max());
            max_data_given = true;
        } else if (o == "--block-size") {
            options.capture.block_size = static_cast<std::uint32_t>(reader.size_value(1, kMaxBlockSize));
        } else if (o == "-j" || o == "--threads") {
            options.capture.threads = static_cast<unsigned>(reader.uint_value(1, 1024));
        } else if (o == "--no-progress") {
            reader.flag();
            options.progress = false;
        } else if (o == "-q" || o == "--quiet") {
            reader.flag();
            options.quiet = true;
        } else if (!parse_region_option(reader, o, options.filter)) {
            reader.unknown();
        }
    }
    if (positionals.size() != 1) {
        invalid(positionals.empty() ? "missing target process: give a PID or an executable name"
                                    : "unexpected argument '" + positionals[1] + "'");
    }
    options.target = positionals.front();
    if (options.path.empty()) {
        invalid("snapshot needs an output file: -o FILE");
    }
    if (max_data_given && !options.with_data) {
        invalid("--max-data applies to --with-data");
    }
    return options;
}

DiffOptions parse_diff_options(std::vector<std::string> args) {
    DiffOptions options;
    ArgReader reader(std::move(args));
    bool show_given = false;
    while (!reader.done()) {
        const auto option = reader.next_option();
        if (!option) {
            if (!reader.done()) {
                options.operands.push_back(reader.positional());
            }
            continue;
        }
        const std::string& o = *option;
        if (o == "-f" || o == "--format") {
            options.format = parse_format(reader.value());
        } else if (o == "-o" || o == "--output") {
            options.path = reader.value();
            if (options.path.empty()) {
                invalid("--output needs a file name");
            }
        } else if (o == "--show") {
            const std::string value = reader.value();
            std::string_view list = value;
            if (!show_given) {
                options.show = 0;
                show_given = true;
            }
            while (!list.empty()) {
                const auto comma = list.find(',');
                const std::string_view item = list.substr(0, comma);
                list = comma == std::string_view::npos ? std::string_view{} : list.substr(comma + 1);
                if (iequals_ascii(item, "all")) {
                    options.show = (1u << kRangeKindCount) - 1;
                } else if (const auto kind = parse_range_kind(item)) {
                    options.show |= range_kind_bit(*kind);
                } else if (!item.empty()) {
                    invalid("unknown range kind '" + std::string(item) + "'; expected changed, unchanged, unknown, added, removed or all");
                }
            }
        } else if (o == "--limit") {
            options.limit = reader.uint_value(0, std::numeric_limits<std::uint32_t>::max());
            options.limit_given = true;
        } else if (o == "--force") {
            reader.flag();
            options.force = true;
        } else if (o == "-j" || o == "--threads") {
            options.threads = static_cast<unsigned>(reader.uint_value(1, 1024));
        } else if (o == "--no-progress") {
            reader.flag();
            options.progress = false;
        } else if (o == "-q" || o == "--quiet") {
            reader.flag();
            options.quiet = true;
        } else {
            reader.unknown();
        }
    }
    if (options.operands.size() < 2 || options.operands.size() > 3) {
        invalid("diff expects BEFORE AFTER snapshots, or a process followed by one or two snapshots");
    }
    return options;
}

InfoOptions parse_info_options(std::vector<std::string> args) {
    InfoOptions options;
    ArgReader reader(std::move(args));
    std::vector<std::string> positionals;
    while (!reader.done()) {
        const auto option = reader.next_option();
        if (!option) {
            if (!reader.done()) {
                positionals.push_back(reader.positional());
            }
            continue;
        }
        if (*option == "-f" || *option == "--format") {
            options.format = parse_format(reader.value());
        } else {
            reader.unknown();
        }
    }
    if (positionals.size() != 1) {
        invalid(positionals.empty() ? "missing snapshot file" : "unexpected argument '" + positionals[1] + "'");
    }
    options.path = positionals.front();
    return options;
}

TuiOptions parse_tui_options(std::vector<std::string> args) {
    TuiOptions options;
    ArgReader reader(std::move(args));
    std::vector<std::string> positionals;
    while (!reader.done()) {
        const auto option = reader.next_option();
        if (!option) {
            if (!reader.done()) {
                positionals.push_back(reader.positional());
            }
            continue;
        }
        if (*option == "-j" || *option == "--threads") {
            options.threads = static_cast<unsigned>(reader.uint_value(1, 1024));
        } else {
            reader.unknown();
        }
    }
    if (positionals.size() != 1) {
        invalid(positionals.empty() ? "missing process id or name" : "unexpected argument '" + positionals[1] + "'");
    }
    options.target = positionals.front();
    return options;
}

namespace {

void set_condition(const ArgReader& reader, std::optional<Compare>& compare, Compare value) {
    if (compare) {
        invalid("give one condition per scan; " + reader.option() + " follows another one");
    }
    compare = value;
}

// --eq, --gt, --lt and --between; false for any other option.
bool parse_number_condition(ArgReader& reader, const std::string& o, std::optional<Compare>& compare, std::string& low,
                            std::string& high) {
    if (o == "--eq" || o == "--gt" || o == "--lt") {
        set_condition(reader, compare, o == "--eq" ? Compare::Exact : o == "--gt" ? Compare::Greater : Compare::Less);
        low = reader.value();
    } else if (o == "--between") {
        set_condition(reader, compare, Compare::Between);
        const std::string range = reader.value();
        const auto colon = range.find(':');
        if (colon == std::string::npos) {
            invalid("--between expects LOW:HIGH, e.g. 50:100, got '" + range + "'");
        }
        low = range.substr(0, colon);
        high = range.substr(colon + 1);
    } else {
        return false;
    }
    return true;
}

}  // namespace

ValueOptions parse_value_options(std::vector<std::string> args) {
    ValueOptions options;
    ArgReader reader(std::move(args));
    std::vector<std::string> positionals;
    const auto condition = [&](Compare compare) { set_condition(reader, options.compare, compare); };
    while (!reader.done()) {
        const auto option = reader.next_option();
        if (!option) {
            if (!reader.done()) {
                positionals.push_back(reader.positional());
            }
            continue;
        }
        const std::string& o = *option;
        if (parse_number_condition(reader, o, options.compare, options.operand, options.operand_high)) {
            continue;
        }
        if (o == "--unknown"|| o == "--increased" || o == "--decreased" || o == "--changed" || o == "--unchanged") {
            reader.flag();
            condition(o == "--unknown"     ? Compare::Unknown
                      : o == "--increased" ? Compare::Increased
                      : o == "--decreased" ? Compare::Decreased
                      : o == "--changed"   ? Compare::Changed
                                           : Compare::Unchanged);
        } else if (o == "--as") {
            options.type = parse_value_type(reader.value());
        } else if (o == "--unaligned") {
            reader.flag();
            options.unaligned = true;
        } else if (o == "--save") {
            options.save = reader.value();
            if (options.save.empty()) {
                invalid("--save needs a file name");
            }
        } else if (o == "-j" || o == "--threads") {
            options.threads = static_cast<unsigned>(reader.uint_value(1, 1024));
        } else if (o == "-f" || o == "--format") {
            options.format = parse_format(reader.value());
        } else if (o == "-o" || o == "--output") {
            options.path = reader.value();
            if (options.path.empty()) {
                invalid("--output needs a file name");
            }
        } else if (o == "--limit") {
            options.limit = reader.uint_value(0, std::numeric_limits<std::uint32_t>::max());
            options.limit_given = true;
        } else if (o == "--no-progress") {
            reader.flag();
            options.progress = false;
        } else if (o == "-q" || o == "--quiet") {
            reader.flag();
            options.quiet = true;
        } else if (parse_region_option(reader, o, options.filter)) {
            options.filter_given = true;
        } else {
            reader.unknown();
        }
    }
    if (positionals.size() != 1) {
        invalid(positionals.empty() ? "missing target: give a PID, an executable name or a value file saved with --save"
                                    : "unexpected argument '" + positionals[1] + "'");
    }
    options.target = positionals.front();
    return options;
}

PointerOptions parse_pointer_options(std::vector<std::string> args) {
    PointerOptions options;
    ArgReader reader(std::move(args));
    std::vector<std::string> positionals;
    while (!reader.done()) {
        const auto option = reader.next_option();
        if (!option) {
            if (!reader.done()) {
                positionals.push_back(reader.positional());
            }
            continue;
        }
        const std::string& o = *option;
        if (parse_number_condition(reader, o, options.compare, options.operand, options.operand_high)) {
            continue;
        }
        if (o == "--to") {
            const std::string text = reader.value();
            options.to = parse_uint(text);
            if (!options.to) {
                invalid("--to expects an address, e.g. 0x7FF6A0001000, got '" + text + "'");
            }
        } else if (o == "--as") {
            options.type = parse_value_type(reader.value());
        } else if (o == "--depth") {
            options.search.depth = static_cast<unsigned>(reader.uint_value(1, kMaxPointerDepth));
            options.search_given = true;
        } else if (o == "--max-offset") {
            options.search.max_offset = static_cast<std::uint32_t>(reader.uint_value(0, std::numeric_limits<std::uint32_t>::max()));
            options.search_given = true;
        } else if (o == "--max-chains") {
            options.search.max_chains = reader.uint_value(1, std::numeric_limits<std::uint32_t>::max());
            options.search_given = true;
        } else if (o == "--save") {
            options.save = reader.value();
            if (options.save.empty()) {
                invalid("--save needs a file name");
            }
        } else if (o == "-j" || o == "--threads") {
            options.search.threads = static_cast<unsigned>(reader.uint_value(1, 1024));
        } else if (o == "-f" || o == "--format") {
            options.format = parse_format(reader.value());
        } else if (o == "-o" || o == "--output") {
            options.path = reader.value();
            if (options.path.empty()) {
                invalid("--output needs a file name");
            }
        } else if (o == "--limit") {
            options.limit = reader.uint_value(0, std::numeric_limits<std::uint32_t>::max());
        } else if (o == "--no-progress") {
            reader.flag();
            options.progress = false;
        } else if (o == "-q" || o == "--quiet") {
            reader.flag();
            options.quiet = true;
        } else if (parse_region_option(reader, o, options.filter)) {
            options.filter_given = true;
        } else {
            reader.unknown();
        }
    }
    if (positionals.empty() || positionals.size() > 2) {
        invalid(positionals.empty() ? "missing target: give a PID, an executable name or a pointer file saved with --save"
                                    : "unexpected argument '" + positionals[2] + "'");
    }
    options.target = positionals[0];
    if (positionals.size() == 2) {
        options.process = positionals[1];
    }
    return options;
}

StructOptions parse_struct_options(std::vector<std::string> args) {
    StructOptions options;
    ArgReader reader(std::move(args));
    std::vector<std::string> positionals;
    while (!reader.done()) {
        const auto option = reader.next_option();
        if (!option) {
            if (!reader.done()) {
                positionals.push_back(reader.positional());
            }
            continue;
        }
        const std::string& o = *option;
        if (o == "--size") {
            options.size = static_cast<std::uint32_t>(reader.uint_value(1, kMaxStructSize));
            options.size_given = true;
        } else if (o == "--def") {
            options.definition = reader.value();
            if (options.definition.empty()) {
                invalid("--def needs a file name");
            }
        } else if (o == "-f" || o == "--format") {
            options.format = parse_format(reader.value());
        } else if (o == "-o" || o == "--output") {
            options.path = reader.value();
            if (options.path.empty()) {
                invalid("--output needs a file name");
            }
        } else if (o == "-q" || o == "--quiet") {
            reader.flag();
            options.quiet = true;
        } else {
            reader.unknown();
        }
    }
    if (positionals.size() != 2) {
        invalid(positionals.empty()     ? "missing target process: give a PID or an executable name"
                : positionals.size() == 1 ? "missing base: give an address such as 0x1F4A2C3B0D8 or a chain such as [[game.exe+0x52080]+0x8]"
                                          : "unexpected argument '" + positionals[2] + "'");
    }
    options.target = positionals[0];
    const auto base = parse_pointer_path(positionals[1], 8);
    if (!base) {
        invalid("the base is an address such as 0x1F4A2C3B0D8 or a chain such as [[game.exe+0x52080]+0x8], got '" + positionals[1] +
                "'");
    }
    options.base = *base;
    return options;
}

InspectArgs parse_inspect_options(std::vector<std::string> args) {
    InspectArgs options;
    ArgReader reader(std::move(args));
    std::vector<std::string> positionals;
    while (!reader.done()) {
        const auto option = reader.next_option();
        if (!option) {
            if (!reader.done()) {
                positionals.push_back(reader.positional());
            }
            continue;
        }
        const std::string& o = *option;
        if (o == "--all") {
            reader.flag();
            options.all = true;
        } else if (o == "--kind") {
            options.kinds = parse_finding_kinds(reader.value());
        } else if (o == "-f" || o == "--format") {
            options.format = parse_format(reader.value());
        } else if (o == "-o" || o == "--output") {
            options.path = reader.value();
            if (options.path.empty()) {
                invalid("--output needs a file name");
            }
        } else if (o == "-q" || o == "--quiet") {
            reader.flag();
            options.quiet = true;
        } else {
            reader.unknown();
        }
    }
    if (options.all) {
        if (!positionals.empty()) {
            invalid("--all checks every process; leave out the target '" + positionals.front() + "'");
        }
        return options;
    }
    if (positionals.size() != 1) {
        invalid(positionals.empty() ? "missing target process: give a PID or an executable name, or --all"
                                    : "unexpected argument '" + positionals[1] + "'");
    }
    options.target = positionals.front();
    return options;
}

namespace {

std::uint64_t parse_hex_address(std::string_view text) {
    std::string_view digits = trim(text);
    if (digits.size() > 2 && digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X')) {
        digits.remove_prefix(2);
    }
    std::uint64_t value = 0;
    const auto [end, error] = std::from_chars(digits.data(), digits.data() + digits.size(), value, 16);
    if (digits.empty() || error != std::errc{} || end != digits.data() + digits.size()) {
        invalid("the address is hexadecimal, e.g. 0x7FF6A0001000, got '" + std::string(text) + "'");
    }
    return value;
}

}  // namespace

DisasmArgs parse_disasm_options(std::vector<std::string> args) {
    DisasmArgs options;
    ArgReader reader(std::move(args));
    std::vector<std::string> positionals;
    bool count_given = false;
    while (!reader.done()) {
        const auto option = reader.next_option();
        if (!option) {
            if (!reader.done()) {
                positionals.push_back(reader.positional());
            }
            continue;
        }
        const std::string& o = *option;
        if (o == "-n" || o == "--count") {
            options.count = static_cast<std::size_t>(reader.uint_value(1, 100000));
            count_given = true;
        } else if (o == "--bytes") {
            options.bytes = reader.size_value(1, std::uint64_t{16} << 20);
            options.bytes_given = true;
        } else if (o == "-f" || o == "--format") {
            options.format = parse_format(reader.value());
        } else if (o == "-o" || o == "--output") {
            options.path = reader.value();
            if (options.path.empty()) {
                invalid("--output needs a file name");
            }
        } else if (o == "-q" || o == "--quiet") {
            reader.flag();
            options.quiet = true;
        } else {
            reader.unknown();
        }
    }
    if (count_given && options.bytes_given) {
        invalid("give either --count or --bytes, not both");
    }
    if (positionals.size() != 2) {
        invalid(positionals.empty()      ? "missing target process: give a PID or an executable name"
                : positionals.size() == 1 ? "missing address: give it in hexadecimal, e.g. 0x7FF6A0001000"
                                          : "unexpected argument '" + positionals[2] + "'");
    }
    options.target = positionals[0];
    options.address = parse_hex_address(positionals[1]);
    return options;
}

bool take_debug_privilege(std::vector<std::string>& args) {
    const auto end = std::find(args.begin(), args.end(), "--");
    const auto removed = std::remove(args.begin(), end, "--debug-privilege");
    if (removed == end) {
        return false;
    }
    args.erase(removed, end);
    return true;
}

ValueCondition parse_value_condition(Compare compare, ValueType type, std::string_view low, std::string_view high) {
    ValueCondition condition;
    condition.compare = compare;
    if (compare != Compare::Exact && compare != Compare::Greater && compare != Compare::Less && compare != Compare::Between) {
        return condition;
    }
    low = trim(low);
    high = compare == Compare::Between ? trim(high) : low;
    if (low.empty() || high.empty()) {
        invalid(compare == Compare::Between ? "--between needs two numbers: LOW:HIGH" : "the condition needs a number");
    }
    if (is_float(type)) {
        condition.number = float_operand(low, type);
        condition.number_high = float_operand(high, type);
        if (compare == Compare::Exact) {
            condition.tolerance = typed_tolerance(low);
        }
        if (condition.number > condition.number_high) {
            std::swap(condition.number, condition.number_high);
        }
    } else if (compare == Compare::Exact) {
        condition.bits = integer_bits(low, type);
    } else {
        condition.integer = signed_integer(low, type);
        condition.integer_high = signed_integer(high, type);
        if (condition.integer > condition.integer_high) {
            std::swap(condition.integer, condition.integer_high);
        }
    }
    return condition;
}

}  // namespace mh::cli
