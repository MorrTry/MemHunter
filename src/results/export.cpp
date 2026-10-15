#include "results/export.hpp"

#include <algorithm>
#include <array>
#include <cstdio>

#include "common/text.hpp"

namespace mh {

namespace {

constexpr std::size_t kTextHexBytes = 16;

std::string format_seconds(double seconds) {
    std::array<char, 32> buffer{};
    std::snprintf(buffer.data(), buffer.size(), "%.3f s", seconds);
    return buffer.data();
}

const PatternInfo& pattern_of(const ResultSet& results, const Match& match) {
    static const PatternInfo unknown{"?", PatternKind::Bytes, 0, false};
    return match.pattern < results.patterns.size() ? results.patterns[match.pattern] : unknown;
}

std::string text_column_preview(const ResultSet& results, const Match& match) {
    const PatternKind kind = pattern_of(results, match).kind;
    if (kind == PatternKind::Bytes || kind == PatternKind::Signature) {
        const auto bytes = results.preview(match);
        return hex_preview(bytes.first(std::min(bytes.size(), kTextHexBytes)));
    }
    return results.preview_text(match);
}

}  // namespace

std::optional<OutputFormat> parse_output_format(std::string_view text) {
    if (iequals_ascii(text, "text") || iequals_ascii(text, "table")) return OutputFormat::Text;
    if (iequals_ascii(text, "json")) return OutputFormat::Json;
    if (iequals_ascii(text, "csv")) return OutputFormat::Csv;
    return std::nullopt;
}

std::size_t display_width(std::string_view utf8) {
    std::size_t width = 0;
    for (const char c : utf8) {
        if ((static_cast<unsigned char>(c) & 0xC0) != 0x80) {
            ++width;
        }
    }
    return width;
}

std::string fit_width(std::string_view utf8, std::size_t width) {
    if (display_width(utf8) <= width) {
        std::string out(utf8);
        out.append(width - display_width(utf8), ' ');
        return out;
    }
    std::string out;
    std::size_t used = 0;
    for (std::size_t i = 0; i < utf8.size(); ++i) {
        const bool starts_code_point = (static_cast<unsigned char>(utf8[i]) & 0xC0) != 0x80;
        if (starts_code_point && used + 1 >= width) {
            break;
        }
        used += starts_code_point ? 1 : 0;
        out.push_back(utf8[i]);
    }
    out += "\xE2\x80\xA6";
    return out;
}

std::string json_escape(std::string_view text) {
    std::string out;
    out.reserve(text.size() + 2);
    for (const char c : text) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    std::array<char, 8> buffer{};
                    std::snprintf(buffer.data(), buffer.size(), "\\u%04X", static_cast<unsigned>(static_cast<unsigned char>(c)));
                    out += buffer.data();
                } else {
                    out.push_back(c);
                }
        }
    }
    return out;
}

std::string csv_field(std::string_view text) {
    if (text.find_first_of(",\"\r\n") == std::string_view::npos) {
        return std::string(text);
    }
    std::string out = "\"";
    for (const char c : text) {
        if (c == '"') {
            out.push_back('"');
        }
        out.push_back(c);
    }
    out.push_back('"');
    return out;
}

void write_results(std::ostream& out, OutputFormat format, const ResultSet& results, std::span<const std::size_t> rows,
                   const ExportOptions& options) {
    switch (format) {
        case OutputFormat::Text: write_text(out, results, rows, options); break;
        case OutputFormat::Json: write_json(out, results, rows, options); break;
        case OutputFormat::Csv: write_csv(out, results, rows, options); break;
    }
}

void write_text(std::ostream& out, const ResultSet& results, std::span<const std::size_t> rows, const ExportOptions& options) {
    out << fit_width("ADDRESS", 19) << fit_width("KIND", 14) << fit_width("LEN", 7) << fit_width("PROT", 6)
        << fit_width("TYPE", 8) << fit_width("MODULE", 17) << fit_width("PATTERN", 21);
    out << (options.include_preview ? "PREVIEW" : "") << '\n';
    for (const std::size_t row : rows) {
        const Match& match = results.matches[row];
        const PatternInfo& pattern = pattern_of(results, match);
        const Region* region = results.region_of(match);
        out << fit_width(format_address(match.address), 19) << fit_width(to_string(pattern.kind), 14)
            << fit_width(std::to_string(match.length), 7)
            << fit_width(region ? protection_to_string(region->protect) : "?", 6)
            << fit_width(region ? to_string(region->type) : "?", 8)
            << fit_width(region ? region->module_name() : "", 17)
            << fit_width(is_extracted_string(pattern.kind) ? "-" : pattern.label, 21);
        if (options.include_preview) {
            const std::string preview = text_column_preview(results, match);
            out << (display_width(preview) > options.preview_width ? fit_width(preview, options.preview_width) : preview);
        }
        out << '\n';
    }
}

void write_json(std::ostream& out, const ResultSet& results, std::span<const std::size_t> rows, const ExportOptions& options) {
    const auto& s = results.stats;
    out << "{\n  \"tool\": \"memhunter\",\n  \"version\": \"" << MEMHUNTER_VERSION << "\",\n";
    out << "  \"process\": {\"pid\": " << results.process.pid << ", \"name\": \"" << json_escape(results.process.name)
        << "\", \"path\": \"" << json_escape(results.process.path) << "\", \"wow64\": " << (results.process.wow64 ? "true" : "false")
        << "},\n";
    out << "  \"patterns\": [";
    for (std::size_t i = 0; i < results.patterns.size(); ++i) {
        const auto& p = results.patterns[i];
        out << (i == 0 ? "\n" : ",\n") << "    {\"id\": " << i << ", \"label\": \"" << json_escape(p.label) << "\", \"kind\": \""
            << to_string(p.kind) << "\", \"length\": " << p.length << ", \"case_insensitive\": " << (p.case_insensitive ? "true" : "false")
            << "}";
    }
    out << "\n  ],\n";
    out << "  \"stats\": {\"status\": \"" << to_string(s.status) << "\", \"algorithm\": \"" << json_escape(s.algorithm)
        << "\", \"scan_threads\": " << s.scan_threads << ", \"read_threads\": " << s.read_threads << ", \"chunk_size\": " << s.chunk_size
        << ", \"regions_total\": " << s.regions_total << ", \"regions_selected\": " << s.regions_selected
        << ", \"bytes_planned\": " << s.bytes_planned << ", \"bytes_read\": " << s.bytes_read
        << ", \"bytes_unreadable\": " << s.bytes_unreadable << ", \"read_calls\": " << s.read_calls
        << ", \"read_failures\": " << s.read_failures << ", \"matches_found\": " << s.matches_found
        << ", \"matches_stored\": " << results.matches.size() << ", \"matches_exported\": " << rows.size()
        << ", \"truncated\": " << (s.truncated ? "true" : "false") << ", \"enumerate_seconds\": " << s.enumerate_seconds
        << ", \"read_seconds\": " << s.read_seconds << ", \"scan_seconds\": " << s.scan_seconds
        << ", \"wall_seconds\": " << s.wall_seconds << "},\n";
    out << "  \"matches\": [";
    bool first = true;
    for (const std::size_t row : rows) {
        const Match& match = results.matches[row];
        const PatternInfo& pattern = pattern_of(results, match);
        const Region* region = results.region_of(match);
        out << (first ? "\n" : ",\n") << "    {\"address\": \"" << format_address(match.address) << "\", \"length\": " << match.length
            << ", \"pattern\": " << match.pattern << ", \"kind\": \"" << to_string(pattern.kind) << "\"";
        if (region) {
            out << ", \"region_base\": \"" << format_address(region->base) << "\", \"region_size\": " << region->size
                << ", \"protection\": \"" << protection_to_string(region->protect) << "\", \"type\": \"" << to_string(region->type)
                << "\", \"module\": \"" << json_escape(region->module_name()) << "\"";
        }
        if (options.include_preview && match.preview_size != 0) {
            out << ", \"preview_hex\": \"" << results.preview_hex(match) << "\", \"preview_text\": \""
                << json_escape(results.preview_text(match)) << "\"";
        }
        out << "}";
        first = false;
    }
    out << "\n  ],\n  \"read_failures\": [";
    for (std::size_t i = 0; i < results.read_failures.size(); ++i) {
        const auto& f = results.read_failures[i];
        out << (i == 0 ? "\n" : ",\n") << "    {\"address\": \"" << format_address(f.address) << "\", \"size\": " << f.size
            << ", \"error\": " << f.error << "}";
    }
    out << "\n  ]\n}\n";
}

void write_csv(std::ostream& out, const ResultSet& results, std::span<const std::size_t> rows, const ExportOptions& options) {
    out << "address,length,pattern,kind,label,region_base,region_size,protection,type,module";
    out << (options.include_preview ? ",preview_hex,preview_text\r\n" : "\r\n");
    for (const std::size_t row : rows) {
        const Match& match = results.matches[row];
        const PatternInfo& pattern = pattern_of(results, match);
        const Region* region = results.region_of(match);
        out << format_address(match.address) << ',' << match.length << ',' << match.pattern << ',' << to_string(pattern.kind) << ','
            << csv_field(pattern.label) << ',' << (region ? format_address(region->base) : "") << ','
            << (region ? std::to_string(region->size) : "") << ',' << (region ? protection_to_string(region->protect) : "") << ','
            << (region ? to_string(region->type) : "") << ',' << csv_field(region ? region->module_name() : "");
        if (options.include_preview) {
            out << ',' << results.preview_hex(match) << ',' << csv_field(results.preview_text(match));
        }
        out << "\r\n";
    }
}

void write_summary(std::ostream& out, const ResultSet& results, std::size_t shown) {
    const auto& s = results.stats;
    out << "Scanned " << format_size(s.bytes_read) << " in " << s.regions_selected << " of " << s.regions_total << " regions in "
        << format_seconds(s.wall_seconds) << " (" << format_rate(s.wall_seconds > 0 ? static_cast<double>(s.bytes_read) / s.wall_seconds : 0)
        << "); thread time: read " << format_seconds(s.read_seconds) << ", scan " << format_seconds(s.scan_seconds) << '\n';
    out << "Matches: " << results.matches.size();
    if (shown != results.matches.size()) {
        out << " (" << shown << " shown)";
    }
    out << "; unreadable: " << format_size(s.bytes_unreadable) << " in " << s.read_failures << " ranges; status: " << to_string(s.status)
        << '\n';
    out << "Engine: " << s.algorithm << "; " << s.scan_threads << " scan + " << s.read_threads << " read threads; "
        << format_size(s.chunk_size) << " chunks\n";
    if (s.truncated) {
        out << "Result storage was capped: " << s.matches_found << " matches were found but only " << results.matches.size()
            << " kept. Raise --max-matches to keep more.\n";
    }
}

}  // namespace mh
