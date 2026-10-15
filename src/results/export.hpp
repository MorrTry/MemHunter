#pragma once

#include <cstddef>
#include <optional>
#include <ostream>
#include <span>
#include <string>
#include <string_view>

#include "results/result_set.hpp"

namespace mh {

enum class OutputFormat { Text, Json, Csv };

std::optional<OutputFormat> parse_output_format(std::string_view text);

struct ExportOptions {
    bool include_preview = true;
    std::size_t preview_width = 64;
};

void write_results(std::ostream& out, OutputFormat format, const ResultSet& results, std::span<const std::size_t> rows,
                   const ExportOptions& options);

void write_text(std::ostream& out, const ResultSet& results, std::span<const std::size_t> rows, const ExportOptions& options);
void write_json(std::ostream& out, const ResultSet& results, std::span<const std::size_t> rows, const ExportOptions& options);
void write_csv(std::ostream& out, const ResultSet& results, std::span<const std::size_t> rows, const ExportOptions& options);

void write_summary(std::ostream& out, const ResultSet& results, std::size_t shown);

std::string json_escape(std::string_view text);
std::string csv_field(std::string_view text);

// Terminal columns occupied by UTF-8 text, assuming one column per code point.
std::size_t display_width(std::string_view utf8);
std::string fit_width(std::string_view utf8, std::size_t width);

}  // namespace mh
