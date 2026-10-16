#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "inspect/inspect.hpp"
#include "pipeline/scan_session.hpp"
#include "pointer/pointer_scan.hpp"
#include "results/export.hpp"
#include "results/query.hpp"
#include "snapshot/capture.hpp"
#include "snapshot/diff_export.hpp"
#include "structure/struct_layout.hpp"
#include "value/value_scan.hpp"

namespace mh::cli {

// Walks the tokens after the command name. Accepts "--name value", "--name=value", "-x value", and "--" to
// end option parsing. Errors are reported as Error(InvalidArgument) naming the offending option.
class ArgReader {
public:
    explicit ArgReader(std::vector<std::string> args) : args_(std::move(args)) {}

    bool done() const noexcept { return index_ >= args_.size(); }

    // The next token as an option name, or nullopt when it is a positional argument.
    std::optional<std::string> next_option();
    std::string positional();

    std::string value();
    std::uint64_t uint_value(std::uint64_t min, std::uint64_t max);
    std::uint64_t size_value(std::uint64_t min, std::uint64_t max);
    // Marks the current option as a flag; rejects "--flag=value".
    void flag();
    [[noreturn]] void unknown() const;

    const std::string& option() const noexcept { return option_; }

private:
    std::vector<std::string> args_;
    std::size_t index_ = 0;
    std::string option_;
    std::optional<std::string> inline_value_;
    bool options_ended_ = false;
};

struct OutputOptions {
    OutputFormat format = OutputFormat::Text;
    std::string path;
    ExportOptions export_options;
    MatchQuery query;
    bool limit_given = false;
    std::vector<std::string> pattern_filters;
    bool progress = true;
    bool quiet = false;
};

struct ScanOptions {
    std::string target;
    ScanRequest request;
    OutputOptions output;
    std::string changed_since;
};

struct SnapshotOptions {
    std::string target;
    std::string path;
    RegionFilter filter;
    CaptureOptions capture;
    bool with_data = false;
    std::uint64_t max_data = std::uint64_t{1} << 30;
    bool progress = true;
    bool quiet = false;
};

struct DiffOptions {
    std::vector<std::string> operands;
    OutputFormat format = OutputFormat::Text;
    std::string path;
    std::uint32_t show = kDefaultShownRanges;
    std::size_t limit = 0;
    bool limit_given = false;
    bool force = false;
    unsigned threads = 0;
    bool progress = true;
    bool quiet = false;
};

struct InfoOptions {
    std::string path;
    OutputFormat format = OutputFormat::Text;
};

struct TuiOptions {
    std::string target;
    unsigned threads = 0;
};

struct RegionsOptions {
    std::string target;
    RegionFilter filter;
    bool all = false;
    OutputFormat format = OutputFormat::Text;
    std::string path;
};

inline constexpr std::size_t kDefaultValueRows = 20;

// A first scan when the target is a process, a next scan when it is a value file. Without a condition the
// candidates of the file are only shown.
struct ValueOptions {
    std::string target;
    std::optional<Compare> compare;
    // As typed; parsed once the value type is known.
    std::string operand;
    std::string operand_high;
    std::optional<ValueType> type;
    bool unaligned = false;
    RegionFilter filter;
    bool filter_given = false;
    unsigned threads = 0;
    std::string save;
    OutputFormat format = OutputFormat::Text;
    std::string path;
    std::size_t limit = kDefaultValueRows;
    bool limit_given = false;
    bool progress = true;
    bool quiet = false;
};

inline constexpr std::size_t kDefaultPointerRows = 20;

// A search when the target is a process, a check of the saved chains when it is a pointer file. Without --to or
// a condition the chains of the file are only shown.
struct PointerOptions {
    std::string target;
    // For a pointer file; empty means the process the file was saved from, found by its name.
    std::string process;
    std::optional<std::uint64_t> to;
    std::optional<Compare> compare;
    // As typed; parsed once the value type is known.
    std::string operand;
    std::string operand_high;
    std::optional<ValueType> type;
    PointerScanOptions search;
    bool search_given = false;
    RegionFilter filter = pointer_region_filter();
    bool filter_given = false;
    std::string save;
    OutputFormat format = OutputFormat::Text;
    std::string path;
    std::size_t limit = kDefaultPointerRows;
    bool progress = true;
    bool quiet = false;
};

// The structure at an address or at the end of a chain: the fields of a definition file and guesses between them.
struct StructOptions {
    std::string target;
    // Parsed with 8-byte pointers; the command sets the pointer size of the process.
    PointerPath base;
    std::uint32_t size = kDefaultStructSize;
    bool size_given = false;
    std::string definition;
    OutputFormat format = OutputFormat::Text;
    std::string path;
    bool quiet = false;
};

struct PsOptions {
    std::string filter;
    OutputFormat format = OutputFormat::Text;
};

// Signs of injected code in one process, or with `all` in every process MemHunter can open.
struct InspectArgs {
    std::string target;
    bool all = false;
    std::uint32_t kinds = kAllFindingKinds;
    OutputFormat format = OutputFormat::Text;
    std::string path;
    bool quiet = false;
};

inline constexpr std::size_t kDefaultDisasmCount = 32;

// Disassembles machine code from an address: either a count of instructions or a span of bytes.
struct DisasmArgs {
    std::string target;
    std::uint64_t address = 0;
    std::size_t count = kDefaultDisasmCount;
    std::uint64_t bytes = 0;
    bool bytes_given = false;
    OutputFormat format = OutputFormat::Text;
    std::string path;
    bool quiet = false;
};

ScanOptions parse_scan_options(std::vector<std::string> args);
RegionsOptions parse_regions_options(std::vector<std::string> args);
PsOptions parse_ps_options(std::vector<std::string> args);
SnapshotOptions parse_snapshot_options(std::vector<std::string> args);
DiffOptions parse_diff_options(std::vector<std::string> args);
InfoOptions parse_info_options(std::vector<std::string> args);
TuiOptions parse_tui_options(std::vector<std::string> args);
ValueOptions parse_value_options(std::vector<std::string> args);
PointerOptions parse_pointer_options(std::vector<std::string> args);
StructOptions parse_struct_options(std::vector<std::string> args);
InspectArgs parse_inspect_options(std::vector<std::string> args);
DisasmArgs parse_disasm_options(std::vector<std::string> args);

// Removes every --debug-privilege before a "--" and tells whether there was one.
bool take_debug_privilege(std::vector<std::string>& args);

// The condition for values of `type`. Integers: decimal or 0x-hex; = accepts the signed and the unsigned range of
// the type, the ordered comparisons the signed one. Floats: = matches within half of the last digit typed ("100"
// is 99.5 to 100.5), with an exponent exactly. Swapped bounds of between are put in order.
ValueCondition parse_value_condition(Compare compare, ValueType type, std::string_view low, std::string_view high);

// "name=48 8B ?? 90" names a signature; signatures never contain '=' themselves.
Pattern parse_named_signature(std::string_view text);
std::vector<Pattern> read_pattern_file(const std::string& path);

}  // namespace mh::cli
