#include "cli/commands.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <string_view>
#include <thread>

#include "cli/args.hpp"
#include "cli/listings.hpp"
#include "common/text.hpp"
#include "inspect/process_inspect.hpp"
#include "memory/memory_dump.hpp"
#include "memory/process_memory.hpp"
#include "pointer/pointer_file.hpp"
#include "pointer/pointer_scan.hpp"
#include "process/privilege.hpp"
#include "process/process.hpp"
#include "snapshot/capture.hpp"
#include "snapshot/diff.hpp"
#include "snapshot/diff_export.hpp"
#include "snapshot/snapshot_file.hpp"
#include "structure/struct_file.hpp"
#include "tui/app.hpp"
#include "value/value_file.hpp"
#include "value/value_scan.hpp"

namespace mh::cli {

namespace {

constexpr std::size_t kConsoleRowLimit = 200;

constexpr std::string_view kMainHelp = R"(MemHunter )" MEMHUNTER_VERSION R"( - fast search in the memory of Windows processes you are allowed to read

Usage:
  memhunter scan <pid|name> [options]      search strings, byte patterns and signatures in one pass
  memhunter regions <pid|name> [options]   list memory regions
  memhunter ps [filter]                    list running processes
  memhunter snapshot <pid|name> -o FILE    record regions and block hashes for later comparison
  memhunter diff BEFORE AFTER              compare two snapshots
  memhunter diff <pid|name> BEFORE         compare a snapshot with the live process
  memhunter info SNAPSHOT                  show what a snapshot file contains
  memhunter value <pid|name> --eq N        find the addresses of a number; --save FILE keeps them
  memhunter value FILE --decreased         narrow the saved addresses down with the next scan
  memhunter pointers <pid|name> --to ADDR  find chains of pointers that lead to an address
  memhunter pointers FILE --to ADDR        keep the saved chains that lead to the address after a restart
  memhunter struct <pid|name> BASE         show the fields of the structure at an address or a chain
  memhunter inspect <pid|name>             look for injected code: executable memory outside modules,
                                           PE headers, RWX memory, patched or replaced modules
  memhunter inspect --all                  the same for every process MemHunter can open
  memhunter tui <pid|name>                 full-screen interface: scan, browse, filter and save results
  memhunter help [command]                 show help for a command
  memhunter --version

Any command:
  --debug-privilege                        enable SeDebugPrivilege, so that the processes of other users
                                           and of services can be opened too; needs MemHunter to run as
                                           administrator. Protected processes (PPL) stay closed

Examples:
  memhunter scan 1234 --strings --min-length 8 --unicode
  memhunter scan 1234 --pattern "48 8B ?? ?? 90"
  memhunter scan notepad.exe --string "https://" --string "config.json" --protection readwrite
  memhunter scan 1234 --pattern-file sigs.txt --format json --output results.json
  memhunter snapshot 1234 -o before.mhs      and later      memhunter diff 1234 before.mhs
  memhunter scan 1234 --strings --changed-since before.mhs

Exit codes:
  0  matches found (or command succeeded)     1  scan completed without matches
  2  invalid arguments or pattern             3  process not found, access denied or exited
  4  file error                               5  scan interrupted or target exited; partial results written
  6  damaged or foreign snapshot, value, pointer or structure file    9  internal error

MemHunter only reads memory of processes the current user can open with PROCESS_VM_READ. It enables
SeDebugPrivilege only when asked with --debug-privilege, and never injects code or touches guard pages.
)";

constexpr std::string_view kScanHelp = R"(Usage: memhunter scan <pid|name> [options]

What to search for (any combination, all in a single pass over memory):
  -s, --string TEXT         literal text, as ASCII/UTF-8 and UTF-16LE unless --ascii or --unicode is given
  -p, --pattern SIG         byte signature: "48 8B ?? ?? 90", "488B????90", nibble wildcards like "4?";
                            "name=SIG" gives it a label
      --pattern-file FILE   one [name=]signature per line; lines starting with # are ignored
      --strings             extract printable strings (ASCII anywhere, UTF-16LE at even addresses)
      --ascii, --unicode    restrict --string and --strings to one encoding
      --encoding LIST       ascii, utf16 or both
  -i, --ignore-case         ASCII case-insensitive --string
      --min-length N        minimum characters for --strings (default 4)
      --max-length N        longer strings are reported truncated (default 4096)

Which memory (default: committed, readable regions of every type; guard and no-access pages are skipped):
      --protection LIST     r, rw, wc, rx, rwx, wcx, writable, executable, readable (comma-separated)
      --type LIST           image, mapped, private, all
      --min-region-size S   only regions of at least S bytes (suffixes K, M, G)
      --max-region-size S   only regions of at most S bytes
      --include SPEC        address range START-END or module/file glob such as "game*.dll" (repeatable)
      --exclude SPEC        like --include, removes memory from the scan (repeatable)

Engine:
  -j, --threads N           scanner threads (default: number of logical CPUs)
      --readers N           reader threads (default: a quarter of the scanner threads)
      --chunk-size S        bytes per work item, 64K to 256M (default 256K)
      --algorithm NAME      auto, simd, horspool, aho-corasick, naive (default auto)
      --max-matches N       keep at most N matches, 0 = unlimited (default 1000000)
      --preview N           bytes captured with each match (default 32, strings keep the whole text)
      --changed-since SNAP  incremental rescan: report only matches that overlap memory which changed or
                            appeared since snapshot SNAP of the same process run. The selected memory is
                            still read once to hash it; only the changed parts are searched

Output:
  -f, --format FMT          text (default), json or csv
  -o, --output FILE         write results to FILE instead of standard output
      --sort KEY            address (default), pattern, kind, length or region
      --desc                sort in descending order
      --limit N             at most N rows (default: 200 for text on a console, otherwise all)
      --filter-kind LIST    ascii, utf16, bytes, signature, strings-ascii, strings-utf16, strings
      --filter-pattern L    only matches of the pattern labelled L, or #ID (repeatable)
      --filter-range R      only matches starting inside START-END (repeatable)
      --grep TEXT           only matches whose preview contains TEXT (ASCII case-insensitive)
      --no-preview          leave previews out of the output
      --no-progress         do not draw the progress line on stderr
  -q, --quiet               do not print the summary on stderr
)";

constexpr std::string_view kRegionsHelp = R"(Usage: memhunter regions <pid|name> [options]

Lists the regions a scan would read (committed, readable, not guard/no-access). Region filters of
'memhunter scan' apply: --protection, --type, --min-region-size, --max-region-size, --include, --exclude.

  --all                     list every allocated region, including reserved and inaccessible ones; the
                            other filters still apply, --protection cannot be combined with it
  -f, --format FMT          text (default), json or csv
  -o, --output FILE         write to FILE instead of standard output
)";

constexpr std::string_view kPsHelp = R"(Usage: memhunter ps [filter] [options]

Lists running processes. The optional filter is a case-insensitive name glob ("chrome*") or substring.

  -f, --format FMT          text (default), json or csv
)";

constexpr std::string_view kSnapshotHelp = R"(Usage: memhunter snapshot <pid|name> -o FILE [options]

Records the region table, the captured address ranges and a 64-bit hash of every block, so that a later
'memhunter diff' or 'memhunter scan --changed-since' can tell which memory changed. By default the memory
contents are NOT saved: the file shows whether a block changed, not what it contained.

  -o, --output FILE         snapshot file to write (written as FILE.partial, renamed when complete)
      --block-size S        hash granularity, a power of two from 4K to 1M (default 4K)
      --with-data           also save the memory contents, for byte-exact diffs. The file then holds raw
                            process memory (possibly passwords or keys) and is as large as the selection
      --max-data S          refuse --with-data when the selection is larger than S (default 1G)
  -j, --threads N           reader threads (default: number of logical CPUs)
      --no-progress         do not draw the progress line on stderr
  -q, --quiet               do not print the summary on stderr

Region filters of 'memhunter scan' select what is captured: --protection, --type, --min-region-size,
--max-region-size, --include, --exclude.

The process keeps running while it is captured, so a snapshot is not an atomic point-in-time image.
)";

constexpr std::string_view kDiffHelp = R"(Usage: memhunter diff BEFORE AFTER [options]
       memhunter diff <pid|name> BEFORE [AFTER] [options]

Compares two snapshots, or a snapshot with the live memory of the process it was taken from. Reports added,
removed and modified regions and splits the captured memory into ranges:
  changed     readable in both, contents differ        unchanged   readable in both, contents equal
  unknown     unreadable on one side, not comparable   added       captured only by AFTER
  removed     captured only by BEFORE
A live comparison reads the ranges that BEFORE captured. Ranges are exact to the block unless both sides
have contents (snapshots taken with --with-data, or live memory against such a snapshot).

Snapshots of different process runs are refused: Windows reuses and randomizes virtual addresses, so equal
addresses in two runs may hold unrelated data. --force compares them anyway and marks the report.

      --show LIST           range kinds to list: changed, unchanged, unknown, added, removed, all
                            (default changed,added,removed)
      --limit N             at most N ranges (default: 200 for text on a console, otherwise all)
  -f, --format FMT          text (default), json or csv (csv lists the ranges only)
  -o, --output FILE         write the report to FILE
      --force               compare snapshots of different process runs
  -j, --threads N           reader threads for live comparisons
      --no-progress         do not draw the progress line on stderr
  -q, --quiet               do not print the summary on stderr

Exit code 0 means differences were found, 1 means there were none.
)";

constexpr std::string_view kTuiHelp = R"(Usage: memhunter tui <pid|name> [-j N]

Opens a full-screen interface for one process. Type a text and/or a byte signature, choose the encoding,
case and memory type, and press Enter: the scan runs in the background with live progress and can be
cancelled at any time. Results can then be browsed, filtered, shown as hex or text, marked and saved.

  -j, --threads N           scanner threads (default: number of logical CPUs)

Keys:
  Tab, Shift+Tab            next / previous field          Enter, F5     start the scan
  Esc                       cancel the scan or a prompt    F10, Ctrl+C   quit
  Up, Down, PgUp, PgDn      move through results           Home, End     first / last result
  Space                     mark the selected result       a             mark all / none
  /                         filter by address, pattern or text            v, F3   hex or text preview
  F2, s                     save the marked results (or all shown) as .json, .csv or text by extension

Needs an interactive console of at least 80x20 characters that understands virtual terminal sequences
(Windows 10 1607 or later). The interface is strictly white on black. For scripts and pipes use 'scan'.
)";

constexpr std::string_view kInfoHelp = R"(Usage: memhunter info SNAPSHOT [-f text|json|csv]

Validates a snapshot file and shows the process it came from, when it was captured, what was saved
(hashes only, or hashes and memory contents) and how much memory it covers.
)";

constexpr std::string_view kValueHelp = R"(Usage: memhunter value <pid|name> CONDITION [options]     first scan
       memhunter value FILE [CONDITION] [options]         next scan, or show the saved addresses

Finds where a program keeps a number. Start with what you know about the value and save the addresses,
change the value in the program, then narrow the addresses down with the next scans:
  memhunter value game.exe --eq 100 --save hp.mhv
  memhunter value hp.mhv --decreased             FILE is replaced with the addresses that are left
  memhunter value hp.mhv --eq 73
  memhunter value hp.mhv                         shows the addresses with their current values

Conditions, one per scan:
      --eq N                equal to N; a float matches within half of its last digit ("100" is 99.5 to 100.5)
      --gt N, --lt N        greater than N, less than N
      --between A:B         from A to B, both included
      --unknown             any value, for a number the program does not show (first scan only)
      --increased, --decreased, --changed, --unchanged
                            compared with the scan before (next scans only)
Integers may be negative or 0x-hex; = takes the signed and the unsigned range of the type.

First scan:
      --as TYPE             int8, int16, int32 (default), int64, float or double
      --unaligned           check every byte offset, not only multiples of the value size
      --save FILE           save the addresses for the next scans (written as FILE.partial, then renamed)
Region filters of 'memhunter scan' select the memory: --protection, --type, --min-region-size,
--max-region-size, --include, --exclude.

Next scans take the process from FILE and need the same process run: after a restart the addresses mean
nothing, so start a new search. FILE is replaced only when addresses are left; --save NEW keeps FILE as it is.

Output:
  -f, --format FMT          text (default), json or csv; values are written as text
  -o, --output FILE         write the addresses to FILE instead of standard output
      --limit N             at most N addresses (default 20, 0 = all)
  -j, --threads N           scanner threads (default: number of logical CPUs)
      --no-progress         do not draw the progress line on stderr
  -q, --quiet               do not print the summary on stderr
VALUE is what this scan read and PREVIOUS what the scan before read. Without a condition VALUE is read now
and PREVIOUS is from the last scan.

Exit codes: 0 addresses found, 1 none (FILE is not changed), 2 invalid arguments, 3 process not found or
access denied, 4 file error, 5 interrupted, target exited or the list outgrew its memory budget (a third
of the free RAM; nothing is saved), 6 FILE damaged or saved from another process run.
)";

constexpr std::string_view kPointersHelp = R"(Usage: memhunter pointers <pid|name> --to ADDR [options]       search
       memhunter pointers FILE [<pid|name>] [CHECK] [options]   check the saved chains, or show them

Finds chains of pointers from a module to an address, so that the address can be found again after the
program restarts and puts its objects elsewhere. Find the address first, e.g. with 'memhunter value':
  memhunter pointers game.exe --to 0x1F4A2C3B0D8 --save hp.mhp
  (restart the game and find the new address of the value)
  memhunter pointers hp.mhp --to 0x2A61F0E1A48    FILE is replaced with the chains that lead there
  memhunter pointers hp.mhp --eq 100              or keep the chains whose value is 100 now
  memhunter pointers hp.mhp                       shows the chains and where they lead now
The chain [[game.exe+0x1A2B0]+0x10]+0x8 reads the pointer at game.exe+0x1A2B0, adds 0x10, reads the
pointer there and adds 0x8. Keep checking until a few chains are left.

Search:
      --to ADDR             the address to find chains to (decimal or 0x-hex)
      --depth N             at most N pointers in a chain, 1 to 7 (default 5)
      --max-offset N        the largest offset added to a pointer (default 0x1000)
      --max-chains N        keep at most N chains, the shortest first (default 1000000)
      --as TYPE             the type of the value: int8, int16, int32 (default), int64, float or double;
                            it shows the values and is what a check by value compares
      --save FILE           save the chains for checks after a restart (written as FILE.partial, then renamed)
Pointers are read from writable memory of every type, and chains start in a module image. The region
filters of 'memhunter scan' change the memory: --protection, --type, --min-region-size, --max-region-size,
--include, --exclude. A larger depth or offset finds more chains, but needs more time and memory.

Check (the process defaults to the one FILE was saved from, found by its name):
      --to ADDR             keep the chains that lead to ADDR now
      --eq N, --gt N, --lt N, --between A:B
                            keep the chains whose value passes the condition (numbers only)
      --save NEW            write the chains that are left to NEW and keep FILE as it is
FILE is replaced only when chains are left.

Output:
  -f, --format FMT          text (default), json or csv
  -o, --output FILE         write the chains to FILE instead of standard output
      --limit N             at most N chains (default 20, 0 = all)
  -j, --threads N           threads (default: number of logical CPUs)
      --no-progress         do not draw the progress line on stderr
  -q, --quiet               do not print the summary on stderr
ADDRESS is where a chain leads now and VALUE what is there; ?? when a pointer on the way cannot be read.
MemHunter only reads memory: it does not write values or freeze them.

Exit codes: 0 chains found or left, 1 none (FILE is not changed), 2 invalid arguments, 3 process not found
or access denied, 4 file error, 5 interrupted, target exited or the search outgrew its memory budget (a
third of the free RAM; nothing is saved), 6 FILE damaged or saved from a process of the other bitness.
)";

constexpr std::string_view kStructHelp = R"(Usage: memhunter struct <pid|name> BASE [options]

Shows the structure that starts at BASE field by field: offset, type, name and value, like the structure
page of memhunter_gui. BASE is an address or a chain of pointers to the structure (numbers are hex):
  memhunter struct game.exe 0x1F4A2C3B0D8
  memhunter struct game.exe "[[game.exe+0x52080]+0x8]" --def player.mhst
A chain is followed anew on every run, so it finds the structure again after the program restarts. Types
are guessed from the bytes: pointers into readable memory, ASCII and UTF-16 text, runs of zeros (one row
each), doubles, floats and int32; int64 is never guessed.

      --size N              bytes to show, 1 to 0x10000 (default 0x200)
      --def FILE            fields from a definition file, one per line: "0x50 int32 health" (the GUI
                            saves them); the fields between them are guessed
  -f, --format FMT          text (default), json or csv
  -o, --output FILE         write the fields to FILE instead of standard output
  -q, --quiet               do not print the summary on stderr
Types: int8, int16, int32, int64, float, double, pointer, ascii[N], utf16[N], bytes[N]. A pointer shows
module+offset when it points into a module. ?? marks bytes that cannot be read.
MemHunter only reads memory: it does not write values or freeze them.

Exit codes: 0 shown, 1 the chain leads nowhere or nothing can be read there, 2 invalid arguments,
3 process not found or access denied, 4 file error, 6 damaged definition file.
)";

constexpr std::string_view kInspectHelp = R"(Usage: memhunter inspect <pid|name> [options]
       memhunter inspect --all [options]

Looks for signs of code that was injected into a process or of modules that were changed after loading,
like pe-sieve and Moneta. Only reads memory. Kinds of findings:
  exec-private   executable memory that belongs to no module: private memory or a mapping without a
                 file. Programs with a JIT compiler (browsers, .NET, Java, LuaJIT) have such memory too
  pe-header      a PE header (MZ...PE) at the start of memory that is not a loaded module: a module that
                 was copied in by hand instead of being loaded by Windows
  rwx            memory that is writable and executable at once, also inside modules
  patched        code of a module that differs from its file on disk once relocations are applied, such
                 as hooks; antivirus programs and overlays hook functions too. Import tables are left out,
                 and pages the process still shares with the file are unchanged and skipped
  hollowed       a module whose file is missing or does not match it, or a main image that is not the
                 file the process was started from (process hollowing)

      --all                 check every process MemHunter can open; the others are listed as skipped
      --kind LIST           only these kinds, comma-separated (default: all)
  -f, --format FMT          text (default), json or csv
  -o, --output FILE         write the findings to FILE instead of standard output
  -q, --quiet               do not print the summary on stderr
      --debug-privilege     enable SeDebugPrivilege to open the processes of other users and of services;
                            needs MemHunter to run as administrator. Protected processes (PPL) stay closed

Exit codes: 0 findings, 1 none, 2 invalid arguments, 3 process not found or access denied (or
--debug-privilege without administrator rights), 4 file error, 5 interrupted; the findings are partial.
)";

template <typename Writer>
void emit(const std::string& path, Writer&& writer) {
    if (path.empty()) {
        writer(std::cout);
        std::cout.flush();
        if (!std::cout) {
            throw Error(ErrorCode::Io, "cannot write to standard output");
        }
        return;
    }
    std::ofstream file(std::filesystem::path(utf8_to_wide(path)), std::ios::binary | std::ios::trunc);
    if (!file) {
        throw Error(ErrorCode::Io, "cannot create '" + path + "'");
    }
    writer(file);
    file.close();
    if (!file) {
        throw Error(ErrorCode::Io, "cannot write '" + path + "' (disk full?)");
    }
}

ProcessSummary summarize(const Process& process) {
    ProcessSummary summary;
    summary.pid = process.pid();
    summary.name = process.image_name();
    summary.path = process.image_path();
    summary.creation_time = process.creation_time();
    summary.wow64 = process.is_wow64();
    return summary;
}

std::vector<std::uint32_t> resolve_pattern_filters(std::span<const PatternInfo> patterns, std::span<const std::string> filters) {
    std::vector<std::uint32_t> ids;
    for (const auto& filter : filters) {
        if (filter.starts_with('#')) {
            const auto id = parse_uint(std::string_view(filter).substr(1));
            if (!id || *id >= patterns.size()) {
                throw Error(ErrorCode::InvalidArgument, "--filter-pattern " + filter + ": there are only " +
                                                            std::to_string(patterns.size()) + " patterns (#0 to #" +
                                                            std::to_string(patterns.size() - 1) + ")");
            }
            ids.push_back(static_cast<std::uint32_t>(*id));
            continue;
        }
        const std::size_t before = ids.size();
        for (std::uint32_t i = 0; i < patterns.size(); ++i) {
            if (patterns[i].label == filter) {
                ids.push_back(i);
            }
        }
        if (ids.size() == before) {
            throw Error(ErrorCode::InvalidArgument, "--filter-pattern '" + filter + "' does not name any pattern of this scan");
        }
    }
    return ids;
}

void print_status(const ResultSet& results) {
    switch (results.stats.status) {
        case ScanStatus::Completed: break;
        case ScanStatus::Cancelled: std::cerr << "Scan interrupted; the results below are partial.\n"; break;
        case ScanStatus::TargetExited: std::cerr << "The target process exited during the scan; the results are partial.\n"; break;
    }
}

std::string format_seconds(double seconds) {
    std::array<char, 32> buffer{};
    std::snprintf(buffer.data(), buffer.size(), "%.3f s", seconds);
    return buffer.data();
}

std::string describe_run(const ProcessSummary& process) {
    return "pid " + std::to_string(process.pid) + " " + process.name + " started " + format_filetime(process.creation_time);
}

std::string cross_run_message(const ProcessSummary& a, const ProcessSummary& b) {
    return "the snapshots come from different process runs (" + describe_run(a) + "; " + describe_run(b) +
           "); Windows reuses and randomizes virtual addresses between runs, so equal addresses may hold unrelated data";
}

void print_snapshot_status(ScanStatus status) {
    if (status == ScanStatus::Cancelled) {
        std::cerr << "Snapshot interrupted; nothing was written.\n";
    } else if (status == ScanStatus::TargetExited) {
        std::cerr << "The target process exited during the snapshot; nothing was written.\n";
    }
}

CaptureResult capture_with_progress(const MemorySource& memory, const ScanPlan& plan, const CaptureOptions& options,
                                    SnapshotDataSink* sink, bool progress_enabled, std::stop_source& stop) {
    ScanProgress progress;
    const InterruptScope interrupt(stop);
    ProgressLine line(progress, progress_enabled, "");
    CaptureResult result = capture_snapshot(memory, plan, options, sink, progress, stop.get_token());
    line.finish();
    return result;
}

struct IncrementalSummary {
    std::uint64_t selected = 0;
    std::uint64_t changed = 0;
    std::size_t ranges = 0;
    double seconds = 0;
};

// Narrows the request to memory that changed since the baseline snapshot; nullopt when hashing was interrupted.
std::optional<IncrementalSummary> restrict_to_changes(const ProcessMemory& memory, const ProcessSummary& target, const ScanPlan& plan,
                                                      ScanOptions& options, bool progress_enabled, std::stop_source& stop) {
    const SnapshotFile baseline(options.changed_since);
    if (!same_process_instance(baseline.snapshot().process, target)) {
        throw Error(ErrorCode::IncompatibleSnapshot, "snapshot '" + baseline.name() + "' was captured from another process run (" +
                                                         describe_run(baseline.snapshot().process) + "; the target is " +
                                                         describe_run(target) + "), and addresses cannot be compared across runs");
    }
    CaptureOptions capture;
    capture.block_size = baseline.snapshot().block_size;
    capture.threads = options.request.engine.scan_threads;
    const CaptureResult current = capture_with_progress(memory, plan, capture, nullptr, progress_enabled, stop);
    if (current.status != ScanStatus::Completed) {
        return std::nullopt;
    }
    const SnapshotDiff diff = diff_snapshots(baseline.snapshot(), current.snapshot);
    auto changed = ranges_to_rescan(diff);
    IncrementalSummary summary;
    summary.selected = current.snapshot.captured_bytes();
    summary.ranges = changed.size();
    for (const auto& range : changed) {
        summary.changed += range.end - range.begin;
    }
    summary.seconds = current.seconds;
    options.request.changed = std::move(changed);
    return summary;
}

int scan_command(std::vector<std::string> args, const ConsoleSession& console) {
    ScanOptions options = parse_scan_options(std::move(args));
    OutputOptions& output = options.output;
    output.query.patterns = resolve_pattern_filters(describe_patterns(options.request), output.pattern_filters);

    const Process process = Process::open(resolve_process(options.target));
    const ProcessMemory memory(process);
    const bool progress_enabled = output.progress && console.stderr_is_console();

    ScanProgress progress;
    std::stop_source stop;
    ScanPlan plan = plan_scan(memory, options.request.filter);
    std::optional<IncrementalSummary> incremental;
    if (!options.changed_since.empty()) {
        incremental = restrict_to_changes(memory, summarize(process), plan, options, progress_enabled, stop);
        if (!incremental) {
            std::cerr << "Scan interrupted while hashing memory; no results.\n";
            return kExitIncomplete;
        }
    }
    ResultSet results;
    {
        const InterruptScope interrupt(stop);
        ProgressLine line(progress, progress_enabled);
        results = run_scan(memory, options.request, std::move(plan), progress, stop.get_token());
        line.finish();
    }
    results.process = summarize(process);

    if (output.format == OutputFormat::Text && output.path.empty() && console.stdout_is_console() && !output.limit_given) {
        output.query.limit = kConsoleRowLimit;
    }
    const auto rows = run_query(results, output.query);
    emit(output.path, [&](std::ostream& out) { write_results(out, output.format, results, rows, output.export_options); });

    if (!output.quiet) {
        if (results.stats.regions_selected == 0) {
            std::cerr << "No memory regions matched the region filters.\n";
        }
        if (incremental) {
            std::cerr << "Changed since " << options.changed_since << ": " << format_size(incremental->changed) << " of "
                      << format_size(incremental->selected) << " in " << incremental->ranges << " ranges (hashed in "
                      << format_seconds(incremental->seconds) << "); only matches overlapping them are reported\n";
        }
        write_summary(std::cerr, results, rows.size());
        if (!output.path.empty()) {
            std::cerr << "Wrote " << rows.size() << " matches to " << output.path << '\n';
        } else if (rows.size() < results.matches.size() && output.query.limit != 0 && !output.limit_given) {
            std::cerr << "Showing the first " << rows.size() << " rows; use --limit 0 or --output FILE for all.\n";
        }
    }
    print_status(results);
    if (results.stats.status != ScanStatus::Completed) {
        return kExitIncomplete;
    }
    return rows.empty() ? kExitNoMatches : kExitSuccess;
}

bool intersects_any(const Region& region, std::span<const AddressRange> ranges) {
    return std::any_of(ranges.begin(), ranges.end(), [&](const AddressRange& r) { return r.begin < region.end() && region.base < r.end; });
}

int regions_command(std::vector<std::string> args) {
    const RegionsOptions options = parse_regions_options(std::move(args));
    const Process process = Process::open(resolve_process(options.target));
    const ProcessMemory memory(process);

    std::vector<Region> regions = memory.query_regions();
    const RegionFilter& filter = options.filter;
    std::erase_if(regions, [&](const Region& region) {
        if (!(options.all ? filter.accepts_any_protection(region) : filter.accepts(region))) {
            return true;
        }
        if (!filter.include_ranges.empty() && !intersects_any(region, filter.include_ranges)) {
            return true;
        }
        return std::any_of(filter.exclude_ranges.begin(), filter.exclude_ranges.end(),
                           [&](const AddressRange& r) { return r.begin <= region.base && region.end() <= r.end; });
    });
    const ProcessSummary summary = summarize(process);
    emit(options.path, [&](std::ostream& out) { write_regions(out, options.format, summary, regions); });
    return kExitSuccess;
}

int ps_command(std::vector<std::string> args) {
    const PsOptions options = parse_ps_options(std::move(args));
    std::vector<ProcessEntry> processes = list_processes();
    if (!options.filter.empty()) {
        const bool glob = options.filter.find_first_of("*?") != std::string::npos;
        const std::string pattern = glob ? options.filter : "*" + options.filter + "*";
        std::erase_if(processes, [&](const ProcessEntry& p) { return !glob_match_ci(pattern, p.name); });
    }
    std::sort(processes.begin(), processes.end(), [](const ProcessEntry& a, const ProcessEntry& b) { return a.pid < b.pid; });
    emit("", [&](std::ostream& out) { write_processes(out, options.format, processes); });
    return processes.empty() ? kExitNoMatches : kExitSuccess;
}

int snapshot_command(std::vector<std::string> args, const ConsoleSession& console) {
    const SnapshotOptions options = parse_snapshot_options(std::move(args));
    const Process process = Process::open(resolve_process(options.target));
    const ProcessMemory memory(process);
    validate_block_size(options.capture.block_size, memory.page_size());

    const ScanPlan plan = plan_scan(memory, options.filter);
    std::uint64_t selected = 0;
    for (const auto& span : plan.spans) {
        selected += span.end - span.begin;
    }
    if (options.with_data && selected > options.max_data) {
        throw Error(ErrorCode::InvalidArgument, "the selected memory is " + format_size(selected) + ", more than --max-data " +
                                                    format_size(options.max_data) + "; narrow it with region filters or raise --max-data");
    }
    const std::uint64_t needed = estimate_snapshot_size(plan, options.capture.block_size, options.with_data);
    const std::uint64_t available = free_disk_space(options.path);
    if (needed > available) {
        throw Error(ErrorCode::Io, "not enough disk space for '" + options.path + "': about " + format_size(needed) + " needed, " +
                                       format_size(available) + " free");
    }
    if (!options.quiet) {
        if (options.with_data) {
            std::cerr << "Saving memory contents: about " << format_size(needed) << " will be written to " << options.path
                      << ". The file holds raw process memory, which may include passwords or keys.\n";
        }
        if (plan.regions_selected == 0) {
            std::cerr << "No memory regions matched the region filters; only the region table is recorded.\n";
        }
    }

    SnapshotWriter writer(options.path, options.with_data);
    std::stop_source stop;
    CaptureResult capture = capture_with_progress(memory, plan, options.capture, options.with_data ? &writer : nullptr,
                                                  options.progress && console.stderr_is_console(), stop);
    if (capture.status != ScanStatus::Completed) {
        print_snapshot_status(capture.status);
        return kExitIncomplete;
    }
    Snapshot& snapshot = capture.snapshot;
    snapshot.process = summarize(process);
    const std::uint64_t size = writer.commit(snapshot);
    if (!options.quiet) {
        std::cerr << "Snapshot of pid " << snapshot.process.pid << ' ' << snapshot.process.name << ": " << format_size(snapshot.captured_bytes())
                  << " in " << snapshot.spans.size() << " ranges (" << format_size(capture.bytes_unreadable) << " unreadable), "
                  << snapshot.block_count() << " blocks of " << format_size(snapshot.block_size) << ", "
                  << (snapshot.has_data ? "hashes and memory contents" : "hashes only") << ", " << format_seconds(capture.seconds) << '\n';
        std::cerr << "Wrote " << options.path << " (" << format_size(size) << ")\n";
    }
    return kExitSuccess;
}

bool is_file(const std::string& path) {
    std::error_code ec;
    return std::filesystem::is_regular_file(std::filesystem::path(utf8_to_wide(path)), ec);
}

int diff_command(std::vector<std::string> args, const ConsoleSession& console) {
    const DiffOptions options = parse_diff_options(std::move(args));
    const auto& operands = options.operands;
    const bool files_only = operands.size() == 2 && is_file(operands[0]);

    SnapshotFile before(files_only ? operands[0] : operands[1]);
    std::optional<SnapshotFile> after_file;
    if (files_only) {
        after_file.emplace(operands[1]);
    } else if (operands.size() == 3) {
        after_file.emplace(operands[2]);
    }

    std::vector<std::string> warnings;
    const auto check_run = [&](const ProcessSummary& a, const ProcessSummary& b) {
        if (same_process_instance(a, b)) {
            return;
        }
        if (!options.force) {
            throw Error(ErrorCode::IncompatibleSnapshot, cross_run_message(a, b) + "; pass --force to compare anyway");
        }
        warnings.push_back(cross_run_message(a, b));
    };

    std::optional<Process> process;
    std::optional<ProcessMemory> memory;
    std::optional<Snapshot> live;
    if (files_only) {
        check_run(before.snapshot().process, after_file->snapshot().process);
    } else {
        process.emplace(Process::open(resolve_process(operands[0])));
        memory.emplace(*process);
        const ProcessSummary current = summarize(*process);
        check_run(before.snapshot().process, current);
        if (after_file) {
            check_run(after_file->snapshot().process, current);
        } else {
            RegionFilter filter;
            for (const auto& span : before.snapshot().spans) {
                filter.include_ranges.push_back({span.begin, span.end});
            }
            ScanPlan plan = plan_scan(*memory, filter);
            if (before.snapshot().spans.empty()) {
                plan.spans.clear();
            }
            CaptureOptions capture;
            capture.block_size = before.snapshot().block_size;
            capture.threads = options.threads;
            std::stop_source stop;
            CaptureResult result = capture_with_progress(*memory, plan, capture, nullptr, options.progress && console.stderr_is_console(), stop);
            if (result.status != ScanStatus::Completed) {
                std::cerr << (result.status == ScanStatus::Cancelled ? "Comparison interrupted.\n"
                                                                     : "The target process exited during the comparison.\n");
                return kExitIncomplete;
            }
            live = std::move(result.snapshot);
            live->process = current;
        }
    }
    const Snapshot& after = live ? *live : after_file->snapshot();
    if (before.snapshot().captured_at > after.captured_at) {
        warnings.push_back("BEFORE was captured after AFTER; changes are reported from BEFORE to AFTER");
    }

    BlockReader before_reader;
    BlockReader after_reader;
    if (before.snapshot().has_data) {
        before_reader = [&](std::size_t span, std::uint64_t block, std::span<std::byte> out) { return before.read_block(span, block, out); };
        if (after_file && after_file->snapshot().has_data) {
            after_reader = [&](std::size_t span, std::uint64_t block, std::span<std::byte> out) {
                return after_file->read_block(span, block, out);
            };
        } else if (live) {
            after_reader = [&](std::size_t span, std::uint64_t block, std::span<std::byte> out) {
                const AddressRange range = live->block_range(span, block);
                const std::size_t size = range.end - range.begin;
                return memory->read(range.begin, out.first(size)).bytes == size;
            };
        }
    }
    const SnapshotDiff diff = diff_snapshots(before.snapshot(), after, before_reader, after_reader);

    DiffReport report;
    report.before = {before.name(), &before.snapshot(), false, before.file_size()};
    report.after = live ? SnapshotSide{"live memory", &*live, true, 0}
                        : SnapshotSide{after_file->name(), &after_file->snapshot(), false, after_file->file_size()};
    report.diff = &diff;
    report.warnings = warnings;
    report.show = options.show;
    report.limit = options.limit;
    const bool console_text = options.format == OutputFormat::Text && options.path.empty() && console.stdout_is_console();
    if (console_text && !options.limit_given) {
        report.limit = kConsoleRowLimit;
    }
    emit(options.path, [&](std::ostream& out) { write_diff(out, options.format, report); });

    if (!options.quiet) {
        if (!console_text) {
            for (const auto& warning : warnings) {
                std::cerr << "Warning: " << warning << '\n';
            }
            const auto kind = [&](RangeKind k) { return format_size(diff.bytes[static_cast<std::size_t>(k)]); };
            std::cerr << "Changed " << kind(RangeKind::Changed) << ", unchanged " << kind(RangeKind::Unchanged) << ", unknown "
                      << kind(RangeKind::Unknown) << ", added " << kind(RangeKind::Added) << ", removed " << kind(RangeKind::Removed)
                      << "; " << diff.regions.size() << " region changes\n";
        }
        if (!options.path.empty()) {
            std::cerr << "Wrote the comparison to " << options.path << '\n';
        }
        if (!options.limit_given && report.limit != 0) {
            report.limit = 0;
            const std::size_t all = diff_rows(report).size();
            if (all > kConsoleRowLimit) {
                std::cerr << "Showing the first " << kConsoleRowLimit << " of " << all << " ranges; use --limit 0 or --output FILE for all.\n";
            }
        }
    }
    const bool differs = diff.bytes[static_cast<std::size_t>(RangeKind::Changed)] + diff.bytes[static_cast<std::size_t>(RangeKind::Added)] +
                             diff.bytes[static_cast<std::size_t>(RangeKind::Removed)] != 0 || !diff.regions.empty();
    return differs ? kExitSuccess : kExitNoMatches;
}

bool ends_with_ci(std::string_view text, std::string_view suffix) {
    return text.size() >= suffix.size() &&
           std::equal(suffix.begin(), suffix.end(), text.end() - suffix.size(), [](char a, char b) {
               return std::tolower(static_cast<unsigned char>(a)) == std::tolower(static_cast<unsigned char>(b));
           });
}

// A process is given by its PID or its .exe name; a .mhv name or any other existing file is a value file.
bool is_value_file(const std::string& target) {
    if (ends_with_ci(target, ".mhv")) {
        return true;
    }
    return !ends_with_ci(target, ".exe") && !parse_uint(target) && is_file(target);
}

std::string count_text(std::uint64_t count) {
    return std::to_string(count) + (count == 1 ? " address" : " addresses");
}

std::string describe_condition(Compare compare, const std::string& low, const std::string& high) {
    switch (compare) {
        case Compare::Exact: return "= " + low;
        case Compare::Greater: return "> " + low;
        case Compare::Less: return "< " + low;
        case Compare::Between: return low + " to " + high;
        default: return std::string(to_string(compare));
    }
}

std::string describe_condition(const ValueOptions& options) {
    return describe_condition(*options.compare, options.operand, options.operand_high);
}

template <typename Scan>
ValueScanResult with_value_progress(bool progress_enabled, Scan&& scan) {
    ScanProgress progress;
    std::stop_source stop;
    const InterruptScope interrupt(stop);
    ProgressLine line(progress, progress_enabled, "addresses");
    ValueScanResult result = scan(progress, stop.get_token());
    line.finish();
    return result;
}

int report_unfinished(const ValueScanResult& result, std::uint64_t budget, const std::string& kept) {
    switch (result.status) {
        case ValueScanStatus::Completed: break;
        case ValueScanStatus::Cancelled: std::cerr << "Scan interrupted; " << kept << ".\n"; break;
        case ValueScanStatus::TargetExited: std::cerr << "The target process exited during the scan; " << kept << ".\n"; break;
        case ValueScanStatus::OverBudget:
            std::cerr << "The address list outgrew its memory budget of " << format_size(budget)
                      << " (a third of the free memory; about " << format_size(result.needed_bytes) << " needed); " << kept
                      << ". Narrow the search: give a value instead of --unknown, or select less memory with --type private, "
                         "--protection rw or --include.\n";
            break;
    }
    return kExitIncomplete;
}

ValueListing make_listing(ProcessSummary process, const ValueCandidates& candidates, std::string condition) {
    ValueListing listing;
    listing.process = std::move(process);
    listing.type = candidates.type;
    listing.scan = candidates.scans;
    listing.condition = std::move(condition);
    listing.count = candidates.count();
    return listing;
}

std::size_t row_limit(const ValueOptions& options) {
    return options.limit == 0 ? std::numeric_limits<std::size_t>::max() : options.limit;
}

// VALUE is what the last scan read; PREVIOUS comes from `before`, the list of the scan before it.
std::vector<ValueRow> value_rows(const ValueCandidates& candidates, std::size_t limit, const ValueCandidates* before) {
    std::vector<ValueRow> rows;
    for (const ValueCandidate& candidate : candidates.list(limit)) {
        ValueRow row;
        row.address = candidate.address;
        row.value = format_value(candidates.type, candidate.previous);
        if (before != nullptr) {
            if (const auto value = before->value_at(candidate.address)) {
                row.previous = format_value(candidates.type, *value);
            }
        }
        row.region = candidates.region_of(candidate.address);
        rows.push_back(std::move(row));
    }
    return rows;
}

void print_value_footer(const ValueListing& listing) {
    if (listing.rows.size() < listing.count) {
        std::cerr << "Showing the first " << listing.rows.size() << "; use --limit 0 for all.\n";
    }
}

// The file is written before the listing, so a failed save leaves no output that looks like a success.
int publish_values(const ValueOptions& options, const ValueListing& listing, const ValueCandidates& candidates,
                   const std::string& save, const std::string& summary) {
    const std::uint64_t saved = save.empty() ? 0 : write_value_file(save, listing.process, candidates);
    emit(options.path, [&](std::ostream& out) { write_values(out, options.format, listing); });
    if (!options.quiet) {
        std::cerr << summary << '\n';
        print_value_footer(listing);
        if (!save.empty()) {
            std::cerr << "Saved " << save << " (" << format_size(saved) << ")\n";
        }
    }
    return kExitSuccess;
}

int first_value_command(const ValueOptions& options, bool progress_enabled) {
    if (!options.compare) {
        throw Error(ErrorCode::InvalidArgument, "the first scan needs a condition: --eq N, --gt N, --lt N, --between A:B or --unknown");
    }
    if (needs_previous(*options.compare)) {
        throw Error(ErrorCode::InvalidArgument, "--" + std::string(to_string(*options.compare)) +
                                                    " compares with the scan before: save the first scan with --save FILE and "
                                                    "pass FILE instead of the process");
    }
    const ValueType type = options.type.value_or(ValueType::Int32);
    const ValueCondition condition = parse_value_condition(*options.compare, type, options.operand, options.operand_high);

    const Process process = Process::open(resolve_process(options.target));
    const ProcessMemory memory(process);
    const ScanPlan plan = plan_scan(memory, options.filter);
    ValueScanOptions scan;
    scan.threads = options.threads;
    scan.memory_budget = value_memory_budget();
    ValueScanResult result = with_value_progress(progress_enabled, [&](ScanProgress& progress, std::stop_token stop) {
        return first_value_scan(memory, plan, type, !options.unaligned, condition, scan, progress, stop);
    });
    if (result.status != ValueScanStatus::Completed) {
        return report_unfinished(result, scan.memory_budget, "nothing was saved");
    }

    const ValueCandidates& found = result.candidates;
    ValueListing listing = make_listing(summarize(process), found, describe_condition(options));
    listing.rows = value_rows(found, row_limit(options), nullptr);
    const std::string prefix = "scan 1 (" + std::string(to_string(type)) + ", " + listing.condition + "): ";
    if (listing.count == 0) {
        emit(options.path, [&](std::ostream& out) { write_values(out, options.format, listing); });
        if (!options.quiet) {
            std::cerr << prefix << "no address matches" << (options.save.empty() ? "" : "; nothing was saved") << '\n';
        }
        return kExitNoMatches;
    }
    const int code = publish_values(options, listing, found, options.save,
                                    prefix + count_text(listing.count) + ", " + format_size(result.bytes_read) + " read in " +
                                        format_seconds(result.seconds));
    if (!options.quiet && options.save.empty()) {
        std::cerr << "Add --save FILE to narrow these addresses down with the next scans.\n";
    }
    return code;
}

Process open_saved_run(const ProcessSummary& saved, const std::string& name) {
    std::optional<Process> process;
    try {
        process.emplace(Process::open(saved.pid));
    } catch (const Error& error) {
        if (error.code() != ErrorCode::ProcessNotFound && error.code() != ErrorCode::ProcessExited) {
            throw;
        }
        throw Error(ErrorCode::ProcessNotFound,
                    "the process of '" + name + "' (" + describe_run(saved) + ") is not running; start a new search");
    }
    const ProcessSummary current = summarize(*process);
    if (!same_process_instance(saved, current)) {
        throw Error(ErrorCode::IncompatibleSnapshot, "'" + name + "' belongs to another run of the process (" + describe_run(saved) +
                                                         "; now " + describe_run(current) +
                                                         "): addresses cannot be compared across runs; start a new search");
    }
    return std::move(*process);
}

int show_saved_values(const ValueOptions& options, const ValueFile& file, const Process& process, const ProcessMemory& memory) {
    const ValueCandidates& saved = file.candidates;
    const std::size_t size = size_of(saved.type);
    ValueListing listing = make_listing(summarize(process), saved, "");
    listing.has_previous = true;
    for (const ValueCandidate& candidate : saved.list(row_limit(options))) {
        ValueRow row;
        row.address = candidate.address;
        std::array<std::byte, 8> buffer{};
        if (memory.read(candidate.address, std::span(buffer).first(size)).bytes == size) {
            std::uint64_t bits = 0;
            std::memcpy(&bits, buffer.data(), size);
            row.value = format_value(saved.type, bits);
        } else {
            row.value = "??";
        }
        row.previous = format_value(saved.type, candidate.previous);
        row.region = saved.region_of(candidate.address);
        listing.rows.push_back(std::move(row));
    }
    emit(options.path, [&](std::ostream& out) { write_values(out, options.format, listing); });
    if (!options.quiet) {
        std::cerr << "'" << options.target << "': " << count_text(listing.count) << " after scan " << saved.scans << " ("
                  << to_string(saved.type) << "), " << describe_run(file.process) << "; VALUE is read now\n";
        print_value_footer(listing);
    }
    return listing.count == 0 ? kExitNoMatches : kExitSuccess;
}

int next_value_command(const ValueOptions& options, bool progress_enabled) {
    const std::string& name = options.target;
    if (options.type || options.unaligned || options.filter_given) {
        throw Error(ErrorCode::InvalidArgument, "--as, --unaligned and the region filters apply to the first scan; '" + name +
                                                    "' keeps the type and the addresses it was started with");
    }
    if (options.compare == Compare::Unknown) {
        throw Error(ErrorCode::InvalidArgument, "--unknown starts a new search: give the process instead of '" + name + "'");
    }
    ValueFile file = read_value_file(name);
    const ValueType type = file.candidates.type;
    std::optional<ValueCondition> condition;
    if (options.compare) {
        condition = parse_value_condition(*options.compare, type, options.operand, options.operand_high);
    }
    const Process process = open_saved_run(file.process, name);
    const ProcessMemory memory(process);
    if (!condition) {
        return show_saved_values(options, file, process, memory);
    }

    ValueScanOptions scan;
    scan.threads = options.threads;
    scan.memory_budget = value_memory_budget();
    ValueScanResult result = with_value_progress(progress_enabled, [&](ScanProgress& progress, std::stop_token stop) {
        return next_value_scan(memory, file.candidates, *condition, scan, progress, stop);
    });
    const std::string unchanged = "'" + name + "' was not changed";
    if (result.status != ValueScanStatus::Completed) {
        return report_unfinished(result, scan.memory_budget, unchanged);
    }

    const ValueCandidates& found = result.candidates;
    const std::uint64_t before = file.candidates.count();
    ValueListing listing = make_listing(summarize(process), found, describe_condition(options));
    listing.has_previous = true;
    listing.rows = value_rows(found, row_limit(options), &file.candidates);
    file.candidates = {};
    const std::string prefix = "scan " + std::to_string(found.scans) + " (" + std::string(to_string(type)) + ", " + listing.condition + "): ";
    if (listing.count == 0) {
        emit(options.path, [&](std::ostream& out) { write_values(out, options.format, listing); });
        if (!options.quiet) {
            std::cerr << prefix << "none of the " << count_text(before) << " matches; "
                      << (options.save.empty() ? unchanged : "nothing was saved") << '\n';
        }
        return kExitNoMatches;
    }
    return publish_values(options, listing, found, options.save.empty() ? name : options.save,
                          prefix + std::to_string(listing.count) + " of " + count_text(before) + " left, " +
                              format_seconds(result.seconds));
}

int value_command(std::vector<std::string> args, const ConsoleSession& console) {
    const ValueOptions options = parse_value_options(std::move(args));
    const bool progress_enabled = options.progress && console.stderr_is_console();
    return is_value_file(options.target) ? next_value_command(options, progress_enabled) : first_value_command(options, progress_enabled);
}

// A .mhp name or any other existing file that is not a process is a pointer file.
bool is_pointer_file(const std::string& target) {
    if (ends_with_ci(target, ".mhp")) {
        return true;
    }
    return !ends_with_ci(target, ".exe") && !parse_uint(target) && is_file(target);
}

// Pointer files number the target types as the address list of the GUI does: the value types, then text and bytes.
constexpr std::uint8_t kAsciiTarget = 6;
constexpr std::uint8_t kUtf16Target = 7;
constexpr std::uint32_t kMaxShownBytes = 256;

std::optional<ValueType> number_type(std::uint8_t type) {
    return type < kAsciiTarget ? std::optional(static_cast<ValueType>(type)) : std::nullopt;
}

std::string target_type_name(std::uint8_t type) {
    if (const auto number = number_type(type)) {
        return std::string(to_string(*number));
    }
    return type == kAsciiTarget ? "ascii" : type == kUtf16Target ? "utf16" : "bytes";
}

std::optional<std::string> read_target(const MemorySource& memory, std::uint64_t address, const PointerFile& file) {
    const auto number = number_type(file.target_type);
    const std::size_t size = number ? size_of(*number) : std::clamp<std::uint32_t>(file.target_length, 1, kMaxShownBytes);
    std::vector<std::byte> bytes(size);
    if (memory.read(address, bytes).bytes != size) {
        return std::nullopt;
    }
    if (number) {
        std::uint64_t bits = 0;
        std::memcpy(&bits, bytes.data(), size);
        return format_value(*number, bits);
    }
    switch (file.target_type) {
        case kAsciiTarget: return ascii_preview(bytes);
        case kUtf16Target: return utf16_preview(bytes);
        default: return hex_preview(bytes);
    }
}

std::string count_chains(std::uint64_t count) {
    return std::to_string(count) + (count == 1 ? " chain" : " chains");
}

PointerListing pointer_listing(const PointerFile& file, ProcessSummary process) {
    PointerListing listing;
    listing.process = std::move(process);
    listing.target = file.target;
    listing.type = target_type_name(file.target_type);
    listing.depth = file.depth;
    listing.max_offset = file.max_offset;
    listing.checks = file.checks;
    listing.count = file.chains.chains.size();
    return listing;
}

// The first `limit` chains (0 = all) with where they lead now.
void add_pointer_rows(PointerListing& listing, const MemorySource& memory, const PointerFile& file, std::size_t limit) {
    const std::vector<Region> regions = memory.query_regions();
    const std::vector<std::uint64_t> bases = module_bases(ModuleMap(regions), file.chains.modules);
    const std::size_t count = file.chains.chains.size();
    const std::size_t shown = limit == 0 ? count : std::min(count, limit);
    for (std::size_t i = 0; i < shown; ++i) {
        PointerRow row;
        row.path = path_of(file.chains, i);
        row.address = resolve_chain(memory, bases, file.chains.chains[i], file.chains.pointer_size);
        if (row.address) {
            row.value = read_target(memory, *row.address, file);
        }
        listing.rows.push_back(std::move(row));
    }
}

void print_pointer_footer(const PointerListing& listing) {
    if (listing.rows.size() < listing.count) {
        std::cerr << "Showing the first " << listing.rows.size() << "; use --limit 0 for all.\n";
    }
}

// The file is written before the listing, so a failed save leaves no output that looks like a success.
int publish_pointers(const PointerOptions& options, const PointerListing& listing, const PointerFile& file, const std::string& save,
                     const std::string& summary) {
    const std::uint64_t saved = save.empty() ? 0 : write_pointer_file(save, file);
    emit(options.path, [&](std::ostream& out) { write_pointers(out, options.format, listing); });
    if (!options.quiet) {
        std::cerr << summary << '\n';
        print_pointer_footer(listing);
        if (!save.empty()) {
            std::cerr << "Saved " << save << " (" << format_size(saved) << ")\n";
        }
    }
    return kExitSuccess;
}

// kExitSuccess for a run that finished.
int report_pointer_status(PointerScanStatus status, const std::string& kept, std::uint64_t budget, std::uint64_t needed) {
    switch (status) {
        case PointerScanStatus::Completed: return kExitSuccess;
        case PointerScanStatus::Cancelled: std::cerr << "Interrupted; " << kept << ".\n"; break;
        case PointerScanStatus::TargetExited: std::cerr << "The target process exited; " << kept << ".\n"; break;
        case PointerScanStatus::OverBudget:
            std::cerr << "The search outgrew its memory budget of " << format_size(budget) << " (a third of the free memory; about "
                      << format_size(needed) << " needed); " << kept
                      << ". Lower --depth or --max-offset, or select less memory with --include or --exclude.\n";
            break;
    }
    return kExitIncomplete;
}

std::string percent_of(std::uint64_t done, std::uint64_t total) {
    std::array<char, 16> text{};
    std::snprintf(text.data(), text.size(), "%.1f%%", total == 0 ? 0.0 : 100.0 * static_cast<double>(done) / static_cast<double>(total));
    return text.data();
}

std::string pointer_progress_text(const PointerScanProgress& progress, unsigned depth) {
    const auto load = [](const std::atomic<std::uint64_t>& value) { return value.load(std::memory_order_relaxed); };
    switch (progress.stage.load(std::memory_order_relaxed)) {
        case PointerStage::Reading:
            return "reading memory " + percent_of(load(progress.reading.bytes_done), load(progress.reading.bytes_total)) + "  " +
                   format_size(load(progress.reading.bytes_done)) + " / " + format_size(load(progress.reading.bytes_total)) +
                   "  pointers " + std::to_string(load(progress.pointers));
        case PointerStage::Sorting: return "sorting " + std::to_string(load(progress.pointers)) + " pointers";
        case PointerStage::Searching:
            return "level " + std::to_string(progress.level.load(std::memory_order_relaxed)) + " of " + std::to_string(depth) +
                   "  addresses in chains " + std::to_string(load(progress.nodes));
        case PointerStage::Listing: return "listing the chains";
    }
    return {};
}

int search_pointers_command(const PointerOptions& options, bool progress_enabled) {
    if (!options.process.empty()) {
        throw Error(ErrorCode::InvalidArgument, "unexpected argument '" + options.process + "'");
    }
    if (options.compare) {
        throw Error(ErrorCode::InvalidArgument, "a condition checks saved chains: search with --to ADDR --save FILE, then pass FILE "
                                                "instead of the process");
    }
    if (!options.to) {
        throw Error(ErrorCode::InvalidArgument,
                    "give the address to find chains to: --to ADDR (find it first, e.g. with 'memhunter value')");
    }
    const Process process = Process::open(resolve_process(options.target));
    const ProcessMemory memory(process);
    PointerScanOptions search = options.search;
    search.memory_budget = pointer_memory_budget();
    const ScanPlan plan = plan_scan(memory, options.filter);
    PointerScanResult result;
    {
        PointerScanProgress progress;
        std::stop_source stop;
        const InterruptScope interrupt(stop);
        ProgressLine line([&](double) { return pointer_progress_text(progress, search.depth); }, progress_enabled);
        result = find_pointer_chains(memory, plan, *options.to, process.is_wow64() ? 4 : 8, search, progress, stop.get_token());
        line.finish();
    }
    if (const int code = report_pointer_status(result.status, "nothing was saved", search.memory_budget, result.needed_bytes);
        code != kExitSuccess) {
        return code;
    }

    const bool truncated = result.truncated();
    PointerFile file;
    file.process = summarize(process);
    file.target = *options.to;
    file.target_type = static_cast<std::uint8_t>(options.type.value_or(ValueType::Int32));
    file.depth = search.depth;
    file.max_offset = search.max_offset;
    file.chains = std::move(result.chains);
    PointerListing listing = pointer_listing(file, file.process);
    add_pointer_rows(listing, memory, file, options.limit);
    const std::string goal = format_address(file.target);
    const std::string settings = "depth " + std::to_string(search.depth) + ", offsets up to " + format_hex(search.max_offset);
    const std::string work = format_size(result.bytes_read) + " read in " + format_seconds(result.seconds);
    if (file.chains.chains.empty()) {
        emit(options.path, [&](std::ostream& out) { write_pointers(out, options.format, listing); });
        if (!options.quiet) {
            std::cerr << "No chain leads to " << goal << " (" << settings << "; " << work << ")"
                      << (options.save.empty() ? "" : "; nothing was saved") << ". Try a larger --depth or --max-offset.\n";
        }
        return kExitNoMatches;
    }
    std::string summary = count_chains(result.total_chains) + " to " + goal + " (" + settings + "): " + std::to_string(result.pointers) +
                          " pointers in " + work;
    if (truncated) {
        summary += "; the list keeps the shortest " + std::to_string(file.chains.chains.size());
    }
    const int code = publish_pointers(options, listing, file, options.save, summary);
    if (!options.quiet && options.save.empty()) {
        std::cerr << "Add --save FILE.mhp to check the chains after the program restarts.\n";
    }
    return code;
}

std::string checks_text(std::uint32_t checks) {
    return checks == 0 ? "not checked yet" : "checked " + std::to_string(checks) + (checks == 1 ? " time" : " times");
}

int check_pointers_command(const PointerOptions& options, bool progress_enabled) {
    const std::string& name = options.target;
    if (options.search_given || options.filter_given || options.type) {
        throw Error(ErrorCode::InvalidArgument, "--depth, --max-offset, --max-chains, --as and the region filters apply to a search; '" +
                                                    name + "' keeps the chains it was saved with");
    }
    if (options.to && options.compare) {
        throw Error(ErrorCode::InvalidArgument, "check by --to ADDR or by a value condition, not both");
    }
    PointerFile file = read_pointer_file(name);
    PointerCheck check;
    check.address = options.to;
    if (options.compare) {
        const auto type = number_type(file.target_type);
        if (!type) {
            throw Error(ErrorCode::InvalidArgument, "the chains of '" + name + "' lead to " + target_type_name(file.target_type) +
                                                        "; only numbers are checked by value, so check with --to ADDR");
        }
        check.type = *type;
        check.condition = parse_value_condition(*options.compare, *type, options.operand, options.operand_high);
    }
    const Process process = Process::open(resolve_process(options.process.empty() ? file.process.name : options.process));
    const ProcessSummary current = summarize(process);
    const unsigned pointer_size = current.wow64 ? 4 : 8;
    if (file.chains.pointer_size != pointer_size) {
        const auto bits = [](unsigned size) { return std::to_string(size * 8) + "-bit"; };
        throw Error(ErrorCode::IncompatibleSnapshot, "'" + name + "' holds the chains of a " + bits(file.chains.pointer_size) +
                                                         " process; " + describe_run(current) + " is " + bits(pointer_size));
    }
    const ProcessMemory memory(process);
    if (!check.address && !options.compare) {
        PointerListing listing = pointer_listing(file, current);
        add_pointer_rows(listing, memory, file, options.limit);
        emit(options.path, [&](std::ostream& out) { write_pointers(out, options.format, listing); });
        if (!options.quiet) {
            std::cerr << "'" << name << "': " << count_chains(listing.count) << " to " << format_address(file.target) << " ("
                      << listing.type << ", " << checks_text(file.checks) << "); ADDRESS and VALUE are read now\n";
            print_pointer_footer(listing);
        }
        return kExitSuccess;
    }

    const std::vector<Region> regions = memory.query_regions();
    PointerFilterResult result;
    {
        ScanProgress progress;
        std::stop_source stop;
        const InterruptScope interrupt(stop);
        ProgressLine line(
            [&](double) {
                return "checked " + std::to_string(progress.chunks_done.load(std::memory_order_relaxed)) + " of " +
                       std::to_string(progress.chunks_total.load(std::memory_order_relaxed)) + " chains  left " +
                       std::to_string(progress.matches.load(std::memory_order_relaxed));
            },
            progress_enabled);
        result = filter_pointer_chains(memory, regions, file.chains, check, options.search.threads, progress, stop.get_token());
        line.finish();
    }
    const std::string unchanged = "'" + name + "' was not changed";
    if (const int code = report_pointer_status(result.status, unchanged, 0, 0); code != kExitSuccess) {
        return code;
    }

    const std::size_t before = file.chains.chains.size();
    const std::string goal = check.address ? format_address(*check.address)
                                           : "value " + describe_condition(*options.compare, options.operand, options.operand_high);
    const std::string prefix = "check " + std::to_string(file.checks + 1) + " (" + goal + "): ";
    if (result.chains.chains.empty()) {
        PointerListing listing = pointer_listing(file, current);
        listing.count = 0;
        emit(options.path, [&](std::ostream& out) { write_pointers(out, options.format, listing); });
        if (!options.quiet) {
            std::cerr << prefix << "none of the " << count_chains(before) << " leads there; "
                      << (options.save.empty() ? unchanged : "nothing was saved") << '\n';
        }
        return kExitNoMatches;
    }
    file.process = current;
    ++file.checks;
    if (check.address) {
        file.target = *check.address;
    }
    file.chains = std::move(result.chains);
    PointerListing listing = pointer_listing(file, current);
    add_pointer_rows(listing, memory, file, options.limit);
    return publish_pointers(options, listing, file, options.save.empty() ? name : options.save,
                            prefix + std::to_string(file.chains.chains.size()) + " of " + count_chains(before) + " left, " +
                                format_seconds(result.seconds));
}

int pointers_command(std::vector<std::string> args, const ConsoleSession& console) {
    const PointerOptions options = parse_pointer_options(std::move(args));
    const bool progress_enabled = options.progress && console.stderr_is_console();
    return is_pointer_file(options.target) ? check_pointers_command(options, progress_enabled)
                                           : search_pointers_command(options, progress_enabled);
}

int struct_command(std::vector<std::string> args) {
    StructOptions options = parse_struct_options(std::move(args));
    const Process process = Process::open(resolve_process(options.target));
    const ProcessSummary summary = summarize(process);
    const unsigned pointer_size = summary.wow64 ? 4 : 8;
    options.base.pointer_size = pointer_size;
    StructDefinition definition;
    if (!options.definition.empty()) {
        definition = read_struct_file(std::filesystem::path(utf8_to_wide(options.definition)), pointer_size);
    }
    std::uint32_t size = options.size_given ? options.size : definition.size;
    for (const StructField& field : definition.fields) {
        size = std::max(size, field.end(pointer_size));
    }

    const ProcessMemory memory(process);
    const std::vector<Region> regions = memory.query_regions();
    const ModuleMap modules(regions);
    const std::string base = format_struct_base(options.base);
    const bool chain = !options.base.module.empty() || !options.base.offsets.empty();
    const auto address = resolve_pointer_path(memory, modules, options.base);
    if (!address) {
        if (!options.quiet) {
            std::cerr << base << " leads nowhere now: its module is not loaded or a pointer on the way cannot be read\n";
        }
        return kExitNoMatches;
    }
    const MemoryDump dump = read_dump(memory, *address, size);
    if (!dump.any_readable()) {
        if (!options.quiet) {
            std::cerr << "Nothing can be read at " << format_address(*address) << (chain ? ", where " + base + " leads now" : "") << '\n';
        }
        return kExitNoMatches;
    }

    StructListing listing;
    listing.process = summary;
    listing.base = base;
    listing.address = *address;
    listing.size = size;
    listing.pointer_size = pointer_size;
    for (StructField& field : layout_struct(definition.fields, dump, size, PointerTargets(regions), pointer_size)) {
        std::string value = format_field_value(field, dump, modules, pointer_size);
        listing.rows.push_back({std::move(field), std::move(value)});
    }
    emit(options.path, [&](std::ostream& out) { write_struct(out, options.format, listing); });
    if (!options.quiet) {
        const auto defined = std::count_if(listing.rows.begin(), listing.rows.end(), [](const StructRow& row) { return row.field.defined; });
        std::cerr << (chain ? base + " leads to " + format_address(*address) : base) << ": " << format_hex(size) << " bytes, "
                  << listing.rows.size() << " fields";
        if (!options.definition.empty()) {
            std::cerr << ", " << defined << " of them from '" << options.definition << "'";
        }
        std::cerr << '\n';
    }
    return kExitSuccess;
}

std::string finding_counts(std::span<const InspectedProcess> processes) {
    std::array<std::size_t, kFindingKindCount> counts{};
    for (const InspectedProcess& inspected : processes) {
        for (const Finding& finding : inspected.report.findings) {
            ++counts[static_cast<std::size_t>(finding.kind)];
        }
    }
    std::string text;
    for (std::size_t kind = 0; kind < kFindingKindCount; ++kind) {
        if (counts[kind] != 0) {
            text += (text.empty() ? "" : ", ") + std::string(to_string(static_cast<FindingKind>(kind))) + ' ' + std::to_string(counts[kind]);
        }
    }
    return text;
}

std::string findings_text(std::size_t count) {
    return count == 1 ? "1 finding" : std::to_string(count) + " findings";
}

void print_inspection_summary(const InspectedProcess& inspected) {
    const InspectReport& report = inspected.report;
    const InspectStats& stats = report.stats;
    std::cerr << "pid " << inspected.process.pid << ' ' << inspected.process.name << ": ";
    if (report.findings.empty()) {
        std::cerr << "no findings";
    } else {
        std::cerr << findings_text(report.findings.size()) << " (" << finding_counts({&inspected, 1}) << ')';
    }
    std::cerr << "; " << stats.modules << " modules, " << format_size(stats.code_bytes) << " of code compared with the files, "
              << format_size(stats.shared_bytes) << " shared with them unchanged, " << format_seconds(stats.seconds) << '\n';
    for (const std::string& warning : report.warnings) {
        std::cerr << "warning: " << warning << '\n';
    }
}

void print_inspection_totals(const InspectListing& listing, double seconds) {
    std::size_t with_findings = 0;
    std::size_t warnings = 0;
    for (const InspectedProcess& inspected : listing.processes) {
        with_findings += inspected.report.findings.empty() ? 0 : 1;
        warnings += inspected.report.warnings.size();
    }
    std::cerr << "Inspected " << listing.processes.size() << " processes in " << format_seconds(seconds) << ": ";
    if (with_findings == 0) {
        std::cerr << "no findings";
    } else {
        std::cerr << with_findings << " with findings (" << finding_counts(listing.processes) << ')';
    }
    std::cerr << "; " << listing.skipped.size() << " could not be opened\n";
    if (warnings != 0) {
        std::cerr << warnings << " warnings; -f json lists them with each process\n";
    }
    if (!listing.skipped.empty()) {
        std::cerr << (debug_privilege_enabled()
                          ? "Protected processes (PPL) cannot be opened even with SeDebugPrivilege.\n"
                          : "Run MemHunter as administrator with --debug-privilege to open the processes of other users and of "
                            "services too.\n");
    }
}

InspectListing inspect_all(const InspectOptions& options, ImageFileCache& files, bool progress_enabled, std::stop_source& stop) {
    std::vector<ProcessEntry> entries = list_processes();
    std::erase_if(entries, [](const ProcessEntry& entry) { return entry.pid == 0; });
    std::sort(entries.begin(), entries.end(), [](const ProcessEntry& a, const ProcessEntry& b) { return a.pid < b.pid; });
    std::vector<std::optional<InspectedProcess>> inspected(entries.size());
    std::vector<std::optional<SkippedProcess>> skipped(entries.size());
    std::atomic<std::size_t> next{0};
    std::atomic<std::size_t> done{0};
    {
        ProgressLine line(
            [&](double) { return "Inspecting processes: " + std::to_string(done.load()) + " of " + std::to_string(entries.size()); },
            progress_enabled);
        const unsigned workers = std::clamp(std::thread::hardware_concurrency(), 1u, 8u);
        std::vector<std::jthread> threads;
        for (unsigned i = 0; i < workers; ++i) {
            threads.emplace_back([&] {
                for (std::size_t index = next++; index < entries.size() && !stop.stop_requested(); index = next++) {
                    try {
                        const Process process = Process::open(entries[index].pid);
                        inspected[index] = InspectedProcess{summarize(process), inspect_process(process, files, options, stop.get_token())};
                    } catch (const std::exception& error) {
                        skipped[index] = SkippedProcess{entries[index].pid, entries[index].name, error.what()};
                    }
                    ++done;
                }
            });
        }
        threads.clear();
        line.finish();
    }
    InspectListing listing;
    listing.all = true;
    for (std::size_t i = 0; i < entries.size(); ++i) {
        if (inspected[i]) {
            listing.processes.push_back(std::move(*inspected[i]));
        } else if (skipped[i]) {
            listing.skipped.push_back(std::move(*skipped[i]));
        }
    }
    return listing;
}

int inspect_command(std::vector<std::string> args, const ConsoleSession& console) {
    const InspectArgs args_given = parse_inspect_options(std::move(args));
    InspectOptions options;
    options.kinds = args_given.kinds;
    ImageFileCache files;
    std::stop_source stop;
    const InterruptScope interrupt(stop);
    const bool progress_enabled = !args_given.quiet && console.stderr_is_console();
    const auto started = std::chrono::steady_clock::now();

    InspectListing listing;
    if (args_given.all) {
        listing = inspect_all(options, files, progress_enabled, stop);
    } else {
        const Process process = Process::open(resolve_process(args_given.target));
        ProcessSummary summary = summarize(process);
        ProgressLine line([&](double) { return "Inspecting pid " + std::to_string(summary.pid) + ' ' + summary.name; }, progress_enabled);
        InspectReport report = inspect_process(process, files, options, stop.get_token());
        line.finish();
        listing.processes.push_back({std::move(summary), std::move(report)});
    }
    emit(args_given.path, [&](std::ostream& out) { write_inspection(out, args_given.format, listing); });

    const bool complete = !stop.stop_requested() && std::all_of(listing.processes.begin(), listing.processes.end(),
                                                                 [](const InspectedProcess& p) { return p.report.complete; });
    if (!args_given.quiet) {
        if (args_given.all) {
            print_inspection_totals(listing, std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count());
        } else {
            print_inspection_summary(listing.processes.front());
        }
    }
    if (!complete) {
        std::cerr << "Inspection interrupted; the findings are partial.\n";
        return kExitIncomplete;
    }
    const bool found = std::any_of(listing.processes.begin(), listing.processes.end(),
                                   [](const InspectedProcess& p) { return !p.report.findings.empty(); });
    return found ? kExitSuccess : kExitNoMatches;
}

int info_command(std::vector<std::string> args) {
    const InfoOptions options = parse_info_options(std::move(args));
    const SnapshotFile file(options.path);
    const SnapshotSide side{file.name(), &file.snapshot(), false, file.file_size()};
    emit("", [&](std::ostream& out) { write_snapshot_info(out, options.format, side); });
    return kExitSuccess;
}

int help_command(const std::vector<std::string>& args) {
    const std::string topic = args.size() > 1 ? args[1] : "";
    if (topic.empty()) {
        std::cout << kMainHelp;
    } else if (topic == "scan") {
        std::cout << kScanHelp;
    } else if (topic == "regions") {
        std::cout << kRegionsHelp;
    } else if (topic == "ps") {
        std::cout << kPsHelp;
    } else if (topic == "snapshot") {
        std::cout << kSnapshotHelp;
    } else if (topic == "diff") {
        std::cout << kDiffHelp;
    } else if (topic == "info") {
        std::cout << kInfoHelp;
    } else if (topic == "tui") {
        std::cout << kTuiHelp;
    } else if (topic == "value") {
        std::cout << kValueHelp;
    } else if (topic == "pointers") {
        std::cout << kPointersHelp;
    } else if (topic == "struct") {
        std::cout << kStructHelp;
    } else if (topic == "inspect") {
        std::cout << kInspectHelp;
    } else {
        throw Error(ErrorCode::InvalidArgument, "no help for unknown command '" + topic + "'");
    }
    return kExitSuccess;
}

int tui_command(std::vector<std::string> args) {
    const TuiOptions options = parse_tui_options(std::move(args));
    const Process process = Process::open(resolve_process(options.target));
    const ProcessMemory memory(process);
    tui::AppOptions app;
    app.threads = options.threads;
    return tui::run_app(memory, summarize(process), app);
}

bool wants_help(const std::vector<std::string>& args) {
    return args.size() > 1 && (args[1] == "-h" || args[1] == "--help");
}

}  // namespace

int exit_code_for(ErrorCode code) noexcept {
    switch (code) {
        case ErrorCode::InvalidArgument:
        case ErrorCode::InvalidPattern: return kExitUsage;
        case ErrorCode::ProcessNotFound:
        case ErrorCode::AccessDenied:
        case ErrorCode::ProcessExited: return kExitProcess;
        case ErrorCode::Io: return kExitIo;
        case ErrorCode::CorruptSnapshot:
        case ErrorCode::IncompatibleSnapshot: return kExitSnapshot;
        case ErrorCode::SystemError: return kExitInternal;
    }
    return kExitInternal;
}

int run(std::vector<std::string> args, const ConsoleSession& console) {
    if (take_debug_privilege(args)) {
        enable_debug_privilege();
    }
    if (args.empty() || args[0] == "-h" || args[0] == "--help") {
        std::cout << kMainHelp;
        return args.empty() ? kExitUsage : kExitSuccess;
    }
    const std::string& command = args[0];
    if (command == "--version" || command == "-V") {
        std::cout << "memhunter " << MEMHUNTER_VERSION << '\n';
        return kExitSuccess;
    }
    if (command == "help") {
        return help_command(args);
    }
    if (wants_help(args)) {
        return help_command({"help", command});
    }
    std::vector<std::string> rest(args.begin() + 1, args.end());
    if (command == "scan") {
        return scan_command(std::move(rest), console);
    }
    if (command == "regions") {
        return regions_command(std::move(rest));
    }
    if (command == "ps") {
        return ps_command(std::move(rest));
    }
    if (command == "snapshot") {
        return snapshot_command(std::move(rest), console);
    }
    if (command == "diff") {
        return diff_command(std::move(rest), console);
    }
    if (command == "info") {
        return info_command(std::move(rest));
    }
    if (command == "value") {
        return value_command(std::move(rest), console);
    }
    if (command == "pointers") {
        return pointers_command(std::move(rest), console);
    }
    if (command == "struct") {
        return struct_command(std::move(rest));
    }
    if (command == "inspect") {
        return inspect_command(std::move(rest), console);
    }
    if (command == "tui") {
        return tui_command(std::move(rest));
    }
    throw Error(ErrorCode::InvalidArgument, "unknown command '" + command + "'");
}

}  // namespace mh::cli
