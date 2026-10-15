#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <vector>

#include "common/error.hpp"
#include "gui/finding_list.hpp"
#include "gui/job.hpp"
#include "gui/pointer_list.hpp"
#include "gui/results_table.hpp"
#include "gui/search.hpp"
#include "gui/struct_table.hpp"
#include "gui/value_history.hpp"
#include "gui/value_table.hpp"
#include "gui/watch_list.hpp"
#include "memory/memory_dump.hpp"
#include "memory/memory_source.hpp"
#include "pattern/pattern.hpp"
#include "results/result_set.hpp"
#include "snapshot/snapshot.hpp"

namespace mh::gui {

// A process opened for reading, or any other memory source in tests.
class Target {
public:
    virtual ~Target() = default;
    virtual const MemorySource& memory() const = 0;
    virtual const ProcessSummary& summary() const = 0;
    // Looks for injected code (see inspect_memory) from the job thread; nullopt when the target cannot be inspected.
    virtual std::optional<InspectReport> inspect(const InspectOptions& options, std::stop_token stop) const;
};

// Throws Error when the process cannot be opened for reading.
std::unique_ptr<Target> open_process(std::uint32_t pid);

// A sentence for the user; the details of Windows errors stay in the original English text.
std::string describe_error(const Error& error);

enum class LiveState : std::uint8_t { Same, Changed, Unreadable };

// Whether the bytes of the match still match its pattern (or, for extracted strings, the text found).
LiveState live_state(const ResultSet& results, std::span<const Pattern> patterns, const Match& match, const MemoryDump& dump);

// The format follows the extension: .csv, .txt, anything else JSON. Throws Error(Io).
void export_rows(const std::filesystem::path& path, const ResultSet& results, std::span<const std::size_t> rows);

// The shown candidates of a value scan; the format follows the extension like export_rows. Throws Error(Io).
void export_values(const std::filesystem::path& path, const ProcessSummary& process, const ValueTable& table);

// The values are read from `memory` while writing, so the file shows them as they are now. Throws Error(Io).
void export_watch(const std::filesystem::path& path, const ProcessSummary& process, const WatchList& list, const MemorySource& memory);

// Reading statistics of the last value scan, whatever its outcome.
struct ValueRun {
    std::uint64_t bytes_read = 0;
    std::uint64_t read_failures = 0;
    unsigned threads = 0;
};

// Statistics of the last pointer search or check, whatever its outcome; a check reads no bytes of its own.
struct PointerRun {
    JobKind kind = JobKind::PointerScan;
    double seconds = 0;
    unsigned threads = 0;
    std::uint64_t bytes_read = 0;
    std::uint64_t read_failures = 0;
    std::uint64_t pointers = 0;
};

struct Baseline {
    std::shared_ptr<const Snapshot> snapshot;
    std::uint64_t bytes = 0;
};

// What the chains must lead to after a restart: the address found again, or the value of the search target.
struct PointerCheckForm {
    bool by_value = false;
    std::string address;
    std::string value;
};

struct Notice {
    std::string text;
    bool error = false;
};

class Session {
public:
    Session() = default;
    ~Session();
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    // Cancels and waits for a running job; the previous results and the remembered memory are dropped. The address
    // list stays for the same process, keeps only its chains for another run of the same program and is emptied
    // otherwise. The structure follows the same rule, and the pointer list stays.
    void attach(std::unique_ptr<Target> target);
    void detach();
    const Target* target() const noexcept { return target_.get(); }
    bool target_alive() const;

    // Problems with the form are reported in notice() instead of being thrown.
    bool start_scan(const SearchForm& form, bool only_changed);
    bool start_remember(const SearchForm& form);
    void forget();
    // The first value scan, or a next scan over the candidates while there are any. The type and the alignment
    // of a next scan are those of the first one.
    bool start_value_scan(const SearchForm& form);
    // Drops the candidates and the history, so that the next value scan is a first one again.
    void reset_values();
    // Shows the candidates of an earlier or later step of the history; a next scan then starts from them. False
    // while a job runs or when there is no such step.
    bool go_to_scan(std::size_t step);
    void cancel();

    // Takes the outcome of a finished job; true when the job finished during this call.
    bool poll();

    bool busy() const noexcept { return job_ != nullptr; }
    const Job* job() const noexcept { return job_.get(); }
    const std::optional<Baseline>& baseline() const noexcept { return baseline_; }

    ResultsTable& table() noexcept { return table_; }
    const ResultsTable& table() const noexcept { return table_; }
    // Patterns of the scan whose results the table shows.
    std::span<const Pattern> patterns() const noexcept { return patterns_; }
    const std::optional<ChangeSummary>& changes() const noexcept { return changes_; }
    ValueTable& values() noexcept { return values_; }
    const ValueTable& values() const noexcept { return values_; }
    const ValueRun& value_run() const noexcept { return value_run_; }
    const ValueHistory& history() const noexcept { return history_; }
    WatchList& watch() noexcept { return watch_; }
    const WatchList& watch() const noexcept { return watch_; }
    // Rereads the regions of the target for the module column; the notice says whether the entry is new.
    bool add_watch(WatchEntry entry);
    double last_seconds() const noexcept { return last_seconds_; }

    PointerList& pointers() noexcept { return pointers_; }
    const PointerList& pointers() const noexcept { return pointers_; }
    const PointerRun& pointer_run() const noexcept { return pointer_run_; }
    // Chains of pointers from the modules of the target to the address of the entry in `watch_row`.
    bool start_pointer_scan(std::size_t watch_row, unsigned depth, std::uint32_t max_offset, unsigned threads = 0);
    // Keeps the chains that lead to the form's address or value now. A check that no chain passes leaves the list
    // as it was.
    bool start_pointer_check(const PointerCheckForm& form, unsigned threads = 0);
    bool save_pointers(const std::filesystem::path& path);
    bool load_pointers(const std::filesystem::path& path);
    void clear_pointers();
    // Adds an entry that follows the chain in `row`; false when it is already listed.
    bool add_pointer_watch(std::size_t row);

    // 8, or 4 for a 32-bit target.
    unsigned pointer_size() const noexcept;
    StructTable& structure() noexcept { return structure_; }
    const StructTable& structure() const noexcept { return structure_; }
    // Reads the structure at once; `known` becomes its first defined field.
    bool open_structure(PointerPath base, std::uint32_t size, std::optional<std::uint32_t> focus = std::nullopt,
                        std::optional<StructField> known = std::nullopt);
    void refresh_structure(StructTable::Clock::time_point now);
    // Rereads the regions, so that pointers into memory allocated since are recognised, and guesses again.
    void guess_structure_again();
    bool add_struct_watch(std::size_t row, std::size_t instance);
    // Saves the defined fields; there must be at least one.
    bool save_structure(const std::filesystem::path& path);
    bool load_structure(const std::filesystem::path& path);

    FindingList& findings() noexcept { return findings_; }
    const FindingList& findings() const noexcept { return findings_; }
    // Looks for injected code in the target; the findings replace those of the last inspection when it completes.
    bool start_inspect();

    const Notice& notice() const noexcept { return notice_; }
    void set_notice(std::string text, bool error);

private:
    void stop_job();
    void finish(JobKind kind, JobOutcome outcome, double seconds);
    void finish_values(ValueScanResult result, double seconds);
    void finish_pointers(PointerScanResult result, double seconds);
    void finish_check(PointerFilterResult result, double seconds);
    void finish_inspect(std::optional<InspectReport> report, double seconds);
    // Rereads the regions of the target for the address list, the pointer list and the structure.
    void refresh_modules();

    // Declared before job_, so that the job is joined before the memory it reads goes away.
    std::unique_ptr<Target> target_;
    std::unique_ptr<Job> job_;
    std::vector<Pattern> pending_patterns_;
    std::vector<Pattern> patterns_;
    ResultsTable table_;
    std::optional<Baseline> baseline_;
    std::optional<ChangeSummary> changes_;
    ValueTable values_;
    ValueRun value_run_;
    ValueHistory history_;
    // What the first scan was allowed to occupy; the whole history keeps within it.
    std::uint64_t history_budget_ = 0;
    std::string pending_label_;
    WatchList watch_;
    PointerList pointers_;
    PointerSearch pending_search_;
    std::optional<std::uint64_t> pending_address_;
    PointerRun pointer_run_;
    StructTable structure_;
    FindingList findings_;
    double last_seconds_ = 0;
    Notice notice_;
};

}  // namespace mh::gui
