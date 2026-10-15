#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <thread>

#include "memory/memory_source.hpp"
#include "pipeline/scan_session.hpp"
#include "pointer/pointer_scan.hpp"
#include "results/result_set.hpp"
#include "snapshot/snapshot.hpp"
#include "value/value_scan.hpp"

namespace mh::gui {

enum class JobKind : std::uint8_t { Scan, ChangedScan, Remember, ValueScan, PointerScan, PointerCheck };
enum class JobStage : std::uint8_t { Hashing, Scanning, Pointers };

// Shared with the UI thread, which only reads it.
struct JobProgress {
    std::atomic<JobStage> stage{JobStage::Scanning};
    ScanProgress hashing;
    ScanProgress scanning;
    PointerScanProgress pointers;

    const ScanProgress& current() const noexcept {
        switch (stage.load(std::memory_order_relaxed)) {
            case JobStage::Hashing: return hashing;
            case JobStage::Pointers: return pointers.reading;
            default: return scanning;
        }
    }
};

// What a changed-only scan found out about the memory before searching it.
struct ChangeSummary {
    std::uint64_t compared = 0;
    std::uint64_t changed = 0;
    std::size_t ranges = 0;
};

struct JobOutcome {
    ScanStatus status = ScanStatus::Completed;
    std::optional<ResultSet> results;
    std::optional<Snapshot> snapshot;
    std::optional<ChangeSummary> changes;
    std::optional<ValueScanResult> values;
    std::optional<PointerScanResult> pointers;
    std::optional<PointerFilterResult> checked;
};

// Runs one piece of work on its own thread. The UI thread polls finished() and then takes the outcome, so
// nothing the work writes is shared while it runs.
class Job {
public:
    using Work = std::function<JobOutcome(std::stop_token, JobProgress&)>;

    Job(JobKind kind, Work work);
    ~Job();
    Job(const Job&) = delete;
    Job& operator=(const Job&) = delete;

    JobKind kind() const noexcept { return kind_; }
    const JobProgress& progress() const noexcept { return progress_; }
    double elapsed_seconds() const;
    void cancel() noexcept;
    bool cancel_requested() const noexcept { return thread_.get_stop_token().stop_requested(); }
    bool finished() const noexcept { return finished_.load(std::memory_order_acquire); }

    // Only after finished(); rethrows what the work threw.
    JobOutcome take();

private:
    void run(std::stop_token stop, const Work& work);

    JobKind kind_;
    JobProgress progress_;
    std::chrono::steady_clock::time_point started_;
    std::atomic<double> seconds_{0};
    std::atomic<bool> finished_{false};
    std::mutex mutex_;
    std::optional<JobOutcome> outcome_;
    std::exception_ptr error_;
    // Last, so that it is joined before the members the work uses are destroyed.
    std::jthread thread_;
};

// `memory` must outlive the job.
Job::Work scan_work(const MemorySource& memory, ProcessSummary process, ScanRequest request);

// Hashes the memory the request selects, compares it with `baseline` and searches only what changed since then.
Job::Work changed_scan_work(const MemorySource& memory, ProcessSummary process, ScanRequest request,
                            std::shared_ptr<const Snapshot> baseline);

// The first value scan over the memory the filter selects, or with `previous` a next scan over its candidates.
Job::Work value_scan_work(const MemorySource& memory, RegionFilter filter, ValueType type, bool aligned, ValueCondition condition,
                          ValueScanOptions options, std::shared_ptr<const ValueCandidates> previous);

// Chains of pointers to `target` through the writable memory of the process.
Job::Work pointer_scan_work(const MemorySource& memory, std::uint64_t target, unsigned pointer_size, PointerScanOptions options);

// Keeps the chains that pass the check; progress.scanning counts the chains.
Job::Work pointer_check_work(const MemorySource& memory, std::shared_ptr<const PointerChains> chains, PointerCheck check,
                             unsigned threads);

// Hashes the memory the filter selects; the outcome carries the snapshot to compare later scans with.
Job::Work remember_work(const MemorySource& memory, ProcessSummary process, RegionFilter filter, unsigned threads);

}  // namespace mh::gui
