#include "gui/job.hpp"

#include <utility>

#include "common/error.hpp"
#include "gui/lang.hpp"
#include "snapshot/capture.hpp"
#include "snapshot/diff.hpp"

namespace mh::gui {

Job::Job(JobKind kind, Work work)
    : kind_(kind),
      started_(std::chrono::steady_clock::now()),
      thread_([this](std::stop_token stop, Work w) { run(stop, w); }, std::move(work)) {}

Job::~Job() {
    thread_.request_stop();
}

void Job::run(std::stop_token stop, const Work& work) {
    std::optional<JobOutcome> outcome;
    std::exception_ptr error;
    try {
        outcome.emplace(work(stop, progress_));
    } catch (...) {
        // Handed to the UI thread, which reports it.
        error = std::current_exception();
    }
    {
        std::lock_guard lock(mutex_);
        outcome_ = std::move(outcome);
        error_ = error;
    }
    seconds_.store(std::chrono::duration<double>(std::chrono::steady_clock::now() - started_).count(), std::memory_order_relaxed);
    finished_.store(true, std::memory_order_release);
}

double Job::elapsed_seconds() const {
    if (finished()) {
        return seconds_.load(std::memory_order_relaxed);
    }
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - started_).count();
}

void Job::cancel() noexcept {
    thread_.request_stop();
}

JobOutcome Job::take() {
    if (!finished()) {
        throw Error(ErrorCode::InvalidArgument, "the job is still running");
    }
    std::lock_guard lock(mutex_);
    if (error_) {
        std::rethrow_exception(error_);
    }
    if (!outcome_) {
        throw Error(ErrorCode::InvalidArgument, "the job outcome was already taken");
    }
    JobOutcome outcome = std::move(*outcome_);
    outcome_.reset();
    return outcome;
}

Job::Work scan_work(const MemorySource& memory, ProcessSummary process, ScanRequest request) {
    return [&memory, process = std::move(process), request = std::move(request)](std::stop_token stop, JobProgress& progress) {
        progress.stage.store(JobStage::Scanning, std::memory_order_relaxed);
        JobOutcome outcome;
        outcome.results.emplace(run_scan(memory, request, progress.scanning, stop));
        outcome.results->process = process;
        outcome.status = outcome.results->stats.status;
        return outcome;
    };
}

Job::Work changed_scan_work(const MemorySource& memory, ProcessSummary process, ScanRequest request,
                            std::shared_ptr<const Snapshot> baseline) {
    return [&memory, process = std::move(process), request = std::move(request), baseline = std::move(baseline)](
               std::stop_token stop, JobProgress& progress) mutable {
        if (!same_process_instance(baseline->process, process)) {
            throw Error(ErrorCode::IncompatibleSnapshot,
                        tr("The remembered memory belongs to a different run of the process. Remember the memory again.",
                           "Запомненная память относится к другому запуску процесса. Запомните память заново."));
        }
        progress.stage.store(JobStage::Hashing, std::memory_order_relaxed);
        ScanPlan plan = plan_scan(memory, request.filter);
        CaptureOptions options;
        options.block_size = baseline->block_size;
        options.threads = request.engine.scan_threads;
        const CaptureResult current = capture_snapshot(memory, plan, options, nullptr, progress.hashing, stop);
        JobOutcome outcome;
        if (current.status != ScanStatus::Completed) {
            outcome.status = current.status;
            return outcome;
        }
        const SnapshotDiff diff = diff_snapshots(*baseline, current.snapshot);
        auto changed = ranges_to_rescan(diff);
        ChangeSummary changes;
        changes.compared = current.snapshot.captured_bytes();
        changes.ranges = changed.size();
        for (const auto& range : changed) {
            changes.changed += range.end - range.begin;
        }
        outcome.changes = changes;
        request.changed = std::move(changed);

        progress.stage.store(JobStage::Scanning, std::memory_order_relaxed);
        outcome.results.emplace(run_scan(memory, request, std::move(plan), progress.scanning, stop));
        outcome.results->process = process;
        outcome.status = outcome.results->stats.status;
        return outcome;
    };
}

Job::Work value_scan_work(const MemorySource& memory, RegionFilter filter, ValueType type, bool aligned, ValueCondition condition,
                          ValueScanOptions options, std::shared_ptr<const ValueCandidates> previous) {
    return [&memory, filter = std::move(filter), type, aligned, condition, options, previous = std::move(previous)](
               std::stop_token stop, JobProgress& progress) {
        progress.stage.store(JobStage::Scanning, std::memory_order_relaxed);
        JobOutcome outcome;
        if (previous) {
            outcome.values.emplace(next_value_scan(memory, *previous, condition, options, progress.scanning, stop));
        } else {
            outcome.values.emplace(
                first_value_scan(memory, plan_scan(memory, filter), type, aligned, condition, options, progress.scanning, stop));
        }
        return outcome;
    };
}

Job::Work remember_work(const MemorySource& memory, ProcessSummary process, RegionFilter filter, unsigned threads) {
    return [&memory, process = std::move(process), filter = std::move(filter), threads](std::stop_token stop, JobProgress& progress) {
        progress.stage.store(JobStage::Hashing, std::memory_order_relaxed);
        CaptureOptions options;
        options.threads = threads;
        CaptureResult capture = capture_snapshot(memory, plan_scan(memory, filter), options, nullptr, progress.hashing, stop);
        JobOutcome outcome;
        outcome.status = capture.status;
        if (capture.status == ScanStatus::Completed) {
            capture.snapshot.process = process;
            outcome.snapshot = std::move(capture.snapshot);
        }
        return outcome;
    };
}

Job::Work pointer_scan_work(const MemorySource& memory, std::uint64_t target, unsigned pointer_size, PointerScanOptions options) {
    return [&memory, target, pointer_size, options](std::stop_token stop, JobProgress& progress) {
        progress.stage.store(JobStage::Pointers, std::memory_order_relaxed);
        JobOutcome outcome;
        outcome.pointers.emplace(find_pointer_chains(memory, plan_scan(memory, pointer_region_filter()), target, pointer_size,
                                                     options, progress.pointers, stop));
        return outcome;
    };
}

Job::Work pointer_check_work(const MemorySource& memory, std::shared_ptr<const PointerChains> chains, PointerCheck check,
                             unsigned threads) {
    return [&memory, chains = std::move(chains), check, threads](std::stop_token stop, JobProgress& progress) {
        progress.stage.store(JobStage::Scanning, std::memory_order_relaxed);
        JobOutcome outcome;
        outcome.checked.emplace(
            filter_pointer_chains(memory, memory.query_regions(), *chains, check, threads, progress.scanning, stop));
        return outcome;
    };
}

}  // namespace mh::gui
