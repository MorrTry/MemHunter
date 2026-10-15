#pragma once

#include <atomic>
#include <chrono>
#include <exception>
#include <mutex>
#include <optional>
#include <thread>

#include "memory/memory_source.hpp"
#include "pipeline/scan_session.hpp"
#include "results/result_set.hpp"

namespace mh::tui {

// Runs one scan on its own thread. The UI thread only reads the progress atomics and, once finished() is
// true, takes the result; the result set itself is never shared while the scan writes it.
class ScanTask {
public:
    ScanTask(const MemorySource& source, ScanRequest request, ProcessSummary process);
    ~ScanTask();
    ScanTask(const ScanTask&) = delete;
    ScanTask& operator=(const ScanTask&) = delete;

    const ScanProgress& progress() const noexcept { return progress_; }
    double elapsed_seconds() const;
    void cancel() noexcept;
    bool finished() const noexcept { return finished_.load(std::memory_order_acquire); }

    // Only after finished(); rethrows what the scan threw.
    ResultSet take();

private:
    void run(std::stop_token stop, const MemorySource& source, ScanRequest request, ProcessSummary process);

    ScanProgress progress_;
    std::chrono::steady_clock::time_point started_;
    std::atomic<double> seconds_{0};
    std::atomic<bool> finished_{false};
    std::mutex mutex_;
    std::optional<ResultSet> result_;
    std::exception_ptr error_;
    // Last, so that it is joined before the members the scan thread uses are destroyed.
    std::jthread thread_;
};

}  // namespace mh::tui
