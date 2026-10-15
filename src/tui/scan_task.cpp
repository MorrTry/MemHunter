#include "tui/scan_task.hpp"

#include <utility>

#include "common/error.hpp"

namespace mh::tui {

ScanTask::ScanTask(const MemorySource& source, ScanRequest request, ProcessSummary process)
    : started_(std::chrono::steady_clock::now()),
      thread_([this, &source](std::stop_token stop, ScanRequest r, ProcessSummary p) { run(stop, source, std::move(r), std::move(p)); },
              std::move(request), std::move(process)) {}

ScanTask::~ScanTask() {
    thread_.request_stop();
}

void ScanTask::run(std::stop_token stop, const MemorySource& source, ScanRequest request, ProcessSummary process) {
    std::optional<ResultSet> result;
    std::exception_ptr error;
    try {
        result.emplace(run_scan(source, request, progress_, stop));
        result->process = std::move(process);
    } catch (...) {
        // Handed to the UI thread, which reports it; nothing is lost here.
        error = std::current_exception();
    }
    {
        std::lock_guard lock(mutex_);
        result_ = std::move(result);
        error_ = error;
    }
    seconds_.store(std::chrono::duration<double>(std::chrono::steady_clock::now() - started_).count(), std::memory_order_relaxed);
    finished_.store(true, std::memory_order_release);
}

double ScanTask::elapsed_seconds() const {
    if (finished()) {
        return seconds_.load(std::memory_order_relaxed);
    }
    return std::chrono::duration<double>(std::chrono::steady_clock::now() - started_).count();
}

void ScanTask::cancel() noexcept {
    thread_.request_stop();
}

ResultSet ScanTask::take() {
    if (!finished()) {
        throw Error(ErrorCode::InvalidArgument, "the scan is still running");
    }
    std::lock_guard lock(mutex_);
    if (error_) {
        std::rethrow_exception(error_);
    }
    if (!result_) {
        throw Error(ErrorCode::InvalidArgument, "the scan result was already taken");
    }
    ResultSet result = std::move(*result_);
    result_.reset();
    return result;
}

}  // namespace mh::tui
