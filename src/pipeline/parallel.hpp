#pragma once

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <exception>
#include <mutex>
#include <stop_token>
#include <thread>
#include <vector>

#include "pipeline/scan_engine.hpp"

namespace mh {

// Runs body(index, worker) for every index on one thread per worker until the body returns false or a stop is
// requested. Returns how many items completed; rethrows the first exception of a worker.
template <typename Worker, typename Body>
std::size_t parallel_items(std::size_t count, std::vector<Worker>& workers, std::stop_token stop, Body&& body) {
    std::stop_source halt;
    const std::stop_callback forward(stop, [&halt] { halt.request_stop(); });
    const std::stop_token token = halt.get_token();
    std::atomic<std::size_t> next{0};
    std::atomic<std::size_t> done{0};
    std::mutex error_mutex;
    std::exception_ptr error;
    {
        std::vector<std::jthread> threads;
        threads.reserve(workers.size());
        for (std::size_t t = 0; t < workers.size(); ++t) {
            threads.emplace_back([&, t] {
                try {
                    Worker& worker = workers[t];
                    while (!token.stop_requested()) {
                        const std::size_t index = next.fetch_add(1, std::memory_order_relaxed);
                        if (index >= count) {
                            break;
                        }
                        if (!body(index, worker)) {
                            halt.request_stop();
                            break;
                        }
                        done.fetch_add(1, std::memory_order_relaxed);
                    }
                } catch (...) {
                    {
                        std::lock_guard lock(error_mutex);
                        if (!error) {
                            error = std::current_exception();
                        }
                    }
                    halt.request_stop();
                }
            });
        }
    }
    if (error) {
        std::rethrow_exception(error);
    }
    return done.load();
}

// `requested` threads (0 = the default), at least 1 and at most one per item.
inline unsigned worker_count(unsigned requested, std::size_t items) {
    const auto limit = static_cast<unsigned>(std::clamp<std::size_t>(items, 1, 1024));
    return std::clamp(requested != 0 ? requested : default_scan_threads(), 1u, limit);
}

}  // namespace mh
