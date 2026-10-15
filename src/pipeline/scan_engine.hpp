#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stop_token>
#include <vector>

#include "memory/memory_source.hpp"
#include "pipeline/work_plan.hpp"
#include "results/result_set.hpp"
#include "scanner/matcher.hpp"

namespace mh {

struct EngineConfig {
    unsigned scan_threads = 0;
    unsigned read_threads = 0;
    std::size_t preview_bytes = 32;
    std::uint64_t max_matches = 1'000'000;
    std::size_t max_recorded_failures = 256;
    // Indexed by pattern id; non-zero means the preview keeps the whole match (extracted strings).
    std::vector<std::uint8_t> full_preview;
};

// Shared with UI threads; every field is updated once per chunk, never per byte.
struct ScanProgress {
    std::atomic<std::uint64_t> bytes_total{0};
    std::atomic<std::uint64_t> bytes_done{0};
    std::atomic<std::uint64_t> chunks_total{0};
    std::atomic<std::uint64_t> chunks_done{0};
    std::atomic<std::uint64_t> regions_total{0};
    std::atomic<std::uint64_t> regions_done{0};
    std::atomic<std::uint64_t> matches{0};
    std::atomic<std::uint64_t> read_failures{0};
};

struct EngineResult {
    std::vector<Match> matches;
    std::vector<std::byte> previews;
    std::vector<ReadFailure> failures;
    ScanStatus status = ScanStatus::Completed;
    unsigned scan_threads = 0;
    unsigned read_threads = 0;
    std::uint64_t bytes_read = 0;
    std::uint64_t bytes_unreadable = 0;
    std::uint64_t read_calls = 0;
    std::uint64_t read_failures = 0;
    std::uint64_t matches_found = 0;
    bool truncated = false;
    double read_seconds = 0;
    double scan_seconds = 0;
    double wall_seconds = 0;
};

unsigned default_scan_threads() noexcept;
unsigned default_read_threads(unsigned scan_threads) noexcept;

// Reader threads fill buffers from a fixed pool and hand them to scanner threads through a bounded queue,
// so memory use is capped at (2 * scanners + readers) buffers regardless of how much memory is scanned.
EngineResult run_engine(const MemorySource& source, const Matcher& matcher, std::span<const WorkItem> work,
                        const EngineConfig& config, ScanProgress& progress, std::stop_token stop);

}  // namespace mh
