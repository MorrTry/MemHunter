#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stop_token>
#include <vector>

#include "memory/memory_source.hpp"
#include "pipeline/scan_engine.hpp"
#include "pipeline/scan_session.hpp"
#include "pointer/pointer_chain.hpp"
#include "value/value_scan.hpp"

namespace mh {

struct PointerScanOptions {
    unsigned depth = 5;
    std::uint32_t max_offset = 0x1000;
    std::size_t max_chains = 1'000'000;
    unsigned threads = 0;
    std::size_t chunk_size = std::size_t{1} << 20;
    // Bytes the pointer map and the search may occupy; 0 means no limit.
    std::uint64_t memory_budget = 0;
};

enum class PointerStage : std::uint8_t { Reading, Sorting, Searching, Listing };

// Shared with UI threads.
struct PointerScanProgress {
    ScanProgress reading;
    std::atomic<PointerStage> stage{PointerStage::Reading};
    std::atomic<std::uint64_t> pointers{0};
    std::atomic<unsigned> level{0};
    std::atomic<std::uint64_t> nodes{0};
};

enum class PointerScanStatus : std::uint8_t { Completed, Cancelled, TargetExited, OverBudget };

struct PointerScanResult {
    PointerChains chains;
    PointerScanStatus status = PointerScanStatus::Completed;
    // Every chain found, saturating at UINT64_MAX; more than the list holds when max_chains cut it.
    std::uint64_t total_chains = 0;
    std::uint64_t pointers = 0;
    // Addresses from which the target can be reached.
    std::uint64_t nodes = 0;
    unsigned threads = 0;
    std::uint64_t bytes_read = 0;
    std::uint64_t read_failures = 0;
    // With OverBudget: what the search had reached when it stopped.
    std::uint64_t needed_bytes = 0;
    double seconds = 0;

    bool truncated() const noexcept { return total_chains > chains.chains.size(); }
};

// The chains of at most options.depth pointers that start in a module image and lead to `target`, every step adding
// 0..max_offset to the pointer it read. Pointers are the values at addresses divisible by pointer_size in plan.spans
// that point into plan.spans. An address takes part only at its shortest distance from the target, and a chain
// never passes another image address; the list is ordered by length, then by address. Throws
// Error(InvalidArgument) for a depth over kMaxPointerDepth or a pointer size other than 4 and 8.
PointerScanResult find_pointer_chains(const MemorySource& source, const ScanPlan& plan, std::uint64_t target,
                                      unsigned pointer_size, const PointerScanOptions& options,
                                      PointerScanProgress& progress, std::stop_token stop);

// What a chain must lead to now: `address`, or else a value that passes `condition`.
struct PointerCheck {
    std::optional<std::uint64_t> address;
    ValueType type = ValueType::Int32;
    ValueCondition condition;
};

struct PointerFilterResult {
    PointerChains chains;
    PointerScanStatus status = PointerScanStatus::Completed;
    unsigned threads = 0;
    double seconds = 0;
};

// Keeps the chains that pass the check. progress counts chains in chunks_done/chunks_total and kept ones in
// matches. Throws Error(InvalidArgument) for a comparison that needs a previous scan.
PointerFilterResult filter_pointer_chains(const MemorySource& memory, std::span<const Region> regions,
                                          const PointerChains& chains, const PointerCheck& check, unsigned threads,
                                          ScanProgress& progress, std::stop_token stop);

// Writable memory of every type: where pointers that change at run time live.
RegionFilter pointer_region_filter();

// A third of the free physical memory, like a value search.
std::uint64_t pointer_memory_budget();

}  // namespace mh
