#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <stop_token>

#include "memory/memory_source.hpp"
#include "pipeline/scan_session.hpp"
#include "snapshot/snapshot.hpp"

namespace mh {

struct CaptureOptions {
    std::uint32_t block_size = kDefaultBlockSize;
    unsigned threads = 0;
    std::size_t chunk_size = std::size_t{1} << 20;
};

class SnapshotDataSink {
public:
    virtual ~SnapshotDataSink() = default;

    // Called concurrently with disjoint ranges of the data section; unreadable blocks arrive zero-filled.
    virtual void write(std::uint64_t offset, std::span<const std::byte> bytes) = 0;
};

struct CaptureResult {
    Snapshot snapshot;
    ScanStatus status = ScanStatus::Completed;
    unsigned threads = 0;
    std::uint64_t bytes_hashed = 0;
    std::uint64_t bytes_unreadable = 0;
    std::uint64_t read_calls = 0;
    double seconds = 0;
};

// Throws Error(InvalidArgument) unless block_size is a power of two between the page size and kMaxBlockSize.
void validate_block_size(std::uint64_t block_size, std::size_t page_size);

// Hashes every block of plan.spans; with a sink the block contents are streamed to it as well. A block that is
// only partly readable is recorded as unreadable. The caller fills snapshot.process.
CaptureResult capture_snapshot(const MemorySource& source, const ScanPlan& plan, const CaptureOptions& options,
                               SnapshotDataSink* sink, ScanProgress& progress, std::stop_token stop);

}  // namespace mh
