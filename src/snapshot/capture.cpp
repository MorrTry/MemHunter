#include "snapshot/capture.hpp"

#include <algorithm>
#include <atomic>
#include <bit>
#include <chrono>
#include <cstring>
#include <exception>
#include <mutex>
#include <thread>
#include <vector>

#include "common/error.hpp"
#include "common/text.hpp"
#include "memory/segmented_read.hpp"
#include "snapshot/hash.hpp"

namespace mh {

namespace {

using Clock = std::chrono::steady_clock;

struct CaptureItem {
    std::size_t span = 0;
    std::uint64_t first_block = 0;
    std::uint64_t blocks = 0;
    std::uint64_t begin = 0;
    std::uint64_t end = 0;
};

struct WorkerTotals {
    std::uint64_t hashed = 0;
    std::uint64_t unreadable = 0;
    std::uint64_t read_calls = 0;
};

std::vector<CaptureItem> split_capture(const Snapshot& snapshot, std::size_t chunk_size) {
    const std::uint64_t per_item = std::max<std::uint64_t>(1, chunk_size / snapshot.block_size);
    std::vector<CaptureItem> items;
    for (std::size_t s = 0; s < snapshot.spans.size(); ++s) {
        const SnapshotSpan& span = snapshot.spans[s];
        const std::uint64_t count = blocks_in_range(span.begin, span.end, snapshot.block_size);
        for (std::uint64_t b = 0; b < count; b += per_item) {
            CaptureItem item;
            item.span = s;
            item.first_block = span.first_block + b;
            item.blocks = std::min(per_item, count - b);
            item.begin = snapshot.block_range(s, item.first_block).begin;
            item.end = snapshot.block_range(s, item.first_block + item.blocks - 1).end;
            items.push_back(item);
        }
    }
    return items;
}

}  // namespace

void validate_block_size(std::uint64_t block_size, std::size_t page_size) {
    if (!std::has_single_bit(block_size) || block_size < page_size || block_size > kMaxBlockSize) {
        throw Error(ErrorCode::InvalidArgument, "block size " + format_size(block_size) + " must be a power of two from " +
                                                    format_size(page_size) + " to " + format_size(kMaxBlockSize));
    }
}

CaptureResult capture_snapshot(const MemorySource& source, const ScanPlan& plan, const CaptureOptions& options,
                               SnapshotDataSink* sink, ScanProgress& progress, std::stop_token stop) {
    const auto started = Clock::now();
    const std::size_t page_size = std::max<std::size_t>(source.page_size(), 1);
    validate_block_size(options.block_size, page_size);

    CaptureResult result;
    Snapshot& snapshot = result.snapshot;
    snapshot.captured_at = filetime_now();
    snapshot.page_size = static_cast<std::uint32_t>(page_size);
    snapshot.block_size = options.block_size;
    snapshot.has_data = sink != nullptr;
    snapshot.regions = plan.regions;
    layout_spans(snapshot, plan.spans);

    const std::vector<CaptureItem> items = split_capture(snapshot, options.chunk_size);
    progress.bytes_total = snapshot.captured_bytes();
    progress.chunks_total = items.size();
    if (items.empty()) {
        return result;
    }

    const auto limit = static_cast<unsigned>(std::min<std::size_t>(items.size(), 1024));
    const unsigned threads = std::clamp(options.threads != 0 ? options.threads : default_scan_threads(), 1u, limit);
    result.threads = threads;
    std::size_t capacity = 0;
    for (const auto& item : items) {
        capacity = std::max<std::size_t>(capacity, item.end - item.begin);
    }

    std::stop_source halt;
    const std::stop_callback forward(stop, [&halt] { halt.request_stop(); });
    const std::stop_token token = halt.get_token();
    std::atomic<std::size_t> next_item{0};
    std::atomic<std::size_t> items_done{0};
    std::atomic<bool> target_exited{false};
    std::vector<WorkerTotals> totals(threads);
    std::mutex error_mutex;
    std::exception_ptr error;

    {
        std::vector<std::jthread> workers;
        workers.reserve(threads);
        for (unsigned t = 0; t < threads; ++t) {
            workers.emplace_back([&, t] {
                try {
                    std::vector<std::byte> buffer(capacity);
                    std::vector<Segment> segments;
                    WorkerTotals& mine = totals[t];
                    while (!token.stop_requested()) {
                        const std::size_t index = next_item.fetch_add(1, std::memory_order_relaxed);
                        if (index >= items.size()) {
                            break;
                        }
                        const CaptureItem& item = items[index];
                        const std::span<std::byte> data(buffer.data(), item.end - item.begin);
                        if (!read_segments(source, item.begin, data, page_size, segments, mine.read_calls)) {
                            progress.read_failures.fetch_add(1, std::memory_order_relaxed);
                            if (!source.target_alive()) {
                                target_exited = true;
                                halt.request_stop();
                                break;
                            }
                        }
                        // Each block index belongs to exactly one item, so the tables are written without locks.
                        std::size_t segment = 0;
                        for (std::uint64_t b = item.first_block; b < item.first_block + item.blocks; ++b) {
                            const AddressRange range = snapshot.block_range(item.span, b);
                            const std::size_t begin = range.begin - item.begin;
                            const std::size_t end = range.end - item.begin;
                            if (segment_covers(segments, segment, begin, end)) {
                                snapshot.states[b] = BlockState::Hashed;
                                snapshot.hashes[b] = xxh64(data.subspan(begin, end - begin));
                                mine.hashed += end - begin;
                            } else {
                                std::memset(data.data() + begin, 0, end - begin);
                                mine.unreadable += end - begin;
                            }
                        }
                        if (sink != nullptr) {
                            sink->write(snapshot.spans[item.span].data_offset + (item.begin - snapshot.spans[item.span].begin), data);
                        }
                        progress.bytes_done.fetch_add(item.end - item.begin, std::memory_order_relaxed);
                        progress.chunks_done.fetch_add(1, std::memory_order_relaxed);
                        items_done.fetch_add(1, std::memory_order_relaxed);
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
    if (items_done.load() == items.size()) {
        result.status = ScanStatus::Completed;
    } else {
        result.status = target_exited.load() ? ScanStatus::TargetExited : ScanStatus::Cancelled;
    }
    for (const auto& t : totals) {
        result.bytes_hashed += t.hashed;
        result.bytes_unreadable += t.unreadable;
        result.read_calls += t.read_calls;
    }
    result.seconds = std::chrono::duration<double>(Clock::now() - started).count();
    return result;
}

}  // namespace mh
