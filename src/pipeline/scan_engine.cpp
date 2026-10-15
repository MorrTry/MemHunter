#include "pipeline/scan_engine.hpp"

#include <algorithm>
#include <chrono>
#include <exception>
#include <mutex>
#include <optional>
#include <thread>

#include "pipeline/bounded_queue.hpp"

namespace mh {

namespace {

using Clock = std::chrono::steady_clock;

double to_seconds(Clock::duration duration) {
    return std::chrono::duration<double>(duration).count();
}

struct Segment {
    std::size_t begin = 0;
    std::size_t end = 0;
};

struct Slot {
    std::vector<std::byte> data;
    std::vector<Segment> segments;
    std::size_t item = 0;
    std::uint64_t base = 0;
};

struct ReaderTotals {
    std::uint64_t bytes_read = 0;
    std::uint64_t bytes_unreadable = 0;
    std::uint64_t read_calls = 0;
    std::uint64_t failures = 0;
    Clock::duration busy{};
};

struct ScannerOutput {
    std::vector<Match> matches;
    std::vector<std::byte> previews;
    Clock::duration busy{};
};

class FailureLog {
public:
    explicit FailureLog(std::size_t limit) : limit_(limit) {}

    void add(const ReadFailure& failure) {
        std::lock_guard lock(mutex_);
        if (records_.size() < limit_) {
            records_.push_back(failure);
        }
    }

    std::vector<ReadFailure> take() {
        std::lock_guard lock(mutex_);
        std::sort(records_.begin(), records_.end(), [](const ReadFailure& a, const ReadFailure& b) { return a.address < b.address; });
        return std::move(records_);
    }

private:
    std::mutex mutex_;
    std::vector<ReadFailure> records_;
    std::size_t limit_;
};

void add_segment(std::vector<Segment>& segments, std::size_t begin, std::size_t end) {
    if (begin >= end) {
        return;
    }
    if (!segments.empty() && segments.back().end == begin) {
        segments.back().end = end;
    } else {
        segments.push_back({begin, end});
    }
}

// Unreadable bytes are accounted only inside the item's own range; look-ahead failures belong to the next item.
class FailureTracker {
public:
    FailureTracker(const WorkItem& item, ReaderTotals& totals, FailureLog& log, ScanProgress& progress)
        : item_(item), totals_(totals), log_(log), progress_(progress) {}
    FailureTracker(const FailureTracker&) = delete;
    FailureTracker& operator=(const FailureTracker&) = delete;
    ~FailureTracker() { flush(); }

    void note(std::uint64_t begin, std::uint64_t end, std::uint32_t error) {
        begin = std::max(begin, item_.own_begin);
        end = std::min(end, item_.own_end);
        if (begin >= end) {
            return;
        }
        if (pending_ && pending_->address + pending_->size == begin && pending_->error == error) {
            pending_->size += end - begin;
            return;
        }
        flush();
        pending_ = ReadFailure{begin, end - begin, error};
    }

    bool any() const noexcept { return seen_ || pending_.has_value(); }

private:
    void flush() {
        if (!pending_) {
            return;
        }
        ++totals_.failures;
        totals_.bytes_unreadable += pending_->size;
        progress_.read_failures.fetch_add(1, std::memory_order_relaxed);
        log_.add(*pending_);
        pending_.reset();
        seen_ = true;
    }

    const WorkItem& item_;
    ReaderTotals& totals_;
    FailureLog& log_;
    ScanProgress& progress_;
    std::optional<ReadFailure> pending_;
    bool seen_ = false;
};

// Returns false once the target process has exited.
bool fill_slot(const MemorySource& source, const WorkItem& item, std::size_t page_size, Slot& slot, ReaderTotals& totals,
               FailureLog& log, ScanProgress& progress) {
    const std::size_t size = item.read_end - item.read_begin;
    const std::span<std::byte> buffer(slot.data.data(), size);
    slot.base = item.read_begin;
    slot.segments.clear();

    ++totals.read_calls;
    const ReadResult bulk = source.read(item.read_begin, buffer);
    add_segment(slot.segments, 0, bulk.bytes);

    bool failed = false;
    if (bulk.bytes < size) {
        // Pages may be decommitted or re-protected after VirtualQueryEx, and a failed bulk read can report
        // fewer bytes than are actually readable; salvage the remainder page by page.
        FailureTracker tracker(item, totals, log, progress);
        std::uint64_t address = item.read_begin + bulk.bytes;
        while (address < item.read_end) {
            const std::uint64_t page_end = std::min<std::uint64_t>(item.read_end, (address / page_size + 1) * page_size);
            const std::size_t offset = address - item.read_begin;
            const std::size_t length = page_end - address;
            ++totals.read_calls;
            const ReadResult part = source.read(address, buffer.subspan(offset, length));
            add_segment(slot.segments, offset, offset + part.bytes);
            if (part.bytes < length) {
                tracker.note(address + part.bytes, page_end, part.error != 0 ? part.error : bulk.error);
                failed = true;
            }
            address = page_end;
        }
    }

    const std::size_t own_begin = item.own_begin - item.read_begin;
    const std::size_t own_end = item.own_end - item.read_begin;
    for (const auto& segment : slot.segments) {
        const std::size_t begin = std::max(own_begin, segment.begin);
        const std::size_t end = std::min(own_end, segment.end);
        totals.bytes_read += end > begin ? end - begin : 0;
    }
    return !failed || source.target_alive();
}

std::uint64_t scan_slot(const Matcher& matcher, const WorkItem& item, const Slot& slot, const EngineConfig& config,
                        std::vector<Hit>& hits, ScannerOutput& out, std::atomic<std::uint64_t>& stored,
                        std::atomic<bool>& truncated) {
    std::uint64_t found = 0;
    const std::size_t own_begin = item.own_begin - slot.base;
    const std::size_t own_end = item.own_end - slot.base;
    for (const Segment& segment : slot.segments) {
        const std::size_t begin = std::max(own_begin, segment.begin);
        const std::size_t end = std::min(own_end, segment.end);
        if (begin >= end) {
            continue;
        }
        const std::span<const std::byte> data(slot.data.data() + segment.begin, segment.end - segment.begin);
        hits.clear();
        matcher.scan(data, slot.base + segment.begin, begin - segment.begin, end - segment.begin, hits);
        if (hits.empty()) {
            continue;
        }
        found += hits.size();
        std::size_t keep = hits.size();
        if (config.max_matches != 0) {
            const std::uint64_t before = stored.fetch_add(hits.size(), std::memory_order_relaxed);
            keep = before >= config.max_matches ? 0 : static_cast<std::size_t>(std::min<std::uint64_t>(hits.size(), config.max_matches - before));
            if (keep < hits.size()) {
                truncated.store(true, std::memory_order_relaxed);
            }
        }
        for (std::size_t k = 0; k < keep; ++k) {
            const Hit& hit = hits[k];
            Match match;
            match.address = slot.base + segment.begin + hit.offset;
            match.length = hit.length;
            match.pattern = hit.pattern;
            const bool full = hit.pattern < config.full_preview.size() && config.full_preview[hit.pattern] != 0;
            const std::size_t take = std::min<std::size_t>(full ? hit.length : config.preview_bytes, data.size() - hit.offset);
            if (take != 0) {
                match.preview_offset = out.previews.size();
                match.preview_size = static_cast<std::uint32_t>(take);
                out.previews.insert(out.previews.end(), data.begin() + static_cast<std::ptrdiff_t>(hit.offset),
                                    data.begin() + static_cast<std::ptrdiff_t>(hit.offset + take));
            }
            out.matches.push_back(match);
        }
    }
    return found;
}

}  // namespace

unsigned default_scan_threads() noexcept {
    return std::max(1u, std::thread::hardware_concurrency());
}

unsigned default_read_threads(unsigned scan_threads) noexcept {
    return std::max(1u, scan_threads / 4);
}

EngineResult run_engine(const MemorySource& source, const Matcher& matcher, std::span<const WorkItem> work,
                        const EngineConfig& config, ScanProgress& progress, std::stop_token stop) {
    const auto started = Clock::now();
    EngineResult result;

    std::uint64_t total = 0;
    std::size_t capacity = 0;
    for (const auto& item : work) {
        total += item.own_end - item.own_begin;
        capacity = std::max<std::size_t>(capacity, item.read_end - item.read_begin);
    }
    progress.bytes_total = total;
    progress.chunks_total = work.size();
    if (work.empty()) {
        return result;
    }

    const auto limit = static_cast<unsigned>(std::min<std::size_t>(work.size(), 1024));
    const unsigned scanners = std::clamp(config.scan_threads != 0 ? config.scan_threads : default_scan_threads(), 1u, limit);
    const unsigned readers = std::clamp(config.read_threads != 0 ? config.read_threads : default_read_threads(scanners), 1u, limit);
    result.scan_threads = scanners;
    result.read_threads = readers;

    const std::size_t slot_count = 2 * std::size_t{scanners} + readers;
    std::vector<Slot> slots(slot_count);
    for (auto& slot : slots) {
        slot.data.resize(capacity);
    }
    BoundedQueue<std::size_t> free_slots(slot_count);
    BoundedQueue<std::size_t> filled(slot_count);
    for (std::size_t i = 0; i < slot_count; ++i) {
        free_slots.push(i, {});
    }

    std::stop_source halt;
    const std::stop_callback forward(stop, [&halt] { halt.request_stop(); });
    const std::stop_token token = halt.get_token();

    std::atomic<std::size_t> next_item{0};
    std::atomic<std::size_t> items_scanned{0};
    std::atomic<unsigned> readers_running{readers};
    std::atomic<bool> target_exited{false};
    std::atomic<bool> truncated{false};
    std::atomic<std::uint64_t> stored{0};
    std::atomic<std::uint64_t> found{0};
    std::vector<ReaderTotals> reader_totals(readers);
    std::vector<ScannerOutput> outputs(scanners);
    FailureLog failure_log(config.max_recorded_failures);
    const std::size_t page_size = std::max<std::size_t>(source.page_size(), 1);

    std::mutex error_mutex;
    std::exception_ptr error;
    const auto record_error = [&](std::exception_ptr exception) {
        {
            std::lock_guard lock(error_mutex);
            if (!error) {
                error = exception;
            }
        }
        halt.request_stop();
    };

    {
        std::vector<std::jthread> threads;
        threads.reserve(readers + scanners);
        for (unsigned r = 0; r < readers; ++r) {
            threads.emplace_back([&, r] {
                try {
                    ReaderTotals& totals = reader_totals[r];
                    while (!token.stop_requested()) {
                        const std::size_t index = next_item.fetch_add(1, std::memory_order_relaxed);
                        if (index >= work.size()) {
                            break;
                        }
                        const auto slot_index = free_slots.pop(token);
                        if (!slot_index) {
                            break;
                        }
                        Slot& slot = slots[*slot_index];
                        slot.item = index;
                        const auto t0 = Clock::now();
                        const bool alive = fill_slot(source, work[index], page_size, slot, totals, failure_log, progress);
                        totals.busy += Clock::now() - t0;
                        if (!alive) {
                            target_exited = true;
                            halt.request_stop();
                            break;
                        }
                        if (!filled.push(*slot_index, token)) {
                            break;
                        }
                    }
                } catch (...) {
                    record_error(std::current_exception());
                }
                // The last reader to finish closes the queue so that scanners drain it and exit.
                if (readers_running.fetch_sub(1) == 1) {
                    filled.close();
                }
            });
        }
        for (unsigned s = 0; s < scanners; ++s) {
            threads.emplace_back([&, s] {
                try {
                    ScannerOutput& out = outputs[s];
                    std::vector<Hit> hits;
                    while (const auto slot_index = filled.pop(token)) {
                        const Slot& slot = slots[*slot_index];
                        const WorkItem& item = work[slot.item];
                        const auto t0 = Clock::now();
                        const std::uint64_t hits_found = scan_slot(matcher, item, slot, config, hits, out, stored, truncated);
                        out.busy += Clock::now() - t0;
                        found.fetch_add(hits_found, std::memory_order_relaxed);
                        progress.matches.fetch_add(hits_found, std::memory_order_relaxed);
                        progress.bytes_done.fetch_add(item.own_end - item.own_begin, std::memory_order_relaxed);
                        progress.chunks_done.fetch_add(1, std::memory_order_relaxed);
                        progress.regions_done.fetch_add(item.regions_finished, std::memory_order_relaxed);
                        items_scanned.fetch_add(1, std::memory_order_relaxed);
                        free_slots.push(*slot_index, {});
                    }
                } catch (...) {
                    record_error(std::current_exception());
                }
            });
        }
    }

    if (error) {
        std::rethrow_exception(error);
    }

    if (items_scanned.load() == work.size()) {
        result.status = ScanStatus::Completed;
    } else if (target_exited.load()) {
        result.status = ScanStatus::TargetExited;
    } else {
        result.status = ScanStatus::Cancelled;
    }

    std::size_t match_count = 0;
    std::size_t preview_bytes = 0;
    for (const auto& out : outputs) {
        match_count += out.matches.size();
        preview_bytes += out.previews.size();
    }
    result.matches.reserve(match_count);
    result.previews.reserve(preview_bytes);
    for (auto& out : outputs) {
        const std::uint64_t shift = result.previews.size();
        for (Match match : out.matches) {
            if (match.preview_size != 0) {
                match.preview_offset += shift;
            }
            result.matches.push_back(match);
        }
        result.previews.insert(result.previews.end(), out.previews.begin(), out.previews.end());
        result.scan_seconds += to_seconds(out.busy);
        out = {};
    }
    for (const auto& totals : reader_totals) {
        result.bytes_read += totals.bytes_read;
        result.bytes_unreadable += totals.bytes_unreadable;
        result.read_calls += totals.read_calls;
        result.read_failures += totals.failures;
        result.read_seconds += to_seconds(totals.busy);
    }
    result.failures = failure_log.take();
    result.matches_found = found.load();
    result.truncated = truncated.load();
    result.wall_seconds = to_seconds(Clock::now() - started);
    return result;
}

}  // namespace mh
