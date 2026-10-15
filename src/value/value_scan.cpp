#include "value/value_scan.hpp"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <bit>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstring>
#include <exception>
#include <mutex>
#include <thread>
#include <type_traits>

#include "common/error.hpp"
#include "memory/segmented_read.hpp"
#include "pipeline/parallel.hpp"

namespace mh {

namespace {

static_assert(std::endian::native == std::endian::little, "candidate values are stored as little-endian bits");

using Clock = std::chrono::steady_clock;

// Sparse candidates closer than this are read together, in reads of at most kSparseGroup bytes.
constexpr std::uint64_t kSparseGap = 4096;
constexpr std::uint64_t kSparseGroup = std::uint64_t{64} << 10;

constexpr bool compares_previous(Compare compare) noexcept {
    return compare == Compare::Increased || compare == Compare::Decreased || compare == Compare::Changed ||
           compare == Compare::Unchanged;
}

template <typename T>
T load(const std::byte* data) noexcept {
    T value;
    std::memcpy(&value, data, sizeof(T));
    return value;
}

std::uint64_t bits_at(const std::byte* data, std::size_t size) noexcept {
    std::uint64_t bits = 0;
    std::memcpy(&bits, data, size);
    return bits;
}

template <typename T, Compare C>
bool passes(const ValueCondition& condition, const std::byte* now, const std::byte* before) noexcept {
    if constexpr (C == Compare::Unknown) {
        return true;
    } else if constexpr (C == Compare::Changed) {
        return std::memcmp(now, before, sizeof(T)) != 0;
    } else if constexpr (C == Compare::Unchanged) {
        return std::memcmp(now, before, sizeof(T)) == 0;
    } else if constexpr (C == Compare::Increased) {
        return load<T>(now) > load<T>(before);
    } else if constexpr (C == Compare::Decreased) {
        return load<T>(now) < load<T>(before);
    } else if constexpr (std::is_floating_point_v<T>) {
        const double value = load<T>(now);
        if constexpr (C == Compare::Exact) {
            return std::fabs(value - condition.number) <= condition.tolerance;
        } else if constexpr (C == Compare::Greater) {
            return value > condition.number;
        } else if constexpr (C == Compare::Less) {
            return value < condition.number;
        } else {
            return condition.number <= value && value <= condition.number_high;
        }
    } else {
        const T value = load<T>(now);
        if constexpr (C == Compare::Exact) {
            return value == static_cast<T>(condition.bits);
        } else if constexpr (C == Compare::Greater) {
            return static_cast<std::int64_t>(value) > condition.integer;
        } else if constexpr (C == Compare::Less) {
            return static_cast<std::int64_t>(value) < condition.integer;
        } else {
            return condition.integer <= value && value <= condition.integer_high;
        }
    }
}

template <typename T, typename F>
decltype(auto) with_compare(Compare compare, F&& f) {
    switch (compare) {
        case Compare::Exact: return f.template operator()<T, Compare::Exact>();
        case Compare::Greater: return f.template operator()<T, Compare::Greater>();
        case Compare::Less: return f.template operator()<T, Compare::Less>();
        case Compare::Between: return f.template operator()<T, Compare::Between>();
        case Compare::Unknown: return f.template operator()<T, Compare::Unknown>();
        case Compare::Increased: return f.template operator()<T, Compare::Increased>();
        case Compare::Decreased: return f.template operator()<T, Compare::Decreased>();
        case Compare::Changed: return f.template operator()<T, Compare::Changed>();
        case Compare::Unchanged: return f.template operator()<T, Compare::Unchanged>();
    }
    throw Error(ErrorCode::InvalidArgument, "unknown comparison");
}

// Calls f.template operator()<T, C>() with the C++ type of `type` and the comparison as a constant.
template <typename F>
decltype(auto) dispatch(ValueType type, Compare compare, F&& f) {
    switch (type) {
        case ValueType::Int8: return with_compare<std::int8_t>(compare, f);
        case ValueType::Int16: return with_compare<std::int16_t>(compare, f);
        case ValueType::Int32: return with_compare<std::int32_t>(compare, f);
        case ValueType::Int64: return with_compare<std::int64_t>(compare, f);
        case ValueType::Float: return with_compare<float>(compare, f);
        case ValueType::Double: return with_compare<double>(compare, f);
    }
    throw Error(ErrorCode::InvalidArgument, "unknown value type");
}

std::uint64_t bitmap_words(std::uint64_t positions) noexcept {
    return (positions + 63) / 64;
}

void set_bit(std::vector<std::uint64_t>& words, std::uint64_t index) noexcept {
    words[index / 64] |= std::uint64_t{1} << (index % 64);
}

void set_bits(std::vector<std::uint64_t>& words, std::uint64_t begin, std::uint64_t end) noexcept {
    for (std::uint64_t i = begin; i < end && i % 64 != 0; ++i) {
        set_bit(words, i);
        begin = i + 1;
    }
    for (; begin + 64 <= end; begin += 64) {
        words[begin / 64] = ~std::uint64_t{0};
    }
    for (; begin < end; ++begin) {
        set_bit(words, begin);
    }
}

template <typename F>
void for_each_bit(const std::vector<std::uint64_t>& words, F&& f) {
    for (std::size_t w = 0; w < words.size(); ++w) {
        for (std::uint64_t word = words[w]; word != 0; word &= word - 1) {
            f(w * 64 + static_cast<std::uint64_t>(std::countr_zero(word)));
        }
    }
}

struct Worker {
    std::vector<std::byte> buffer;
    std::vector<Segment> segments;
    std::uint64_t bytes_read = 0;
    std::uint64_t read_calls = 0;
    std::uint64_t read_failures = 0;
};

// What one chunk keeps: a dense block (count > 0) or sparse entries.
struct ChunkOutput {
    DenseValues dense;
    std::vector<ValueCandidate> sparse;
};

struct Shared {
    const MemorySource& source;
    std::size_t page_size;
    std::uint64_t budget;
    ScanProgress& progress;
    std::atomic<std::uint64_t> stored{0};
    std::atomic<bool> exited{false};
    std::atomic<bool> over_budget{false};

    // Reads into the worker's buffer; false once the target has exited.
    bool read(Worker& worker, std::uint64_t address, std::size_t length) {
        worker.buffer.resize(length);
        worker.bytes_read += length;
        if (read_segments(source, address, worker.buffer, page_size, worker.segments, worker.read_calls)) {
            return true;
        }
        ++worker.read_failures;
        progress.read_failures.fetch_add(1, std::memory_order_relaxed);
        if (!source.target_alive()) {
            exited = true;
            return false;
        }
        return true;
    }

    bool reserve(std::uint64_t bytes) {
        const std::uint64_t total = stored.fetch_add(bytes, std::memory_order_relaxed) + bytes;
        if (budget != 0 && total > budget) {
            over_budget = true;
            return false;
        }
        return true;
    }
};

// Keeps `block` (whose alive bits and count are final) as it is or as sparse entries, whichever is smaller;
// `bytes` holds the values to remember and moves into the block when it stays dense.
bool settle(Shared& shared, DenseValues block, std::size_t size, std::vector<std::byte>& bytes, std::size_t step,
            ChunkOutput& output) {
    if (block.count == 0) {
        return true;
    }
    const std::uint64_t dense_bytes = bytes.size() + block.alive.size() * sizeof(std::uint64_t);
    const std::uint64_t sparse_bytes = block.count * sizeof(ValueCandidate);
    if (sparse_bytes < dense_bytes) {
        if (!shared.reserve(sparse_bytes)) {
            return false;
        }
        output.sparse.reserve(block.count);
        for_each_bit(block.alive, [&](std::uint64_t i) {
            const std::uint64_t address = block.first + i * step;
            output.sparse.push_back({address, bits_at(bytes.data() + (address - block.base), size)});
        });
        return true;
    }
    if (!shared.reserve(dense_bytes)) {
        return false;
    }
    block.bytes = std::move(bytes);
    bytes.clear();
    output.dense = std::move(block);
    return true;
}

ValueScanStatus final_status(std::size_t done, std::size_t items, const Shared& shared) {
    if (done == items) {
        return ValueScanStatus::Completed;
    }
    if (shared.exited.load()) {
        return ValueScanStatus::TargetExited;
    }
    return shared.over_budget.load() ? ValueScanStatus::OverBudget : ValueScanStatus::Cancelled;
}

void finish(ValueScanResult& result, const std::vector<Worker>& workers, const Shared& shared, Clock::time_point started) {
    for (const Worker& worker : workers) {
        result.bytes_read += worker.bytes_read;
        result.read_calls += worker.read_calls;
        result.read_failures += worker.read_failures;
    }
    if (result.status == ValueScanStatus::OverBudget) {
        result.needed_bytes = shared.stored.load();
    }
    result.threads = static_cast<unsigned>(workers.size());
    result.seconds = std::chrono::duration<double>(Clock::now() - started).count();
}

// Concatenates the chunk outputs in address order.
void collect(std::vector<ChunkOutput>& outputs, ValueCandidates& candidates) {
    std::size_t sparse = 0;
    for (const ChunkOutput& output : outputs) {
        sparse += output.sparse.size();
    }
    candidates.sparse.reserve(candidates.sparse.size() + sparse);
    for (ChunkOutput& output : outputs) {
        if (output.dense.count != 0) {
            candidates.dense.push_back(std::move(output.dense));
        }
        candidates.sparse.insert(candidates.sparse.end(), output.sparse.begin(), output.sparse.end());
    }
}

struct Chunk {
    std::uint64_t begin = 0;
    std::uint64_t end = 0;
    std::uint64_t read_end = 0;
    std::uint64_t first = 0;
    std::uint64_t positions = 0;
};

std::vector<Chunk> split_chunks(const std::vector<AddressRange>& spans, std::size_t chunk_size, std::size_t size,
                                std::size_t step) {
    std::vector<Chunk> chunks;
    for (const AddressRange& span : spans) {
        for (std::uint64_t begin = span.begin; begin < span.end; begin += chunk_size) {
            Chunk chunk;
            chunk.begin = begin;
            chunk.end = std::min<std::uint64_t>(span.end, begin + chunk_size);
            chunk.read_end = std::min<std::uint64_t>(span.end, chunk.end + size - 1);
            chunk.first = (begin + step - 1) / step * step;
            if (chunk.read_end >= chunk.first + size) {
                chunk.positions = (chunk.read_end - size - chunk.first) / step + 1;
            }
            if (chunk.positions != 0) {
                chunks.push_back(chunk);
            }
        }
    }
    return chunks;
}

template <typename T, Compare C>
void mark_first(const ValueCondition& condition, const Chunk& chunk, const Worker& worker, std::size_t step, DenseValues& block) {
    constexpr std::size_t size = sizeof(T);
    for (const Segment& segment : worker.segments) {
        const std::uint64_t low = chunk.begin + segment.begin;
        const std::uint64_t high = chunk.begin + segment.end;
        if (high < low + size || high - size < chunk.first) {
            continue;
        }
        const std::uint64_t begin = low <= chunk.first ? 0 : (low - chunk.first + step - 1) / step;
        const std::uint64_t end = std::min(chunk.positions, (high - size - chunk.first) / step + 1);
        if (begin >= end) {
            continue;
        }
        if constexpr (C == Compare::Unknown) {
            set_bits(block.alive, begin, end);
            block.count += end - begin;
        } else if constexpr (!compares_previous(C)) {
            const std::byte* data = worker.buffer.data() + (chunk.first - chunk.begin);
            for (std::uint64_t i = begin; i < end; ++i) {
                if (passes<T, C>(condition, data + i * step, nullptr)) {
                    set_bit(block.alive, i);
                    ++block.count;
                }
            }
        }
    }
}

template <typename T, Compare C>
void mark_next(const ValueCondition& condition, const DenseValues& old, const Worker& worker, std::size_t step,
               DenseValues& block) {
    std::size_t cursor = 0;
    for_each_bit(old.alive, [&](std::uint64_t i) {
        const std::size_t offset = old.first - old.base + i * step;
        if (segment_covers(worker.segments, cursor, offset, offset + sizeof(T)) &&
            passes<T, C>(condition, worker.buffer.data() + offset, old.bytes.data() + offset)) {
            set_bit(block.alive, i);
            ++block.count;
        }
    });
}

// Sparse candidates re-read together.
struct Group {
    std::size_t first = 0;
    std::size_t last = 0;
    std::uint64_t begin = 0;
    std::uint64_t end = 0;
};

std::vector<Group> group_sparse(const std::vector<ValueCandidate>& sparse, std::size_t size) {
    std::vector<Group> groups;
    for (std::size_t i = 0; i < sparse.size();) {
        std::size_t j = i + 1;
        while (j < sparse.size() && sparse[j].address - sparse[j - 1].address <= kSparseGap &&
               sparse[j].address + size - sparse[i].address <= kSparseGroup) {
            ++j;
        }
        groups.push_back({i, j, sparse[i].address, sparse[j - 1].address + size});
        i = j;
    }
    return groups;
}

template <typename T, Compare C>
std::uint64_t recheck_group(const ValueCondition& condition, const std::vector<ValueCandidate>& sparse, const Group& group,
                            const Worker& worker, std::vector<ValueCandidate>& rechecked, std::vector<std::uint8_t>& keep) {
    std::uint64_t kept = 0;
    std::size_t cursor = 0;
    for (std::size_t e = group.first; e < group.last; ++e) {
        const std::size_t offset = sparse[e].address - group.begin;
        const std::byte* now = worker.buffer.data() + offset;
        if (segment_covers(worker.segments, cursor, offset, offset + sizeof(T)) &&
            passes<T, C>(condition, now, reinterpret_cast<const std::byte*>(&sparse[e].previous))) {
            rechecked[e] = {sparse[e].address, bits_at(now, sizeof(T))};
            keep[e] = 1;
            ++kept;
        }
    }
    return kept;
}

}  // namespace

std::size_t size_of(ValueType type) noexcept {
    switch (type) {
        case ValueType::Int8: return 1;
        case ValueType::Int16: return 2;
        case ValueType::Int32: return 4;
        case ValueType::Int64: return 8;
        case ValueType::Float: return 4;
        case ValueType::Double: return 8;
    }
    return 1;
}

bool is_float(ValueType type) noexcept {
    return type == ValueType::Float || type == ValueType::Double;
}

std::string_view to_string(ValueType type) {
    switch (type) {
        case ValueType::Int8: return "int8";
        case ValueType::Int16: return "int16";
        case ValueType::Int32: return "int32";
        case ValueType::Int64: return "int64";
        case ValueType::Float: return "float";
        case ValueType::Double: return "double";
    }
    return "?";
}

std::string_view to_string(Compare compare) {
    switch (compare) {
        case Compare::Exact: return "exact";
        case Compare::Greater: return "greater";
        case Compare::Less: return "less";
        case Compare::Between: return "between";
        case Compare::Unknown: return "unknown";
        case Compare::Increased: return "increased";
        case Compare::Decreased: return "decreased";
        case Compare::Changed: return "changed";
        case Compare::Unchanged: return "unchanged";
    }
    return "?";
}

bool needs_previous(Compare compare) noexcept {
    return compares_previous(compare);
}

bool matches_condition(ValueType type, const ValueCondition& condition, std::span<const std::byte> bytes) {
    if (needs_previous(condition.compare)) {
        throw Error(ErrorCode::InvalidArgument, "comparison '" + std::string(to_string(condition.compare)) + "' needs a previous scan");
    }
    if (bytes.size() < size_of(type)) {
        return false;
    }
    return dispatch(type, condition.compare, [&]<typename T, Compare C>() {
        if constexpr (compares_previous(C)) {
            return false;
        } else {
            return passes<T, C>(condition, bytes.data(), nullptr);
        }
    });
}

std::uint64_t ValueCandidates::count() const noexcept {
    std::uint64_t total = sparse.size();
    for (const DenseValues& block : dense) {
        total += block.count;
    }
    return total;
}

std::uint64_t ValueCandidates::stored_bytes() const noexcept {
    std::uint64_t total = sparse.size() * sizeof(ValueCandidate);
    for (const DenseValues& block : dense) {
        total += block.stored_bytes();
    }
    return total;
}

const Region* ValueCandidates::region_of(std::uint64_t address) const {
    const auto after = std::upper_bound(regions.begin(), regions.end(), address,
                                        [](std::uint64_t value, const Region& region) { return value < region.base; });
    if (after == regions.begin()) {
        return nullptr;
    }
    const Region& region = *std::prev(after);
    return address < region.end() ? &region : nullptr;
}

std::vector<ValueCandidate> ValueCandidates::list(std::size_t limit) const {
    std::vector<ValueCandidate> out;
    out.reserve(static_cast<std::size_t>(std::min<std::uint64_t>(limit, count())));
    const std::size_t size = size_of(type);
    std::size_t s = 0;
    for (const DenseValues& block : dense) {
        while (s < sparse.size() && sparse[s].address < block.base && out.size() < limit) {
            out.push_back(sparse[s++]);
        }
        for (std::size_t w = 0; w < block.alive.size() && out.size() < limit; ++w) {
            for (std::uint64_t word = block.alive[w]; word != 0 && out.size() < limit; word &= word - 1) {
                const std::uint64_t address = block.first + (w * 64 + static_cast<std::uint64_t>(std::countr_zero(word))) * step();
                out.push_back({address, bits_at(block.bytes.data() + (address - block.base), size)});
            }
        }
    }
    while (s < sparse.size() && out.size() < limit) {
        out.push_back(sparse[s++]);
    }
    return out;
}

ValueScanResult first_value_scan(const MemorySource& source, const ScanPlan& plan, ValueType type, bool aligned,
                                 const ValueCondition& condition, const ValueScanOptions& options, ScanProgress& progress,
                                 std::stop_token stop) {
    if (needs_previous(condition.compare)) {
        throw Error(ErrorCode::InvalidArgument, "comparison '" + std::string(to_string(condition.compare)) + "' needs a previous scan");
    }
    const auto started = Clock::now();
    ValueScanResult result;
    ValueCandidates& candidates = result.candidates;
    candidates.type = type;
    candidates.aligned = aligned;
    candidates.scans = 1;
    candidates.regions = plan.regions;

    const std::size_t size = size_of(type);
    const std::size_t step = candidates.step();
    const std::size_t chunk_size = std::max<std::size_t>(options.chunk_size, 64);
    const std::vector<Chunk> chunks = split_chunks(plan.spans, chunk_size, size, step);

    std::uint64_t total = 0;
    std::uint64_t estimate = 0;
    for (const Chunk& chunk : chunks) {
        total += chunk.read_end - chunk.begin;
        estimate += chunk.read_end - chunk.begin + bitmap_words(chunk.positions) * sizeof(std::uint64_t);
    }
    progress.bytes_total = total;
    progress.chunks_total = chunks.size();
    if (condition.compare == Compare::Unknown && options.memory_budget != 0 && estimate > options.memory_budget) {
        result.status = ValueScanStatus::OverBudget;
        result.needed_bytes = estimate;
        return result;
    }
    if (chunks.empty()) {
        return result;
    }

    Shared shared{source, std::max<std::size_t>(source.page_size(), 1), options.memory_budget, progress};
    std::vector<Worker> workers(worker_count(options.threads, chunks.size()));
    std::vector<ChunkOutput> outputs(chunks.size());
    const std::size_t done = parallel_items(chunks.size(), workers, std::move(stop), [&](std::size_t index, Worker& worker) {
        const Chunk& chunk = chunks[index];
        if (!shared.read(worker, chunk.begin, chunk.read_end - chunk.begin)) {
            return false;
        }
        DenseValues block;
        block.base = chunk.begin;
        block.first = chunk.first;
        block.positions = chunk.positions;
        block.alive.assign(bitmap_words(chunk.positions), 0);
        dispatch(type, condition.compare,
                 [&]<typename T, Compare C>() { mark_first<T, C>(condition, chunk, worker, step, block); });
        const std::uint64_t count = block.count;
        if (!settle(shared, std::move(block), size, worker.buffer, step, outputs[index])) {
            return false;
        }
        progress.matches.fetch_add(count, std::memory_order_relaxed);
        progress.bytes_done.fetch_add(chunk.read_end - chunk.begin, std::memory_order_relaxed);
        progress.chunks_done.fetch_add(1, std::memory_order_relaxed);
        return true;
    });

    result.status = final_status(done, chunks.size(), shared);
    collect(outputs, candidates);
    finish(result, workers, shared, started);
    return result;
}

ValueScanResult next_value_scan(const MemorySource& source, const ValueCandidates& previous, const ValueCondition& condition,
                                const ValueScanOptions& options, ScanProgress& progress, std::stop_token stop) {
    if (condition.compare == Compare::Unknown) {
        throw Error(ErrorCode::InvalidArgument, "comparison 'unknown' is only valid for the first scan");
    }
    const auto started = Clock::now();
    ValueScanResult result;
    ValueCandidates& candidates = result.candidates;
    candidates.type = previous.type;
    candidates.aligned = previous.aligned;
    candidates.scans = previous.scans + 1;
    candidates.regions = previous.regions;

    const std::size_t size = size_of(previous.type);
    const std::size_t step = previous.step();
    const std::vector<Group> groups = group_sparse(previous.sparse, size);
    const std::size_t items = previous.dense.size() + groups.size();

    std::uint64_t total = 0;
    for (const DenseValues& block : previous.dense) {
        total += block.bytes.size();
    }
    for (const Group& group : groups) {
        total += group.end - group.begin;
    }
    progress.bytes_total = total;
    progress.chunks_total = items;
    if (items == 0) {
        return result;
    }

    // A next scan never grows the list, so the budget is not checked again.
    Shared shared{source, std::max<std::size_t>(source.page_size(), 1), 0, progress};
    std::vector<Worker> workers(worker_count(options.threads, items));
    std::vector<ChunkOutput> outputs(previous.dense.size());
    std::vector<ValueCandidate> rechecked(previous.sparse.size());
    std::vector<std::uint8_t> keep(previous.sparse.size(), 0);
    const std::size_t done = parallel_items(items, workers, std::move(stop), [&](std::size_t index, Worker& worker) {
        std::uint64_t length = 0;
        std::uint64_t kept = 0;
        if (index < previous.dense.size()) {
            const DenseValues& old = previous.dense[index];
            length = old.bytes.size();
            if (!shared.read(worker, old.base, length)) {
                return false;
            }
            DenseValues block;
            block.base = old.base;
            block.first = old.first;
            block.positions = old.positions;
            block.alive.assign(old.alive.size(), 0);
            dispatch(previous.type, condition.compare,
                     [&]<typename T, Compare C>() { mark_next<T, C>(condition, old, worker, step, block); });
            kept = block.count;
            if (!settle(shared, std::move(block), size, worker.buffer, step, outputs[index])) {
                return false;
            }
        } else {
            const Group& group = groups[index - previous.dense.size()];
            length = group.end - group.begin;
            if (!shared.read(worker, group.begin, length)) {
                return false;
            }
            kept = dispatch(previous.type, condition.compare, [&]<typename T, Compare C>() {
                return recheck_group<T, C>(condition, previous.sparse, group, worker, rechecked, keep);
            });
        }
        progress.matches.fetch_add(kept, std::memory_order_relaxed);
        progress.bytes_done.fetch_add(length, std::memory_order_relaxed);
        progress.chunks_done.fetch_add(1, std::memory_order_relaxed);
        return true;
    });

    result.status = final_status(done, items, shared);
    collect(outputs, candidates);
    const std::size_t converted = candidates.sparse.size();
    for (std::size_t e = 0; e < rechecked.size(); ++e) {
        if (keep[e] != 0) {
            candidates.sparse.push_back(rechecked[e]);
        }
    }
    std::inplace_merge(candidates.sparse.begin(), candidates.sparse.begin() + static_cast<std::ptrdiff_t>(converted),
                       candidates.sparse.end(),
                       [](const ValueCandidate& a, const ValueCandidate& b) { return a.address < b.address; });
    finish(result, workers, shared, started);
    return result;
}

std::optional<std::uint64_t> ValueCandidates::value_at(std::uint64_t address) const {
    const auto entry = std::lower_bound(sparse.begin(), sparse.end(), address,
                                        [](const ValueCandidate& candidate, std::uint64_t value) { return candidate.address < value; });
    if (entry != sparse.end() && entry->address == address) {
        return entry->previous;
    }
    const auto after = std::upper_bound(dense.begin(), dense.end(), address,
                                        [](std::uint64_t value, const DenseValues& block) { return value < block.first; });
    if (after == dense.begin()) {
        return std::nullopt;
    }
    const DenseValues& block = *std::prev(after);
    const std::uint64_t offset = address - block.first;
    const std::uint64_t index = offset / step();
    if (offset % step() != 0 || index >= block.positions || ((block.alive[index / 64] >> (index % 64)) & 1) == 0) {
        return std::nullopt;
    }
    return bits_at(block.bytes.data() + (address - block.base), size_of(type));
}

std::uint64_t value_memory_budget() {
    MEMORYSTATUSEX status{};
    status.dwLength = sizeof(status);
    if (GlobalMemoryStatusEx(&status) == 0) {
        throw_win32(ErrorCode::SystemError, "GlobalMemoryStatusEx", GetLastError());
    }
    return status.ullAvailPhys / 3;
}

std::string format_value(ValueType type, std::uint64_t bits) {
    char text[64];
    std::to_chars_result written{};
    switch (type) {
        case ValueType::Int8: return std::to_string(static_cast<std::int8_t>(bits));
        case ValueType::Int16: return std::to_string(static_cast<std::int16_t>(bits));
        case ValueType::Int32: return std::to_string(static_cast<std::int32_t>(bits));
        case ValueType::Int64: return std::to_string(static_cast<std::int64_t>(bits));
        case ValueType::Float:
            written = std::to_chars(text, text + sizeof(text), std::bit_cast<float>(static_cast<std::uint32_t>(bits)));
            break;
        case ValueType::Double: written = std::to_chars(text, text + sizeof(text), std::bit_cast<double>(bits)); break;
    }
    return written.ec == std::errc{} ? std::string(text, written.ptr) : std::string("?");
}

}  // namespace mh
