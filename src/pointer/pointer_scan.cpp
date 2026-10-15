#include "pointer/pointer_scan.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <limits>
#include <map>
#include <string>

#include "common/error.hpp"
#include "memory/segmented_read.hpp"
#include "pipeline/parallel.hpp"

namespace mh {

namespace {

using Clock = std::chrono::steady_clock;

// Map entries or nodes per work item of the search.
constexpr std::size_t kSearchItem = std::size_t{1} << 16;
constexpr std::size_t kCheckItem = 4096;

// A pointer in memory: its value and where it is stored.
struct Pointer {
    std::uint64_t value = 0;
    std::uint64_t address = 0;
};

bool by_value(const Pointer& a, const Pointer& b) noexcept {
    return a.value != b.value ? a.value < b.value : a.address < b.address;
}

bool by_address(const Pointer& a, const Pointer& b) noexcept {
    return a.address < b.address;
}

std::uint64_t saturating_add(std::uint64_t a, std::uint64_t b) noexcept {
    return a > std::numeric_limits<std::uint64_t>::max() - b ? std::numeric_limits<std::uint64_t>::max() : a + b;
}

std::uint64_t load_pointer(const std::byte* data, unsigned pointer_size) noexcept {
    std::uint64_t value = 0;
    std::memcpy(&value, data, pointer_size);
    return value;
}

class SpanSet {
public:
    explicit SpanSet(std::span<const AddressRange> spans) : spans_(spans) {
        if (!spans.empty()) {
            low_ = spans.front().begin;
            high_ = spans.back().end;
        }
    }

    bool contains(std::uint64_t value) const noexcept {
        if (value < low_ || value >= high_) {
            return false;
        }
        const auto after = std::upper_bound(spans_.begin(), spans_.end(), value,
                                            [](std::uint64_t v, const AddressRange& range) { return v < range.begin; });
        return after != spans_.begin() && value < std::prev(after)->end;
    }

private:
    std::span<const AddressRange> spans_;
    std::uint64_t low_ = 0;
    std::uint64_t high_ = 0;
};

struct Budget {
    std::uint64_t limit = 0;
    std::atomic<std::uint64_t> used{0};
    std::atomic<bool> over{false};

    bool take(std::uint64_t bytes) {
        const std::uint64_t total = used.fetch_add(bytes, std::memory_order_relaxed) + bytes;
        if (limit != 0 && total > limit) {
            over = true;
            return false;
        }
        return true;
    }
};

struct Chunk {
    std::uint64_t begin = 0;
    std::uint64_t end = 0;
    std::uint64_t read_end = 0;
};

struct Reader {
    std::vector<std::byte> buffer;
    std::vector<Segment> segments;
    std::vector<Pointer> found;
    std::uint64_t bytes_read = 0;
    std::uint64_t read_calls = 0;
    std::uint64_t read_failures = 0;
};

std::vector<Chunk> split_chunks(std::span<const AddressRange> spans, std::size_t chunk_size, unsigned pointer_size) {
    std::vector<Chunk> chunks;
    for (const AddressRange& span : spans) {
        for (std::uint64_t begin = span.begin; begin < span.end; begin += chunk_size) {
            Chunk chunk;
            chunk.begin = begin;
            chunk.end = std::min<std::uint64_t>(span.end, begin + chunk_size);
            chunk.read_end = std::min<std::uint64_t>(span.end, chunk.end + pointer_size - 1);
            chunks.push_back(chunk);
        }
    }
    return chunks;
}

void collect_pointers(const Chunk& chunk, Reader& reader, const SpanSet& spans, unsigned pointer_size) {
    for (const Segment& segment : reader.segments) {
        const std::uint64_t low = chunk.begin + segment.begin;
        const std::uint64_t high = chunk.begin + segment.end;
        for (std::uint64_t address = (low + pointer_size - 1) / pointer_size * pointer_size;
             address < chunk.end && address + pointer_size <= high; address += pointer_size) {
            const std::uint64_t value = load_pointer(reader.buffer.data() + (address - chunk.begin), pointer_size);
            if (spans.contains(value)) {
                reader.found.push_back({value, address});
            }
        }
    }
}

// Sorts each run by value on its own thread, then merges pairs of runs until one is left. False when stopped.
bool sort_runs(std::vector<std::vector<Pointer>>& runs, unsigned threads, std::stop_token stop) {
    std::vector<int> lanes(worker_count(threads, runs.size()));
    if (parallel_items(runs.size(), lanes, stop, [&](std::size_t i, int&) {
            std::sort(runs[i].begin(), runs[i].end(), by_value);
            return true;
        }) != runs.size()) {
        return false;
    }
    while (runs.size() > 1) {
        std::vector<std::vector<Pointer>> merged((runs.size() + 1) / 2);
        lanes.resize(worker_count(threads, merged.size()));
        const std::size_t done = parallel_items(merged.size(), lanes, stop, [&](std::size_t i, int&) {
            if (2 * i + 1 == runs.size()) {
                merged[i] = std::move(runs[2 * i]);
                return true;
            }
            std::vector<Pointer>& a = runs[2 * i];
            std::vector<Pointer>& b = runs[2 * i + 1];
            merged[i].resize(a.size() + b.size());
            std::merge(a.begin(), a.end(), b.begin(), b.end(), merged[i].begin(), by_value);
            std::vector<Pointer>().swap(a);
            std::vector<Pointer>().swap(b);
            return true;
        });
        if (done != merged.size()) {
            return false;
        }
        runs = std::move(merged);
    }
    return true;
}

// The addresses at one distance from the target, sorted by address: those that lead on and the image addresses
// where chains start.
struct Level {
    std::vector<Pointer> onward;
    std::vector<Pointer> bases;
    // Chains from each onward node to the target.
    std::vector<std::uint64_t> paths;
};

// [first, last) of the onward nodes that a pointer with this value reaches.
std::pair<std::size_t, std::size_t> reached(const std::vector<Pointer>& onward, std::uint64_t value, std::uint32_t max_offset) {
    const auto first = std::lower_bound(onward.begin(), onward.end(), value,
                                        [](const Pointer& node, std::uint64_t v) { return node.address < v; });
    const std::uint64_t limit = saturating_add(value, max_offset);
    auto last = first;
    while (last != onward.end() && last->address <= limit) {
        ++last;
    }
    return {static_cast<std::size_t>(first - onward.begin()), static_cast<std::size_t>(last - onward.begin())};
}

// Index ranges of `map` whose values reach one of the nodes.
std::vector<std::pair<std::size_t, std::size_t>> reaching(const std::vector<Pointer>& map, const std::vector<Pointer>& nodes,
                                                          std::uint32_t max_offset) {
    std::vector<std::pair<std::uint64_t, std::uint64_t>> values;
    for (const Pointer& node : nodes) {
        const std::uint64_t low = node.address >= max_offset ? node.address - max_offset : 0;
        if (!values.empty() && low <= values.back().second + 1) {
            values.back().second = node.address;
        } else {
            values.emplace_back(low, node.address);
        }
    }
    std::vector<std::pair<std::size_t, std::size_t>> items;
    for (const auto& [low, high] : values) {
        const auto first = std::lower_bound(map.begin(), map.end(), low,
                                            [](const Pointer& entry, std::uint64_t v) { return entry.value < v; });
        const auto last = std::upper_bound(first, map.end(), high,
                                           [](std::uint64_t v, const Pointer& entry) { return v < entry.value; });
        for (auto at = first; at < last; at += std::min<std::ptrdiff_t>(last - at, kSearchItem)) {
            const auto end = at + std::min<std::ptrdiff_t>(last - at, kSearchItem);
            items.emplace_back(static_cast<std::size_t>(at - map.begin()), static_cast<std::size_t>(end - map.begin()));
        }
    }
    return items;
}

class Search {
public:
    Search(const std::vector<Pointer>& map, const ModuleMap& modules, std::uint64_t target, const PointerScanOptions& options,
           Budget& budget, PointerScanProgress& progress)
        : map_(map), modules_(modules), target_(target), options_(options), budget_(budget), progress_(progress) {}

    // False when stopped or over the budget.
    bool run(std::stop_token stop) {
        if (!budget_.take(map_.size())) {
            return false;
        }
        visited_.assign(map_.size(), 0);
        levels_.resize(1);
        if (modules_.locate(target_) != nullptr) {
            levels_[0].bases.push_back({0, target_});
            total_ = 1;
        } else {
            levels_[0].onward.push_back({0, target_});
            levels_[0].paths.push_back(1);
        }
        for (unsigned depth = 1; depth <= options_.depth && !levels_.back().onward.empty(); ++depth) {
            progress_.level = depth;
            if (!expand(depth, stop) || !count(depth, stop)) {
                return false;
            }
        }
        return true;
    }

    const std::vector<Level>& levels() const noexcept { return levels_; }

    std::uint64_t total() const noexcept { return total_; }

private:
    bool expand(unsigned depth, std::stop_token stop) {
        const auto items = reaching(map_, levels_.back().onward, options_.max_offset);
        const bool last = depth == options_.depth;
        std::vector<Level> found(items.size());
        std::vector<int> lanes(worker_count(options_.threads, items.size()));
        const std::size_t done = parallel_items(items.size(), lanes, stop, [&](std::size_t index, int&) {
            Level& out = found[index];
            for (std::size_t e = items[index].first; e < items[index].second; ++e) {
                const Pointer& entry = map_[e];
                if (visited_[e] != 0 || entry.address == target_) {
                    continue;
                }
                visited_[e] = 1;
                if (modules_.locate(entry.address) != nullptr) {
                    out.bases.push_back(entry);
                } else if (!last) {
                    out.onward.push_back(entry);
                }
            }
            return budget_.take((out.bases.size() + out.onward.size()) * sizeof(Pointer) + out.onward.size() * sizeof(std::uint64_t));
        });
        if (done != items.size()) {
            return false;
        }
        Level level;
        for (Level& part : found) {
            level.onward.insert(level.onward.end(), part.onward.begin(), part.onward.end());
            level.bases.insert(level.bases.end(), part.bases.begin(), part.bases.end());
            part = {};
        }
        std::sort(level.onward.begin(), level.onward.end(), by_address);
        std::sort(level.bases.begin(), level.bases.end(), by_address);
        progress_.nodes.fetch_add(level.onward.size() + level.bases.size(), std::memory_order_relaxed);
        levels_.push_back(std::move(level));
        return true;
    }

    // Chains from the nodes of the newest level to the target.
    bool count(unsigned depth, std::stop_token stop) {
        Level& level = levels_[depth];
        const Level& below = levels_[depth - 1];
        const std::size_t nodes = level.onward.size() + level.bases.size();
        const std::size_t items = (nodes + kSearchItem - 1) / kSearchItem;
        level.paths.assign(level.onward.size(), 0);
        std::vector<std::uint64_t> sums(items, 0);
        std::vector<int> lanes(worker_count(options_.threads, items));
        const std::size_t done = parallel_items(items, lanes, stop, [&](std::size_t index, int&) {
            const std::size_t end = std::min(nodes, (index + 1) * kSearchItem);
            for (std::size_t n = index * kSearchItem; n < end; ++n) {
                const bool onward = n < level.onward.size();
                const Pointer& node = onward ? level.onward[n] : level.bases[n - level.onward.size()];
                const auto [first, last] = reached(below.onward, node.value, options_.max_offset);
                std::uint64_t paths = 0;
                for (std::size_t c = first; c < last; ++c) {
                    paths = saturating_add(paths, below.paths[c]);
                }
                if (onward) {
                    level.paths[n] = paths;
                } else {
                    sums[index] = saturating_add(sums[index], paths);
                }
            }
            return true;
        });
        for (const std::uint64_t sum : sums) {
            total_ = saturating_add(total_, sum);
        }
        return done == items;
    }

    const std::vector<Pointer>& map_;
    const ModuleMap& modules_;
    std::uint64_t target_;
    const PointerScanOptions& options_;
    Budget& budget_;
    PointerScanProgress& progress_;
    std::vector<std::uint8_t> visited_;
    std::vector<Level> levels_;
    std::uint64_t total_ = 0;
};

class Lister {
public:
    Lister(const std::vector<Level>& levels, const ModuleMap& modules, const PointerScanOptions& options, PointerChains& out)
        : levels_(levels), modules_(modules), options_(options), out_(out) {}

    // False when stopped.
    bool run(std::stop_token stop) {
        if (levels_[0].bases.size() == 1) {
            start(levels_[0].bases[0]);
            emit(0);
        }
        for (std::size_t depth = 1; depth < levels_.size() && !full(); ++depth) {
            for (const Pointer& base : levels_[depth].bases) {
                if (full()) {
                    break;
                }
                if (stop.stop_requested()) {
                    return false;
                }
                start(base);
                walk(base.value, depth, 0);
            }
        }
        return true;
    }

private:
    bool full() const noexcept { return out_.chains.size() >= options_.max_chains; }

    void start(const Pointer& base) {
        const Module* module = modules_.locate(base.address);
        const auto [at, added] = indices_.try_emplace(module, static_cast<std::uint16_t>(out_.modules.size()));
        if (added) {
            out_.modules.push_back(module->name);
        }
        chain_ = {};
        chain_.module = at->second;
        chain_.base_offset = base.address - module->base;
    }

    void walk(std::uint64_t value, std::size_t level, std::size_t step) {
        const std::vector<Pointer>& onward = levels_[level - 1].onward;
        const auto [first, last] = reached(onward, value, options_.max_offset);
        for (std::size_t c = first; c < last && !full(); ++c) {
            chain_.offsets[step] = static_cast<std::uint32_t>(onward[c].address - value);
            if (level == 1) {
                emit(step + 1);
            } else {
                walk(onward[c].value, level - 1, step + 1);
            }
        }
    }

    void emit(std::size_t depth) {
        chain_.depth = static_cast<std::uint8_t>(depth);
        out_.chains.push_back(chain_);
    }

    const std::vector<Level>& levels_;
    const ModuleMap& modules_;
    const PointerScanOptions& options_;
    PointerChains& out_;
    std::map<const Module*, std::uint16_t> indices_;
    PointerChain chain_;
};

PointerScanStatus stopped_status(const MemorySource& source, bool exited, const Budget& budget) {
    if (exited || !source.target_alive()) {
        return PointerScanStatus::TargetExited;
    }
    return budget.over.load() ? PointerScanStatus::OverBudget : PointerScanStatus::Cancelled;
}

// Reads the pointer at each step, reusing the reads of the previous chain where the addresses are the same.
class CachedResolver {
public:
    std::optional<std::uint64_t> resolve(const MemorySource& memory, std::span<const std::uint64_t> bases,
                                         const PointerChain& chain, unsigned pointer_size) {
        if (chain.module >= bases.size() || bases[chain.module] == 0 || (pointer_size != 4 && pointer_size != 8)) {
            return std::nullopt;
        }
        std::uint64_t address = bases[chain.module] + chain.base_offset;
        for (std::size_t step = 0; step < chain.depth; ++step) {
            if (!known_[step] || addresses_[step] != address) {
                std::array<std::byte, 8> bytes{};
                const bool read = memory.read(address, std::span(bytes.data(), pointer_size)).bytes == pointer_size;
                known_[step] = true;
                addresses_[step] = address;
                pointers_[step] = read ? std::optional(load_pointer(bytes.data(), pointer_size)) : std::nullopt;
            }
            if (!pointers_[step]) {
                return std::nullopt;
            }
            address = *pointers_[step] + chain.offsets[step];
        }
        return address;
    }

private:
    std::array<bool, kMaxPointerDepth> known_{};
    std::array<std::uint64_t, kMaxPointerDepth> addresses_{};
    std::array<std::optional<std::uint64_t>, kMaxPointerDepth> pointers_{};
};

struct Checker {
    CachedResolver resolver;
    std::vector<std::byte> value;
};

}  // namespace

PointerScanResult find_pointer_chains(const MemorySource& source, const ScanPlan& plan, std::uint64_t target,
                                      unsigned pointer_size, const PointerScanOptions& options,
                                      PointerScanProgress& progress, std::stop_token stop) {
    if (options.depth == 0 || options.depth > kMaxPointerDepth) {
        throw Error(ErrorCode::InvalidArgument, "the pointer depth must be 1-" + std::to_string(kMaxPointerDepth));
    }
    if (pointer_size != 4 && pointer_size != 8) {
        throw Error(ErrorCode::InvalidArgument, "the pointer size must be 4 or 8");
    }
    const auto started = Clock::now();
    PointerScanResult result;
    result.chains.pointer_size = pointer_size;
    const auto finish = [&](PointerScanStatus status) {
        result.status = status;
        result.seconds = std::chrono::duration<double>(Clock::now() - started).count();
        return std::move(result);
    };

    const std::size_t chunk_size = std::max<std::size_t>(options.chunk_size / 8 * 8, 4096);
    const std::vector<Chunk> chunks = split_chunks(plan.spans, chunk_size, pointer_size);
    for (const Chunk& chunk : chunks) {
        progress.reading.bytes_total.fetch_add(chunk.end - chunk.begin, std::memory_order_relaxed);
    }
    progress.reading.chunks_total = chunks.size();

    const SpanSet spans(plan.spans);
    const std::size_t page_size = std::max<std::size_t>(source.page_size(), 1);
    Budget budget;
    budget.limit = options.memory_budget;
    std::atomic<bool> exited{false};
    std::vector<Reader> readers(worker_count(options.threads, chunks.size()));
    result.threads = static_cast<unsigned>(readers.size());
    const std::size_t read = parallel_items(chunks.size(), readers, stop, [&](std::size_t index, Reader& reader) {
        const Chunk& chunk = chunks[index];
        reader.buffer.resize(chunk.read_end - chunk.begin);
        reader.bytes_read += reader.buffer.size();
        if (!read_segments(source, chunk.begin, reader.buffer, page_size, reader.segments, reader.read_calls)) {
            ++reader.read_failures;
            progress.reading.read_failures.fetch_add(1, std::memory_order_relaxed);
            if (!source.target_alive()) {
                exited = true;
                return false;
            }
        }
        const std::size_t before = reader.found.size();
        collect_pointers(chunk, reader, spans, pointer_size);
        const std::size_t added = reader.found.size() - before;
        progress.pointers.fetch_add(added, std::memory_order_relaxed);
        progress.reading.bytes_done.fetch_add(chunk.end - chunk.begin, std::memory_order_relaxed);
        progress.reading.chunks_done.fetch_add(1, std::memory_order_relaxed);
        // Sorting needs a second copy.
        return budget.take(2 * added * sizeof(Pointer));
    });
    std::vector<std::vector<Pointer>> runs;
    for (Reader& reader : readers) {
        result.bytes_read += reader.bytes_read;
        result.read_failures += reader.read_failures;
        if (!reader.found.empty()) {
            runs.push_back(std::move(reader.found));
        }
        reader = {};
    }
    if (read != chunks.size() || stop.stop_requested()) {
        result.needed_bytes = budget.used.load();
        return finish(stopped_status(source, exited.load(), budget));
    }

    progress.stage = PointerStage::Sorting;
    if (!sort_runs(runs, options.threads, stop)) {
        return finish(PointerScanStatus::Cancelled);
    }
    const std::vector<Pointer> map = runs.empty() ? std::vector<Pointer>{} : std::move(runs.front());
    runs.clear();
    result.pointers = map.size();

    progress.stage = PointerStage::Searching;
    const ModuleMap modules(plan.regions);
    Search search(map, modules, target, options, budget, progress);
    if (!search.run(stop)) {
        result.needed_bytes = budget.used.load();
        return finish(budget.over.load() ? PointerScanStatus::OverBudget : PointerScanStatus::Cancelled);
    }
    result.total_chains = search.total();
    for (const Level& level : search.levels()) {
        result.nodes += level.onward.size() + level.bases.size();
    }

    progress.stage = PointerStage::Listing;
    const std::uint64_t listed = std::min<std::uint64_t>(result.total_chains, options.max_chains);
    if (!budget.take(listed * sizeof(PointerChain))) {
        result.needed_bytes = budget.used.load();
        return finish(PointerScanStatus::OverBudget);
    }
    result.chains.chains.reserve(listed);
    Lister lister(search.levels(), modules, options, result.chains);
    if (!lister.run(stop)) {
        return finish(PointerScanStatus::Cancelled);
    }
    return finish(PointerScanStatus::Completed);
}

PointerFilterResult filter_pointer_chains(const MemorySource& memory, std::span<const Region> regions,
                                          const PointerChains& chains, const PointerCheck& check, unsigned threads,
                                          ScanProgress& progress, std::stop_token stop) {
    if (!check.address && needs_previous(check.condition.compare)) {
        throw Error(ErrorCode::InvalidArgument,
                    "comparison '" + std::string(to_string(check.condition.compare)) + "' needs a previous scan");
    }
    const auto started = Clock::now();
    PointerFilterResult result;
    result.chains.pointer_size = chains.pointer_size;
    result.chains.modules = chains.modules;

    const ModuleMap modules(regions);
    const std::vector<std::uint64_t> bases = module_bases(modules, chains.modules);
    const std::size_t count = chains.chains.size();
    const std::size_t items = (count + kCheckItem - 1) / kCheckItem;
    const std::size_t value_size = size_of(check.type);
    progress.chunks_total = count;
    std::vector<std::uint8_t> keep(count, 0);
    std::vector<Checker> checkers(worker_count(threads, items));
    result.threads = static_cast<unsigned>(checkers.size());
    const std::size_t done = parallel_items(items, checkers, stop, [&](std::size_t index, Checker& checker) {
        const std::size_t end = std::min(count, (index + 1) * kCheckItem);
        std::uint64_t kept = 0;
        for (std::size_t i = index * kCheckItem; i < end; ++i) {
            const auto address = checker.resolver.resolve(memory, bases, chains.chains[i], chains.pointer_size);
            bool pass = false;
            if (address && check.address) {
                pass = *address == *check.address;
            } else if (address) {
                checker.value.resize(value_size);
                pass = memory.read(*address, checker.value).bytes == value_size &&
                       matches_condition(check.type, check.condition, checker.value);
            }
            keep[i] = pass ? 1 : 0;
            kept += pass ? 1 : 0;
        }
        progress.chunks_done.fetch_add(end - index * kCheckItem, std::memory_order_relaxed);
        progress.matches.fetch_add(kept, std::memory_order_relaxed);
        return true;
    });
    if (done != items) {
        result.status = memory.target_alive() ? PointerScanStatus::Cancelled : PointerScanStatus::TargetExited;
    } else {
        for (std::size_t i = 0; i < count; ++i) {
            if (keep[i] != 0) {
                result.chains.chains.push_back(chains.chains[i]);
            }
        }
    }
    result.seconds = std::chrono::duration<double>(Clock::now() - started).count();
    return result;
}

std::uint64_t pointer_memory_budget() {
    return value_memory_budget();
}

RegionFilter pointer_region_filter() {
    RegionFilter filter;
    filter.protections = protection_class::ReadWrite | protection_class::WriteCopy | protection_class::ExecuteReadWrite |
                         protection_class::ExecuteWriteCopy;
    return filter;
}

}  // namespace mh
