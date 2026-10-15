#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

#include "memory/memory_source.hpp"
#include "pipeline/scan_engine.hpp"
#include "pipeline/scan_session.hpp"

namespace mh {

enum class ValueType : std::uint8_t { Int8, Int16, Int32, Int64, Float, Double };

// Unknown is valid only for the first scan; Increased, Decreased, Changed and Unchanged compare with the
// previous scan and need one.
enum class Compare : std::uint8_t { Exact, Greater, Less, Between, Unknown, Increased, Decreased, Changed, Unchanged };

std::size_t size_of(ValueType type) noexcept;
bool is_float(ValueType type) noexcept;
std::string_view to_string(ValueType type);
std::string_view to_string(Compare compare);
bool needs_previous(Compare compare) noexcept;

// Integers: Exact compares the bits, so both the signed and the unsigned reading of a value match; the ordered
// comparisons treat values as signed. Floats are compared as doubles: Exact matches |value - number| <= tolerance,
// NaN never matches. Between includes both bounds.
struct ValueCondition {
    Compare compare = Compare::Exact;
    std::uint64_t bits = 0;
    std::int64_t integer = 0;
    std::int64_t integer_high = 0;
    double number = 0;
    double number_high = 0;
    double tolerance = 0;
};

struct ValueScanOptions {
    unsigned threads = 0;
    std::size_t chunk_size = std::size_t{1} << 20;
    // Bytes the candidate list of a first scan may occupy; 0 means no limit. Next scans only shrink the list.
    std::uint64_t memory_budget = 0;
};

struct ValueCandidate {
    std::uint64_t address = 0;
    // Little-endian bits of the value read by the last scan.
    std::uint64_t previous = 0;
};

// Candidates of one chunk while there are many of them: a bit per possible position and the bytes read by the
// last scan.
struct DenseValues {
    std::uint64_t base = 0;
    std::uint64_t first = 0;
    std::uint64_t positions = 0;
    std::uint64_t count = 0;
    std::vector<std::uint64_t> alive;
    std::vector<std::byte> bytes;

    std::uint64_t stored_bytes() const noexcept { return bytes.size() + alive.size() * sizeof(std::uint64_t); }
};

struct ValueCandidates {
    ValueType type = ValueType::Int32;
    bool aligned = true;
    unsigned scans = 0;
    std::vector<Region> regions;
    // Both sorted by address. A chunk is either dense or contributes sparse entries, never both.
    std::vector<DenseValues> dense;
    std::vector<ValueCandidate> sparse;

    std::size_t step() const noexcept { return aligned ? size_of(type) : 1; }
    std::uint64_t count() const noexcept;
    std::uint64_t stored_bytes() const noexcept;
    const Region* region_of(std::uint64_t address) const;
    // The first `limit` candidates in address order.
    std::vector<ValueCandidate> list(std::size_t limit) const;
    // The value the last scan read at `address`, or nullopt when it is not a candidate.
    std::optional<std::uint64_t> value_at(std::uint64_t address) const;
};

enum class ValueScanStatus : std::uint8_t { Completed, Cancelled, TargetExited, OverBudget };

struct ValueScanResult {
    ValueCandidates candidates;
    ValueScanStatus status = ValueScanStatus::Completed;
    unsigned threads = 0;
    std::uint64_t bytes_read = 0;
    std::uint64_t read_calls = 0;
    // Reads that left part of their range unread.
    std::uint64_t read_failures = 0;
    // With OverBudget: what the list needed (an estimate) or had reached when the scan stopped.
    std::uint64_t needed_bytes = 0;
    double seconds = 0;
};

// Whether the value in `bytes` passes a comparison that needs no previous scan; false when fewer than
// size_of(type) bytes are given. Throws Error(InvalidArgument) for one that needs a previous scan.
bool matches_condition(ValueType type, const ValueCondition& condition, std::span<const std::byte> bytes);

// Checks every position of plan.spans that is fully readable; with `aligned` only addresses divisible by the
// value size. Throws Error(InvalidArgument) for a comparison that needs a previous scan.
ValueScanResult first_value_scan(const MemorySource& source, const ScanPlan& plan, ValueType type, bool aligned,
                                 const ValueCondition& condition, const ValueScanOptions& options, ScanProgress& progress,
                                 std::stop_token stop);

// Rechecks the candidates and keeps the ones that pass; those that can no longer be read are dropped. Throws
// Error(InvalidArgument) for Unknown.
ValueScanResult next_value_scan(const MemorySource& source, const ValueCandidates& previous, const ValueCondition& condition,
                                const ValueScanOptions& options, ScanProgress& progress, std::stop_token stop);

// What the candidate list of a first value scan may occupy: a third of the free physical memory, because a next
// scan builds its list while the previous one is still kept.
std::uint64_t value_memory_budget();

// The value as text: integers signed, floats in the shortest form that reads back exactly.
std::string format_value(ValueType type, std::uint64_t bits);

}  // namespace mh
