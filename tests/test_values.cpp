#include <gtest/gtest.h>

#include <algorithm>
#include <bit>
#include <cmath>
#include <cstring>
#include <limits>
#include <stop_token>
#include <vector>

#include "common/error.hpp"
#include "pipeline/scan_session.hpp"
#include "support/fake_memory.hpp"
#include "value/value_scan.hpp"

namespace mh {
namespace {

using testing::FakeMemory;

constexpr std::uint64_t kBase = 0x100000;

template <typename T>
void put(FakeMemory& memory, std::uint64_t address, T value) {
    std::memcpy(memory.bytes_at(address, sizeof(T)).data(), &value, sizeof(T));
}

ValueCondition compare(Compare kind) {
    ValueCondition condition;
    condition.compare = kind;
    return condition;
}

ValueCondition exact(std::int64_t value) {
    ValueCondition condition = compare(Compare::Exact);
    condition.bits = static_cast<std::uint64_t>(value);
    return condition;
}

ValueCondition near(double value, double tolerance) {
    ValueCondition condition = compare(Compare::Exact);
    condition.number = value;
    condition.tolerance = tolerance;
    return condition;
}

ValueCondition ordered(Compare kind, std::int64_t low, std::int64_t high = 0) {
    ValueCondition condition = compare(kind);
    condition.integer = low;
    condition.integer_high = high;
    return condition;
}

struct Scanner {
    FakeMemory& memory;
    ValueScanOptions options{};
    std::stop_token stop{};

    ValueScanResult first(ValueType type, const ValueCondition& condition, bool aligned = true) {
        ScanProgress progress;
        return first_value_scan(memory, plan_scan(memory, RegionFilter{}), type, aligned, condition, options, progress, stop);
    }

    ValueCandidates next(const ValueCandidates& previous, const ValueCondition& condition) {
        ScanProgress progress;
        ValueScanResult result = next_value_scan(memory, previous, condition, options, progress, stop);
        EXPECT_EQ(result.status, ValueScanStatus::Completed);
        EXPECT_EQ(result.candidates.scans, previous.scans + 1);
        return std::move(result.candidates);
    }
};

std::vector<std::uint64_t> offsets(const ValueCandidates& candidates) {
    std::vector<std::uint64_t> out;
    for (const ValueCandidate& candidate : candidates.list(std::numeric_limits<std::size_t>::max())) {
        out.push_back(candidate.address - kBase);
    }
    EXPECT_EQ(out.size(), candidates.count());
    return out;
}

using Offsets = std::vector<std::uint64_t>;

TEST(ValueScan, ExactFindsAlignedOrEveryPosition) {
    FakeMemory memory;
    memory.add(kBase, FakeMemory::kPage);
    put<std::int32_t>(memory, kBase + 0x58, 15000);
    put<std::int32_t>(memory, kBase + 0x101, 15000);
    Scanner scanner{memory};

    const ValueScanResult aligned = scanner.first(ValueType::Int32, exact(15000));
    EXPECT_EQ(aligned.status, ValueScanStatus::Completed);
    EXPECT_EQ(offsets(aligned.candidates), (Offsets{0x58}));
    EXPECT_EQ(aligned.candidates.list(1)[0].previous, 15000u);
    EXPECT_EQ(offsets(scanner.first(ValueType::Int32, exact(15000), false).candidates), (Offsets{0x58, 0x101}));
}

TEST(ValueScan, IntegerExactAcceptsTheUnsignedBits) {
    FakeMemory memory;
    memory.add(kBase, FakeMemory::kPage);
    put<std::int16_t>(memory, kBase + 0x20, -2);
    Scanner scanner{memory};
    EXPECT_EQ(offsets(scanner.first(ValueType::Int16, exact(0xFFFE)).candidates), (Offsets{0x20}));
    EXPECT_EQ(offsets(scanner.first(ValueType::Int16, exact(-2)).candidates), (Offsets{0x20}));
}

TEST(ValueScan, OrderedComparisonsAreSigned) {
    FakeMemory memory;
    std::span<std::byte> page = memory.add(kBase, FakeMemory::kPage);
    std::memset(page.data(), 0x7F, page.size());
    put<std::int32_t>(memory, kBase + 0x10, -5);
    put<std::int32_t>(memory, kBase + 0x20, 7);
    put<std::int32_t>(memory, kBase + 0x30, 100);
    Scanner scanner{memory};

    EXPECT_EQ(offsets(scanner.first(ValueType::Int32, ordered(Compare::Less, 0)).candidates), (Offsets{0x10}));
    EXPECT_EQ(offsets(scanner.first(ValueType::Int32, ordered(Compare::Between, -10, 10)).candidates), (Offsets{0x10, 0x20}));
    EXPECT_EQ(offsets(scanner.first(ValueType::Int32, ordered(Compare::Between, 7, 100)).candidates), (Offsets{0x20, 0x30}));
    const auto greater = offsets(scanner.first(ValueType::Int32, ordered(Compare::Greater, 6)).candidates);
    EXPECT_EQ(greater.size(), FakeMemory::kPage / 4 - 1);
    EXPECT_EQ(greater[0], 0x00u);
    EXPECT_EQ(std::count(greater.begin(), greater.end(), 0x10u), 0);
}

TEST(ValueScan, FloatExactUsesTheTolerance) {
    FakeMemory memory;
    memory.add(kBase, FakeMemory::kPage);
    put(memory, kBase + 0x10, 100.3f);
    put(memory, kBase + 0x20, 100.6f);
    put(memory, kBase + 0x30, 99.54f);
    put(memory, kBase + 0x40, 99.6f);
    put(memory, kBase + 0x50, std::numeric_limits<float>::quiet_NaN());
    Scanner scanner{memory};

    EXPECT_EQ(offsets(scanner.first(ValueType::Float, near(100, 0.5)).candidates), (Offsets{0x10, 0x30, 0x40}));
    EXPECT_EQ(offsets(scanner.first(ValueType::Float, near(99.5, 0.05)).candidates), (Offsets{0x30}));
    const ValueScanResult any = scanner.first(ValueType::Float, near(0, std::numeric_limits<double>::infinity()));
    EXPECT_EQ(any.candidates.count(), FakeMemory::kPage / 4 - 1);

    ValueCondition between = compare(Compare::Between);
    between.number = 99.6;
    between.number_high = 100.5;
    EXPECT_EQ(offsets(scanner.first(ValueType::Float, between).candidates), (Offsets{0x10}));
}

TEST(ValueScan, UnknownThenComparisonsWithThePreviousScan) {
    FakeMemory memory;
    memory.add(kBase, FakeMemory::kPage);
    put<std::int32_t>(memory, kBase + 0x10, 5);
    put<std::int32_t>(memory, kBase + 0x20, 50);
    Scanner scanner{memory};

    const ValueScanResult unknown = scanner.first(ValueType::Int32, compare(Compare::Unknown));
    ASSERT_EQ(unknown.status, ValueScanStatus::Completed);
    EXPECT_EQ(unknown.candidates.count(), FakeMemory::kPage / 4);

    put<std::int32_t>(memory, kBase + 0x10, 9);
    put<std::int32_t>(memory, kBase + 0x20, 40);
    EXPECT_EQ(offsets(scanner.next(unknown.candidates, compare(Compare::Increased))), (Offsets{0x10}));
    EXPECT_EQ(offsets(scanner.next(unknown.candidates, compare(Compare::Decreased))), (Offsets{0x20}));
    EXPECT_EQ(scanner.next(unknown.candidates, compare(Compare::Unchanged)).count(), FakeMemory::kPage / 4 - 2);

    const ValueCandidates changed = scanner.next(unknown.candidates, compare(Compare::Changed));
    EXPECT_EQ(offsets(changed), (Offsets{0x10, 0x20}));
    const auto values = changed.list(2);
    EXPECT_EQ(values[0].previous, 9u);
    EXPECT_EQ(values[1].previous, 40u);

    const ValueCandidates same = scanner.next(changed, compare(Compare::Unchanged));
    EXPECT_EQ(offsets(same), (Offsets{0x10, 0x20}));
    put<std::int32_t>(memory, kBase + 0x10, -1);
    EXPECT_EQ(offsets(scanner.next(same, compare(Compare::Unchanged))), (Offsets{0x20}));
    EXPECT_EQ(offsets(scanner.next(same, compare(Compare::Decreased))), (Offsets{0x10}));
}

TEST(ValueScan, ExactAfterUnknownKeepsOnlyTheValue) {
    FakeMemory memory;
    memory.add(kBase, FakeMemory::kPage);
    Scanner scanner{memory};
    const ValueScanResult unknown = scanner.first(ValueType::Int32, compare(Compare::Unknown));
    put<std::int32_t>(memory, kBase + 0x40, 77);
    const ValueCandidates found = scanner.next(unknown.candidates, exact(77));
    EXPECT_EQ(offsets(found), (Offsets{0x40}));
    EXPECT_EQ(found.list(1)[0].previous, 77u);
    EXPECT_TRUE(found.dense.empty());
}

TEST(ValueScan, UnreadableCandidatesAreDropped) {
    FakeMemory memory;
    memory.add(kBase, 2 * FakeMemory::kPage);
    put<std::int32_t>(memory, kBase + 0x10, 5);
    put<std::int32_t>(memory, kBase + 0x1010, 5);
    Scanner scanner{memory};
    const ValueScanResult first = scanner.first(ValueType::Int32, exact(5));
    ASSERT_EQ(offsets(first.candidates), (Offsets{0x10, 0x1010}));

    memory.fail_page(kBase + 0x1000);
    EXPECT_EQ(offsets(scanner.next(first.candidates, compare(Compare::Unchanged))), (Offsets{0x10}));
    EXPECT_EQ(offsets(scanner.first(ValueType::Int32, exact(5)).candidates), (Offsets{0x10}));
    EXPECT_EQ(scanner.first(ValueType::Int32, compare(Compare::Unknown)).candidates.count(), FakeMemory::kPage / 4);
}

TEST(ValueScan, DenseChunksTurnSparseAndStayCorrect) {
    FakeMemory memory;
    std::span<std::byte> bytes = memory.add(kBase, 4 * FakeMemory::kPage);
    Scanner scanner{memory};
    scanner.options.chunk_size = FakeMemory::kPage;
    scanner.options.threads = 3;

    const ValueScanResult unknown = scanner.first(ValueType::Int32, compare(Compare::Unknown));
    ASSERT_EQ(unknown.candidates.dense.size(), 4u);
    EXPECT_TRUE(unknown.candidates.sparse.empty());

    for (std::size_t i = 0; i < FakeMemory::kPage; i += 4) {
        put<std::int32_t>(memory, kBase + 2 * FakeMemory::kPage + i, 3);
    }
    put<std::int32_t>(memory, kBase + 0x10, 1);
    put<std::int32_t>(memory, kBase + 0x3008, 1);
    const ValueCandidates changed = scanner.next(unknown.candidates, compare(Compare::Changed));
    EXPECT_EQ(changed.dense.size(), 1u);
    EXPECT_EQ(changed.sparse.size(), 2u);
    EXPECT_EQ(changed.count(), FakeMemory::kPage / 4 + 2);
    const Offsets listed = offsets(changed);
    EXPECT_EQ(listed.front(), 0x10u);
    EXPECT_EQ(listed[1], 0x2000u);
    EXPECT_EQ(listed.back(), 0x3008u);
    EXPECT_TRUE(std::is_sorted(listed.begin(), listed.end()));

    put<std::int32_t>(memory, kBase + 0x2004, 4);
    put<std::int32_t>(memory, kBase + 0x3008, 2);
    const ValueCandidates increased = scanner.next(changed, compare(Compare::Increased));
    EXPECT_EQ(offsets(increased), (Offsets{0x2004, 0x3008}));
    EXPECT_TRUE(increased.dense.empty());
    std::memset(bytes.data(), 0, bytes.size());
    EXPECT_EQ(offsets(scanner.next(increased, compare(Compare::Decreased))), (Offsets{0x2004, 0x3008}));
}

TEST(ValueScan, MemoryBudgetStopsTheFirstScan) {
    FakeMemory memory;
    memory.add(kBase, 4 * FakeMemory::kPage);
    Scanner scanner{memory};
    scanner.options.memory_budget = 1000;

    const ValueScanResult unknown = scanner.first(ValueType::Int32, compare(Compare::Unknown));
    EXPECT_EQ(unknown.status, ValueScanStatus::OverBudget);
    EXPECT_GT(unknown.needed_bytes, 4 * FakeMemory::kPage);
    EXPECT_EQ(memory.read_count(), 0u);

    const ValueScanResult zeros = scanner.first(ValueType::Int32, exact(0));
    EXPECT_EQ(zeros.status, ValueScanStatus::OverBudget);
    EXPECT_GT(zeros.needed_bytes, 1000u);

    scanner.options.memory_budget = 0;
    EXPECT_EQ(scanner.first(ValueType::Int32, exact(0)).status, ValueScanStatus::Completed);
}

TEST(ValueScan, StopAndExitAreReported) {
    FakeMemory memory;
    memory.add(kBase, 8 * FakeMemory::kPage);
    std::stop_source stop;
    Scanner scanner{memory, {}, stop.get_token()};
    scanner.options.chunk_size = FakeMemory::kPage;
    scanner.options.threads = 1;
    memory.on_read([&](std::size_t) { stop.request_stop(); });
    EXPECT_EQ(scanner.first(ValueType::Int32, compare(Compare::Unknown)).status, ValueScanStatus::Cancelled);

    FakeMemory exiting;
    exiting.add(kBase, 8 * FakeMemory::kPage);
    Scanner other{exiting};
    other.options.chunk_size = FakeMemory::kPage;
    other.options.threads = 1;
    exiting.exit_after_reads(2);
    EXPECT_EQ(other.first(ValueType::Int32, compare(Compare::Unknown)).status, ValueScanStatus::TargetExited);
}

TEST(ValueScan, EveryTypeIsRead) {
    FakeMemory memory;
    memory.add(kBase, FakeMemory::kPage);
    put<std::int8_t>(memory, kBase + 0x11, -3);
    put<std::int64_t>(memory, kBase + 0x60, 64200);
    put(memory, kBase + 0x80, -37.25);
    Scanner scanner{memory};
    EXPECT_EQ(offsets(scanner.first(ValueType::Int8, exact(-3)).candidates), (Offsets{0x11}));
    EXPECT_EQ(offsets(scanner.first(ValueType::Int8, exact(253)).candidates), (Offsets{0x11}));
    EXPECT_EQ(offsets(scanner.first(ValueType::Int64, exact(64200)).candidates), (Offsets{0x60}));
    EXPECT_EQ(offsets(scanner.first(ValueType::Double, near(-37.25, 0)).candidates), (Offsets{0x80}));
    ValueCondition below = compare(Compare::Less);
    below.number = -1;
    EXPECT_EQ(offsets(scanner.first(ValueType::Double, below).candidates), (Offsets{0x80}));
}

TEST(ValueScan, ComparisonsNeedTheRightScan) {
    FakeMemory memory;
    memory.add(kBase, FakeMemory::kPage);
    Scanner scanner{memory};
    EXPECT_THROW(scanner.first(ValueType::Int32, compare(Compare::Increased)), Error);
    const ValueScanResult first = scanner.first(ValueType::Int32, exact(0));
    ScanProgress progress;
    EXPECT_THROW(next_value_scan(memory, first.candidates, compare(Compare::Unknown), {}, progress, {}), Error);
}

TEST(ValueScan, ValuesAcrossChunkBoundariesAreFoundOnce) {
    FakeMemory memory;
    memory.add(kBase, FakeMemory::kPage);
    put<std::uint32_t>(memory, kBase + 0x3E, 0x11223344);
    put<std::uint32_t>(memory, kBase + 0x7C, 0x11223344);
    put<std::uint32_t>(memory, kBase + 0x80, 0x11223344);
    Scanner scanner{memory};
    scanner.options.chunk_size = 64;
    const ValueScanResult unaligned = scanner.first(ValueType::Int32, exact(0x11223344), false);
    EXPECT_EQ(offsets(unaligned.candidates), (Offsets{0x3E, 0x7C, 0x80}));
    EXPECT_EQ(offsets(scanner.first(ValueType::Int32, exact(0x11223344)).candidates), (Offsets{0x7C, 0x80}));
    EXPECT_EQ(offsets(scanner.next(unaligned.candidates, compare(Compare::Unchanged))), (Offsets{0x3E, 0x7C, 0x80}));
}

TEST(ValueScan, ValueAcrossAdjacentRegions) {
    FakeMemory memory;
    memory.add(kBase, FakeMemory::kPage);
    memory.add(kBase + FakeMemory::kPage, FakeMemory::kPage, page::ReadOnly);
    put<std::uint16_t>(memory, kBase + 0xFFE, 0x3344);
    put<std::uint16_t>(memory, kBase + 0x1000, 0x1122);
    Scanner scanner{memory};
    const ValueScanResult found = scanner.first(ValueType::Int32, exact(0x11223344), false);
    EXPECT_EQ(offsets(found.candidates), (Offsets{0xFFE}));
    const Region* region = found.candidates.region_of(kBase + 0xFFE);
    ASSERT_NE(region, nullptr);
    EXPECT_EQ(region->base, kBase);
    EXPECT_EQ(found.candidates.region_of(kBase + 0x1000)->protect, page::ReadOnly);
    EXPECT_EQ(found.candidates.region_of(kBase + 0x2000), nullptr);
}

TEST(ValueScan, ThreadCountDoesNotChangeTheResult) {
    FakeMemory memory;
    std::span<std::byte> bytes = memory.add(kBase, 64 * FakeMemory::kPage);
    testing::fill_random(bytes, 7);
    for (std::size_t i = 0; i < bytes.size(); i += 3) {
        bytes[i] = std::byte{0};
    }
    std::vector<Offsets> results;
    for (unsigned threads : {1u, 8u}) {
        FakeMemory copy;
        std::span<std::byte> target = copy.add(kBase, bytes.size());
        std::memcpy(target.data(), bytes.data(), bytes.size());
        Scanner scanner{copy};
        scanner.options.threads = threads;
        scanner.options.chunk_size = 3000;
        const ValueScanResult first = scanner.first(ValueType::Int16, ordered(Compare::Between, -100, 100), false);
        testing::fill_random(target.subspan(0, target.size() / 2), 11);
        results.push_back(offsets(scanner.next(first.candidates, compare(Compare::Unchanged))));
    }
    EXPECT_FALSE(results[0].empty());
    EXPECT_EQ(results[0], results[1]);
}

TEST(ValueScan, ListStopsAtTheLimit) {
    FakeMemory memory;
    memory.add(kBase, 2 * FakeMemory::kPage);
    put<std::int32_t>(memory, kBase + 0x1004, 1);
    Scanner scanner{memory};
    scanner.options.chunk_size = FakeMemory::kPage;
    const ValueScanResult unknown = scanner.first(ValueType::Int32, compare(Compare::Unknown));
    const auto listed = unknown.candidates.list(1025);
    ASSERT_EQ(listed.size(), 1025u);
    EXPECT_EQ(listed.back().address, kBase + 0x1000);
    const ValueCandidates mixed = scanner.next(unknown.candidates, exact(0));
    EXPECT_EQ(mixed.count(), 2 * FakeMemory::kPage / 4 - 1);
    EXPECT_EQ(mixed.list(1026).back().address, kBase + 0x1008);
}

TEST(ValueScan, ValueAtFindsDenseAndSparseCandidates) {
    FakeMemory memory;
    memory.add(kBase, FakeMemory::kPage);
    std::span<std::byte> second = memory.add(kBase + FakeMemory::kPage, FakeMemory::kPage);
    std::memset(second.data(), 1, second.size());
    put<std::int32_t>(memory, kBase + 8, 7);
    put<std::int32_t>(memory, kBase + 0x1010, 3);
    Scanner scanner{memory};
    scanner.options.chunk_size = FakeMemory::kPage;
    const ValueCandidates below = scanner.first(ValueType::Int32, ordered(Compare::Less, 10)).candidates;
    ASSERT_EQ(below.dense.size(), 1u);
    ASSERT_EQ(below.sparse.size(), 1u);

    EXPECT_EQ(below.value_at(kBase + 8), std::optional<std::uint64_t>(7));
    EXPECT_EQ(below.value_at(kBase + 0xC), std::optional<std::uint64_t>(0));
    EXPECT_EQ(below.value_at(kBase + 0x1010), std::optional<std::uint64_t>(3));
    EXPECT_FALSE(below.value_at(kBase + 9));
    EXPECT_FALSE(below.value_at(kBase + 0x1014));
    EXPECT_FALSE(below.value_at(kBase - 4));
    EXPECT_FALSE(below.value_at(kBase + 0x3000));
}

TEST(ValueScan, FormatsValues) {
    EXPECT_EQ(format_value(ValueType::Int32, 0xFFFFFFF3), "-13");
    EXPECT_EQ(format_value(ValueType::Int8, 0x80), "-128");
    EXPECT_EQ(format_value(ValueType::Int64, 64200), "64200");
    EXPECT_EQ(format_value(ValueType::Float, std::bit_cast<std::uint32_t>(102.5f)), "102.5");
    EXPECT_EQ(format_value(ValueType::Double, std::bit_cast<std::uint64_t>(-37.25)), "-37.25");
}

}  // namespace
}  // namespace mh
