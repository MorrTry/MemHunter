#include <gtest/gtest.h>

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <mutex>
#include <optional>
#include <string>

#include "common/error.hpp"
#include "common/text.hpp"
#include "memory/process_memory.hpp"
#include "pipeline/scan_session.hpp"
#include "process/process.hpp"
#include "snapshot/capture.hpp"
#include "snapshot/diff.hpp"
#include "snapshot/hash.hpp"
#include "snapshot/snapshot_file.hpp"
#include "support/fake_memory.hpp"
#include "support/target_process.hpp"

namespace mh {
namespace {

using testing::FakeMemory;

constexpr std::uint64_t kA = 0x100000;  // 64K rw
constexpr std::uint64_t kB = 0x200000;  // 16K rw, only in the earlier memory
constexpr std::uint64_t kC = 0x300000;  // 8K rw, only in the later memory
constexpr std::uint64_t kD = 0x400000;  // 8K rw, read-only in the later memory
constexpr std::uint64_t kG = 0x500000;  // 8K rw + guard

std::span<const std::byte> bytes_of(std::string_view text) {
    return std::as_bytes(std::span(text.data(), text.size()));
}

template <typename F>
std::optional<ErrorCode> error_of(F&& f) {
    try {
        f();
    } catch (const Error& error) {
        return error.code();
    }
    return std::nullopt;
}

// Collects the data section in memory, as SnapshotWriter would on disk.
class BufferSink final : public SnapshotDataSink {
public:
    void write(std::uint64_t offset, std::span<const std::byte> bytes) override {
        std::lock_guard lock(mutex_);
        if (data_.size() < offset + bytes.size()) {
            data_.resize(offset + bytes.size());
        }
        std::memcpy(data_.data() + offset, bytes.data(), bytes.size());
    }

    BlockReader reader(const Snapshot& snapshot) const {
        return [this, &snapshot](std::size_t span, std::uint64_t block, std::span<std::byte> out) {
            if (snapshot.states[block] != BlockState::Hashed) {
                return false;
            }
            const AddressRange range = snapshot.block_range(span, block);
            std::memcpy(out.data(), data_.data() + snapshot.block_data_offset(span, block), range.end - range.begin);
            return true;
        };
    }

    std::span<const std::byte> data() const noexcept { return data_; }

private:
    std::mutex mutex_;
    std::vector<std::byte> data_;
};

struct BlockRef {
    std::size_t span = 0;
    std::uint64_t block = 0;
};

BlockRef block_at(const Snapshot& snapshot, std::uint64_t address) {
    for (std::size_t s = 0; s < snapshot.spans.size(); ++s) {
        const SnapshotSpan& span = snapshot.spans[s];
        if (span.begin <= address && address < span.end) {
            return {s, span.first_block + (address / snapshot.block_size - span.begin / snapshot.block_size)};
        }
    }
    ADD_FAILURE() << "address " << format_address(address) << " was not captured";
    return {};
}

std::optional<RangeKind> kind_at(const SnapshotDiff& diff, std::uint64_t address) {
    for (const auto& range : diff.ranges) {
        if (range.begin <= address && address < range.end) {
            return range.kind;
        }
    }
    return std::nullopt;
}

bool changed_overlaps(const SnapshotDiff& diff, std::uint64_t begin, std::uint64_t end) {
    return std::any_of(diff.ranges.begin(), diff.ranges.end(), [&](const DiffRange& range) {
        return range.kind == RangeKind::Changed && range.begin < end && begin < range.end;
    });
}

CaptureResult capture(const MemorySource& memory, const CaptureOptions& options = {}, SnapshotDataSink* sink = nullptr,
                      std::stop_token stop = {}) {
    ScanProgress progress;
    return capture_snapshot(memory, plan_scan(memory, RegionFilter{}), options, sink, progress, stop);
}

// The earlier and later state of the same fake process: one byte of A changed, one page of A became
// unreadable, B was freed, C was allocated and D changed its protection.
void build_memory(FakeMemory& memory, bool later) {
    testing::fill_random(memory.add(kA, 64 * 1024), 1);
    if (later) {
        memory.bytes_at(kA + 0x1234, 1)[0] ^= std::byte{0xFF};
        memory.fail_page(kA + 0x5000);
    } else {
        testing::fill_random(memory.add(kB, 16 * 1024), 2);
    }
    if (later) {
        testing::fill_random(memory.add(kC, 8 * 1024), 3);
    }
    testing::fill_random(memory.add(kD, 8 * 1024, later ? page::ReadOnly : page::ReadWrite), 4);
    testing::fill_random(memory.add(kG, 8 * 1024, page::ReadWrite | page::Guard), 5);
}

TEST(SnapshotHash, MatchesXxh64ReferenceValues) {
    EXPECT_EQ(xxh64(bytes_of("")), 0xEF46DB3751D8E999ull);
    EXPECT_EQ(xxh64(bytes_of("a")), 0xD24EC4F1A98C6E5Bull);
    EXPECT_EQ(xxh64(bytes_of("abc")), 0x44BC2CF5AD770999ull);
    EXPECT_EQ(xxh64(bytes_of("Nobody inspects the spammish repetition")), 0xFBCEA83C8A378BF1ull);
    EXPECT_NE(xxh64(bytes_of("abc"), 1), xxh64(bytes_of("abc")));
}

TEST(SnapshotLayout, BlocksFollowTheAbsoluteGrid) {
    EXPECT_EQ(blocks_in_range(0x201000, 0x206000, 0x4000), 2u);
    EXPECT_EQ(blocks_in_range(0x200000, 0x204000, 0x4000), 1u);
    EXPECT_EQ(blocks_in_range(0x200000, 0x200000, 0x4000), 0u);

    Snapshot snapshot;
    snapshot.block_size = 0x4000;
    const std::vector<AddressRange> ranges{{0x201000, 0x206000}, {0x300000, 0x308000}};
    layout_spans(snapshot, ranges);
    ASSERT_EQ(snapshot.spans.size(), 2u);
    EXPECT_EQ(snapshot.block_count(), 4u);
    EXPECT_EQ(snapshot.captured_bytes(), 0x5000u + 0x8000u);
    EXPECT_EQ(snapshot.block_range(0, 0), (AddressRange{0x201000, 0x204000}));
    EXPECT_EQ(snapshot.block_range(0, 1), (AddressRange{0x204000, 0x206000}));
    EXPECT_EQ(snapshot.spans[1].first_block, 2u);
    EXPECT_EQ(snapshot.block_range(1, 3), (AddressRange{0x304000, 0x308000}));
    EXPECT_EQ(snapshot.block_data_offset(1, 3), 0x5000u + 0x4000u);
    EXPECT_EQ(snapshot.unreadable_bytes(), snapshot.captured_bytes());
}

TEST(SnapshotCapture, HashesEveryReadableBlock) {
    FakeMemory memory;
    build_memory(memory, false);
    memory.fail_page(kA + 0x3000);
    BufferSink sink;
    CaptureOptions options;
    options.threads = 4;
    options.chunk_size = 16 * 1024;
    const CaptureResult result = capture(memory, options, &sink);
    const Snapshot& snapshot = result.snapshot;

    EXPECT_EQ(result.status, ScanStatus::Completed);
    EXPECT_TRUE(snapshot.has_data);
    EXPECT_EQ(snapshot.captured_bytes(), (64 + 16 + 8) * 1024u);
    EXPECT_EQ(snapshot.block_count(), snapshot.captured_bytes() / kDefaultBlockSize);
    EXPECT_EQ(snapshot.regions.size(), 4u);
    EXPECT_EQ(result.bytes_unreadable, 4096u);
    EXPECT_EQ(result.bytes_hashed, snapshot.captured_bytes() - 4096);
    EXPECT_EQ(snapshot.unreadable_bytes(), 4096u);
    EXPECT_EQ(memory.guard_reads(), 0u);

    const BlockRef bad = block_at(snapshot, kA + 0x3000);
    EXPECT_EQ(snapshot.states[bad.block], BlockState::Unreadable);
    for (const std::uint64_t address : {kA, kA + 0x2000, kA + 0x4000, kB + 0x3000, kD}) {
        const BlockRef ref = block_at(snapshot, address);
        ASSERT_EQ(snapshot.states[ref.block], BlockState::Hashed) << format_address(address);
        EXPECT_EQ(snapshot.hashes[ref.block], xxh64(memory.view(address, 4096))) << format_address(address);
        const auto saved = sink.data().subspan(snapshot.block_data_offset(ref.span, ref.block), 4096);
        EXPECT_TRUE(std::ranges::equal(saved, memory.view(address, 4096))) << format_address(address);
    }
    const auto zeroed = sink.data().subspan(snapshot.block_data_offset(bad.span, bad.block), 4096);
    EXPECT_TRUE(std::ranges::all_of(zeroed, [](std::byte b) { return b == std::byte{0}; }));
}

TEST(SnapshotCapture, PartlyReadableLargeBlockIsUnreadable) {
    FakeMemory memory;
    testing::fill_random(memory.add(0x201000, 0x5000), 7);
    memory.fail_page(0x205000);
    CaptureOptions options;
    options.block_size = 0x4000;
    const CaptureResult result = capture(memory, options);
    const Snapshot& snapshot = result.snapshot;
    ASSERT_EQ(snapshot.block_count(), 2u);
    EXPECT_EQ(snapshot.states[0], BlockState::Hashed);
    EXPECT_EQ(snapshot.hashes[0], xxh64(memory.view(0x201000, 0x3000)));
    EXPECT_EQ(snapshot.states[1], BlockState::Unreadable);
    EXPECT_EQ(result.bytes_unreadable, 0x2000u);
}

TEST(SnapshotCapture, ValidatesBlockSize) {
    EXPECT_NO_THROW(validate_block_size(8192, 4096));
    EXPECT_NO_THROW(validate_block_size(kMaxBlockSize, 4096));
    EXPECT_EQ(error_of([] { validate_block_size(3000, 4096); }), ErrorCode::InvalidArgument);
    EXPECT_EQ(error_of([] { validate_block_size(2048, 4096); }), ErrorCode::InvalidArgument);
    EXPECT_EQ(error_of([] { validate_block_size(kMaxBlockSize * 2, 4096); }), ErrorCode::InvalidArgument);
}

TEST(SnapshotCapture, ReportsTargetExitAndCancellation) {
    FakeMemory memory;
    testing::fill_random(memory.add(kA, 256 * 1024), 8);
    CaptureOptions options;
    options.threads = 1;
    options.chunk_size = 4096;
    memory.exit_after_reads(3);
    EXPECT_EQ(capture(memory, options).status, ScanStatus::TargetExited);

    FakeMemory alive;
    testing::fill_random(alive.add(kA, 256 * 1024), 8);
    std::stop_source stop;
    stop.request_stop();
    const CaptureResult cancelled = capture(alive, options, nullptr, stop.get_token());
    EXPECT_EQ(cancelled.status, ScanStatus::Cancelled);
    EXPECT_EQ(alive.read_count(), 0u);
}

class SnapshotFiles : public ::testing::Test {
protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        directory_ = std::filesystem::temp_directory_path() /
                     ("memhunter-snap-" + std::to_string(GetCurrentProcessId()) + "-" + info->name());
        std::filesystem::create_directories(directory_);
        build_memory(memory_, false);
        memory_.fail_page(kA + 0x3000);
    }

    void TearDown() override {
        std::error_code ignored;
        std::filesystem::remove_all(directory_, ignored);
    }

    std::string path(const std::string& name) const { return wide_to_utf8((directory_ / name).wstring()); }

    Snapshot write(const std::string& name, bool with_data) {
        SnapshotWriter writer(path(name), with_data);
        CaptureResult result = capture(memory_, {}, with_data ? &writer : nullptr);
        result.snapshot.process = {4242, "fake.exe", "C:\\fake\\fake.exe", 133'000'000'000'000'000ull, true};
        written_size_ = writer.commit(result.snapshot);
        return result.snapshot;
    }

    std::string read_raw(const std::string& name) const {
        std::ifstream in(directory_ / name, std::ios::binary);
        return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    }

    void write_raw(const std::string& name, const std::string& bytes) const {
        std::ofstream out(directory_ / name, std::ios::binary | std::ios::trunc);
        out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    }

    std::optional<ErrorCode> open_error(const std::string& name) const {
        return error_of([&] { SnapshotFile file(path(name)); });
    }

    FakeMemory memory_;
    std::filesystem::path directory_;
    std::uint64_t written_size_ = 0;
};

TEST_F(SnapshotFiles, RoundTripWithoutContents) {
    const Snapshot original = write("a.mhs", false);
    EXPECT_FALSE(std::filesystem::exists(directory_ / "a.mhs.partial"));
    SnapshotFile file(path("a.mhs"));
    const Snapshot& loaded = file.snapshot();
    EXPECT_EQ(file.file_size(), written_size_);
    EXPECT_EQ(file.file_size(), std::filesystem::file_size(directory_ / "a.mhs"));
    EXPECT_LT(file.file_size(), 4096u);

    EXPECT_FALSE(loaded.has_data);
    EXPECT_EQ(loaded.process.pid, 4242u);
    EXPECT_EQ(loaded.process.name, "fake.exe");
    EXPECT_EQ(loaded.process.path, "C:\\fake\\fake.exe");
    EXPECT_EQ(loaded.process.creation_time, 133'000'000'000'000'000ull);
    EXPECT_TRUE(loaded.process.wow64);
    EXPECT_EQ(loaded.captured_at, original.captured_at);
    EXPECT_EQ(loaded.block_size, original.block_size);
    EXPECT_EQ(loaded.page_size, original.page_size);
    ASSERT_EQ(loaded.regions.size(), original.regions.size());
    for (std::size_t i = 0; i < loaded.regions.size(); ++i) {
        EXPECT_EQ(loaded.regions[i].base, original.regions[i].base);
        EXPECT_EQ(loaded.regions[i].size, original.regions[i].size);
        EXPECT_EQ(loaded.regions[i].protect, original.regions[i].protect);
        EXPECT_EQ(loaded.regions[i].type, original.regions[i].type);
    }
    ASSERT_EQ(loaded.spans.size(), original.spans.size());
    for (std::size_t i = 0; i < loaded.spans.size(); ++i) {
        EXPECT_EQ(loaded.spans[i].begin, original.spans[i].begin);
        EXPECT_EQ(loaded.spans[i].end, original.spans[i].end);
    }
    EXPECT_EQ(loaded.states, original.states);
    EXPECT_EQ(loaded.hashes, original.hashes);

    std::vector<std::byte> buffer(loaded.block_size);
    EXPECT_EQ(error_of([&] { file.read_block(0, 0, buffer); }), ErrorCode::InvalidArgument);
    const SnapshotDiff same = diff_snapshots(original, loaded);
    EXPECT_TRUE(same.regions.empty());
    EXPECT_EQ(same.bytes[static_cast<std::size_t>(RangeKind::Changed)], 0u);
    EXPECT_EQ(same.bytes[static_cast<std::size_t>(RangeKind::Unknown)], 4096u);
}

TEST_F(SnapshotFiles, RoundTripWithContents) {
    const Snapshot original = write("data.mhs", true);
    SnapshotFile file(path("data.mhs"));
    EXPECT_TRUE(file.snapshot().has_data);
    EXPECT_GT(file.file_size(), kSnapshotHeaderSize + original.captured_bytes());

    std::vector<std::byte> buffer(original.block_size);
    for (const std::uint64_t address : {kA, kA + 0x4000, kB + 0x1000, kD + 0x1000}) {
        const BlockRef ref = block_at(original, address);
        ASSERT_TRUE(file.read_block(ref.span, ref.block, buffer));
        EXPECT_TRUE(std::ranges::equal(buffer, memory_.view(address, 4096))) << format_address(address);
    }
    const BlockRef bad = block_at(original, kA + 0x3000);
    EXPECT_FALSE(file.read_block(bad.span, bad.block, buffer));
}

TEST_F(SnapshotFiles, UncommittedWriterLeavesNothing) {
    {
        SnapshotWriter writer(path("never.mhs"), true);
        const std::array<std::byte, 16> bytes{};
        writer.write(0, bytes);
        EXPECT_TRUE(std::filesystem::exists(directory_ / "never.mhs.partial"));
    }
    EXPECT_FALSE(std::filesystem::exists(directory_ / "never.mhs"));
    EXPECT_FALSE(std::filesystem::exists(directory_ / "never.mhs.partial"));
}

TEST_F(SnapshotFiles, CommitReplacesAnOlderFile) {
    write_raw("old.mhs", "stale contents");
    write("old.mhs", false);
    EXPECT_NO_THROW(SnapshotFile file(path("old.mhs")));
}

TEST_F(SnapshotFiles, DamagedFilesAreRejected) {
    write("good.mhs", false);
    const std::string good = read_raw("good.mhs");
    ASSERT_GT(good.size(), kSnapshotHeaderSize + 16);

    std::string flipped_meta = good;
    flipped_meta[good.size() - 10] ^= 0x01;
    write_raw("meta.mhs", flipped_meta);
    EXPECT_EQ(open_error("meta.mhs"), ErrorCode::CorruptSnapshot);

    std::string flipped_header = good;
    flipped_header[20] ^= 0x40;
    write_raw("header.mhs", flipped_header);
    EXPECT_EQ(open_error("header.mhs"), ErrorCode::CorruptSnapshot);

    write_raw("short.mhs", good.substr(0, good.size() - 1));
    EXPECT_EQ(open_error("short.mhs"), ErrorCode::CorruptSnapshot);
    write_raw("long.mhs", good + '\0');
    EXPECT_EQ(open_error("long.mhs"), ErrorCode::CorruptSnapshot);
    write_raw("head-only.mhs", good.substr(0, 30));
    EXPECT_EQ(open_error("head-only.mhs"), ErrorCode::CorruptSnapshot);
    write_raw("empty.mhs", "");
    EXPECT_EQ(open_error("empty.mhs"), ErrorCode::CorruptSnapshot);

    write_raw("text.mhs", "this is not a snapshot at all, just some text that is long enough to fill a header");
    try {
        SnapshotFile file(path("text.mhs"));
        FAIL() << "expected an error";
    } catch (const Error& error) {
        EXPECT_EQ(error.code(), ErrorCode::CorruptSnapshot);
        EXPECT_NE(std::string(error.what()).find("is not a MemHunter snapshot"), std::string::npos) << error.what();
    }

    EXPECT_EQ(open_error("missing.mhs"), ErrorCode::Io);
}

TEST_F(SnapshotFiles, NewerFormatVersionIsIncompatible) {
    write("good.mhs", false);
    std::string newer = read_raw("good.mhs");
    newer[8] = 2;
    const std::uint64_t hash = xxh64(std::as_bytes(std::span(newer.data(), kSnapshotHeaderSize - 8)));
    std::memcpy(newer.data() + kSnapshotHeaderSize - 8, &hash, sizeof(hash));
    write_raw("newer.mhs", newer);
    EXPECT_EQ(open_error("newer.mhs"), ErrorCode::IncompatibleSnapshot);
}

TEST_F(SnapshotFiles, DamagedContentsAreDetectedWhenRead) {
    const Snapshot original = write("data.mhs", true);
    std::string bytes = read_raw("data.mhs");
    const BlockRef ref = block_at(original, kA + 0x1000);
    bytes[kSnapshotHeaderSize + original.block_data_offset(ref.span, ref.block) + 77] ^= 0x01;
    write_raw("data.mhs", bytes);

    SnapshotFile file(path("data.mhs"));
    std::vector<std::byte> buffer(original.block_size);
    EXPECT_EQ(error_of([&] { file.read_block(ref.span, ref.block, buffer); }), ErrorCode::CorruptSnapshot);
    const BlockRef other = block_at(original, kA);
    EXPECT_TRUE(file.read_block(other.span, other.block, buffer));
}

TEST(SnapshotDiffTest, ClassifiesRangesAndRegions) {
    FakeMemory before_memory;
    FakeMemory after_memory;
    build_memory(before_memory, false);
    build_memory(after_memory, true);
    const Snapshot before = capture(before_memory).snapshot;
    const Snapshot after = capture(after_memory).snapshot;
    const SnapshotDiff diff = diff_snapshots(before, after);

    EXPECT_FALSE(diff.exact);
    ASSERT_EQ(diff.regions.size(), 3u);
    EXPECT_EQ(diff.regions[0].kind, RegionChangeKind::Removed);
    EXPECT_EQ(diff.regions[0].before.base, kB);
    EXPECT_EQ(diff.regions[1].kind, RegionChangeKind::Added);
    EXPECT_EQ(diff.regions[1].after.base, kC);
    EXPECT_EQ(diff.regions[2].kind, RegionChangeKind::Modified);
    EXPECT_EQ(diff.regions[2].before.protect, page::ReadWrite);
    EXPECT_EQ(diff.regions[2].after.protect, page::ReadOnly);

    const std::vector<DiffRange> expected{
        {kA, kA + 0x1000, RangeKind::Unchanged},       {kA + 0x1000, kA + 0x2000, RangeKind::Changed},
        {kA + 0x2000, kA + 0x5000, RangeKind::Unchanged}, {kA + 0x5000, kA + 0x6000, RangeKind::Unknown},
        {kA + 0x6000, kA + 0x10000, RangeKind::Unchanged}, {kB, kB + 0x4000, RangeKind::Removed},
        {kC, kC + 0x2000, RangeKind::Added},           {kD, kD + 0x2000, RangeKind::Unchanged},
    };
    ASSERT_EQ(diff.ranges.size(), expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i) {
        EXPECT_EQ(diff.ranges[i].begin, expected[i].begin) << i;
        EXPECT_EQ(diff.ranges[i].end, expected[i].end) << i;
        EXPECT_EQ(diff.ranges[i].kind, expected[i].kind) << i;
    }
    const auto bytes = [&](RangeKind kind) { return diff.bytes[static_cast<std::size_t>(kind)]; };
    EXPECT_EQ(bytes(RangeKind::Changed), 0x1000u);
    EXPECT_EQ(bytes(RangeKind::Unknown), 0x1000u);
    EXPECT_EQ(bytes(RangeKind::Unchanged), 0xE000u + 0x2000u);
    EXPECT_EQ(bytes(RangeKind::Added), 0x2000u);
    EXPECT_EQ(bytes(RangeKind::Removed), 0x4000u);
    EXPECT_EQ(diff.range_counts[static_cast<std::size_t>(RangeKind::Unchanged)], 4u);

    const std::vector<AddressRange> rescan = ranges_to_rescan(diff);
    const std::vector<AddressRange> expected_rescan{{kA + 0x1000, kA + 0x2000}, {kA + 0x5000, kA + 0x6000}, {kC, kC + 0x2000}};
    EXPECT_EQ(rescan, expected_rescan);

    const SnapshotDiff same = diff_snapshots(before, before);
    EXPECT_TRUE(same.regions.empty());
    ASSERT_EQ(same.ranges.size(), 3u);
    EXPECT_TRUE(std::ranges::all_of(same.ranges, [](const DiffRange& r) { return r.kind == RangeKind::Unchanged; }));
    EXPECT_TRUE(ranges_to_rescan(same).empty());
}

TEST(SnapshotDiffTest, ContentsGiveByteExactRanges) {
    FakeMemory before_memory;
    FakeMemory after_memory;
    build_memory(before_memory, false);
    build_memory(after_memory, true);
    BufferSink before_data;
    BufferSink after_data;
    const Snapshot before = capture(before_memory, {}, &before_data).snapshot;
    const Snapshot after = capture(after_memory, {}, &after_data).snapshot;
    const SnapshotDiff diff = diff_snapshots(before, after, before_data.reader(before), after_data.reader(after));

    EXPECT_TRUE(diff.exact);
    EXPECT_EQ(diff.bytes[static_cast<std::size_t>(RangeKind::Changed)], 1u);
    ASSERT_GE(diff.ranges.size(), 3u);
    EXPECT_EQ(diff.ranges[0].begin, kA);
    EXPECT_EQ(diff.ranges[0].end, kA + 0x1234);
    EXPECT_EQ(diff.ranges[0].kind, RangeKind::Unchanged);
    EXPECT_EQ(diff.ranges[1].begin, kA + 0x1234);
    EXPECT_EQ(diff.ranges[1].end, kA + 0x1235);
    EXPECT_EQ(diff.ranges[1].kind, RangeKind::Changed);
    EXPECT_EQ(diff.ranges[2].begin, kA + 0x1235);
    EXPECT_EQ(diff.ranges[2].kind, RangeKind::Unchanged);
    EXPECT_EQ(kind_at(diff, kA + 0x5800), RangeKind::Unknown);
}

TEST(SnapshotDiffTest, DifferentlyClippedBlocksAreUnknown) {
    FakeMemory memory;
    testing::fill_random(memory.add(kA, 64 * 1024), 1);
    const Snapshot before = capture(memory).snapshot;
    RegionFilter filter;
    filter.add_include("0x100800-0x110000");
    ScanProgress progress;
    const Snapshot after = capture_snapshot(memory, plan_scan(memory, filter), {}, nullptr, progress, {}).snapshot;
    ASSERT_EQ(after.spans.size(), 1u);
    ASSERT_EQ(after.spans[0].begin, kA + 0x800);

    const SnapshotDiff diff = diff_snapshots(before, after);
    ASSERT_GE(diff.ranges.size(), 3u);
    EXPECT_EQ(diff.ranges[0].kind, RangeKind::Removed);
    EXPECT_EQ(diff.ranges[0].end, kA + 0x800);
    EXPECT_EQ(diff.ranges[1].kind, RangeKind::Unknown);
    EXPECT_EQ(diff.ranges[1].end, kA + 0x1000);
    EXPECT_EQ(diff.ranges[2].kind, RangeKind::Unchanged);
    EXPECT_EQ(diff.ranges[2].end, kA + 0x10000);
}

TEST(SnapshotDiffTest, DifferentBlockSizesAreNotComparable) {
    FakeMemory memory;
    testing::fill_random(memory.add(kA, 64 * 1024), 1);
    CaptureOptions large;
    large.block_size = 0x10000;
    const Snapshot a = capture(memory).snapshot;
    const Snapshot b = capture(memory, large).snapshot;
    EXPECT_EQ(error_of([&] { check_comparable(a, b); }), ErrorCode::IncompatibleSnapshot);
    EXPECT_EQ(error_of([&] { diff_snapshots(a, b); }), ErrorCode::IncompatibleSnapshot);
    EXPECT_NO_THROW(check_comparable(b, b));
}

TEST(SnapshotDiffTest, RangeKindNames) {
    EXPECT_EQ(parse_range_kind("Changed"), RangeKind::Changed);
    EXPECT_EQ(parse_range_kind("removed"), RangeKind::Removed);
    EXPECT_EQ(parse_range_kind("bogus"), std::nullopt);
    for (std::size_t i = 0; i < kRangeKindCount; ++i) {
        const auto kind = static_cast<RangeKind>(i);
        EXPECT_EQ(parse_range_kind(to_string(kind)), kind);
    }
    ProcessSummary a{1, "a.exe", "", 100, false};
    ProcessSummary b = a;
    EXPECT_TRUE(same_process_instance(a, b));
    b.creation_time = 101;
    EXPECT_FALSE(same_process_instance(a, b));
}

TEST(ProcessSnapshot, DiffAndIncrementalRescanFollowTheMovedNeedle) {
    testing::TargetProcess target = testing::start_target(MEMHUNTER_TEST_TARGET);
    const Process process = Process::open(target.pid);
    const ProcessMemory memory(process);
    RegionFilter filter;
    filter.types = type_class::Private;
    const std::vector<std::uint64_t> old_address = target.addresses("mutable");
    ASSERT_EQ(old_address.size(), 1u);

    const auto directory = std::filesystem::temp_directory_path() / ("memhunter-psnap-" + std::to_string(GetCurrentProcessId()));
    std::filesystem::create_directories(directory);
    const std::string file_path = wide_to_utf8((directory / "before.mhs").wstring());
    {
        SnapshotWriter writer(file_path, true);
        ScanProgress progress;
        CaptureResult result = capture_snapshot(memory, plan_scan(memory, filter), {}, &writer, progress, {});
        ASSERT_EQ(result.status, ScanStatus::Completed);
        result.snapshot.process.pid = target.pid;
        writer.commit(result.snapshot);
    }

    const std::string reply = target.command("mutate");
    ASSERT_EQ(reply.rfind("mutated ", 0), 0u) << reply;
    const std::uint64_t moved = parse_uint(reply.substr(8)).value_or(0);

    SnapshotFile before(file_path);
    BufferSink live;
    ScanProgress progress;
    const Snapshot after = capture_snapshot(memory, plan_scan(memory, filter), {}, &live, progress, {}).snapshot;
    const SnapshotDiff blocks = diff_snapshots(before.snapshot(), after);
    EXPECT_EQ(kind_at(blocks, old_address[0]), RangeKind::Changed);
    EXPECT_EQ(kind_at(blocks, moved), RangeKind::Changed);

    const SnapshotDiff exact = diff_snapshots(
        before.snapshot(), after,
        [&before](std::size_t span, std::uint64_t block, std::span<std::byte> out) { return before.read_block(span, block, out); },
        live.reader(after));
    EXPECT_TRUE(exact.exact);
    EXPECT_TRUE(changed_overlaps(exact, old_address[0], old_address[0] + testing::kNeedleSize));
    EXPECT_TRUE(changed_overlaps(exact, moved, moved + testing::kNeedleSize));
    EXPECT_LT(exact.bytes[static_cast<std::size_t>(RangeKind::Changed)], blocks.bytes[static_cast<std::size_t>(RangeKind::Changed)]);

    ScanRequest request;
    request.patterns.push_back(testing::byte_needle(12));
    request.filter = filter;
    request.changed = ranges_to_rescan(blocks);
    ScanProgress scan_progress;
    const ResultSet results = run_scan(memory, request, scan_progress, {});
    ASSERT_EQ(results.matches.size(), 1u);
    EXPECT_EQ(results.matches[0].address, moved);
    EXPECT_LT(results.stats.bytes_planned, before.snapshot().captured_bytes());

    target.child->write_line("exit");
    EXPECT_EQ(target.child->wait(10000), 0u);
    std::error_code ignored;
    std::filesystem::remove_all(directory, ignored);
}

}  // namespace
}  // namespace mh
