#include <gtest/gtest.h>

#include <windows.h>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <string>
#include <vector>

#include "common/error.hpp"
#include "common/text.hpp"
#include "snapshot/hash.hpp"
#include "support/fake_memory.hpp"
#include "value/value_file.hpp"

namespace mh {
namespace {

using testing::FakeMemory;

constexpr std::uint64_t kBase = 0x100000;
constexpr std::size_t kHeaderSize = 40;

ProcessSummary game() {
    ProcessSummary process;
    process.pid = 4242;
    process.name = "game.exe";
    process.path = "C:\\Games\\game.exe";
    process.creation_time = 133'000'000'000'000'000ull;
    process.wow64 = true;
    return process;
}

// One dense block for the first page and two sparse entries in the second.
ValueCandidates mixed_candidates() {
    FakeMemory memory;
    memory.add(kBase, FakeMemory::kPage);
    std::span<std::byte> second = memory.add(kBase + 0x10000, FakeMemory::kPage, page::ReadWrite, MemType::Image);
    std::memset(second.data(), 1, second.size());
    std::memset(second.data() + 0x10, 0, 4);
    std::memset(second.data() + 0x20, 0, 4);
    ValueScanOptions options;
    options.chunk_size = FakeMemory::kPage;
    ScanProgress progress;
    ValueCondition zero;
    zero.compare = Compare::Exact;
    ValueScanResult result =
        first_value_scan(memory, plan_scan(memory, RegionFilter{}), ValueType::Int32, true, zero, options, progress, {});
    result.candidates.regions.at(1).mapped_file = "C:\\Games\\game.exe";
    return std::move(result.candidates);
}

void expect_same(const ValueCandidates& a, const ValueCandidates& b) {
    EXPECT_EQ(a.type, b.type);
    EXPECT_EQ(a.aligned, b.aligned);
    EXPECT_EQ(a.scans, b.scans);
    ASSERT_EQ(a.regions.size(), b.regions.size());
    for (std::size_t i = 0; i < a.regions.size(); ++i) {
        EXPECT_EQ(a.regions[i].base, b.regions[i].base);
        EXPECT_EQ(a.regions[i].size, b.regions[i].size);
        EXPECT_EQ(a.regions[i].protect, b.regions[i].protect);
        EXPECT_EQ(a.regions[i].type, b.regions[i].type);
        EXPECT_EQ(a.regions[i].mapped_file, b.regions[i].mapped_file);
    }
    ASSERT_EQ(a.dense.size(), b.dense.size());
    for (std::size_t i = 0; i < a.dense.size(); ++i) {
        EXPECT_EQ(a.dense[i].base, b.dense[i].base);
        EXPECT_EQ(a.dense[i].first, b.dense[i].first);
        EXPECT_EQ(a.dense[i].positions, b.dense[i].positions);
        EXPECT_EQ(a.dense[i].count, b.dense[i].count);
        EXPECT_EQ(a.dense[i].alive, b.dense[i].alive);
        EXPECT_EQ(a.dense[i].bytes, b.dense[i].bytes);
    }
    ASSERT_EQ(a.sparse.size(), b.sparse.size());
    for (std::size_t i = 0; i < a.sparse.size(); ++i) {
        EXPECT_EQ(a.sparse[i].address, b.sparse[i].address);
        EXPECT_EQ(a.sparse[i].previous, b.sparse[i].previous);
    }
}

void expect_rejected(const std::vector<std::byte>& bytes, ErrorCode code, const std::string& text, const char* what) {
    try {
        decode_value_file(bytes, "x.mhv");
        ADD_FAILURE() << what << ": accepted";
    } catch (const Error& error) {
        EXPECT_EQ(error.code(), code) << what << ": " << error.what();
        EXPECT_NE(std::string(error.what()).find(text), std::string::npos) << what << ": " << error.what();
    }
}

std::uint64_t load64(const std::vector<std::byte>& bytes, std::size_t offset) {
    std::uint64_t value;
    std::memcpy(&value, bytes.data() + offset, sizeof value);
    return value;
}

void store(std::vector<std::byte>& bytes, std::size_t offset, std::uint64_t value, std::size_t size) {
    std::memcpy(bytes.data() + offset, &value, size);
}

TEST(ValueFile, RoundTripKeepsEveryField) {
    const ValueCandidates candidates = mixed_candidates();
    ASSERT_EQ(candidates.dense.size(), 1u);
    ASSERT_EQ(candidates.sparse.size(), 2u);
    ASSERT_EQ(candidates.regions.size(), 2u);

    const ValueFile file = decode_value_file(encode_value_file(game(), candidates), "x.mhv");
    EXPECT_EQ(file.process.pid, 4242u);
    EXPECT_EQ(file.process.name, "game.exe");
    EXPECT_EQ(file.process.path, "C:\\Games\\game.exe");
    EXPECT_EQ(file.process.creation_time, game().creation_time);
    EXPECT_TRUE(file.process.wow64);
    expect_same(file.candidates, candidates);
}

TEST(ValueFile, WritesThroughATemporaryFileAndReplacesTheOldOne) {
    const auto directory = std::filesystem::temp_directory_path() / ("memhunter-values-" + std::to_string(GetCurrentProcessId()));
    std::filesystem::create_directories(directory);
    const std::string path = wide_to_utf8((directory / "hp.mhv").wstring());
    std::ofstream(directory / "hp.mhv") << "old contents";

    const ValueCandidates candidates = mixed_candidates();
    const std::uint64_t size = write_value_file(path, game(), candidates);
    EXPECT_EQ(size, std::filesystem::file_size(directory / "hp.mhv"));
    EXPECT_FALSE(std::filesystem::exists(directory / "hp.mhv.partial"));
    expect_same(read_value_file(path).candidates, candidates);

    try {
        read_value_file(wide_to_utf8((directory / "missing.mhv").wstring()));
        ADD_FAILURE() << "a missing file was read";
    } catch (const Error& error) {
        EXPECT_EQ(error.code(), ErrorCode::Io);
    }
    std::error_code ignored;
    std::filesystem::remove_all(directory, ignored);
}

TEST(ValueFile, RejectsForeignTruncatedAndDamagedFiles) {
    const std::vector<std::byte> good = encode_value_file(game(), mixed_candidates());
    ASSERT_GT(good.size(), kHeaderSize);
    const auto damaged = ErrorCode::CorruptSnapshot;

    const std::string snapshot_magic = "MHSNAP\x1A\n and more bytes after the magic of a snapshot file";
    std::vector<std::byte> foreign(snapshot_magic.size());
    std::memcpy(foreign.data(), snapshot_magic.data(), snapshot_magic.size());
    expect_rejected(foreign, damaged, "is not a MemHunter value file", "snapshot");
    expect_rejected({}, damaged, "is not a MemHunter value file", "empty");

    expect_rejected({good.begin(), good.begin() + 20}, damaged, "truncated", "cut header");
    expect_rejected({good.begin(), good.end() - 1}, damaged, "truncated", "cut payload");
    std::vector<std::byte> longer = good;
    longer.push_back(std::byte{0});
    expect_rejected(longer, damaged, "trailing", "trailing byte");

    std::vector<std::byte> payload = good;
    payload[kHeaderSize + 30] ^= std::byte{0x40};
    expect_rejected(payload, damaged, "checksum", "flipped payload byte");
    std::vector<std::byte> header = good;
    header[16] ^= std::byte{0x01};
    expect_rejected(header, damaged, "checksum", "flipped header byte");
}

TEST(ValueFile, RejectsANewerFormat) {
    std::vector<std::byte> newer = encode_value_file(game(), mixed_candidates());
    store(newer, 8, 2, 4);
    store(newer, 32, xxh64(std::span(newer).first(32)), 8);
    expect_rejected(newer, ErrorCode::IncompatibleSnapshot, "newer", "version 2");
    EXPECT_EQ(load64(newer, 32), xxh64(std::span(newer).first(32)));
}

TEST(ValueFile, RejectsInconsistentCandidates) {
    const ValueCandidates good = mixed_candidates();
    const auto rejects = [&](const char* what, const std::function<void(ValueCandidates&)>& spoil) {
        ValueCandidates bad = good;
        spoil(bad);
        expect_rejected(encode_value_file(game(), bad), ErrorCode::CorruptSnapshot, "is damaged", what);
    };
    rejects("bits past the positions", [](ValueCandidates& c) { c.dense[0].positions = 1000; });
    rejects("count differs from the bits", [](ValueCandidates& c) { c.dense[0].count -= 1; });
    rejects("bytes too short", [](ValueCandidates& c) { c.dense[0].bytes.resize(100); });
    rejects("misaligned first", [](ValueCandidates& c) { c.dense[0].first += 1; });
    rejects("unsorted sparse", [](ValueCandidates& c) { std::swap(c.sparse[0], c.sparse[1]); });
    rejects("sparse value too wide", [](ValueCandidates& c) { c.sparse[0].previous = std::uint64_t{1} << 40; });
    rejects("unknown type", [](ValueCandidates& c) { c.type = static_cast<ValueType>(9); });
    rejects("no scan", [](ValueCandidates& c) { c.scans = 0; });
    rejects("overlapping regions", [](ValueCandidates& c) { c.regions[1].base = c.regions[0].base + 0x10; });
}

}  // namespace
}  // namespace mh
