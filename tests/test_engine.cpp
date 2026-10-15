#include <gtest/gtest.h>

#include <algorithm>
#include <random>

#include "common/text.hpp"
#include "pipeline/scan_session.hpp"
#include "support/fake_memory.hpp"
#include "support/oracle.hpp"

namespace mh {
namespace {

using testing::FakeMemory;
using testing::Found;
using testing::found_of;
using testing::reference_scan;

constexpr std::uint64_t kA = 0x100000;  // 256K rw, followed directly by B
constexpr std::uint64_t kB = 0x140000;  // 64K r, followed directly by C
constexpr std::uint64_t kC = 0x150000;  // 16K no-access
constexpr std::uint64_t kD = 0x154000;  // 128K rw
constexpr std::uint64_t kH = 0x1F0000;  // 64K rw, followed directly by E
constexpr std::uint64_t kE = 0x200000;  // 32K rw + guard
constexpr std::uint64_t kF = 0x300000;  // 64K reserved
constexpr std::uint64_t kG = 0x400000;  // 300K r-x image

class EngineTest : public ::testing::Test {
protected:
    void SetUp() override {
        std::mt19937_64 rng(2024);
        const auto add = [&](std::uint64_t base, std::size_t size, std::uint32_t protect, MemType type = MemType::Private) {
            testing::fill_random(memory_.add(base, size, protect, type), rng());
        };
        add(kA, 256 * 1024, page::ReadWrite);
        add(kB, 64 * 1024, page::ReadOnly);
        add(kC, 16 * 1024, page::NoAccess);
        add(kD, 128 * 1024, page::ReadWrite);
        add(kH, 64 * 1024, page::ReadWrite);
        add(kE, 32 * 1024, page::ReadWrite | page::Guard);
        memory_.add_reserved(kF, 64 * 1024);
        add(kG, 300 * 1024, page::ExecuteRead, MemType::Image);

        for (std::size_t i = 0; i < 16; ++i) {
            needle_.push_back(static_cast<std::uint8_t>(rng()));
        }
        // Region and span edges, region boundaries inside a span, span ends next to unreadable memory on both
        // sides, inside the guard region, and then every ~3000 bytes so that any chunk boundary is crossed.
        plant(kA);
        plant(kB - 7);
        plant(kC - 16);
        plant(kD - 5);
        plant(kD + 11);
        plant(kE - 5);
        plant(kD + 128 * 1024 - 16);
        plant(kE + 100);
        plant(kG + 300 * 1024 - 16);
        for (std::uint64_t at = kA + 1000; at + 16 < kB + 60 * 1024; at += 2999) {
            plant(at);
        }
        for (std::uint64_t at = kG + 17; at + 16 < kG + 300 * 1024; at += 3001) {
            plant(at);
        }

        put(kA + 5000, std::string(10, 'A'));
        put(kD + 4090, "config.json");
        put(kD + 8000, "CONFIG.JSON");
        put_utf16(kG + 4094, "Config.Json");
        put(kA + 65536 - 100, std::string(300, 'x'));

        patterns_.push_back(exact(needle_, "needle"));
        Pattern sig = exact(needle_, "needle-sig");
        for (const std::size_t i : {2, 3, 9}) {
            sig.and_mask[i] = 0;
            sig.value[i] = 0;
        }
        sig.and_mask[12] = 0xF0;
        sig.value[12] &= 0xF0;
        sig.kind = PatternKind::Signature;
        patterns_.push_back(sig);
        for (auto& p : make_text_patterns("config.json", encoding::Both, true)) {
            patterns_.push_back(std::move(p));
        }
        patterns_.push_back(exact({'A', 'A', 'A', 'A'}, "AAAA"));
        patterns_.push_back(parse_signature("90 ?? 90"));
        std::vector<std::uint8_t> long_pattern;
        for (const auto b : read(kA + 30000, 3000)) {
            long_pattern.push_back(static_cast<std::uint8_t>(b));
        }
        patterns_.push_back(exact(long_pattern, "long"));
    }

    static Pattern exact(const std::vector<std::uint8_t>& bytes, std::string label) {
        Pattern pattern;
        pattern.label = std::move(label);
        pattern.kind = PatternKind::Bytes;
        pattern.value = bytes;
        pattern.and_mask.assign(bytes.size(), 0xFF);
        pattern.or_mask.assign(bytes.size(), 0x00);
        return pattern;
    }

    // Byte-wise so that planted data may cross fake region boundaries.
    void write(std::uint64_t address, std::span<const std::uint8_t> bytes) {
        for (std::size_t i = 0; i < bytes.size(); ++i) {
            memory_.bytes_at(address + i, 1)[0] = static_cast<std::byte>(bytes[i]);
        }
    }

    std::vector<std::byte> read(std::uint64_t address, std::size_t size) const {
        std::vector<std::byte> out;
        for (std::size_t i = 0; i < size; ++i) {
            out.push_back(memory_.view(address + i, 1)[0]);
        }
        return out;
    }

    void plant(std::uint64_t address) { write(address, needle_); }

    void put(std::uint64_t address, std::string_view text) {
        write(address, std::span(reinterpret_cast<const std::uint8_t*>(text.data()), text.size()));
    }

    void put_utf16(std::uint64_t address, std::string_view text) {
        std::vector<std::uint8_t> bytes;
        for (const char c : text) {
            bytes.push_back(static_cast<std::uint8_t>(c));
            bytes.push_back(0);
        }
        write(address, bytes);
    }

    ScanRequest request(unsigned threads, std::size_t chunk, Algorithm algorithm = Algorithm::Auto) const {
        ScanRequest r;
        r.patterns = patterns_;
        r.chunk_size = chunk;
        r.algorithm = algorithm;
        r.engine.scan_threads = threads;
        r.engine.read_threads = std::max(1u, threads / 2);
        r.engine.max_matches = 0;
        return r;
    }

    ResultSet scan(const ScanRequest& r, std::stop_token stop = {}) {
        ScanProgress progress;
        ResultSet results = run_scan(memory_, r, progress, std::move(stop));
        if (results.stats.status == ScanStatus::Completed) {
            EXPECT_EQ(progress.chunks_done.load(), results.stats.chunks);
            EXPECT_EQ(progress.bytes_done.load(), results.stats.bytes_planned);
            EXPECT_EQ(progress.regions_done.load(), progress.regions_total.load());
            EXPECT_LE(progress.regions_total.load(), results.stats.regions_selected);
        }
        return results;
    }

    std::vector<Found> expected(const ScanRequest& r) const {
        StringIds ids;
        describe_patterns(r, &ids);
        return reference_scan(memory_, r.filter, r.patterns, r.strings, ids);
    }

    FakeMemory memory_;
    std::vector<std::uint8_t> needle_;
    std::vector<Pattern> patterns_;
};

TEST_F(EngineTest, ReferenceSanity) {
    const auto reference = expected(request(1, 4096));
    const auto count = [&](std::uint32_t pattern) {
        return std::count_if(reference.begin(), reference.end(), [&](const Found& f) { return std::get<1>(f) == pattern; });
    };
    EXPECT_GT(count(0), 150);
    EXPECT_EQ(count(2), 2);  // ASCII config.json, both cases
    EXPECT_EQ(count(3), 1);  // UTF-16
    EXPECT_EQ(count(4), 7);  // overlapping AAAA in ten A's
    EXPECT_EQ(count(6), 1);
    const auto at = [&](std::uint64_t address) {
        return std::any_of(reference.begin(), reference.end(), [&](const Found& f) { return std::get<0>(f) == address; });
    };
    EXPECT_TRUE(at(kB - 7));         // crosses the A/B region boundary inside one span
    EXPECT_TRUE(at(kC - 16));        // ends exactly at the span end
    EXPECT_FALSE(at(kD - 5));        // starts in no-access memory
    EXPECT_FALSE(at(kE - 5));        // would continue into the guard region
    EXPECT_FALSE(at(kE + 100));      // guard region
    EXPECT_TRUE(at(kD + 11));
}

TEST_F(EngineTest, MatchesReferenceForEveryThreadCountChunkSizeAndAlgorithm) {
    const auto reference = expected(request(1, 4096));
    for (const unsigned threads : {1u, 2u, 5u, 16u}) {
        for (const std::size_t chunk : {std::size_t{4096}, std::size_t{4097}, std::size_t{10007}, std::size_t{65536}, std::size_t{1} << 20}) {
            for (const auto algorithm : {Algorithm::Auto, Algorithm::Naive, Algorithm::Horspool, Algorithm::Simd, Algorithm::AhoCorasick}) {
                const ResultSet results = scan(request(threads, chunk, algorithm));
                ASSERT_EQ(results.stats.status, ScanStatus::Completed);
                ASSERT_EQ(found_of(results), reference)
                    << "threads=" << threads << " chunk=" << chunk << " algorithm=" << to_string(algorithm);
                EXPECT_EQ(results.stats.bytes_read, results.stats.bytes_planned);
                EXPECT_EQ(results.stats.bytes_unreadable, 0u);
            }
        }
    }
    EXPECT_EQ(memory_.guard_reads(), 0u);
}

TEST_F(EngineTest, StringExtractionIsIndependentOfChunking) {
    ScanRequest base = request(1, 4096);
    base.patterns.clear();
    base.strings = StringOptions{encoding::Both, 6, 64};
    const auto reference = expected(base);
    ASSERT_FALSE(reference.empty());
    for (const unsigned threads : {1u, 3u, 16u}) {
        for (const std::size_t chunk : {std::size_t{4096}, std::size_t{4099}, std::size_t{65536}}) {
            ScanRequest r = base;
            r.chunk_size = chunk;
            r.engine.scan_threads = threads;
            ASSERT_EQ(found_of(scan(r)), reference) << "threads=" << threads << " chunk=" << chunk;
        }
    }
}

TEST_F(EngineTest, PreviewsHoldTheMatchedBytes) {
    ScanRequest r = request(4, 4096);
    r.strings = StringOptions{encoding::Ascii, 8, 64};
    r.engine.preview_bytes = 24;
    const ResultSet results = scan(r);
    ASSERT_FALSE(results.matches.empty());
    for (const auto& match : results.matches) {
        const auto preview = results.preview(match);
        const bool string = is_extracted_string(results.patterns[match.pattern].kind);
        if (string) {
            EXPECT_EQ(preview.size(), match.length);
        } else {
            EXPECT_GE(preview.size(), std::min<std::size_t>(24, match.length));
            EXPECT_LE(preview.size(), 24u);
        }
        const auto memory = read(match.address, preview.size());
        EXPECT_TRUE(std::equal(preview.begin(), preview.end(), memory.begin())) << format_address(match.address);
        ASSERT_NE(results.region_of(match), nullptr);
        EXPECT_TRUE(results.region_of(match)->base <= match.address && match.address < results.region_of(match)->end());
    }
}

TEST_F(EngineTest, PagesThatFailToReadAreSkippedAndReported) {
    for (const bool all_or_nothing : {false, true}) {
        FakeMemory& memory = memory_;
        memory.set_all_or_nothing(all_or_nothing);
        memory.fail_page(kA + 8 * 4096);
        memory.fail_page(kA + 9 * 4096);
        memory.fail_page(kD + 3 * 4096);
        memory.fail_page(kG);
        const auto reference = expected(request(1, 4096));
        for (const std::size_t chunk : {std::size_t{4096}, std::size_t{6000}, std::size_t{1} << 20}) {
            const ResultSet results = scan(request(3, chunk));
            ASSERT_EQ(found_of(results), reference) << "chunk=" << chunk << " all_or_nothing=" << all_or_nothing;
            EXPECT_EQ(results.stats.status, ScanStatus::Completed);
            EXPECT_EQ(results.stats.bytes_unreadable, 4u * 4096);
            EXPECT_EQ(results.stats.bytes_read + results.stats.bytes_unreadable, results.stats.bytes_planned);
            std::uint64_t reported = 0;
            for (const auto& failure : results.read_failures) {
                reported += failure.size;
                EXPECT_FALSE(memory.page_readable(failure.address));
            }
            EXPECT_EQ(reported, 4u * 4096);
        }
    }
}

TEST_F(EngineTest, TargetExitEndsTheScanWithPartialResults) {
    memory_.exit_after_reads(3);
    const ResultSet results = scan(request(2, 4096));
    EXPECT_EQ(results.stats.status, ScanStatus::TargetExited);
    const auto reference = expected(request(1, 4096));
    for (const auto& found : found_of(results)) {
        EXPECT_TRUE(std::binary_search(reference.begin(), reference.end(), found));
    }
}

TEST_F(EngineTest, CancellationStopsCleanly) {
    std::stop_source stop;
    memory_.on_read([&](std::size_t reads) {
        if (reads == 5) {
            stop.request_stop();
        }
    });
    const ResultSet results = scan(request(4, 4096), stop.get_token());
    EXPECT_EQ(results.stats.status, ScanStatus::Cancelled);
    EXPECT_LT(results.stats.bytes_read, results.stats.bytes_planned);

    std::stop_source already;
    already.request_stop();
    EXPECT_EQ(scan(request(4, 4096), already.get_token()).stats.status, ScanStatus::Cancelled);
}

TEST_F(EngineTest, MatchCapKeepsCountingButStopsStoring) {
    ScanRequest r = request(4, 4096);
    r.patterns = {patterns_[0]};
    const std::size_t total = expected(r).size();
    r.engine.max_matches = 10;
    const ResultSet results = scan(r);
    EXPECT_EQ(results.matches.size(), 10u);
    EXPECT_TRUE(results.stats.truncated);
    EXPECT_EQ(results.stats.matches_found, total);
}

TEST_F(EngineTest, RegionFiltersApply) {
    ScanRequest r = request(2, 65536);
    r.filter.protections = parse_protection_list("rw");
    const ResultSet rw = scan(r);
    EXPECT_EQ(found_of(rw), expected(r));
    for (const auto& match : rw.matches) {
        EXPECT_TRUE(match.address < kB || (match.address >= kD && match.address < kD + 128 * 1024) ||
                    (match.address >= kH && match.address < kE));
    }

    r = request(2, 65536);
    r.filter.types = parse_type_list("image");
    r.filter.add_exclude("0x400000-0x401000");
    const ResultSet image = scan(r);
    EXPECT_EQ(found_of(image), expected(r));
    for (const auto& match : image.matches) {
        EXPECT_GE(match.address, kG + 0x1000);
    }
}

TEST_F(EngineTest, ChangedRangesFindOnlyOverlappingMatches) {
    ScanRequest r = request(3, 4096);
    const std::vector<AddressRange> changed{{kB - 4, kB}, {kD + 4095, kD + 4096}, {kG + 100000, kG + 120000}};
    r.changed = changed;
    const ResultSet results = scan(r);
    std::vector<Found> want;
    for (const auto& f : expected(request(1, 4096))) {
        const std::uint64_t begin = std::get<0>(f);
        const std::uint64_t end = begin + std::get<2>(f);
        if (std::any_of(changed.begin(), changed.end(), [&](const AddressRange& c) { return begin < c.end && c.begin < end; })) {
            want.push_back(f);
        }
    }
    ASSERT_FALSE(want.empty());
    EXPECT_EQ(found_of(results), want);
    EXPECT_LT(results.stats.bytes_planned, 100000u);
}

TEST_F(EngineTest, NothingSelectedIsNotAnError) {
    ScanRequest r = request(2, 4096);
    r.filter.min_size = 1ull << 40;
    const ResultSet results = scan(r);
    EXPECT_EQ(results.stats.status, ScanStatus::Completed);
    EXPECT_TRUE(results.matches.empty());
    EXPECT_EQ(results.stats.chunks, 0u);
}

}  // namespace
}  // namespace mh
