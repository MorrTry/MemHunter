#include <gtest/gtest.h>

#include <algorithm>
#include <map>
#include <set>
#include <thread>

#include "common/error.hpp"
#include "memory/process_memory.hpp"
#include "pipeline/scan_session.hpp"
#include "process/process.hpp"
#include "support/oracle.hpp"
#include "support/target_process.hpp"

namespace mh {
namespace {

using testing::byte_needle;
using testing::Needle;
using testing::kNeedleSize;
using testing::kTextNeedleSize;
using testing::text_needle;
using Target = testing::TargetProcess;

Target start_target(std::vector<std::string> extra = {}) {
    Target target = testing::start_target(MEMHUNTER_TEST_TARGET, std::move(extra));
    EXPECT_EQ(target.pid, target.child->pid());
    return target;
}

ScanRequest byte_request(std::initializer_list<std::uint32_t> indices) {
    ScanRequest request;
    for (const auto index : indices) {
        request.patterns.push_back(byte_needle(index));
    }
    return request;
}

ResultSet scan(const Target& target, const ScanRequest& request) {
    const Process process = Process::open(target.pid);
    const ProcessMemory memory(process);
    ScanProgress progress;
    return run_scan(memory, request, progress, {});
}

std::vector<std::uint64_t> hits_of(const ResultSet& results, std::string_view label) {
    std::vector<std::uint64_t> out;
    for (const auto& match : results.matches) {
        if (results.patterns[match.pattern].label == label) {
            out.push_back(match.address);
        }
    }
    return out;
}

class ProcessScan : public ::testing::Test {
protected:
    static void SetUpTestSuite() { target_ = new Target(start_target()); }

    static void TearDownTestSuite() {
        if (target_->child) {
            target_->child->write_line("exit");
        }
        delete target_;
        target_ = nullptr;
    }

    static Target* target_;
};

Target* ProcessScan::target_ = nullptr;

TEST_F(ProcessScan, TargetAnnouncedEveryCase) {
    ASSERT_NE(target_->pid, 0u);
    EXPECT_EQ(target_->addresses("page_boundary").size(), 255u);
    for (const auto* name : {"region_start", "region_end", "cross_protection", "cross_noaccess", "inside_noaccess",
                             "after_noaccess", "guard", "text_ascii", "text_utf16", "text_lower", "execute", "mutable"}) {
        EXPECT_EQ(std::count_if(target_->needles.begin(), target_->needles.end(), [&](const Needle& n) { return n.name == name; }), 1)
            << name;
    }
}

TEST_F(ProcessScan, ByteNeedlesAreFoundExactlyWhereExpected) {
    const ResultSet results = scan(*target_, byte_request({0, 1, 2, 3, 4, 5, 6, 7, 11, 12}));
    EXPECT_EQ(results.stats.status, ScanStatus::Completed);
    for (const auto& needle : target_->needles) {
        if (needle.encoding != "bytes") {
            continue;
        }
        const auto hits = hits_of(results, "n" + std::to_string(needle.index));
        const bool found = std::find(hits.begin(), hits.end(), needle.address) != hits.end();
        EXPECT_EQ(found, needle.expect) << needle.name << " at " << format_address(needle.address);
    }
    for (const std::uint32_t index : {0u, 1u, 2u, 3u, 6u, 11u, 12u}) {
        std::set<std::uint64_t> expected;
        for (const auto& needle : target_->needles) {
            if (needle.index == index && needle.expect) {
                expected.insert(needle.address);
            }
        }
        const auto hits = hits_of(results, "n" + std::to_string(index));
        EXPECT_EQ(std::set<std::uint64_t>(hits.begin(), hits.end()), expected) << "needle " << index;
        EXPECT_EQ(hits.size(), expected.size()) << "needle " << index;
    }
    for (const auto& match : results.matches) {
        const Region* region = results.region_of(match);
        ASSERT_NE(region, nullptr);
        EXPECT_TRUE(region->readable());
        const auto preview = results.preview(match);
        // The preview is a bounded window starting at the match and may run past it.
        ASSERT_GE(preview.size(), kNeedleSize);
        EXPECT_LE(preview.size(), EngineConfig{}.preview_bytes);
        const Pattern needle = byte_needle(std::stoul(results.patterns[match.pattern].label.substr(1)));
        EXPECT_TRUE(needle.matches(reinterpret_cast<const std::uint8_t*>(preview.data())));
    }
    EXPECT_EQ(target_->command("check-guard"), "guard 1");
}

TEST_F(ProcessScan, ResultsDoNotDependOnThreadsChunksOrAlgorithm) {
    ScanRequest request = byte_request({0, 1, 2, 3, 6, 11, 12});
    // Only needles are searched for: the rest of a live process may change between scans.
    Pattern signature = byte_needle(2);
    signature.label = "n2-sig";
    signature.kind = PatternKind::Signature;
    for (const std::size_t i : {0, 5, 15}) {
        signature.and_mask[i] = 0;
        signature.value[i] = 0;
    }
    request.patterns.push_back(signature);
    for (auto& text : make_text_patterns(text_needle(8), encoding::Both, false)) {
        request.patterns.push_back(std::move(text));
    }
    ScanRequest strings_request;
    strings_request.strings = StringOptions{encoding::Both, kTextNeedleSize, 64};
    strings_request.filter.add_include(format_address(target_->addresses("text_ascii")[0] & ~0xFFFull) + "-" +
                                       format_address((target_->addresses("text_ascii")[0] & ~0xFFFull) + 0x1000));

    const auto baseline = testing::found_of(scan(*target_, request));
    const auto strings_baseline = testing::found_of(scan(*target_, strings_request));
    ASSERT_FALSE(baseline.empty());
    ASSERT_EQ(strings_baseline.size(), 3u);
    for (const unsigned threads : {1u, 3u, 16u}) {
        for (const std::size_t chunk : {std::size_t{64} << 10, std::size_t{1} << 20, std::size_t{16} << 20}) {
            for (const auto algorithm : {Algorithm::Auto, Algorithm::Naive, Algorithm::Horspool, Algorithm::AhoCorasick}) {
                request.engine.scan_threads = threads;
                request.chunk_size = chunk;
                request.algorithm = algorithm;
                EXPECT_EQ(testing::found_of(scan(*target_, request)), baseline)
                    << "threads=" << threads << " chunk=" << chunk << " algorithm=" << to_string(algorithm);
            }
            strings_request.engine.scan_threads = threads;
            strings_request.chunk_size = chunk;
            EXPECT_EQ(testing::found_of(scan(*target_, strings_request)), strings_baseline);
        }
    }
}

TEST_F(ProcessScan, TextNeedlesInBothEncodingsAndCases) {
    ScanRequest request;
    request.patterns = make_text_patterns(text_needle(8), encoding::Both, false);
    for (auto& p : make_text_patterns(text_needle(10), encoding::Both, false)) {
        p.label = "lower-exact";
        request.patterns.push_back(std::move(p));
    }
    for (auto& p : make_text_patterns(text_needle(10), encoding::Both, true)) {
        p.label = "lower-folded";
        request.patterns.push_back(std::move(p));
    }
    const ResultSet results = scan(*target_, request);
    std::vector<std::uint64_t> ascii;
    std::vector<std::uint64_t> utf16;
    for (const auto& match : results.matches) {
        if (results.patterns[match.pattern].label != text_needle(8)) {
            continue;
        }
        (results.patterns[match.pattern].kind == PatternKind::Utf16 ? utf16 : ascii).push_back(match.address);
    }
    EXPECT_EQ(ascii, target_->addresses("text_ascii"));
    EXPECT_EQ(utf16, target_->addresses("text_utf16"));
    EXPECT_TRUE(hits_of(results, "lower-exact").empty());
    EXPECT_EQ(hits_of(results, "lower-folded"), target_->addresses("text_lower"));
}

TEST_F(ProcessScan, ExtractedStringsSeeTheTextNeedles) {
    ScanRequest request;
    request.strings = StringOptions{encoding::Both, kTextNeedleSize, 4096};
    const std::uint64_t page = target_->addresses("text_ascii")[0] & ~0xFFFull;
    request.filter.add_include(format_address(page) + "-" + format_address(page + 0x1000));
    const ResultSet results = scan(*target_, request);
    std::map<std::uint64_t, std::string> found;
    for (const auto& match : results.matches) {
        found[match.address] = results.preview_text(match);
    }
    std::string lower = text_needle(10);
    std::transform(lower.begin(), lower.end(), lower.begin(), [](char c) { return static_cast<char>(c - 'A' + 'a'); });
    EXPECT_EQ(found, (std::map<std::uint64_t, std::string>{{page, text_needle(8)}, {page + 512, text_needle(8)}, {page + 2048, lower}}));
}

TEST_F(ProcessScan, RegionFiltersLimitTheScan) {
    ScanRequest request = byte_request({0, 1, 11});
    request.filter.protections = parse_protection_list("rw");
    ResultSet results = scan(*target_, request);
    EXPECT_TRUE(hits_of(results, "n11").empty());
    EXPECT_EQ(hits_of(results, "n0"), target_->addresses("region_start"));

    request = byte_request({0, 1, 11});
    request.filter.protections = parse_protection_list("rx");
    results = scan(*target_, request);
    EXPECT_EQ(hits_of(results, "n11"), target_->addresses("execute"));
    EXPECT_TRUE(hits_of(results, "n0").empty());

    request = byte_request({0, 1, 11});
    const std::uint64_t start = target_->addresses("region_start")[0];
    request.filter.add_include(format_address(start) + "-" + format_address(start + 0x8000));
    results = scan(*target_, request);
    EXPECT_EQ(hits_of(results, "n0"), target_->addresses("region_start"));
    EXPECT_TRUE(hits_of(results, "n1").empty());
    EXPECT_TRUE(hits_of(results, "n11").empty());
    EXPECT_LE(results.stats.bytes_planned, 0x8000u);
}

TEST(ProcessRescan, SeesMemoryChangesBetweenScans) {
    Target target = start_target();
    const ScanRequest request = byte_request({12});
    EXPECT_EQ(hits_of(scan(target, request), "n12"), target.addresses("mutable"));

    const std::string reply = target.command("mutate");
    ASSERT_EQ(reply.rfind("mutated ", 0), 0u) << reply;
    const std::uint64_t moved = parse_uint(reply.substr(8)).value_or(0);
    EXPECT_EQ(hits_of(scan(target, request), "n12"), std::vector<std::uint64_t>{moved});

    ScanRequest incremental = request;
    incremental.changed = std::vector<AddressRange>{{moved, moved + 1}};
    const ResultSet changed = scan(target, incremental);
    EXPECT_EQ(hits_of(changed, "n12"), std::vector<std::uint64_t>{moved});
    EXPECT_LT(changed.stats.bytes_planned, 0x1000u);
    target.child->write_line("exit");
    EXPECT_EQ(target.child->wait(10000), 0u);
}

TEST(ProcessRescan, TargetExitingDuringScanIsReported) {
    Target target = start_target({"--fill", "512M"});
    ASSERT_GE(target.fill_bytes, 512ull << 20);
    const Process process = Process::open(target.pid);
    const ProcessMemory memory(process);
    ScanRequest request = byte_request({100, 101});
    request.engine.scan_threads = 1;
    request.engine.read_threads = 1;
    request.chunk_size = 64 << 10;
    ScanProgress progress;
    std::jthread killer([&] {
        while (progress.bytes_done.load() < (1ull << 20)) {
            std::this_thread::yield();
        }
        target.child->kill();
    });
    const ResultSet results = run_scan(memory, request, progress, {});
    killer.join();
    EXPECT_EQ(results.stats.status, ScanStatus::TargetExited);
    EXPECT_LT(results.stats.bytes_read, results.stats.bytes_planned);
    EXPECT_FALSE(process.is_running());
}

TEST(ProcessOpen, MissingProcessIsReported) {
    try {
        Process::open(0xFFFFFFF0u);
        FAIL() << "expected an error";
    } catch (const Error& error) {
        EXPECT_EQ(error.code(), ErrorCode::ProcessNotFound);
    }
    EXPECT_THROW(resolve_process("no-such-process-name-memhunter.exe"), Error);
    EXPECT_EQ(resolve_process(std::to_string(GetCurrentProcessId())), GetCurrentProcessId());
}

}  // namespace
}  // namespace mh
