#include <gtest/gtest.h>

#include <cstring>
#include <stop_token>
#include <string>
#include <vector>

#include "common/error.hpp"
#include "pipeline/scan_session.hpp"
#include "pointer/pointer_file.hpp"
#include "pointer/pointer_scan.hpp"
#include "support/fake_memory.hpp"

namespace mh {
namespace {

using testing::FakeMemory;

void put(FakeMemory& memory, std::uint64_t address, std::uint64_t value, unsigned size = 8) {
    std::memcpy(memory.bytes_at(address, size).data(), &value, size);
}

// game.exe: a read-only header page and a data page. The heap holds S1 -> A, A+0x20 -> B, S2 -> B and the value
// at B+0x30.
struct Layout {
    std::uint64_t game;
    std::uint64_t heap;
    unsigned size = 8;

    std::uint64_t s1() const { return game + 0x1010; }
    std::uint64_t s2() const { return game + 0x1020; }
    std::uint64_t a() const { return heap + 0x4000; }
    std::uint64_t b() const { return heap + 0x8000; }
    std::uint64_t target() const { return b() + 0x30; }

    void build(FakeMemory& memory, const std::string& file = "C:\\Games\\game.exe") const {
        memory.add_image(game, 0x1000, file, 0, page::ReadOnly);
        memory.add_image(game + 0x1000, 0x1000, file, game);
        memory.add(heap, 0x10000);
        put(memory, s1(), a(), size);
        put(memory, a() + 0x20, b(), size);
        put(memory, s2(), b(), size);
        put(memory, target(), 100, 4);
    }
};

constexpr Layout kLayout{0x140000000, 0x200000};

struct Chain {
    std::string module;
    std::uint64_t base_offset;
    std::vector<std::uint32_t> offsets;

    friend bool operator==(const Chain&, const Chain&) = default;
};

std::ostream& operator<<(std::ostream& out, const Chain& chain) {
    out << chain.module << "+" << std::hex << chain.base_offset;
    for (const std::uint32_t offset : chain.offsets) {
        out << " " << offset;
    }
    return out;
}

std::vector<Chain> listed(const PointerChains& chains) {
    std::vector<Chain> out;
    for (const PointerChain& chain : chains.chains) {
        const auto steps = chain.steps();
        out.push_back({chains.modules.at(chain.module), chain.base_offset, {steps.begin(), steps.end()}});
    }
    return out;
}

class PointerScan : public ::testing::Test {
protected:
    FakeMemory memory;
    PointerScanOptions options;
    std::stop_source stop;

    void SetUp() override {
        options.threads = 3;
        options.chunk_size = 0x1000;
    }

    PointerScanResult scan(std::uint64_t target, unsigned pointer_size = 8) {
        PointerScanProgress progress;
        return find_pointer_chains(memory, plan_scan(memory, RegionFilter{}), target, pointer_size, options, progress,
                                   stop.get_token());
    }
};

TEST_F(PointerScan, FindsChainsShortestFirst) {
    kLayout.build(memory);
    const PointerScanResult result = scan(kLayout.target());
    EXPECT_EQ(result.status, PointerScanStatus::Completed);
    EXPECT_EQ(result.chains.pointer_size, 8u);
    const std::vector<Chain> expected{{"game.exe", 0x1020, {0x30}}, {"game.exe", 0x1010, {0x20, 0x30}}};
    EXPECT_EQ(listed(result.chains), expected);
    EXPECT_EQ(result.total_chains, 2u);
    EXPECT_FALSE(result.truncated());
    EXPECT_EQ(result.pointers, 3u);
    EXPECT_GT(result.bytes_read, 0u);
}

TEST_F(PointerScan, StopsAtTheDepth) {
    kLayout.build(memory);
    options.depth = 1;
    const std::vector<Chain> expected{{"game.exe", 0x1020, {0x30}}};
    EXPECT_EQ(listed(scan(kLayout.target()).chains), expected);
}

TEST_F(PointerScan, MaxOffsetIsInclusive) {
    kLayout.build(memory);
    options.max_offset = 0x2F;
    EXPECT_TRUE(scan(kLayout.target()).chains.chains.empty());
    options.max_offset = 0x30;
    EXPECT_EQ(scan(kLayout.target()).chains.chains.size(), 2u);
}

TEST_F(PointerScan, CyclesAddNoChains) {
    kLayout.build(memory);
    put(memory, kLayout.a() + 0x8, kLayout.a());
    put(memory, kLayout.b(), kLayout.a() + 0x20);
    const PointerScanResult result = scan(kLayout.target());
    EXPECT_EQ(result.status, PointerScanStatus::Completed);
    const std::vector<Chain> expected{{"game.exe", 0x1020, {0x30}}, {"game.exe", 0x1010, {0x20, 0x30}}};
    EXPECT_EQ(listed(result.chains), expected);
}

TEST_F(PointerScan, IgnoresUnalignedPointers) {
    kLayout.build(memory);
    put(memory, kLayout.game + 0x1031, kLayout.b());
    EXPECT_EQ(scan(kLayout.target()).chains.chains.size(), 2u);
}

TEST_F(PointerScan, DefaultMemoryIsWritableMemory) {
    kLayout.build(memory);
    put(memory, kLayout.game + 0x100, kLayout.b());
    EXPECT_EQ(scan(kLayout.target()).chains.chains.size(), 3u);
    PointerScanProgress progress;
    const PointerScanResult result = find_pointer_chains(memory, plan_scan(memory, pointer_region_filter()), kLayout.target(), 8,
                                                         options, progress, stop.get_token());
    EXPECT_EQ(result.chains.chains.size(), 2u);
}

TEST_F(PointerScan, ChainsNeverPassAnotherImageAddress) {
    kLayout.build(memory);
    put(memory, kLayout.game + 0x1100, kLayout.s2());
    put(memory, kLayout.heap + 0x100, kLayout.s2() - 0x8);
    EXPECT_EQ(scan(kLayout.target()).chains.chains.size(), 2u);
}

TEST_F(PointerScan, TargetInAnImageIsAChainWithoutPointers) {
    kLayout.build(memory);
    put(memory, kLayout.game + 0x1900, kLayout.game + 0x1800);
    const std::vector<Chain> expected{{"game.exe", 0x1800, {}}};
    EXPECT_EQ(listed(scan(kLayout.game + 0x1800).chains), expected);
}

TEST_F(PointerScan, ThirtyTwoBitPointers) {
    const Layout layout{0x400000, 0xA00000, 4};
    layout.build(memory, "C:\\Games\\game32.exe");
    put(memory, layout.game + 0x1024, layout.b(), 4);
    const PointerScanResult result = scan(layout.target(), 4);
    EXPECT_EQ(result.chains.pointer_size, 4u);
    const std::vector<Chain> expected{
        {"game32.exe", 0x1020, {0x30}}, {"game32.exe", 0x1024, {0x30}}, {"game32.exe", 0x1010, {0x20, 0x30}}};
    EXPECT_EQ(listed(result.chains), expected);
}

TEST_F(PointerScan, MaxChainsCutsTheList) {
    kLayout.build(memory);
    options.max_chains = 1;
    const PointerScanResult result = scan(kLayout.target());
    EXPECT_EQ(result.chains.chains.size(), 1u);
    EXPECT_EQ(result.total_chains, 2u);
    EXPECT_TRUE(result.truncated());
}

TEST_F(PointerScan, CountsChainsThroughSharedAddresses) {
    kLayout.build(memory);
    put(memory, kLayout.game + 0x1040, kLayout.a());
    put(memory, kLayout.a() + 0x28, kLayout.b() + 0x10);
    // Two bases reach A, and A reaches the target over A+0x20 and A+0x28.
    const PointerScanResult result = scan(kLayout.target());
    EXPECT_EQ(result.total_chains, 5u);
    const std::vector<Chain> expected{{"game.exe", 0x1020, {0x30}},
                                      {"game.exe", 0x1010, {0x20, 0x30}},
                                      {"game.exe", 0x1010, {0x28, 0x20}},
                                      {"game.exe", 0x1040, {0x20, 0x30}},
                                      {"game.exe", 0x1040, {0x28, 0x20}}};
    EXPECT_EQ(listed(result.chains), expected);
}

TEST_F(PointerScan, StopsOverTheMemoryBudget) {
    kLayout.build(memory);
    options.memory_budget = 1;
    const PointerScanResult result = scan(kLayout.target());
    EXPECT_EQ(result.status, PointerScanStatus::OverBudget);
    EXPECT_GT(result.needed_bytes, 1u);
    EXPECT_TRUE(result.chains.chains.empty());
}

TEST_F(PointerScan, Cancels) {
    kLayout.build(memory);
    stop.request_stop();
    EXPECT_EQ(scan(kLayout.target()).status, PointerScanStatus::Cancelled);
}

TEST_F(PointerScan, ReportsAnExitedTarget) {
    kLayout.build(memory);
    memory.exit_after_reads(1);
    EXPECT_EQ(scan(kLayout.target()).status, PointerScanStatus::TargetExited);
}

TEST_F(PointerScan, RejectsInvalidOptions) {
    kLayout.build(memory);
    options.depth = kMaxPointerDepth + 1;
    EXPECT_THROW(scan(kLayout.target()), Error);
    options.depth = 2;
    EXPECT_THROW(scan(kLayout.target(), 2), Error);
}

TEST(PointerModules, GroupsImageRegionsByAllocationBase) {
    FakeMemory memory;
    kLayout.build(memory);
    memory.add_image(0x7FF800000000, 0x1000, "C:\\Windows\\System32\\KERNEL32.DLL");
    const ModuleMap modules(memory.query_regions());
    ASSERT_EQ(modules.modules().size(), 2u);
    const Module* game = modules.find("GAME.EXE");
    ASSERT_NE(game, nullptr);
    EXPECT_EQ(game->base, kLayout.game);
    EXPECT_EQ(game->end, kLayout.game + 0x2000);
    EXPECT_EQ(modules.locate(kLayout.game + 0x1500), game);
    EXPECT_EQ(modules.locate(kLayout.heap), nullptr);
    ASSERT_NE(modules.find("kernel32.dll"), nullptr);
    EXPECT_EQ(modules.find("missing.dll"), nullptr);
}

class PointerPaths : public PointerScan {
protected:
    PointerChains found() {
        kLayout.build(memory);
        PointerScanResult result = scan(kLayout.target());
        EXPECT_EQ(result.chains.chains.size(), 2u);
        return std::move(result.chains);
    }
};

TEST_F(PointerPaths, ResolveToTheTarget) {
    const PointerChains chains = found();
    const ModuleMap modules(memory.query_regions());
    const PointerPath path = path_of(chains, 1);
    EXPECT_EQ(path.module, "game.exe");
    EXPECT_EQ(path.base_offset, 0x1010u);
    EXPECT_EQ(path.offsets, (std::vector<std::uint32_t>{0x20, 0x30}));
    EXPECT_EQ(resolve_pointer_path(memory, modules, path), kLayout.target());
    const auto bases = module_bases(modules, chains.modules);
    EXPECT_EQ(resolve_chain(memory, bases, chains.chains[0], 8), kLayout.target());
}

TEST_F(PointerPaths, FailWithoutTheModuleOrAPointer) {
    const PointerChains chains = found();
    const ModuleMap modules(memory.query_regions());
    PointerPath path = path_of(chains, 1);
    path.module = "other.dll";
    EXPECT_EQ(resolve_pointer_path(memory, modules, path), std::nullopt);
    put(memory, kLayout.s1(), 0);
    EXPECT_EQ(resolve_pointer_path(memory, modules, path_of(chains, 1)), std::nullopt);
}

TEST(PointerFormat, ShowsBaseAndOffsets) {
    const PointerPath path{"game.exe", 0x1A2B0, {0x10, 0x8}, 8};
    EXPECT_EQ(format_pointer_base(path.module, path.base_offset), "game.exe+0x1A2B0");
    EXPECT_EQ(format_pointer_offsets(path.offsets), "0x10, 0x8");
    EXPECT_EQ(format_pointer_path(path), "[[game.exe+0x1A2B0]+0x10]+0x8");
    EXPECT_EQ(format_pointer_path({"game.exe", 0x40, {}, 8}), "game.exe+0x40");
}

// The same objects after a restart: other module and heap bases, and S2 no longer set.
class PointerCheckAfterRestart : public PointerPaths {
protected:
    static constexpr Layout kMoved{0x150000000, 0x300000};
    FakeMemory restarted;

    void SetUp() override {
        PointerPaths::SetUp();
        kMoved.build(restarted);
        put(restarted, kMoved.s2(), 0);
    }

    PointerFilterResult check(const PointerChains& chains, const PointerCheck& rule) {
        ScanProgress progress;
        PointerFilterResult result =
            filter_pointer_chains(restarted, restarted.query_regions(), chains, rule, 2, progress, stop.get_token());
        EXPECT_EQ(progress.chunks_done.load(), chains.chains.size());
        EXPECT_EQ(progress.matches.load(), result.chains.chains.size());
        return result;
    }
};

TEST_F(PointerCheckAfterRestart, KeepsChainsThatReachTheNewAddress) {
    const PointerChains chains = found();
    PointerCheck rule;
    rule.address = kMoved.target();
    const PointerFilterResult result = check(chains, rule);
    EXPECT_EQ(result.status, PointerScanStatus::Completed);
    const std::vector<Chain> expected{{"game.exe", 0x1010, {0x20, 0x30}}};
    EXPECT_EQ(listed(result.chains), expected);
    EXPECT_EQ(result.chains.pointer_size, 8u);
}

TEST_F(PointerCheckAfterRestart, KeepsChainsThatReachTheValue) {
    const PointerChains chains = found();
    PointerCheck rule;
    rule.type = ValueType::Int32;
    rule.condition.bits = 100;
    EXPECT_EQ(check(chains, rule).chains.chains.size(), 1u);
    rule.condition.bits = 101;
    EXPECT_TRUE(check(chains, rule).chains.chains.empty());
    rule.condition.compare = Compare::Increased;
    ScanProgress progress;
    EXPECT_THROW(filter_pointer_chains(restarted, restarted.query_regions(), chains, rule, 1, progress, stop.get_token()),
                 Error);
}

TEST_F(PointerCheckAfterRestart, Cancels) {
    const PointerChains chains = found();
    PointerCheck rule;
    rule.address = kMoved.target();
    stop.request_stop();
    ScanProgress progress;
    EXPECT_EQ(filter_pointer_chains(restarted, restarted.query_regions(), chains, rule, 1, progress, stop.get_token()).status,
              PointerScanStatus::Cancelled);
}

PointerFile sample_file() {
    PointerFile file;
    file.process = {4242, "game.exe", "C:\\Games\\game.exe", 0x1D9ABCDEF, false};
    file.target = 0x208030;
    file.target_type = 4;
    file.depth = 6;
    file.max_offset = 0x800;
    file.checks = 2;
    file.chains.pointer_size = 8;
    file.chains.modules = {"game.exe", "engine.dll"};
    PointerChain a;
    a.module = 1;
    a.base_offset = 0x1234;
    a.depth = 3;
    a.offsets = {0x10, 0x0, 0x7F8};
    PointerChain b;
    b.base_offset = 0x40;
    file.chains.chains = {a, b};
    return file;
}

TEST(PointerFiles, RoundTrip) {
    const PointerFile file = sample_file();
    const PointerFile back = decode_pointer_file(encode_pointer_file(file), "x.mhp");
    EXPECT_EQ(back.process.pid, 4242u);
    EXPECT_EQ(back.process.name, "game.exe");
    EXPECT_EQ(back.process.path, file.process.path);
    EXPECT_EQ(back.process.creation_time, file.process.creation_time);
    EXPECT_EQ(back.target, file.target);
    EXPECT_EQ(back.target_type, 4u);
    EXPECT_EQ(back.depth, 6u);
    EXPECT_EQ(back.max_offset, 0x800u);
    EXPECT_EQ(back.checks, 2u);
    EXPECT_EQ(back.chains.modules, file.chains.modules);
    EXPECT_EQ(listed(back.chains), listed(file.chains));
}

TEST(PointerFiles, RejectsDamage) {
    std::vector<std::byte> bytes = encode_pointer_file(sample_file());
    bytes[bytes.size() - 3] ^= std::byte{1};
    EXPECT_THROW(decode_pointer_file(bytes, "x.mhp"), Error);
    bytes = encode_pointer_file(sample_file());
    bytes[0] = std::byte{'X'};
    EXPECT_THROW(decode_pointer_file(bytes, "x.mhp"), Error);
}

TEST(PointerFiles, RejectsInvalidChains) {
    PointerFile file = sample_file();
    file.chains.chains[0].module = 2;
    try {
        decode_pointer_file(encode_pointer_file(file), "x.mhp");
        FAIL();
    } catch (const Error& e) {
        EXPECT_EQ(e.code(), ErrorCode::CorruptSnapshot);
        EXPECT_NE(std::string(e.what()).find("damaged"), std::string::npos);
    }
    file = sample_file();
    file.chains.pointer_size = 2;
    EXPECT_THROW(decode_pointer_file(encode_pointer_file(file), "x.mhp"), Error);
}

}  // namespace
}  // namespace mh
