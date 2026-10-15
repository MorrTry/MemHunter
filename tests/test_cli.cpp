#include <gtest/gtest.h>

#include <windows.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>

#include "common/text.hpp"
#include "pointer/pointer_file.hpp"
#include "support/child_process.hpp"
#include "support/target_process.hpp"
#include "value/value_file.hpp"

namespace mh {
namespace {

using testing::run_program;
using testing::RunResult;

RunResult memhunter(const std::vector<std::string>& args) {
    return run_program(MEMHUNTER_EXE, args);
}

std::string utf8(const std::filesystem::path& path) {
    return wide_to_utf8(path.wstring());
}

std::string read_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

class Cli : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        target_ = new testing::TargetProcess(testing::start_target(MEMHUNTER_TEST_TARGET));
        directory_ = std::filesystem::temp_directory_path() / ("memhunter-cli-" + std::to_string(GetCurrentProcessId()));
        std::filesystem::create_directories(directory_);
    }

    static void TearDownTestSuite() {
        target_->child->write_line("exit");
        delete target_;
        target_ = nullptr;
        std::error_code ignored;
        std::filesystem::remove_all(directory_, ignored);
    }

    static std::string pid() { return std::to_string(target_->pid); }

    static testing::TargetProcess* target_;
    static std::filesystem::path directory_;
};

testing::TargetProcess* Cli::target_ = nullptr;
std::filesystem::path Cli::directory_;

TEST_F(Cli, VersionAndHelp) {
    const auto version = memhunter({"--version"});
    EXPECT_EQ(version.exit_code, 0u);
    EXPECT_EQ(version.out, "memhunter " MEMHUNTER_VERSION "\n");

    const auto help = memhunter({"help"});
    EXPECT_EQ(help.exit_code, 0u);
    EXPECT_NE(help.out.find("Exit codes:"), std::string::npos);

    const auto scan_help = memhunter({"scan", "--help"});
    EXPECT_EQ(scan_help.exit_code, 0u);
    EXPECT_NE(scan_help.out.find("--pattern"), std::string::npos);

    EXPECT_EQ(memhunter({}).exit_code, 2u);
    EXPECT_EQ(memhunter({"frobnicate"}).exit_code, 2u);
}

TEST_F(Cli, InvalidArgumentsExitWithUsageError) {
    const auto bad_pattern = memhunter({"scan", pid(), "--pattern", "48 8G"});
    EXPECT_EQ(bad_pattern.exit_code, 2u);
    EXPECT_NE(bad_pattern.err.find("memhunter: "), std::string::npos);
    EXPECT_TRUE(bad_pattern.out.empty());

    EXPECT_EQ(memhunter({"scan", pid()}).exit_code, 2u);
    EXPECT_EQ(memhunter({"scan", pid(), "-s", "x", "--min-length", "5"}).exit_code, 2u);
    EXPECT_EQ(memhunter({"scan", pid(), "-s", "x", "--threads", "0"}).exit_code, 2u);
    EXPECT_EQ(memhunter({"scan", pid(), "-s", "x", "--protection", "bogus"}).exit_code, 2u);
    EXPECT_EQ(memhunter({"scan", pid(), "-s", "x", "--bogus-option"}).exit_code, 2u);
    EXPECT_EQ(memhunter({"scan", pid(), "-s", "x", "--filter-pattern", "nope"}).exit_code, 2u);
}

TEST_F(Cli, MissingProcess) {
    const auto missing = memhunter({"scan", "4294967280", "-s", "abc"});
    EXPECT_EQ(missing.exit_code, 3u);
    EXPECT_NE(missing.err.find("memhunter: "), std::string::npos);
    EXPECT_EQ(memhunter({"scan", "no-such-process-memhunter.exe", "-s", "abc"}).exit_code, 3u);
}

TEST_F(Cli, ScanFindsNeedleAndWritesJson) {
    const auto file = directory_ / "results.json";
    const auto result = memhunter({"scan", pid(), "--pattern", "start=" + testing::needle_signature(0), "--pattern",
                                   testing::needle_signature(1), "--format", "json", "--output", utf8(file), "--no-progress"});
    EXPECT_EQ(result.exit_code, 0u) << result.err;
    EXPECT_TRUE(result.out.empty());
    EXPECT_NE(result.err.find("Wrote 2 matches to"), std::string::npos) << result.err;
    const std::string json = read_file(file);
    EXPECT_NE(json.find("\"label\": \"start\""), std::string::npos);
    EXPECT_NE(json.find("\"address\": \"" + format_address(target_->addresses("region_start")[0]) + "\""), std::string::npos) << json;
    EXPECT_NE(json.find("\"address\": \"" + format_address(target_->addresses("region_end")[0]) + "\""), std::string::npos);
    EXPECT_NE(json.find("\"status\": \"completed\""), std::string::npos);
}

TEST_F(Cli, ScanWithoutMatchesExitsWithOne) {
    const auto result = memhunter({"scan", pid(), "--pattern", "DE AD BE EF 01 23 45 67 89 AB CD EF FE ED FA CE 13 37", "-q"});
    EXPECT_EQ(result.exit_code, 1u) << result.err;
}

TEST_F(Cli, TextSearchToCsvOnStdout) {
    const std::string text = testing::text_needle(8);
    const auto result = memhunter({"scan", pid(), "--string", text, "--format", "csv", "--quiet"});
    EXPECT_EQ(result.exit_code, 0u) << result.err;
    EXPECT_EQ(result.out.rfind("address,length,pattern,kind,label", 0), 0u);
    EXPECT_NE(result.out.find(format_address(target_->addresses("text_ascii")[0]) + ",20,0,ascii," + text), std::string::npos)
        << result.out;
    EXPECT_NE(result.out.find(format_address(target_->addresses("text_utf16")[0]) + ",40,1,utf16," + text), std::string::npos);

    const auto ascii_only = memhunter({"scan", pid(), "--string", text, "--ascii", "--format", "csv", "-q", "--sort", "length"});
    EXPECT_EQ(ascii_only.out.find(",utf16,"), std::string::npos);

    std::string lower = testing::text_needle(10);
    for (auto& c : lower) {
        c = static_cast<char>(c - 'A' + 'a');
    }
    const std::string upper = testing::text_needle(10);
    EXPECT_EQ(memhunter({"scan", pid(), "--string", upper, "-q"}).exit_code, 1u);
    const auto folded = memhunter({"scan", pid(), "--string", upper, "--ignore-case", "-f", "csv", "-q"});
    EXPECT_EQ(folded.exit_code, 0u);
    EXPECT_NE(folded.out.find(lower), std::string::npos);
}

TEST_F(Cli, PatternFile) {
    const auto file = directory_ / "sigs.txt";
    std::ofstream(file, std::ios::binary) << "# needles\nmid=" << testing::needle_signature(6) << "\n\n" << testing::needle_signature(11)
                                         << "\n";
    const auto result = memhunter({"scan", pid(), "--pattern-file", utf8(file), "-f", "csv", "-q", "--protection", "rw"});
    EXPECT_EQ(result.exit_code, 0u) << result.err;
    EXPECT_NE(result.out.find(format_address(target_->addresses("after_noaccess")[0]) + ",16,0,bytes,mid"), std::string::npos)
        << result.out;
    EXPECT_EQ(result.out.find(format_address(target_->addresses("execute")[0])), std::string::npos);

    const auto broken = directory_ / "broken.txt";
    std::ofstream(broken, std::ios::binary) << "AA BB\nzz\n";
    const auto error = memhunter({"scan", pid(), "--pattern-file", utf8(broken)});
    EXPECT_EQ(error.exit_code, 2u);
    EXPECT_NE(error.err.find("broken.txt:2:"), std::string::npos) << error.err;
}

TEST_F(Cli, OutputErrors) {
    const auto result =
        memhunter({"scan", pid(), "-p", testing::needle_signature(0), "-o", utf8(directory_ / "missing-dir" / "out.json")});
    EXPECT_EQ(result.exit_code, 4u) << result.err;
}

TEST_F(Cli, StringsLimitAndFilters) {
    const auto result = memhunter({"scan", pid(), "--strings", "--min-length", "20", "--format", "csv", "-q", "--limit", "3",
                                   "--filter-kind", "strings"});
    EXPECT_EQ(result.exit_code, 0u) << result.err;
    std::size_t lines = 0;
    for (const char c : result.out) {
        lines += c == '\n' ? 1 : 0;
    }
    EXPECT_EQ(lines, 4u);
}

TEST_F(Cli, RegionsAndProcessList) {
    const auto regions = memhunter({"regions", pid(), "-f", "csv"});
    EXPECT_EQ(regions.exit_code, 0u) << regions.err;
    EXPECT_NE(regions.out.find(format_address(target_->addresses("region_start")[0])), std::string::npos);

    const auto all = memhunter({"regions", pid(), "--all", "-f", "json"});
    EXPECT_EQ(all.exit_code, 0u);
    EXPECT_GT(all.out.size(), regions.out.size());

    const auto all_image = memhunter({"regions", pid(), "--all", "--type", "image", "-f", "csv"});
    ASSERT_EQ(all_image.exit_code, 0u) << all_image.err;
    std::istringstream rows(all_image.out);
    std::string row;
    std::getline(rows, row);
    std::size_t image_rows = 0;
    while (std::getline(rows, row)) {
        EXPECT_NE(row.find(",image,"), std::string::npos) << row;
        ++image_rows;
    }
    EXPECT_GT(image_rows, 0u);
    EXPECT_EQ(memhunter({"regions", pid(), "--all", "--protection", "rw"}).exit_code, 2u);

    const auto ps = memhunter({"ps", "memhunter_test_target"});
    EXPECT_EQ(ps.exit_code, 0u);
    EXPECT_NE(ps.out.find(pid()), std::string::npos);
    EXPECT_EQ(memhunter({"ps", "no-such-process-memhunter"}).exit_code, 1u);
}

TEST_F(Cli, SnapshotInfoAndDiffOfFiles) {
    const std::string a = utf8(directory_ / "a.mhs");
    const auto snapshot = memhunter({"snapshot", pid(), "-o", a, "--type", "private", "--no-progress"});
    ASSERT_EQ(snapshot.exit_code, 0u) << snapshot.err;
    EXPECT_NE(snapshot.err.find("Wrote "), std::string::npos) << snapshot.err;
    EXPECT_TRUE(std::filesystem::exists(directory_ / "a.mhs"));
    EXPECT_FALSE(std::filesystem::exists(directory_ / "a.mhs.partial"));

    const auto info = memhunter({"info", a, "-f", "json"});
    ASSERT_EQ(info.exit_code, 0u) << info.err;
    EXPECT_NE(info.out.find("\"contents_saved\": false"), std::string::npos) << info.out;
    EXPECT_NE(info.out.find("\"pid\": " + pid()), std::string::npos) << info.out;
    const auto text = memhunter({"info", a});
    EXPECT_EQ(text.exit_code, 0u);
    EXPECT_NE(text.out.find("hashes only"), std::string::npos) << text.out;

    const auto same = memhunter({"diff", a, a, "-q"});
    EXPECT_EQ(same.exit_code, 1u) << same.err;

    const std::string large = utf8(directory_ / "large.mhs");
    ASSERT_EQ(memhunter({"snapshot", pid(), "-o", large, "--type", "private", "--block-size", "64K", "-q", "--no-progress"}).exit_code, 0u);
    const auto mismatch = memhunter({"diff", a, large});
    EXPECT_EQ(mismatch.exit_code, 6u);
    EXPECT_NE(mismatch.err.find("block sizes"), std::string::npos) << mismatch.err;
}

TEST_F(Cli, SnapshotArgumentsAndDamagedFiles) {
    EXPECT_EQ(memhunter({"snapshot", pid()}).exit_code, 2u);
    EXPECT_EQ(memhunter({"snapshot", pid(), "-o", utf8(directory_ / "x.mhs"), "--max-data", "1M"}).exit_code, 2u);
    EXPECT_EQ(memhunter({"snapshot", pid(), "-o", utf8(directory_ / "x.mhs"), "--block-size", "3000"}).exit_code, 2u);
    EXPECT_EQ(memhunter({"diff", utf8(directory_ / "only-one.mhs")}).exit_code, 2u);
    EXPECT_EQ(memhunter({"diff", "a", "b", "--show", "sideways"}).exit_code, 2u);
    EXPECT_EQ(memhunter({"info"}).exit_code, 2u);
    EXPECT_FALSE(std::filesystem::exists(directory_ / "x.mhs"));

    const auto too_big = memhunter({"snapshot", pid(), "-o", utf8(directory_ / "big.mhs"), "--with-data", "--max-data", "4K", "-q"});
    EXPECT_EQ(too_big.exit_code, 2u);
    EXPECT_NE(too_big.err.find("--max-data"), std::string::npos) << too_big.err;
    EXPECT_FALSE(std::filesystem::exists(directory_ / "big.mhs"));

    const std::string good = utf8(directory_ / "good.mhs");
    ASSERT_EQ(memhunter({"snapshot", pid(), "-o", good, "--type", "private", "-q", "--no-progress"}).exit_code, 0u);
    std::string bytes = read_file(directory_ / "good.mhs");
    bytes[bytes.size() / 2] ^= 0x10;
    const std::string bad = utf8(directory_ / "bad.mhs");
    std::ofstream(directory_ / "bad.mhs", std::ios::binary) << bytes;
    const auto damaged = memhunter({"info", bad});
    EXPECT_EQ(damaged.exit_code, 6u);
    EXPECT_NE(damaged.err.find("damaged"), std::string::npos) << damaged.err;
    EXPECT_EQ(memhunter({"diff", good, bad}).exit_code, 6u);
    EXPECT_EQ(memhunter({"scan", pid(), "-s", "x", "--changed-since", bad}).exit_code, 6u);

    std::ofstream(directory_ / "notes.txt") << "just some notes, not a snapshot";
    EXPECT_EQ(memhunter({"info", utf8(directory_ / "notes.txt")}).exit_code, 6u);
    EXPECT_EQ(memhunter({"info", utf8(directory_ / "missing.mhs")}).exit_code, 4u);
}

TEST_F(Cli, SnapshotHelp) {
    for (const std::string topic : {"snapshot", "diff", "info"}) {
        const auto help = memhunter({"help", topic});
        EXPECT_EQ(help.exit_code, 0u) << topic;
        EXPECT_EQ(help.out.rfind("Usage: memhunter " + topic, 0), 0u) << help.out;
        EXPECT_EQ(memhunter({topic, "--help"}).out, help.out);
    }
    EXPECT_NE(memhunter({"help", "snapshot"}).out.find("NOT saved"), std::string::npos);
    EXPECT_NE(memhunter({"help", "diff"}).out.find("different process runs"), std::string::npos);
}

TEST_F(Cli, TuiNeedsAnInteractiveConsole) {
    const auto help = memhunter({"help", "tui"});
    EXPECT_EQ(help.exit_code, 0u);
    EXPECT_EQ(help.out.rfind("Usage: memhunter tui", 0), 0u) << help.out;
    EXPECT_EQ(memhunter({"tui", "--help"}).out, help.out);
    EXPECT_NE(memhunter({"help"}).out.find("memhunter tui <pid|name>"), std::string::npos);

    // The tests run memhunter with pipes, which is exactly the case the interface must refuse cleanly.
    const auto piped = memhunter({"tui", pid()});
    EXPECT_EQ(piped.exit_code, 2u);
    EXPECT_NE(piped.err.find("interactive console"), std::string::npos) << piped.err;
    EXPECT_TRUE(piped.out.empty()) << piped.out;

    EXPECT_EQ(memhunter({"tui"}).exit_code, 2u);
    EXPECT_NE(memhunter({"tui"}).err.find("missing process"), std::string::npos);
    EXPECT_EQ(memhunter({"tui", pid(), "extra"}).exit_code, 2u);
    EXPECT_EQ(memhunter({"tui", pid(), "-j", "0"}).exit_code, 2u);
    EXPECT_EQ(memhunter({"tui", pid(), "--bogus"}).exit_code, 2u);
    EXPECT_EQ(memhunter({"tui", "4294967280"}).exit_code, 3u);
}

std::string counter_page(std::uint64_t counter) {
    const std::uint64_t page = counter / 4096 * 4096;
    return format_address(page) + "-" + format_address(page + 4096);
}

TEST_F(Cli, ValueSearchContinuesFromAFile) {
    const std::string page = counter_page(target_->counter);
    const std::string address = format_address(target_->counter);
    const std::string file = utf8(directory_ / "counter.mhv");
    ASSERT_EQ(target_->command("set 1000"), "counter 1000");

    const auto first = memhunter({"value", pid(), "--eq", "1000", "--include", page, "--save", file});
    ASSERT_EQ(first.exit_code, 0u) << first.err;
    EXPECT_NE(first.out.find(address), std::string::npos) << first.out;
    EXPECT_NE(first.err.find("scan 1"), std::string::npos) << first.err;
    EXPECT_NE(first.err.find("1 address"), std::string::npos) << first.err;

    ASSERT_EQ(target_->command("set 1500"), "counter 1500");
    const auto increased = memhunter({"value", file, "--increased"});
    ASSERT_EQ(increased.exit_code, 0u) << increased.err;
    EXPECT_NE(increased.out.find(address), std::string::npos) << increased.out;
    EXPECT_NE(increased.out.find("1500"), std::string::npos) << increased.out;
    EXPECT_NE(increased.out.find("1000"), std::string::npos) << increased.out;
    EXPECT_NE(increased.err.find("scan 2"), std::string::npos) << increased.err;
    EXPECT_NE(increased.err.find("1 of 1 address left"), std::string::npos) << increased.err;

    const std::string saved = read_file(directory_ / "counter.mhv");
    const auto none = memhunter({"value", file, "--decreased"});
    EXPECT_EQ(none.exit_code, 1u) << none.err;
    EXPECT_NE(none.err.find("was not changed"), std::string::npos) << none.err;
    EXPECT_EQ(read_file(directory_ / "counter.mhv"), saved);

    const auto shown = memhunter({"value", file, "-f", "json"});
    EXPECT_EQ(shown.exit_code, 0u) << shown.err;
    EXPECT_NE(shown.out.find("\"value\": \"1500\""), std::string::npos) << shown.out;
    EXPECT_NE(shown.out.find("\"scan\": 2"), std::string::npos) << shown.out;
    EXPECT_EQ(read_file(directory_ / "counter.mhv"), saved);

    ASSERT_EQ(target_->command("set 1200"), "counter 1200");
    const std::string branch = utf8(directory_ / "branch.mhv");
    const auto exact = memhunter({"value", file, "--eq", "1200", "--save", branch, "-f", "csv"});
    EXPECT_EQ(exact.exit_code, 0u) << exact.err;
    EXPECT_EQ(exact.out.rfind("address,value,previous,protection,type,module\r\n", 0), 0u) << exact.out;
    EXPECT_NE(exact.out.find(address + ",1200,1500,rw-,private,"), std::string::npos) << exact.out;
    EXPECT_EQ(read_file(directory_ / "counter.mhv"), saved);
    EXPECT_TRUE(std::filesystem::exists(directory_ / "branch.mhv"));
    EXPECT_FALSE(std::filesystem::exists(directory_ / "branch.mhv.partial"));
}

TEST_F(Cli, ValueSearchFromAnUnknownValue) {
    const std::string page = counter_page(target_->counter);
    const std::string file = utf8(directory_ / "unknown.mhv");
    ASSERT_EQ(target_->command("set 70"), "counter 70");
    const auto unknown = memhunter({"value", pid(), "--unknown", "--include", page, "--save", file});
    ASSERT_EQ(unknown.exit_code, 0u) << unknown.err;
    EXPECT_NE(unknown.err.find("1024 addresses"), std::string::npos) << unknown.err;

    ASSERT_EQ(target_->command("set 65"), "counter 65");
    const auto changed = memhunter({"value", file, "--changed"});
    ASSERT_EQ(changed.exit_code, 0u) << changed.err;
    EXPECT_NE(changed.err.find("1 of 1024 addresses left"), std::string::npos) << changed.err;
    EXPECT_NE(changed.out.find(format_address(target_->counter)), std::string::npos) << changed.out;

    const auto as_int16 = memhunter({"value", pid(), "--as", "int16", "--unaligned", "--between", "60:70", "--include", page});
    EXPECT_EQ(as_int16.exit_code, 0u) << as_int16.err;
    EXPECT_NE(as_int16.err.find("1 address"), std::string::npos) << as_int16.err;
}

TEST_F(Cli, ValueArgumentsAndFiles) {
    const std::string file = utf8(directory_ / "args.mhv");
    ASSERT_EQ(target_->command("set 5"), "counter 5");
    ASSERT_EQ(memhunter({"value", pid(), "--eq", "5", "--include", counter_page(target_->counter), "--save", file}).exit_code, 0u);

    for (const std::vector<std::string>& args : std::vector<std::vector<std::string>>{
             {"value"},
             {"value", pid()},
             {"value", pid(), "--increased"},
             {"value", pid(), "--eq", "abc"},
             {"value", pid(), "--eq", "1", "--gt", "2"},
             {"value", pid(), "--as", "bogus", "--eq", "1"},
             {"value", pid(), "--between", "5"},
             {"value", pid(), "--eq", "99999999999"},
             {"value", pid(), "--as", "float", "--eq", "1x"},
             {"value", pid(), "--eq", "1", "--bogus"},
             {"value", file, "--unknown"},
             {"value", file, "--as", "float"},
             {"value", file, "--type", "private"},
         }) {
        const auto result = memhunter(args);
        EXPECT_EQ(result.exit_code, 2u) << args.back() << ": " << result.err;
        EXPECT_NE(result.err.find("memhunter: "), std::string::npos) << result.err;
    }
    EXPECT_EQ(memhunter({"value", utf8(directory_ / "missing.mhv"), "--eq", "1"}).exit_code, 4u);
    EXPECT_EQ(memhunter({"value", "4294967280", "--eq", "1"}).exit_code, 3u);

    std::ofstream(directory_ / "notes.mhv") << "not a value file";
    const auto damaged = memhunter({"value", utf8(directory_ / "notes.mhv"), "--eq", "1"});
    EXPECT_EQ(damaged.exit_code, 6u);
    EXPECT_NE(damaged.err.find("not a MemHunter value file"), std::string::npos) << damaged.err;

    ValueFile other = read_value_file(file);
    other.process.creation_time += 1;
    write_value_file(utf8(directory_ / "other-run.mhv"), other.process, other.candidates);
    const auto foreign = memhunter({"value", utf8(directory_ / "other-run.mhv"), "--eq", "5"});
    EXPECT_EQ(foreign.exit_code, 6u) << foreign.err;
    EXPECT_NE(foreign.err.find("another run"), std::string::npos) << foreign.err;

    other.process.pid = 4294967280u;
    write_value_file(utf8(directory_ / "gone.mhv"), other.process, other.candidates);
    const auto gone = memhunter({"value", utf8(directory_ / "gone.mhv")});
    EXPECT_EQ(gone.exit_code, 3u) << gone.err;
    EXPECT_NE(gone.err.find("is not running"), std::string::npos) << gone.err;

    const auto help = memhunter({"help", "value"});
    EXPECT_EQ(help.exit_code, 0u);
    EXPECT_EQ(help.out.rfind("Usage: memhunter value", 0), 0u) << help.out;
    EXPECT_EQ(memhunter({"value", "--help"}).out, help.out);
    EXPECT_NE(memhunter({"help"}).out.find("memhunter value <pid|name>"), std::string::npos);
}

std::uint64_t moved_counter(testing::TargetProcess& target) {
    const std::string reply = target.command("move");
    EXPECT_EQ(reply.rfind("counter 0x", 0), 0u) << reply;
    return parse_uint(reply.substr(8)).value_or(0);
}

TEST(CliPointers, ChainsFollowTheCounterToItsNewPage) {
    testing::TargetProcess target = testing::start_target(MEMHUNTER_TEST_TARGET);
    const std::string pid = std::to_string(target.pid);
    const auto directory = std::filesystem::temp_directory_path() / ("memhunter-cli-ptr-" + std::to_string(GetCurrentProcessId()));
    std::filesystem::create_directories(directory);
    const std::string file = utf8(directory / "counter.mhp");
    ASSERT_EQ(target.command("set 41"), "counter 41");

    const auto found = memhunter({"pointers", pid, "--to", format_address(target.counter), "--depth", "3", "--save", file, "-f",
                                  "csv", "--limit", "0", "--no-progress"});
    ASSERT_EQ(found.exit_code, 0u) << found.err;
    EXPECT_EQ(found.out.rfind("base,offsets,path,address,value\r\n", 0), 0u) << found.out;
    const auto row = found.out.find("]+0x10]+0x40," + format_address(target.counter) + ",41\r\n");
    EXPECT_NE(row, std::string::npos) << found.out;
    EXPECT_NE(found.err.find("Saved "), std::string::npos) << found.err;
    EXPECT_EQ(found.err.find("keeps the shortest"), std::string::npos) << found.err;
    EXPECT_FALSE(std::filesystem::exists(directory / "counter.mhp.partial"));

    const auto cut = memhunter({"pointers", pid, "--to", format_address(target.counter), "--depth", "3", "--max-chains", "1",
                                "--no-progress"});
    EXPECT_EQ(cut.exit_code, 0u) << cut.err;
    EXPECT_NE(cut.err.find("the list keeps the shortest 1\r\n"), std::string::npos) << cut.err;
    const PointerFile saved = read_pointer_file(file);
    EXPECT_EQ(saved.target, target.counter);
    EXPECT_EQ(saved.depth, 3u);
    EXPECT_EQ(saved.checks, 0u);
    ASSERT_FALSE(saved.chains.chains.empty());

    const std::uint64_t moved = moved_counter(target);
    ASSERT_NE(moved, target.counter);
    ASSERT_EQ(target.command("set 77"), "counter 77");
    const std::string before = read_file(directory / "counter.mhp");
    const auto shown = memhunter({"pointers", file, pid, "--limit", "0"});
    ASSERT_EQ(shown.exit_code, 0u) << shown.err;
    EXPECT_NE(shown.out.find(format_address(moved)), std::string::npos) << shown.out;
    EXPECT_NE(shown.out.find("77"), std::string::npos) << shown.out;
    EXPECT_EQ(read_file(directory / "counter.mhp"), before);

    const auto by_address = memhunter({"pointers", file, pid, "--to", format_address(moved), "--no-progress"});
    ASSERT_EQ(by_address.exit_code, 0u) << by_address.err;
    EXPECT_NE(by_address.err.find(" of " + std::to_string(saved.chains.chains.size())), std::string::npos) << by_address.err;
    const PointerFile checked = read_pointer_file(file);
    EXPECT_EQ(checked.checks, 1u);
    EXPECT_EQ(checked.target, moved);
    EXPECT_FALSE(checked.chains.chains.empty());
    EXPECT_LE(checked.chains.chains.size(), saved.chains.chains.size());

    const auto by_value = memhunter({"pointers", file, pid, "--eq", "77", "-f", "json", "--no-progress"});
    ASSERT_EQ(by_value.exit_code, 0u) << by_value.err;
    EXPECT_NE(by_value.out.find("\"checks\": 2"), std::string::npos) << by_value.out;
    EXPECT_NE(by_value.out.find("+0x10]+0x40\", \"address\": \"" + format_address(moved) + "\", \"value\": \"77\""),
              std::string::npos)
        << by_value.out;

    const std::string kept = read_file(directory / "counter.mhp");
    const auto none = memhunter({"pointers", file, pid, "--eq", "12345", "--no-progress"});
    EXPECT_EQ(none.exit_code, 1u) << none.err;
    EXPECT_NE(none.err.find("was not changed"), std::string::npos) << none.err;
    EXPECT_EQ(read_file(directory / "counter.mhp"), kept);

    const std::string branch = utf8(directory / "branch.mhp");
    EXPECT_EQ(memhunter({"pointers", file, pid, "--between", "70:80", "--save", branch, "-q", "--no-progress"}).exit_code, 0u);
    EXPECT_EQ(read_file(directory / "counter.mhp"), kept);
    EXPECT_EQ(read_pointer_file(branch).checks, 3u);

    target.child->write_line("exit");
    EXPECT_EQ(target.child->wait(10000), 0u);
    std::error_code ignored;
    std::filesystem::remove_all(directory, ignored);
}

TEST_F(Cli, PointerArgumentsAndFiles) {
    const std::string file = utf8(directory_ / "args.mhp");
    const auto saved = memhunter({"pointers", pid(), "--to", format_address(target_->counter), "--depth", "2", "--save", file, "-q",
                                  "--no-progress"});
    ASSERT_EQ(saved.exit_code, 0u) << saved.err;

    for (const std::vector<std::string>& args : std::vector<std::vector<std::string>>{
             {"pointers"},
             {"pointers", pid()},
             {"pointers", pid(), "--to", "xyz"},
             {"pointers", pid(), "--to", "0x1000", "--depth", "0"},
             {"pointers", pid(), "--to", "0x1000", "--depth", "8"},
             {"pointers", pid(), "--to", "0x1000", "--max-offset", "0x100000000"},
             {"pointers", pid(), "--to", "0x1000", "--eq", "5"},
             {"pointers", pid(), "--to", "0x1000", "--as", "ascii"},
             {"pointers", pid(), "other", "--to", "0x1000"},
             {"pointers", pid(), "--to", "0x1000", "--increased"},
             {"pointers", file, pid(), "--depth", "3"},
             {"pointers", file, pid(), "--type", "private"},
             {"pointers", file, pid(), "--to", "0x1000", "--eq", "1"},
             {"pointers", file, pid(), "--eq", "1", "--gt", "2"},
         }) {
        const auto result = memhunter(args);
        EXPECT_EQ(result.exit_code, 2u) << args.back() << ": " << result.err;
        EXPECT_NE(result.err.find("memhunter: "), std::string::npos) << result.err;
    }
    EXPECT_EQ(memhunter({"pointers", utf8(directory_ / "missing.mhp"), pid()}).exit_code, 4u);
    EXPECT_EQ(memhunter({"pointers", "4294967280", "--to", "0x1000"}).exit_code, 3u);
    EXPECT_EQ(memhunter({"pointers", file, "4294967280"}).exit_code, 3u);

    std::ofstream(directory_ / "notes.mhp") << "not a pointer file";
    const auto damaged = memhunter({"pointers", utf8(directory_ / "notes.mhp"), pid()});
    EXPECT_EQ(damaged.exit_code, 6u);
    EXPECT_NE(damaged.err.find("not a MemHunter pointer file"), std::string::npos) << damaged.err;

    PointerFile narrow = read_pointer_file(file);
    narrow.chains.pointer_size = 4;
    write_pointer_file(utf8(directory_ / "narrow.mhp"), narrow);
    const auto other_width = memhunter({"pointers", utf8(directory_ / "narrow.mhp"), pid()});
    EXPECT_EQ(other_width.exit_code, 6u) << other_width.err;
    EXPECT_NE(other_width.err.find("32-bit"), std::string::npos) << other_width.err;

    PointerFile text = read_pointer_file(file);
    text.target_type = 6;
    text.target_length = 4;
    write_pointer_file(utf8(directory_ / "text.mhp"), text);
    EXPECT_EQ(memhunter({"pointers", utf8(directory_ / "text.mhp"), pid(), "--eq", "1"}).exit_code, 2u);
    const auto text_rows = memhunter({"pointers", utf8(directory_ / "text.mhp"), pid(), "-f", "json"});
    EXPECT_EQ(text_rows.exit_code, 0u) << text_rows.err;
    EXPECT_NE(text_rows.out.find("\"type\": \"ascii\""), std::string::npos) << text_rows.out;

    const auto help = memhunter({"help", "pointers"});
    EXPECT_EQ(help.exit_code, 0u);
    EXPECT_EQ(help.out.rfind("Usage: memhunter pointers", 0), 0u) << help.out;
    EXPECT_EQ(memhunter({"pointers", "--help"}).out, help.out);
    EXPECT_NE(memhunter({"help"}).out.find("memhunter pointers <pid|name>"), std::string::npos);
}

TEST(CliStruct, ShowsTheFieldsAtAnAddressAndFollowsAChain) {
    testing::TargetProcess target = testing::start_target(MEMHUNTER_TEST_TARGET);
    const std::string pid = std::to_string(target.pid);
    const auto directory = std::filesystem::temp_directory_path() / ("memhunter-cli-struct-" + std::to_string(GetCurrentProcessId()));
    std::filesystem::create_directories(directory);
    ASSERT_EQ(target.command("set 41"), "counter 41");

    const auto plain = memhunter({"struct", pid, format_address(target.counter - 0x40), "--size", "0x80", "-f", "csv"});
    ASSERT_EQ(plain.exit_code, 0u) << plain.err;
    EXPECT_EQ(plain.out, "offset,type,name,value\r\n0x0,bytes[64],,00 \xC3\x97 64\r\n0x40,int32,,41\r\n0x44,bytes[60],,00 \xC3\x97 60\r\n");
    EXPECT_NE(plain.err.find(": 0x80 bytes, 3 fields"), std::string::npos) << plain.err;

    const auto chains = memhunter({"pointers", pid, "--to", format_address(target.counter), "--depth", "2", "-f", "csv", "--limit", "0",
                                   "-q", "--no-progress"});
    ASSERT_EQ(chains.exit_code, 0u) << chains.err;
    const auto start = chains.out.find("[[memhunter_test_target.exe+");
    ASSERT_NE(start, std::string::npos) << chains.out;
    const auto end = chains.out.find("]+0x10]+0x40,", start);
    ASSERT_NE(end, std::string::npos) << chains.out;
    const std::string base = chains.out.substr(start, end + 7 - start);

    const std::uint64_t moved = moved_counter(target);
    ASSERT_EQ(target.command("set 77"), "counter 77");
    const std::string definition = utf8(directory / "counter.mhst");
    std::ofstream(directory / "counter.mhst") << "# the page of the counter\nsize 0x48\n0x40 int32 counter\n";
    const auto followed = memhunter({"struct", pid, base, "--def", definition, "-f", "json"});
    ASSERT_EQ(followed.exit_code, 0u) << followed.err;
    EXPECT_NE(followed.out.find("\"base\": \"" + base + "\""), std::string::npos) << followed.out;
    EXPECT_NE(followed.out.find("\"address\": \"" + format_address(moved - 0x40) + "\""), std::string::npos) << followed.out;
    EXPECT_NE(followed.out.find("\"size\": \"0x48\""), std::string::npos) << followed.out;
    EXPECT_NE(followed.out.find("{\"offset\": \"0x40\", \"address\": \"" + format_address(moved) +
                                "\", \"type\": \"int32\", \"size\": 4, \"name\": \"counter\", \"defined\": true, \"value\": \"77\"}"),
              std::string::npos)
        << followed.out;
    EXPECT_NE(followed.err.find(base + " leads to " + format_address(moved - 0x40) + ": 0x48 bytes, 3 fields, 1 of them from"),
              std::string::npos)
        << followed.err;

    const auto text = memhunter({"struct", pid, base, "--def", definition, "--size", "0x44", "-q"});
    ASSERT_EQ(text.exit_code, 0u) << text.err;
    EXPECT_EQ(text.out.rfind("OFFSET  TYPE       NAME     VALUE\n", 0), 0u) << text.out;
    EXPECT_NE(text.out.find("\n0x40    int32      counter  77\n"), std::string::npos) << text.out;
    EXPECT_TRUE(text.err.empty()) << text.err;

    const auto nowhere = memhunter({"struct", pid, "[[no-such-module.dll+0x10]+0x8]"});
    EXPECT_EQ(nowhere.exit_code, 1u);
    EXPECT_NE(nowhere.err.find("leads nowhere now"), std::string::npos) << nowhere.err;
    const auto unreadable = memhunter({"struct", pid, "0x10"});
    EXPECT_EQ(unreadable.exit_code, 1u);
    EXPECT_NE(unreadable.err.find("Nothing can be read at"), std::string::npos) << unreadable.err;

    for (const std::vector<std::string>& args : std::vector<std::vector<std::string>>{
             {"struct"},
             {"struct", pid},
             {"struct", pid, "[[x"},
             {"struct", pid, "0x1000", "other"},
             {"struct", pid, "0x1000", "--size", "0"},
             {"struct", pid, "0x1000", "--size", "0x10001"},
             {"struct", pid, "0x1000", "-f", "xml"},
             {"struct", pid, "0x1000", "--def", ""},
             {"struct", pid, "0x1000", "--bogus"},
         }) {
        const auto result = memhunter(args);
        EXPECT_EQ(result.exit_code, 2u) << args.back() << ": " << result.err;
        EXPECT_NE(result.err.find("memhunter: "), std::string::npos) << result.err;
    }
    EXPECT_EQ(memhunter({"struct", "4294967280", "0x1000"}).exit_code, 3u);
    EXPECT_EQ(memhunter({"struct", pid, "0x1000", "--def", utf8(directory / "missing.mhst")}).exit_code, 4u);
    std::ofstream(directory / "damaged.mhst") << "0x40 int33 counter\n";
    const auto damaged = memhunter({"struct", pid, "0x1000", "--def", utf8(directory / "damaged.mhst")});
    EXPECT_EQ(damaged.exit_code, 6u);
    EXPECT_NE(damaged.err.find("line 1"), std::string::npos) << damaged.err;

    const auto help = memhunter({"help", "struct"});
    EXPECT_EQ(help.exit_code, 0u);
    EXPECT_EQ(help.out.rfind("Usage: memhunter struct", 0), 0u) << help.out;
    EXPECT_EQ(memhunter({"struct", "--help"}).out, help.out);
    EXPECT_NE(memhunter({"help"}).out.find("memhunter struct <pid|name> BASE"), std::string::npos);

    target.child->write_line("exit");
    EXPECT_EQ(target.child->wait(10000), 0u);
    std::error_code ignored;
    std::filesystem::remove_all(directory, ignored);
}

TEST(CliSnapshot, LiveDiffAndIncrementalRescan) {
    testing::TargetProcess target = testing::start_target(MEMHUNTER_TEST_TARGET);
    testing::TargetProcess other = testing::start_target(MEMHUNTER_TEST_TARGET);
    const std::string pid = std::to_string(target.pid);
    const auto directory = std::filesystem::temp_directory_path() / ("memhunter-cli-snap-" + std::to_string(GetCurrentProcessId()));
    std::filesystem::create_directories(directory);
    const std::string before = utf8(directory / "before.mhs");
    const std::string with_data = utf8(directory / "before-data.mhs");
    const std::string signature = "n12=" + testing::needle_signature(12);

    ASSERT_EQ(memhunter({"snapshot", pid, "-o", before, "--type", "private", "-q", "--no-progress"}).exit_code, 0u);
    const auto data = memhunter({"snapshot", pid, "-o", with_data, "--type", "private", "--with-data", "--no-progress"});
    ASSERT_EQ(data.exit_code, 0u) << data.err;
    EXPECT_NE(data.err.find("passwords or keys"), std::string::npos) << data.err;

    const std::string reply = target.command("mutate");
    ASSERT_EQ(reply.rfind("mutated ", 0), 0u) << reply;
    const std::string moved = format_address(parse_uint(reply.substr(8)).value_or(0));
    const std::string old = format_address(target.addresses("mutable")[0]);

    const auto live = memhunter({"diff", pid, before, "-f", "csv", "--show", "changed", "--no-progress"});
    ASSERT_EQ(live.exit_code, 0u) << live.err;
    EXPECT_EQ(live.out.rfind("kind,start,end,size,region,protection,type,module\n", 0), 0u) << live.out;
    EXPECT_NE(live.out.find("changed,"), std::string::npos);

    const auto exact = memhunter({"diff", pid, with_data, "-f", "json", "--no-progress"});
    ASSERT_EQ(exact.exit_code, 0u) << exact.err;
    EXPECT_NE(exact.out.find("\"exact\": true"), std::string::npos) << exact.out.substr(0, 2000);

    const auto rescan = memhunter({"scan", pid, "-p", signature, "--changed-since", before, "-f", "csv", "--no-progress"});
    ASSERT_EQ(rescan.exit_code, 0u) << rescan.err;
    EXPECT_NE(rescan.out.find("\n" + moved + ","), std::string::npos) << rescan.out;
    EXPECT_EQ(rescan.out.find("\n" + old + ","), std::string::npos) << rescan.out;
    EXPECT_EQ(std::count(rescan.out.begin(), rescan.out.end(), '\n'), 2) << rescan.out;
    EXPECT_NE(rescan.err.find("Changed since"), std::string::npos) << rescan.err;

    const std::string after = utf8(directory / "after.mhs");
    ASSERT_EQ(memhunter({"snapshot", pid, "-o", after, "--type", "private", "-q", "--no-progress"}).exit_code, 0u);
    EXPECT_EQ(memhunter({"diff", before, after, "-q"}).exit_code, 0u);
    EXPECT_EQ(memhunter({"diff", pid, before, after, "-q"}).exit_code, 0u);

    // A snapshot of another process run must not be compared silently.
    const std::string other_pid = std::to_string(other.pid);
    const auto cross = memhunter({"scan", other_pid, "-p", signature, "--changed-since", before, "-q"});
    EXPECT_EQ(cross.exit_code, 6u);
    EXPECT_NE(cross.err.find("another process run"), std::string::npos) << cross.err;
    const std::string foreign = utf8(directory / "other.mhs");
    ASSERT_EQ(memhunter({"snapshot", other_pid, "-o", foreign, "--type", "private", "-q", "--no-progress"}).exit_code, 0u);
    EXPECT_EQ(memhunter({"diff", before, foreign, "-q"}).exit_code, 6u);
    const auto forced = memhunter({"diff", before, foreign, "--force", "-f", "json"});
    EXPECT_LE(forced.exit_code, 1u) << forced.err;
    EXPECT_NE(forced.out.find("different process runs"), std::string::npos);

    target.child->write_line("exit");
    other.child->write_line("exit");
    EXPECT_EQ(target.child->wait(10000), 0u);
    EXPECT_EQ(other.child->wait(10000), 0u);
    std::error_code ignored;
    std::filesystem::remove_all(directory, ignored);
}

}  // namespace
}  // namespace mh
