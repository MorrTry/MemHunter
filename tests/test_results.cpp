#include <gtest/gtest.h>

#include <algorithm>
#include <sstream>

#include "results/export.hpp"
#include "results/query.hpp"
#include "results/result_set.hpp"

namespace mh {
namespace {

Region region(std::uint64_t base, std::uint64_t size, std::uint32_t protect, MemType type, std::string file = {}) {
    Region r;
    r.base = base;
    r.size = size;
    r.protect = protect;
    r.state = MemState::Commit;
    r.type = type;
    r.mapped_file = std::move(file);
    return r;
}

class ResultsTest : public ::testing::Test {
protected:
    void SetUp() override {
        results_.process = {1234, "game \"x\".exe", "C:\\Games\\game.exe", 0, false};
        results_.patterns = {
            {"needle", PatternKind::Bytes, 4, false},
            {"cfg,\"main\"", PatternKind::Ascii, 6, true},
            {"strings:utf16", PatternKind::StringsUtf16, 0, false},
        };
        // Deliberately unsorted; normalize orders regions by base address.
        results_.regions = {
            region(0x20000, 0x1000, page::ReadOnly, MemType::Image, "C:\\Games\\engine.dll"),
            region(0x10000, 0x2000, page::ReadWrite, MemType::Private),
        };
        add(0x20010, 1, 6, "Config");
        add(0x10100, 0, 4, std::string("\x01\x02\x03\x04", 4));
        add(0x10100, 0, 4, std::string("\x01\x02\x03\x04", 4));
        add(0x30000, 0, 4, std::string("\x01\x02\x03\x04", 4));
        add(0x10F00, 2, 10, std::string("H\0i\0!\0\n\0\"\0", 10));
        add(0x10000, 1, 6, "CONFIG");
        normalize(results_);
    }

    void add(std::uint64_t address, std::uint32_t pattern, std::uint32_t length, std::string_view preview) {
        Match match;
        match.address = address;
        match.pattern = pattern;
        match.length = length;
        match.preview_offset = results_.previews.size();
        match.preview_size = static_cast<std::uint32_t>(preview.size());
        for (const char c : preview) {
            results_.previews.push_back(static_cast<std::byte>(c));
        }
        results_.matches.push_back(match);
    }

    std::vector<std::uint64_t> addresses(const std::vector<std::size_t>& rows) const {
        std::vector<std::uint64_t> out;
        for (const auto row : rows) {
            out.push_back(results_.matches[row].address);
        }
        return out;
    }

    std::vector<std::size_t> all_rows() const {
        std::vector<std::size_t> rows(results_.matches.size());
        for (std::size_t i = 0; i < rows.size(); ++i) {
            rows[i] = i;
        }
        return rows;
    }

    ResultSet results_;
};

TEST_F(ResultsTest, NormalizeSortsDeduplicatesAndAssignsRegions) {
    ASSERT_EQ(results_.matches.size(), 5u);
    EXPECT_EQ(addresses(all_rows()), (std::vector<std::uint64_t>{0x10000, 0x10100, 0x10F00, 0x20010, 0x30000}));
    EXPECT_EQ(results_.regions[0].base, 0x10000u);
    EXPECT_EQ(results_.matches[0].region, 0u);
    EXPECT_EQ(results_.matches[2].region, 0u);
    EXPECT_EQ(results_.matches[3].region, 1u);
    EXPECT_EQ(results_.matches[4].region, kNoRegion);
    EXPECT_EQ(results_.region_of(results_.matches[4]), nullptr);
}

TEST_F(ResultsTest, PreviewsDecodeByKind) {
    EXPECT_EQ(results_.preview_text(results_.matches[0]), "CONFIG");
    EXPECT_EQ(results_.preview_hex(results_.matches[1]), "01 02 03 04");
    EXPECT_EQ(results_.preview_text(results_.matches[2]), "Hi!.\"");
}

TEST_F(ResultsTest, QueryFilters) {
    MatchQuery query;
    query.address_ranges = {{0x10000, 0x10200}, {0x30000, 0x30001}};
    EXPECT_EQ(addresses(run_query(results_, query)), (std::vector<std::uint64_t>{0x10000, 0x10100, 0x30000}));

    query = {};
    query.kinds = {PatternKind::Ascii, PatternKind::StringsUtf16};
    EXPECT_EQ(addresses(run_query(results_, query)), (std::vector<std::uint64_t>{0x10000, 0x10F00, 0x20010}));

    query = {};
    query.patterns = patterns_with_label(results_, "needle");
    EXPECT_EQ(addresses(run_query(results_, query)), (std::vector<std::uint64_t>{0x10100, 0x30000}));
    EXPECT_TRUE(patterns_with_label(results_, "missing").empty());

    query = {};
    query.text = "config";
    EXPECT_EQ(addresses(run_query(results_, query)), (std::vector<std::uint64_t>{0x10000, 0x20010}));
}

TEST_F(ResultsTest, QuerySortsStablyAndLimits) {
    MatchQuery query;
    query.sort = SortKey::Length;
    query.descending = true;
    EXPECT_EQ(addresses(run_query(results_, query)), (std::vector<std::uint64_t>{0x10F00, 0x10000, 0x20010, 0x10100, 0x30000}));
    query.limit = 2;
    EXPECT_EQ(addresses(run_query(results_, query)), (std::vector<std::uint64_t>{0x10F00, 0x10000}));

    query = {};
    query.sort = SortKey::Pattern;
    EXPECT_EQ(addresses(run_query(results_, query)), (std::vector<std::uint64_t>{0x10100, 0x30000, 0x10000, 0x20010, 0x10F00}));
    EXPECT_EQ(parse_sort_key("LENGTH"), SortKey::Length);
    EXPECT_FALSE(parse_sort_key("size"));
}

TEST(Export, Escaping) {
    const std::string backslash(1, '\\');
    EXPECT_EQ(json_escape("a\"b"), "a" + backslash + "\"b");
    EXPECT_EQ(json_escape("C:\\x"), "C:" + backslash + backslash + "x");
    EXPECT_EQ(json_escape(std::string("\n\x01", 2)), backslash + "n" + backslash + "u0001");
    EXPECT_EQ(json_escape("\xD0\x9F"), "\xD0\x9F");
    EXPECT_EQ(csv_field("plain"), "plain");
    EXPECT_EQ(csv_field("a,b"), "\"a,b\"");
    EXPECT_EQ(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
    EXPECT_EQ(csv_field("two\nlines"), "\"two\nlines\"");
}

TEST(Export, DisplayWidth) {
    const std::string privet = "\xD0\x9F\xD1\x80\xD0\xB8\xD0\xB2\xD0\xB5\xD1\x82";
    EXPECT_EQ(display_width(privet), 6u);
    EXPECT_EQ(fit_width(privet, 8), privet + "  ");
    EXPECT_EQ(fit_width(privet, 4), "\xD0\x9F\xD1\x80\xD0\xB8\xE2\x80\xA6");
    EXPECT_EQ(display_width(fit_width(privet, 4)), 4u);
    EXPECT_EQ(parse_output_format("JSON"), OutputFormat::Json);
    EXPECT_EQ(parse_output_format("table"), OutputFormat::Text);
    EXPECT_FALSE(parse_output_format("xml"));
}

TEST_F(ResultsTest, JsonExport) {
    results_.read_failures = {{0x50000, 0x2000, 299}};
    std::ostringstream out;
    const std::vector<std::size_t> rows{0, 2};
    write_json(out, results_, rows, {});
    const std::string json = out.str();
    EXPECT_NE(json.find("\"pid\": 1234"), std::string::npos);
    EXPECT_NE(json.find("\"name\": \"game \\\"x\\\".exe\""), std::string::npos);
    EXPECT_NE(json.find("\"path\": \"C:\\\\Games\\\\game.exe\""), std::string::npos);
    EXPECT_NE(json.find("\"label\": \"cfg,\\\"main\\\"\""), std::string::npos);
    EXPECT_NE(json.find("\"address\": \"0x0000000000010000\""), std::string::npos);
    EXPECT_NE(json.find("\"address\": \"0x0000000000010F00\""), std::string::npos);
    EXPECT_EQ(json.find("0x0000000000010100"), std::string::npos);
    EXPECT_NE(json.find("\"matches_exported\": 2"), std::string::npos);
    EXPECT_NE(json.find("\"preview_text\": \"Hi!.\\\"\""), std::string::npos);
    EXPECT_NE(json.find("\"protection\": \"rw-\""), std::string::npos);
    EXPECT_NE(json.find("{\"address\": \"0x0000000000050000\", \"size\": 8192, \"error\": 299}"), std::string::npos);
    EXPECT_EQ(std::count(json.begin(), json.end(), '{'), std::count(json.begin(), json.end(), '}'));
    EXPECT_EQ(std::count(json.begin(), json.end(), '['), std::count(json.begin(), json.end(), ']'));

    std::ostringstream bare;
    write_json(bare, results_, rows, ExportOptions{false, 64});
    EXPECT_EQ(bare.str().find("preview_hex"), std::string::npos);
}

TEST_F(ResultsTest, CsvExport) {
    std::ostringstream out;
    write_csv(out, results_, all_rows(), {});
    const std::string csv = out.str();
    std::vector<std::string> lines;
    std::size_t start = 0;
    for (std::size_t at = csv.find("\r\n"); at != std::string::npos; at = csv.find("\r\n", start)) {
        lines.push_back(csv.substr(start, at - start));
        start = at + 2;
    }
    EXPECT_EQ(start, csv.size());
    ASSERT_EQ(lines.size(), 6u);
    EXPECT_EQ(lines[0], "address,length,pattern,kind,label,region_base,region_size,protection,type,module,preview_hex,preview_text");
    EXPECT_EQ(lines[1], "0x0000000000010000,6,1,ascii,\"cfg,\"\"main\"\"\",0x0000000000010000,8192,rw-,private,,43 4F 4E 46 49 47,CONFIG");
    EXPECT_EQ(lines[4], "0x0000000000020010,6,1,ascii,\"cfg,\"\"main\"\"\",0x0000000000020000,4096,r--,image,engine.dll,"
                        "43 6F 6E 66 69 67,Config");
    EXPECT_EQ(lines[5], "0x0000000000030000,4,0,bytes,needle,,,,,,01 02 03 04,....");
}

TEST_F(ResultsTest, TextExport) {
    std::ostringstream out;
    write_text(out, results_, all_rows(), ExportOptions{true, 3});
    const std::string text = out.str();
    EXPECT_EQ(std::count(text.begin(), text.end(), '\n'), 6);
    EXPECT_EQ(text.rfind("ADDRESS", 0), 0u);
    EXPECT_NE(text.find("engine.dll"), std::string::npos);
    EXPECT_NE(text.find("CO\xE2\x80\xA6"), std::string::npos);
    EXPECT_EQ(text.find("CONFIG"), std::string::npos);

    std::ostringstream summary;
    results_.stats.truncated = true;
    results_.stats.matches_found = 99;
    write_summary(summary, results_, 2);
    EXPECT_NE(summary.str().find("Matches: 5 (2 shown)"), std::string::npos);
    EXPECT_NE(summary.str().find("99 matches were found but only 5 kept"), std::string::npos);
}

}  // namespace
}  // namespace mh
