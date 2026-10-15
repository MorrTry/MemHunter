#include <gtest/gtest.h>

#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <thread>

#include "common/error.hpp"
#include "common/text.hpp"
#include "gui/process_picker.hpp"
#include "gui/results_table.hpp"
#include "gui/search.hpp"
#include "gui/session.hpp"
#include "gui/value_history.hpp"
#include "gui/value_table.hpp"
#include "gui/watch_list.hpp"
#include "support/fake_memory.hpp"
#include "support/fake_target.hpp"

namespace mh::gui {
namespace {

using mh::testing::FakeMemory;
using mh::testing::FakeTarget;
using namespace std::chrono_literals;

constexpr std::uint64_t kBase = 0x10000;

std::string hex(std::string_view number, NumberType type) {
    return number_signature(number, type);
}

void write_ascii(FakeMemory& memory, std::uint64_t address, std::string_view text) {
    std::memcpy(memory.bytes_at(address, text.size()).data(), text.data(), text.size());
}

void write_utf16(FakeMemory& memory, std::uint64_t address, std::string_view text) {
    const auto bytes = memory.bytes_at(address, text.size() * 2);
    for (std::size_t i = 0; i < text.size(); ++i) {
        bytes[2 * i] = static_cast<std::byte>(text[i]);
        bytes[2 * i + 1] = std::byte{0};
    }
}

template <typename T>
void put(FakeMemory& memory, std::uint64_t address, T value) {
    std::memcpy(memory.bytes_at(address, sizeof(T)).data(), &value, sizeof(T));
}

bool contains(std::string_view text, std::string_view part) {
    return text.find(part) != std::string_view::npos;
}

TEST(GuiSearch, NumbersBecomeLittleEndianBytes) {
    EXPECT_EQ(hex("15000", NumberType::Int32), "98 3A 00 00");
    EXPECT_EQ(hex(" 0x3A98 ", NumberType::Int32), "98 3A 00 00");
    EXPECT_EQ(hex("-1", NumberType::Int16), "FF FF");
    EXPECT_EQ(hex("255", NumberType::Int8), "FF");
    EXPECT_EQ(hex("-128", NumberType::Int8), "80");
    EXPECT_EQ(hex("18446744073709551615", NumberType::Int64), "FF FF FF FF FF FF FF FF");
    EXPECT_EQ(hex("-9223372036854775808", NumberType::Int64), "00 00 00 00 00 00 00 80");
    EXPECT_EQ(hex("102.5", NumberType::Float), "00 00 CD 42");
    EXPECT_EQ(hex("-37,25", NumberType::Float), "00 00 15 C2");
    EXPECT_EQ(hex("1.5", NumberType::Double), "00 00 00 00 00 00 F8 3F");

    EXPECT_THROW(encode_number("256", NumberType::Int8), Error);
    EXPECT_THROW(encode_number("-129", NumberType::Int8), Error);
    EXPECT_THROW(encode_number("18446744073709551616", NumberType::Int64), Error);
    EXPECT_THROW(encode_number("12abc", NumberType::Int32), Error);
    EXPECT_THROW(encode_number("", NumberType::Int32), Error);
    EXPECT_THROW(encode_number("1e999", NumberType::Float), Error);
    EXPECT_THROW(encode_number("nan", NumberType::Double), Error);
    try {
        encode_number("300", NumberType::Int8);
        FAIL();
    } catch (const Error& error) {
        EXPECT_TRUE(contains(error.what(), "от -128 до 255")) << error.what();
    }
}

TEST(GuiSearch, RequestFollowsTheSelectedMode) {
    SearchForm form;
    EXPECT_THROW(build_request(form), Error);

    form.text = "password";
    ScanRequest request = build_request(form);
    ASSERT_EQ(request.patterns.size(), 2u);
    EXPECT_EQ(request.patterns[0].kind, PatternKind::Ascii);
    EXPECT_EQ(request.patterns[1].kind, PatternKind::Utf16);
    EXPECT_FALSE(request.strings);
    EXPECT_EQ(request.filter.types, type_class::All);
    EXPECT_EQ(request.filter.protections, protection_class::Readable);
    EXPECT_EQ(request.engine.preview_bytes, kPreviewBytes);
    EXPECT_EQ(request.engine.max_matches, kDefaultMaxMatches);

    form.text_encoding = TextEncoding::Utf16;
    form.ignore_case = true;
    request = build_request(form);
    ASSERT_EQ(request.patterns.size(), 1u);
    EXPECT_TRUE(request.patterns[0].case_insensitive);

    form.mode = SearchMode::Bytes;
    form.signatures = "money = 98 3A 00 00\r\n\r\n48 8B ?? 89\n";
    request = build_request(form);
    ASSERT_EQ(request.patterns.size(), 2u);
    EXPECT_EQ(request.patterns[0].label, "money");
    EXPECT_EQ(request.patterns[0].kind, PatternKind::Bytes);
    EXPECT_EQ(request.patterns[1].kind, PatternKind::Signature);
    form.signatures = "90 90\n48 zz";
    try {
        build_request(form);
        FAIL();
    } catch (const Error& error) {
        EXPECT_TRUE(contains(error.what(), "строке 2")) << error.what();
    }
    form.signatures = " \n ";
    EXPECT_THROW(build_request(form), Error);

    form.mode = SearchMode::Number;
    form.number = "15000";
    request = build_request(form);
    ASSERT_EQ(request.patterns.size(), 1u);
    EXPECT_EQ(request.patterns[0].label, "int32 15000");
    EXPECT_EQ(request.patterns[0].value, (std::vector<std::uint8_t>{0x98, 0x3A, 0x00, 0x00}));

    form.mode = SearchMode::Strings;
    form.min_length = 8;
    form.strings_encoding = TextEncoding::Ascii;
    request = build_request(form);
    EXPECT_TRUE(request.patterns.empty());
    ASSERT_TRUE(request.strings);
    EXPECT_EQ(request.strings->min_length, 8u);
    EXPECT_EQ(request.strings->encodings, encoding::Ascii);
    form.min_length = 1;
    EXPECT_THROW(build_request(form), Error);
    form.min_length = 8;

    form.image_memory = false;
    form.mapped_memory = false;
    form.writable_only = true;
    form.threads = 3;
    request = build_request(form);
    EXPECT_EQ(request.filter.types, type_class::Private);
    EXPECT_EQ(request.filter.protections & protection_class::ReadOnly, 0u);
    EXPECT_NE(request.filter.protections & protection_class::ReadWrite, 0u);
    EXPECT_EQ(request.engine.scan_threads, 3u);
    form.threads = kMaxThreads + 1;
    EXPECT_THROW(build_request(form), Error);
    form.threads = kMaxThreads;
    EXPECT_EQ(build_request(form).engine.scan_threads, kMaxThreads);
    form.private_memory = false;
    EXPECT_THROW(build_request(form), Error);
}

TEST(GuiSearch, ValueConditionsFromTheForm) {
    SearchForm form;
    form.number = "15000";
    EXPECT_EQ(value_condition(form, NumberType::Int32).bits, 15000u);
    form.number = "4294967295";
    EXPECT_EQ(value_condition(form, NumberType::Int32).bits, 0xFFFFFFFFu);

    form.compare = Compare::Greater;
    EXPECT_THROW(value_condition(form, NumberType::Int32), Error);
    form.number = " -5 ";
    EXPECT_EQ(value_condition(form, NumberType::Int32).integer, -5);
    form.number = "128";
    EXPECT_THROW(value_condition(form, NumberType::Int8), Error);

    form.compare = Compare::Between;
    form.number = "10";
    form.number_high = "";
    EXPECT_THROW(value_condition(form, NumberType::Int32), Error);
    form.number_high = "2";
    const ValueCondition between = value_condition(form, NumberType::Int32);
    EXPECT_EQ(between.integer, 2);
    EXPECT_EQ(between.integer_high, 10);
    form.number = "1,5";
    form.number_high = "-0.5";
    const ValueCondition floats = value_condition(form, NumberType::Double);
    EXPECT_EQ(floats.number, -0.5);
    EXPECT_EQ(floats.number_high, 1.5);

    form.compare = Compare::Exact;
    form.number = "100";
    EXPECT_DOUBLE_EQ(value_condition(form, NumberType::Float).tolerance, 0.5);
    form.number = "99,5";
    const ValueCondition decimals = value_condition(form, NumberType::Float);
    EXPECT_EQ(decimals.number, 99.5);
    EXPECT_DOUBLE_EQ(decimals.tolerance, 0.05);
    form.number = "1e2";
    EXPECT_EQ(value_condition(form, NumberType::Double).tolerance, 0);
    form.number = "0.1";
    EXPECT_EQ(value_condition(form, NumberType::Float).number, static_cast<double>(0.1f));
    form.number = "abc";
    EXPECT_THROW(value_condition(form, NumberType::Float), Error);

    form.number = "";
    for (Compare compare : {Compare::Unknown, Compare::Increased, Compare::Decreased, Compare::Changed, Compare::Unchanged}) {
        form.compare = compare;
        EXPECT_FALSE(takes_number(compare));
        EXPECT_EQ(value_condition(form, NumberType::Int32).compare, compare);
    }
}

TEST(GuiText, CountsUseRussianPlurals) {
    EXPECT_EQ(count_addresses(1), "1 адрес");
    EXPECT_EQ(count_addresses(3), "3 адреса");
    EXPECT_EQ(count_addresses(11), "11 адресов");
    EXPECT_EQ(count_addresses(20480), "20 480 адресов");
    EXPECT_EQ(count_matches(0), "0 совпадений");
    EXPECT_EQ(count_matches(1), "1 совпадение");
    EXPECT_EQ(count_matches(3), "3 совпадения");
    EXPECT_EQ(count_matches(5), "5 совпадений");
    EXPECT_EQ(count_matches(11), "11 совпадений");
    EXPECT_EQ(count_matches(22), "22 совпадения");
    EXPECT_EQ(count_matches(112), "112 совпадений");
    EXPECT_EQ(count_matches(1234567), "1 234 567 совпадений");
    EXPECT_EQ(group_digits(999), "999");
    EXPECT_EQ(format_seconds(0.5), "0.50 с");
}

// "password" three times as ASCII, once as UTF-16 and once in upper case.
class GuiScan : public ::testing::Test {
protected:
    GuiScan() {
        memory_.add(kBase, 64 * 1024);
        memory_.add(kBase + 0x20000, 16 * 1024, page::ReadOnly, MemType::Image);
        write_ascii(memory_, kBase + 0x100, "password");
        write_ascii(memory_, kBase + 0x2000, "password");
        write_utf16(memory_, kBase + 0x4000, "password");
        write_ascii(memory_, kBase + 0x8000, "PASSWORD");
        write_ascii(memory_, kBase + 0x20010, "password");
    }

    void wait(Session& session) {
        const auto deadline = std::chrono::steady_clock::now() + 10s;
        while (!session.poll()) {
            ASSERT_LT(std::chrono::steady_clock::now(), deadline);
            std::this_thread::sleep_for(2ms);
        }
    }

    void attach(Session& session) { session.attach(std::make_unique<FakeTarget>(memory_)); }

    FakeMemory memory_;
};

TEST_F(GuiScan, ScanFillsTheTableAndSelectsTheFirstRow) {
    Session session;
    SearchForm form;
    form.text = "password";
    EXPECT_FALSE(session.start_scan(form, false));
    EXPECT_TRUE(session.notice().error);

    session.attach(std::make_unique<FakeTarget>(memory_));
    EXPECT_TRUE(contains(session.notice().text, "fake.exe (PID 4321)"));
    ASSERT_TRUE(session.start_scan(form, false));
    EXPECT_TRUE(session.busy());
    EXPECT_FALSE(session.start_scan(form, false));
    wait(session);
    EXPECT_FALSE(session.busy());

    const ResultsTable& table = session.table();
    ASSERT_TRUE(table.has_results());
    EXPECT_EQ(table.rows().size(), 4u);
    EXPECT_TRUE(session.notice().text.starts_with("Найдено 4 совпадения за ")) << session.notice().text;
    EXPECT_FALSE(session.notice().error);
    ASSERT_NE(table.selected_match(), nullptr);
    EXPECT_EQ(table.selected_match()->address, kBase + 0x100);
    EXPECT_EQ(session.patterns().size(), 2u);

    const std::size_t first = table.rows()[0];
    EXPECT_EQ(table.cell(first, Column::Address, PreviewMode::Hex), format_address(kBase + 0x100));
    EXPECT_EQ(table.cell(first, Column::Kind, PreviewMode::Hex), "ASCII");
    EXPECT_EQ(table.cell(first, Column::Pattern, PreviewMode::Hex), "password");
    EXPECT_EQ(table.cell(first, Column::Length, PreviewMode::Hex), "8");
    EXPECT_EQ(table.cell(first, Column::Type, PreviewMode::Hex), "private");
    EXPECT_TRUE(table.cell(first, Column::Preview, PreviewMode::Text).starts_with("password"));
    EXPECT_TRUE(table.cell(first, Column::Preview, PreviewMode::Hex).starts_with("70 61 73 73"));

    form.ignore_case = true;
    ASSERT_TRUE(session.start_scan(form, false));
    wait(session);
    EXPECT_EQ(session.table().rows().size(), 5u);
}

TEST_F(GuiScan, FilterSortAndSelection) {
    Session session;
    attach(session);
    SearchForm form;
    form.text = "password";
    ASSERT_TRUE(session.start_scan(form, false));
    wait(session);
    ResultsTable& table = session.table();
    ASSERT_EQ(table.rows().size(), 4u);

    table.select_row(2);
    const std::uint64_t chosen = table.selected_match()->address;
    table.sort_by(Column::Kind, true);
    ASSERT_TRUE(table.selected_row());
    EXPECT_EQ(table.selected_match()->address, chosen);
    EXPECT_EQ(table.cell(table.rows()[0], Column::Kind, PreviewMode::Hex), "UTF-16");

    table.sort_by(Column::Address, false);
    table.set_filter("UTF-16");
    ASSERT_EQ(table.rows().size(), 1u);
    EXPECT_EQ(table.selected_match()->address, kBase + 0x4000);
    table.set_filter("image");
    EXPECT_EQ(table.rows().size(), 0u);
    EXPECT_EQ(table.selected_match(), nullptr);
    table.set_filter(format_address(kBase + 0x2000).substr(10));
    ASSERT_EQ(table.rows().size(), 1u);
    table.set_filter("70 61 73");
    EXPECT_EQ(table.rows().size(), 3u);
    table.set_filter("");
    EXPECT_EQ(table.rows().size(), 4u);

    table.select_row(0);
    table.move_selection(-5);
    EXPECT_EQ(*table.selected_row(), 0u);
    table.move_selection(100);
    EXPECT_EQ(*table.selected_row(), 3u);
    table.select_row(99);
    EXPECT_EQ(*table.selected_row(), 3u);
}

TEST_F(GuiScan, MemoryTypesAndNumbers) {
    Session session;
    attach(session);
    SearchForm form;
    form.text = "password";
    form.private_memory = false;
    ASSERT_TRUE(session.start_scan(form, false));
    wait(session);
    ASSERT_EQ(session.table().rows().size(), 1u);
    EXPECT_EQ(session.table().selected_match()->address, kBase + 0x20010);

    const std::uint32_t money = 15000;
    std::memcpy(memory_.bytes_at(kBase + 0x3000, 4).data(), &money, 4);
    form = {};
    form.mode = SearchMode::Number;
    form.number = "15000";
    ASSERT_TRUE(session.start_scan(form, false));
    wait(session);
    ASSERT_EQ(session.table().rows().size(), 1u);
    EXPECT_EQ(session.table().selected_match()->address, kBase + 0x3000);
    EXPECT_EQ(session.table().cell(session.table().rows()[0], Column::Kind, PreviewMode::Hex), "байты");
}

TEST_F(GuiScan, OnlyChangedMemoryNeedsABaseline) {
    Session session;
    attach(session);
    SearchForm form;
    form.text = "password";
    EXPECT_FALSE(session.start_scan(form, true));
    EXPECT_TRUE(session.notice().error);

    ASSERT_TRUE(session.start_remember(form));
    wait(session);
    ASSERT_TRUE(session.baseline());
    EXPECT_EQ(session.baseline()->bytes, 80u * 1024);
    EXPECT_TRUE(session.notice().text.starts_with("Память запомнена (80.00 KiB)")) << session.notice().text;

    write_ascii(memory_, kBase + 0xA000, "password");
    ASSERT_TRUE(session.start_scan(form, true));
    wait(session);
    ASSERT_EQ(session.table().rows().size(), 1u);
    EXPECT_EQ(session.table().selected_match()->address, kBase + 0xA000);
    ASSERT_TRUE(session.changes());
    EXPECT_EQ(session.changes()->changed, 4096u);
    EXPECT_TRUE(contains(session.notice().text, "Изменилось 4.00 KiB из 80.00 KiB")) << session.notice().text;

    session.forget();
    EXPECT_FALSE(session.baseline());
    EXPECT_FALSE(session.start_scan(form, true));
}

TEST_F(GuiScan, AttachingAnotherTargetDropsTheResults) {
    Session session;
    attach(session);
    SearchForm form;
    form.text = "password";
    ASSERT_TRUE(session.start_remember(form));
    wait(session);
    ASSERT_TRUE(session.start_scan(form, false));
    session.attach(std::make_unique<FakeTarget>(memory_));
    EXPECT_FALSE(session.busy());
    EXPECT_FALSE(session.table().has_results());
    EXPECT_FALSE(session.baseline());
    session.detach();
    EXPECT_EQ(session.target(), nullptr);
    EXPECT_FALSE(session.target_alive());
}

TEST_F(GuiScan, CancelledScanKeepsWhatWasFound) {
    std::atomic<bool> release{false};
    memory_.on_read([&](std::size_t) {
        while (!release.load()) {
            std::this_thread::sleep_for(1ms);
        }
    });
    Session session;
    attach(session);
    SearchForm form;
    form.text = "password";
    form.threads = 1;
    ASSERT_TRUE(session.start_scan(form, false));
    session.cancel();
    release = true;
    wait(session);
    EXPECT_TRUE(session.table().has_results());
    EXPECT_TRUE(session.notice().text.starts_with("Поиск остановлен")) << session.notice().text;
}

TEST_F(GuiScan, DumpShowsWhatIsReadableAndWhetherTheMatchIsStillThere) {
    Session session;
    attach(session);
    SearchForm form;
    form.text = "password";
    form.text_encoding = TextEncoding::Ascii;
    ASSERT_TRUE(session.start_scan(form, false));
    wait(session);
    const Match match = *session.table().selected_match();

    MemoryDump dump = read_dump(memory_, kBase - 0x40, 0x200);
    EXPECT_FALSE(dump.all_readable(kBase - 0x40, kBase));
    EXPECT_TRUE(dump.all_readable(kBase, kBase + 0x1C0));
    EXPECT_EQ(std::memcmp(dump.bytes.data() + 0x140, "password", 8), 0);
    EXPECT_EQ(live_state(session.table().results(), session.patterns(), match, dump), LiveState::Same);

    write_ascii(memory_, kBase + 0x100, "passw0rd");
    dump = read_dump(memory_, kBase - 0x40, 0x200);
    EXPECT_EQ(live_state(session.table().results(), session.patterns(), match, dump), LiveState::Changed);
    dump = read_dump(memory_, kBase + 0x104, 0x10);
    EXPECT_EQ(live_state(session.table().results(), session.patterns(), match, dump), LiveState::Unreadable);
}

TEST_F(GuiScan, ExtractedStringsCompareWithTheTextFound) {
    Session session;
    attach(session);
    SearchForm form;
    form.mode = SearchMode::Strings;
    form.min_length = 8;
    form.strings_encoding = TextEncoding::Ascii;
    form.image_memory = false;
    ASSERT_TRUE(session.start_scan(form, false));
    wait(session);
    ResultsTable& table = session.table();
    table.set_filter("PASSWORD");
    ASSERT_EQ(table.rows().size(), 3u);
    table.set_filter("строка");
    EXPECT_EQ(table.rows().size(), 3u);
    const Match match = *table.selected_match();
    EXPECT_EQ(live_state(table.results(), session.patterns(), match, read_dump(memory_, match.address, 64)), LiveState::Same);
    memory_.bytes_at(match.address, 1)[0] = std::byte{'X'};
    EXPECT_EQ(live_state(table.results(), session.patterns(), match, read_dump(memory_, match.address, 64)), LiveState::Changed);
}

TEST_F(GuiScan, ExportWritesTheShownRowsInTheFormatOfTheExtension) {
    Session session;
    attach(session);
    SearchForm form;
    form.text = "password";
    ASSERT_TRUE(session.start_scan(form, false));
    wait(session);
    ResultsTable& table = session.table();
    table.set_filter("UTF-16");

    const auto dir = std::filesystem::temp_directory_path() / "memhunter_gui_test";
    std::filesystem::create_directories(dir);
    const auto read = [](const std::filesystem::path& path) {
        std::ifstream in(path, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    };
    const auto json = dir / L"результаты.json";
    export_rows(json, table.results(), table.rows());
    const std::string json_text = read(json);
    EXPECT_TRUE(json_text.starts_with("{")) << json_text.substr(0, 40);
    EXPECT_TRUE(contains(json_text, format_address(kBase + 0x4000)));
    EXPECT_FALSE(contains(json_text, format_address(kBase + 0x100)));

    const auto csv = dir / "results.CSV";
    export_rows(csv, table.results(), table.rows());
    const std::string csv_text = read(csv);
    EXPECT_FALSE(csv_text.starts_with("{"));
    EXPECT_TRUE(contains(csv_text, format_address(kBase + 0x4000)));

    EXPECT_THROW(export_rows(dir / "missing" / "x.json", table.results(), table.rows()), Error);
    std::filesystem::remove_all(dir);
}

TEST_F(GuiScan, ValueScansNarrowTheCandidates) {
    const auto put = [&](std::int32_t value) { std::memcpy(memory_.bytes_at(kBase + 0x3000, 4).data(), &value, 4); };
    put(86);
    Session session;
    attach(session);
    SearchForm form;
    form.mode = SearchMode::Number;
    form.compare = Compare::Increased;
    EXPECT_FALSE(session.start_value_scan(form));
    EXPECT_TRUE(session.notice().error);

    form.compare = Compare::Unknown;
    ASSERT_TRUE(session.start_value_scan(form));
    wait(session);
    ValueTable& values = session.values();
    ASSERT_TRUE(values.has_values());
    EXPECT_EQ(values.total(), (64 + 16) * 1024 / 4);
    EXPECT_EQ(values.rows().size(), kShownValues);
    EXPECT_TRUE(session.notice().text.starts_with("Поиск 1: найдено 20 480 адресов")) << session.notice().text;

    put(73);
    form.compare = Compare::Decreased;
    ASSERT_TRUE(session.start_value_scan(form));
    wait(session);
    ASSERT_EQ(values.total(), 1u);
    EXPECT_EQ(values.rows()[0].address, kBase + 0x3000);
    EXPECT_EQ(values.previous_text(0), "73");
    EXPECT_TRUE(session.notice().text.starts_with("Поиск 2: осталось 1 адрес из 20 480")) << session.notice().text;
    EXPECT_EQ(values.module(0), "");
    ASSERT_NE(values.region(0), nullptr);
    EXPECT_EQ(values.region(0)->base, kBase);

    values.select_row(0);
    put(113);
    form.compare = Compare::Increased;
    ASSERT_TRUE(session.start_value_scan(form));
    wait(session);
    ASSERT_EQ(values.total(), 1u);
    ASSERT_NE(values.selected(), nullptr);
    EXPECT_EQ(values.selected()->address, kBase + 0x3000);

    EXPECT_EQ(values.current_text(0), "");
    values.refresh(memory_, 0, 5);
    EXPECT_EQ(values.current_text(0), "113");
    EXPECT_FALSE(values.changed(0));
    put(-120);
    values.refresh(memory_, 0, 1);
    EXPECT_EQ(values.current_text(0), "-120");
    EXPECT_TRUE(values.changed(0));

    // The type of a next scan is that of the first one.
    form.number_type = NumberType::Float;
    form.compare = Compare::Exact;
    form.number = "-120";
    ASSERT_TRUE(session.start_value_scan(form));
    wait(session);
    EXPECT_EQ(values.total(), 1u);
    EXPECT_EQ(values.candidates()->type, ValueType::Int32);

    form.compare = Compare::Unknown;
    EXPECT_FALSE(session.start_value_scan(form));
    EXPECT_TRUE(session.notice().error);

    session.reset_values();
    EXPECT_FALSE(values.has_values());
    form.number_type = NumberType::Int32;
    form.compare = Compare::Exact;
    form.number = "123456789";
    ASSERT_TRUE(session.start_value_scan(form));
    wait(session);
    EXPECT_FALSE(values.has_values());
    EXPECT_TRUE(session.notice().text.starts_with("Ничего не найдено")) << session.notice().text;

    form.number = "-120";
    ASSERT_TRUE(session.start_value_scan(form));
    wait(session);
    EXPECT_EQ(values.total(), 1u);
    put(5);
    form.number = "6";
    ASSERT_TRUE(session.start_value_scan(form));
    wait(session);
    EXPECT_TRUE(values.has_values());
    EXPECT_EQ(values.total(), 0u);
    EXPECT_TRUE(contains(session.notice().text, "Новый поиск")) << session.notice().text;
}

TEST_F(GuiScan, StoppedNextScanKeepsTheCandidates) {
    Session session;
    attach(session);
    SearchForm form;
    form.mode = SearchMode::Number;
    form.compare = Compare::Unknown;
    form.threads = 1;
    ASSERT_TRUE(session.start_value_scan(form));
    wait(session);
    const std::uint64_t total = session.values().total();
    ASSERT_GT(total, 0u);

    std::atomic<bool> release{false};
    memory_.on_read([&](std::size_t) {
        while (!release.load()) {
            std::this_thread::sleep_for(1ms);
        }
    });
    form.compare = Compare::Changed;
    ASSERT_TRUE(session.start_value_scan(form));
    session.cancel();
    release = true;
    wait(session);
    EXPECT_EQ(session.values().total(), total);
    EXPECT_EQ(session.notice().text, "Поиск остановлен, результаты прежние");
}

TEST_F(GuiScan, ValueExportWritesTheShownRows) {
    const std::int32_t money = 15000;
    std::memcpy(memory_.bytes_at(kBase + 0x3000, 4).data(), &money, 4);
    std::memcpy(memory_.bytes_at(kBase + 0x20020, 4).data(), &money, 4);
    Session session;
    attach(session);
    SearchForm form;
    form.mode = SearchMode::Number;
    form.number = "15000";
    ASSERT_TRUE(session.start_value_scan(form));
    wait(session);
    ASSERT_EQ(session.values().total(), 2u);

    const auto dir = std::filesystem::temp_directory_path() / "memhunter_gui_values";
    std::filesystem::create_directories(dir);
    const auto read = [](const std::filesystem::path& path) {
        std::ifstream in(path, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    };
    const ProcessSummary& process = session.target()->summary();
    export_values(dir / "values.json", process, session.values());
    const std::string json = read(dir / "values.json");
    EXPECT_TRUE(json.starts_with("{")) << json;
    EXPECT_TRUE(contains(json, "\"value_type\": \"int32\"")) << json;
    EXPECT_TRUE(contains(json, "{\"address\": \"" + format_address(kBase + 0x3000) + "\", \"value\": \"15000\"")) << json;
    EXPECT_TRUE(contains(json, "\"memory\": \"image\"")) << json;

    export_values(dir / "values.csv", process, session.values());
    const std::string csv = read(dir / "values.csv");
    EXPECT_TRUE(csv.starts_with("address,value,type,protection,memory,module\n")) << csv;
    EXPECT_TRUE(contains(csv, format_address(kBase + 0x20020) + ",15000,int32,")) << csv;

    export_values(dir / "values.txt", process, session.values());
    EXPECT_TRUE(read(dir / "values.txt").starts_with("process fake.exe (pid 4321), int32, scan 1, 2 addresses")) << read(dir / "values.txt");
    std::filesystem::remove_all(dir);
}

std::shared_ptr<const ValueCandidates> candidates(unsigned scan, std::size_t count) {
    auto list = std::make_shared<ValueCandidates>();
    list->scans = scan;
    list->sparse.resize(count);
    return list;
}

TEST(GuiHistory, DescribesTheScans) {
    SearchForm form;
    form.number = " 86 ";
    EXPECT_EQ(describe_scan(form, NumberType::Int32, true), "int32 = 86");
    EXPECT_EQ(describe_scan(form, NumberType::Int32, false), "= 86");
    form.compare = Compare::Greater;
    EXPECT_EQ(describe_scan(form, NumberType::Float, true), "float > 86");
    form.compare = Compare::Less;
    EXPECT_EQ(describe_scan(form, NumberType::Int8, false), "< 86");
    form.compare = Compare::Between;
    form.number_high = "100";
    EXPECT_EQ(describe_scan(form, NumberType::Double, false), "от 86 до 100");
    form.compare = Compare::Unknown;
    EXPECT_EQ(describe_scan(form, NumberType::Int64, true), "int64, неизвестное");
    form.compare = Compare::Increased;
    EXPECT_EQ(describe_scan(form, NumberType::Int32, false), "Увеличилось");
    form.compare = Compare::Decreased;
    EXPECT_EQ(describe_scan(form, NumberType::Int32, false), "Уменьшилось");
    form.compare = Compare::Changed;
    EXPECT_EQ(describe_scan(form, NumberType::Int32, false), "Изменилось");
    form.compare = Compare::Unchanged;
    EXPECT_EQ(describe_scan(form, NumberType::Int32, false), "Не изменилось");
}

TEST(GuiHistory, UndoRedoAndAScanFromAnEarlierStep) {
    ValueHistory history;
    EXPECT_TRUE(history.empty());
    EXPECT_FALSE(history.can_undo());
    EXPECT_FALSE(history.can_redo());
    history.push(candidates(1, 30), "int32 = 86", 0);
    history.push(candidates(2, 20), "Уменьшилось", 0);
    history.push(candidates(3, 10), "= 60", 0);
    ASSERT_EQ(history.steps().size(), 3u);
    EXPECT_EQ(history.current(), 2u);
    EXPECT_EQ(history.steps()[0].count, 30u);
    EXPECT_EQ(history.steps()[1].label, "Уменьшилось");
    EXPECT_TRUE(history.can_undo());
    EXPECT_FALSE(history.can_redo());

    history.go_to(0);
    EXPECT_EQ(history.current(), 0u);
    EXPECT_FALSE(history.can_undo());
    EXPECT_TRUE(history.can_redo());
    history.go_to(3);
    EXPECT_EQ(history.current(), 0u);

    history.push(candidates(2, 5), "Изменилось", 0);
    ASSERT_EQ(history.steps().size(), 2u);
    EXPECT_EQ(history.current(), 1u);
    EXPECT_EQ(history.steps()[1].label, "Изменилось");
    EXPECT_FALSE(history.can_redo());
    EXPECT_FALSE(history.trimmed());

    history.clear();
    EXPECT_TRUE(history.empty());
    EXPECT_EQ(history.current(), 0u);
}

TEST(GuiHistory, OldestStepsGoWhenTheHistoryTakesTooMuchMemory) {
    constexpr std::uint64_t budget = 150 * sizeof(ValueCandidate);
    ValueHistory history;
    history.push(candidates(1, 100), "a", budget);
    history.push(candidates(2, 40), "b", budget);
    EXPECT_EQ(history.steps().size(), 2u);
    EXPECT_FALSE(history.trimmed());

    history.push(candidates(3, 30), "c", budget);
    ASSERT_EQ(history.steps().size(), 2u);
    EXPECT_EQ(history.steps()[0].label, "b");
    EXPECT_EQ(history.current(), 1u);
    EXPECT_TRUE(history.trimmed());

    // The current step stays even when it alone is over the budget.
    history.push(candidates(4, 200), "d", budget);
    ASSERT_EQ(history.steps().size(), 1u);
    EXPECT_EQ(history.steps()[0].label, "d");
    EXPECT_EQ(history.current(), 0u);

    history.clear();
    EXPECT_FALSE(history.trimmed());
}

TEST_F(GuiScan, HistoryGoesBackToAnEarlierScan) {
    const auto put = [&](std::int32_t value) { std::memcpy(memory_.bytes_at(kBase + 0x3000, 4).data(), &value, 4); };
    put(86);
    Session session;
    attach(session);
    const ValueHistory& history = session.history();
    SearchForm form;
    form.mode = SearchMode::Number;
    form.compare = Compare::Unknown;
    ASSERT_TRUE(session.start_value_scan(form));
    wait(session);
    put(73);
    form.compare = Compare::Decreased;
    ASSERT_TRUE(session.start_value_scan(form));
    wait(session);
    ASSERT_EQ(history.steps().size(), 2u);
    EXPECT_EQ(history.steps()[0].label, "int32, неизвестное");
    EXPECT_EQ(history.steps()[0].count, 20480u);
    EXPECT_EQ(history.steps()[1].label, "Уменьшилось");
    EXPECT_EQ(history.steps()[1].count, 1u);

    ASSERT_TRUE(session.go_to_scan(0));
    EXPECT_EQ(session.values().total(), 20480u);
    EXPECT_EQ(session.values().candidates()->scans, 1u);
    EXPECT_EQ(session.notice().text, "Показан поиск 1: 20 480 адресов");
    EXPECT_FALSE(session.go_to_scan(2));
    ASSERT_TRUE(session.go_to_scan(1));
    EXPECT_EQ(session.values().total(), 1u);
    EXPECT_EQ(session.values().previous_text(0), "73");

    // A next scan from the first step compares with the values of that step and replaces the second one.
    ASSERT_TRUE(session.go_to_scan(0));
    put(90);
    form.compare = Compare::Increased;
    ASSERT_TRUE(session.start_value_scan(form));
    wait(session);
    ASSERT_EQ(history.steps().size(), 2u);
    EXPECT_EQ(history.current(), 1u);
    EXPECT_EQ(history.steps()[1].label, "Увеличилось");
    EXPECT_EQ(session.values().total(), 1u);
    EXPECT_TRUE(session.notice().text.starts_with("Поиск 2: осталось 1 адрес из 20 480")) << session.notice().text;

    std::atomic<bool> release{false};
    memory_.on_read([&](std::size_t) {
        while (!release.load()) {
            std::this_thread::sleep_for(1ms);
        }
    });
    form.compare = Compare::Changed;
    ASSERT_TRUE(session.start_value_scan(form));
    EXPECT_FALSE(session.go_to_scan(0));
    release = true;
    wait(session);
    ASSERT_EQ(history.steps().size(), 3u);
    EXPECT_EQ(session.values().total(), 0u);
    EXPECT_TRUE(contains(session.notice().text, "Ctrl+Z")) << session.notice().text;

    session.reset_values();
    EXPECT_TRUE(history.empty());
    form.compare = Compare::Unknown;
    ASSERT_TRUE(session.start_value_scan(form));
    wait(session);
    EXPECT_EQ(history.steps().size(), 1u);
    attach(session);
    EXPECT_TRUE(history.empty());
}

TEST(GuiWatch, ShowsValuesOfEveryType) {
    FakeMemory memory;
    memory.add(kBase, FakeMemory::kPage);
    put<std::int8_t>(memory, kBase, -5);
    put<std::int16_t>(memory, kBase + 0x10, -300);
    put<std::int32_t>(memory, kBase + 0x20, 15000);
    put<std::int64_t>(memory, kBase + 0x30, -1234567890123);
    put<float>(memory, kBase + 0x40, 2.5f);
    put<double>(memory, kBase + 0x50, 0.1);
    write_ascii(memory, kBase + 0x60, std::string_view("Hello\0junk", 10));
    write_utf16(memory, kBase + 0x80, "Hi");
    write_ascii(memory, kBase + 0xA0, "pass");

    WatchList list;
    const WatchEntry entries[] = {
        make_watch_entry(kBase, WatchType::Int8),           make_watch_entry(kBase + 0x10, WatchType::Int16),
        make_watch_entry(kBase + 0x20, WatchType::Int32),   make_watch_entry(kBase + 0x30, WatchType::Int64),
        make_watch_entry(kBase + 0x40, WatchType::Float),   make_watch_entry(kBase + 0x50, WatchType::Double),
        make_watch_entry(kBase + 0x60, WatchType::Ascii, 10), make_watch_entry(kBase + 0x80, WatchType::Utf16, 2),
        make_watch_entry(kBase + 0xA0, WatchType::Bytes, 4),
    };
    for (const WatchEntry& entry : entries) {
        EXPECT_TRUE(list.add(entry));
    }
    ASSERT_EQ(list.rows().size(), std::size(entries));
    EXPECT_EQ(list.value_text(0), "");
    list.refresh(memory, 0, list.rows().size(), {});
    const char* expected[] = {"-5", "-300", "15000", "-1234567890123", "2.5", "0.1", "Hello", "Hi", "70 61 73 73"};
    for (std::size_t row = 0; row < std::size(expected); ++row) {
        EXPECT_EQ(list.value_text(row), expected[row]) << row;
    }
    EXPECT_EQ(type_label(list.rows()[2]), "int32");
    EXPECT_EQ(type_label(list.rows()[6]), "ASCII, 10 символов");
    EXPECT_EQ(type_label(list.rows()[7]), "UTF-16, 2 символа");
    EXPECT_EQ(type_label(list.rows()[8]), "4 байта");
    EXPECT_EQ(list.rows()[3].size(), 8u);
    EXPECT_EQ(list.rows()[7].size(), 4u);
    EXPECT_EQ(to_string(WatchType::Utf16), "utf16");
}

TEST(GuiWatch, UnreadableValuesShowQuestionMarks) {
    FakeMemory memory;
    memory.add(kBase, 2 * FakeMemory::kPage);
    memory.fail_page(kBase + FakeMemory::kPage);
    WatchList list;
    list.add(make_watch_entry(kBase + FakeMemory::kPage - 2, WatchType::Int32));
    list.add(make_watch_entry(0x500000, WatchType::Bytes, 8));
    list.add(make_watch_entry(kBase, WatchType::Int32));
    list.refresh(memory, 0, 3, {});
    EXPECT_EQ(list.value_text(0), "??");
    EXPECT_EQ(list.value_text(1), "??");
    EXPECT_EQ(list.value_text(2), "0");
    EXPECT_FALSE(list.readable(0));
    EXPECT_TRUE(list.readable(2));
    EXPECT_FALSE(read_watch_value(memory, list.rows()[0]).has_value());
    const auto bytes = read_watch_value(memory, list.rows()[2]);
    ASSERT_TRUE(bytes.has_value());
    EXPECT_EQ(bytes->size(), 4u);
}

TEST(GuiWatch, SameAddressAndTypeIsNotAddedTwice) {
    WatchList list;
    EXPECT_TRUE(list.add(make_watch_entry(kBase, WatchType::Int32, 0, "здоровье")));
    EXPECT_TRUE(list.add(make_watch_entry(kBase + 4, WatchType::Int32)));
    EXPECT_EQ(list.selected_row(), 1u);
    EXPECT_FALSE(list.add(make_watch_entry(kBase, WatchType::Int32)));
    EXPECT_EQ(list.rows().size(), 2u);
    EXPECT_EQ(list.selected_row(), 0u);
    EXPECT_EQ(list.rows()[0].description, "здоровье");
    EXPECT_TRUE(list.add(make_watch_entry(kBase, WatchType::Float)));
    EXPECT_TRUE(list.add(make_watch_entry(kBase, WatchType::Ascii, 4)));
    EXPECT_TRUE(list.add(make_watch_entry(kBase, WatchType::Ascii, 8)));
    EXPECT_EQ(list.rows().size(), 5u);
    EXPECT_EQ(list.selected_row(), 4u);
}

TEST(GuiWatch, RemovingKeepsTheSelectionInPlace) {
    FakeMemory memory;
    memory.add(kBase, FakeMemory::kPage);
    WatchList list;
    for (std::uint64_t i = 0; i < 4; ++i) {
        put<std::int32_t>(memory, kBase + i * 4, static_cast<std::int32_t>(i * 10));
        list.add(make_watch_entry(kBase + i * 4, WatchType::Int32));
    }
    list.refresh(memory, 0, 4, {});
    list.select_row(1);
    list.remove(1);
    ASSERT_EQ(list.rows().size(), 3u);
    EXPECT_EQ(list.selected()->address, kBase + 8);
    EXPECT_EQ(list.value_text(1), "20");
    list.remove(0);
    EXPECT_EQ(list.selected()->address, kBase + 8);
    EXPECT_EQ(list.value_text(0), "20");
    list.select_row(1);
    list.remove(1);
    EXPECT_EQ(list.selected()->address, kBase + 8);
    list.move_selection(5);
    EXPECT_EQ(list.selected_row(), 0u);
    list.remove(0);
    EXPECT_TRUE(list.empty());
    EXPECT_FALSE(list.selected_row().has_value());
    EXPECT_EQ(list.selected(), nullptr);

    list.add(make_watch_entry(kBase, WatchType::Int32));
    list.clear();
    EXPECT_TRUE(list.empty());
    EXPECT_FALSE(list.selected_row().has_value());
}

TEST(GuiWatch, ChangedValueStaysMarkedForTwoSeconds) {
    FakeMemory memory;
    memory.add(kBase, FakeMemory::kPage);
    put<std::int32_t>(memory, kBase, 100);
    WatchList list;
    list.add(make_watch_entry(kBase, WatchType::Int32));
    const WatchList::Clock::time_point start{};
    list.refresh(memory, 0, 1, start);
    EXPECT_FALSE(list.recently_changed(0, start));
    list.refresh(memory, 0, 1, start + 500ms);
    EXPECT_FALSE(list.recently_changed(0, start + 500ms));

    put<std::int32_t>(memory, kBase, 99);
    const auto changed = start + 1s;
    list.refresh(memory, 0, 1, changed);
    EXPECT_EQ(list.value_text(0), "99");
    EXPECT_TRUE(list.recently_changed(0, changed));
    list.refresh(memory, 0, 1, changed + 1500ms);
    EXPECT_TRUE(list.recently_changed(0, changed + 1999ms));
    EXPECT_FALSE(list.recently_changed(0, changed + 2s));

    memory.fail_page(kBase);
    list.refresh(memory, 0, 1, changed + 3s);
    EXPECT_EQ(list.value_text(0), "??");
    EXPECT_TRUE(list.recently_changed(0, changed + 3s));
}

TEST(GuiWatch, ChangingTheTypeRereadsWithoutMarkingAChange) {
    FakeMemory memory;
    memory.add(kBase, FakeMemory::kPage);
    put<std::int32_t>(memory, kBase, 0x00410041);
    WatchList list;
    list.add(make_watch_entry(kBase, WatchType::Int32));
    const WatchList::Clock::time_point start{};
    list.refresh(memory, 0, 1, start);
    EXPECT_EQ(list.value_text(0), "4259905");

    list.set_type(0, WatchType::Int16, 0);
    EXPECT_EQ(list.value_text(0), "");
    list.refresh(memory, 0, 1, start + 1s);
    EXPECT_EQ(list.value_text(0), "65");
    EXPECT_FALSE(list.recently_changed(0, start + 1s));
    list.set_type(0, WatchType::Utf16, 2);
    list.refresh(memory, 0, 1, start + 2s);
    EXPECT_EQ(list.value_text(0), "AA");

    list.set_type(0, WatchType::Utf16, 1000);
    EXPECT_EQ(list.rows()[0].length, 128u);
    list.set_type(0, WatchType::Bytes, 0);
    EXPECT_EQ(list.rows()[0].length, 1u);
    list.set_type(0, WatchType::Double, 7);
    EXPECT_EQ(list.rows()[0].length, 0u);
    EXPECT_EQ(list.rows()[0].size(), 8u);
    list.set_description(0, "патроны");
    EXPECT_EQ(list.rows()[0].description, "патроны");
}

TEST(GuiWatch, MatchesBecomeTextOrByteEntries) {
    const WatchEntry ascii = watch_entry_for(kBase, PatternKind::Ascii, 8);
    EXPECT_EQ(ascii.address, kBase);
    EXPECT_EQ(ascii.type, WatchType::Ascii);
    EXPECT_EQ(ascii.length, 8u);
    const WatchEntry wide = watch_entry_for(kBase, PatternKind::StringsUtf16, 16);
    EXPECT_EQ(wide.type, WatchType::Utf16);
    EXPECT_EQ(wide.length, 8u);
    EXPECT_EQ(watch_entry_for(kBase, PatternKind::StringsAscii, 5).type, WatchType::Ascii);
    const WatchEntry signature = watch_entry_for(kBase, PatternKind::Signature, 12);
    EXPECT_EQ(signature.type, WatchType::Bytes);
    EXPECT_EQ(signature.length, 12u);
    EXPECT_EQ(watch_entry_for(kBase, PatternKind::Bytes, 4096).length, kMaxWatchBytes);
    EXPECT_EQ(watch_entry_for(kBase, PatternKind::Utf16, 1000).length, kMaxWatchBytes / 2);
    EXPECT_EQ(watch_type(ValueType::Float), WatchType::Float);
    EXPECT_EQ(value_type(WatchType::Int64), ValueType::Int64);
    EXPECT_FALSE(value_type(WatchType::Ascii).has_value());
}

TEST(GuiWatch, AddressesAreTypedInHex) {
    EXPECT_EQ(parse_address("0x7FF6A000"), 0x7FF6A000u);
    EXPECT_EQ(parse_address("  7ff6a000 "), 0x7FF6A000u);
    EXPECT_EQ(parse_address("0X10"), 0x10u);
    EXPECT_EQ(parse_address("FFFFFFFFFFFFFFFF"), ~std::uint64_t{0});
    EXPECT_EQ(parse_address("0x00000000000000001234"), 0x1234u);
    EXPECT_FALSE(parse_address(""));
    EXPECT_FALSE(parse_address("0x"));
    EXPECT_FALSE(parse_address("12 34"));
    EXPECT_FALSE(parse_address("10000000000000000"));
    EXPECT_FALSE(parse_address("-1"));
    EXPECT_FALSE(parse_address("0x1G"));
}

TEST_F(GuiScan, WatchListBelongsToTheProcess) {
    Session session;
    EXPECT_FALSE(session.add_watch(make_watch_entry(kBase, WatchType::Int32)));
    EXPECT_TRUE(session.notice().error);
    EXPECT_TRUE(session.watch().empty());

    attach(session);
    const WatchEntry entry = make_watch_entry(kBase + 0x20010, WatchType::Ascii, 8);
    EXPECT_TRUE(session.add_watch(entry));
    EXPECT_EQ(session.notice().text, format_address(kBase + 0x20010) + " добавлен в список адресов");
    EXPECT_FALSE(session.notice().error);
    EXPECT_FALSE(session.add_watch(entry));
    EXPECT_EQ(session.notice().text, format_address(kBase + 0x20010) + " уже в списке адресов");
    EXPECT_FALSE(session.notice().error);
    ASSERT_EQ(session.watch().rows().size(), 1u);
    ASSERT_NE(session.watch().region(0), nullptr);
    EXPECT_EQ(session.watch().region(0)->type, MemType::Image);

    attach(session);
    EXPECT_EQ(session.watch().rows().size(), 1u);
    session.attach(std::make_unique<FakeTarget>(memory_, 9999));
    EXPECT_TRUE(session.watch().empty());
}

TEST_F(GuiScan, WatchExportReadsTheCurrentValues) {
    put<std::int32_t>(memory_, kBase + 0x3000, 15000);
    Session session;
    attach(session);
    session.add_watch(make_watch_entry(kBase + 0x3000, WatchType::Int32, 0, "деньги, \"золото\""));
    session.add_watch(make_watch_entry(kBase + 0x20010, WatchType::Ascii, 8));
    session.add_watch(make_watch_entry(0x500000, WatchType::Bytes, 2));
    put<std::int32_t>(memory_, kBase + 0x3000, 14000);

    const auto dir = std::filesystem::temp_directory_path() / "memhunter_gui_watch";
    std::filesystem::create_directories(dir);
    const auto read = [](const std::filesystem::path& path) {
        std::ifstream in(path, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    };
    const ProcessSummary& process = session.target()->summary();
    const MemorySource& memory = session.target()->memory();
    export_watch(dir / "watch.json", process, session.watch(), memory);
    const std::string json = read(dir / "watch.json");
    EXPECT_TRUE(json.starts_with("{")) << json;
    EXPECT_TRUE(contains(json, "\"addresses\": [")) << json;
    EXPECT_TRUE(contains(json, "{\"address\": \"" + format_address(kBase + 0x3000) +
                                   "\", \"type\": \"int32\", \"value\": \"14000\", \"description\": \"деньги, \\\"золото\\\"\""))
        << json;
    EXPECT_TRUE(contains(json, "\"type\": \"ascii\", \"length\": 8, \"value\": \"password\"")) << json;
    EXPECT_TRUE(contains(json, "\"type\": \"bytes\", \"length\": 2, \"value\": null")) << json;

    export_watch(dir / "watch.csv", process, session.watch(), memory);
    const std::string csv = read(dir / "watch.csv");
    EXPECT_TRUE(csv.starts_with("address,type,length,value,description,module,pointer\n")) << csv;
    EXPECT_TRUE(contains(csv, format_address(kBase + 0x3000) + ",int32,,14000,\"деньги, \"\"золото\"\"\",,\n")) << csv;
    EXPECT_TRUE(contains(csv, format_address(0x500000) + ",bytes,2,,,,\n")) << csv;

    export_watch(dir / "watch.txt", process, session.watch(), memory);
    const std::string text = read(dir / "watch.txt");
    EXPECT_TRUE(text.starts_with("process fake.exe (pid 4321), 3 addresses\n")) << text;
    EXPECT_TRUE(contains(text, format_address(0x500000) + "  2 байта  ??")) << text;

    EXPECT_THROW(export_watch(dir / "empty.json", process, WatchList{}, memory), Error);
    std::filesystem::remove_all(dir);
}

TEST(GuiPicker, EnterOpensTheOnlyProcessShownWhenThePickedOneIsFilteredOut) {
    const std::vector<ProcessEntry> processes = {{11328, 1, 3, "memhunter_practice.exe"}, {19492, 1, 3, "memhunter_practice.exe"},
                                                 {700, 1, 9, "Notepad.exe"}};

    const auto restarted = matching_processes(processes, "19492");
    ASSERT_EQ(restarted.size(), 1u);
    EXPECT_EQ(picker_choice(restarted, 11328u), 19492u);

    const auto practice = matching_processes(processes, "PRACTICE");
    ASSERT_EQ(practice.size(), 2u);
    EXPECT_EQ(picker_choice(practice, 11328u), 11328u);
    EXPECT_EQ(picker_choice(practice, std::nullopt), std::nullopt);

    EXPECT_EQ(matching_processes(processes, "").size(), 3u);
    EXPECT_EQ(picker_choice(matching_processes(processes, "notepad"), std::nullopt), 700u);
    EXPECT_TRUE(matching_processes(processes, "calc").empty());
}

TEST(GuiErrors, AccessDeniedIsExplained) {
    const std::string text = describe_error(Error(ErrorCode::AccessDenied, "access denied"));
    EXPECT_TRUE(text.starts_with("Нет доступа к процессу")) << text;
    EXPECT_EQ(describe_error(Error(ErrorCode::InvalidPattern, "bad")), "bad");
    EXPECT_THROW(open_process(0xFFFFFFF0u), Error);
}

}  // namespace
}  // namespace mh::gui
