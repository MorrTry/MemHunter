#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <string>
#include <thread>

#include "gui/finding_list.hpp"
#include "gui/results_table.hpp"
#include "gui/session.hpp"
#include "support/fake_memory.hpp"
#include "support/fake_target.hpp"
#include "support/language_guard.hpp"

namespace mh::gui {
namespace {

using mh::testing::FakeMemory;
using mh::testing::FakeTarget;
using mh::testing::LanguageGuard;
using namespace std::chrono_literals;

// A process without modules: the inspection looks only at its memory.
class NoModules final : public InspectFacts {
public:
    std::optional<std::uint64_t> main_image() const override { return std::nullopt; }
    std::string main_path() const override { return {}; }
    std::vector<bool> shared_pages(std::uint64_t, std::size_t pages) const override { return std::vector<bool>(pages, false); }
    OpenedFile open_image(const std::string& path) const override { return {nullptr, "cannot open " + path}; }
    bool file_exists(const std::string&) const override { return true; }
    bool same_file(const std::string& a, const std::string& b) const override { return a == b; }
};

Finding finding(FindingKind kind, std::uint64_t address) {
    return {.kind = kind, .address = address, .size = 0x1000, .where = {}, .details = {}};
}

// Executable private memory at 0x10000 and RWX memory at 0x20000.
InspectReport three_findings() {
    InspectReport report;
    report.findings = {finding(FindingKind::ExecPrivate, 0x10000), finding(FindingKind::ExecPrivate, 0x20000),
                       finding(FindingKind::Rwx, 0x20000)};
    return report;
}

TEST(GuiFindings, CountsInRussian) {
    LanguageGuard ru{Lang::Russian};
    EXPECT_EQ(count_findings(0), "0 находок");
    EXPECT_EQ(count_findings(1), "1 находка");
    EXPECT_EQ(count_findings(3), "3 находки");
    EXPECT_EQ(count_findings(5), "5 находок");
    EXPECT_EQ(count_findings(11), "11 находок");
    EXPECT_EQ(count_findings(14), "14 находок");
    EXPECT_EQ(count_findings(21), "21 находка");
    EXPECT_EQ(count_findings(112), "112 находок");
    EXPECT_EQ(count_findings(1002), group_digits(1002) + " находки");
}

TEST(GuiFindings, ListSelectsTheFirstFinding) {
    FindingList list;
    EXPECT_FALSE(list.has_report());
    EXPECT_TRUE(list.rows().empty());
    EXPECT_EQ(list.selected(), nullptr);

    list.assign(three_findings());
    ASSERT_TRUE(list.has_report());
    ASSERT_EQ(list.rows().size(), 3u);
    ASSERT_NE(list.selected(), nullptr);
    EXPECT_EQ(list.selected()->address, 0x10000u);

    list.move_selection(10);
    EXPECT_EQ(list.selected_row(), 2u);
    list.move_selection(-1);
    EXPECT_EQ(list.selected_row(), 1u);
    list.select_row(7);
    EXPECT_EQ(list.selected_row(), 1u);

    list.assign(InspectReport{});
    EXPECT_TRUE(list.has_report());
    EXPECT_TRUE(list.rows().empty());
    EXPECT_EQ(list.selected(), nullptr);
    list.clear();
    EXPECT_FALSE(list.has_report());
}

TEST(GuiFindings, HiddenKindsKeepTheSelectionOnItsFinding) {
    FindingList list;
    list.assign(three_findings());
    list.select_row(2);

    list.toggle(FindingKind::ExecPrivate);
    EXPECT_FALSE(list.shows(FindingKind::ExecPrivate));
    ASSERT_EQ(list.rows().size(), 1u);
    EXPECT_EQ(list.selected_row(), 0u);
    EXPECT_EQ(list.selected()->kind, FindingKind::Rwx);

    list.toggle(FindingKind::Rwx);
    EXPECT_TRUE(list.rows().empty());
    EXPECT_EQ(list.selected(), nullptr);
    list.toggle(FindingKind::Rwx);
    ASSERT_EQ(list.rows().size(), 1u);
    EXPECT_EQ(list.selected(), nullptr);
    list.move_selection(1);
    EXPECT_EQ(list.selected_row(), 0u);

    // The next inspection shows the same kinds.
    list.assign(three_findings());
    ASSERT_EQ(list.rows().size(), 1u);
    EXPECT_EQ(list.finding(0).kind, FindingKind::Rwx);
    EXPECT_EQ(list.report().findings.size(), 3u);
    list.toggle(FindingKind::ExecPrivate);
    EXPECT_EQ(list.rows().size(), 3u);
    EXPECT_EQ(list.selected()->kind, FindingKind::Rwx);
}

class GuiInspect : public ::testing::Test {
protected:
    GuiInspect() {
        memory_.add(0x10000, 0x2000, page::ExecuteRead);
        memory_.add(0x20000, 0x1000, page::ExecuteReadWrite);
        memory_.add(0x30000, 0x1000, page::ReadWrite);
    }

    void wait(Session& session) {
        const auto deadline = std::chrono::steady_clock::now() + 10s;
        while (!session.poll()) {
            ASSERT_LT(std::chrono::steady_clock::now(), deadline);
            std::this_thread::sleep_for(2ms);
        }
    }

    // These tests check the Russian wording of the report, so pin the language.
    LanguageGuard language_{Lang::Russian};
    FakeMemory memory_;
    NoModules facts_;
};

TEST_F(GuiInspect, ListsWhatTheInspectionFound) {
    Session session;
    EXPECT_FALSE(session.start_inspect());
    EXPECT_TRUE(session.notice().error);

    session.attach(std::make_unique<FakeTarget>(memory_, 100, "game.exe", &facts_));
    ASSERT_TRUE(session.start_inspect());
    EXPECT_TRUE(session.busy());
    EXPECT_EQ(session.job()->kind(), JobKind::Inspect);
    EXPECT_FALSE(session.start_inspect());
    wait(session);

    const FindingList& findings = session.findings();
    ASSERT_TRUE(findings.has_report());
    ASSERT_EQ(findings.rows().size(), 3u);
    EXPECT_EQ(findings.finding(0).kind, FindingKind::ExecPrivate);
    EXPECT_EQ(findings.finding(0).address, 0x10000u);
    EXPECT_EQ(findings.finding(0).size, 0x2000u);
    EXPECT_EQ(findings.finding(2).kind, FindingKind::Rwx);
    EXPECT_EQ(findings.selected_row(), 0u);
    ASSERT_EQ(findings.report().warnings.size(), 1u);
    EXPECT_TRUE(session.notice().text.starts_with("Проверка за ")) << session.notice().text;
    EXPECT_TRUE(session.notice().text.ends_with(": 3 находки")) << session.notice().text;
    EXPECT_FALSE(session.notice().error);

    session.attach(std::make_unique<FakeTarget>(memory_, 100, "game.exe", &facts_));
    EXPECT_FALSE(session.findings().has_report());
}

TEST_F(GuiInspect, SaysWhenNothingWasFound) {
    FakeMemory clean;
    clean.add(0x30000, 0x1000, page::ReadWrite);
    Session session;
    session.attach(std::make_unique<FakeTarget>(clean, 100, "game.exe", &facts_));
    ASSERT_TRUE(session.start_inspect());
    wait(session);
    ASSERT_TRUE(session.findings().has_report());
    EXPECT_TRUE(session.findings().rows().empty());
    EXPECT_TRUE(session.notice().text.ends_with(": ничего подозрительного не найдено")) << session.notice().text;
    EXPECT_FALSE(session.notice().error);
}

TEST_F(GuiInspect, SaysWhenTheTargetCannotBeInspected) {
    Session session;
    session.attach(std::make_unique<FakeTarget>(memory_, 100, "game.exe"));
    ASSERT_TRUE(session.start_inspect());
    wait(session);
    EXPECT_FALSE(session.findings().has_report());
    EXPECT_EQ(session.notice().text, "Этот процесс нельзя проверить");
    EXPECT_TRUE(session.notice().error);
}

}  // namespace
}  // namespace mh::gui
