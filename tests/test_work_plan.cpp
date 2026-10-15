#include <gtest/gtest.h>

#include "pipeline/work_plan.hpp"

namespace mh {
namespace {

using Ranges = std::vector<AddressRange>;

Region region(std::uint64_t base, std::uint64_t size, std::uint32_t protect = page::ReadWrite) {
    Region r;
    r.base = base;
    r.size = size;
    r.protect = protect;
    r.state = MemState::Commit;
    r.type = MemType::Private;
    return r;
}

TEST(WorkPlan, MergeIntersectSubtract) {
    EXPECT_EQ(merge_ranges({{30, 40}, {10, 20}, {20, 25}, {35, 50}, {60, 60}}), (Ranges{{10, 25}, {30, 50}}));
    const Ranges a{{0, 100}, {200, 300}};
    const Ranges b{{50, 250}, {290, 400}};
    EXPECT_EQ(intersect_ranges(a, b), (Ranges{{50, 100}, {200, 250}, {290, 300}}));
    EXPECT_EQ(subtract_ranges(a, b), (Ranges{{0, 50}, {250, 290}}));
    EXPECT_EQ(subtract_ranges(a, Ranges{}), a);
    EXPECT_TRUE(subtract_ranges(a, Ranges{{0, 1000}}).empty());
}

TEST(WorkPlan, AdjacentSelectedRegionsFormOneSpan) {
    const std::vector<Region> regions{
        region(0x10000, 0x1000),
        region(0x11000, 0x1000, page::ReadOnly),
        region(0x12000, 0x1000, page::NoAccess),
        region(0x13000, 0x2000),
        region(0x20000, 0x1000),
    };
    const RegionFilter filter;
    EXPECT_EQ(build_spans(regions, filter), (Ranges{{0x10000, 0x12000}, {0x13000, 0x15000}, {0x20000, 0x21000}}));

    RegionFilter clipped;
    clipped.add_include("0x10800-0x14000");
    clipped.add_exclude("0x11000-0x11800");
    EXPECT_EQ(build_spans(regions, clipped), (Ranges{{0x10800, 0x11000}, {0x11800, 0x12000}, {0x13000, 0x14000}}));
}

TEST(WorkPlan, SplitWorkStaysInsideBounds) {
    const Ranges spans{{0x1000, 0x1000 + 10000}};
    const auto work = split_work(whole_span_targets(spans), 4096, 2, 100);
    ASSERT_EQ(work.size(), 3u);
    EXPECT_EQ(work[0].own_begin, 0x1000u);
    EXPECT_EQ(work[0].read_begin, 0x1000u);
    EXPECT_EQ(work[0].read_end, 0x1000u + 4096 + 100);
    EXPECT_EQ(work[1].own_begin, 0x1000u + 4096);
    EXPECT_EQ(work[1].read_begin, 0x1000u + 4096 - 2);
    EXPECT_EQ(work[2].own_end, 0x1000u + 10000);
    EXPECT_EQ(work[2].read_end, 0x1000u + 10000);
    for (std::size_t i = 1; i < work.size(); ++i) {
        EXPECT_EQ(work[i].own_begin, work[i - 1].own_end);
    }
}

TEST(WorkPlan, ChangedRangesReachBackByLookAhead) {
    const Ranges spans{{0x1000, 0x9000}, {0x10000, 0x11000}};
    const Ranges changed{{0x1100, 0x1200}, {0x1250, 0x1300}, {0x8F00, 0x10100}};
    const auto targets = changed_range_targets(spans, changed, 0x80);
    ASSERT_EQ(targets.size(), 3u);
    EXPECT_EQ(targets[0].own_begin, 0x1080u);
    EXPECT_EQ(targets[0].own_end, 0x1300u);
    EXPECT_EQ(targets[0].bound_begin, 0x1000u);
    EXPECT_EQ(targets[0].bound_end, 0x9000u);
    EXPECT_EQ(targets[1].own_begin, 0x8E80u);
    EXPECT_EQ(targets[1].own_end, 0x9000u);
    EXPECT_EQ(targets[2].own_begin, 0x10000u);
    EXPECT_EQ(targets[2].own_end, 0x10100u);
    EXPECT_EQ(targets[2].bound_end, 0x11000u);
}

TEST(WorkPlan, RegionsAreAttributedToTheItemThatScansTheirLastByte) {
    // Regions: [0,100) [100,150) [150,400) [500,600) [700,800), the last one is not scanned at all.
    const std::vector<Region> regions{region(0, 100), region(100, 50), region(150, 250), region(500, 100), region(700, 100)};
    const std::vector<ScanTarget> targets{{0, 400, 0, 400}, {500, 600, 500, 600}};
    auto work = split_work(targets, 120, 0, 0);
    ASSERT_EQ(work.size(), 5u);  // [0,120) [120,240) [240,360) [360,400) [500,600)
    EXPECT_EQ(attribute_regions(regions, work), 4u);
    EXPECT_EQ(work[0].regions_finished, 1u);
    EXPECT_EQ(work[1].regions_finished, 1u);
    EXPECT_EQ(work[2].regions_finished, 0u);
    EXPECT_EQ(work[3].regions_finished, 1u);
    EXPECT_EQ(work[4].regions_finished, 1u);
}

}  // namespace
}  // namespace mh
