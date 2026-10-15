#include <gtest/gtest.h>

#include "common/error.hpp"
#include "memory/region.hpp"

namespace mh {
namespace {

Region make_region(std::uint32_t protect, MemType type = MemType::Private, std::uint64_t size = 0x1000,
                   MemState state = MemState::Commit) {
    Region region;
    region.base = 0x10000;
    region.size = size;
    region.protect = protect;
    region.state = state;
    region.type = type;
    return region;
}

TEST(Region, ProtectionStrings) {
    EXPECT_EQ(protection_to_string(page::ReadWrite), "rw-");
    EXPECT_EQ(protection_to_string(page::ExecuteRead), "r-x");
    EXPECT_EQ(protection_to_string(page::ReadWrite | page::Guard), "rw- guard");
    EXPECT_EQ(protection_to_string(page::NoAccess), "---");
}

TEST(Region, Readability) {
    EXPECT_TRUE(make_region(page::ReadOnly).readable());
    EXPECT_TRUE(make_region(page::ExecuteWriteCopy).readable());
    EXPECT_FALSE(make_region(page::Execute).readable());
    EXPECT_FALSE(make_region(page::NoAccess).readable());
    EXPECT_FALSE(make_region(page::ReadWrite | page::Guard).readable());
    EXPECT_FALSE(make_region(page::ReadWrite, MemType::Private, 0x1000, MemState::Reserve).readable());
}

TEST(RegionFilter, DefaultSelectsReadableCommittedMemory) {
    const RegionFilter filter;
    EXPECT_TRUE(filter.accepts(make_region(page::ReadWrite)));
    EXPECT_TRUE(filter.accepts(make_region(page::ExecuteRead, MemType::Image)));
    EXPECT_FALSE(filter.accepts(make_region(page::ReadWrite | page::Guard)));
    EXPECT_FALSE(filter.accepts(make_region(page::NoAccess)));
    EXPECT_FALSE(filter.accepts(make_region(page::Execute)));
}

TEST(RegionFilter, ProtectionTypeAndSize) {
    RegionFilter filter;
    filter.protections = parse_protection_list("readwrite");
    filter.types = parse_type_list("private,mapped");
    filter.min_size = 0x2000;
    filter.max_size = 0x10000;
    EXPECT_TRUE(filter.accepts(make_region(page::ReadWrite, MemType::Private, 0x2000)));
    EXPECT_FALSE(filter.accepts(make_region(page::ReadOnly, MemType::Private, 0x2000)));
    EXPECT_FALSE(filter.accepts(make_region(page::ReadWrite, MemType::Image, 0x2000)));
    EXPECT_FALSE(filter.accepts(make_region(page::ReadWrite, MemType::Private, 0x1000)));
    EXPECT_FALSE(filter.accepts(make_region(page::ReadWrite, MemType::Private, 0x11000)));
}

TEST(RegionFilter, AnyProtectionKeepsTheOtherChecks) {
    RegionFilter filter;
    filter.types = parse_type_list("private");
    filter.min_size = 0x2000;
    EXPECT_TRUE(filter.accepts_any_protection(make_region(page::NoAccess, MemType::Private, 0x2000)));
    EXPECT_TRUE(filter.accepts_any_protection(make_region(0, MemType::Private, 0x4000, MemState::Reserve)));
    EXPECT_FALSE(filter.accepts(make_region(page::NoAccess, MemType::Private, 0x2000)));
    EXPECT_FALSE(filter.accepts_any_protection(make_region(page::NoAccess, MemType::Image, 0x2000)));
    EXPECT_FALSE(filter.accepts_any_protection(make_region(page::NoAccess, MemType::Private, 0x1000)));
}

TEST(RegionFilter, WritableGroup) {
    const auto mask = parse_protection_list("writable");
    EXPECT_NE(mask & protection_class::ReadWrite, 0u);
    EXPECT_NE(mask & protection_class::ExecuteWriteCopy, 0u);
    EXPECT_EQ(mask & protection_class::ReadOnly, 0u);
    EXPECT_THROW(parse_protection_list("rw,bogus"), Error);
    EXPECT_THROW(parse_type_list(""), Error);
}

TEST(RegionFilter, ModuleGlobs) {
    RegionFilter filter;
    filter.add_include("game*.dll");
    filter.add_exclude("0x1000-0x2000");
    Region region = make_region(page::ReadOnly, MemType::Image);
    region.mapped_file = "C:\\Games\\GameCore.dll";
    EXPECT_TRUE(filter.accepts(region));
    region.mapped_file = "C:\\Windows\\System32\\kernel32.dll";
    EXPECT_FALSE(filter.accepts(region));
    region.mapped_file.clear();
    EXPECT_FALSE(filter.accepts(region));
    ASSERT_EQ(filter.exclude_ranges.size(), 1u);
    EXPECT_EQ(filter.exclude_ranges[0].begin, 0x1000u);

    RegionFilter excluding;
    excluding.add_exclude("ntdll.dll");
    region.mapped_file = "C:\\Windows\\System32\\NTDLL.DLL";
    EXPECT_FALSE(excluding.accepts(region));
}

TEST(AddressRange, Parse) {
    const auto range = parse_address_range("0x1000-0x2000");
    ASSERT_TRUE(range);
    EXPECT_EQ(range->begin, 0x1000u);
    EXPECT_EQ(range->end, 0x2000u);
    EXPECT_FALSE(parse_address_range("0x2000-0x1000"));
    EXPECT_FALSE(parse_address_range("0x2000"));
    EXPECT_FALSE(parse_address_range("abc-def"));
    RegionFilter filter;
    EXPECT_THROW(filter.add_include("0x2000-0x1000"), Error);
}

}  // namespace
}  // namespace mh
