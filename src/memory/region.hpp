#pragma once

#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace mh {

enum class MemState : std::uint8_t { Free, Reserve, Commit };
enum class MemType : std::uint8_t { None, Image, Mapped, Private };

// Mirrors of the Windows PAGE_* constants so that headers stay free of <windows.h>.
namespace page {
inline constexpr std::uint32_t NoAccess = 0x01;
inline constexpr std::uint32_t ReadOnly = 0x02;
inline constexpr std::uint32_t ReadWrite = 0x04;
inline constexpr std::uint32_t WriteCopy = 0x08;
inline constexpr std::uint32_t Execute = 0x10;
inline constexpr std::uint32_t ExecuteRead = 0x20;
inline constexpr std::uint32_t ExecuteReadWrite = 0x40;
inline constexpr std::uint32_t ExecuteWriteCopy = 0x80;
inline constexpr std::uint32_t Guard = 0x100;
inline constexpr std::uint32_t NoCache = 0x200;
inline constexpr std::uint32_t WriteCombine = 0x400;
}  // namespace page

struct Region {
    std::uint64_t base = 0;
    std::uint64_t size = 0;
    std::uint64_t allocation_base = 0;
    std::uint32_t protect = 0;
    std::uint32_t allocation_protect = 0;
    MemState state = MemState::Free;
    MemType type = MemType::None;
    std::string mapped_file;

    std::uint64_t end() const noexcept { return base + size; }
    bool readable() const noexcept;
    std::string module_name() const;
};

struct AddressRange {
    std::uint64_t begin = 0;
    std::uint64_t end = 0;

    bool contains(std::uint64_t address) const noexcept { return address >= begin && address < end; }

    friend bool operator==(const AddressRange&, const AddressRange&) = default;
};

bool is_readable_protection(std::uint32_t protect) noexcept;
std::string protection_to_string(std::uint32_t protect);
std::string_view to_string(MemState state);
std::string_view to_string(MemType type);

namespace protection_class {
inline constexpr std::uint32_t ReadOnly = 1u << 0;
inline constexpr std::uint32_t ReadWrite = 1u << 1;
inline constexpr std::uint32_t WriteCopy = 1u << 2;
inline constexpr std::uint32_t Execute = 1u << 3;
inline constexpr std::uint32_t ExecuteRead = 1u << 4;
inline constexpr std::uint32_t ExecuteReadWrite = 1u << 5;
inline constexpr std::uint32_t ExecuteWriteCopy = 1u << 6;
inline constexpr std::uint32_t Readable = ReadOnly | ReadWrite | WriteCopy | ExecuteRead | ExecuteReadWrite | ExecuteWriteCopy;
}  // namespace protection_class

namespace type_class {
inline constexpr std::uint32_t Image = 1u << 0;
inline constexpr std::uint32_t Mapped = 1u << 1;
inline constexpr std::uint32_t Private = 1u << 2;
inline constexpr std::uint32_t All = Image | Mapped | Private;
}  // namespace type_class

struct RegionFilter {
    std::uint32_t protections = protection_class::Readable;
    std::uint32_t types = type_class::All;
    std::uint64_t min_size = 0;
    std::uint64_t max_size = std::numeric_limits<std::uint64_t>::max();
    std::vector<AddressRange> include_ranges;
    std::vector<AddressRange> exclude_ranges;
    std::vector<std::string> include_modules;
    std::vector<std::string> exclude_modules;

    // Region-level checks only; address ranges are applied when the work plan clips spans.
    bool accepts(const Region& region) const;
    // The same without readability and protection, for a listing of every allocated region.
    bool accepts_any_protection(const Region& region) const;

    // "0x1000-0x2000" selects an address range, anything else is a module/file name glob.
    void add_include(std::string_view spec);
    void add_exclude(std::string_view spec);
};

std::uint32_t parse_protection_list(std::string_view list);
std::uint32_t parse_type_list(std::string_view list);
std::optional<AddressRange> parse_address_range(std::string_view text);

}  // namespace mh
