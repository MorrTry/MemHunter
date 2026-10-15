#include "memory/region.hpp"

#include <windows.h>

#include <array>

#include "common/error.hpp"
#include "common/text.hpp"

namespace mh {

static_assert(page::NoAccess == PAGE_NOACCESS && page::ReadOnly == PAGE_READONLY && page::ReadWrite == PAGE_READWRITE &&
              page::WriteCopy == PAGE_WRITECOPY && page::Execute == PAGE_EXECUTE &&
              page::ExecuteRead == PAGE_EXECUTE_READ && page::ExecuteReadWrite == PAGE_EXECUTE_READWRITE &&
              page::ExecuteWriteCopy == PAGE_EXECUTE_WRITECOPY && page::Guard == PAGE_GUARD &&
              page::NoCache == PAGE_NOCACHE && page::WriteCombine == PAGE_WRITECOMBINE);

namespace {

std::uint32_t protection_class_of(std::uint32_t protect) noexcept {
    switch (protect & 0xFF) {
        case page::ReadOnly: return protection_class::ReadOnly;
        case page::ReadWrite: return protection_class::ReadWrite;
        case page::WriteCopy: return protection_class::WriteCopy;
        case page::Execute: return protection_class::Execute;
        case page::ExecuteRead: return protection_class::ExecuteRead;
        case page::ExecuteReadWrite: return protection_class::ExecuteReadWrite;
        case page::ExecuteWriteCopy: return protection_class::ExecuteWriteCopy;
        default: return 0;
    }
}

std::uint32_t type_class_of(MemType type) noexcept {
    switch (type) {
        case MemType::Image: return type_class::Image;
        case MemType::Mapped: return type_class::Mapped;
        case MemType::Private: return type_class::Private;
        case MemType::None: return 0;
    }
    return 0;
}

template <std::size_t N>
std::uint32_t parse_flag_list(std::string_view list, const std::array<std::pair<std::string_view, std::uint32_t>, N>& names,
                              std::string_view what) {
    std::uint32_t mask = 0;
    while (!list.empty()) {
        const auto comma = list.find(',');
        const std::string item = to_lower_ascii(list.substr(0, comma));
        list = comma == std::string_view::npos ? std::string_view{} : list.substr(comma + 1);
        if (item.empty()) {
            continue;
        }
        bool known = false;
        for (const auto& [name, bits] : names) {
            if (item == name) {
                mask |= bits;
                known = true;
                break;
            }
        }
        if (!known) {
            std::string valid;
            for (const auto& entry : names) {
                valid += (valid.empty() ? "" : ", ") + std::string(entry.first);
            }
            throw Error(ErrorCode::InvalidArgument, "unknown " + std::string(what) + " '" + item + "'; expected one of: " + valid);
        }
    }
    if (mask == 0) {
        throw Error(ErrorCode::InvalidArgument, "empty " + std::string(what) + " list");
    }
    return mask;
}

bool is_range_spec(std::string_view spec) {
    return spec.size() > 2 && spec[0] == '0' && (spec[1] == 'x' || spec[1] == 'X') && spec.find('-') != std::string_view::npos;
}

AddressRange require_range(std::string_view spec) {
    const auto range = parse_address_range(spec);
    if (!range) {
        throw Error(ErrorCode::InvalidArgument,
                    "invalid address range '" + std::string(spec) + "'; expected 0xSTART-0xEND with START < END");
    }
    return *range;
}

}  // namespace

bool is_readable_protection(std::uint32_t protect) noexcept {
    if ((protect & page::Guard) != 0) {
        return false;
    }
    return (protection_class_of(protect) & protection_class::Readable) != 0;
}

bool Region::readable() const noexcept {
    return state == MemState::Commit && is_readable_protection(protect);
}

std::string Region::module_name() const {
    const auto slash = mapped_file.find_last_of("\\/");
    return slash == std::string::npos ? mapped_file : mapped_file.substr(slash + 1);
}

std::string protection_to_string(std::uint32_t protect) {
    std::string text;
    switch (protect & 0xFF) {
        case 0: return "?";
        case page::NoAccess: text = "---"; break;
        case page::ReadOnly: text = "r--"; break;
        case page::ReadWrite: text = "rw-"; break;
        case page::WriteCopy: text = "rc-"; break;
        case page::Execute: text = "--x"; break;
        case page::ExecuteRead: text = "r-x"; break;
        case page::ExecuteReadWrite: text = "rwx"; break;
        case page::ExecuteWriteCopy: text = "rcx"; break;
        default: text = format_hex(protect & 0xFF); break;
    }
    if ((protect & page::Guard) != 0) text += " guard";
    if ((protect & page::NoCache) != 0) text += " nocache";
    if ((protect & page::WriteCombine) != 0) text += " wcomb";
    return text;
}

std::string_view to_string(MemState state) {
    switch (state) {
        case MemState::Free: return "free";
        case MemState::Reserve: return "reserve";
        case MemState::Commit: return "commit";
    }
    return "?";
}

std::string_view to_string(MemType type) {
    switch (type) {
        case MemType::None: return "-";
        case MemType::Image: return "image";
        case MemType::Mapped: return "mapped";
        case MemType::Private: return "private";
    }
    return "?";
}

bool RegionFilter::accepts(const Region& region) const {
    // Execute-only pages are not readable through ReadProcessMemory, so "--protection x" selects nothing.
    if (!region.readable() || (protection_class_of(region.protect) & protections) == 0) {
        return false;
    }
    return accepts_any_protection(region);
}

bool RegionFilter::accepts_any_protection(const Region& region) const {
    if ((type_class_of(region.type) & types) == 0) {
        return false;
    }
    if (region.size < min_size || region.size > max_size) {
        return false;
    }
    if (!include_modules.empty() || !exclude_modules.empty()) {
        const std::string module = region.module_name();
        if (!include_modules.empty()) {
            bool included = false;
            for (const auto& glob : include_modules) {
                if (!module.empty() && glob_match_ci(glob, module)) {
                    included = true;
                    break;
                }
            }
            if (!included) {
                return false;
            }
        }
        for (const auto& glob : exclude_modules) {
            if (!module.empty() && glob_match_ci(glob, module)) {
                return false;
            }
        }
    }
    return true;
}

void RegionFilter::add_include(std::string_view spec) {
    if (is_range_spec(spec)) {
        include_ranges.push_back(require_range(spec));
    } else if (!spec.empty()) {
        include_modules.emplace_back(spec);
    }
}

void RegionFilter::add_exclude(std::string_view spec) {
    if (is_range_spec(spec)) {
        exclude_ranges.push_back(require_range(spec));
    } else if (!spec.empty()) {
        exclude_modules.emplace_back(spec);
    }
}

std::uint32_t parse_protection_list(std::string_view list) {
    using namespace protection_class;
    static constexpr std::array<std::pair<std::string_view, std::uint32_t>, 17> names{{
        {"r", ReadOnly},
        {"readonly", ReadOnly},
        {"rw", ReadWrite},
        {"readwrite", ReadWrite},
        {"wc", WriteCopy},
        {"writecopy", WriteCopy},
        {"x", Execute},
        {"execute", Execute},
        {"rx", ExecuteRead},
        {"execute-read", ExecuteRead},
        {"rwx", ExecuteReadWrite},
        {"execute-readwrite", ExecuteReadWrite},
        {"wcx", ExecuteWriteCopy},
        {"execute-writecopy", ExecuteWriteCopy},
        {"writable", ReadWrite | WriteCopy | ExecuteReadWrite | ExecuteWriteCopy},
        {"executable", Execute | ExecuteRead | ExecuteReadWrite | ExecuteWriteCopy},
        {"readable", Readable},
    }};
    return parse_flag_list(list, names, "protection");
}

std::uint32_t parse_type_list(std::string_view list) {
    static constexpr std::array<std::pair<std::string_view, std::uint32_t>, 4> names{{
        {"image", type_class::Image},
        {"mapped", type_class::Mapped},
        {"private", type_class::Private},
        {"all", type_class::All},
    }};
    return parse_flag_list(list, names, "memory type");
}

std::optional<AddressRange> parse_address_range(std::string_view text) {
    const auto dash = text.find('-');
    if (dash == std::string_view::npos) {
        return std::nullopt;
    }
    const auto begin = parse_uint(text.substr(0, dash));
    const auto end = parse_uint(text.substr(dash + 1));
    if (!begin || !end || *begin >= *end) {
        return std::nullopt;
    }
    return AddressRange{*begin, *end};
}

}  // namespace mh
