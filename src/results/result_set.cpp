#include "results/result_set.hpp"

#include <algorithm>
#include <tuple>

#include "common/text.hpp"

namespace mh {

std::string_view to_string(ScanStatus status) {
    switch (status) {
        case ScanStatus::Completed: return "completed";
        case ScanStatus::Cancelled: return "cancelled";
        case ScanStatus::TargetExited: return "target-exited";
    }
    return "?";
}

std::span<const std::byte> ResultSet::preview(const Match& match) const {
    if (match.preview_size == 0 || match.preview_offset + match.preview_size > previews.size()) {
        return {};
    }
    return std::span<const std::byte>(previews).subspan(match.preview_offset, match.preview_size);
}

const Region* ResultSet::region_of(const Match& match) const {
    return match.region < regions.size() ? &regions[match.region] : nullptr;
}

std::string ResultSet::preview_text(const Match& match) const {
    const auto bytes = preview(match);
    const PatternKind kind = match.pattern < patterns.size() ? patterns[match.pattern].kind : PatternKind::Bytes;
    return is_utf16_kind(kind) ? utf16_preview(bytes) : ascii_preview(bytes);
}

std::string ResultSet::preview_hex(const Match& match) const {
    return hex_preview(preview(match));
}

void normalize(ResultSet& results) {
    auto& matches = results.matches;
    const auto key = [](const Match& m) { return std::tuple(m.address, m.pattern, m.length); };
    std::sort(matches.begin(), matches.end(), [&](const Match& a, const Match& b) { return key(a) < key(b); });
    matches.erase(std::unique(matches.begin(), matches.end(), [&](const Match& a, const Match& b) { return key(a) == key(b); }),
                  matches.end());

    std::sort(results.regions.begin(), results.regions.end(), [](const Region& a, const Region& b) { return a.base < b.base; });
    std::size_t region = 0;
    for (auto& match : matches) {
        while (region < results.regions.size() && results.regions[region].end() <= match.address) {
            ++region;
        }
        const bool inside = region < results.regions.size() && results.regions[region].base <= match.address;
        match.region = inside ? static_cast<std::uint32_t>(region) : kNoRegion;
    }
}

}  // namespace mh
