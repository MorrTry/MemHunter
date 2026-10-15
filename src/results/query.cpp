#include "results/query.hpp"

#include <algorithm>
#include <tuple>

#include "common/text.hpp"

namespace mh {

std::optional<SortKey> parse_sort_key(std::string_view text) {
    for (const auto key : {SortKey::Address, SortKey::Pattern, SortKey::Kind, SortKey::Length, SortKey::Region}) {
        if (iequals_ascii(text, to_string(key))) {
            return key;
        }
    }
    return std::nullopt;
}

std::string_view to_string(SortKey key) {
    switch (key) {
        case SortKey::Address: return "address";
        case SortKey::Pattern: return "pattern";
        case SortKey::Kind: return "kind";
        case SortKey::Length: return "length";
        case SortKey::Region: return "region";
    }
    return "?";
}

std::vector<std::size_t> run_query(const ResultSet& results, const MatchQuery& query) {
    const std::string needle = to_lower_ascii(query.text);
    const auto kind_of = [&](const Match& m) {
        return m.pattern < results.patterns.size() ? results.patterns[m.pattern].kind : PatternKind::Bytes;
    };

    std::vector<std::size_t> rows;
    rows.reserve(results.matches.size());
    for (std::size_t i = 0; i < results.matches.size(); ++i) {
        const Match& match = results.matches[i];
        if (!query.address_ranges.empty() &&
            std::none_of(query.address_ranges.begin(), query.address_ranges.end(),
                         [&](const AddressRange& r) { return r.contains(match.address); })) {
            continue;
        }
        if (!query.kinds.empty() && std::find(query.kinds.begin(), query.kinds.end(), kind_of(match)) == query.kinds.end()) {
            continue;
        }
        if (!query.patterns.empty() && std::find(query.patterns.begin(), query.patterns.end(), match.pattern) == query.patterns.end()) {
            continue;
        }
        if (!needle.empty() && to_lower_ascii(results.preview_text(match)).find(needle) == std::string::npos) {
            continue;
        }
        rows.push_back(i);
    }

    const auto primary = [&](const Match& m) -> std::uint64_t {
        switch (query.sort) {
            case SortKey::Address: return m.address;
            case SortKey::Pattern: return m.pattern;
            case SortKey::Kind: return static_cast<std::uint64_t>(kind_of(m));
            case SortKey::Length: return m.length;
            case SortKey::Region: return m.region;
        }
        return m.address;
    };
    std::stable_sort(rows.begin(), rows.end(), [&](std::size_t a, std::size_t b) {
        const Match& x = results.matches[a];
        const Match& y = results.matches[b];
        const auto px = primary(x);
        const auto py = primary(y);
        if (px != py) {
            return query.descending ? px > py : px < py;
        }
        return std::tuple(x.address, x.pattern) < std::tuple(y.address, y.pattern);
    });

    if (query.limit != 0 && rows.size() > query.limit) {
        rows.resize(query.limit);
    }
    return rows;
}

std::vector<std::uint32_t> patterns_with_label(const ResultSet& results, std::string_view label) {
    std::vector<std::uint32_t> ids;
    for (std::uint32_t i = 0; i < results.patterns.size(); ++i) {
        if (results.patterns[i].label == label) {
            ids.push_back(i);
        }
    }
    return ids;
}

}  // namespace mh
