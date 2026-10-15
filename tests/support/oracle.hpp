#pragma once

#include <algorithm>
#include <cstdint>
#include <optional>
#include <span>
#include <tuple>
#include <vector>

#include "pattern/pattern.hpp"
#include "pipeline/work_plan.hpp"
#include "results/result_set.hpp"
#include "scanner/matchers.hpp"
#include "support/fake_memory.hpp"

namespace mh::testing {

using Found = std::tuple<std::uint64_t, std::uint32_t, std::uint32_t>;

inline std::vector<Found> found_of(const ResultSet& results) {
    std::vector<Found> out;
    out.reserve(results.matches.size());
    for (const auto& m : results.matches) {
        out.emplace_back(m.address, m.pattern, m.length);
    }
    return out;
}

inline std::vector<Found> brute_force(std::span<const std::uint8_t> data, std::uint64_t base, std::span<const Pattern> patterns) {
    std::vector<Found> out;
    for (std::uint32_t p = 0; p < patterns.size(); ++p) {
        const auto& pattern = patterns[p];
        if (pattern.size() == 0 || data.size() < pattern.size()) {
            continue;
        }
        for (std::size_t i = 0; i + pattern.size() <= data.size(); ++i) {
            if (pattern.matches(data.data() + i)) {
                out.emplace_back(base + i, p, static_cast<std::uint32_t>(pattern.size()));
            }
        }
    }
    return out;
}

// Expected scan result computed without chunking: every maximal run of readable bytes inside the selected
// spans is searched as one buffer. Matches may cross region boundaries but never unreadable pages or gaps.
inline std::vector<Found> reference_scan(const FakeMemory& memory, const RegionFilter& filter, std::span<const Pattern> patterns,
                                         const std::optional<StringOptions>& strings = std::nullopt,
                                         StringIds string_ids = {}) {
    const auto spans = build_spans(memory.query_regions(), filter);
    std::vector<Found> out;
    std::vector<std::uint8_t> buffer;
    const auto flush = [&](std::uint64_t base) {
        auto found = brute_force(buffer, base, patterns);
        out.insert(out.end(), found.begin(), found.end());
        if (strings) {
            StringExtractor extractor(*strings, string_ids.ascii, string_ids.utf16);
            std::vector<Hit> hits;
            extractor.scan(std::as_bytes(std::span<const std::uint8_t>(buffer)), base, 0, buffer.size(), hits);
            for (const auto& hit : hits) {
                out.emplace_back(base + hit.offset, hit.pattern, hit.length);
            }
        }
        buffer.clear();
    };
    for (const auto& span : spans) {
        std::uint64_t run_base = span.begin;
        for (std::uint64_t address = span.begin; address < span.end;) {
            const std::uint64_t page_end = std::min<std::uint64_t>(span.end, (address / FakeMemory::kPage + 1) * FakeMemory::kPage);
            if (memory.page_readable(address)) {
                if (buffer.empty()) {
                    run_base = address;
                }
                const auto bytes = memory.view(address, page_end - address);
                for (const auto b : bytes) {
                    buffer.push_back(static_cast<std::uint8_t>(b));
                }
            } else if (!buffer.empty()) {
                flush(run_base);
            }
            address = page_end;
        }
        if (!buffer.empty()) {
            flush(run_base);
        }
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

}  // namespace mh::testing
