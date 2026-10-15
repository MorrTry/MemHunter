#include "pipeline/scan_session.hpp"

#include <algorithm>
#include <chrono>

#include "common/error.hpp"
#include "pipeline/work_plan.hpp"

namespace mh {

namespace {

using Clock = std::chrono::steady_clock;

bool overlaps_any(const Match& match, const std::vector<AddressRange>& ranges) {
    const std::uint64_t end = match.address + std::max<std::uint32_t>(match.length, 1);
    const auto next = std::upper_bound(ranges.begin(), ranges.end(), match.address,
                                       [](std::uint64_t address, const AddressRange& r) { return address < r.begin; });
    if (next != ranges.end() && next->begin < end) {
        return true;
    }
    return next != ranges.begin() && std::prev(next)->end > match.address;
}

}  // namespace

std::vector<PatternInfo> describe_patterns(const ScanRequest& request, StringIds* string_ids) {
    StringIds ids;
    std::vector<PatternInfo> infos;
    infos.reserve(request.patterns.size() + 2);
    for (const auto& pattern : request.patterns) {
        infos.push_back({pattern.label, pattern.kind, static_cast<std::uint32_t>(pattern.size()), pattern.case_insensitive});
    }
    if (request.strings) {
        const auto add = [&](std::string label, PatternKind kind) {
            infos.push_back({std::move(label), kind, 0, false});
            return static_cast<std::uint32_t>(infos.size() - 1);
        };
        if ((request.strings->encodings & encoding::Ascii) != 0) {
            ids.ascii = add("strings:ascii", PatternKind::StringsAscii);
        }
        if ((request.strings->encodings & encoding::Utf16) != 0) {
            ids.utf16 = add("strings:utf16", PatternKind::StringsUtf16);
        }
    }
    if (string_ids != nullptr) {
        *string_ids = ids;
    }
    return infos;
}

ScanPlan plan_scan(const MemorySource& source, const RegionFilter& filter) {
    const auto started = Clock::now();
    ScanPlan plan;
    plan.regions = source.query_regions();
    plan.enumerate_seconds = std::chrono::duration<double>(Clock::now() - started).count();
    plan.regions_selected = static_cast<std::size_t>(
        std::count_if(plan.regions.begin(), plan.regions.end(), [&](const Region& region) { return filter.accepts(region); }));
    plan.spans = build_spans(plan.regions, filter);
    return plan;
}

ResultSet run_scan(const MemorySource& source, const ScanRequest& request, ScanProgress& progress, std::stop_token stop) {
    return run_scan(source, request, plan_scan(source, request.filter), progress, std::move(stop));
}

ResultSet run_scan(const MemorySource& source, const ScanRequest& request, ScanPlan plan, ScanProgress& progress,
                   std::stop_token stop) {
    ResultSet results;
    StringIds string_ids;
    results.patterns = describe_patterns(request, &string_ids);

    MatcherSetup setup = build_matcher(request.patterns, request.strings, string_ids, request.algorithm);
    if (!setup.matcher) {
        throw Error(ErrorCode::InvalidArgument, "nothing to search for: give --string, --pattern or --strings");
    }

    std::vector<AddressRange> changed;
    std::vector<ScanTarget> targets;
    if (request.changed) {
        changed = merge_ranges(*request.changed);
        targets = changed_range_targets(plan.spans, changed, setup.look_ahead);
    } else {
        targets = whole_span_targets(plan.spans);
    }
    auto work = split_work(targets, request.chunk_size, setup.look_behind, setup.look_ahead);
    progress.regions_total = attribute_regions(plan.regions, work);

    EngineConfig config = request.engine;
    config.full_preview.assign(results.patterns.size(), 0);
    for (std::size_t i = 0; i < results.patterns.size(); ++i) {
        config.full_preview[i] = is_extracted_string(results.patterns[i].kind) ? 1 : 0;
    }

    EngineResult engine = run_engine(source, *setup.matcher, work, config, progress, std::move(stop));

    auto& stats = results.stats;
    stats.status = engine.status;
    stats.algorithm = setup.matcher->describe();
    stats.scan_threads = engine.scan_threads;
    stats.read_threads = engine.read_threads;
    stats.chunk_size = request.chunk_size;
    stats.regions_total = plan.regions.size();
    stats.regions_selected = plan.regions_selected;
    for (const auto& item : work) {
        stats.bytes_planned += item.own_end - item.own_begin;
    }
    stats.bytes_read = engine.bytes_read;
    stats.bytes_unreadable = engine.bytes_unreadable;
    stats.chunks = work.size();
    stats.read_calls = engine.read_calls;
    stats.read_failures = engine.read_failures;
    stats.matches_found = engine.matches_found;
    stats.truncated = engine.truncated;
    stats.enumerate_seconds = plan.enumerate_seconds;
    stats.read_seconds = engine.read_seconds;
    stats.scan_seconds = engine.scan_seconds;
    stats.wall_seconds = engine.wall_seconds + plan.enumerate_seconds;

    results.regions = std::move(plan.regions);
    results.matches = std::move(engine.matches);
    results.previews = std::move(engine.previews);
    results.read_failures = std::move(engine.failures);

    if (request.changed) {
        std::erase_if(results.matches, [&](const Match& match) { return !overlaps_any(match, changed); });
    }
    normalize(results);
    return results;
}

}  // namespace mh
