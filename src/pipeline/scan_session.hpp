#pragma once

#include <cstddef>
#include <optional>
#include <stop_token>
#include <vector>

#include "memory/memory_source.hpp"
#include "pattern/pattern.hpp"
#include "pipeline/scan_engine.hpp"
#include "results/result_set.hpp"
#include "scanner/matcher_factory.hpp"

namespace mh {

// Small enough that a chunk stays in L2 while every SIMD pass rereads it (bench/README.md, "Chunk size").
inline constexpr std::size_t kDefaultChunkSize = std::size_t{256} << 10;

struct ScanRequest {
    std::vector<Pattern> patterns;
    std::optional<StringOptions> strings;
    RegionFilter filter;
    Algorithm algorithm = Algorithm::Auto;
    std::size_t chunk_size = kDefaultChunkSize;
    EngineConfig engine;
    // Incremental mode: only matches overlapping these ranges are searched for and reported.
    std::optional<std::vector<AddressRange>> changed;
};

// Region list captured at the start of a scan together with the spans selected for reading.
struct ScanPlan {
    std::vector<Region> regions;
    std::vector<AddressRange> spans;
    std::size_t regions_selected = 0;
    double enumerate_seconds = 0;
};

ScanPlan plan_scan(const MemorySource& source, const RegionFilter& filter);

// Pattern table of a scan: request patterns first, then one pseudo-pattern per extracted string encoding.
std::vector<PatternInfo> describe_patterns(const ScanRequest& request, StringIds* string_ids = nullptr);

// Throws Error(InvalidArgument) when there is nothing to search for. The caller fills results.process.
ResultSet run_scan(const MemorySource& source, const ScanRequest& request, ScanProgress& progress, std::stop_token stop);

ResultSet run_scan(const MemorySource& source, const ScanRequest& request, ScanPlan plan, ScanProgress& progress,
                   std::stop_token stop);

}  // namespace mh
