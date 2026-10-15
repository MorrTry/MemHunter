#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "memory/region.hpp"
#include "pattern/pattern.hpp"

namespace mh {

inline constexpr std::uint32_t kNoRegion = 0xFFFF'FFFFu;

struct Match {
    std::uint64_t address = 0;
    std::uint32_t length = 0;
    std::uint32_t pattern = 0;
    std::uint32_t region = kNoRegion;
    std::uint32_t preview_size = 0;
    std::uint64_t preview_offset = 0;
};

struct PatternInfo {
    std::string label;
    PatternKind kind = PatternKind::Bytes;
    std::uint32_t length = 0;
    bool case_insensitive = false;
};

enum class ScanStatus { Completed, Cancelled, TargetExited };

std::string_view to_string(ScanStatus status);

struct ReadFailure {
    std::uint64_t address = 0;
    std::uint64_t size = 0;
    std::uint32_t error = 0;
};

struct ScanStats {
    ScanStatus status = ScanStatus::Completed;
    std::string algorithm;
    unsigned scan_threads = 0;
    unsigned read_threads = 0;
    std::uint64_t chunk_size = 0;
    std::uint64_t regions_total = 0;
    std::uint64_t regions_selected = 0;
    std::uint64_t bytes_planned = 0;
    std::uint64_t bytes_read = 0;
    std::uint64_t bytes_unreadable = 0;
    std::uint64_t chunks = 0;
    std::uint64_t read_calls = 0;
    std::uint64_t read_failures = 0;
    std::uint64_t matches_found = 0;
    bool truncated = false;
    double enumerate_seconds = 0;
    double read_seconds = 0;
    double scan_seconds = 0;
    double wall_seconds = 0;
};

struct ProcessSummary {
    std::uint32_t pid = 0;
    std::string name;
    std::string path;
    std::uint64_t creation_time = 0;
    bool wow64 = false;
};

class ResultSet {
public:
    ProcessSummary process;
    std::vector<PatternInfo> patterns;
    std::vector<Region> regions;
    std::vector<Match> matches;
    std::vector<std::byte> previews;
    std::vector<ReadFailure> read_failures;
    ScanStats stats;

    std::span<const std::byte> preview(const Match& match) const;
    const Region* region_of(const Match& match) const;
    std::string preview_text(const Match& match) const;
    std::string preview_hex(const Match& match) const;
};

// Sorts matches by (address, pattern, length), removes exact duplicates and assigns region indices.
void normalize(ResultSet& results);

}  // namespace mh
