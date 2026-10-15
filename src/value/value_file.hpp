#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "results/result_set.hpp"
#include "value/value_scan.hpp"

namespace mh {

inline constexpr std::uint32_t kValueFileVersion = 1;

// The state of a value search between two runs of 'memhunter value': the process run it belongs to and the
// candidates of the last scan.
struct ValueFile {
    ProcessSummary process;
    ValueCandidates candidates;
};

// The whole file: a 40-byte header (magic, version, flags, payload size, payload checksum, header checksum) and
// the payload. Both checksums are XXH64.
std::vector<std::byte> encode_value_file(const ProcessSummary& process, const ValueCandidates& candidates);

// Throws Error(CorruptSnapshot) for a file that is not a value file, is truncated, fails a checksum or holds an
// inconsistent candidate list, and Error(IncompatibleSnapshot) for a newer format.
ValueFile decode_value_file(std::span<const std::byte> bytes, const std::string& name);

// Writes FILE.partial and renames it over FILE once it is complete; returns the size of the file. Throws
// Error(Io), also when the disk has not enough free space.
std::uint64_t write_value_file(const std::string& path, const ProcessSummary& process, const ValueCandidates& candidates);

// Throws Error(Io) when the file cannot be read, otherwise like decode_value_file.
ValueFile read_value_file(const std::string& path);

}  // namespace mh
