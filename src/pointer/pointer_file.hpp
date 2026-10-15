#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "pointer/pointer_chain.hpp"
#include "results/result_set.hpp"

namespace mh {

inline constexpr std::uint32_t kPointerFileVersion = 1;

// Saved chains with what they were searched for.
struct PointerFile {
    ProcessSummary process;
    std::uint64_t target = 0;
    // The type of the value as the address list numbers it (0-5 are the ValueType numbers) and the length of text
    // and byte values.
    std::uint8_t target_type = 2;
    std::uint32_t target_length = 0;
    unsigned depth = 5;
    std::uint32_t max_offset = 0x1000;
    // How many checks have filtered the chains since the search.
    std::uint32_t checks = 0;
    PointerChains chains;
};

// A 40-byte header (magic, version, flags, payload size, payload checksum, header checksum; both XXH64) and the
// payload.
std::vector<std::byte> encode_pointer_file(const PointerFile& file);

// Throws Error(CorruptSnapshot) for a file that is not a pointer file, is truncated, fails a checksum or holds an
// invalid chain, and Error(IncompatibleSnapshot) for a newer format.
PointerFile decode_pointer_file(std::span<const std::byte> bytes, const std::string& name);

// Writes FILE.partial and renames it over FILE once it is complete; returns the size of the file. Throws Error(Io).
std::uint64_t write_pointer_file(const std::string& path, const PointerFile& file);
PointerFile read_pointer_file(const std::string& path);

}  // namespace mh
