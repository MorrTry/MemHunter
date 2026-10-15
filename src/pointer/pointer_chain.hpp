#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "memory/memory_source.hpp"

namespace mh {

inline constexpr unsigned kMaxPointerDepth = 7;

// A loaded image: the image regions that share one allocation base.
struct Module {
    std::string name;
    std::uint64_t base = 0;
    std::uint64_t end = 0;
};

class ModuleMap {
public:
    ModuleMap() = default;
    explicit ModuleMap(std::span<const Region> regions);

    // Case-insensitive; the module with the lowest base when several share the name.
    const Module* find(std::string_view name) const;
    const Module* locate(std::uint64_t address) const;
    const std::vector<Module>& modules() const noexcept { return modules_; }

private:
    // Sorted by base.
    std::vector<Module> modules_;
};

// Starts at the base of module `module` plus base_offset; each offset then reads the pointer at the current address
// and adds the offset to it. With depth 0 the base itself is the address.
struct PointerChain {
    std::uint64_t base_offset = 0;
    std::array<std::uint32_t, kMaxPointerDepth> offsets{};
    std::uint16_t module = 0;
    std::uint8_t depth = 0;

    std::span<const std::uint32_t> steps() const noexcept { return {offsets.data(), depth}; }
};

struct PointerChains {
    // 8, or 4 for a 32-bit process.
    unsigned pointer_size = 8;
    std::vector<std::string> modules;
    std::vector<PointerChain> chains;
};

// The most pointers a path written by hand may follow.
inline constexpr std::size_t kMaxPathOffsets = 16;

// One chain on its own, as an entry of the address list keeps it. Without a module the base offset is an address.
struct PointerPath {
    std::string module;
    std::uint64_t base_offset = 0;
    std::vector<std::uint32_t> offsets;
    unsigned pointer_size = 8;

    friend bool operator==(const PointerPath&, const PointerPath&) = default;
};

PointerPath path_of(const PointerChains& chains, std::size_t index);

// "game.exe+0x1A2B0".
std::string format_pointer_base(std::string_view module, std::uint64_t offset);
// "0x10, 0x8"; empty without offsets.
std::string format_pointer_offsets(std::span<const std::uint32_t> offsets);
// "[[game.exe+0x1A2B0]+0x10]+0x8".
std::string format_pointer_path(const PointerPath& path);
// The inverse of format_pointer_path. Numbers are hexadecimal with or without 0x; "]" without an offset adds 0; a base
// that is only a number is an address. Spaces around the parts are ignored.
std::optional<PointerPath> parse_pointer_path(std::string_view text, unsigned pointer_size);

// The base of each module in `names`; 0 for one that is not loaded.
std::vector<std::uint64_t> module_bases(const ModuleMap& modules, std::span<const std::string> names);

// The address a chain leads to now; nullopt when its module is not loaded or a pointer on the way cannot be read.
std::optional<std::uint64_t> resolve_chain(const MemorySource& memory, std::span<const std::uint64_t> bases,
                                           const PointerChain& chain, unsigned pointer_size);
std::optional<std::uint64_t> resolve_pointer_path(const MemorySource& memory, const ModuleMap& modules, const PointerPath& path);

}  // namespace mh
