#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

#include "inspect/pe_image.hpp"
#include "memory/memory_source.hpp"

namespace mh {

// Signs of code that was injected into a process or of an image that was changed after loading.
enum class FindingKind : std::uint8_t { ExecPrivate, PeHeader, Rwx, Patched, Hollowed };

inline constexpr std::size_t kFindingKindCount = 5;
inline constexpr std::uint32_t kAllFindingKinds = (1u << kFindingKindCount) - 1;

constexpr std::uint32_t kind_bit(FindingKind kind) noexcept {
    return 1u << static_cast<unsigned>(kind);
}

std::string_view to_string(FindingKind kind);
// "exec-private,rwx" as a mask of kind_bit; throws Error(InvalidArgument) for an unknown name.
std::uint32_t parse_finding_kinds(std::string_view list);

struct Finding {
    FindingKind kind = FindingKind::ExecPrivate;
    std::uint64_t address = 0;
    std::uint64_t size = 0;
    // The module (with the offset inside it for code), the mapped file, or empty for private memory.
    std::string where;
    std::string details;
};

struct InspectStats {
    std::uint32_t modules = 0;
    // Code compared with the files, and code skipped because the process shares it unchanged with the file.
    std::uint64_t code_bytes = 0;
    std::uint64_t shared_bytes = 0;
    double seconds = 0;
};

struct InspectReport {
    // By address.
    std::vector<Finding> findings;
    std::vector<std::string> warnings;
    InspectStats stats;
    bool complete = true;

    std::size_t count(FindingKind kind) const noexcept;
};

struct OpenedFile {
    std::shared_ptr<const PeFile> file;
    // Why the file cannot be used when `file` is empty.
    std::string error;
};

// What an inspection needs to know about the process besides its memory.
class InspectFacts {
public:
    virtual ~InspectFacts() = default;
    // The base of the main image the process environment block names; nullopt when it cannot be read.
    virtual std::optional<std::uint64_t> main_image() const = 0;
    // The file the process was started from.
    virtual std::string main_path() const = 0;
    // For each page from `address` on: true when the process shares the page unchanged with the image file, so it
    // need not be compared.
    virtual std::vector<bool> shared_pages(std::uint64_t address, std::size_t pages) const = 0;
    virtual OpenedFile open_image(const std::string& path) const = 0;
    virtual bool file_exists(const std::string& path) const = 0;
    virtual bool same_file(const std::string& a, const std::string& b) const = 0;
};

struct InspectOptions {
    std::uint32_t kinds = kAllFindingKinds;
};

// Only reads: executable memory outside images, PE headers outside images, RWX memory, code of images that differs
// from their files (relocations applied, import tables left out) and images that do not match their files.
InspectReport inspect_memory(const MemorySource& memory, const InspectFacts& facts, const InspectOptions& options = {},
                             std::stop_token stop = {});

}  // namespace mh
