#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace mh {

struct PeSection {
    std::string name;
    std::uint32_t virtual_address = 0;
    std::uint32_t virtual_size = 0;
    std::uint32_t raw_offset = 0;
    std::uint32_t raw_size = 0;
    std::uint32_t characteristics = 0;

    bool executable() const noexcept;
    // The bytes the section takes in a mapped image.
    std::uint32_t mapped_size() const noexcept { return virtual_size != 0 ? virtual_size : raw_size; }
};

struct PeDirectory {
    std::uint32_t rva = 0;
    std::uint32_t size = 0;
};

struct RvaRange {
    std::uint32_t rva = 0;
    std::uint32_t size = 0;
};

struct PeHeaders {
    bool pe32_plus = false;
    std::uint16_t machine = 0;
    std::uint16_t characteristics = 0;
    std::uint32_t timestamp = 0;
    std::uint64_t image_base = 0;
    std::uint32_t entry_point = 0;
    std::uint32_t size_of_image = 0;
    std::uint32_t size_of_headers = 0;
    PeDirectory exports;
    PeDirectory relocations;
    PeDirectory load_config;
    PeDirectory iat;
    std::vector<PeSection> sections;

    bool is_dll() const noexcept;
    const PeSection* section_at(std::uint32_t rva) const noexcept;
    // "64-bit DLL", "32-bit EXE".
    std::string describe() const;
};

// The DOS, NT and section headers at the start of `bytes`, a file or a mapped image; nullopt when they are missing
// or damaged.
std::optional<PeHeaders> parse_pe_headers(std::span<const std::byte> bytes);

// Base relocations, which the loader applies when an image is not mapped at its preferred base.
class Relocations {
public:
    Relocations() = default;
    // The contents of the relocation directory; a damaged block ends the table.
    explicit Relocations(std::span<const std::byte> table);

    // Adds `delta` at every relocation that lies wholly inside `bytes`, which holds the image from `rva` on.
    void apply(std::uint32_t rva, std::span<std::byte> bytes, std::uint64_t delta) const;
    std::size_t size() const noexcept { return entries_.size(); }

private:
    struct Entry {
        std::uint32_t rva = 0;
        std::uint8_t type = 0;
    };
    std::vector<Entry> entries_;
};

class FileReader {
public:
    virtual ~FileReader() = default;
    virtual std::uint64_t size() const = 0;
    // False when the whole range cannot be read.
    virtual bool read(std::uint64_t offset, std::span<std::byte> out) const = 0;
};

// A PE file as the loader would map it, read on demand.
class PeFile {
public:
    // nullptr when the file is not a PE image or cannot be read.
    static std::shared_ptr<const PeFile> load(std::unique_ptr<FileReader> reader);

    const PeHeaders& headers() const noexcept { return headers_; }
    // The bytes the loader maps at [rva, rva + out.size()) for an image based at `base`: the headers and the raw
    // data of the sections, zeros elsewhere, relocated. False when the file cannot be read.
    bool image_bytes(std::uint32_t rva, std::span<std::byte> out, std::uint64_t base) const;
    // The places Windows rewrites while loading to call the chosen variant of a function (function overrides of
    // the dynamic value relocation table, the "fothk" section), by RVA.
    const std::vector<RvaRange>& override_sites() const noexcept { return override_sites_; }

private:
    PeFile() = default;

    std::unique_ptr<FileReader> reader_;
    PeHeaders headers_;
    Relocations relocations_;
    std::vector<RvaRange> override_sites_;
};

// The function override sites of a dynamic value relocation table (version 1, without its 8-byte header).
std::vector<RvaRange> parse_override_sites(std::span<const std::byte> table, bool pe32_plus);

}  // namespace mh
