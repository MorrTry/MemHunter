#include "inspect/pe_image.hpp"

#include <algorithm>
#include <array>
#include <cstring>

namespace mh {

namespace {

constexpr std::uint16_t kDosMagic = 0x5A4D;
constexpr std::uint32_t kNtSignature = 0x00004550;
constexpr std::uint16_t kPe32 = 0x10B;
constexpr std::uint16_t kPe32Plus = 0x20B;
constexpr std::uint16_t kFileDll = 0x2000;
constexpr std::uint32_t kSectionExecute = 0x20000000;
constexpr std::size_t kMaxSections = 96;
constexpr std::size_t kHeaderRead = 0x10000;
constexpr std::uint32_t kMaxRelocationTable = 64u << 20;

constexpr std::uint8_t kRelocHigh = 1;
constexpr std::uint8_t kRelocLow = 2;
constexpr std::uint8_t kRelocHighLow = 3;
constexpr std::uint8_t kRelocHighAdj = 4;
constexpr std::uint8_t kRelocDir64 = 10;

// IMAGE_DYNAMIC_RELOCATION_FUNCTION_OVERRIDE.
constexpr std::uint64_t kFunctionOverride = 7;
constexpr std::uint32_t kMaxDynamicTable = 16u << 20;
// DynamicValueRelocTableOffset, followed by DynamicValueRelocTableSection, in the load configuration.
constexpr std::size_t kDynamicTableField64 = 0xE0;
constexpr std::size_t kDynamicTableField32 = 0x88;

template <typename T>
std::optional<T> load(std::span<const std::byte> bytes, std::size_t offset) {
    if (offset > bytes.size() || bytes.size() - offset < sizeof(T)) {
        return std::nullopt;
    }
    T value;
    std::memcpy(&value, bytes.data() + offset, sizeof(T));
    return value;
}

template <typename T>
void add_at(std::byte* at, T delta) {
    T value;
    std::memcpy(&value, at, sizeof(T));
    value = static_cast<T>(value + delta);
    std::memcpy(at, &value, sizeof(T));
}

template <typename T>
std::optional<T> read_value(const FileReader& reader, std::uint64_t offset) {
    std::array<std::byte, sizeof(T)> bytes{};
    if (offset > reader.size() || reader.size() - offset < sizeof(T) || !reader.read(offset, bytes)) {
        return std::nullopt;
    }
    return load<T>(bytes, 0);
}

std::optional<std::uint64_t> file_offset(const PeHeaders& headers, std::uint32_t rva) {
    const PeSection* section = headers.section_at(rva);
    if (section == nullptr) {
        return std::nullopt;
    }
    return std::uint64_t{section->raw_offset} + (rva - section->virtual_address);
}

// One function override entry: IMAGE_FUNCTION_OVERRIDE_HEADER, then per function its RVAs and the base relocation
// blocks naming the places to rewrite.
void add_override_sites(std::span<const std::byte> entry, std::vector<RvaRange>& sites) {
    const auto overrides_size = load<std::uint32_t>(entry, 0);
    if (!overrides_size || *overrides_size > entry.size() - 4) {
        return;
    }
    const auto overrides = entry.subspan(4, *overrides_size);
    std::size_t at = 0;
    while (at + 16 <= overrides.size()) {
        const std::uint32_t rvas_size = *load<std::uint32_t>(overrides, at + 8);
        const std::uint32_t blocks_size = *load<std::uint32_t>(overrides, at + 12);
        const std::size_t blocks = at + 16 + std::size_t{rvas_size};
        if (blocks > overrides.size() || blocks_size > overrides.size() - blocks) {
            return;
        }
        const std::size_t blocks_end = blocks + blocks_size;
        for (std::size_t block_at = blocks; block_at + 8 <= blocks_end;) {
            const std::uint32_t page = *load<std::uint32_t>(overrides, block_at);
            const std::uint32_t block = *load<std::uint32_t>(overrides, block_at + 4);
            if (block < 8 || block > blocks_end - block_at) {
                break;
            }
            for (std::size_t i = 0; i < (block - 8) / 2; ++i) {
                const std::uint16_t item = *load<std::uint16_t>(overrides, block_at + 8 + i * 2);
                const auto type = static_cast<std::uint8_t>(item >> 12);
                if (type != 0) {
                    sites.push_back({page + (item & 0xFFFu), type == kRelocDir64 ? 8u : 4u});
                }
            }
            block_at += block;
        }
        at = blocks_end;
    }
}

std::vector<RvaRange> read_override_sites(const FileReader& reader, const PeHeaders& headers) {
    const auto config = headers.load_config.rva != 0 ? file_offset(headers, headers.load_config.rva) : std::nullopt;
    if (!config) {
        return {};
    }
    const std::size_t field = headers.pe32_plus ? kDynamicTableField64 : kDynamicTableField32;
    const auto config_size = read_value<std::uint32_t>(reader, *config);
    if (!config_size || *config_size < field + 6) {
        return {};
    }
    const auto offset = read_value<std::uint32_t>(reader, *config + field);
    const auto section = read_value<std::uint16_t>(reader, *config + field + 4);
    if (!offset || !section || *section == 0 || *section > headers.sections.size()) {
        return {};
    }
    const std::uint64_t at = std::uint64_t{headers.sections[*section - 1].raw_offset} + *offset;
    const auto version = read_value<std::uint32_t>(reader, at);
    const auto size = read_value<std::uint32_t>(reader, at + 4);
    if (version != 1u || !size || *size > kMaxDynamicTable || at + 8 + *size > reader.size()) {
        return {};
    }
    std::vector<std::byte> table(*size);
    if (!reader.read(at + 8, table)) {
        return {};
    }
    return parse_override_sites(table, headers.pe32_plus);
}

}  // namespace

std::vector<RvaRange> parse_override_sites(std::span<const std::byte> table, bool pe32_plus) {
    std::vector<RvaRange> sites;
    const std::size_t header = pe32_plus ? 12 : 8;
    std::size_t at = 0;
    while (at + header <= table.size()) {
        const std::uint64_t symbol = pe32_plus ? *load<std::uint64_t>(table, at) : *load<std::uint32_t>(table, at);
        const std::uint32_t size = *load<std::uint32_t>(table, at + header - 4);
        const std::size_t body = at + header;
        if (size > table.size() - body) {
            break;
        }
        if (symbol == kFunctionOverride) {
            add_override_sites(table.subspan(body, size), sites);
        }
        at = body + size;
    }
    std::sort(sites.begin(), sites.end(), [](const RvaRange& a, const RvaRange& b) { return a.rva < b.rva; });
    std::vector<RvaRange> merged;
    for (const RvaRange& site : sites) {
        if (!merged.empty() && site.rva <= std::uint64_t{merged.back().rva} + merged.back().size) {
            const std::uint64_t end = std::max<std::uint64_t>(std::uint64_t{merged.back().rva} + merged.back().size, std::uint64_t{site.rva} + site.size);
            merged.back().size = static_cast<std::uint32_t>(end - merged.back().rva);
        } else {
            merged.push_back(site);
        }
    }
    return merged;
}

bool PeSection::executable() const noexcept {
    return (characteristics & kSectionExecute) != 0;
}

bool PeHeaders::is_dll() const noexcept {
    return (characteristics & kFileDll) != 0;
}

const PeSection* PeHeaders::section_at(std::uint32_t rva) const noexcept {
    for (const auto& section : sections) {
        if (rva >= section.virtual_address && rva - section.virtual_address < section.mapped_size()) {
            return &section;
        }
    }
    return nullptr;
}

std::string PeHeaders::describe() const {
    return std::string(pe32_plus ? "64-bit " : "32-bit ") + (is_dll() ? "DLL" : "EXE");
}

std::optional<PeHeaders> parse_pe_headers(std::span<const std::byte> bytes) {
    if (load<std::uint16_t>(bytes, 0) != kDosMagic) {
        return std::nullopt;
    }
    const auto nt_offset = load<std::uint32_t>(bytes, 0x3C);
    if (!nt_offset || load<std::uint32_t>(bytes, *nt_offset) != kNtSignature) {
        return std::nullopt;
    }
    const std::size_t nt = *nt_offset;
    const std::size_t optional = nt + 24;
    const auto machine = load<std::uint16_t>(bytes, nt + 4);
    const auto section_count = load<std::uint16_t>(bytes, nt + 6);
    const auto timestamp = load<std::uint32_t>(bytes, nt + 8);
    const auto optional_size = load<std::uint16_t>(bytes, nt + 20);
    const auto characteristics = load<std::uint16_t>(bytes, nt + 22);
    const auto magic = load<std::uint16_t>(bytes, optional);
    if (!machine || !section_count || !timestamp || !optional_size || !characteristics || !magic ||
        (*magic != kPe32 && *magic != kPe32Plus) || *section_count > kMaxSections) {
        return std::nullopt;
    }

    PeHeaders headers;
    headers.pe32_plus = *magic == kPe32Plus;
    headers.machine = *machine;
    headers.characteristics = *characteristics;
    headers.timestamp = *timestamp;
    const auto entry_point = load<std::uint32_t>(bytes, optional + 16);
    std::optional<std::uint64_t> image_base = load<std::uint64_t>(bytes, optional + 24);
    if (!headers.pe32_plus) {
        const auto base32 = load<std::uint32_t>(bytes, optional + 28);
        image_base = base32 ? std::optional<std::uint64_t>(*base32) : std::nullopt;
    }
    const auto size_of_image = load<std::uint32_t>(bytes, optional + 56);
    const auto size_of_headers = load<std::uint32_t>(bytes, optional + 60);
    const std::size_t count_at = optional + (headers.pe32_plus ? 108 : 92);
    const auto directory_count = load<std::uint32_t>(bytes, count_at);
    if (!entry_point || !image_base || !size_of_image || !size_of_headers || !directory_count) {
        return std::nullopt;
    }
    headers.entry_point = *entry_point;
    headers.image_base = *image_base;
    headers.size_of_image = *size_of_image;
    headers.size_of_headers = *size_of_headers;

    const auto directory = [&](std::uint32_t index) {
        const std::size_t at = count_at + 4 + std::size_t{index} * 8;
        if (index >= *directory_count || at + 8 > optional + *optional_size) {
            return PeDirectory{};
        }
        return PeDirectory{load<std::uint32_t>(bytes, at).value_or(0), load<std::uint32_t>(bytes, at + 4).value_or(0)};
    };
    headers.exports = directory(0);
    headers.relocations = directory(5);
    headers.load_config = directory(10);
    headers.iat = directory(12);

    const std::size_t table = optional + *optional_size;
    for (std::size_t i = 0; i < *section_count; ++i) {
        const std::size_t at = table + i * 40;
        if (at + 40 > bytes.size()) {
            return std::nullopt;
        }
        PeSection section;
        const char* name = reinterpret_cast<const char*>(bytes.data() + at);
        section.name.assign(name, std::find(name, name + 8, '\0'));
        section.virtual_size = *load<std::uint32_t>(bytes, at + 8);
        section.virtual_address = *load<std::uint32_t>(bytes, at + 12);
        section.raw_size = *load<std::uint32_t>(bytes, at + 16);
        section.raw_offset = *load<std::uint32_t>(bytes, at + 20);
        section.characteristics = *load<std::uint32_t>(bytes, at + 36);
        headers.sections.push_back(std::move(section));
    }
    return headers;
}

Relocations::Relocations(std::span<const std::byte> table) {
    std::size_t at = 0;
    while (at + 8 <= table.size()) {
        const std::uint32_t page = *load<std::uint32_t>(table, at);
        const std::uint32_t block = *load<std::uint32_t>(table, at + 4);
        if (block < 8 || block > table.size() - at) {
            break;
        }
        const std::size_t count = (block - 8) / 2;
        for (std::size_t i = 0; i < count; ++i) {
            const std::uint16_t entry = *load<std::uint16_t>(table, at + 8 + i * 2);
            const auto type = static_cast<std::uint8_t>(entry >> 12);
            if (type == kRelocHighAdj) {
                ++i;
            } else if (type == kRelocHigh || type == kRelocLow || type == kRelocHighLow || type == kRelocDir64) {
                entries_.push_back({page + (entry & 0xFFFu), type});
            }
        }
        at += block;
    }
    std::stable_sort(entries_.begin(), entries_.end(), [](const Entry& a, const Entry& b) { return a.rva < b.rva; });
}

void Relocations::apply(std::uint32_t rva, std::span<std::byte> bytes, std::uint64_t delta) const {
    if (delta == 0 || bytes.empty()) {
        return;
    }
    const std::uint64_t end = std::uint64_t{rva} + bytes.size();
    auto it = std::lower_bound(entries_.begin(), entries_.end(), rva, [](const Entry& e, std::uint32_t r) { return e.rva < r; });
    for (; it != entries_.end() && it->rva < end; ++it) {
        const std::size_t width = it->type == kRelocDir64 ? 8 : it->type == kRelocHighLow ? 4 : 2;
        if (it->rva + width > end) {
            continue;
        }
        std::byte* at = bytes.data() + (it->rva - rva);
        switch (it->type) {
            case kRelocHigh: add_at<std::uint16_t>(at, static_cast<std::uint16_t>(delta >> 16)); break;
            case kRelocLow: add_at<std::uint16_t>(at, static_cast<std::uint16_t>(delta)); break;
            case kRelocHighLow: add_at<std::uint32_t>(at, static_cast<std::uint32_t>(delta)); break;
            case kRelocDir64: add_at<std::uint64_t>(at, delta); break;
            default: break;
        }
    }
}

std::shared_ptr<const PeFile> PeFile::load(std::unique_ptr<FileReader> reader) {
    const std::uint64_t size = reader->size();
    std::vector<std::byte> head(static_cast<std::size_t>(std::min<std::uint64_t>(size, kHeaderRead)));
    if (head.empty() || !reader->read(0, head)) {
        return nullptr;
    }
    auto headers = parse_pe_headers(head);
    if (!headers) {
        return nullptr;
    }
    std::shared_ptr<PeFile> file(new PeFile());
    file->headers_ = std::move(*headers);
    const PeDirectory relocations = file->headers_.relocations;
    if (relocations.rva != 0 && relocations.size != 0 && relocations.size <= kMaxRelocationTable) {
        if (const auto offset = file_offset(file->headers_, relocations.rva); offset && *offset + relocations.size <= size) {
            std::vector<std::byte> table(relocations.size);
            if (reader->read(*offset, table)) {
                file->relocations_ = Relocations(table);
            }
        }
    }
    file->override_sites_ = read_override_sites(*reader, file->headers_);
    file->reader_ = std::move(reader);
    return file;
}

bool PeFile::image_bytes(std::uint32_t rva, std::span<std::byte> out, std::uint64_t base) const {
    // A relocation that ends inside `out` may start before it, so the margins hold the rest of its bytes.
    const std::uint64_t low = rva >= 8 ? rva - 8 : 0;
    const std::uint64_t high = std::uint64_t{rva} + out.size() + 8;
    std::vector<std::byte> buffer(static_cast<std::size_t>(high - low));
    const std::uint64_t file_size = reader_->size();
    const auto copy = [&](std::uint64_t from_rva, std::uint64_t length, std::uint64_t file_offset) {
        if (file_offset >= file_size) {
            return true;
        }
        length = std::min(length, file_size - file_offset);
        const std::uint64_t begin = std::max(from_rva, low);
        const std::uint64_t end = std::min(from_rva + length, high);
        if (begin >= end) {
            return true;
        }
        return reader_->read(file_offset + (begin - from_rva),
                             std::span(buffer).subspan(static_cast<std::size_t>(begin - low), static_cast<std::size_t>(end - begin)));
    };
    if (!copy(0, headers_.size_of_headers, 0)) {
        return false;
    }
    for (const auto& section : headers_.sections) {
        if (!copy(section.virtual_address, std::min(section.raw_size, section.mapped_size()), section.raw_offset)) {
            return false;
        }
    }
    relocations_.apply(static_cast<std::uint32_t>(low), buffer, base - headers_.image_base);
    std::memcpy(out.data(), buffer.data() + (rva - low), out.size());
    return true;
}

}  // namespace mh
