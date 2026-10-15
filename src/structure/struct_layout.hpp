#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "memory/memory_dump.hpp"
#include "memory/region.hpp"
#include "pointer/pointer_chain.hpp"
#include "value/value_scan.hpp"

namespace mh {

// The number types match ValueType.
enum class FieldType : std::uint8_t { Int8, Int16, Int32, Int64, Float, Double, Pointer, Ascii, Utf16, Bytes };

inline constexpr std::uint32_t kDefaultStructSize = 0x200;
inline constexpr std::uint32_t kMaxStructSize = 0x10000;
inline constexpr std::uint32_t kMaxFieldLength = 0x1000;

struct StructField {
    std::uint32_t offset = 0;
    FieldType type = FieldType::Int32;
    // Characters of text, bytes of a byte field, 0 for the others.
    std::uint32_t length = 0;
    std::string name;
    // Given by the user or a definition file rather than guessed.
    bool defined = false;

    std::uint32_t size(unsigned pointer_size) const noexcept;
    std::uint32_t end(unsigned pointer_size) const noexcept { return offset + size(pointer_size); }

    friend bool operator==(const StructField&, const StructField&) = default;
};

bool has_length(FieldType type) noexcept;
std::optional<ValueType> field_value_type(FieldType type) noexcept;
// "int32", "pointer", "ascii[16]", "utf16[24]", "bytes[8]".
std::string field_type_name(FieldType type, std::uint32_t length);
std::string field_type_name(const StructField& field);
// The inverse of field_type_name, ignoring case; lengths are 1 to kMaxFieldLength, decimal or 0x-hex.
std::optional<std::pair<FieldType, std::uint32_t>> parse_field_type(std::string_view text);

// The committed readable memory, where a value has to point to be guessed as a pointer.
class PointerTargets {
public:
    PointerTargets() = default;
    explicit PointerTargets(std::span<const Region> regions);

    bool contains(std::uint64_t address) const noexcept;

private:
    // Sorted and merged.
    std::vector<AddressRange> ranges_;
};

// Guessed fields for the bytes [begin, end) of a dump that starts at the structure: pointers, ASCII and UTF-16 text,
// runs of zeros, doubles, floats, int32; unreadable bytes become byte fields.
std::vector<StructField> guess_fields(const MemoryDump& dump, std::uint32_t begin, std::uint32_t end, const PointerTargets& targets,
                                      unsigned pointer_size);

// Fields in order from 0 to at least `size`: the defined ones (a field that overlaps an earlier one is left out) and
// guessed fields between them.
std::vector<StructField> layout_struct(std::span<const StructField> defined, const MemoryDump& dump, std::uint32_t size,
                                       const PointerTargets& targets, unsigned pointer_size);

// The bytes of the field, empty unless every one of them was read.
std::span<const std::byte> field_bytes(const StructField& field, const MemoryDump& dump, unsigned pointer_size);
// "??" for unreadable bytes. Pointers as "game.exe+0x1A2B0" or an address, text in quotes up to the first zero, bytes
// in hex with a run of zeros as "00 × 24".
std::string format_field_value(const StructField& field, const MemoryDump& dump, const ModuleMap& modules, unsigned pointer_size);
// The address a pointer field holds; nullopt for other fields and unreadable bytes.
std::optional<std::uint64_t> field_pointer(const StructField& field, const MemoryDump& dump, unsigned pointer_size);

// "[[game.exe+0x52080]+0x8]": format_pointer_path without a last "+0x0".
std::string format_struct_base(const PointerPath& base);
// The chain to the field at `offset` of the structure at `base`.
PointerPath field_path(PointerPath base, std::uint32_t offset);
// The chain to the structure the pointer field at `offset` points to.
PointerPath pointee_path(PointerPath base, std::uint32_t offset);
// The structure a chain to one of its fields starts at, and the offset of the field: the last offset of the chain.
std::pair<PointerPath, std::uint32_t> split_field_path(PointerPath path);

}  // namespace mh
