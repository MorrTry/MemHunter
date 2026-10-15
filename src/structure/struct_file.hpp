#pragma once

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "structure/struct_layout.hpp"

namespace mh {

// What the user said about a structure: its size and the fields they gave, sorted by offset and not overlapping.
struct StructDefinition {
    std::uint32_t size = kDefaultStructSize;
    std::vector<StructField> fields;
};

// Lines "size 0x200" and "0x50 int32 health"; # starts a comment.
std::string format_struct_definition(const StructDefinition& definition);
// Throws Error(CorruptSnapshot) naming the line. The size grows to cover every field.
StructDefinition parse_struct_definition(std::string_view text, unsigned pointer_size);
// Throw Error(Io) when the file cannot be read or written.
StructDefinition read_struct_file(const std::filesystem::path& path, unsigned pointer_size);
void write_struct_file(const std::filesystem::path& path, const StructDefinition& definition);

// "struct Struct { ... };" with <cstdint> types. Gaps and unnamed byte fields become char pad_XXXX[N]; other unnamed
// fields are field_XXXX; names are made valid C identifiers.
std::string c_declaration(std::span<const StructField> fields, std::uint32_t size, unsigned pointer_size);

}  // namespace mh
