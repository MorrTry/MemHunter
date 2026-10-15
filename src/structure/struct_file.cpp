#include "structure/struct_file.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <set>

#include "common/error.hpp"
#include "common/text.hpp"

namespace mh {

namespace {

std::string_view trim(std::string_view text) {
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.front())) != 0) {
        text.remove_prefix(1);
    }
    while (!text.empty() && std::isspace(static_cast<unsigned char>(text.back())) != 0) {
        text.remove_suffix(1);
    }
    return text;
}

// The next word and what follows it.
std::pair<std::string_view, std::string_view> split_word(std::string_view text) {
    text = trim(text);
    const std::size_t space = text.find_first_of(" \t");
    if (space == std::string_view::npos) {
        return {text, {}};
    }
    return {text.substr(0, space), trim(text.substr(space))};
}

[[noreturn]] void bad_line(std::size_t line, const std::string& message) {
    throw Error(ErrorCode::CorruptSnapshot, "line " + std::to_string(line) + ": " + message);
}

std::string pad_name(std::uint32_t offset) {
    char text[16];
    std::snprintf(text, sizeof(text), "%04X", offset);
    return text;
}

std::string identifier(std::string_view name, std::uint32_t offset, std::string_view prefix, std::set<std::string>& used) {
    std::string text;
    for (const char c : name) {
        const auto byte = static_cast<unsigned char>(c);
        text.push_back(byte >= 0x80 || std::isalnum(byte) != 0 || c == '_' ? c : '_');
    }
    if (text.empty()) {
        text = std::string(prefix) + pad_name(offset);
    } else if (std::isdigit(static_cast<unsigned char>(text.front())) != 0) {
        text.insert(text.begin(), '_');
    }
    std::string unique = text;
    for (int n = 2; used.contains(unique); ++n) {
        unique = text + "_" + std::to_string(n);
    }
    used.insert(unique);
    return unique;
}

std::string c_type(FieldType type, unsigned pointer_size) {
    switch (type) {
        case FieldType::Int8: return "int8_t";
        case FieldType::Int16: return "int16_t";
        case FieldType::Int32: return "int32_t";
        case FieldType::Int64: return "int64_t";
        case FieldType::Float: return "float";
        case FieldType::Double: return "double";
        case FieldType::Pointer: return pointer_size == 8 ? "void*" : "uint32_t";
        case FieldType::Ascii: return "char";
        case FieldType::Utf16: return "wchar_t";
        case FieldType::Bytes: return "uint8_t";
    }
    return "uint8_t";
}

}  // namespace

std::string format_struct_definition(const StructDefinition& definition) {
    std::string text = "# MemHunter structure: offset, type, name\nsize " + format_hex(definition.size) + "\n";
    for (const StructField& field : definition.fields) {
        text += format_hex(field.offset) + " " + field_type_name(field);
        if (!field.name.empty()) {
            text += " " + field.name;
        }
        text += "\n";
    }
    return text;
}

StructDefinition parse_struct_definition(std::string_view text, unsigned pointer_size) {
    StructDefinition definition;
    std::uint32_t size = 0;
    std::size_t number = 0;
    if (text.starts_with("\xEF\xBB\xBF")) {
        text.remove_prefix(3);
    }
    while (!text.empty()) {
        ++number;
        const std::size_t newline = text.find('\n');
        std::string_view line = text.substr(0, newline);
        text.remove_prefix(newline == std::string_view::npos ? text.size() : newline + 1);
        line = trim(line.substr(0, line.find('#')));
        if (line.empty()) {
            continue;
        }
        const auto [first, rest] = split_word(line);
        if (to_lower_ascii(first) == "size") {
            const auto value = parse_uint(rest);
            if (!value || *value == 0 || *value > kMaxStructSize) {
                bad_line(number, "the size is 1 to " + format_hex(kMaxStructSize) + " bytes, got '" + std::string(rest) + "'");
            }
            size = static_cast<std::uint32_t>(*value);
            continue;
        }
        const auto offset = parse_uint(first);
        if (!offset || *offset >= kMaxStructSize) {
            bad_line(number, "expected 'size N' or 'OFFSET TYPE [NAME]' with an offset below " + format_hex(kMaxStructSize) + ", got '" +
                                 std::string(first) + "'");
        }
        const auto [type_text, name] = split_word(rest);
        const auto type = parse_field_type(type_text);
        if (!type) {
            bad_line(number, "unknown type '" + std::string(type_text) +
                                 "'; use int8, int16, int32, int64, float, double, pointer, ascii[N], utf16[N] or bytes[N]");
        }
        StructField field{static_cast<std::uint32_t>(*offset), type->first, type->second, std::string(name), true};
        if (field.end(pointer_size) > kMaxStructSize) {
            bad_line(number, "the field ends after " + format_hex(kMaxStructSize));
        }
        for (const StructField& other : definition.fields) {
            if (field.offset < other.end(pointer_size) && other.offset < field.end(pointer_size)) {
                bad_line(number, "the field at " + format_hex(field.offset) + " overlaps the field at " + format_hex(other.offset));
            }
        }
        definition.fields.push_back(std::move(field));
    }
    std::sort(definition.fields.begin(), definition.fields.end(), [](const StructField& a, const StructField& b) { return a.offset < b.offset; });
    definition.size = size != 0 ? size : kDefaultStructSize;
    if (!definition.fields.empty()) {
        definition.size = std::max(definition.size, definition.fields.back().end(pointer_size));
    }
    return definition;
}

StructDefinition read_struct_file(const std::filesystem::path& path, unsigned pointer_size) {
    const std::string name = wide_to_utf8(path.wstring());
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw Error(ErrorCode::Io, "cannot open '" + name + "'");
    }
    const std::string text{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    if (in.bad()) {
        throw Error(ErrorCode::Io, "cannot read '" + name + "'");
    }
    try {
        return parse_struct_definition(text, pointer_size);
    } catch (const Error& error) {
        throw Error(error.code(), "'" + name + "' " + error.what());
    }
}

void write_struct_file(const std::filesystem::path& path, const StructDefinition& definition) {
    const std::string name = wide_to_utf8(path.wstring());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw Error(ErrorCode::Io, "cannot create '" + name + "'");
    }
    out << format_struct_definition(definition);
    out.close();
    if (!out) {
        throw Error(ErrorCode::Io, "cannot write '" + name + "' (disk full?)");
    }
}

std::string c_declaration(std::span<const StructField> fields, std::uint32_t size, unsigned pointer_size) {
    std::string text = "struct Struct {\n";
    std::set<std::string> used;
    std::uint32_t cursor = 0;
    const auto pad = [&](std::uint32_t end) {
        if (end > cursor) {
            text += "    char pad_" + pad_name(cursor) + "[" + format_hex(end - cursor) + "];\n";
            cursor = end;
        }
    };
    for (const StructField& field : fields) {
        if (field.offset < cursor) {
            continue;
        }
        if (field.type == FieldType::Bytes && field.name.empty()) {
            continue;
        }
        pad(field.offset);
        text += "    " + c_type(field.type, pointer_size) + " " + identifier(field.name, field.offset, "field_", used);
        if (has_length(field.type)) {
            text += "[" + std::to_string(field.length) + "]";
        }
        text += ";  // " + format_hex(field.offset) + "\n";
        cursor = field.end(pointer_size);
    }
    pad(std::max(size, cursor));
    return text + "};  // " + format_hex(std::max(size, cursor)) + "\n";
}

}  // namespace mh
