#include "structure/struct_layout.hpp"

#include <algorithm>
#include <bit>
#include <cmath>
#include <cstring>

#include "common/text.hpp"

namespace mh {

namespace {

constexpr std::uint64_t kLowestPointer = 0x10000;
constexpr std::uint32_t kMinZeroRun = 8;
constexpr std::size_t kShownBytes = 16;

std::uint32_t align_down(std::uint32_t value, std::uint32_t alignment) {
    return value / alignment * alignment;
}

std::string_view trim(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) {
        text.remove_prefix(1);
    }
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) {
        text.remove_suffix(1);
    }
    return text;
}

class Bytes {
public:
    Bytes(const MemoryDump& dump, std::uint32_t end) : dump_(dump), end_(static_cast<std::uint32_t>(std::min<std::size_t>(end, dump.bytes.size()))) {}

    bool readable(std::uint32_t offset) const { return offset < end_ && dump_.readable[offset] != 0; }
    bool readable(std::uint32_t offset, std::uint32_t size) const {
        for (std::uint32_t i = 0; i < size; ++i) {
            if (!readable(offset + i)) {
                return false;
            }
        }
        return true;
    }
    std::uint8_t at(std::uint32_t offset) const { return static_cast<std::uint8_t>(dump_.bytes[offset]); }
    std::uint64_t value(std::uint32_t offset, std::uint32_t size) const {
        std::uint64_t bits = 0;
        std::memcpy(&bits, dump_.bytes.data() + offset, size);
        return bits;
    }
    std::uint16_t unit(std::uint32_t offset) const { return static_cast<std::uint16_t>(value(offset, 2)); }

private:
    const MemoryDump& dump_;
    std::uint32_t end_;
};

bool printable(std::uint8_t c) {
    return c >= 0x20 && c < 0x7F;
}

// Latin, Greek and Cyrillic: the halves of a float such as 0.3f (0x3E99999A) fall into CJK and Hangul.
bool text_unit(std::uint16_t u) {
    return (u >= 0x20 && u < 0x7F) || (u >= 0xA0 && u < 0x250) || (u >= 0x370 && u < 0x530);
}

bool nice_float(std::uint32_t bits) {
    const float value = std::bit_cast<float>(bits);
    return std::isnormal(value) && std::fabs(value) >= 1e-3f && std::fabs(value) <= 1e7f;
}

// Four printable bytes such as "fff@" that make a float with at most two decimals, 3.6, are not text.
bool round_float(std::uint32_t bits) {
    const float value = std::bit_cast<float>(bits);
    return nice_float(bits) && static_cast<float>(std::round(static_cast<double>(value) * 100) / 100) == value;
}

// A double with at most two decimals: a coordinate or an amount rather than two halves of something else.
bool nice_double(std::uint64_t bits) {
    const double value = std::bit_cast<double>(bits);
    if (!std::isnormal(value) || std::fabs(value) < 1e-3 || std::fabs(value) > 1e12) {
        return false;
    }
    const double hundredths = value * 100;
    return std::fabs(hundredths - std::round(hundredths)) < 1e-6;
}

// The bytes of a text that starts with `length` characters: its terminating zero and the zeros up to the next multiple
// of 4 belong to it, other bytes up to that multiple do not.
std::uint32_t text_bytes(const Bytes& bytes, std::uint32_t offset, std::uint32_t used, std::uint32_t unit, std::uint32_t end) {
    const auto zero_at = [&](std::uint32_t at) { return at + unit <= end && bytes.readable(at, unit) && bytes.value(at, unit) == 0; };
    if (zero_at(offset + used)) {
        used += unit;
        while (used % 4 != 0 && zero_at(offset + used)) {
            used += unit;
        }
    }
    return used % 4 == 0 ? used : align_down(used, 4);
}

std::uint32_t ascii_length(const Bytes& bytes, std::uint32_t offset, std::uint32_t end) {
    std::uint32_t length = 0;
    while (offset + length < end && bytes.readable(offset + length) && printable(bytes.at(offset + length))) {
        ++length;
    }
    return length;
}

std::uint32_t utf16_length(const Bytes& bytes, std::uint32_t offset, std::uint32_t end) {
    std::uint32_t units = 0;
    while (offset + units * 2 + 2 <= end && bytes.readable(offset + units * 2, 2) && text_unit(bytes.unit(offset + units * 2))) {
        ++units;
    }
    return units;
}

std::uint32_t zero_run(const Bytes& bytes, std::uint32_t offset, std::uint32_t end) {
    std::uint32_t length = 0;
    while (offset + length < end && bytes.readable(offset + length) && bytes.at(offset + length) == 0) {
        ++length;
    }
    return length;
}

std::uint32_t unreadable_run(const Bytes& bytes, std::uint32_t offset, std::uint32_t end) {
    std::uint32_t length = 0;
    while (offset + length < end && !bytes.readable(offset + length)) {
        ++length;
    }
    return length;
}

StructField guess_one(const Bytes& bytes, std::uint32_t offset, std::uint32_t end, const PointerTargets& targets, unsigned pointer_size) {
    const std::uint32_t left = end - offset;
    const auto make = [&](FieldType type, std::uint32_t length = 0) { return StructField{offset, type, length, {}, false}; };
    if (offset % 4 != 0) {
        return make(FieldType::Bytes, std::min(4 - offset % 4, left));
    }
    if (const std::uint32_t unreadable = unreadable_run(bytes, offset, end); unreadable != 0) {
        return make(FieldType::Bytes, unreadable);
    }
    if (left < 4 || !bytes.readable(offset, 4)) {
        std::uint32_t readable = 1;
        while (readable < std::min(left, 4u) && bytes.readable(offset + readable)) {
            ++readable;
        }
        return make(FieldType::Bytes, readable);
    }
    if (offset % pointer_size == 0 && left >= pointer_size && bytes.readable(offset, pointer_size)) {
        const std::uint64_t value = bytes.value(offset, pointer_size);
        if (value >= kLowestPointer && targets.contains(value)) {
            return make(FieldType::Pointer);
        }
    }
    if (const std::uint32_t length = ascii_length(bytes, offset, end);
        length >= 4 && !round_float(static_cast<std::uint32_t>(bytes.value(offset, 4)))) {
        return make(FieldType::Ascii, text_bytes(bytes, offset, length, 1, end));
    }
    if (const std::uint32_t units = utf16_length(bytes, offset, end); units >= 3) {
        const std::uint32_t size = text_bytes(bytes, offset, units * 2, 2, end);
        if (size >= 4) {
            return make(FieldType::Utf16, size / 2);
        }
    }
    if (const std::uint32_t zeros = zero_run(bytes, offset, end); zeros >= kMinZeroRun) {
        return make(FieldType::Bytes, align_down(zeros, 4));
    }
    if (offset % 8 == 0 && left >= 8 && bytes.readable(offset, 8)) {
        const std::uint64_t value = bytes.value(offset, 8);
        const bool halves = nice_float(static_cast<std::uint32_t>(value)) && nice_float(static_cast<std::uint32_t>(value >> 32));
        if (nice_double(value) && !halves) {
            return make(FieldType::Double);
        }
    }
    if (nice_float(static_cast<std::uint32_t>(bytes.value(offset, 4)))) {
        return make(FieldType::Float);
    }
    return make(FieldType::Int32);
}

std::span<const std::byte> without_zero_tail(std::span<const std::byte> bytes, std::size_t unit) {
    std::size_t units = 0;
    while ((units + 1) * unit <= bytes.size()) {
        bool zero = true;
        for (std::size_t i = 0; i < unit; ++i) {
            zero = zero && bytes[units * unit + i] == std::byte{0};
        }
        if (zero) {
            break;
        }
        ++units;
    }
    return bytes.first(units * unit);
}

}  // namespace

std::uint32_t StructField::size(unsigned pointer_size) const noexcept {
    switch (type) {
        case FieldType::Int8: return 1;
        case FieldType::Int16: return 2;
        case FieldType::Int32:
        case FieldType::Float: return 4;
        case FieldType::Int64:
        case FieldType::Double: return 8;
        case FieldType::Pointer: return pointer_size;
        case FieldType::Ascii:
        case FieldType::Bytes: return length;
        case FieldType::Utf16: return length * 2;
    }
    return 0;
}

bool has_length(FieldType type) noexcept {
    return type == FieldType::Ascii || type == FieldType::Utf16 || type == FieldType::Bytes;
}

std::optional<ValueType> field_value_type(FieldType type) noexcept {
    return type <= FieldType::Double ? std::optional(static_cast<ValueType>(type)) : std::nullopt;
}

std::string field_type_name(FieldType type, std::uint32_t length) {
    switch (type) {
        case FieldType::Pointer: return "pointer";
        case FieldType::Ascii: return "ascii[" + std::to_string(length) + "]";
        case FieldType::Utf16: return "utf16[" + std::to_string(length) + "]";
        case FieldType::Bytes: return "bytes[" + std::to_string(length) + "]";
        default: return std::string(to_string(*field_value_type(type)));
    }
}

std::string field_type_name(const StructField& field) {
    return field_type_name(field.type, field.length);
}

std::optional<std::pair<FieldType, std::uint32_t>> parse_field_type(std::string_view text) {
    const std::string lower = to_lower_ascii(trim(text));
    const std::size_t open = lower.find('[');
    const std::string_view name = std::string_view(lower).substr(0, open);
    static constexpr std::pair<std::string_view, FieldType> kNames[] = {
        {"int8", FieldType::Int8},   {"int16", FieldType::Int16},     {"int32", FieldType::Int32}, {"int64", FieldType::Int64},
        {"float", FieldType::Float}, {"double", FieldType::Double},   {"pointer", FieldType::Pointer},
        {"ascii", FieldType::Ascii}, {"utf16", FieldType::Utf16},     {"bytes", FieldType::Bytes},
    };
    const auto known = std::find_if(std::begin(kNames), std::end(kNames), [&](const auto& entry) { return entry.first == name; });
    if (known == std::end(kNames)) {
        return std::nullopt;
    }
    const FieldType type = known->second;
    if (!has_length(type)) {
        return open == std::string::npos ? std::optional(std::pair(type, 0u)) : std::nullopt;
    }
    if (open == std::string::npos || lower.back() != ']') {
        return std::nullopt;
    }
    const auto length = parse_uint(std::string_view(lower).substr(open + 1, lower.size() - open - 2));
    if (!length || *length == 0 || *length > kMaxFieldLength) {
        return std::nullopt;
    }
    return std::pair(type, static_cast<std::uint32_t>(*length));
}

PointerTargets::PointerTargets(std::span<const Region> regions) {
    for (const Region& region : regions) {
        if (region.state == MemState::Commit && region.readable()) {
            ranges_.push_back({region.base, region.end()});
        }
    }
    std::sort(ranges_.begin(), ranges_.end(), [](const AddressRange& a, const AddressRange& b) { return a.begin < b.begin; });
    std::vector<AddressRange> merged;
    for (const AddressRange& range : ranges_) {
        if (!merged.empty() && range.begin <= merged.back().end) {
            merged.back().end = std::max(merged.back().end, range.end);
        } else {
            merged.push_back(range);
        }
    }
    ranges_ = std::move(merged);
}

bool PointerTargets::contains(std::uint64_t address) const noexcept {
    const auto after = std::upper_bound(ranges_.begin(), ranges_.end(), address,
                                        [](std::uint64_t value, const AddressRange& range) { return value < range.begin; });
    return after != ranges_.begin() && std::prev(after)->contains(address);
}

std::vector<StructField> guess_fields(const MemoryDump& dump, std::uint32_t begin, std::uint32_t end, const PointerTargets& targets,
                                      unsigned pointer_size) {
    const Bytes bytes(dump, end);
    std::vector<StructField> fields;
    std::uint32_t offset = begin;
    while (offset < end) {
        StructField field = guess_one(bytes, offset, end, targets, pointer_size);
        offset = field.end(pointer_size);
        fields.push_back(std::move(field));
    }
    return fields;
}

std::vector<StructField> layout_struct(std::span<const StructField> defined, const MemoryDump& dump, std::uint32_t size,
                                       const PointerTargets& targets, unsigned pointer_size) {
    std::vector<StructField> sorted(defined.begin(), defined.end());
    std::stable_sort(sorted.begin(), sorted.end(), [](const StructField& a, const StructField& b) { return a.offset < b.offset; });
    std::vector<StructField> fields;
    std::uint32_t cursor = 0;
    for (StructField& field : sorted) {
        if (field.offset < cursor || field.size(pointer_size) == 0) {
            continue;
        }
        auto gap = guess_fields(dump, cursor, field.offset, targets, pointer_size);
        fields.insert(fields.end(), std::make_move_iterator(gap.begin()), std::make_move_iterator(gap.end()));
        cursor = field.end(pointer_size);
        field.defined = true;
        fields.push_back(std::move(field));
    }
    auto tail = guess_fields(dump, cursor, std::max(cursor, size), targets, pointer_size);
    fields.insert(fields.end(), std::make_move_iterator(tail.begin()), std::make_move_iterator(tail.end()));
    return fields;
}

std::span<const std::byte> field_bytes(const StructField& field, const MemoryDump& dump, unsigned pointer_size) {
    const std::uint64_t begin = dump.address + field.offset;
    const std::uint32_t size = field.size(pointer_size);
    if (size == 0 || !dump.all_readable(begin, begin + size)) {
        return {};
    }
    return std::span(dump.bytes).subspan(field.offset, size);
}

std::string format_field_value(const StructField& field, const MemoryDump& dump, const ModuleMap& modules, unsigned pointer_size) {
    const auto bytes = field_bytes(field, dump, pointer_size);
    if (bytes.empty()) {
        return "??";
    }
    std::uint64_t bits = 0;
    std::memcpy(&bits, bytes.data(), std::min(bytes.size(), sizeof(bits)));
    switch (field.type) {
        case FieldType::Pointer: {
            if (const Module* module = modules.locate(bits)) {
                return format_pointer_base(module->name, bits - module->base);
            }
            return format_address(bits);
        }
        case FieldType::Ascii: return "\"" + ascii_preview(without_zero_tail(bytes, 1)) + "\"";
        case FieldType::Utf16: return "\"" + utf16_preview(without_zero_tail(bytes, 2)) + "\"";
        case FieldType::Bytes: {
            if (bytes.size() >= kMinZeroRun && std::all_of(bytes.begin(), bytes.end(), [](std::byte b) { return b == std::byte{0}; })) {
                return "00 × " + std::to_string(bytes.size());
            }
            if (bytes.size() > kShownBytes) {
                return hex_preview(bytes.first(kShownBytes)) + " …";
            }
            return hex_preview(bytes);
        }
        default: return format_value(*field_value_type(field.type), bits);
    }
}

std::optional<std::uint64_t> field_pointer(const StructField& field, const MemoryDump& dump, unsigned pointer_size) {
    if (field.type != FieldType::Pointer) {
        return std::nullopt;
    }
    const auto bytes = field_bytes(field, dump, pointer_size);
    if (bytes.empty()) {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    std::memcpy(&value, bytes.data(), bytes.size());
    return value;
}

std::string format_struct_base(const PointerPath& base) {
    std::string text = format_pointer_path(base);
    if (!base.offsets.empty() && base.offsets.back() == 0) {
        text.resize(text.size() - 4);
    }
    return text;
}

PointerPath field_path(PointerPath base, std::uint32_t offset) {
    if (base.offsets.empty()) {
        base.base_offset += offset;
    } else {
        base.offsets.back() += offset;
    }
    return base;
}

PointerPath pointee_path(PointerPath base, std::uint32_t offset) {
    PointerPath path = field_path(std::move(base), offset);
    path.offsets.push_back(0);
    return path;
}

std::pair<PointerPath, std::uint32_t> split_field_path(PointerPath path) {
    if (path.offsets.empty()) {
        return {std::move(path), 0};
    }
    const std::uint32_t offset = path.offsets.back();
    path.offsets.back() = 0;
    return {std::move(path), offset};
}

}  // namespace mh
