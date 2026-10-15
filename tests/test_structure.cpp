#include <gtest/gtest.h>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

#include "common/error.hpp"
#include "common/text.hpp"
#include "structure/struct_file.hpp"
#include "structure/struct_layout.hpp"
#include "support/fake_memory.hpp"

namespace mh {
namespace {

using testing::FakeMemory;

template <typename T>
void put(FakeMemory& memory, std::uint64_t address, T value) {
    std::memcpy(memory.bytes_at(address, sizeof(T)).data(), &value, sizeof(T));
}

void put_text(FakeMemory& memory, std::uint64_t address, std::string_view text) {
    std::memcpy(memory.bytes_at(address, text.size()).data(), text.data(), text.size());
}

void put_text(FakeMemory& memory, std::uint64_t address, std::u16string_view text) {
    std::memcpy(memory.bytes_at(address, text.size() * 2).data(), text.data(), text.size() * 2);
}

StructField field(std::uint32_t offset, FieldType type, std::uint32_t length = 0, std::string name = {}, bool defined = false) {
    return {offset, type, length, std::move(name), defined};
}

std::string describe(const std::vector<StructField>& fields) {
    std::string text;
    for (const StructField& f : fields) {
        text += format_hex(f.offset) + " " + field_type_name(f) + (f.name.empty() ? "" : " " + f.name) + (f.defined ? " *" : "") + "\n";
    }
    return text;
}

// A player much like the one of memhunter_practice, followed by pointers, a double and zeros.
class Structure : public ::testing::Test {
protected:
    static constexpr std::uint64_t kGame = 0x140000000;
    static constexpr std::uint64_t kHeap = 0x200000;
    static constexpr std::uint64_t kPlayer = kHeap + 0x1000;
    FakeMemory memory;

    void SetUp() override {
        memory.add_image(kGame, 0x2000, "C:\\Games\\game.exe");
        memory.add(kHeap, 0x10000);
        put_text(memory, kPlayer, "PLR1");
        put<std::uint32_t>(memory, kPlayer + 0x04, 1);
        put_text(memory, kPlayer + 0x08, "Stalker_Ivan");
        put_text(memory, kPlayer + 0x20, u"Вольный сталкер");
        put<std::int32_t>(memory, kPlayer + 0x50, 86);
        put<std::int32_t>(memory, kPlayer + 0x54, 100);
        put<std::int32_t>(memory, kPlayer + 0x58, 15000);
        put<std::int32_t>(memory, kPlayer + 0x5C, 7);
        put<std::int64_t>(memory, kPlayer + 0x60, 64200);
        put<float>(memory, kPlayer + 0x68, 102.5f);
        put<float>(memory, kPlayer + 0x6C, 4.0f);
        put<float>(memory, kPlayer + 0x70, -37.25f);
        put<float>(memory, kPlayer + 0x74, 35.0f);
        put<std::uint32_t>(memory, kPlayer + 0x78, 29100);
        put<std::uint32_t>(memory, kPlayer + 0x7C, 7);
        put<std::uint64_t>(memory, kPlayer + 0x80, kHeap + 0x2000);
        put<std::uint64_t>(memory, kPlayer + 0x88, kGame + 0x1010);
        put<double>(memory, kPlayer + 0x90, 1234.5);
    }

    MemoryDump dump(std::uint32_t size = 0xC0) const { return read_dump(memory, kPlayer, size); }
    PointerTargets targets() const { return PointerTargets(memory.query_regions()); }
};

constexpr std::string_view kGuessedPlayer =
    "0x0 ascii[4]\n0x4 int32\n0x8 ascii[16]\n0x18 bytes[8]\n0x20 utf16[16]\n0x40 bytes[16]\n0x50 int32\n0x54 int32\n"
    "0x58 int32\n0x5C int32\n0x60 int32\n0x64 int32\n0x68 float\n0x6C float\n0x70 float\n0x74 float\n0x78 int32\n0x7C int32\n"
    "0x80 pointer\n0x88 pointer\n0x90 double\n0x98 bytes[40]\n";

TEST(StructFields, TypeNamesAndSizes) {
    EXPECT_EQ(field_type_name(FieldType::Int32, 0), "int32");
    EXPECT_EQ(field_type_name(FieldType::Pointer, 0), "pointer");
    EXPECT_EQ(field_type_name(FieldType::Ascii, 16), "ascii[16]");
    EXPECT_EQ(field_type_name(FieldType::Utf16, 24), "utf16[24]");
    EXPECT_EQ(field_type_name(FieldType::Bytes, 8), "bytes[8]");
    EXPECT_EQ(field(0, FieldType::Pointer).size(8), 8u);
    EXPECT_EQ(field(0, FieldType::Pointer).size(4), 4u);
    EXPECT_EQ(field(0, FieldType::Utf16, 24).size(8), 48u);
    EXPECT_EQ(field(0x10, FieldType::Double).end(8), 0x18u);
    EXPECT_EQ(field_value_type(FieldType::Float), ValueType::Float);
    EXPECT_EQ(field_value_type(FieldType::Pointer), std::nullopt);

    for (const FieldType type : {FieldType::Int8, FieldType::Int16, FieldType::Int32, FieldType::Int64, FieldType::Float,
                                 FieldType::Double, FieldType::Pointer}) {
        EXPECT_EQ(parse_field_type(field_type_name(type, 0)), std::pair(type, 0u));
    }
    EXPECT_EQ(parse_field_type("ASCII[16]"), std::pair(FieldType::Ascii, 16u));
    EXPECT_EQ(parse_field_type(" utf16[0x18] "), std::pair(FieldType::Utf16, 24u));
    EXPECT_EQ(parse_field_type("bytes[4096]"), std::pair(FieldType::Bytes, 4096u));
    for (const char* bad : {"", "int33", "ascii", "ascii[]", "ascii[0]", "bytes[4097]", "bytes[x]", "pointer[2]", "int32[4]", "utf16[3"}) {
        EXPECT_EQ(parse_field_type(bad), std::nullopt) << bad;
    }
}

TEST_F(Structure, GuessesThePlayer) {
    EXPECT_EQ(describe(guess_fields(dump(), 0, 0xC0, targets(), 8)), kGuessedPlayer);
}

TEST_F(Structure, FloatsInFrontOfTextAreNotText) {
    const std::uint64_t item = kHeap + 0x3000;
    put<float>(memory, item, 3.6f);
    put_text(memory, item + 0x04, "AK-74");
    put<float>(memory, item + 0x10, 0.3f);
    put_text(memory, item + 0x14, "Medkit");
    put<std::int16_t>(memory, item + 0x20, 120);
    put<std::int16_t>(memory, item + 0x22, 100);
    put<float>(memory, item + 0x24, 1.2f);
    put_text(memory, item + 0x28, u"Аптечка");
    EXPECT_EQ(describe(guess_fields(read_dump(memory, item, 0x38), 0, 0x38, targets(), 8)),
              "0x0 float\n0x4 ascii[8]\n0xC int32\n0x10 float\n0x14 ascii[8]\n0x1C int32\n0x20 int32\n0x24 float\n0x28 utf16[8]\n");
}

TEST_F(Structure, GuessesFromAnOffsetAndUpToAnUnalignedEnd) {
    EXPECT_EQ(describe(guess_fields(dump(), 0x52, 0x5B, targets(), 8)), "0x52 bytes[2]\n0x54 int32\n0x58 bytes[3]\n");
}

TEST_F(Structure, UnreadableBytesAreNotGuessed) {
    memory.fail_page(kHeap + 0x2000);
    const MemoryDump around = read_dump(memory, kHeap + 0x1FF0, 0x30);
    EXPECT_EQ(describe(guess_fields(around, 0, 0x30, targets(), 8)), "0x0 bytes[16]\n0x10 bytes[32]\n");
    EXPECT_EQ(format_field_value(field(0x10, FieldType::Bytes, 32), around, ModuleMap{}, 8), "??");
    EXPECT_EQ(format_field_value(field(0x8, FieldType::Int64), around, ModuleMap{}, 8), "0");
    EXPECT_EQ(format_field_value(field(0xC, FieldType::Int64), around, ModuleMap{}, 8), "??");
    EXPECT_TRUE(field_bytes(field(0xC, FieldType::Int64), around, 8).empty());
}

TEST_F(Structure, ThirtyTwoBitPointers) {
    put<std::uint32_t>(memory, kPlayer + 0x04, static_cast<std::uint32_t>(kHeap + 0x3000));
    const auto fields = guess_fields(dump(0x10), 0, 0x10, targets(), 4);
    ASSERT_GE(fields.size(), 2u);
    EXPECT_EQ(fields[1], field(0x4, FieldType::Pointer));
    EXPECT_EQ(field_pointer(fields[1], dump(0x10), 4), kHeap + 0x3000);
}

TEST_F(Structure, DefinedFieldsWinAndGapsAreGuessed) {
    const std::vector<StructField> defined{field(0x08, FieldType::Ascii, 24, "name", true), field(0x50, FieldType::Int32, 0, "health", true),
                                           field(0x52, FieldType::Int32, 0, "overlap", true),
                                           field(0x60, FieldType::Int64, 0, "experience", true)};
    const auto fields = layout_struct(defined, dump(), 0xC0, targets(), 8);
    EXPECT_EQ(describe(fields),
              "0x0 ascii[4]\n0x4 int32\n0x8 ascii[24] name *\n0x20 utf16[16]\n0x40 bytes[16]\n0x50 int32 health *\n0x54 int32\n"
              "0x58 int32\n0x5C int32\n0x60 int64 experience *\n0x68 float\n0x6C float\n0x70 float\n0x74 float\n0x78 int32\n"
              "0x7C int32\n0x80 pointer\n0x88 pointer\n0x90 double\n0x98 bytes[40]\n");

    const auto past = layout_struct(std::vector{field(0x60, FieldType::Int64, 0, "experience", true)}, dump(), 0x58, targets(), 8);
    ASSERT_FALSE(past.empty());
    EXPECT_EQ(past.back(), field(0x60, FieldType::Int64, 0, "experience", true));
    EXPECT_EQ(past[past.size() - 2], field(0x5C, FieldType::Int32));
}

TEST_F(Structure, ShowsValues) {
    const MemoryDump player = dump();
    const ModuleMap modules(memory.query_regions());
    const auto value = [&](std::uint32_t offset, FieldType type, std::uint32_t length = 0) {
        return format_field_value(field(offset, type, length), player, modules, 8);
    };
    EXPECT_EQ(value(0x00, FieldType::Ascii, 4), "\"PLR1\"");
    EXPECT_EQ(value(0x00, FieldType::Bytes, 4), "50 4C 52 31");
    EXPECT_EQ(value(0x08, FieldType::Ascii, 24), "\"Stalker_Ivan\"");
    EXPECT_EQ(value(0x20, FieldType::Utf16, 24), "\"Вольный сталкер\"");
    EXPECT_EQ(value(0x50, FieldType::Int32), "86");
    EXPECT_EQ(value(0x50, FieldType::Int8), "86");
    EXPECT_EQ(value(0x60, FieldType::Int64), "64200");
    EXPECT_EQ(value(0x70, FieldType::Float), "-37.25");
    EXPECT_EQ(value(0x90, FieldType::Double), "1234.5");
    EXPECT_EQ(value(0x80, FieldType::Pointer), format_address(kHeap + 0x2000));
    EXPECT_EQ(value(0x88, FieldType::Pointer), "game.exe+0x1010");
    EXPECT_EQ(value(0x98, FieldType::Bytes, 40), "00 × 40");
    EXPECT_EQ(value(0x08, FieldType::Bytes, 20), "53 74 61 6C 6B 65 72 5F 49 76 61 6E 00 00 00 00 …");
    EXPECT_EQ(value(0xBC, FieldType::Int64), "??");
    EXPECT_EQ(field_pointer(field(0x80, FieldType::Pointer), player, 8), kHeap + 0x2000);
    EXPECT_EQ(field_pointer(field(0x80, FieldType::Int64), player, 8), std::nullopt);
}

TEST(StructBase, PathsToFieldsAndPointees) {
    const PointerPath base{"game.exe", 0x52080, {0x8, 0}, 8};
    EXPECT_EQ(format_struct_base(base), "[[game.exe+0x52080]+0x8]");
    EXPECT_EQ(format_struct_base({"game.exe", 0x52080, {0x8, 0x10}, 8}), "[[game.exe+0x52080]+0x8]+0x10");
    EXPECT_EQ(format_struct_base({"", 0x1F4A2C3B0D8, {}, 8}), "0x1F4A2C3B0D8");
    EXPECT_EQ(parse_pointer_path(format_struct_base(base), 8), base);

    EXPECT_EQ(field_path(base, 0x50), (PointerPath{"game.exe", 0x52080, {0x8, 0x50}, 8}));
    EXPECT_EQ(field_path({"game.exe", 0x100, {}, 8}, 0x50), (PointerPath{"game.exe", 0x150, {}, 8}));
    EXPECT_EQ(pointee_path(base, 0x10), (PointerPath{"game.exe", 0x52080, {0x8, 0x10, 0}, 8}));
    EXPECT_EQ(pointee_path({"", 0x5000, {}, 4}, 0x8), (PointerPath{"", 0x5008, {0}, 4}));
    EXPECT_EQ(split_field_path({"game.exe", 0x52080, {0x8, 0x50}, 8}), std::pair(base, 0x50u));
    EXPECT_EQ(split_field_path({"game.exe", 0x100, {}, 8}), std::pair(PointerPath{"game.exe", 0x100, {}, 8}, 0u));
}

TEST(StructDefinitions, RoundTrip) {
    StructDefinition definition;
    definition.size = 0x90;
    definition.fields = {field(0x08, FieldType::Ascii, 24, "name", true), field(0x50, FieldType::Int32, 0, "health", true),
                         field(0x80, FieldType::Pointer, 0, "", true)};
    const std::string text = format_struct_definition(definition);
    EXPECT_NE(text.find("size 0x90\n"), std::string::npos) << text;
    EXPECT_NE(text.find("0x50 int32 health\n"), std::string::npos) << text;
    EXPECT_NE(text.find("0x80 pointer\n"), std::string::npos) << text;
    const StructDefinition parsed = parse_struct_definition(text, 8);
    EXPECT_EQ(parsed.size, definition.size);
    EXPECT_EQ(parsed.fields, definition.fields);
}

TEST(StructDefinitions, ReadsWhatPeopleWrite) {
    const StructDefinition parsed =
        parse_struct_definition("\xEF\xBB\xBF# player\r\n\r\n  0x60   INT64   experience points  \r\n0x50 int32 health # current\n112 float x\nsize 16\n", 8);
    EXPECT_EQ(parsed.size, 0x74u);
    EXPECT_EQ(describe(parsed.fields), "0x50 int32 health *\n0x60 int64 experience points *\n0x70 float x *\n");
}

TEST(StructDefinitions, ReportsTheLine) {
    const auto message = [](std::string_view text) {
        try {
            parse_struct_definition(text, 8);
        } catch (const Error& error) {
            EXPECT_EQ(error.code(), ErrorCode::CorruptSnapshot);
            return std::string(error.what());
        }
        return std::string("no error");
    };
    EXPECT_NE(message("0x50 int32 a\n0x52 int32 b\n").find("line 2"), std::string::npos);
    EXPECT_NE(message("0x50 int32 a\n0x52 int32 b\n").find("overlaps"), std::string::npos);
    EXPECT_NE(message("# x\n0x50 int33 a\n").find("line 2"), std::string::npos);
    EXPECT_NE(message("zz int32 a\n").find("line 1"), std::string::npos);
    EXPECT_NE(message("0x50\n").find("line 1"), std::string::npos);
    EXPECT_NE(message("0x10000 int8 a\n").find("line 1"), std::string::npos);
    EXPECT_NE(message("size 0x10001\n").find("line 1"), std::string::npos);
    EXPECT_NE(message("size\n").find("line 1"), std::string::npos);
}

TEST(StructDefinitions, Files) {
    const auto directory = std::filesystem::temp_directory_path() / "memhunter-struct-тест";
    std::filesystem::create_directories(directory);
    StructDefinition definition;
    definition.fields = {field(0x50, FieldType::Int32, 0, "здоровье", true)};
    write_struct_file(directory / "player.mhst", definition);
    const StructDefinition read = read_struct_file(directory / "player.mhst", 8);
    EXPECT_EQ(read.fields, definition.fields);
    EXPECT_EQ(read.size, kDefaultStructSize);
    EXPECT_THROW(read_struct_file(directory / "missing.mhst", 8), Error);
    std::filesystem::remove_all(directory);
}

TEST(StructDeclaration, PadsGapsAndNamesFields) {
    const std::vector<StructField> fields{field(0x08, FieldType::Ascii, 24, "name", true), field(0x20, FieldType::Utf16, 24, "rank"),
                                          field(0x50, FieldType::Int32, 0, "max health", true), field(0x54, FieldType::Int32, 0, "1st"),
                                          field(0x58, FieldType::Bytes, 8), field(0x60, FieldType::Int64, 0, "max health"),
                                          field(0x68, FieldType::Float), field(0x70, FieldType::Double, 0, "d"),
                                          field(0x78, FieldType::Pointer), field(0x80, FieldType::Int8), field(0x82, FieldType::Int16),
                                          field(0x84, FieldType::Bytes, 4, "raw")};
    EXPECT_EQ(c_declaration(fields, 0x90, 8),
              "struct Struct {\n"
              "    char pad_0000[0x8];\n"
              "    char name[24];  // 0x8\n"
              "    wchar_t rank[24];  // 0x20\n"
              "    int32_t max_health;  // 0x50\n"
              "    int32_t _1st;  // 0x54\n"
              "    char pad_0058[0x8];\n"
              "    int64_t max_health_2;  // 0x60\n"
              "    float field_0068;  // 0x68\n"
              "    char pad_006C[0x4];\n"
              "    double d;  // 0x70\n"
              "    void* field_0078;  // 0x78\n"
              "    int8_t field_0080;  // 0x80\n"
              "    char pad_0081[0x1];\n"
              "    int16_t field_0082;  // 0x82\n"
              "    uint8_t raw[4];  // 0x84\n"
              "    char pad_0088[0x8];\n"
              "};  // 0x90\n");
    EXPECT_EQ(c_declaration(std::vector{field(0x0, FieldType::Pointer)}, 0x4, 4), "struct Struct {\n    uint32_t field_0000;  // 0x0\n};  // 0x4\n");
}

}  // namespace
}  // namespace mh
