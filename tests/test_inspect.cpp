#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>
#include <map>
#include <set>
#include <sstream>

#include "common/error.hpp"
#include "common/text.hpp"
#include "inspect/inspect.hpp"
#include "inspect/pe_image.hpp"
#include "inspect/process_inspect.hpp"
#include "process/privilege.hpp"
#include "process/process.hpp"
#include "support/child_process.hpp"
#include "support/fake_memory.hpp"
#include "support/target_process.hpp"

namespace mh {
namespace {

using testing::FakeMemory;

constexpr std::uint64_t kImageBase64 = 0x180000000;
constexpr std::uint64_t kImageBase32 = 0x10000000;
constexpr std::uint32_t kImageSize = 0x4000;
constexpr std::uint32_t kTextRva = 0x1000;
constexpr std::uint32_t kRdataRva = 0x2000;
constexpr std::uint32_t kRelocRva = 0x3000;
// .rdata has less raw data than it maps; the rest of it is zeros.
constexpr std::uint32_t kRdataRaw = 0x200;
constexpr std::uint32_t kPointerRva = 0x1010;
constexpr std::uint32_t kOverrideRva = 0x1040;
constexpr std::uint32_t kExportRva = 0x1800;
constexpr std::uint32_t kTimestamp = 0x5EED0001;

template <typename T>
void put(std::vector<std::byte>& bytes, std::size_t at, T value) {
    std::memcpy(bytes.data() + at, &value, sizeof(T));
}

template <typename T>
T get(std::span<const std::byte> bytes, std::size_t at) {
    T value;
    std::memcpy(&value, bytes.data() + at, sizeof(T));
    return value;
}

// A DLL with .text, .rdata (holding the load configuration) and .reloc (base relocations and a dynamic value
// relocation table with one function override site).
std::vector<std::byte> build_image(bool pe32_plus = true, std::uint32_t timestamp = kTimestamp) {
    constexpr std::size_t kTextRaw = 0x400;
    constexpr std::size_t kRdataOffset = 0x1400;
    constexpr std::size_t kRelocOffset = 0x1600;
    std::vector<std::byte> file(0x1800);
    put<std::uint16_t>(file, 0, 0x5A4D);
    put<std::uint32_t>(file, 0x3C, 0x80);
    put<std::uint32_t>(file, 0x80, 0x00004550);
    put<std::uint16_t>(file, 0x84, pe32_plus ? 0x8664 : 0x14C);
    put<std::uint16_t>(file, 0x86, 3);
    put<std::uint32_t>(file, 0x88, timestamp);
    const std::uint16_t optional_size = pe32_plus ? 0xF0 : 0xE0;
    put<std::uint16_t>(file, 0x94, optional_size);
    put<std::uint16_t>(file, 0x96, 0x2022);
    const std::size_t optional = 0x98;
    put<std::uint16_t>(file, optional, pe32_plus ? 0x20B : 0x10B);
    put<std::uint32_t>(file, optional + 16, kTextRva);
    if (pe32_plus) {
        put<std::uint64_t>(file, optional + 24, kImageBase64);
    } else {
        put<std::uint32_t>(file, optional + 28, static_cast<std::uint32_t>(kImageBase32));
    }
    put<std::uint32_t>(file, optional + 32, 0x1000);
    put<std::uint32_t>(file, optional + 36, 0x200);
    put<std::uint32_t>(file, optional + 56, kImageSize);
    put<std::uint32_t>(file, optional + 60, 0x400);
    const std::size_t count_at = optional + (pe32_plus ? 108 : 92);
    put<std::uint32_t>(file, count_at, 16);
    const auto directory = [&](std::size_t index, std::uint32_t rva, std::uint32_t size) {
        put(file, count_at + 4 + index * 8, rva);
        put(file, count_at + 8 + index * 8, size);
    };
    const auto section = [&](std::size_t index, const char* name, std::uint32_t rva, std::uint32_t virtual_size, std::uint32_t raw,
                             std::uint32_t raw_size, std::uint32_t characteristics) {
        const std::size_t at = optional + optional_size + index * 40;
        std::memcpy(file.data() + at, name, std::strlen(name));
        put(file, at + 8, virtual_size);
        put(file, at + 12, rva);
        put(file, at + 16, raw_size);
        put(file, at + 20, raw);
        put(file, at + 36, characteristics);
    };
    section(0, ".text", kTextRva, 0x1000, kTextRaw, 0x1000, 0x60000020);
    section(1, ".rdata", kRdataRva, 0x1000, kRdataOffset, kRdataRaw, 0x40000040);
    section(2, ".reloc", kRelocRva, 0x200, kRelocOffset, 0x200, 0x42000040);

    for (std::size_t i = 0; i < 0x1000; ++i) {
        file[kTextRaw + i] = static_cast<std::byte>(i * 7 + 1);
    }
    if (pe32_plus) {
        put<std::uint64_t>(file, kTextRaw + (kPointerRva - kTextRva), kImageBase64 + kRdataRva);
    } else {
        put<std::uint32_t>(file, kTextRaw + (kPointerRva - kTextRva), static_cast<std::uint32_t>(kImageBase32 + kRdataRva));
    }
    const std::uint16_t pointer_type = pe32_plus ? 10 : 3;
    put<std::uint32_t>(file, kRelocOffset, kTextRva);
    put<std::uint32_t>(file, kRelocOffset + 4, 12);
    put<std::uint16_t>(file, kRelocOffset + 8, static_cast<std::uint16_t>(pointer_type << 12 | (kPointerRva - kTextRva)));
    directory(5, kRelocRva, 12);
    directory(0, kExportRva, 0x40);

    const std::size_t field = pe32_plus ? 0xE0 : 0x88;
    put<std::uint32_t>(file, kRdataOffset, pe32_plus ? 0x148 : 0xC0);
    put<std::uint32_t>(file, kRdataOffset + field, 0x100);
    put<std::uint16_t>(file, kRdataOffset + field + 4, 3);
    directory(10, kRdataRva, pe32_plus ? 0x148 : 0xC0);
    directory(12, kRdataRva + 0x100, 0x40);

    std::size_t at = kRelocOffset + 0x100;
    const std::size_t entry_header = pe32_plus ? 12 : 8;
    put<std::uint32_t>(file, at, 1);
    put<std::uint32_t>(file, at + 4, static_cast<std::uint32_t>(entry_header + 36));
    at += 8;
    if (pe32_plus) {
        put<std::uint64_t>(file, at, 7);
    } else {
        put<std::uint32_t>(file, at, 7);
    }
    put<std::uint32_t>(file, at + entry_header - 4, 36);
    at += entry_header;
    put<std::uint32_t>(file, at, 32);
    put<std::uint32_t>(file, at + 4, 0x1800);
    put<std::uint32_t>(file, at + 8, 0);
    put<std::uint32_t>(file, at + 12, 4);
    put<std::uint32_t>(file, at + 16, 12);
    put<std::uint32_t>(file, at + 20, 0x1800);
    put<std::uint32_t>(file, at + 24, kTextRva);
    put<std::uint32_t>(file, at + 28, 12);
    put<std::uint16_t>(file, at + 32, static_cast<std::uint16_t>(1 << 12 | (kOverrideRva - kTextRva)));
    return file;
}

class ByteFile final : public FileReader {
public:
    explicit ByteFile(std::vector<std::byte> bytes) : bytes_(std::move(bytes)) {}

    std::uint64_t size() const override { return bytes_.size(); }

    bool read(std::uint64_t offset, std::span<std::byte> out) const override {
        if (offset > bytes_.size() || bytes_.size() - offset < out.size()) {
            return false;
        }
        std::memcpy(out.data(), bytes_.data() + offset, out.size());
        return true;
    }

private:
    std::vector<std::byte> bytes_;
};

std::shared_ptr<const PeFile> load_image(std::vector<std::byte> bytes) {
    return PeFile::load(std::make_unique<ByteFile>(std::move(bytes)));
}

std::vector<std::byte> mapped(const PeFile& file, std::uint64_t base) {
    std::vector<std::byte> image(kImageSize);
    EXPECT_TRUE(file.image_bytes(0, image, base));
    return image;
}

TEST(PeImage, ParsesTheHeadersOfA64BitDll) {
    const auto bytes = build_image();
    const auto headers = parse_pe_headers(bytes);
    ASSERT_TRUE(headers);
    EXPECT_TRUE(headers->pe32_plus);
    EXPECT_TRUE(headers->is_dll());
    EXPECT_EQ(headers->describe(), "64-bit DLL");
    EXPECT_EQ(headers->machine, 0x8664);
    EXPECT_EQ(headers->timestamp, kTimestamp);
    EXPECT_EQ(headers->image_base, kImageBase64);
    EXPECT_EQ(headers->size_of_image, kImageSize);
    EXPECT_EQ(headers->relocations.rva, kRelocRva);
    EXPECT_EQ(headers->iat.rva, kRdataRva + 0x100u);
    ASSERT_EQ(headers->sections.size(), 3u);
    EXPECT_EQ(headers->sections[0].name, ".text");
    EXPECT_TRUE(headers->sections[0].executable());
    EXPECT_FALSE(headers->sections[1].executable());
    EXPECT_EQ(headers->sections[2].mapped_size(), 0x200u);
    EXPECT_EQ(headers->section_at(0x1FFF)->name, ".text");
    EXPECT_EQ(headers->section_at(0x3200), nullptr);
}

TEST(PeImage, ParsesTheHeadersOfA32BitImage) {
    const auto headers = parse_pe_headers(build_image(false));
    ASSERT_TRUE(headers);
    EXPECT_FALSE(headers->pe32_plus);
    EXPECT_EQ(headers->describe(), "32-bit DLL");
    EXPECT_EQ(headers->image_base, kImageBase32);
    EXPECT_EQ(headers->relocations.rva, kRelocRva);
}

TEST(PeImage, RejectsDamagedHeaders) {
    auto bytes = build_image();
    EXPECT_FALSE(parse_pe_headers(std::span(bytes).first(0x40)));
    EXPECT_FALSE(parse_pe_headers(std::span(bytes).first(0x1A0)));

    auto no_dos = bytes;
    put<std::uint16_t>(no_dos, 0, 0x4D5A);
    EXPECT_FALSE(parse_pe_headers(no_dos));

    auto far_nt = bytes;
    put<std::uint32_t>(far_nt, 0x3C, 0xFFFFFFF0);
    EXPECT_FALSE(parse_pe_headers(far_nt));

    auto bad_magic = bytes;
    put<std::uint16_t>(bad_magic, 0x98, 0x107);
    EXPECT_FALSE(parse_pe_headers(bad_magic));

    EXPECT_FALSE(load_image(std::vector<std::byte>(0x100)));
}

std::vector<std::byte> relocation_block(std::uint32_t page, std::initializer_list<std::uint16_t> entries) {
    std::vector<std::byte> block(8 + entries.size() * 2);
    put<std::uint32_t>(block, 0, page);
    put<std::uint32_t>(block, 4, static_cast<std::uint32_t>(block.size()));
    std::size_t at = 8;
    for (const std::uint16_t entry : entries) {
        put<std::uint16_t>(block, at, entry);
        at += 2;
    }
    return block;
}

TEST(PeImage, RelocationsAddTheDeltaByType) {
    // HIGH, LOW, HIGHLOW, DIR64, and HIGHADJ, whose parameter looks like a DIR64 at 0x30 but is not one.
    const Relocations relocations(relocation_block(0x1000, {0x1000, 0x2004, 0x3008, 0xA010, 0x4020, 0xA030, 0x0000}));
    EXPECT_EQ(relocations.size(), 4u);
    std::vector<std::byte> bytes(0x40);
    constexpr std::uint64_t kDelta = 0x0000000112345678;
    relocations.apply(0x1000, bytes, kDelta);
    EXPECT_EQ(get<std::uint16_t>(bytes, 0x00), 0x1234);
    EXPECT_EQ(get<std::uint16_t>(bytes, 0x04), 0x5678);
    EXPECT_EQ(get<std::uint32_t>(bytes, 0x08), 0x12345678u);
    EXPECT_EQ(get<std::uint64_t>(bytes, 0x10), kDelta);
    EXPECT_EQ(get<std::uint64_t>(bytes, 0x20), 0u);
    EXPECT_EQ(get<std::uint64_t>(bytes, 0x30), 0u);
}

TEST(PeImage, RelocationsApplyOnlyWhollyInsideTheBytes) {
    const Relocations relocations(relocation_block(0x1000, {0xA010}));
    std::vector<std::byte> tail(6);
    relocations.apply(0x1012, tail, 1);
    EXPECT_EQ(std::count(tail.begin(), tail.end(), std::byte{0}), 6);
    std::vector<std::byte> head(6);
    relocations.apply(0x1010, head, 1);
    EXPECT_EQ(std::count(head.begin(), head.end(), std::byte{0}), 6);

    // A damaged block ends the table.
    auto damaged = relocation_block(0x1000, {0xA010});
    put<std::uint32_t>(damaged, 4, 0x1000);
    EXPECT_EQ(Relocations(damaged).size(), 0u);
}

TEST(PeImage, MapsTheSectionsLikeTheLoader) {
    const auto bytes = build_image();
    const auto file = load_image(bytes);
    ASSERT_TRUE(file);
    const auto image = mapped(*file, kImageBase64);
    EXPECT_TRUE(std::equal(image.begin(), image.begin() + 0x400, bytes.begin()));
    EXPECT_TRUE(std::equal(image.begin() + kTextRva, image.begin() + kTextRva + 0x1000, bytes.begin() + 0x400));
    EXPECT_EQ(get<std::uint64_t>(image, kPointerRva), kImageBase64 + kRdataRva);
    EXPECT_EQ(std::count(image.begin() + kRdataRva + kRdataRaw, image.begin() + kRelocRva, std::byte{0}), 0x1000 - kRdataRaw);
}

TEST(PeImage, RelocatesForAnotherBase) {
    for (const bool pe32_plus : {true, false}) {
        const auto file = load_image(build_image(pe32_plus));
        ASSERT_TRUE(file);
        const std::uint64_t base = pe32_plus ? kImageBase64 + 0x100000000 : kImageBase32 + 0x200000;
        const auto image = mapped(*file, base);
        if (pe32_plus) {
            EXPECT_EQ(get<std::uint64_t>(image, kPointerRva), base + kRdataRva);
            // A read that starts inside the pointer still sees it relocated.
            std::vector<std::byte> upper(4);
            ASSERT_TRUE(file->image_bytes(kPointerRva + 4, upper, base));
            EXPECT_EQ(get<std::uint32_t>(upper, 0), static_cast<std::uint32_t>((base + kRdataRva) >> 32));
        } else {
            EXPECT_EQ(get<std::uint32_t>(image, kPointerRva), static_cast<std::uint32_t>(base + kRdataRva));
        }
    }
}

TEST(PeImage, FindsFunctionOverrideSites) {
    for (const bool pe32_plus : {true, false}) {
        const auto file = load_image(build_image(pe32_plus));
        ASSERT_TRUE(file);
        ASSERT_EQ(file->override_sites().size(), 1u);
        EXPECT_EQ(file->override_sites()[0].rva, kOverrideRva);
        EXPECT_EQ(file->override_sites()[0].size, 4u);
    }
}

TEST(PeImage, OverrideSitesSkipOtherEntriesAndDamage) {
    // A symbol 3 entry, then a function override entry with two overlapping sites.
    std::vector<std::byte> table(12 + 4 + 12 + 4 + 16 + 4 + 12);
    put<std::uint64_t>(table, 0, 3);
    put<std::uint32_t>(table, 8, 4);
    put<std::uint32_t>(table, 12, 0xA123);
    put<std::uint64_t>(table, 16, 7);
    put<std::uint32_t>(table, 24, 4 + 16 + 4 + 12);
    put<std::uint32_t>(table, 28, 16 + 4 + 12);
    put<std::uint32_t>(table, 40, 4);
    put<std::uint32_t>(table, 44, 12);
    put<std::uint32_t>(table, 52, 0x5000);
    put<std::uint32_t>(table, 56, 12);
    put<std::uint16_t>(table, 60, 0x1010);
    put<std::uint16_t>(table, 62, 0x1012);
    const auto sites = parse_override_sites(table, true);
    ASSERT_EQ(sites.size(), 1u);
    EXPECT_EQ(sites[0].rva, 0x5010u);
    EXPECT_EQ(sites[0].size, 6u);

    put<std::uint32_t>(table, 28, 0x10000);
    EXPECT_TRUE(parse_override_sites(table, true).empty());
    EXPECT_TRUE(parse_override_sites(std::span(table).first(10), true).empty());
}

class FakeFacts final : public InspectFacts {
public:
    std::optional<std::uint64_t> main;
    std::string started_from;
    std::map<std::string, std::shared_ptr<const PeFile>> files;
    std::set<std::string> missing;
    bool all_shared = false;

    std::optional<std::uint64_t> main_image() const override { return main; }
    std::string main_path() const override { return started_from; }
    std::vector<bool> shared_pages(std::uint64_t, std::size_t pages) const override { return std::vector<bool>(pages, all_shared); }

    OpenedFile open_image(const std::string& path) const override {
        const auto it = files.find(path);
        if (it == files.end()) {
            return {nullptr, "cannot open " + path};
        }
        return {it->second, ""};
    }

    bool file_exists(const std::string& path) const override { return !missing.contains(path); }
    bool same_file(const std::string& a, const std::string& b) const override { return iequals_ascii(a, b); }
};

constexpr std::uint64_t kModuleBase = 0x7FF600000000;
const std::string kModulePath = "C:\\fake\\test.dll";

// The synthetic DLL loaded at kModuleBase, which is not its preferred base, exactly as its file says.
class Inspect : public ::testing::Test {
protected:
    void SetUp() override {
        file_ = load_image(build_image());
        ASSERT_TRUE(file_);
        facts_.files[kModulePath] = file_;
        facts_.main = kModuleBase;
        facts_.started_from = kModulePath;
        const auto image = mapped(*file_, kModuleBase);
        const auto add = [&](std::uint32_t rva, std::size_t size, std::uint32_t protect) {
            const auto bytes = memory_.add_image(kModuleBase + rva, size, kModulePath, kModuleBase, protect);
            std::copy_n(image.begin() + rva, size, bytes.begin());
        };
        add(0, 0x1000, page::ReadOnly);
        add(kTextRva, 0x1000, page::ExecuteRead);
        add(kRdataRva, 0x2000, page::ReadOnly);
    }

    InspectReport inspect(std::uint32_t kinds = kAllFindingKinds) const {
        InspectOptions options;
        options.kinds = kinds;
        return inspect_memory(memory_, facts_, options);
    }

    std::span<std::byte> code(std::uint32_t rva, std::size_t size) { return memory_.bytes_at(kModuleBase + rva, size); }

    FakeMemory memory_;
    FakeFacts facts_;
    std::shared_ptr<const PeFile> file_;
};

const Finding* find(const InspectReport& report, FindingKind kind, std::uint64_t address) {
    const auto it = std::find_if(report.findings.begin(), report.findings.end(),
                                 [&](const Finding& f) { return f.kind == kind && f.address == address; });
    return it != report.findings.end() ? &*it : nullptr;
}

TEST(InspectKinds, ParseAndName) {
    EXPECT_EQ(parse_finding_kinds("rwx,patched"), kind_bit(FindingKind::Rwx) | kind_bit(FindingKind::Patched));
    EXPECT_EQ(parse_finding_kinds("EXEC-PRIVATE,,pe-header"), kind_bit(FindingKind::ExecPrivate) | kind_bit(FindingKind::PeHeader));
    EXPECT_EQ(to_string(FindingKind::Hollowed), "hollowed");
    EXPECT_THROW(parse_finding_kinds("rwx,hooks"), Error);
    EXPECT_THROW(parse_finding_kinds(","), Error);
}

TEST_F(Inspect, AnUnchangedModuleHasNoFindings) {
    const InspectReport report = inspect();
    EXPECT_TRUE(report.findings.empty()) << report.findings.front().details;
    EXPECT_TRUE(report.warnings.empty());
    EXPECT_TRUE(report.complete);
    EXPECT_EQ(report.stats.modules, 1u);
    EXPECT_EQ(report.stats.code_bytes, 0x1000u);
    EXPECT_EQ(report.stats.shared_bytes, 0u);
}

TEST_F(Inspect, FindsPatchedCode) {
    const auto patch = code(0x1100, 5);
    const std::byte jump[] = {std::byte{0xE9}, std::byte{0x11}, std::byte{0x22}, std::byte{0x33}, std::byte{0x44}};
    std::copy(std::begin(jump), std::end(jump), patch.begin());
    code(0x1180, 1)[0] ^= std::byte{0xFF};

    const InspectReport report = inspect();
    ASSERT_EQ(report.count(FindingKind::Patched), 2u);
    const Finding* hook = find(report, FindingKind::Patched, kModuleBase + 0x1100);
    ASSERT_NE(hook, nullptr);
    EXPECT_EQ(hook->size, 5u);
    EXPECT_EQ(hook->where, "test.dll+0x1100");
    EXPECT_NE(hook->details.find(".text: 5 bytes differ from the file; memory E9 11 22 33 44"), std::string::npos) << hook->details;
    const Finding* flip = find(report, FindingKind::Patched, kModuleBase + 0x1180);
    ASSERT_NE(flip, nullptr);
    EXPECT_EQ(flip->size, 1u);
}

TEST_F(Inspect, NamesAChangedExportTable) {
    code(kExportRva + 8, 1)[0] ^= std::byte{0xFF};
    const InspectReport report = inspect();
    ASSERT_EQ(report.count(FindingKind::Patched), 1u);
    EXPECT_TRUE(report.findings.front().details.starts_with(".text (export table): 1 byte differs")) << report.findings.front().details;
}

TEST_F(Inspect, NearbyChangesAreOneFinding) {
    code(0x1200, 1)[0] ^= std::byte{1};
    code(0x1206, 1)[0] ^= std::byte{1};
    const InspectReport report = inspect();
    ASSERT_EQ(report.count(FindingKind::Patched), 1u);
    EXPECT_EQ(report.findings.front().size, 7u);
    EXPECT_NE(report.findings.front().details.find("2 bytes differ"), std::string::npos);
}

TEST_F(Inspect, IgnoresWhatTheLoaderRewrites) {
    const auto site = code(kOverrideRva, 4);
    std::fill(site.begin(), site.end(), std::byte{0xAB});
    EXPECT_EQ(inspect().count(FindingKind::Patched), 0u);
}

TEST_F(Inspect, SkipsPagesSharedWithTheFile) {
    code(0x1100, 1)[0] ^= std::byte{0xFF};
    facts_.all_shared = true;
    const InspectReport report = inspect();
    EXPECT_EQ(report.count(FindingKind::Patched), 0u);
    EXPECT_EQ(report.stats.code_bytes, 0u);
    EXPECT_EQ(report.stats.shared_bytes, 0x1000u);
}

TEST_F(Inspect, FindsExecutableAndWritableExecutableMemory) {
    memory_.add(0x10000, 0x2000, page::ExecuteRead);
    memory_.add(0x20000, 0x1000, page::ExecuteReadWrite);
    memory_.add(0x30000, 0x1000, page::ReadWrite);
    memory_.add(0x40000, 0x1000, page::ExecuteRead, MemType::Mapped);
    memory_.add_image(kModuleBase + 0x4000, 0x1000, kModulePath, kModuleBase, page::ExecuteReadWrite);

    const InspectReport report = inspect();
    ASSERT_NE(find(report, FindingKind::ExecPrivate, 0x10000), nullptr);
    EXPECT_EQ(find(report, FindingKind::ExecPrivate, 0x10000)->size, 0x2000u);
    EXPECT_NE(find(report, FindingKind::ExecPrivate, 0x20000), nullptr);
    EXPECT_NE(find(report, FindingKind::Rwx, 0x20000), nullptr);
    EXPECT_NE(find(report, FindingKind::ExecPrivate, 0x40000), nullptr);
    EXPECT_EQ(find(report, FindingKind::ExecPrivate, 0x30000), nullptr);
    const Finding* in_image = find(report, FindingKind::Rwx, kModuleBase + 0x4000);
    ASSERT_NE(in_image, nullptr);
    EXPECT_EQ(in_image->where, "test.dll+0x4000");
    EXPECT_EQ(find(report, FindingKind::ExecPrivate, kModuleBase + 0x4000), nullptr);
    EXPECT_TRUE(std::is_sorted(report.findings.begin(), report.findings.end(),
                               [](const Finding& a, const Finding& b) { return a.address < b.address; }));
}

TEST_F(Inspect, FindsPeHeadersOutsideModules) {
    const auto bytes = build_image();
    const auto copy = memory_.add(0x50000, 0x2000, page::ReadWrite);
    std::copy_n(bytes.begin(), 0x1000, copy.begin());
    memory_.add(0x60000, 0x1000, page::ReadWrite)[0] = std::byte{'M'};
    std::vector<std::byte> stub(bytes.begin(), bytes.begin() + 0x1000);
    std::uint32_t nt = 0;
    std::memcpy(&nt, stub.data() + 0x3C, sizeof(nt));
    put<std::uint32_t>(stub, nt + 24 + 56, 0);
    std::copy(stub.begin(), stub.end(), memory_.add(0x68000, 0x1000, page::ReadWrite).begin());

    const InspectReport report = inspect();
    const Finding* header = find(report, FindingKind::PeHeader, 0x50000);
    ASSERT_NE(header, nullptr);
    EXPECT_EQ(header->size, 0x2000u);
    EXPECT_NE(header->details.find("64-bit DLL"), std::string::npos) << header->details;
    EXPECT_EQ(report.count(FindingKind::PeHeader), 1u);
}

TEST_F(Inspect, FindsModulesThatDoNotMatchTheirFiles) {
    facts_.missing.insert(kModulePath);
    InspectReport report = inspect();
    ASSERT_EQ(report.count(FindingKind::Hollowed), 1u);
    EXPECT_NE(report.findings.front().details.find("no longer exists"), std::string::npos);

    facts_.missing.clear();
    facts_.files[kModulePath] = load_image(build_image(true, kTimestamp + 1));
    report = inspect(kind_bit(FindingKind::Hollowed));
    ASSERT_EQ(report.count(FindingKind::Hollowed), 1u);
    EXPECT_NE(report.findings.front().details.find("timestamp"), std::string::npos) << report.findings.front().details;

    facts_.files[kModulePath] = file_;
    const auto headers = code(0, 0x200);
    std::fill(headers.begin(), headers.end(), std::byte{0});
    report = inspect(kind_bit(FindingKind::Hollowed));
    ASSERT_EQ(report.count(FindingKind::Hollowed), 1u);
    EXPECT_NE(report.findings.front().details.find("erased"), std::string::npos);
}

TEST_F(Inspect, WarnsWhenAFileCannotBeRead) {
    facts_.files.clear();
    const InspectReport report = inspect();
    EXPECT_TRUE(report.findings.empty());
    ASSERT_EQ(report.warnings.size(), 1u);
    EXPECT_NE(report.warnings.front().find("test.dll: cannot open"), std::string::npos);
}

TEST_F(Inspect, WarnsWhenAModuleCannotBeRead) {
    memory_.fail_page(kModuleBase);
    memory_.fail_page(kModuleBase + kTextRva);
    const InspectReport report = inspect();
    EXPECT_TRUE(report.findings.empty()) << report.findings.front().details;
    EXPECT_EQ(report.stats.modules, 0u);
    ASSERT_EQ(report.warnings.size(), 1u);
    EXPECT_EQ(report.warnings.front(), "1 image cannot be read and was not compared with the files: test.dll");
}

TEST_F(Inspect, FindsHeadersHiddenBehindNoAccess) {
    constexpr std::uint64_t base = kModuleBase + 0x100000;
    const auto image = mapped(*file_, base);
    memory_.add_image(base, 0x1000, kModulePath, base, page::NoAccess);
    std::copy_n(image.begin() + kTextRva, 0x1000, memory_.add_image(base + kTextRva, 0x1000, kModulePath, base, page::ExecuteRead).begin());
    const InspectReport report = inspect(kind_bit(FindingKind::Hollowed));
    ASSERT_EQ(report.count(FindingKind::Hollowed), 1u);
    EXPECT_EQ(report.findings.front().address, base);
    EXPECT_NE(report.findings.front().details.find("cannot be read: the page is"), std::string::npos) << report.findings.front().details;
    EXPECT_TRUE(report.warnings.empty());
}

TEST_F(Inspect, FindsAHollowedMainImage) {
    const auto bytes = build_image();
    const auto copy = memory_.add(0x70000, 0x1000, page::ExecuteReadWrite);
    std::copy_n(bytes.begin(), 0x1000, copy.begin());
    facts_.main = 0x70000;
    InspectReport report = inspect(kind_bit(FindingKind::Hollowed));
    ASSERT_EQ(report.findings.size(), 1u);
    EXPECT_EQ(report.findings.front().address, 0x70000u);
    EXPECT_NE(report.findings.front().details.find("starts with a PE header"), std::string::npos) << report.findings.front().details;

    facts_.main = kModuleBase;
    facts_.started_from = "C:\\fake\\other.exe";
    report = inspect(kind_bit(FindingKind::Hollowed));
    ASSERT_EQ(report.findings.size(), 1u);
    EXPECT_NE(report.findings.front().details.find("started from C:\\fake\\other.exe"), std::string::npos);

    facts_.main.reset();
    report = inspect(kind_bit(FindingKind::Hollowed));
    EXPECT_TRUE(report.findings.empty());
    EXPECT_EQ(report.warnings.size(), 1u);
}

TEST_F(Inspect, ReportsOnlyTheKindsAskedFor) {
    memory_.add(0x20000, 0x1000, page::ExecuteReadWrite);
    code(0x1100, 1)[0] ^= std::byte{0xFF};
    const InspectReport report = inspect(kind_bit(FindingKind::Rwx));
    ASSERT_EQ(report.findings.size(), 1u);
    EXPECT_EQ(report.findings.front().kind, FindingKind::Rwx);
    EXPECT_EQ(report.stats.modules, 0u);
}

TEST_F(Inspect, StopsWhenAsked) {
    std::stop_source stop;
    stop.request_stop();
    const InspectReport report = inspect_memory(memory_, facts_, {}, stop.get_token());
    EXPECT_FALSE(report.complete);
}

testing::RunResult memhunter(const std::vector<std::string>& args) {
    return testing::run_program(MEMHUNTER_EXE, args);
}

std::uint64_t address_in(const std::string& line, std::string_view word) {
    std::istringstream in(line);
    std::string first;
    std::string address;
    in >> first >> address;
    EXPECT_EQ(first, word) << line;
    return parse_uint(address).value_or(0);
}

// A test target with executable private memory (the "execute" needle), an RWX page, a copy of its PE headers and
// four changed bytes of its own code on a page that is out of the working set.
class InspectTarget : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        target_ = new testing::TargetProcess(testing::start_target(MEMHUNTER_TEST_TARGET));
        rwx_ = address_in(target_->command("rwx"), "rwx");
        pe_ = address_in(target_->command("pe"), "pe");
        patch_ = address_in(target_->command("patch"), "patched");
        target_->command("trim");
    }

    static void TearDownTestSuite() {
        target_->child->write_line("exit");
        delete target_;
        target_ = nullptr;
    }

    static std::string pid() { return std::to_string(target_->pid); }

    static testing::TargetProcess* target_;
    static std::uint64_t rwx_;
    static std::uint64_t pe_;
    static std::uint64_t patch_;
};

testing::TargetProcess* InspectTarget::target_ = nullptr;
std::uint64_t InspectTarget::rwx_ = 0;
std::uint64_t InspectTarget::pe_ = 0;
std::uint64_t InspectTarget::patch_ = 0;

TEST_F(InspectTarget, FindsWhatWasPlanted) {
    ImageFileCache files;
    const Process process = Process::open(target_->pid);
    const InspectReport report = inspect_process(process, files);
    EXPECT_TRUE(report.complete);

    const auto execute = target_->addresses("execute");
    ASSERT_EQ(execute.size(), 1u);
    EXPECT_NE(find(report, FindingKind::ExecPrivate, execute.front() / 4096 * 4096), nullptr);
    EXPECT_NE(find(report, FindingKind::ExecPrivate, rwx_), nullptr);
    EXPECT_NE(find(report, FindingKind::Rwx, rwx_), nullptr);
    const Finding* header = find(report, FindingKind::PeHeader, pe_);
    ASSERT_NE(header, nullptr);
    EXPECT_NE(header->details.find("64-bit EXE"), std::string::npos);

    std::vector<const Finding*> own;
    for (const Finding& finding : report.findings) {
        if (finding.kind == FindingKind::Patched && finding.where.starts_with("memhunter_test_target.exe+")) {
            own.push_back(&finding);
        }
    }
    ASSERT_EQ(own.size(), 1u);
    EXPECT_EQ(own.front()->address, patch_);
    EXPECT_EQ(own.front()->size, 4u);
    EXPECT_NE(own.front()->details.find(".text: 4 bytes differ"), std::string::npos) << own.front()->details;
    EXPECT_EQ(report.count(FindingKind::Hollowed), 0u);
    EXPECT_GE(report.stats.modules, 3u);
}

TEST_F(InspectTarget, CliWritesTheFindings) {
    const auto csv = memhunter({"inspect", pid(), "-f", "csv", "-q"});
    EXPECT_EQ(csv.exit_code, 0u) << csv.err;
    EXPECT_TRUE(csv.out.starts_with("pid,process,kind,address,size,where,details\r\n"));
    EXPECT_NE(csv.out.find(pid() + ",memhunter_test_target.exe,rwx," + format_address(rwx_) + ",4096,"), std::string::npos) << csv.out;
    EXPECT_NE(csv.out.find(",pe-header," + format_address(pe_)), std::string::npos);
    EXPECT_NE(csv.out.find(",patched," + format_address(patch_) + ",4,"), std::string::npos);

    const auto json = memhunter({"inspect", pid(), "-f", "json", "--kind", "pe-header"});
    EXPECT_EQ(json.exit_code, 0u);
    EXPECT_NE(json.out.find("\"kind\": \"pe-header\""), std::string::npos) << json.out;
    EXPECT_EQ(json.out.find("\"kind\": \"rwx\""), std::string::npos);
    EXPECT_NE(json.err.find("1 finding (pe-header 1)"), std::string::npos) << json.err;

    const auto text = memhunter({"inspect", pid(), "--kind", "rwx"});
    EXPECT_EQ(text.exit_code, 0u);
    EXPECT_TRUE(text.out.starts_with("ADDRESS"));
    EXPECT_NE(text.out.find(format_address(rwx_)), std::string::npos);

    const auto none = memhunter({"inspect", pid(), "--kind", "hollowed"});
    EXPECT_EQ(none.exit_code, 1u) << none.err;
    EXPECT_NE(none.err.find("no findings"), std::string::npos);
}

TEST_F(InspectTarget, CliChecksEveryProcess) {
    const auto all = memhunter({"inspect", "--all", "--kind", "rwx", "-f", "csv"});
    EXPECT_EQ(all.exit_code, 0u) << all.err;
    EXPECT_NE(all.out.find(pid() + ",memhunter_test_target.exe,rwx," + format_address(rwx_)), std::string::npos);
    EXPECT_NE(all.err.find("Inspected "), std::string::npos) << all.err;
}

TEST(InspectCli, RejectsBadArguments) {
    EXPECT_EQ(memhunter({"inspect"}).exit_code, 2u);
    EXPECT_EQ(memhunter({"inspect", "1", "--all"}).exit_code, 2u);
    EXPECT_EQ(memhunter({"inspect", "1", "--kind", "hooks"}).exit_code, 2u);
    EXPECT_EQ(memhunter({"inspect", "2", "3"}).exit_code, 2u);
    EXPECT_EQ(memhunter({"inspect", "no-such-process-name.exe"}).exit_code, 3u);
    const auto help = memhunter({"help", "inspect"});
    EXPECT_EQ(help.exit_code, 0u);
    EXPECT_NE(help.out.find("exec-private"), std::string::npos);
}

// Puts the privilege back as it was, whatever the test did with it.
class PrivilegeRestore {
public:
    PrivilegeRestore() : enabled_(debug_privilege_enabled()) {}
    ~PrivilegeRestore() {
        try {
            enabled_ ? enable_debug_privilege() : disable_debug_privilege();
        } catch (const Error&) {
        }
    }

private:
    bool enabled_;
};

TEST(DebugPrivilege, OpensAProcessThatDeniesAccess) {
    testing::TargetProcess target = testing::start_target(MEMHUNTER_TEST_TARGET);
    ASSERT_EQ(target.command("lock"), "locked");
    const std::string pid = std::to_string(target.pid);
    const PrivilegeRestore restore;
    bool administrator = true;
    try {
        enable_debug_privilege();
    } catch (const Error& error) {
        EXPECT_EQ(error.code(), ErrorCode::AccessDenied);
        administrator = false;
    }
    disable_debug_privilege();
    EXPECT_FALSE(debug_privilege_enabled());
    EXPECT_THROW(Process::open(target.pid), Error);

    const auto denied = memhunter({"inspect", pid, "--kind", "exec-private", "-q"});
    EXPECT_EQ(denied.exit_code, 3u) << denied.out;
    const auto allowed = memhunter({"inspect", pid, "--kind", "exec-private", "-q", "--debug-privilege"});
    if (administrator) {
        EXPECT_EQ(allowed.exit_code, 0u) << allowed.err;
        EXPECT_EQ(memhunter({"--debug-privilege", "regions", pid, "-f", "csv"}).exit_code, 0u);
        enable_debug_privilege();
        EXPECT_TRUE(debug_privilege_enabled());
        EXPECT_NO_THROW(Process::open(target.pid));
    } else {
        EXPECT_EQ(allowed.exit_code, 3u);
        EXPECT_NE(allowed.err.find("administrator"), std::string::npos) << allowed.err;
    }
    target.child->write_line("exit");
}

}  // namespace
}  // namespace mh
