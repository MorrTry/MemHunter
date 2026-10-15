#include "snapshot/binary_io.hpp"

#include <windows.h>

#include <fstream>
#include <limits>

#include "common/text.hpp"
#include "snapshot/hash.hpp"
#include "snapshot/snapshot_file.hpp"

namespace mh {

namespace {

constexpr std::size_t kPayloadSizeAt = 16;
constexpr std::size_t kPayloadHashAt = 24;
constexpr std::size_t kHeaderHashAt = 32;

}  // namespace

void write_regions(ByteWriter& w, std::span<const Region> regions) {
    w.u32(static_cast<std::uint32_t>(regions.size()));
    for (const auto& r : regions) {
        w.u64(r.base);
        w.u64(r.size);
        w.u64(r.allocation_base);
        w.u32(r.protect);
        w.u32(r.allocation_protect);
        w.u8(static_cast<std::uint8_t>(r.state));
        w.u8(static_cast<std::uint8_t>(r.type));
        w.str(r.mapped_file);
    }
}

std::vector<Region> read_regions(ByteReader& r, bool sorted) {
    const std::uint32_t count = r.u32();
    if (count > r.remaining() / kMinRegionRecord) {
        r.corrupt("the region table is larger than the file");
    }
    std::vector<Region> regions(count);
    std::uint64_t previous_end = 0;
    for (auto& region : regions) {
        region.base = r.u64();
        region.size = r.u64();
        region.allocation_base = r.u64();
        region.protect = r.u32();
        region.allocation_protect = r.u32();
        const std::uint8_t state = r.u8();
        const std::uint8_t type = r.u8();
        if (state > static_cast<std::uint8_t>(MemState::Commit) || type > static_cast<std::uint8_t>(MemType::Private) ||
            region.size == 0 || region.base > std::numeric_limits<std::uint64_t>::max() - region.size) {
            r.corrupt("invalid region record");
        }
        if (sorted && region.base < previous_end) {
            r.corrupt("regions are unsorted or overlapping");
        }
        previous_end = region.end();
        region.state = static_cast<MemState>(state);
        region.type = static_cast<MemType>(type);
        region.mapped_file = r.str();
    }
    return regions;
}

void replace_file(const std::filesystem::path& from, const std::filesystem::path& to, const std::string& name) {
    if (MoveFileExW(from.c_str(), to.c_str(), MOVEFILE_REPLACE_EXISTING) == 0) {
        throw_win32(ErrorCode::Io, "cannot rename '" + wide_to_utf8(from.wstring()) + "' to '" + name + "'", GetLastError());
    }
}

ByteWriter begin_sealed(const SealedFormat& format, std::size_t payload_size) {
    ByteWriter w;
    w.reserve(kSealedHeaderSize + payload_size);
    w.raw(format.magic.data(), format.magic.size());
    w.u32(format.version);
    w.u32(0);
    w.u64(0);
    w.u64(0);
    w.u64(0);
    return w;
}

std::vector<std::byte> seal(ByteWriter& w) {
    std::vector<std::byte>& bytes = w.bytes();
    const auto store = [&](std::size_t offset, std::uint64_t value) { std::memcpy(bytes.data() + offset, &value, sizeof value); };
    const auto payload = std::span<const std::byte>(bytes).subspan(kSealedHeaderSize);
    store(kPayloadSizeAt, payload.size());
    store(kPayloadHashAt, xxh64(payload));
    store(kHeaderHashAt, xxh64(std::span<const std::byte>(bytes).first(kHeaderHashAt)));
    return std::move(bytes);
}

std::span<const std::byte> unseal(std::span<const std::byte> bytes, const SealedFormat& format, const std::string& name) {
    if (bytes.size() < format.magic.size() || std::memcmp(bytes.data(), format.magic.data(), format.magic.size()) != 0) {
        throw Error(ErrorCode::CorruptSnapshot, "'" + name + "' is not a MemHunter " + std::string(format.kind));
    }
    const std::string what = std::string(format.kind) + " '" + name + "'";
    ByteReader head(bytes.first(std::min(bytes.size(), kSealedHeaderSize)), what);
    if (bytes.size() < kSealedHeaderSize) {
        head.corrupt("the header is truncated");
    }
    head.take(format.magic.size());
    const std::uint32_t version = head.u32();
    const std::uint32_t flags = head.u32();
    const std::uint64_t size = head.u64();
    const std::uint64_t payload_hash = head.u64();
    if (head.u64() != xxh64(bytes.first(kHeaderHashAt))) {
        head.corrupt("header checksum mismatch");
    }
    if (version > format.version) {
        throw Error(ErrorCode::IncompatibleSnapshot, what + " uses format version " + std::to_string(version) +
                                                         ", which is newer than this MemHunter supports (" +
                                                         std::to_string(format.version) + ")");
    }
    if (version == 0 || flags != 0) {
        head.corrupt("invalid format version or flags");
    }
    const auto payload = bytes.subspan(kSealedHeaderSize);
    if (size > payload.size()) {
        head.corrupt("the file is truncated");
    }
    if (size < payload.size()) {
        head.corrupt("the file has trailing bytes");
    }
    if (xxh64(payload) != payload_hash) {
        head.corrupt("checksum mismatch");
    }
    return payload;
}

void write_file_replacing(const std::string& path, std::span<const std::byte> bytes) {
    const std::uint64_t available = free_disk_space(path);
    if (bytes.size() > available) {
        throw Error(ErrorCode::Io, "not enough disk space for '" + path + "': " + format_size(bytes.size()) + " needed, " +
                                       format_size(available) + " free");
    }
    const std::filesystem::path target(utf8_to_wide(path));
    std::filesystem::path temp = target;
    temp += L".partial";
    const auto discard = [&] {
        std::error_code ignored;
        std::filesystem::remove(temp, ignored);
    };
    std::ofstream file(temp, std::ios::binary | std::ios::trunc);
    if (!file) {
        throw Error(ErrorCode::Io, "cannot create '" + path + ".partial'");
    }
    file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    file.close();
    if (!file) {
        discard();
        throw Error(ErrorCode::Io, "cannot write '" + path + ".partial' (disk full?)");
    }
    try {
        replace_file(temp, target, path);
    } catch (...) {
        discard();
        throw;
    }
}

std::vector<std::byte> read_file_bytes(const std::string& path, std::string_view kind) {
    const std::filesystem::path native(utf8_to_wide(path));
    std::ifstream file(native, std::ios::binary);
    std::error_code ec;
    const std::uint64_t size = file ? std::filesystem::file_size(native, ec) : 0;
    if (!file || ec) {
        throw Error(ErrorCode::Io, "cannot open " + std::string(kind) + " '" + path + "'");
    }
    std::vector<std::byte> bytes(size);
    file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (file.gcount() != static_cast<std::streamsize>(bytes.size())) {
        throw Error(ErrorCode::Io, "cannot read " + std::string(kind) + " '" + path + "'");
    }
    return bytes;
}

}  // namespace mh
