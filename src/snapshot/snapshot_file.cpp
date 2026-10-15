#include "snapshot/snapshot_file.hpp"

#include <windows.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <limits>
#include <vector>

#include "common/error.hpp"
#include "common/text.hpp"
#include "snapshot/binary_io.hpp"
#include "snapshot/hash.hpp"

namespace mh {

namespace {

constexpr std::array<char, 8> kMagic{'M', 'H', 'S', 'N', 'A', 'P', '\x1A', '\n'};
constexpr std::uint32_t kFlagContents = 1u << 0;
constexpr std::uint32_t kKnownFlags = kFlagContents;

struct Header {
    std::uint32_t version = kSnapshotVersion;
    std::uint32_t flags = 0;
    std::uint64_t data_offset = 0;
    std::uint64_t data_size = 0;
    std::uint64_t meta_offset = 0;
    std::uint64_t meta_size = 0;
    std::uint64_t meta_hash = 0;
};

std::array<std::byte, kSnapshotHeaderSize> encode_header(const Header& header) {
    ByteWriter w;
    w.raw(kMagic.data(), kMagic.size());
    w.u32(header.version);
    w.u32(header.flags);
    w.u64(header.data_offset);
    w.u64(header.data_size);
    w.u64(header.meta_offset);
    w.u64(header.meta_size);
    w.u64(header.meta_hash);
    w.u64(xxh64(w.bytes()));
    std::array<std::byte, kSnapshotHeaderSize> out{};
    std::copy(w.bytes().begin(), w.bytes().end(), out.begin());
    return out;
}

std::vector<std::byte> encode_metadata(const Snapshot& s) {
    ByteWriter w;
    w.u32(s.page_size);
    w.u32(s.block_size);
    w.u64(s.captured_at);
    w.u32(s.process.pid);
    w.u64(s.process.creation_time);
    w.u8(s.process.wow64 ? 1 : 0);
    w.str(s.process.name);
    w.str(s.process.path);
    write_regions(w, s.regions);
    w.u32(static_cast<std::uint32_t>(s.spans.size()));
    for (const auto& span : s.spans) {
        w.u64(span.begin);
        w.u64(span.end);
    }
    w.u64(s.block_count());
    w.raw(s.states.data(), s.states.size());
    w.raw(s.hashes.data(), s.hashes.size() * sizeof(std::uint64_t));
    return w.bytes();
}

Snapshot decode_metadata(std::span<const std::byte> bytes, const std::string& name) {
    ByteReader r(bytes, "snapshot '" + name + "'");
    Snapshot s;
    s.page_size = r.u32();
    s.block_size = r.u32();
    if (!std::has_single_bit(s.page_size) || s.page_size < 512 || s.page_size > (1u << 16)) {
        r.corrupt("invalid page size");
    }
    if (!std::has_single_bit(s.block_size) || s.block_size < s.page_size || s.block_size > kMaxBlockSize) {
        r.corrupt("invalid block size");
    }
    s.captured_at = r.u64();
    s.process.pid = r.u32();
    s.process.creation_time = r.u64();
    s.process.wow64 = r.u8() != 0;
    s.process.name = r.str();
    s.process.path = r.str();

    s.regions = read_regions(r, false);

    const std::uint32_t span_count = r.u32();
    if (span_count > r.remaining() / 16) {
        r.corrupt("the span table is larger than the file");
    }
    std::vector<AddressRange> ranges(span_count);
    std::uint64_t previous_end = 0;
    for (auto& range : ranges) {
        range.begin = r.u64();
        range.end = r.u64();
        if (range.begin >= range.end || range.begin < previous_end) {
            r.corrupt("spans are empty, unsorted or overlapping");
        }
        previous_end = range.end;
    }
    layout_spans(s, ranges);

    if (r.u64() != s.block_count() || r.remaining() != s.block_count() * (1 + sizeof(std::uint64_t))) {
        r.corrupt("the block table does not match the spans");
    }
    const auto states = r.take(s.block_count());
    for (std::size_t i = 0; i < states.size(); ++i) {
        const auto state = std::to_integer<std::uint8_t>(states[i]);
        if (state > static_cast<std::uint8_t>(BlockState::Hashed)) {
            r.corrupt("invalid block state");
        }
        s.states[i] = static_cast<BlockState>(state);
    }
    const auto hashes = r.take(s.block_count() * sizeof(std::uint64_t));
    std::memcpy(s.hashes.data(), hashes.data(), hashes.size());
    return s;
}

}  // namespace

SnapshotWriter::SnapshotWriter(const std::string& path, bool with_data)
    : name_(path), path_(utf8_to_wide(path)), with_data_(with_data) {
    temp_ = path_;
    temp_ += L".partial";
    file_.open(temp_, std::ios::binary | std::ios::trunc);
    if (!file_) {
        throw Error(ErrorCode::Io, "cannot create snapshot '" + name_ + "'");
    }
    const std::array<std::byte, kSnapshotHeaderSize> placeholder{};
    file_.write(reinterpret_cast<const char*>(placeholder.data()), placeholder.size());
    if (!file_) {
        fail("cannot write snapshot '" + name_ + "'");
    }
}

SnapshotWriter::~SnapshotWriter() {
    if (!committed_) {
        file_.close();
        std::error_code ignored;
        std::filesystem::remove(temp_, ignored);
    }
}

void SnapshotWriter::fail(const std::string& what) {
    throw Error(ErrorCode::Io, what + " (disk full?)");
}

void SnapshotWriter::write(std::uint64_t offset, std::span<const std::byte> bytes) {
    std::lock_guard lock(mutex_);
    file_.seekp(static_cast<std::streamoff>(kSnapshotHeaderSize + offset));
    file_.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!file_) {
        fail("cannot write snapshot contents to '" + name_ + "'");
    }
}

std::uint64_t SnapshotWriter::commit(const Snapshot& snapshot) {
    std::lock_guard lock(mutex_);
    const std::vector<std::byte> meta = encode_metadata(snapshot);
    Header header;
    header.flags = with_data_ ? kFlagContents : 0;
    header.data_offset = with_data_ ? kSnapshotHeaderSize : 0;
    header.data_size = with_data_ ? snapshot.captured_bytes() : 0;
    header.meta_offset = kSnapshotHeaderSize + header.data_size;
    header.meta_size = meta.size();
    header.meta_hash = xxh64(meta);
    const auto head = encode_header(header);

    file_.seekp(static_cast<std::streamoff>(header.meta_offset));
    file_.write(reinterpret_cast<const char*>(meta.data()), static_cast<std::streamsize>(meta.size()));
    file_.seekp(0);
    file_.write(reinterpret_cast<const char*>(head.data()), head.size());
    file_.close();
    if (!file_) {
        fail("cannot write snapshot '" + name_ + "'");
    }
    replace_file(temp_, path_, name_);
    committed_ = true;
    return header.meta_offset + header.meta_size;
}

SnapshotFile::SnapshotFile(const std::string& path) : name_(path) {
    const std::filesystem::path native(utf8_to_wide(path));
    file_.open(native, std::ios::binary);
    if (!file_) {
        throw Error(ErrorCode::Io, "cannot open snapshot '" + name_ + "'");
    }
    std::error_code ec;
    file_size_ = std::filesystem::file_size(native, ec);
    if (ec) {
        throw Error(ErrorCode::Io, "cannot read snapshot '" + name_ + "'");
    }
    const auto corrupt = [&](const std::string& what) -> Error {
        return Error(ErrorCode::CorruptSnapshot, "snapshot '" + name_ + "' is damaged: " + what);
    };

    std::array<std::byte, kSnapshotHeaderSize> head{};
    file_.read(reinterpret_cast<char*>(head.data()), head.size());
    if (file_.gcount() < static_cast<std::streamsize>(kMagic.size()) ||
        std::memcmp(head.data(), kMagic.data(), kMagic.size()) != 0) {
        throw Error(ErrorCode::CorruptSnapshot, "'" + name_ + "' is not a MemHunter snapshot");
    }
    if (file_.gcount() != static_cast<std::streamsize>(head.size())) {
        throw corrupt("the header is truncated");
    }
    ByteReader r(head, "snapshot '" + name_ + "'");
    r.take(kMagic.size());
    Header header;
    header.version = r.u32();
    header.flags = r.u32();
    header.data_offset = r.u64();
    header.data_size = r.u64();
    header.meta_offset = r.u64();
    header.meta_size = r.u64();
    header.meta_hash = r.u64();
    const std::uint64_t header_hash = r.u64();
    if (header_hash != xxh64(std::span(head).first(kSnapshotHeaderSize - 8))) {
        throw corrupt("header checksum mismatch");
    }
    if (header.version > kSnapshotVersion || (header.flags & ~kKnownFlags) != 0) {
        throw Error(ErrorCode::IncompatibleSnapshot, "snapshot '" + name_ + "' uses format version " + std::to_string(header.version) +
                                                         ", which is newer than this MemHunter supports (" +
                                                         std::to_string(kSnapshotVersion) + ")");
    }
    if (header.version == 0) {
        throw corrupt("invalid format version 0");
    }
    const bool contents = (header.flags & kFlagContents) != 0;
    if (header.meta_offset < kSnapshotHeaderSize || header.meta_size > file_size_ || header.meta_offset != file_size_ - header.meta_size) {
        throw corrupt("the file is truncated or has trailing bytes");
    }
    if (contents ? header.data_offset != kSnapshotHeaderSize || header.data_offset + header.data_size != header.meta_offset
                 : header.data_offset != 0 || header.data_size != 0 || header.meta_offset != kSnapshotHeaderSize) {
        throw corrupt("inconsistent section offsets");
    }
    if (header.meta_size > (std::uint64_t{1} << 32)) {
        throw corrupt("the metadata section is implausibly large");
    }

    std::vector<std::byte> meta(header.meta_size);
    file_.seekg(static_cast<std::streamoff>(header.meta_offset));
    file_.read(reinterpret_cast<char*>(meta.data()), static_cast<std::streamsize>(meta.size()));
    if (file_.gcount() != static_cast<std::streamsize>(meta.size())) {
        throw corrupt("the metadata is truncated");
    }
    if (xxh64(meta) != header.meta_hash) {
        throw corrupt("metadata checksum mismatch");
    }
    snapshot_ = decode_metadata(meta, name_);
    snapshot_.has_data = contents;
    if (contents && header.data_size != snapshot_.captured_bytes()) {
        throw corrupt("the contents section does not match the captured ranges");
    }
    data_offset_ = header.data_offset;
}

bool SnapshotFile::read_block(std::size_t span, std::uint64_t block, std::span<std::byte> out) {
    if (!snapshot_.has_data) {
        throw Error(ErrorCode::InvalidArgument, "snapshot '" + name_ + "' holds hashes only, not memory contents");
    }
    if (snapshot_.states[block] != BlockState::Hashed) {
        return false;
    }
    const AddressRange range = snapshot_.block_range(span, block);
    const std::size_t size = range.end - range.begin;
    if (out.size() < size) {
        throw Error(ErrorCode::InvalidArgument, "block buffer too small");
    }
    file_.clear();
    file_.seekg(static_cast<std::streamoff>(data_offset_ + snapshot_.block_data_offset(span, block)));
    file_.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(size));
    if (file_.gcount() != static_cast<std::streamsize>(size) || xxh64(out.first(size)) != snapshot_.hashes[block]) {
        throw Error(ErrorCode::CorruptSnapshot, "snapshot '" + name_ + "' is damaged: the saved contents at " +
                                                    format_address(range.begin) + " do not match their hash");
    }
    return true;
}

std::uint64_t estimate_snapshot_size(const ScanPlan& plan, std::uint32_t block_size, bool with_data) {
    std::uint64_t bytes = 0;
    std::uint64_t blocks = 0;
    for (const auto& span : plan.spans) {
        bytes += span.end - span.begin;
        blocks += blocks_in_range(span.begin, span.end, block_size);
    }
    std::uint64_t regions = 0;
    for (const auto& region : plan.regions) {
        regions += kMinRegionRecord + region.mapped_file.size();
    }
    return kSnapshotHeaderSize + 1024 + regions + plan.spans.size() * 16 + blocks * 9 + (with_data ? bytes : 0);
}

std::uint64_t free_disk_space(const std::string& path) {
    std::filesystem::path target = std::filesystem::absolute(std::filesystem::path(utf8_to_wide(path)));
    std::filesystem::path directory = target.parent_path();
    ULARGE_INTEGER available{};
    if (GetDiskFreeSpaceExW(directory.c_str(), &available, nullptr, nullptr) == 0) {
        throw_win32(ErrorCode::Io, "cannot query free space for '" + path + "'", GetLastError());
    }
    return available.QuadPart;
}

}  // namespace mh
