#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "common/error.hpp"
#include "memory/region.hpp"

namespace mh {

// Little-endian building blocks of the snapshot and value file formats.
inline constexpr std::uint32_t kMaxStringBytes = 1u << 16;
// The smallest encoded region: a record with an empty file name.
inline constexpr std::uint64_t kMinRegionRecord = 38;

class ByteWriter {
public:
    void reserve(std::size_t size) { bytes_.reserve(size); }
    void u8(std::uint8_t value) { bytes_.push_back(static_cast<std::byte>(value)); }
    void u32(std::uint32_t value) { raw(&value, sizeof value); }
    void u64(std::uint64_t value) { raw(&value, sizeof value); }
    void str(const std::string& text) {
        const auto size = static_cast<std::uint32_t>(std::min<std::size_t>(text.size(), kMaxStringBytes));
        u32(size);
        raw(text.data(), size);
    }
    void raw(const void* data, std::size_t size) {
        const auto* p = static_cast<const std::byte*>(data);
        bytes_.insert(bytes_.end(), p, p + size);
    }

    const std::vector<std::byte>& bytes() const noexcept { return bytes_; }
    std::vector<std::byte>& bytes() noexcept { return bytes_; }

private:
    std::vector<std::byte> bytes_;
};

// Throws Error(CorruptSnapshot) "<what> is damaged: ..." when the data ends early or a field is invalid.
class ByteReader {
public:
    ByteReader(std::span<const std::byte> bytes, std::string what) : bytes_(bytes), what_(std::move(what)) {}

    std::uint8_t u8() { return std::to_integer<std::uint8_t>(take(1)[0]); }
    std::uint32_t u32() { return load<std::uint32_t>(); }
    std::uint64_t u64() { return load<std::uint64_t>(); }
    std::string str() {
        const std::uint32_t size = u32();
        if (size > kMaxStringBytes) {
            corrupt("a text field is too long");
        }
        const auto bytes = take(size);
        return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
    }
    std::span<const std::byte> take(std::uint64_t size) {
        if (size > bytes_.size() - offset_) {
            corrupt("the data ends unexpectedly");
        }
        const auto out = bytes_.subspan(offset_, size);
        offset_ += size;
        return out;
    }
    std::uint64_t remaining() const noexcept { return bytes_.size() - offset_; }

    [[noreturn]] void corrupt(const std::string& detail) const {
        throw Error(ErrorCode::CorruptSnapshot, what_ + " is damaged: " + detail);
    }

private:
    template <typename T>
    T load() {
        T value;
        std::memcpy(&value, take(sizeof value).data(), sizeof value);
        return value;
    }

    std::span<const std::byte> bytes_;
    std::string what_;
    std::size_t offset_ = 0;
};

void write_regions(ByteWriter& w, std::span<const Region> regions);
// Rejects invalid records; with `sorted` also regions that are out of order or overlap.
std::vector<Region> read_regions(ByteReader& r, bool sorted);

// Moves a finished FILE.partial over FILE.
void replace_file(const std::filesystem::path& from, const std::filesystem::path& to, const std::string& name);

// A file of one payload behind a 40-byte header: magic, version, flags (0), payload size, XXH64 of the payload and
// XXH64 of the header before it.
struct SealedFormat {
    std::array<char, 8> magic{};
    std::uint32_t version = 0;
    // Names the file in messages: "value file".
    std::string_view kind;
};

inline constexpr std::size_t kSealedHeaderSize = 40;

// A writer that holds the header already; the payload follows, then seal().
ByteWriter begin_sealed(const SealedFormat& format, std::size_t payload_size);
std::vector<std::byte> seal(ByteWriter& w);
// The payload of a checked file. Throws Error(CorruptSnapshot) for a foreign, truncated or damaged file and
// Error(IncompatibleSnapshot) for a newer version.
std::span<const std::byte> unseal(std::span<const std::byte> bytes, const SealedFormat& format, const std::string& name);

// Writes FILE.partial and renames it over FILE once it is complete; checks the free disk space first. Throws
// Error(Io).
void write_file_replacing(const std::string& path, std::span<const std::byte> bytes);
// Throws Error(Io) "cannot open <kind> '<path>'".
std::vector<std::byte> read_file_bytes(const std::string& path, std::string_view kind);

}  // namespace mh
