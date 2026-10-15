#pragma once

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <span>
#include <string>

#include "pipeline/scan_session.hpp"
#include "snapshot/capture.hpp"
#include "snapshot/snapshot.hpp"

namespace mh {

// File layout (little-endian), version 1:
//   header   64 bytes: magic, version, flags, data and metadata extents, metadata hash, header hash
//   data     block contents in span order, present only with the "contents" flag
//   metadata page/block size, capture time, process identity, region table, spans, block states and hashes
// Every byte is covered by a hash: the header and metadata directly, block contents by their block hashes.
inline constexpr std::size_t kSnapshotHeaderSize = 64;

// Writes "<path>.partial" and renames it over <path> on commit, so an interrupted capture never leaves a
// truncated snapshot under the requested name.
class SnapshotWriter final : public SnapshotDataSink {
public:
    SnapshotWriter(const std::string& path, bool with_data);
    ~SnapshotWriter() override;
    SnapshotWriter(const SnapshotWriter&) = delete;
    SnapshotWriter& operator=(const SnapshotWriter&) = delete;

    void write(std::uint64_t offset, std::span<const std::byte> bytes) override;

    // Returns the size of the finished file.
    std::uint64_t commit(const Snapshot& snapshot);

private:
    void fail(const std::string& what);

    std::string name_;
    std::filesystem::path path_;
    std::filesystem::path temp_;
    std::ofstream file_;
    std::mutex mutex_;
    bool with_data_ = false;
    bool committed_ = false;
};

// Loads and validates the header and metadata; block contents are read on demand.
class SnapshotFile {
public:
    explicit SnapshotFile(const std::string& path);

    const Snapshot& snapshot() const noexcept { return snapshot_; }
    const std::string& name() const noexcept { return name_; }
    std::uint64_t file_size() const noexcept { return file_size_; }

    // False for unreadable blocks. Throws Error(CorruptSnapshot) when the stored contents no longer match the
    // block hash. Not thread-safe.
    bool read_block(std::size_t span, std::uint64_t block, std::span<std::byte> out);

private:
    std::string name_;
    std::ifstream file_;
    std::uint64_t file_size_ = 0;
    std::uint64_t data_offset_ = 0;
    Snapshot snapshot_;
};

std::uint64_t estimate_snapshot_size(const ScanPlan& plan, std::uint32_t block_size, bool with_data);

// Free bytes available to the current user on the volume that holds `path` (or its directory).
std::uint64_t free_disk_space(const std::string& path);

}  // namespace mh
