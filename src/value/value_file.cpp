#include "value/value_file.hpp"

#include <bit>
#include <cstring>
#include <limits>

#include "common/error.hpp"
#include "common/text.hpp"
#include "snapshot/binary_io.hpp"

namespace mh {

namespace {

const SealedFormat kFormat{{'M', 'H', 'V', 'A', 'L', 'S', '\x1A', '\n'}, kValueFileVersion, "value file"};
constexpr std::uint64_t kDenseRecord = 5 * sizeof(std::uint64_t);
constexpr std::uint64_t kSparseRecord = 2 * sizeof(std::uint64_t);

std::uint64_t bitmap_words(std::uint64_t positions) noexcept {
    return (positions + 63) / 64;
}

std::uint64_t payload_size(const ProcessSummary& process, const ValueCandidates& candidates) {
    std::uint64_t size = 64 + process.name.size() + process.path.size();
    for (const Region& region : candidates.regions) {
        size += kMinRegionRecord + region.mapped_file.size();
    }
    for (const DenseValues& block : candidates.dense) {
        size += kDenseRecord + block.alive.size() * sizeof(std::uint64_t) + block.bytes.size();
    }
    return size + candidates.sparse.size() * kSparseRecord;
}

DenseValues read_dense(ByteReader& r, std::size_t size, std::size_t step, bool aligned) {
    DenseValues block;
    block.base = r.u64();
    block.first = r.u64();
    block.positions = r.u64();
    block.count = r.u64();
    const std::uint64_t length = r.u64();
    if (block.positions == 0 || block.positions > length || length > r.remaining() ||
        bitmap_words(block.positions) > r.remaining() / sizeof(std::uint64_t) ||
        block.base > std::numeric_limits<std::uint64_t>::max() - length || block.first < block.base ||
        block.first - block.base >= step || (aligned && block.first % size != 0) ||
        block.first - block.base + (block.positions - 1) * step + size > length) {
        r.corrupt("invalid candidate block at " + format_address(block.base));
    }
    block.alive.resize(bitmap_words(block.positions));
    const auto words = r.take(block.alive.size() * sizeof(std::uint64_t));
    std::memcpy(block.alive.data(), words.data(), words.size());
    const std::uint64_t tail = block.positions % 64;
    std::uint64_t count = 0;
    for (const std::uint64_t word : block.alive) {
        count += static_cast<std::uint64_t>(std::popcount(word));
    }
    if ((tail != 0 && (block.alive.back() >> tail) != 0) || count == 0 || count != block.count) {
        r.corrupt("the candidates of the block at " + format_address(block.base) + " do not match its count");
    }
    const auto bytes = r.take(length);
    block.bytes.assign(bytes.begin(), bytes.end());
    return block;
}

ValueCandidates read_candidates(ByteReader& r) {
    ValueCandidates c;
    const std::uint8_t type = r.u8();
    const std::uint8_t aligned = r.u8();
    c.scans = r.u32();
    if (type > static_cast<std::uint8_t>(ValueType::Double) || aligned > 1 || c.scans == 0) {
        r.corrupt("invalid value type or scan number");
    }
    c.type = static_cast<ValueType>(type);
    c.aligned = aligned != 0;
    c.regions = read_regions(r, true);

    const std::size_t size = size_of(c.type);
    const std::size_t step = c.step();
    const std::uint64_t dense = r.u64();
    if (dense > r.remaining() / (kDenseRecord + sizeof(std::uint64_t) + 1)) {
        r.corrupt("the candidate blocks are larger than the file");
    }
    c.dense.reserve(dense);
    for (std::uint64_t i = 0; i < dense; ++i) {
        DenseValues block = read_dense(r, size, step, c.aligned);
        if (!c.dense.empty() && block.first <= c.dense.back().first + (c.dense.back().positions - 1) * step) {
            r.corrupt("candidate blocks are unsorted or overlapping");
        }
        c.dense.push_back(std::move(block));
    }

    const std::uint64_t sparse = r.u64();
    if (r.remaining() % kSparseRecord != 0 || sparse != r.remaining() / kSparseRecord) {
        r.corrupt("the candidate table does not match the file size");
    }
    c.sparse.resize(sparse);
    for (std::size_t i = 0; i < c.sparse.size(); ++i) {
        ValueCandidate& candidate = c.sparse[i];
        candidate.address = r.u64();
        candidate.previous = r.u64();
        if (candidate.address > std::numeric_limits<std::uint64_t>::max() - size ||
            (i != 0 && candidate.address <= c.sparse[i - 1].address) || (size < 8 && (candidate.previous >> (size * 8)) != 0)) {
            r.corrupt("invalid candidate at " + format_address(candidate.address));
        }
    }
    return c;
}

}  // namespace

std::vector<std::byte> encode_value_file(const ProcessSummary& process, const ValueCandidates& candidates) {
    ByteWriter w = begin_sealed(kFormat, payload_size(process, candidates));
    w.u32(process.pid);
    w.u64(process.creation_time);
    w.u8(process.wow64 ? 1 : 0);
    w.str(process.name);
    w.str(process.path);
    w.u8(static_cast<std::uint8_t>(candidates.type));
    w.u8(candidates.aligned ? 1 : 0);
    w.u32(candidates.scans);
    write_regions(w, candidates.regions);
    w.u64(candidates.dense.size());
    for (const DenseValues& block : candidates.dense) {
        w.u64(block.base);
        w.u64(block.first);
        w.u64(block.positions);
        w.u64(block.count);
        w.u64(block.bytes.size());
        w.raw(block.alive.data(), block.alive.size() * sizeof(std::uint64_t));
        w.raw(block.bytes.data(), block.bytes.size());
    }
    w.u64(candidates.sparse.size());
    for (const ValueCandidate& candidate : candidates.sparse) {
        w.u64(candidate.address);
        w.u64(candidate.previous);
    }

    return seal(w);
}

ValueFile decode_value_file(std::span<const std::byte> bytes, const std::string& name) {
    ByteReader r(unseal(bytes, kFormat, name), "value file '" + name + "'");
    ValueFile file;
    file.process.pid = r.u32();
    file.process.creation_time = r.u64();
    file.process.wow64 = r.u8() != 0;
    file.process.name = r.str();
    file.process.path = r.str();
    file.candidates = read_candidates(r);
    return file;
}

std::uint64_t write_value_file(const std::string& path, const ProcessSummary& process, const ValueCandidates& candidates) {
    const std::vector<std::byte> bytes = encode_value_file(process, candidates);
    write_file_replacing(path, bytes);
    return bytes.size();
}

ValueFile read_value_file(const std::string& path) {
    return decode_value_file(read_file_bytes(path, kFormat.kind), path);
}

}  // namespace mh
