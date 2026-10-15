#include "pointer/pointer_file.hpp"

#include "common/error.hpp"
#include "snapshot/binary_io.hpp"

namespace mh {

namespace {

const SealedFormat kFormat{{'M', 'H', 'P', 'T', 'R', 'S', '\x1A', '\n'}, kPointerFileVersion, "pointer file"};
// Module index, depth and base offset.
constexpr std::uint64_t kMinChainRecord = 4 + 1 + 8;
// The highest type number of the address list (bytes).
constexpr std::uint8_t kMaxTargetType = 8;

}  // namespace

std::vector<std::byte> encode_pointer_file(const PointerFile& file) {
    std::size_t size = 64 + file.process.name.size() + file.process.path.size() + file.chains.chains.size() * 40;
    for (const std::string& module : file.chains.modules) {
        size += 4 + module.size();
    }
    ByteWriter w = begin_sealed(kFormat, size);
    w.u32(file.process.pid);
    w.u64(file.process.creation_time);
    w.u8(file.process.wow64 ? 1 : 0);
    w.str(file.process.name);
    w.str(file.process.path);
    w.u64(file.target);
    w.u8(file.target_type);
    w.u32(file.target_length);
    w.u8(static_cast<std::uint8_t>(file.depth));
    w.u32(file.max_offset);
    w.u32(file.checks);
    w.u8(static_cast<std::uint8_t>(file.chains.pointer_size));
    w.u32(static_cast<std::uint32_t>(file.chains.modules.size()));
    for (const std::string& module : file.chains.modules) {
        w.str(module);
    }
    w.u64(file.chains.chains.size());
    for (const PointerChain& chain : file.chains.chains) {
        w.u32(chain.module);
        w.u8(chain.depth);
        w.u64(chain.base_offset);
        for (const std::uint32_t offset : chain.steps()) {
            w.u32(offset);
        }
    }
    return seal(w);
}

PointerFile decode_pointer_file(std::span<const std::byte> bytes, const std::string& name) {
    ByteReader r(unseal(bytes, kFormat, name), "pointer file '" + name + "'");
    PointerFile file;
    file.process.pid = r.u32();
    file.process.creation_time = r.u64();
    file.process.wow64 = r.u8() != 0;
    file.process.name = r.str();
    file.process.path = r.str();
    file.target = r.u64();
    file.target_type = r.u8();
    file.target_length = r.u32();
    file.depth = r.u8();
    file.max_offset = r.u32();
    file.checks = r.u32();
    file.chains.pointer_size = r.u8();
    if (file.target_type > kMaxTargetType || file.depth == 0 || file.depth > kMaxPointerDepth ||
        (file.chains.pointer_size != 4 && file.chains.pointer_size != 8)) {
        r.corrupt("invalid search settings");
    }
    const std::uint32_t modules = r.u32();
    if (modules > r.remaining() / 4 || modules > 0x10000) {
        r.corrupt("the module table is larger than the file");
    }
    file.chains.modules.reserve(modules);
    for (std::uint32_t i = 0; i < modules; ++i) {
        file.chains.modules.push_back(r.str());
    }
    const std::uint64_t chains = r.u64();
    if (chains > r.remaining() / kMinChainRecord) {
        r.corrupt("the chain table is larger than the file");
    }
    file.chains.chains.resize(chains);
    for (PointerChain& chain : file.chains.chains) {
        const std::uint32_t module = r.u32();
        chain.depth = r.u8();
        chain.base_offset = r.u64();
        if (module >= modules || chain.depth > kMaxPointerDepth) {
            r.corrupt("invalid chain");
        }
        chain.module = static_cast<std::uint16_t>(module);
        for (std::uint8_t step = 0; step < chain.depth; ++step) {
            chain.offsets[step] = r.u32();
        }
    }
    if (r.remaining() != 0) {
        r.corrupt("the chain table does not match the file size");
    }
    return file;
}

std::uint64_t write_pointer_file(const std::string& path, const PointerFile& file) {
    const std::vector<std::byte> bytes = encode_pointer_file(file);
    write_file_replacing(path, bytes);
    return bytes.size();
}

PointerFile read_pointer_file(const std::string& path) {
    return decode_pointer_file(read_file_bytes(path, kFormat.kind), path);
}

}  // namespace mh
