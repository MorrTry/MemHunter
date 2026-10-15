#pragma once

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <random>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#include "memory/memory_source.hpp"

namespace mh::testing {

// In-memory MemorySource that can simulate what makes real process reads hard: pages that fail although
// VirtualQueryEx called them readable, ReadProcessMemory returning nothing for a range that is only partly
// readable, and the target exiting in the middle of a scan.
class FakeMemory final : public MemorySource {
public:
    static constexpr std::size_t kPage = 4096;
    static constexpr std::uint32_t kPartialCopy = 299;
    static constexpr std::uint32_t kNoAccess = 998;

    std::span<std::byte> add(std::uint64_t base, std::size_t size, std::uint32_t protect = page::ReadWrite,
                             MemType type = MemType::Private) {
        if (base % kPage != 0 || size % kPage != 0 || size == 0) {
            throw std::invalid_argument("fake regions must be page aligned");
        }
        Block block;
        block.region.base = base;
        block.region.size = size;
        block.region.allocation_base = base;
        block.region.protect = protect;
        block.region.allocation_protect = protect;
        block.region.state = MemState::Commit;
        block.region.type = type;
        block.bytes.resize(size);
        const auto at = std::upper_bound(blocks_.begin(), blocks_.end(), base,
                                         [](std::uint64_t b, const Block& other) { return b < other.region.base; });
        const auto inserted = blocks_.insert(at, std::move(block));
        return inserted->bytes;
    }

    // A region of the module image loaded at `allocation_base` (0: this region starts it).
    std::span<std::byte> add_image(std::uint64_t base, std::size_t size, std::string path, std::uint64_t allocation_base = 0,
                                   std::uint32_t protect = page::ReadWrite) {
        const auto bytes = add(base, size, protect, MemType::Image);
        auto& block = find_block(base);
        block.region.mapped_file = std::move(path);
        block.region.allocation_base = allocation_base != 0 ? allocation_base : base;
        return bytes;
    }

    void add_reserved(std::uint64_t base, std::size_t size) {
        add(base, size, 0, MemType::Private);
        auto& block = find_block(base);
        block.region.state = MemState::Reserve;
    }

    void fail_page(std::uint64_t address) { failing_.insert(address / kPage * kPage); }
    void set_all_or_nothing(bool value) { all_or_nothing_ = value; }
    void exit_after_reads(std::size_t reads) { exit_after_ = reads; }
    void on_read(std::function<void(std::size_t)> callback) { on_read_ = std::move(callback); }

    std::span<std::byte> bytes_at(std::uint64_t address, std::size_t size) {
        auto& block = find_block(address);
        return std::span<std::byte>(block.bytes).subspan(address - block.region.base, size);
    }

    std::span<const std::byte> view(std::uint64_t address, std::size_t size) const {
        const Block* block = block_at(address);
        if (block == nullptr) {
            throw std::out_of_range("address outside fake memory");
        }
        return std::span<const std::byte>(block->bytes).subspan(address - block->region.base, size);
    }

    bool page_readable(std::uint64_t address) const {
        const Block* block = block_at(address);
        return block != nullptr && block->region.state == MemState::Commit && is_readable_protection(block->region.protect) &&
               (block->region.protect & page::Guard) == 0 && failing_.count(address / kPage * kPage) == 0;
    }

    std::size_t read_count() const noexcept { return reads_.load(); }
    std::size_t guard_reads() const noexcept { return guard_reads_.load(); }

    std::vector<Region> query_regions() const override {
        std::vector<Region> regions;
        for (const auto& block : blocks_) {
            regions.push_back(block.region);
        }
        return regions;
    }

    ReadResult read(std::uint64_t address, std::span<std::byte> out) const override {
        const std::size_t number = ++reads_;
        if (on_read_) {
            on_read_(number);
        }
        if (exited(number)) {
            return {0, kPartialCopy};
        }
        std::size_t copied = 0;
        while (copied < out.size()) {
            const std::uint64_t at = address + copied;
            const Block* block = block_at(at);
            if (block != nullptr && (block->region.protect & page::Guard) != 0) {
                ++guard_reads_;
            }
            if (!page_readable(at)) {
                return {all_or_nothing_ ? 0 : copied, copied == 0 ? kNoAccess : kPartialCopy};
            }
            const std::uint64_t page_end = (at / kPage + 1) * kPage;
            const std::size_t take = std::min<std::uint64_t>(out.size() - copied, page_end - at);
            std::memcpy(out.data() + copied, block->bytes.data() + (at - block->region.base), take);
            copied += take;
        }
        return {copied, 0};
    }

    bool target_alive() const override { return !exited(reads_.load()); }
    std::size_t page_size() const override { return kPage; }

private:
    struct Block {
        Region region;
        std::vector<std::byte> bytes;
    };

    bool exited(std::size_t reads) const noexcept { return exit_after_ != 0 && reads > exit_after_; }

    const Block* block_at(std::uint64_t address) const {
        const auto it = std::upper_bound(blocks_.begin(), blocks_.end(), address,
                                         [](std::uint64_t a, const Block& b) { return a < b.region.base; });
        if (it == blocks_.begin()) {
            return nullptr;
        }
        const Block& block = *std::prev(it);
        return address < block.region.end() ? &block : nullptr;
    }

    Block& find_block(std::uint64_t address) {
        const Block* block = block_at(address);
        if (block == nullptr) {
            throw std::out_of_range("address outside fake memory");
        }
        return const_cast<Block&>(*block);
    }

    std::vector<Block> blocks_;
    std::set<std::uint64_t> failing_;
    bool all_or_nothing_ = false;
    std::size_t exit_after_ = 0;
    std::function<void(std::size_t)> on_read_;
    mutable std::atomic<std::size_t> reads_{0};
    mutable std::atomic<std::size_t> guard_reads_{0};
};

inline void fill_random(std::span<std::byte> bytes, std::uint64_t seed) {
    std::mt19937_64 rng(seed);
    for (auto& b : bytes) {
        b = static_cast<std::byte>(rng() & 0xFF);
    }
}

}  // namespace mh::testing
