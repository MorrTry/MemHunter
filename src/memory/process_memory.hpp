#pragma once

#include "memory/memory_source.hpp"
#include "process/process.hpp"

namespace mh {

class ProcessMemory final : public MemorySource {
public:
    explicit ProcessMemory(const Process& process);

    std::vector<Region> query_regions() const override;
    ReadResult read(std::uint64_t address, std::span<std::byte> out) const override;
    bool target_alive() const override;
    std::size_t page_size() const override { return page_size_; }

private:
    const Process& process_;
    std::size_t page_size_ = 4096;
};

}  // namespace mh
