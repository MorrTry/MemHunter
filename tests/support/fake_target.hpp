#pragma once

#include <cstdint>
#include <string>

#include "gui/session.hpp"
#include "support/fake_memory.hpp"

namespace mh::testing {

// A process of the GUI session that reads a FakeMemory.
class FakeTarget final : public gui::Target {
public:
    explicit FakeTarget(const FakeMemory& memory, std::uint32_t pid = 4321, std::string name = "fake.exe") : memory_(memory) {
        summary_.pid = pid;
        summary_.name = std::move(name);
        summary_.creation_time = 1;
    }

    const MemorySource& memory() const override { return memory_; }
    const ProcessSummary& summary() const override { return summary_; }

private:
    const FakeMemory& memory_;
    ProcessSummary summary_;
};

}  // namespace mh::testing
