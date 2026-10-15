#pragma once

#include <cstdint>
#include <string>

#include "gui/session.hpp"
#include "inspect/inspect.hpp"
#include "support/fake_memory.hpp"

namespace mh::testing {

// A process of the GUI session that reads a FakeMemory; it can be inspected when it is given the facts.
class FakeTarget final : public gui::Target {
public:
    explicit FakeTarget(const FakeMemory& memory, std::uint32_t pid = 4321, std::string name = "fake.exe",
                        const InspectFacts* facts = nullptr)
        : memory_(memory), facts_(facts) {
        summary_.pid = pid;
        summary_.name = std::move(name);
        summary_.creation_time = 1;
    }

    const MemorySource& memory() const override { return memory_; }
    const ProcessSummary& summary() const override { return summary_; }

    std::optional<InspectReport> inspect(const InspectOptions& options, std::stop_token stop) const override {
        if (facts_ == nullptr) {
            return std::nullopt;
        }
        return inspect_memory(memory_, *facts_, options, std::move(stop));
    }

private:
    const FakeMemory& memory_;
    const InspectFacts* facts_;
    ProcessSummary summary_;
};

}  // namespace mh::testing
