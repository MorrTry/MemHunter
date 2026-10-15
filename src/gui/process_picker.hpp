#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "process/process.hpp"

namespace mh::gui {

// Processes whose name (ignoring ASCII case) or PID contains the filter.
std::vector<const ProcessEntry*> matching_processes(std::span<const ProcessEntry> processes, std::string_view filter);

// What Enter and «Открыть» open: the picked process while the filter shows it, otherwise the only process shown.
std::optional<std::uint32_t> picker_choice(std::span<const ProcessEntry* const> visible, std::optional<std::uint32_t> picked);

}  // namespace mh::gui
