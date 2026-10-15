#include "gui/process_picker.hpp"

#include <string>

#include "common/text.hpp"

namespace mh::gui {

std::vector<const ProcessEntry*> matching_processes(std::span<const ProcessEntry> processes, std::string_view filter) {
    const std::string needle = to_lower_ascii(filter);
    std::vector<const ProcessEntry*> visible;
    visible.reserve(processes.size());
    for (const ProcessEntry& entry : processes) {
        if (needle.empty() || to_lower_ascii(entry.name).find(needle) != std::string::npos ||
            std::to_string(entry.pid).find(needle) != std::string::npos) {
            visible.push_back(&entry);
        }
    }
    return visible;
}

std::optional<std::uint32_t> picker_choice(std::span<const ProcessEntry* const> visible, std::optional<std::uint32_t> picked) {
    for (const ProcessEntry* entry : visible) {
        if (picked == entry->pid) {
            return picked;
        }
    }
    if (visible.size() == 1) {
        return visible.front()->pid;
    }
    return std::nullopt;
}

}  // namespace mh::gui
