#include "pointer/pointer_chain.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <map>

#include "common/text.hpp"

namespace mh {

ModuleMap::ModuleMap(std::span<const Region> regions) {
    std::map<std::uint64_t, Module> by_base;
    for (const Region& region : regions) {
        if (region.type != MemType::Image || region.mapped_file.empty() || region.allocation_base > region.base) {
            continue;
        }
        Module& module = by_base[region.allocation_base];
        if (module.name.empty()) {
            module.name = region.module_name();
            module.base = region.allocation_base;
        }
        module.end = std::max(module.end, region.end());
    }
    for (auto& [base, module] : by_base) {
        modules_.push_back(std::move(module));
    }
}

const Module* ModuleMap::find(std::string_view name) const {
    for (const Module& module : modules_) {
        if (iequals_ascii(module.name, name)) {
            return &module;
        }
    }
    return nullptr;
}

const Module* ModuleMap::locate(std::uint64_t address) const {
    const auto after = std::upper_bound(modules_.begin(), modules_.end(), address,
                                        [](std::uint64_t value, const Module& module) { return value < module.base; });
    if (after == modules_.begin()) {
        return nullptr;
    }
    const Module& module = *std::prev(after);
    return address < module.end ? &module : nullptr;
}

PointerPath path_of(const PointerChains& chains, std::size_t index) {
    const PointerChain& chain = chains.chains.at(index);
    const auto steps = chain.steps();
    return {chains.modules.at(chain.module), chain.base_offset, {steps.begin(), steps.end()}, chains.pointer_size};
}

std::string format_pointer_base(std::string_view module, std::uint64_t offset) {
    return module.empty() ? format_hex(offset) : std::string(module) + "+" + format_hex(offset);
}

std::string format_pointer_offsets(std::span<const std::uint32_t> offsets) {
    std::string text;
    for (const std::uint32_t offset : offsets) {
        if (!text.empty()) {
            text += ", ";
        }
        text += format_hex(offset);
    }
    return text;
}

std::string format_pointer_path(const PointerPath& path) {
    std::string text = std::string(path.offsets.size(), '[') + format_pointer_base(path.module, path.base_offset);
    for (const std::uint32_t offset : path.offsets) {
        text += "]+" + format_hex(offset);
    }
    return text;
}

namespace {

std::string_view trim_spaces(std::string_view text) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) {
        text.remove_prefix(1);
    }
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) {
        text.remove_suffix(1);
    }
    return text;
}

std::optional<std::uint64_t> parse_hex(std::string_view text) {
    text = trim_spaces(text);
    if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        text.remove_prefix(2);
    }
    if (text.empty() || text.size() > 16) {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    for (const char c : text) {
        const int digit = c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
        if (digit < 0) {
            return std::nullopt;
        }
        value = value << 4 | static_cast<std::uint64_t>(digit);
    }
    return value;
}

bool parse_base(std::string_view text, PointerPath& path) {
    text = trim_spaces(text);
    const std::size_t plus = text.find('+');
    const std::string_view name = trim_spaces(text.substr(0, plus));
    std::uint64_t offset = 0;
    if (plus != std::string_view::npos) {
        const auto parsed = parse_hex(text.substr(plus + 1));
        if (!parsed) {
            return false;
        }
        offset = *parsed;
    }
    if (name.empty()) {
        return false;
    }
    if (const auto address = parse_hex(name); address && name.find('.') == std::string_view::npos) {
        path.base_offset = *address + offset;
        return true;
    }
    if (name.find_first_of("[]") != std::string_view::npos) {
        return false;
    }
    path.module = std::string(name);
    path.base_offset = offset;
    return true;
}

}  // namespace

std::optional<PointerPath> parse_pointer_path(std::string_view text, unsigned pointer_size) {
    PointerPath path;
    path.pointer_size = pointer_size;
    text = trim_spaces(text);
    std::size_t depth = 0;
    while (!text.empty() && text.front() == '[') {
        ++depth;
        text = trim_spaces(text.substr(1));
    }
    if (depth > kMaxPathOffsets || !parse_base(text.substr(0, text.find(']')), path)) {
        return std::nullopt;
    }
    text.remove_prefix(std::min(text.size(), text.find(']')));
    while (!text.empty()) {
        if (text.front() != ']' || path.offsets.size() == depth) {
            return std::nullopt;
        }
        text = trim_spaces(text.substr(1));
        std::uint64_t offset = 0;
        if (!text.empty() && text.front() == '+') {
            const std::size_t end = text.find(']');
            const auto parsed = parse_hex(text.substr(1, end == std::string_view::npos ? std::string_view::npos : end - 1));
            if (!parsed || *parsed > std::numeric_limits<std::uint32_t>::max()) {
                return std::nullopt;
            }
            offset = *parsed;
            text.remove_prefix(std::min(text.size(), end));
        }
        path.offsets.push_back(static_cast<std::uint32_t>(offset));
    }
    if (path.offsets.size() != depth) {
        return std::nullopt;
    }
    return path;
}

std::vector<std::uint64_t> module_bases(const ModuleMap& modules, std::span<const std::string> names) {
    std::vector<std::uint64_t> bases;
    bases.reserve(names.size());
    for (const std::string& name : names) {
        const Module* module = modules.find(name);
        bases.push_back(module != nullptr ? module->base : 0);
    }
    return bases;
}

namespace {

std::optional<std::uint64_t> follow(const MemorySource& memory, std::uint64_t address, std::span<const std::uint32_t> offsets,
                                    unsigned pointer_size) {
    if (pointer_size != 4 && pointer_size != 8) {
        return std::nullopt;
    }
    for (const std::uint32_t offset : offsets) {
        std::uint64_t pointer = 0;
        std::byte bytes[8];
        if (memory.read(address, std::span(bytes, pointer_size)).bytes != pointer_size) {
            return std::nullopt;
        }
        std::memcpy(&pointer, bytes, pointer_size);
        address = pointer + offset;
    }
    return address;
}

}  // namespace

std::optional<std::uint64_t> resolve_chain(const MemorySource& memory, std::span<const std::uint64_t> bases,
                                           const PointerChain& chain, unsigned pointer_size) {
    if (chain.module >= bases.size() || bases[chain.module] == 0) {
        return std::nullopt;
    }
    return follow(memory, bases[chain.module] + chain.base_offset, chain.steps(), pointer_size);
}

std::optional<std::uint64_t> resolve_pointer_path(const MemorySource& memory, const ModuleMap& modules, const PointerPath& path) {
    if (path.module.empty()) {
        return follow(memory, path.base_offset, path.offsets, path.pointer_size);
    }
    const Module* module = modules.find(path.module);
    if (module == nullptr) {
        return std::nullopt;
    }
    return follow(memory, module->base + path.base_offset, path.offsets, path.pointer_size);
}

}  // namespace mh
