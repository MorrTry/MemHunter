#include "pointer/pointer_chain.hpp"

#include <algorithm>
#include <cstring>
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
    return std::string(module) + "+" + format_hex(offset);
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
    const Module* module = modules.find(path.module);
    if (module == nullptr) {
        return std::nullopt;
    }
    return follow(memory, module->base + path.base_offset, path.offsets, path.pointer_size);
}

}  // namespace mh
