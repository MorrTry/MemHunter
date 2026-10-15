#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "gui/watch_list.hpp"
#include "memory/memory_source.hpp"
#include "pointer/pointer_chain.hpp"
#include "results/result_set.hpp"

namespace mh::gui {

// What the chains of the list lead to and how they were found.
struct PointerSearch {
    // The process of the search, or of the last check.
    ProcessSummary process;
    // The entry of the address list the search started from, with the address of the search or the last check.
    WatchEntry target;
    unsigned depth = 5;
    std::uint32_t max_offset = 0x1000;
    // Checks that have filtered the chains since the search.
    std::uint32_t checks = 0;
    // Chains the search found; more than the list holds when it was cut at its limit.
    std::uint64_t found = 0;
};

// Chains of pointers found by a search, with where the shown ones lead now.
class PointerList {
public:
    // Selects the first chain.
    void assign(std::shared_ptr<const PointerChains> chains, PointerSearch search);
    void clear();

    bool has_chains() const noexcept { return chains_ != nullptr; }
    const std::shared_ptr<const PointerChains>& chains() const noexcept { return chains_; }
    std::span<const PointerChain> rows() const noexcept;
    const PointerSearch& search() const noexcept { return search_; }

    // The modules of the target process, where the chains start.
    void set_modules(const ModuleMap& modules);

    std::optional<std::size_t> selected_row() const noexcept { return selected_; }
    void select_row(std::size_t row);
    void move_selection(std::ptrdiff_t delta);

    // Follows the chains of rows [first, last) and reads the values they lead to.
    void refresh(const MemorySource& memory, std::size_t first, std::size_t last);
    // Forgets what was read, so that only the rows refreshed next are kept.
    void forget_live() { live_.clear(); }
    bool read(std::size_t row) const { return live_.contains(row); }
    // Where the chain led at the last refresh; nullopt when it was not read or leads nowhere.
    std::optional<std::uint64_t> address(std::size_t row) const;

    // "game.exe+0x1A2B0".
    std::string base_text(std::size_t row) const;
    // "0x10, 0x8".
    std::string offsets_text(std::size_t row) const;
    // "[[game.exe+0x1A2B0]+0x10]+0x8".
    std::string path_text(std::size_t row) const;
    // Empty until read, "??" when the chain leads nowhere or the value cannot be read.
    std::string address_text(std::size_t row) const;
    std::string value_text(std::size_t row) const;

    PointerPath path(std::size_t row) const;
    // An entry of the address list that follows the chain, with the type and description of the search target.
    WatchEntry watch_entry(std::size_t row) const;

private:
    struct Live {
        std::optional<std::uint64_t> address;
        std::optional<std::vector<std::byte>> bytes;
    };

    std::shared_ptr<const PointerChains> chains_;
    PointerSearch search_;
    std::vector<std::uint64_t> bases_;
    std::map<std::size_t, Live> live_;
    std::optional<std::size_t> selected_;
};

}  // namespace mh::gui
