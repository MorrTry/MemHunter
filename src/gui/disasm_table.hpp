#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace mh::gui {

// "1 инструкция", "2 инструкции", "5 инструкций".
std::string count_instructions(std::uint64_t count);

// One decoded instruction, ready to show.
struct DisasmLine {
    std::uint64_t address = 0;
    // "48 89 D8", uppercase and space-separated.
    std::string bytes;
    // How many bytes the instruction occupies.
    std::uint8_t size = 0;
    // "mov rax, rbx", or "db 0xCC" for a byte that does not decode.
    std::string text;
    bool valid = true;
    // "module.dll+0x1234" when a branch leads into a known module; empty otherwise.
    std::string target;
    // The absolute address a jump or call leads to; set only for a relative branch.
    std::uint64_t target_address = 0;
    bool has_target = false;
};

// The instructions of the last disassembly in the GUI: a flat list from one address, with a selection.
class DisasmTable {
public:
    void assign(std::uint64_t address, bool wow64, std::vector<DisasmLine> lines);
    void clear();

    bool has_result() const noexcept { return has_result_; }
    std::uint64_t address() const noexcept { return address_; }
    bool wow64() const noexcept { return wow64_; }

    std::span<const DisasmLine> rows() const noexcept { return lines_; }
    const DisasmLine& line(std::size_t row) const { return lines_[row]; }

    std::optional<std::size_t> selected_row() const noexcept { return selected_; }
    const DisasmLine* selected() const;
    void select_row(std::size_t row);
    void move_selection(std::ptrdiff_t delta);

private:
    bool has_result_ = false;
    std::uint64_t address_ = 0;
    bool wow64_ = false;
    std::vector<DisasmLine> lines_;
    std::optional<std::size_t> selected_;
};

}  // namespace mh::gui
