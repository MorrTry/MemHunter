#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

#include "tui/theme.hpp"

namespace mh::tui {

// ch == 0 marks the right half of a double-width character.
struct Cell {
    char32_t ch = U' ';
    Style style = Style::Normal;

    bool operator==(const Cell&) const = default;
};

// Off-screen character grid; a frame is drawn into it completely and then sent to the terminal at once.
class Screen {
public:
    Screen(std::size_t width, std::size_t height);

    std::size_t width() const noexcept { return width_; }
    std::size_t height() const noexcept { return height_; }
    const Cell& at(std::size_t x, std::size_t y) const { return cells_[y * width_ + x]; }

    // Writes UTF-8 text at (x, y), clipped to `max_width` cells and to the screen. Control characters are shown
    // as '.'. Returns the number of cells used.
    std::size_t text(std::size_t x, std::size_t y, std::string_view utf8, Style style = Style::Normal,
                     std::size_t max_width = std::string_view::npos);
    void put(std::size_t x, std::size_t y, char32_t ch, Style style = Style::Normal);
    void fill(std::size_t x, std::size_t y, std::size_t w, std::size_t h, char32_t ch, Style style = Style::Normal);
    void frame(std::size_t x, std::size_t y, std::size_t w, std::size_t h, const Frame& frame, Style style = Style::Normal);
    void restyle(std::size_t x, std::size_t y, std::size_t w, Style style);

    // The row as UTF-8 text, for tests and diagnostics.
    std::string row(std::size_t y) const;

private:
    std::size_t width_;
    std::size_t height_;
    std::vector<Cell> cells_;
};

// Display cells a code point occupies: 2 for East Asian wide characters, otherwise 1.
std::size_t char_width(char32_t ch) noexcept;
std::size_t text_width(std::string_view utf8);

// Terminal output that turns `previous` into `next`: rows that did not change are skipped, and a null or
// differently sized `previous` repaints everything.
std::wstring render(const Screen& next, const Screen* previous);

}  // namespace mh::tui
