#pragma once

#include <cstddef>

#include "tui/model.hpp"
#include "tui/screen.hpp"

namespace mh::tui {

// Rows of the six areas: top bar, search, progress, results, details and the status line.
struct Layout {
    bool too_small = false;
    std::size_t width = 0;
    std::size_t height = 0;
    std::size_t search_y = 1;
    std::size_t progress_y = 5;
    std::size_t results_y = 8;
    std::size_t results_height = 0;
    std::size_t details_y = 0;
    std::size_t status_y = 0;
    std::size_t page_rows = 0;
};

Layout layout_for(std::size_t width, std::size_t height);

void draw(Screen& screen, const State& state);

}  // namespace mh::tui
