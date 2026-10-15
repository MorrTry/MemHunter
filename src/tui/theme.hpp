#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace mh::tui {

// The only visual attributes the interface uses: white on black, with emphasis by inversion, bold text or a
// double frame. No other colour appears anywhere, so the whole look is defined in this header.
enum class Style : std::uint8_t {
    Normal,   // white on black
    Strong,   // bold white on black: titles, column headers, the focused field label
    Inverse,  // black on white: selection, the focused control, the input cursor
};

struct Frame {
    char32_t horizontal;
    char32_t vertical;
    char32_t top_left;
    char32_t top_right;
    char32_t bottom_left;
    char32_t bottom_right;
};

namespace theme {

// Explicit 24-bit colours, so that a terminal palette or colour scheme cannot tint the interface.
inline constexpr std::string_view kNormalSgr = "\x1b[0;38;2;255;255;255;48;2;0;0;0m";
inline constexpr std::string_view kStrongSgr = "\x1b[0;1;38;2;255;255;255;48;2;0;0;0m";
inline constexpr std::string_view kInverseSgr = "\x1b[0;38;2;0;0;0;48;2;255;255;255m";

constexpr std::string_view sgr(Style style) noexcept {
    switch (style) {
        case Style::Strong: return kStrongSgr;
        case Style::Inverse: return kInverseSgr;
        case Style::Normal: break;
    }
    return kNormalSgr;
}

inline constexpr Frame kPanel{U'─', U'│', U'┌', U'┐', U'└', U'┘'};
inline constexpr Frame kFocusedPanel{U'═', U'║', U'╔', U'╗', U'╚', U'╝'};

inline constexpr char32_t kBarFilled = U'█';
inline constexpr char32_t kBarEmpty = U' ';
inline constexpr char32_t kSeparator = U'│';
inline constexpr char32_t kMarked = U'*';

inline constexpr std::size_t kMinWidth = 80;
inline constexpr std::size_t kMinHeight = 20;

}  // namespace theme
}  // namespace mh::tui
