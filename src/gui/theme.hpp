#pragma once

#include <imgui.h>

namespace mh::gui::theme {

// The whole interface uses these values and nothing else: black and white, plus neutral greys for
// inactive text and hover. There are no hues anywhere, so every pixel has R == G == B.
inline constexpr ImU32 kBlack = IM_COL32(0, 0, 0, 255);
inline constexpr ImU32 kWhite = IM_COL32(255, 255, 255, 255);
inline constexpr ImU32 kMuted = IM_COL32(150, 150, 150, 255);
inline constexpr ImU32 kHover = IM_COL32(44, 44, 44, 255);
inline constexpr ImU32 kPressed = IM_COL32(70, 70, 70, 255);
inline constexpr ImU32 kTextSelection = IM_COL32(105, 105, 105, 255);

inline constexpr float kFontSize = 16.0f;
inline constexpr float kMonoFontSize = 15.0f;

// Border of a pressed button; every other line is one pixel (times the DPI scale).
inline constexpr float kPressedBorder = 2.0f;

struct Fonts {
    ImFont* ui = nullptr;
    ImFont* heading = nullptr;
    ImFont* mono = nullptr;
};

// Spacing, borders and colours of every ImGui widget, scaled for the monitor DPI.
void apply_style(ImGuiStyle& style, float scale);

class FontLoader {
public:
    // Rebuilds the atlas from the Windows fonts (Segoe UI, Consolas) with Latin and Cyrillic glyphs. A missing
    // font falls back to Segoe UI, and Segoe UI itself to the ImGui built-in font.
    Fonts load(ImGuiIO& io, float scale);

private:
    // The atlas keeps a pointer to the glyph ranges until it is built.
    ImVector<ImWchar> ranges_;
};

}  // namespace mh::gui::theme
