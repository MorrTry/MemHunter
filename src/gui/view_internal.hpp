#pragma once

#include <imgui.h>

#include <chrono>
#include <string_view>

// Pieces shared by the files that implement View.
namespace mh::gui {

inline constexpr ImGuiWindowFlags kPanel = ImGuiWindowFlags_NoSavedSettings;
inline constexpr ImGuiWindowFlags kDialog =
    ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings;
// How often values on screen are reread.
inline constexpr auto kLiveRefresh = std::chrono::milliseconds(500);

float button_width(const char* label);
float font_text_width(ImFont* font, std::string_view text);
// Text on a white block, in the flow of a line.
void inverted_text(std::string_view text);

void center_next_dialog(float width);
bool enter_pressed();
// Buttons at the right edge of the line; returns the index of the pressed one.
int dialog_buttons(const char* first, const char* second);

// Arrows, Page Up/Down, Home and End move the selection of a table; true when one of them was pressed.
template <typename Table>
bool navigate(Table& table, int page_rows) {
    const auto rows = static_cast<std::ptrdiff_t>(table.rows().size());
    std::ptrdiff_t delta = 0;
    if (ImGui::IsKeyPressed(ImGuiKey_DownArrow)) {
        delta = 1;
    } else if (ImGui::IsKeyPressed(ImGuiKey_UpArrow)) {
        delta = -1;
    } else if (ImGui::IsKeyPressed(ImGuiKey_PageDown)) {
        delta = page_rows;
    } else if (ImGui::IsKeyPressed(ImGuiKey_PageUp)) {
        delta = -page_rows;
    } else if (ImGui::IsKeyPressed(ImGuiKey_Home, false)) {
        delta = -rows;
    } else if (ImGui::IsKeyPressed(ImGuiKey_End, false)) {
        delta = rows;
    } else {
        return false;
    }
    table.move_selection(delta);
    return true;
}

}  // namespace mh::gui
