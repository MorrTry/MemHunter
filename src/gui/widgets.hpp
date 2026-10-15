#pragma once

#include <imgui.h>

#include <initializer_list>
#include <string_view>
#include <utility>

namespace mh::gui::ui {

// ImGui draws button text in one colour whatever the state, so buttons that invert on hover are drawn here.
// Normal: black with a white outline. Hover and "selected": white with black text. Pressed: black with a
// thicker outline. Disabled: grey outline and grey text.
bool button(const char* label, bool enabled = true, ImVec2 size = ImVec2(0, 0));

// One choice of a group; the selected one stays inverted.
bool segment(const char* label, bool selected, bool enabled = true, ImVec2 size = ImVec2(0, 0));

// A row of segments that share the available width; returns true when the value changed.
template <typename E>
bool segments(E& value, std::initializer_list<std::pair<E, const char*>> options, bool enabled = true) {
    const float spacing = ImGui::GetStyle().ItemSpacing.x;
    const float count = static_cast<float>(options.size());
    const float width = (ImGui::GetContentRegionAvail().x - spacing * (count - 1.0f)) / count;
    bool changed = false;
    bool first = true;
    ImGui::PushID(static_cast<const void*>(&value));
    for (const auto& [option, label] : options) {
        if (!first) {
            ImGui::SameLine(0.0f, spacing);
        }
        first = false;
        if (segment(label, value == option, enabled, ImVec2(width, 0.0f)) && value != option) {
            value = option;
            changed = true;
        }
    }
    ImGui::PopID();
    return changed;
}

// White outline and fill; the overlay text is black over the filled part and white over the rest.
void progress_bar(float fraction, std::string_view overlay, ImVec2 size = ImVec2(-1.0f, 0.0f));

// Section title with a thin rule under it.
void heading(ImFont* font, const char* text);

void muted(std::string_view text);
void muted_wrapped(std::string_view text);
void text(std::string_view text);

// An inverted block for messages that must not be missed.
void inverted_block(std::string_view text);

// "Label   value" with the value starting at `value_x` from the left edge of the content and wrapped at its right edge.
void field(const char* label, std::string_view value, float value_x, ImFont* value_font = nullptr);

}  // namespace mh::gui::ui
