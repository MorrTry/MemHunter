#include "gui/widgets.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>

#include "gui/theme.hpp"

namespace mh::gui::ui {

namespace {

const char* visible_end(const char* label) {
    const char* hidden = std::strstr(label, "##");
    return hidden != nullptr ? hidden : label + std::strlen(label);
}

ImVec2 snapped(ImVec2 point) {
    return ImVec2(std::floor(point.x), std::floor(point.y));
}

bool framed_button(const char* label, bool selected, bool enabled, ImVec2 size) {
    const ImGuiStyle& style = ImGui::GetStyle();
    const char* end = visible_end(label);
    const ImVec2 text_size = ImGui::CalcTextSize(label, end);
    if (size.x == 0.0f) {
        size.x = text_size.x + style.FramePadding.x * 2.0f;
    } else if (size.x < 0.0f) {
        size.x = std::max(ImGui::GetContentRegionAvail().x, 1.0f);
    }
    if (size.y <= 0.0f) {
        size.y = ImGui::GetFrameHeight();
    }
    size = snapped(size);

    if (!enabled) {
        ImGui::BeginDisabled();
    }
    const bool pressed = ImGui::InvisibleButton(label, size);
    if (!enabled) {
        ImGui::EndDisabled();
    }
    const bool hovered = enabled && ImGui::IsItemHovered();
    const bool held = enabled && ImGui::IsItemActive();

    ImDrawList* draw = ImGui::GetWindowDrawList();
    const ImVec2 min = ImGui::GetItemRectMin();
    const ImVec2 max = ImGui::GetItemRectMax();
    const bool inverted = enabled && !held && (hovered || selected);
    if (inverted) {
        draw->AddRectFilled(min, max, theme::kWhite);
    }
    const ImU32 line = enabled ? theme::kWhite : theme::kMuted;
    draw->AddRect(min, max, line);
    if (held) {
        for (float inset = 1.0f; inset < theme::kPressedBorder; inset += 1.0f) {
            draw->AddRect(ImVec2(min.x + inset, min.y + inset), ImVec2(max.x - inset, max.y - inset), line);
        }
    }
    const ImU32 text = inverted ? theme::kBlack : line;
    const ImVec2 at(min.x + (size.x - text_size.x) * 0.5f, min.y + (size.y - text_size.y) * 0.5f);
    draw->AddText(snapped(at), text, label, end);
    return pressed && enabled;
}

}  // namespace

bool button(const char* label, bool enabled, ImVec2 size) {
    return framed_button(label, false, enabled, size);
}

bool segment(const char* label, bool selected, bool enabled, ImVec2 size) {
    return framed_button(label, selected, enabled, size);
}

void progress_bar(float fraction, std::string_view overlay, ImVec2 size) {
    fraction = std::clamp(fraction, 0.0f, 1.0f);
    if (size.x <= 0.0f) {
        size.x = std::max(ImGui::GetContentRegionAvail().x, 1.0f);
    }
    if (size.y <= 0.0f) {
        size.y = ImGui::GetFrameHeight();
    }
    const ImVec2 min = snapped(ImGui::GetCursorScreenPos());
    ImGui::Dummy(size);
    const ImVec2 max(min.x + std::floor(size.x), min.y + std::floor(size.y));
    ImDrawList* draw = ImGui::GetWindowDrawList();
    const float fill = std::floor(min.x + (max.x - min.x) * fraction);
    if (fill > min.x) {
        draw->AddRectFilled(min, ImVec2(fill, max.y), theme::kWhite);
    }
    draw->AddRect(min, max, theme::kWhite);

    const char* begin = overlay.data();
    const char* end = begin + overlay.size();
    const ImVec2 text_size = ImGui::CalcTextSize(begin, end);
    const ImVec2 at = snapped(ImVec2(min.x + (max.x - min.x - text_size.x) * 0.5f, min.y + (max.y - min.y - text_size.y) * 0.5f));
    draw->PushClipRect(min, ImVec2(fill, max.y), true);
    draw->AddText(at, theme::kBlack, begin, end);
    draw->PopClipRect();
    draw->PushClipRect(ImVec2(fill, min.y), max, true);
    draw->AddText(at, theme::kWhite, begin, end);
    draw->PopClipRect();
}

void heading(ImFont* font, const char* label) {
    ImGui::PushFont(font);
    ImGui::TextUnformatted(label);
    ImGui::PopFont();
    ImGui::Separator();
}

void muted(std::string_view value) {
    ImGui::PushStyleColor(ImGuiCol_Text, theme::kMuted);
    ImGui::TextUnformatted(value.data(), value.data() + value.size());
    ImGui::PopStyleColor();
}

void muted_wrapped(std::string_view value) {
    ImGui::PushStyleColor(ImGuiCol_Text, theme::kMuted);
    ImGui::PushTextWrapPos(0.0f);
    ImGui::TextUnformatted(value.data(), value.data() + value.size());
    ImGui::PopTextWrapPos();
    ImGui::PopStyleColor();
}

void text(std::string_view value) {
    ImGui::TextUnformatted(value.data(), value.data() + value.size());
}

void inverted_block(std::string_view value) {
    const ImGuiStyle& style = ImGui::GetStyle();
    const char* begin = value.data();
    const char* end = begin + value.size();
    const float width = std::max(ImGui::GetContentRegionAvail().x, 1.0f);
    const float wrap = std::max(width - style.FramePadding.x * 2.0f, 1.0f);
    const ImVec2 text_size = ImGui::CalcTextSize(begin, end, false, wrap);
    const ImVec2 min = snapped(ImGui::GetCursorScreenPos());
    const ImVec2 size(std::floor(width), std::floor(text_size.y + style.FramePadding.y * 2.0f));
    ImGui::Dummy(size);
    ImDrawList* draw = ImGui::GetWindowDrawList();
    draw->AddRectFilled(min, ImVec2(min.x + size.x, min.y + size.y), theme::kWhite);
    draw->AddText(ImGui::GetFont(), ImGui::GetFontSize(), ImVec2(min.x + style.FramePadding.x, min.y + style.FramePadding.y), theme::kBlack,
                  begin, end, wrap);
}

void field(const char* label, std::string_view value, float value_x, ImFont* value_font) {
    muted(label);
    ImGui::SameLine(value_x);
    if (value_font != nullptr) {
        ImGui::PushFont(value_font);
    }
    ImGui::PushTextWrapPos(0.0f);
    text(value);
    ImGui::PopTextWrapPos();
    if (value_font != nullptr) {
        ImGui::PopFont();
    }
}

}  // namespace mh::gui::ui
