#include "gui/theme.hpp"

#include <windows.h>

#include <filesystem>
#include <string>

#include "common/text.hpp"

namespace mh::gui::theme {

namespace {

ImVec4 color(ImU32 value) {
    return ImGui::ColorConvertU32ToFloat4(value);
}

ImVec4 black_alpha(float alpha) {
    return ImVec4(0.0f, 0.0f, 0.0f, alpha);
}

std::filesystem::path fonts_directory() {
    std::wstring windows(MAX_PATH, L'\0');
    const UINT length = GetWindowsDirectoryW(windows.data(), static_cast<UINT>(windows.size()));
    if (length == 0 || length >= windows.size()) {
        return std::filesystem::path(L"C:\\Windows\\Fonts");
    }
    windows.resize(length);
    return std::filesystem::path(windows) / L"Fonts";
}

ImFont* add_font(ImGuiIO& io, const std::filesystem::path& path, float size, const ImWchar* ranges) {
    std::error_code error;
    if (!std::filesystem::is_regular_file(path, error)) {
        return nullptr;
    }
    ImFontConfig config;
    config.OversampleH = 2;
    config.OversampleV = 1;
    return io.Fonts->AddFontFromFileTTF(wide_to_utf8(path.wstring()).c_str(), size, &config, ranges);
}

}  // namespace

void apply_style(ImGuiStyle& style, float scale) {
    style = ImGuiStyle();
    style.WindowPadding = ImVec2(10, 10);
    style.FramePadding = ImVec2(8, 5);
    style.CellPadding = ImVec2(6, 3);
    style.ItemSpacing = ImVec2(8, 7);
    style.ItemInnerSpacing = ImVec2(6, 5);
    style.IndentSpacing = 16;
    style.ScrollbarSize = 13;
    style.GrabMinSize = 12;
    style.WindowRounding = 0;
    style.ChildRounding = 0;
    style.FrameRounding = 0;
    style.PopupRounding = 0;
    style.ScrollbarRounding = 0;
    style.GrabRounding = 0;
    style.TabRounding = 0;
    style.WindowBorderSize = 1;
    style.ChildBorderSize = 1;
    style.PopupBorderSize = 1;
    style.FrameBorderSize = 1;
    style.TabBorderSize = 1;
    style.SeparatorTextBorderSize = 1;
    style.DisabledAlpha = 0.45f;
    style.SelectableTextAlign = ImVec2(0.0f, 0.5f);
    style.ScaleAllSizes(scale);

    ImVec4* c = style.Colors;
    c[ImGuiCol_Text] = color(kWhite);
    c[ImGuiCol_TextDisabled] = color(kMuted);
    c[ImGuiCol_WindowBg] = color(kBlack);
    c[ImGuiCol_ChildBg] = color(kBlack);
    c[ImGuiCol_PopupBg] = color(kBlack);
    c[ImGuiCol_Border] = color(kWhite);
    c[ImGuiCol_BorderShadow] = black_alpha(0.0f);
    c[ImGuiCol_FrameBg] = color(kBlack);
    c[ImGuiCol_FrameBgHovered] = color(kHover);
    c[ImGuiCol_FrameBgActive] = color(kPressed);
    c[ImGuiCol_TitleBg] = color(kBlack);
    c[ImGuiCol_TitleBgActive] = color(kBlack);
    c[ImGuiCol_TitleBgCollapsed] = color(kBlack);
    c[ImGuiCol_MenuBarBg] = color(kBlack);
    c[ImGuiCol_ScrollbarBg] = color(kBlack);
    c[ImGuiCol_ScrollbarGrab] = color(kTextSelection);
    c[ImGuiCol_ScrollbarGrabHovered] = color(kMuted);
    c[ImGuiCol_ScrollbarGrabActive] = color(kWhite);
    c[ImGuiCol_CheckMark] = color(kWhite);
    c[ImGuiCol_SliderGrab] = color(kWhite);
    c[ImGuiCol_SliderGrabActive] = color(kWhite);
    c[ImGuiCol_Button] = color(kBlack);
    c[ImGuiCol_ButtonHovered] = color(kHover);
    c[ImGuiCol_ButtonActive] = color(kPressed);
    // Selected rows are white; the view draws their text black.
    c[ImGuiCol_Header] = color(kWhite);
    c[ImGuiCol_HeaderHovered] = color(kHover);
    c[ImGuiCol_HeaderActive] = color(kPressed);
    c[ImGuiCol_Separator] = color(kWhite);
    c[ImGuiCol_SeparatorHovered] = color(kWhite);
    c[ImGuiCol_SeparatorActive] = color(kWhite);
    c[ImGuiCol_ResizeGrip] = black_alpha(0.0f);
    c[ImGuiCol_ResizeGripHovered] = black_alpha(0.0f);
    c[ImGuiCol_ResizeGripActive] = black_alpha(0.0f);
    c[ImGuiCol_TabHovered] = color(kHover);
    c[ImGuiCol_Tab] = color(kBlack);
    c[ImGuiCol_TabSelected] = color(kPressed);
    c[ImGuiCol_TabSelectedOverline] = color(kWhite);
    c[ImGuiCol_TabDimmed] = color(kBlack);
    c[ImGuiCol_TabDimmedSelected] = color(kPressed);
    c[ImGuiCol_TabDimmedSelectedOverline] = color(kWhite);
    c[ImGuiCol_PlotLines] = color(kWhite);
    c[ImGuiCol_PlotLinesHovered] = color(kWhite);
    c[ImGuiCol_PlotHistogram] = color(kWhite);
    c[ImGuiCol_PlotHistogramHovered] = color(kWhite);
    c[ImGuiCol_TableHeaderBg] = color(kBlack);
    c[ImGuiCol_TableBorderStrong] = color(kWhite);
    c[ImGuiCol_TableBorderLight] = color(kWhite);
    c[ImGuiCol_TableRowBg] = black_alpha(0.0f);
    c[ImGuiCol_TableRowBgAlt] = black_alpha(0.0f);
    c[ImGuiCol_TextLink] = color(kWhite);
    c[ImGuiCol_TextSelectedBg] = color(kTextSelection);
    c[ImGuiCol_DragDropTarget] = color(kWhite);
    c[ImGuiCol_NavCursor] = color(kWhite);
    c[ImGuiCol_NavWindowingHighlight] = color(kWhite);
    c[ImGuiCol_NavWindowingDimBg] = black_alpha(0.6f);
    c[ImGuiCol_ModalWindowDimBg] = black_alpha(0.7f);
}

Fonts FontLoader::load(ImGuiIO& io, float scale) {
    io.Fonts->Clear();
    ranges_.clear();
    ImFontGlyphRangesBuilder builder;
    builder.AddRanges(io.Fonts->GetGlyphRangesCyrillic());
    builder.AddText("—–…«»„“”‘’→←↑↓№×·•−");
    builder.BuildRanges(&ranges_);

    const std::filesystem::path fonts = fonts_directory();
    Fonts result;
    result.ui = add_font(io, fonts / L"segoeui.ttf", kFontSize * scale, ranges_.Data);
    if (result.ui == nullptr) {
        ImFontConfig config;
        config.SizePixels = 13.0f * scale;
        result.ui = io.Fonts->AddFontDefault(&config);
    }
    result.heading = add_font(io, fonts / L"seguisb.ttf", kFontSize * scale, ranges_.Data);
    result.mono = add_font(io, fonts / L"consola.ttf", kMonoFontSize * scale, ranges_.Data);
    if (result.heading == nullptr) {
        result.heading = result.ui;
    }
    if (result.mono == nullptr) {
        result.mono = result.ui;
    }
    io.FontDefault = result.ui;
    return result;
}

}  // namespace mh::gui::theme
