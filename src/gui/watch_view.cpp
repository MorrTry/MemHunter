#include <imgui.h>
#include <misc/cpp/imgui_stdlib.h>

#include <algorithm>
#include <cfloat>
#include <cmath>

#include "common/text.hpp"
#include "gui/view.hpp"
#include "gui/view_internal.hpp"
#include "gui/widgets.hpp"

namespace mh::gui {

namespace {

// Three rows of segments, each starting at `x`.
bool type_segments(WatchType& type, float x) {
    ImGui::SetCursorPosX(x);
    bool changed = ui::segments(
        type, {{WatchType::Int8, "int8"}, {WatchType::Int16, "int16"}, {WatchType::Int32, "int32"}, {WatchType::Int64, "int64"}});
    ImGui::SetCursorPosX(x);
    changed |= ui::segments(type, {{WatchType::Float, "float"}, {WatchType::Double, "double"}});
    ImGui::SetCursorPosX(x);
    changed |= ui::segments(type, {{WatchType::Ascii, "ASCII"}, {WatchType::Utf16, "UTF-16"}, {WatchType::Bytes, "Байты"}});
    return changed;
}

std::string length_unit(WatchType type) {
    return std::string(type == WatchType::Bytes ? "байт" : "символов") + ", до " + std::to_string(max_length(type));
}

}  // namespace

void center_next_dialog(float width) {
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowSize(ImVec2(std::min(width, viewport->WorkSize.x - 40.0f), 0.0f), ImGuiCond_Always);
    ImGui::SetNextWindowPos(ImVec2(viewport->WorkPos.x + viewport->WorkSize.x * 0.5f, viewport->WorkPos.y + viewport->WorkSize.y * 0.5f),
                            ImGuiCond_Always, ImVec2(0.5f, 0.5f));
}

bool enter_pressed() {
    return ImGui::IsKeyPressed(ImGuiKey_Enter, false) || ImGui::IsKeyPressed(ImGuiKey_KeypadEnter, false);
}

int dialog_buttons(const char* first, const char* second) {
    ImGui::Separator();
    const float width = button_width(first) + button_width(second) + ImGui::GetStyle().ItemSpacing.x;
    ImGui::SetCursorPosX(ImGui::GetCursorPosX() + std::max(ImGui::GetContentRegionAvail().x - width, 0.0f));
    int pressed = -1;
    if (ui::button(first)) {
        pressed = 0;
    }
    ImGui::SameLine();
    if (ui::button(second)) {
        pressed = 1;
    }
    return pressed;
}

std::optional<WatchEntry> View::selected_as_watch() const {
    if (value_mode()) {
        const ValueTable& values = session_.values();
        if (values.selected() == nullptr || !values.candidates()) {
            return std::nullopt;
        }
        return make_watch_entry(values.selected()->address, watch_type(values.candidates()->type));
    }
    const ResultsTable& table = session_.table();
    const Match* match = table.selected_match();
    if (match == nullptr) {
        return std::nullopt;
    }
    return watch_entry_for(match->address, table.results().patterns[match->pattern].kind, match->length);
}

void View::open_add_watch() {
    const WatchEntry* selected = session_.watch().selected();
    add_address_ = selected != nullptr ? format_address(selected->address) : std::string();
    add_description_.clear();
    add_error_.clear();
    add_watch_requested_ = true;
    add_watch_focus_ = true;
}

void View::start_editing_description(std::size_t row) {
    WatchList& watch = session_.watch();
    if (row >= watch.rows().size()) {
        return;
    }
    watch.select_row(row);
    editing_row_ = row;
    description_edit_ = watch.rows()[row].description;
    focus_description_ = true;
    scroll_to_selection_ = true;
}

void View::handle_watch_shortcuts(bool copy) {
    WatchList& watch = session_.watch();
    scroll_to_selection_ |= navigate(watch, page_rows_);
    const std::optional<std::size_t> row = watch.selected_row();
    if (!row) {
        return;
    }
    if (ImGui::IsKeyPressed(ImGuiKey_Delete, false)) {
        watch.remove(*row);
        editing_row_.reset();
        scroll_to_selection_ = true;
        return;
    }
    if (ImGui::IsKeyPressed(ImGuiKey_F2, false)) {
        start_editing_description(*row);
    }
    if (copy) {
        copy_address(watch.rows()[*row].address);
    }
}

void View::draw_watch_bar(float right_edge) {
    const WatchList& watch = session_.watch();
    if (ui::button("Добавить адрес…")) {
        open_add_watch();
    }
    ImGui::SameLine();
    if (ui::button("Очистить", !watch.empty())) {
        clear_watch_requested_ = true;
    }
    ImGui::SameLine();
    if (ui::button("Найти указатели…", watch.selected() != nullptr && !session_.busy() && alive_)) {
        open_pointer_scan();
    }
    ImGui::SetItemTooltip("Цепочки указателей к выбранному адресу: по ним адрес находится и после перезапуска программы");
    ImGui::SameLine();
    if (ui::button("Структура…", watch.selected() != nullptr)) {
        open_struct_from_selection();
    }
    ImGui::SetItemTooltip("Разобрать структуру вокруг выбранного адреса.  Ctrl+D");
    ImGui::SameLine(0.0f, 20.0f * scale_);
    ImGui::AlignTextToFramePadding();
    const std::string count = watch.empty() ? std::string("Список пуст") : "В списке " + count_addresses(watch.rows().size());
    const float count_end = ImGui::GetCursorPosX() + ImGui::CalcTextSize(count.c_str()).x;
    ui::muted(count_end <= right_edge ? count : std::string());
    const char* hint = "Рамка — значение менялось за 2 с";
    const float hint_x = right_edge - ImGui::CalcTextSize(hint).x;
    if (!watch.empty() && hint_x > count_end + 20.0f * scale_) {
        ImGui::SameLine(hint_x);
        ui::muted(hint);
        ImGui::SetItemTooltip("Значения перечитываются дважды в секунду");
    }
}

void View::draw_watch_table(float height) {
    WatchList& watch = session_.watch();
    if (editing_row_ && *editing_row_ >= watch.rows().size()) {
        editing_row_.reset();
    }
    if (watch.empty()) {
        ImGui::BeginChild("##no_watch", ImVec2(0, height), ImGuiChildFlags_Borders, kPanel);
        ui::muted_wrapped("Здесь будут адреса, за которыми вы следите. Добавьте их из результатов поиска правой кнопкой мыши "
                          "или клавишей Insert, либо введите адрес сами кнопкой «Добавить адрес…».");
        ImGui::EndChild();
        return;
    }

    const MemorySource& memory = session_.target()->memory();
    const std::vector<WatchEntry>& rows = watch.rows();
    const std::optional<std::size_t> selected = watch.selected_row();
    const ImGuiStyle& style = ImGui::GetStyle();
    const float ui_line = ImGui::GetTextLineHeight();
    const float mono_line = fonts_.mono->FontSize;
    const float row_height = std::max(ui_line, mono_line);
    const float ui_offset = std::floor((row_height - ui_line) * 0.5f);
    const float mono_offset = std::floor((row_height - mono_line) * 0.5f);
    page_rows_ = std::max(1, static_cast<int>(height / (row_height + style.CellPadding.y * 2.0f)) - 2);
    const auto now = std::chrono::steady_clock::now();
    const bool due = now - watch_time_ >= kLiveRefresh;
    if (due) {
        watch_time_ = now;
    }

    constexpr ImGuiTableFlags flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersInnerV |
                                      ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingFixedFit;
    if (!ImGui::BeginTable("##watch", 5, flags, ImVec2(0, height))) {
        return;
    }
    ImGui::TableSetupColumn("Описание", ImGuiTableColumnFlags_WidthStretch, 1.8f);
    ImGui::TableSetupColumn("Адрес", 0, font_text_width(fonts_.mono, "P->0x0000000000000000"));
    ImGui::TableSetupColumn("Тип", ImGuiTableColumnFlags_WidthStretch, 1.4f);
    ImGui::TableSetupColumn("Значение", ImGuiTableColumnFlags_WidthStretch, 4.0f);
    ImGui::TableSetupColumn("Модуль", ImGuiTableColumnFlags_WidthStretch, 1.3f);
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableHeadersRow();

    std::optional<std::size_t> remove_row;
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(rows.size()), row_height + style.CellPadding.y * 2.0f);
    if (selected) {
        clipper.IncludeItemByIndex(static_cast<int>(*selected));
    }
    if (editing_row_) {
        clipper.IncludeItemByIndex(static_cast<int>(*editing_row_));
    }
    while (clipper.Step()) {
        const auto first = static_cast<std::size_t>(clipper.DisplayStart);
        const auto last = static_cast<std::size_t>(clipper.DisplayEnd);
        bool stale = due;
        for (std::size_t index = first; index < last && !stale; ++index) {
            stale = !watch.read(index);
        }
        if (stale) {
            watch.refresh(memory, first, last, now);
        }
        for (std::size_t index = first; index < last; ++index) {
            const WatchEntry& entry = rows[index];
            const bool is_selected = selected == index;
            ImGui::TableNextRow(ImGuiTableRowFlags_None, row_height);
            ImGui::TableSetColumnIndex(0);
            ImGui::PushID(static_cast<int>(index));
            if (is_selected) {
                ImGui::PushStyleColor(ImGuiCol_HeaderHovered, theme::kWhite);
                ImGui::PushStyleColor(ImGuiCol_HeaderActive, theme::kWhite);
            }
            const ImVec2 row_start = ImGui::GetCursorPos();
            const bool clicked = ImGui::Selectable(
                "##row", is_selected,
                ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap | ImGuiSelectableFlags_AllowDoubleClick,
                ImVec2(0.0f, row_height));
            if (is_selected) {
                ImGui::PopStyleColor(2);
            }
            if (clicked || ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                watch.select_row(index);
            }
            if (clicked && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                start_editing_description(index);
            }
            if (ImGui::BeginPopupContextItem("##menu")) {
                if (ImGui::MenuItem("Изменить описание", "F2")) {
                    start_editing_description(index);
                }
                if (ImGui::MenuItem("Копировать адрес", "Ctrl+C")) {
                    copy_address(entry.address);
                }
                if (ImGui::MenuItem("Копировать значение", nullptr, false, watch.readable(index))) {
                    ImGui::SetClipboardText(watch.value_text(index).c_str());
                }
                if (entry.path && ImGui::MenuItem("Копировать цепочку")) {
                    ImGui::SetClipboardText(format_pointer_path(*entry.path).c_str());
                }
                ImGui::Separator();
                if (ImGui::MenuItem("Найти указатели…", nullptr, false, !session_.busy() && alive_)) {
                    open_pointer_scan();
                }
                if (ImGui::MenuItem("Разобрать структуру…", "Ctrl+D")) {
                    open_struct_from_selection();
                }
                if (ImGui::MenuItem("Дизассемблировать")) {
                    disassemble_at(entry.address);
                }
                ImGui::Separator();
                if (ImGui::MenuItem("Удалить", "Del")) {
                    remove_row = index;
                }
                if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
                    ImGui::CloseCurrentPopup();
                }
                ImGui::EndPopup();
            }
            if (is_selected) {
                keep_selection_visible(row_height);
            }

            if (is_selected) {
                ImGui::PushStyleColor(ImGuiCol_Text, theme::kBlack);
            }
            ImGui::SetCursorPos(row_start);
            if (editing_row_ == index) {
                // Typing changes the description at once; Esc brings back the text it had before.
                ImGui::PushStyleColor(ImGuiCol_Text, theme::kWhite);
                ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(std::floor(style.FramePadding.x * 0.5f), 0.0f));
                ImGui::SetNextItemWidth(-FLT_MIN);
                if (focus_description_) {
                    ImGui::SetKeyboardFocusHere();
                    focus_description_ = false;
                }
                if (ImGui::InputText("##description", &description_edit_, ImGuiInputTextFlags_AutoSelectAll)) {
                    watch.set_description(index, description_edit_);
                }
                if (ImGui::IsItemDeactivated()) {
                    editing_row_.reset();
                }
                ImGui::PopStyleVar();
                ImGui::PopStyleColor();
            } else {
                ImGui::SetCursorPosY(ImGui::GetCursorPosY() + ui_offset);
                ui::text(entry.description);
            }

            ImGui::TableSetColumnIndex(1);
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + mono_offset);
            ImGui::PushFont(fonts_.mono);
            ui::text(watch.address_text(index));
            ImGui::PopFont();
            if (entry.path) {
                ImGui::SetItemTooltip("%s", ("Адрес по цепочке " + format_pointer_path(*entry.path)).c_str());
            }

            ImGui::TableSetColumnIndex(2);
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + ui_offset);
            ui::text(type_label(entry));

            ImGui::TableSetColumnIndex(3);
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + (entry.type == WatchType::Bytes ? mono_offset : ui_offset));
            if (watch.read(index) && !watch.readable(index)) {
                ui::muted("??");
            } else {
                if (entry.type == WatchType::Bytes) {
                    ImGui::PushFont(fonts_.mono);
                }
                ui::text(watch.value_text(index));
                if (entry.type == WatchType::Bytes) {
                    ImGui::PopFont();
                }
                if (watch.recently_changed(index, now)) {
                    const ImVec2 min = ImGui::GetItemRectMin();
                    const ImVec2 max = ImGui::GetItemRectMax();
                    const float pad = std::floor(style.CellPadding.x * 0.75f);
                    ImGui::GetWindowDrawList()->AddRect(ImVec2(min.x - pad, min.y - 1.0f), ImVec2(max.x + pad, max.y + 1.0f),
                                                        is_selected ? theme::kBlack : theme::kWhite);
                }
            }

            ImGui::TableSetColumnIndex(4);
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + ui_offset);
            ui::text(watch.module(index));
            if (is_selected) {
                ImGui::PopStyleColor();
            }
            ImGui::PopID();
        }
    }
    if (scroll_to_selection_ && !selected) {
        scroll_to_selection_ = false;
    }
    ImGui::EndTable();

    if (remove_row) {
        watch.remove(*remove_row);
        editing_row_.reset();
    }
}

void View::draw_watch_info(std::size_t row, float value_x) {
    WatchList& watch = session_.watch();
    const WatchEntry& entry = watch.rows()[row];
    ui::heading(fonts_.heading, "АДРЕС");
    if (entry.path) {
        const std::string path = format_pointer_path(*entry.path);
        ui::field("Цепочка", path, value_x, fonts_.mono);
        ImGui::SetItemTooltip("%s", path.c_str());
        ui::field("Адрес", watch.resolved(row) ? format_address(entry.address) : std::string("цепочка никуда не ведёт"), value_x,
                  fonts_.mono);
    } else {
        ui::field("Адрес", format_address(entry.address), value_x, fonts_.mono);
    }
    ui::field("Описание", entry.description.empty() ? std::string_view("—") : std::string_view(entry.description), value_x);
    ui::muted("Сейчас");
    ImGui::SameLine(value_x);
    if (!watch.read(row)) {
        ui::muted("—");
    } else if (!watch.readable(row)) {
        ui::muted("не читается");
    } else {
        const bool mono = entry.type == WatchType::Bytes;
        if (mono) {
            ImGui::PushFont(fonts_.mono);
        }
        const std::string text = watch.value_text(row);
        const bool clipped = ImGui::CalcTextSize(text.c_str()).x > ImGui::GetContentRegionAvail().x;
        if (watch.recently_changed(row, std::chrono::steady_clock::now())) {
            inverted_text(text);
        } else {
            ui::text(text);
        }
        if (mono) {
            ImGui::PopFont();
        }
        if (clipped) {
            ImGui::SetItemTooltip("%s", text.c_str());
        }
    }

    ImGui::Spacing();
    ui::field("Тип", type_label(entry), value_x);
    WatchType type = entry.type;
    if (type_segments(type, ImGui::GetCursorPosX())) {
        // The new type covers the same bytes where it can.
        const std::size_t bytes = entry.size();
        watch.set_type(row, type, static_cast<std::uint32_t>(type == WatchType::Utf16 ? bytes / 2 : bytes));
    }
    if (has_length(entry.type)) {
        ImGui::AlignTextToFramePadding();
        ui::muted("Длина");
        ImGui::SameLine(value_x);
        int length = static_cast<int>(entry.length);
        ImGui::SetNextItemWidth(std::floor(70.0f * scale_));
        if (ImGui::InputInt("##watch_length", &length, 0, 0)) {
            watch.set_type(row, entry.type, static_cast<std::uint32_t>(std::max(length, 1)));
        }
        ImGui::SameLine();
        ui::muted(length_unit(entry.type));
    }

    ImGui::Spacing();
    draw_region_fields(watch.region(row), entry.address, watch.module(row), value_x);
}

void View::draw_add_watch() {
    center_next_dialog(480.0f * scale_);
    if (!ImGui::BeginPopupModal("##add_watch", nullptr, kDialog)) {
        return;
    }
    bool close = ImGui::IsKeyPressed(ImGuiKey_Escape, false);
    bool submit = enter_pressed();
    const float value_x = std::floor(100.0f * scale_);

    ui::heading(fonts_.heading, "ДОБАВИТЬ АДРЕС");
    ImGui::AlignTextToFramePadding();
    ui::muted("Адрес");
    ImGui::SameLine(value_x);
    ImGui::SetNextItemWidth(-FLT_MIN);
    if (add_watch_focus_) {
        ImGui::SetKeyboardFocusHere();
        add_watch_focus_ = false;
    }
    ImGui::PushFont(fonts_.mono);
    ImGui::InputTextWithHint("##add_address", "0x7FF6A0001000", &add_address_);
    ImGui::PopFont();

    ImGui::AlignTextToFramePadding();
    ui::muted("Тип");
    ImGui::SameLine(value_x);
    type_segments(add_type_, value_x);

    if (has_length(add_type_)) {
        ImGui::AlignTextToFramePadding();
        ui::muted("Длина");
        ImGui::SameLine(value_x);
        ImGui::SetNextItemWidth(std::floor(70.0f * scale_));
        ImGui::InputInt("##add_length", &add_length_, 0, 0);
        ImGui::SameLine();
        ui::muted(length_unit(add_type_));
    }

    ImGui::AlignTextToFramePadding();
    ui::muted("Описание");
    ImGui::SameLine(value_x);
    ImGui::SetNextItemWidth(-FLT_MIN);
    ImGui::InputTextWithHint("##add_description", "необязательно", &add_description_);

    if (!add_error_.empty()) {
        ImGui::Spacing();
        ui::inverted_block(add_error_);
    }
    ImGui::Spacing();
    const int pressed = dialog_buttons("Добавить", "Отмена");
    submit |= pressed == 0;
    close |= pressed == 1;

    if (submit && !close) {
        if (const auto address = parse_address(add_address_)) {
            const auto length = static_cast<std::uint32_t>(std::max(add_length_, 1));
            session_.add_watch(make_watch_entry(*address, add_type_, length, add_description_));
            page_ = Page::Watch;
            scroll_to_selection_ = true;
            close = true;
        } else {
            add_error_ = add_address_.empty() ? "Введите адрес." : "Адрес — шестнадцатеричное число, например 0x7FF6A0001000.";
            add_watch_focus_ = true;
        }
    }
    if (close) {
        add_error_.clear();
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

void View::draw_clear_watch() {
    center_next_dialog(420.0f * scale_);
    if (!ImGui::BeginPopupModal("##clear_watch", nullptr, kDialog)) {
        return;
    }
    WatchList& watch = session_.watch();
    bool close = ImGui::IsKeyPressed(ImGuiKey_Escape, false);
    ui::heading(fonts_.heading, "ОЧИСТИТЬ СПИСОК");
    ui::text("Убрать из списка " + count_addresses(watch.rows().size()) + "?");
    ui::muted("Описания тоже пропадут.");
    ImGui::Spacing();
    const int pressed = dialog_buttons("Очистить", "Отмена");
    if (pressed == 0 || (enter_pressed() && !close)) {
        watch.clear();
        editing_row_.reset();
        session_.set_notice("Список адресов очищен", false);
        close = true;
    }
    close |= pressed == 1;
    if (close) {
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

}  // namespace mh::gui
