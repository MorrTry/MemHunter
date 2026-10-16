#include <imgui.h>
#include <misc/cpp/imgui_stdlib.h>

#include <algorithm>
#include <cfloat>
#include <cmath>

#include "common/error.hpp"
#include "common/text.hpp"
#include "gui/lang.hpp"
#include "gui/view.hpp"
#include "gui/view_internal.hpp"
#include "gui/widgets.hpp"

namespace mh::gui {

namespace {

const char* base_error() {
    return tr("The base is an address (0x1F4A2C3B0D8) or a chain like [[game.exe+0x52080]+0x8].",
              "База — адрес (0x1F4A2C3B0D8) или цепочка вида [[game.exe+0x52080]+0x8].");
}

const char* base_hint() {
    return tr("[[game.exe+0x52080]+0x8] or 0x1F4A2C3B0D8", "[[game.exe+0x52080]+0x8] или 0x1F4A2C3B0D8");
}

std::string trimmed(const std::string& text) {
    const auto first = text.find_first_not_of(" \t");
    if (first == std::string::npos) {
        return {};
    }
    return text.substr(first, text.find_last_not_of(" \t") - first + 1);
}

bool is_chain(const PointerPath& path) {
    return !path.module.empty() || !path.offsets.empty();
}

// The value of another instance that differs from the first one: inverted against the row it is in.
void contrast_text(std::string_view text, bool on_white) {
    const ImGuiStyle& style = ImGui::GetStyle();
    const char* begin = text.data();
    const char* end = begin + text.size();
    const ImVec2 size = ImGui::CalcTextSize(begin, end);
    const ImVec2 min = ImGui::GetCursorScreenPos();
    const float pad = std::floor(style.FramePadding.x * 0.5f);
    ImGui::Dummy(ImVec2(size.x + pad * 2.0f, size.y));
    ImDrawList* draw = ImGui::GetWindowDrawList();
    draw->AddRectFilled(min, ImVec2(min.x + size.x + pad * 2.0f, min.y + size.y), on_white ? theme::kBlack : theme::kWhite);
    draw->AddText(ImVec2(min.x + pad, min.y), on_white ? theme::kWhite : theme::kBlack, begin, end);
}

bool mono_value(FieldType type) {
    return type == FieldType::Pointer || type == FieldType::Bytes;
}

}  // namespace

void View::open_struct_from_selection() {
    if (session_.target() == nullptr) {
        return;
    }
    const unsigned pointer_size = session_.pointer_size();
    const auto open_at = [&](const WatchEntry& entry) {
        const StructStart start = struct_start(entry, pointer_size);
        std::optional<StructField> known;
        // A description the program made up ("+0x50") is no name.
        if (!entry.description.empty() && !entry.description.starts_with("+0x")) {
            known = StructField{start.focus, field_type(entry.type), entry.length, entry.description, true};
        }
        open_struct_dialog(start, known);
    };
    if (page_ == Page::Watch) {
        if (const WatchEntry* entry = session_.watch().selected()) {
            open_at(*entry);
        }
    } else if (page_ == Page::Pointers) {
        if (const auto row = session_.pointers().selected_row()) {
            open_at(session_.pointers().watch_entry(*row));
        }
    } else if (page_ == Page::Results) {
        if (const auto entry = selected_as_watch()) {
            open_at(*entry);
        }
    } else {
        open_struct_dialog(std::nullopt);
    }
}

void View::open_struct_dialog(std::optional<StructStart> start, std::optional<StructField> known) {
    const StructTable& structure = session_.structure();
    std::uint32_t size = kDefaultStructSize;
    struct_focus_offset_.reset();
    struct_known_.reset();
    if (start) {
        struct_base_ = format_struct_base(start->base);
        struct_focus_offset_ = start->focus;
        struct_known_ = std::move(known);
        if (start->focus + 0x40 > size) {
            size = std::min<std::uint32_t>(kMaxStructSize, (start->focus + 0x40 + 0xF) & ~0xFu);
        }
    } else if (structure.active()) {
        struct_base_ = format_struct_base(structure.base());
        size = structure.size();
    }
    struct_suggested_base_ = struct_base_;
    struct_size_ = format_hex(size);
    struct_error_.clear();
    struct_open_requested_ = true;
    struct_focus_ = true;
}

void View::open_field_dialog(std::optional<std::size_t> row) {
    const StructTable& structure = session_.structure();
    if (!structure.active()) {
        return;
    }
    if (row) {
        if (!structure.editable(*row)) {
            return;
        }
        const StructField& field = structure.rows()[*row].field;
        field_offset_ = format_hex(field.offset);
        field_type_ = field.type;
        if (has_length(field.type)) {
            field_length_ = static_cast<int>(field.length);
        }
        field_name_ = field.name;
    } else {
        field_offset_.clear();
        field_name_.clear();
    }
    struct_error_.clear();
    struct_field_requested_ = true;
    struct_focus_ = true;
}

void View::open_instance_dialog() {
    const StructTable& structure = session_.structure();
    if (!structure.active() || structure.instances() >= kMaxInstances) {
        return;
    }
    // Another instance usually differs from the first one in the last offset only.
    instance_base_ = format_struct_base(structure.base());
    struct_error_.clear();
    struct_instance_requested_ = true;
    struct_focus_ = true;
}

void View::save_structure() {
    const StructTable& structure = session_.structure();
    if (!structure.active()) {
        return;
    }
    if (structure.definition().fields.empty()) {
        session_.save_structure({});
        return;
    }
    const std::string& process = session_.target() != nullptr ? session_.target()->summary().name : std::string();
    const std::wstring name =
        (process.empty() ? std::wstring(L"memhunter") : std::filesystem::path(utf8_to_wide(process)).stem().wstring()) + L"-struct.mhst";
    try {
        if (const auto path = platform_.ask_save_path(name, FileKind::Structure)) {
            session_.save_structure(*path);
        }
    } catch (const Error& error) {
        session_.set_notice(describe_error(error), true);
    }
}

void View::load_structure() {
    if (!session_.structure().active()) {
        session_.load_structure({});
        return;
    }
    try {
        if (const auto path = platform_.ask_open_path(FileKind::Structure); path && session_.load_structure(*path)) {
            page_ = Page::Structure;
            scroll_to_selection_ = true;
        }
    } catch (const Error& error) {
        session_.set_notice(describe_error(error), true);
    }
}

void View::copy_struct_field(std::size_t row) {
    const StructTable& structure = session_.structure();
    const std::string text = structure.path_text(row, 0);
    ImGui::SetClipboardText(text.c_str());
    const bool address = structure.path_to(row, 0).module.empty() && structure.field_address(row, 0).has_value();
    session_.set_notice((address ? tr("Address copied: ", "Адрес скопирован: ") : tr("Chain copied: ", "Цепочка скопирована: ")) + text, false);
}

void View::handle_struct_shortcuts(bool copy) {
    StructTable& structure = session_.structure();
    if (!structure.active()) {
        return;
    }
    scroll_to_selection_ |= navigate(structure, page_rows_);
    const std::optional<std::size_t> row = structure.selected_row();
    if (!row) {
        return;
    }
    const StructRow& at = structure.rows()[*row];
    if (ImGui::IsKeyPressed(ImGuiKey_RightArrow, false) && structure.expandable(*row) && !structure.expanded(*row)) {
        structure.toggle(*row);
    } else if (ImGui::IsKeyPressed(ImGuiKey_LeftArrow, false)) {
        if (structure.expanded(*row)) {
            structure.toggle(*row);
        } else if (at.depth > 0) {
            // The rows of a structure a pointer leads to follow the row of the pointer.
            for (std::size_t i = *row; i-- > 0;) {
                if (structure.rows()[i].depth + 1 == at.depth) {
                    structure.select_row(i);
                    scroll_to_selection_ = true;
                    break;
                }
            }
        }
    } else if (enter_pressed()) {
        if (structure.expandable(*row)) {
            structure.toggle(*row);
        } else {
            open_field_dialog(*row);
        }
    } else if (ImGui::IsKeyPressed(ImGuiKey_F2, false)) {
        open_field_dialog(*row);
    } else if (ImGui::IsKeyPressed(ImGuiKey_Delete, false) && structure.editable(*row) && at.field.defined) {
        structure.forget(*row);
    } else if (ImGui::IsKeyPressed(ImGuiKey_Insert, false)) {
        session_.add_struct_watch(*row, 0);
    } else if (copy) {
        copy_struct_field(*row);
    }
}

void View::draw_struct_bar(float right_edge) {
    const StructTable& structure = session_.structure();
    const bool active = structure.active();
    if (ui::button(tr("Open…", "Открыть…"), session_.target() != nullptr)) {
        open_struct_dialog(std::nullopt);
    }
    ImGui::SetItemTooltip("%s", tr("Lay out a structure at an address or chain.  Ctrl+D on the «Addresses», «Pointers» and «Results» tabs",
                                   "Разобрать структуру по адресу или цепочке.  Ctrl+D на вкладках «Адреса», «Указатели» и «Результаты»"));
    ImGui::SameLine();
    if (ui::button(tr("Compare…", "Сравнить…"), active && structure.instances() < kMaxInstances)) {
        open_instance_dialog();
    }
    ImGui::SetItemTooltip("%s", tr("The same structure at another address — as a column beside it, up to 4 columns",
                                   "Та же структура по другому адресу — столбцом рядом, до 4 столбцов"));
    ImGui::SameLine();
    const std::size_t defined = active ? structure.definition().fields.size() : 0;
    if (ui::button(tr("Save…", "Сохранить…"), defined > 0)) {
        save_structure();
    }
    ImGui::SetItemTooltip("%s", tr("The defined fields to an .mhst file.  Ctrl+S", "Заданные поля в файл .mhst.  Ctrl+S"));
    ImGui::SameLine();
    if (ui::button(tr("Load…", "Загрузить…"), active)) {
        load_structure();
    }
    ImGui::SetItemTooltip("%s", tr("Fields from an .mhst file over the open structure", "Поля из файла .mhst поверх открытой структуры"));
    ImGui::SameLine(0.0f, 20.0f * scale_);
    ImGui::AlignTextToFramePadding();
    const std::string count =
        active ? tr("Rows: ", "Строк: ") + group_digits(structure.rows().size()) + tr(", defined fields: ", ", задано полей: ") + std::to_string(defined)
               : std::string(tr("No structure open", "Структура не открыта"));
    const float count_end = ImGui::GetCursorPosX() + ImGui::CalcTextSize(count.c_str()).x;
    ui::muted(count_end <= right_edge ? count : std::string());
    const char* hint = tr("Box — the value changed within 2 s", "Рамка — значение менялось за 2 с");
    const float hint_x = right_edge - ImGui::CalcTextSize(hint).x;
    if (active && hint_x > count_end + 20.0f * scale_) {
        ImGui::SameLine(hint_x);
        ui::muted(hint);
    }
}

void View::draw_struct_table(float height) {
    StructTable& structure = session_.structure();
    if (!structure.active()) {
        ImGui::BeginChild("##no_struct", ImVec2(0, height), ImGuiChildFlags_Borders, kPanel);
        ui::muted_wrapped(tr("Here will be the structure's fields: offset, guessed type, and value, refreshed twice a second. "
                             "Select an address on the «Addresses», «Pointers» or «Results» tab and press «Lay out structure…» "
                             "(Ctrl+D), or press «Open…» and enter an address or chain.",
                             "Здесь будут поля структуры: смещение, угаданный тип и значение, которое обновляется дважды в секунду. "
                             "Выберите адрес на вкладке «Адреса», «Указатели» или «Результаты» и нажмите «Разобрать структуру…» "
                             "(Ctrl+D) или нажмите «Открыть…» и введите адрес или цепочку."));
        ImGui::EndChild();
        return;
    }
    const auto now = StructTable::Clock::now();
    if (structure.due(now, kLiveRefresh)) {
        session_.refresh_structure(now);
    }

    const ImGuiStyle& style = ImGui::GetStyle();
    const float top = ImGui::GetCursorPosY();
    const float right = ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x;
    const float gap = 16.0f * scale_;
    const std::string base = format_struct_base(structure.base());
    const std::optional<std::uint64_t> start = structure.address(0);
    const std::string current = start && is_chain(structure.base()) ? format_address(*start) : std::string();
    const std::string size = tr("size ", "размер ") + format_hex(structure.size());
    const char* lost = tr("the chain leads nowhere now", "цепочка сейчас никуда не ведёт");
    const char* now_label = tr("now", "сейчас");
    const float base_width = font_text_width(fonts_.mono, base);
    const float current_width = font_text_width(fonts_.mono, current);
    const float buttons = buttons_width({tr("Guess again", "Угадать заново"), tr("As C", "Как C"), tr("Close", "Закрыть")});
    float room = right - ImGui::GetCursorPosX() - buttons - gap - ImGui::CalcTextSize(tr("Base", "База")).x - style.ItemSpacing.x - base_width;
    if (!start) {
        room -= gap + ImGui::CalcTextSize(lost).x + std::floor(style.FramePadding.x * 0.5f) * 2.0f;
    }
    // What does not fit goes first the size, then the current address; both stay in the panel below the table.
    const float current_part = current.empty() ? 0.0f : gap + ImGui::CalcTextSize(now_label).x + style.ItemSpacing.x + current_width;
    const bool show_current = !current.empty() && room >= current_part;
    if (show_current) {
        room -= current_part;
    }
    const float size_part = gap + ImGui::CalcTextSize(size.c_str()).x;
    const bool show_size = start && room >= size_part;
    if (show_size) {
        room -= size_part;
    }
    ImGui::AlignTextToFramePadding();
    ui::muted(tr("Base", "База"));
    ImGui::SameLine();
    ImGui::PushFont(fonts_.mono);
    ui::text(base);
    ImGui::PopFont();
    if (!start) {
        ImGui::SameLine(0.0f, gap);
        inverted_text(lost);
    }
    if (show_current) {
        ImGui::SameLine(0.0f, gap);
        ui::muted(now_label);
        ImGui::SameLine();
        ImGui::PushFont(fonts_.mono);
        ui::text(current);
        ImGui::PopFont();
    }
    if (show_size) {
        ImGui::SameLine(0.0f, gap);
        ui::muted(size);
    }
    if (room >= 0.0f) {
        ImGui::SameLine(right - buttons);
    } else {
        ImGui::SetCursorPosX(std::max(ImGui::GetCursorPosX(), right - buttons));
    }
    if (ui::button(tr("Guess again", "Угадать заново"))) {
        session_.guess_structure_again();
    }
    ImGui::SetItemTooltip("%s", tr("Guess the types of undefined fields from what is in them now",
                                   "Угадать типы незаданных полей по тому, что в них сейчас"));
    ImGui::SameLine();
    if (ui::button(tr("As C", "Как C"))) {
        ImGui::SetClipboardText(structure.c_declaration().c_str());
        session_.set_notice(tr("The C struct declaration is copied", "Объявление структуры на C скопировано"), false);
    }
    ImGui::SetItemTooltip("%s", tr("Copy the struct declaration in C: the defined fields, or the guessed ones while there are none",
                                   "Скопировать объявление struct на C: заданные поля, а пока их нет — угаданные"));
    ImGui::SameLine();
    if (ui::button(tr("Close", "Закрыть"))) {
        structure.close();
        return;
    }

    const std::vector<StructRow>& rows = structure.rows();
    const std::optional<std::size_t> selected = structure.selected_row();
    const std::size_t instances = structure.instances();
    const float ui_line = ImGui::GetTextLineHeight();
    const float mono_line = fonts_.mono->FontSize;
    const float row_height = std::max(ui_line, mono_line);
    const float ui_offset = std::floor((row_height - ui_line) * 0.5f);
    const float mono_offset = std::floor((row_height - mono_line) * 0.5f);
    const float indent = font_text_width(fonts_.mono, "  ");
    const float marker = font_text_width(fonts_.mono, "+ ");
    const float rest = std::max(height - (ImGui::GetCursorPosY() - top), 40.0f * scale_);
    page_rows_ = std::max(1, static_cast<int>(rest / (row_height + style.CellPadding.y * 2.0f)) - 2);

    constexpr ImGuiTableFlags flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersInnerV |
                                      ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingFixedFit;
    ImGui::PushID(static_cast<int>(instances));
    if (!ImGui::BeginTable("##struct", static_cast<int>(3 + instances), flags, ImVec2(0, rest))) {
        ImGui::PopID();
        return;
    }
    ImGui::TableSetupColumn(tr("Offset", "Смещение"), 0, font_text_width(fonts_.mono, "+ 0x0000") + indent * 2.0f);
    ImGui::TableSetupColumn(tr("Type", "Тип"), 0, font_text_width(fonts_.mono, "ascii[4096]"));
    ImGui::TableSetupColumn(tr("Name", "Имя"), 0, 150.0f * scale_);
    ImGui::TableSetupColumn(tr("Value", "Значение"), ImGuiTableColumnFlags_WidthStretch);
    for (std::size_t i = 1; i < instances; ++i) {
        ImGui::TableSetupColumn((tr("Value ", "Значение ") + std::to_string(i + 1)).c_str(), ImGuiTableColumnFlags_WidthStretch);
    }
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableHeadersRow();

    std::optional<std::size_t> toggle_row;
    std::optional<std::size_t> activate_row;
    std::optional<std::size_t> edit_row;
    std::optional<std::size_t> forget_row;
    std::optional<std::size_t> dissect_row;
    std::optional<std::size_t> watch_row;
    bool guess = false;
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(rows.size()), row_height + style.CellPadding.y * 2.0f);
    if (selected) {
        clipper.IncludeItemByIndex(static_cast<int>(*selected));
    }
    while (clipper.Step()) {
        for (auto index = static_cast<std::size_t>(clipper.DisplayStart); index < static_cast<std::size_t>(clipper.DisplayEnd); ++index) {
            const StructRow& row = rows[index];
            const StructField& field = row.field;
            const bool is_selected = selected == index;
            const bool expandable = structure.expandable(index);
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
                structure.select_row(index);
            }
            if (clicked && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                activate_row = index;
            }
            if (ImGui::BeginPopupContextItem("##menu")) {
                const bool editable = structure.editable(index);
                if (ImGui::MenuItem(tr("Edit field…", "Изменить поле…"), "F2", false, editable)) {
                    edit_row = index;
                }
                if (ImGui::MenuItem(tr("Reset to guessed", "Сбросить к угаданному"), "Del", false, editable && field.defined)) {
                    forget_row = index;
                }
                ImGui::Separator();
                if (ImGui::MenuItem(structure.expanded(index) ? tr("Collapse", "Свернуть") : tr("Expand", "Раскрыть"), "Enter", false, expandable)) {
                    toggle_row = index;
                }
                if (ImGui::MenuItem(tr("Lay out from here", "Разобрать отсюда"), nullptr, false, field.type == FieldType::Pointer)) {
                    dissect_row = index;
                }
                const std::optional<std::uint64_t> field_address = structure.field_address(index, 0);
                if (ImGui::MenuItem(tr("Disassemble", "Дизассемблировать"), nullptr, false, field_address.has_value())) {
                    disassemble_at(*field_address);
                }
                ImGui::Separator();
                if (ImGui::MenuItem(tr("To the address list", "В список адресов"), "Insert")) {
                    watch_row = index;
                }
                if (ImGui::MenuItem(is_chain(structure.path_to(index, 0)) ? tr("Copy chain", "Копировать цепочку") : tr("Copy address", "Копировать адрес"), "Ctrl+C")) {
                    copy_struct_field(index);
                }
                const std::string value = structure.value_text(index, 0);
                if (ImGui::MenuItem(tr("Copy value", "Копировать значение"), nullptr, false, !value.empty() && value != "??")) {
                    ImGui::SetClipboardText(value.c_str());
                }
                if (ImGui::MenuItem(tr("Copy as C", "Копировать как C"))) {
                    ImGui::SetClipboardText(structure.c_declaration().c_str());
                    session_.set_notice(tr("The C struct declaration is copied", "Объявление структуры на C скопировано"), false);
                }
                ImGui::Separator();
                if (ImGui::MenuItem(tr("Guess again", "Угадать заново"))) {
                    guess = true;
                }
                if (ImGui::IsKeyPressed(ImGuiKey_Escape, false)) {
                    ImGui::CloseCurrentPopup();
                }
                ImGui::EndPopup();
            }
            if (is_selected) {
                keep_selection_visible(row_height);
                ImGui::PushStyleColor(ImGuiCol_Text, theme::kBlack);
            }

            ImGui::PushFont(fonts_.mono);
            const float x = row_start.x + indent * static_cast<float>(row.depth);
            if (expandable) {
                ImGui::SetCursorPos(ImVec2(x, row_start.y));
                if (ImGui::InvisibleButton("##toggle", ImVec2(marker, row_height))) {
                    toggle_row = index;
                }
                ImGui::SetItemTooltip("%s", structure.expanded(index) ? tr("Collapse", "Свернуть")
                                                                       : tr("Expand the structure the pointer leads to", "Раскрыть структуру, куда ведёт указатель"));
                ImGui::SetCursorPos(ImVec2(x, row_start.y + mono_offset));
                ui::text(structure.expanded(index) ? "-" : "+");
            }
            ImGui::SetCursorPos(ImVec2(x + marker, row_start.y + mono_offset));
            ui::text(format_hex(field.offset));

            ImGui::TableSetColumnIndex(1);
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + mono_offset);
            const std::string type = field_type_name(field);
            if (field.defined || is_selected) {
                ui::text(type);
            } else {
                ui::muted(type);
            }
            ImGui::PopFont();

            ImGui::TableSetColumnIndex(2);
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + ui_offset);
            ui::text(field.name);

            const bool mono = mono_value(field.type);
            for (std::size_t i = 0; i < instances; ++i) {
                ImGui::TableSetColumnIndex(static_cast<int>(3 + i));
                ImGui::SetCursorPosY(ImGui::GetCursorPosY() + (mono ? mono_offset : ui_offset));
                const std::string value = structure.value_text(index, i);
                if (value.empty()) {
                    continue;
                }
                if (value == "??") {
                    ui::muted(value);
                    continue;
                }
                if (mono) {
                    ImGui::PushFont(fonts_.mono);
                }
                if (structure.differs(index, i)) {
                    contrast_text(value, is_selected);
                } else {
                    ui::text(value);
                }
                if (mono) {
                    ImGui::PopFont();
                }
                if (structure.recently_changed(index, i, now)) {
                    const ImVec2 min = ImGui::GetItemRectMin();
                    const ImVec2 max = ImGui::GetItemRectMax();
                    const float pad = std::floor(style.CellPadding.x * 0.75f);
                    ImGui::GetWindowDrawList()->AddRect(ImVec2(min.x - pad, min.y - 1.0f), ImVec2(max.x + pad, max.y + 1.0f),
                                                        is_selected ? theme::kBlack : theme::kWhite);
                }
            }
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
    ImGui::PopID();

    if (activate_row) {
        if (structure.editable(*activate_row)) {
            edit_row = activate_row;
        } else {
            toggle_row = activate_row;
        }
    }
    if (toggle_row) {
        structure.toggle(*toggle_row);
    } else if (edit_row) {
        open_field_dialog(*edit_row);
    } else if (forget_row) {
        structure.forget(*forget_row);
    } else if (dissect_row) {
        if (structure.dissect(*dissect_row)) {
            session_.refresh_structure(StructTable::Clock::now());
            session_.set_notice(tr("Structure ", "Структура ") + format_struct_base(structure.base()), false);
        } else {
            session_.set_notice(tr("The chain would come out longer than ", "Цепочка вышла бы длиннее ") + std::to_string(kMaxPathOffsets) + tr(" pointers", " указателей"), true);
        }
    } else if (watch_row) {
        session_.add_struct_watch(*watch_row, 0);
    } else if (guess) {
        session_.guess_structure_again();
    }
}

void View::draw_struct_info(std::size_t row, float value_x) {
    StructTable& structure = session_.structure();
    const StructRow& at = structure.rows()[row];
    const StructField& field = at.field;
    const auto now = StructTable::Clock::now();
    ui::heading(fonts_.heading, tr("FIELD", "ПОЛЕ"));
    ui::field(tr("Offset", "Смещение"),
              format_hex(field.offset) + (at.depth > 0 ? tr("   depth ", "   глубина ") + std::to_string(at.depth) : std::string()), value_x,
              fonts_.mono);
    ui::field(tr("Type", "Тип"), field_type_name(field) + (field.defined ? "" : tr("   guessed", "   угадан")), value_x);
    ui::field(tr("Name", "Имя"), field.name.empty() ? std::string_view("—") : std::string_view(field.name), value_x);
    const PointerPath path = structure.path_to(row, 0);
    const std::optional<std::uint64_t> address = structure.field_address(row, 0);
    if (is_chain(path)) {
        const std::string text = format_pointer_path(path);
        ui::field(tr("Chain", "Цепочка"), text, value_x, fonts_.mono);
        ImGui::SetItemTooltip("%s", text.c_str());
        ui::field(tr("Address", "Адрес"), address ? format_address(*address) : std::string(tr("the chain leads nowhere now", "цепочка сейчас никуда не ведёт")),
                  value_x, address ? fonts_.mono : nullptr);
    } else {
        ui::field(tr("Address", "Адрес"), address ? format_address(*address) : std::string("—"), value_x, fonts_.mono);
    }
    const bool mono = mono_value(field.type);
    for (std::size_t i = 0; i < structure.instances(); ++i) {
        ui::muted(i == 0 ? std::string(tr("Now", "Сейчас")) : tr("Column ", "Столбец ") + std::to_string(i + 1));
        ImGui::SameLine(value_x);
        const std::string value = structure.value_text(row, i);
        if (value.empty()) {
            ui::muted("—");
            continue;
        }
        if (value == "??") {
            ui::muted(tr("unreadable", "не читается"));
            continue;
        }
        if (mono) {
            ImGui::PushFont(fonts_.mono);
        }
        const bool clipped = ImGui::CalcTextSize(value.c_str()).x > ImGui::GetContentRegionAvail().x;
        if (structure.recently_changed(row, i, now) || structure.differs(row, i)) {
            inverted_text(value);
        } else {
            ui::text(value);
        }
        if (mono) {
            ImGui::PopFont();
        }
        if (clipped) {
            ImGui::SetItemTooltip("%s", value.c_str());
        }
    }

    ImGui::Spacing();
    if (ui::button(tr("Edit…", "Изменить…"), structure.editable(row))) {
        open_field_dialog(row);
    }
    ImGui::SetItemTooltip("%s", tr("The field's type, length and name.  F2", "Тип, длина и имя поля.  F2"));
    ImGui::SameLine();
    if (ui::button(tr("Reset", "Сбросить"), structure.editable(row) && field.defined)) {
        structure.forget(row);
        return;
    }
    ImGui::SetItemTooltip("%s", tr("Guess the field's type again.  Del", "Снова угадывать тип поля.  Del"));
    if (ui::button(tr("To the address list", "В список адресов"))) {
        session_.add_struct_watch(row, 0);
    }
    ImGui::SetItemTooltip("Insert");
    ImGui::SameLine();
    if (ui::button(tr("Lay out from here", "Разобрать отсюда"), field.type == FieldType::Pointer)) {
        if (structure.dissect(row)) {
            session_.refresh_structure(now);
        }
        return;
    }
    ImGui::SetItemTooltip("%s", tr("Make the structure the pointer leads to the main one", "Сделать главной структуру, куда ведёт указатель"));

    ImGui::Spacing();
    ui::heading(fonts_.heading, tr("STRUCTURE", "СТРУКТУРА"));
    const std::string base = format_struct_base(structure.base());
    ui::field(tr("Base", "База"), base, value_x, fonts_.mono);
    ImGui::SetItemTooltip("%s", base.c_str());
    if (is_chain(structure.base())) {
        const std::optional<std::uint64_t> start = structure.address(0);
        ui::field(tr("Address", "Адрес"), start ? format_address(*start) : std::string(tr("the chain leads nowhere now", "цепочка сейчас никуда не ведёт")),
                  value_x, start ? fonts_.mono : nullptr);
    }
    ImGui::AlignTextToFramePadding();
    ui::muted(tr("Size", "Размер"));
    ImGui::SameLine(value_x);
    if (!struct_resizing_) {
        struct_resize_ = format_hex(structure.size());
    }
    ImGui::SetNextItemWidth(std::floor(90.0f * scale_));
    ImGui::PushFont(fonts_.mono);
    if (ImGui::InputText("##struct_resize", &struct_resize_, ImGuiInputTextFlags_EnterReturnsTrue)) {
        const std::optional<std::uint64_t> size = parse_address(struct_resize_);
        if (size && *size > 0 && *size <= kMaxStructSize) {
            structure.set_size(static_cast<std::uint32_t>(*size));
            session_.refresh_structure(now);
        }
    }
    struct_resizing_ = ImGui::IsItemActive();
    ImGui::PopFont();
    ImGui::SameLine();
    ui::muted(tr("bytes, hex, Enter", "байт, hex, Enter"));
    for (std::size_t i = 1; i < structure.instances(); ++i) {
        ImGui::PushID(static_cast<int>(i));
        ImGui::AlignTextToFramePadding();
        ui::muted(tr("Column ", "Столбец ") + std::to_string(i + 1));
        ImGui::SameLine(value_x);
        if (ui::button(tr("Remove", "Убрать"))) {
            structure.remove_instance(i);
            ImGui::PopID();
            break;
        }
        ImGui::SameLine();
        ImGui::PushFont(fonts_.mono);
        ui::text(format_struct_base(structure.instance(i)));
        ImGui::PopFont();
        ImGui::PopID();
    }
}

void View::draw_struct_open() {
    center_next_dialog(580.0f * scale_);
    if (!ImGui::BeginPopupModal("##struct_open", nullptr, kDialog)) {
        return;
    }
    bool close = ImGui::IsKeyPressed(ImGuiKey_Escape, false);
    bool submit = enter_pressed();
    const float value_x = std::floor(90.0f * scale_);

    ui::heading(fonts_.heading, tr("LAY OUT A STRUCTURE", "РАЗОБРАТЬ СТРУКТУРУ"));
    ui::muted_wrapped(tr("Fields are read from the program's memory twice a second, types are guessed from the bytes. The chain is "
                         "walked anew on each read, so the structure is found even after the program moves it or restarts.",
                         "Поля читаются из памяти программы дважды в секунду, типы угадываются по байтам. Цепочка проходится заново "
                         "при каждом чтении, поэтому структура находится и после того, как программа переложит её или перезапустится."));
    ImGui::Spacing();
    ImGui::AlignTextToFramePadding();
    ui::muted(tr("Base", "База"));
    ImGui::SameLine(value_x);
    ImGui::SetNextItemWidth(-FLT_MIN);
    if (struct_focus_) {
        ImGui::SetKeyboardFocusHere();
        struct_focus_ = false;
    }
    ImGui::PushFont(fonts_.mono);
    ImGui::InputTextWithHint("##struct_base", base_hint(), &struct_base_);
    ImGui::PopFont();

    ImGui::AlignTextToFramePadding();
    ui::muted(tr("Size", "Размер"));
    ImGui::SameLine(value_x);
    ImGui::SetNextItemWidth(std::floor(110.0f * scale_));
    ImGui::PushFont(fonts_.mono);
    ImGui::InputText("##struct_size", &struct_size_);
    ImGui::PopFont();
    ImGui::SameLine();
    ui::muted(tr("bytes, hex, up to ", "байт, hex, до ") + format_hex(kMaxStructSize));

    const bool suggested = struct_base_ == struct_suggested_base_;
    if (suggested && struct_focus_offset_ && (*struct_focus_offset_ > 0 || struct_known_)) {
        ImGui::SetCursorPosX(value_x);
        std::string note = tr("Field ", "Будет выделено поле ") + format_hex(*struct_focus_offset_) + tr(" will be selected", "");
        if (struct_known_) {
            note += " «" + struct_known_->name + "»";
        }
        ui::muted(note);
    }
    if (!struct_error_.empty()) {
        ImGui::Spacing();
        ui::inverted_block(struct_error_);
    }
    ImGui::Spacing();
    const int pressed = dialog_buttons(tr("Lay out", "Разобрать"), tr("Cancel", "Отмена"));
    submit |= pressed == 0;
    close |= pressed == 1;

    if (submit && !close) {
        std::optional<PointerPath> base = parse_pointer_path(trimmed(struct_base_), session_.pointer_size());
        const std::optional<std::uint64_t> size = parse_address(struct_size_);
        if (!base) {
            struct_error_ = base_error();
            struct_focus_ = true;
        } else if (!size || *size == 0 || *size > kMaxStructSize) {
            struct_error_ = tr("The size is from 0x1 to ", "Размер — от 0x1 до ") + format_hex(kMaxStructSize) + tr(" bytes, hex.", " байт, hex.");
        } else if (session_.open_structure(std::move(*base), static_cast<std::uint32_t>(*size), suggested ? struct_focus_offset_ : std::nullopt,
                                           suggested ? struct_known_ : std::nullopt)) {
            page_ = Page::Structure;
            scroll_to_selection_ = true;
            close = true;
        } else {
            struct_error_ = session_.notice().text;
        }
    }
    if (close) {
        struct_error_.clear();
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

void View::draw_struct_field() {
    center_next_dialog(520.0f * scale_);
    if (!ImGui::BeginPopupModal("##struct_field", nullptr, kDialog)) {
        return;
    }
    bool close = ImGui::IsKeyPressed(ImGuiKey_Escape, false);
    bool submit = enter_pressed();
    const float value_x = std::floor(100.0f * scale_);
    StructTable& structure = session_.structure();

    ui::heading(fonts_.heading, tr("STRUCTURE FIELD", "ПОЛЕ СТРУКТУРЫ"));
    ImGui::AlignTextToFramePadding();
    ui::muted(tr("Offset", "Смещение"));
    ImGui::SameLine(value_x);
    ImGui::SetNextItemWidth(std::floor(110.0f * scale_));
    ImGui::PushFont(fonts_.mono);
    ImGui::InputTextWithHint("##field_offset", "0x50", &field_offset_);
    ImGui::PopFont();
    ImGui::SameLine();
    ui::muted(tr("from the start of the structure, hex", "от начала структуры, hex"));

    ImGui::AlignTextToFramePadding();
    ui::muted(tr("Type", "Тип"));
    ImGui::SameLine(value_x);
    const float x = ImGui::GetCursorPosX();
    ui::segments(field_type_, {{FieldType::Int8, "int8"}, {FieldType::Int16, "int16"}, {FieldType::Int32, "int32"}, {FieldType::Int64, "int64"}});
    ImGui::SetCursorPosX(x);
    ui::segments(field_type_, {{FieldType::Float, "float"}, {FieldType::Double, "double"}, {FieldType::Pointer, "pointer"}});
    ImGui::SetCursorPosX(x);
    ui::segments(field_type_, {{FieldType::Ascii, "ASCII"}, {FieldType::Utf16, "UTF-16"}, {FieldType::Bytes, tr("Bytes", "Байты")}});
    if (has_length(field_type_)) {
        ImGui::AlignTextToFramePadding();
        ui::muted(tr("Length", "Длина"));
        ImGui::SameLine(value_x);
        ImGui::SetNextItemWidth(std::floor(70.0f * scale_));
        ImGui::InputInt("##field_length", &field_length_, 0, 0);
        ImGui::SameLine();
        ui::muted(std::string(field_type_ == FieldType::Bytes ? tr("bytes", "байт") : tr("characters", "символов")) + tr(", up to ", ", до ") + std::to_string(kMaxFieldLength));
    }

    ImGui::AlignTextToFramePadding();
    ui::muted(tr("Name", "Имя"));
    ImGui::SameLine(value_x);
    ImGui::SetNextItemWidth(-FLT_MIN);
    if (struct_focus_) {
        ImGui::SetKeyboardFocusHere();
        struct_focus_ = false;
    }
    ImGui::InputTextWithHint("##field_name", tr("for example health", "например health"), &field_name_);
    ImGui::Spacing();
    ui::muted_wrapped(tr("Defined fields are saved with the «Save…» button; the fields around them are guessed anew.",
                         "Заданные поля сохраняются кнопкой «Сохранить…»; поля вокруг угадываются заново."));
    if (!struct_error_.empty()) {
        ImGui::Spacing();
        ui::inverted_block(struct_error_);
    }
    ImGui::Spacing();
    const int pressed = dialog_buttons(tr("Set", "Задать"), tr("Cancel", "Отмена"));
    submit |= pressed == 0;
    close |= pressed == 1;

    if (submit && !close) {
        const std::optional<std::uint64_t> offset = parse_address(field_offset_);
        const bool length_ok = !has_length(field_type_) || (field_length_ >= 1 && field_length_ <= static_cast<int>(kMaxFieldLength));
        if (!offset || *offset >= kMaxStructSize) {
            struct_error_ = tr("The offset is from 0x0 to ", "Смещение — от 0x0 до ") + format_hex(kMaxStructSize - 1) + tr(", hex.", ", hex.");
        } else if (!length_ok) {
            struct_error_ = tr("Length is from 1 to ", "Длина — от 1 до ") + std::to_string(kMaxFieldLength) + ".";
        } else if (structure.define(static_cast<std::uint32_t>(*offset), field_type_,
                                    has_length(field_type_) ? static_cast<std::uint32_t>(field_length_) : 0, trimmed(field_name_))) {
            structure.select_offset(static_cast<std::uint32_t>(*offset));
            scroll_to_selection_ = true;
            close = true;
        } else {
            struct_error_ = tr("The field does not fit in ", "Поле не помещается в ") + format_hex(kMaxStructSize) + tr(" bytes.", " байт.");
        }
    }
    if (close) {
        struct_error_.clear();
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

void View::draw_struct_instance() {
    center_next_dialog(560.0f * scale_);
    if (!ImGui::BeginPopupModal("##struct_instance", nullptr, kDialog)) {
        return;
    }
    bool close = ImGui::IsKeyPressed(ImGuiKey_Escape, false);
    bool submit = enter_pressed();
    const float value_x = std::floor(90.0f * scale_);

    ui::heading(fonts_.heading, tr("COMPARE WITH ANOTHER INSTANCE", "СРАВНИТЬ С ДРУГИМ ЭКЗЕМПЛЯРОМ"));
    ui::muted_wrapped(tr("The same structure at another address, for example another player. Its values stand in a column beside, and "
                         "the ones that differ from the first column are highlighted.",
                         "Та же структура по другому адресу, например другой игрок. Его значения встанут столбцом рядом, а те, что "
                         "отличаются от первого столбца, будут выделены."));
    ImGui::Spacing();
    ImGui::AlignTextToFramePadding();
    ui::muted(tr("Base", "База"));
    ImGui::SameLine(value_x);
    ImGui::SetNextItemWidth(-FLT_MIN);
    if (struct_focus_) {
        ImGui::SetKeyboardFocusHere();
        struct_focus_ = false;
    }
    ImGui::PushFont(fonts_.mono);
    ImGui::InputTextWithHint("##instance_base", base_hint(), &instance_base_);
    ImGui::PopFont();
    if (!struct_error_.empty()) {
        ImGui::Spacing();
        ui::inverted_block(struct_error_);
    }
    ImGui::Spacing();
    const int pressed = dialog_buttons(tr("Add", "Добавить"), tr("Cancel", "Отмена"));
    submit |= pressed == 0;
    close |= pressed == 1;

    if (submit && !close) {
        StructTable& structure = session_.structure();
        std::optional<PointerPath> base = parse_pointer_path(trimmed(instance_base_), session_.pointer_size());
        if (!base) {
            struct_error_ = base_error();
            struct_focus_ = true;
        } else if (!structure.add_instance(std::move(*base))) {
            struct_error_ = tr("That column already exists, or there are already ", "Такой столбец уже есть, или их уже ") + std::to_string(kMaxInstances) + ".";
            struct_focus_ = true;
        } else {
            session_.refresh_structure(StructTable::Clock::now());
            close = true;
        }
    }
    if (close) {
        struct_error_.clear();
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

}  // namespace mh::gui
