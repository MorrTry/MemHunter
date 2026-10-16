#include <imgui.h>
#include <misc/cpp/imgui_stdlib.h>

#include <algorithm>
#include <cfloat>
#include <cmath>
#include <limits>

#include "common/error.hpp"
#include "common/text.hpp"
#include "gui/lang.hpp"
#include "gui/view.hpp"
#include "gui/view_internal.hpp"
#include "gui/widgets.hpp"

namespace mh::gui {

namespace {

unsigned dialog_threads(const SearchForm& form) {
    return std::min(form.threads, kMaxThreads);
}

}  // namespace

void View::open_pointer_scan() {
    const std::optional<std::size_t> row = session_.watch().selected_row();
    if (!row || session_.busy() || !alive_) {
        return;
    }
    pointer_row_ = *row;
    pointer_error_.clear();
    pointer_scan_requested_ = true;
    pointer_focus_ = true;
}

void View::open_pointer_check() {
    const PointerList& pointers = session_.pointers();
    if (!pointers.has_chains() || session_.busy() || !alive_) {
        return;
    }
    // The address found again after a restart is usually the one just added to the address list.
    if (const WatchEntry* selected = session_.watch().selected(); selected != nullptr && !selected->path) {
        check_form_.address = format_address(selected->address);
    }
    if (!value_type(pointers.search().target.type)) {
        check_form_.by_value = false;
    }
    pointer_error_.clear();
    pointer_check_requested_ = true;
    pointer_focus_ = true;
}

void View::save_pointers() {
    const PointerList& pointers = session_.pointers();
    if (!pointers.has_chains()) {
        return;
    }
    const std::string& process = pointers.search().process.name;
    const std::wstring name =
        (process.empty() ? std::wstring(L"memhunter") : std::filesystem::path(utf8_to_wide(process)).stem().wstring()) + L"-pointers.mhp";
    try {
        if (const auto path = platform_.ask_save_path(name, FileKind::Pointers)) {
            session_.save_pointers(*path);
        }
    } catch (const Error& error) {
        session_.set_notice(describe_error(error), true);
    }
}

void View::load_pointers() {
    if (session_.busy()) {
        return;
    }
    try {
        if (const auto path = platform_.ask_open_path(FileKind::Pointers); path && session_.load_pointers(*path)) {
            page_ = Page::Pointers;
            scroll_to_selection_ = true;
        }
    } catch (const Error& error) {
        session_.set_notice(describe_error(error), true);
    }
}

void View::handle_pointer_shortcuts(bool copy) {
    PointerList& pointers = session_.pointers();
    scroll_to_selection_ |= navigate(pointers, page_rows_);
    const std::optional<std::size_t> row = pointers.selected_row();
    if (!row) {
        return;
    }
    if (ImGui::IsKeyPressed(ImGuiKey_Insert, false)) {
        session_.add_pointer_watch(*row);
    }
    if (copy) {
        const std::string path = pointers.path_text(*row);
        ImGui::SetClipboardText(path.c_str());
        session_.set_notice(tr("Chain copied: ", "Цепочка скопирована: ") + path, false);
    }
}

void View::draw_pointer_bar(float right_edge) {
    const PointerList& pointers = session_.pointers();
    const Job* job = session_.job();
    const bool chains = pointers.has_chains();
    if (ui::button(tr("Check…", "Проверить…"), chains && job == nullptr && alive_)) {
        open_pointer_check();
    }
    ImGui::SetItemTooltip("%s", tr("After the program restarts, keeps the chains that lead to the address found again, or to the value",
                                   "После перезапуска программы оставит цепочки, которые ведут к адресу, найденному заново, или к значению"));
    ImGui::SameLine();
    if (ui::button(tr("Save…", "Сохранить…"), chains)) {
        save_pointers();
    }
    ImGui::SetItemTooltip("%s", tr("An .mhp file to check the chains after the program restarts.  Ctrl+S",
                                   "Файл .mhp, чтобы проверить цепочки после перезапуска программы.  Ctrl+S"));
    ImGui::SameLine();
    if (ui::button(tr("Load…", "Загрузить…"), job == nullptr)) {
        load_pointers();
    }
    ImGui::SameLine();
    if (ui::button(tr("Clear", "Очистить"), chains && !(job != nullptr && job->kind() == JobKind::PointerCheck))) {
        clear_pointers_requested_ = true;
    }
    ImGui::SameLine(0.0f, 20.0f * scale_);
    ImGui::AlignTextToFramePadding();
    const std::size_t rows = pointers.rows().size();
    const PointerSearch& search = pointers.search();
    std::string count;
    if (!chains) {
        count = tr("The list is empty", "Список пуст");
    } else if (search.checks == 0 && search.found > rows) {
        count = tr("Showing the shortest ", "Показаны самые короткие ") + group_digits(rows) + tr(" of ", " из ") + group_digits(search.found);
    } else {
        count = tr("Chains: ", "Цепочек: ") + group_digits(rows);
    }
    const float count_end = ImGui::GetCursorPosX() + ImGui::CalcTextSize(count.c_str()).x;
    ui::muted(count_end <= right_edge ? count : std::string());
    const char* hint = tr("Shorter chains first", "Короткие цепочки — выше");
    const float hint_x = right_edge - ImGui::CalcTextSize(hint).x;
    if (chains && hint_x > count_end + 20.0f * scale_) {
        ImGui::SameLine(hint_x);
        ui::muted(hint);
        ImGui::SetItemTooltip("%s", tr("The fewer pointers in a chain, the likelier it survives a restart and an update of the program",
                                       "Чем меньше в цепочке указателей, тем вероятнее она переживёт перезапуск и обновление программы"));
    }
}

void View::draw_pointer_table(float height) {
    PointerList& pointers = session_.pointers();
    if (!pointers.has_chains()) {
        ImGui::BeginChild("##no_pointers", ImVec2(0, height), ImGuiChildFlags_Borders, kPanel);
        const Job* job = session_.job();
        if (job != nullptr && job->kind() == JobKind::PointerScan) {
            ui::muted(tr("Searching for pointers…", "Идёт поиск указателей…"));
        } else {
            ui::muted_wrapped(tr("Here will be pointer chains. Add a value to the address list, select it there, and press "
                                 "«Find pointers…». The «Load…» button opens saved chains.",
                                 "Здесь будут цепочки указателей. Добавьте значение в список адресов, выберите его там и нажмите "
                                 "«Найти указатели…». Сохранённые цепочки открывает кнопка «Загрузить…»."));
        }
        ImGui::EndChild();
        return;
    }

    const MemorySource& memory = session_.target()->memory();
    const std::span<const PointerChain> rows = pointers.rows();
    const std::optional<std::size_t> selected = pointers.selected_row();
    const bool bytes = pointers.search().target.type == WatchType::Bytes;
    const ImGuiStyle& style = ImGui::GetStyle();
    const float ui_line = ImGui::GetTextLineHeight();
    const float mono_line = fonts_.mono->FontSize;
    const float row_height = std::max(ui_line, mono_line);
    const float ui_offset = std::floor((row_height - ui_line) * 0.5f);
    const float mono_offset = std::floor((row_height - mono_line) * 0.5f);
    page_rows_ = std::max(1, static_cast<int>(height / (row_height + style.CellPadding.y * 2.0f)) - 2);
    const auto now = std::chrono::steady_clock::now();
    if (now - pointers_time_ >= kLiveRefresh) {
        pointers_time_ = now;
        pointers.forget_live();
    }

    constexpr ImGuiTableFlags flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersInnerV |
                                      ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingFixedFit;
    if (!ImGui::BeginTable("##pointers", 4, flags, ImVec2(0, height))) {
        return;
    }
    ImGui::TableSetupColumn(tr("Base", "База"), 0, font_text_width(fonts_.mono, "game_client_win64.exe+0x1A2B3C"));
    ImGui::TableSetupColumn(tr("Offsets", "Смещения"), ImGuiTableColumnFlags_WidthStretch, 2.4f);
    ImGui::TableSetupColumn(tr("Address", "Адрес"), ImGuiTableColumnFlags_WidthStretch, 1.6f);
    ImGui::TableSetupColumn(tr("Value", "Значение"), ImGuiTableColumnFlags_WidthStretch, 1.0f);
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableHeadersRow();

    std::optional<std::size_t> add_row;
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(rows.size()), row_height + style.CellPadding.y * 2.0f);
    if (selected) {
        clipper.IncludeItemByIndex(static_cast<int>(*selected));
    }
    while (clipper.Step()) {
        const auto first = static_cast<std::size_t>(clipper.DisplayStart);
        const auto last = static_cast<std::size_t>(clipper.DisplayEnd);
        bool stale = false;
        for (std::size_t index = first; index < last && !stale; ++index) {
            stale = !pointers.read(index);
        }
        if (stale) {
            pointers.refresh(memory, first, last);
        }
        for (std::size_t index = first; index < last; ++index) {
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
                pointers.select_row(index);
            }
            if (clicked && ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                add_row = index;
            }
            ImGui::SetItemTooltip("%s", tr("Double click — to the address list", "Двойной щелчок — в список адресов"));
            if (ImGui::BeginPopupContextItem("##menu")) {
                if (ImGui::MenuItem(tr("To the address list", "В список адресов"), "Insert")) {
                    add_row = index;
                }
                if (ImGui::MenuItem(tr("Copy chain", "Копировать цепочку"), "Ctrl+C")) {
                    const std::string path = pointers.path_text(index);
                    ImGui::SetClipboardText(path.c_str());
                    session_.set_notice(tr("Chain copied: ", "Цепочка скопирована: ") + path, false);
                }
                const std::optional<std::uint64_t> address = pointers.address(index);
                if (ImGui::MenuItem(tr("Copy address", "Копировать адрес"), nullptr, false, address.has_value())) {
                    copy_address(*address);
                }
                ImGui::Separator();
                if (ImGui::MenuItem(tr("Lay out structure…", "Разобрать структуру…"), "Ctrl+D")) {
                    open_struct_from_selection();
                }
                if (ImGui::MenuItem(tr("Disassemble", "Дизассемблировать"), nullptr, false, address.has_value())) {
                    disassemble_at(*address);
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
            ImGui::SetCursorPos(ImVec2(row_start.x, row_start.y + mono_offset));
            ui::text(pointers.base_text(index));
            ImGui::TableSetColumnIndex(1);
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + mono_offset);
            ui::text(pointers.offsets_text(index));
            ImGui::TableSetColumnIndex(2);
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + mono_offset);
            const std::string address = pointers.address_text(index);
            if (address == "??") {
                ui::muted(address);
            } else {
                ui::text(address);
            }
            ImGui::PopFont();

            ImGui::TableSetColumnIndex(3);
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + (bytes ? mono_offset : ui_offset));
            const std::string value = pointers.value_text(index);
            if (value == "??") {
                ui::muted(value);
            } else {
                if (bytes) {
                    ImGui::PushFont(fonts_.mono);
                }
                ui::text(value);
                if (bytes) {
                    ImGui::PopFont();
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

    if (add_row) {
        session_.add_pointer_watch(*add_row);
    }
}

void View::draw_pointer_info(std::size_t row, float value_x) {
    const PointerList& pointers = session_.pointers();
    const PointerSearch& search = pointers.search();
    ui::heading(fonts_.heading, tr("CHAIN", "ЦЕПОЧКА"));
    const std::string path = pointers.path_text(row);
    ui::field(tr("Path", "Путь"), path, value_x, fonts_.mono);
    ImGui::SetItemTooltip("%s", path.c_str());
    ui::field(tr("Base", "База"), pointers.base_text(row), value_x, fonts_.mono);
    ui::field(tr("Offsets", "Смещения"), pointers.offsets_text(row), value_x, fonts_.mono);
    const std::optional<std::uint64_t> address = pointers.address(row);
    if (address) {
        ui::field(tr("Address", "Адрес"), format_address(*address), value_x, fonts_.mono);
    } else {
        ui::field(tr("Address", "Адрес"), pointers.read(row) ? tr("the chain leads nowhere now", "цепочка сейчас никуда не ведёт") : "—", value_x);
    }
    const std::string value = pointers.value_text(row);
    ui::field(tr("Value", "Значение"),
              value.empty() ? std::string_view("—") : value == "??" ? std::string_view(tr("unreadable", "не читается")) : std::string_view(value),
              value_x, search.target.type == WatchType::Bytes ? fonts_.mono : nullptr);

    ImGui::Spacing();
    ui::heading(fonts_.heading, tr("SEARCH", "ПОИСК"));
    ui::field(tr("Target", "Цель"), format_address(search.target.address) + "   " + type_label(search.target), value_x);
    ImGui::SetItemTooltip("%s", search.checks == 0 ? tr("The address the chains were searched to", "Адрес, к которому искались цепочки")
                                                   : tr("The address at the last check", "Адрес при последней проверке"));
    if (!search.target.description.empty()) {
        ui::field(tr("Description", "Описание"), search.target.description, value_x);
    }
    ui::field(tr("Depth", "Глубина"), std::to_string(search.depth) + tr(", offsets up to ", ", смещения до ") + format_hex(search.max_offset), value_x);
    ui::field(tr("Checks", "Проверок"), std::to_string(search.checks), value_x);
    ui::field(tr("Process", "Процесс"), search.process.name + "   PID " + std::to_string(search.process.pid), value_x);
}

void View::draw_pointer_scan() {
    center_next_dialog(540.0f * scale_);
    if (!ImGui::BeginPopupModal("##pointer_scan", nullptr, kDialog)) {
        return;
    }
    bool close = ImGui::IsKeyPressed(ImGuiKey_Escape, false);
    bool submit = enter_pressed();
    const float value_x = std::floor(120.0f * scale_);
    const WatchList& watch = session_.watch();

    ui::heading(fonts_.heading, tr("FIND POINTERS", "НАЙТИ УКАЗАТЕЛИ"));
    ui::muted_wrapped(tr("A chain starts in a module of the program (exe or dll) and through a few pointers arrives at the address. "
                         "Module addresses shift together with the modules between runs, so the chain finds the value even after a "
                         "restart.",
                         "Цепочка начинается в модуле программы (exe или dll) и через несколько указателей приходит к адресу. "
                         "Адреса модулей между запусками сдвигаются вместе с ними, поэтому цепочка находит значение и после "
                         "перезапуска."));
    ImGui::Spacing();
    if (pointer_row_ < watch.rows().size()) {
        const WatchEntry& entry = watch.rows()[pointer_row_];
        std::string target = format_address(entry.address) + "   " + type_label(entry);
        if (!entry.description.empty()) {
            target += "   " + entry.description;
        }
        ui::field(tr("Address", "Адрес"), target, value_x);
    }

    ImGui::AlignTextToFramePadding();
    ui::muted(tr("Depth", "Глубина"));
    ImGui::SameLine(value_x);
    ImGui::SetNextItemWidth(std::floor(70.0f * scale_));
    if (pointer_focus_) {
        ImGui::SetKeyboardFocusHere();
        pointer_focus_ = false;
    }
    ImGui::InputInt("##pointer_depth", &pointer_depth_, 0, 0);
    ImGui::SameLine();
    ui::muted(tr("pointers in the chain, from 1 to ", "указателей в цепочке, от 1 до ") + std::to_string(kMaxPointerDepth));

    ImGui::AlignTextToFramePadding();
    ui::muted(tr("Offset up to", "Смещение до"));
    ImGui::SameLine(value_x);
    ImGui::SetNextItemWidth(std::floor(110.0f * scale_));
    ImGui::PushFont(fonts_.mono);
    ImGui::InputText("##pointer_offset", &pointer_offset_);
    ImGui::PopFont();
    ImGui::SameLine();
    ui::muted(tr("from a pointer to a field, hex", "от указателя до поля, hex"));

    ImGui::Spacing();
    ui::muted_wrapped(tr("The greater the depth and offset, the more chains are found, but the search takes longer and uses more memory.",
                         "Чем больше глубина и смещение, тем больше цепочек находится, но поиск идёт дольше и занимает больше памяти."));
    if (!pointer_error_.empty()) {
        ImGui::Spacing();
        ui::inverted_block(pointer_error_);
    }
    ImGui::Spacing();
    const int pressed = dialog_buttons(tr("Find", "Найти"), tr("Cancel", "Отмена"));
    submit |= pressed == 0;
    close |= pressed == 1;

    if (submit && !close) {
        const std::optional<std::uint64_t> offset = parse_address(pointer_offset_);
        if (pointer_depth_ < 1 || pointer_depth_ > static_cast<int>(kMaxPointerDepth)) {
            pointer_error_ = tr("Depth is from 1 to ", "Глубина — от 1 до ") + std::to_string(kMaxPointerDepth) + ".";
            pointer_focus_ = true;
        } else if (!offset || *offset > std::numeric_limits<std::uint32_t>::max()) {
            pointer_error_ = tr("The offset is a hexadecimal number, for example 0x1000.", "Смещение — шестнадцатеричное число, например 0x1000.");
        } else if (session_.start_pointer_scan(pointer_row_, static_cast<unsigned>(pointer_depth_), static_cast<std::uint32_t>(*offset),
                                               dialog_threads(form_))) {
            page_ = Page::Pointers;
            scroll_to_selection_ = true;
            close = true;
        } else {
            pointer_error_ = session_.notice().text;
        }
    }
    if (close) {
        pointer_error_.clear();
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

void View::draw_pointer_check() {
    center_next_dialog(540.0f * scale_);
    if (!ImGui::BeginPopupModal("##pointer_check", nullptr, kDialog)) {
        return;
    }
    bool close = ImGui::IsKeyPressed(ImGuiKey_Escape, false);
    bool submit = enter_pressed();
    const float value_x = std::floor(120.0f * scale_);
    const PointerList& pointers = session_.pointers();
    const PointerSearch& search = pointers.search();
    const bool numbers = value_type(search.target.type).has_value();

    ui::heading(fonts_.heading, tr("CHECK THE CHAINS", "ПРОВЕРИТЬ ЦЕПОЧКИ"));
    ui::muted_wrapped(tr("Restart the program, pick it again, and find the same value. The check keeps the chains that lead to it "
                         "now. If none fit, the list stays as it was.",
                         "Перезапустите программу, выберите её заново и найдите то же значение. Проверка оставит цепочки, которые "
                         "сейчас ведут к нему. Если не подойдёт ни одна, список останется прежним."));
    ImGui::Spacing();
    ui::field(tr("Chains", "Цепочек"), group_digits(pointers.rows().size()), value_x);
    ui::field(tr("The target was", "Цель была"), format_address(search.target.address) + "   " + type_label(search.target), value_x);

    ImGui::AlignTextToFramePadding();
    ui::muted(tr("Check by", "Проверить"));
    ImGui::SameLine(value_x);
    const float spacing = ImGui::GetStyle().ItemSpacing.x;
    const float segment_width = std::floor((ImGui::GetContentRegionAvail().x - spacing) * 0.5f);
    if (ui::segment(tr("By address", "По адресу"), !check_form_.by_value, true, ImVec2(segment_width, 0.0f))) {
        check_form_.by_value = false;
        pointer_focus_ = true;
    }
    ImGui::SameLine(0.0f, spacing);
    if (ui::segment(tr("By value", "По значению"), check_form_.by_value, numbers, ImVec2(segment_width, 0.0f))) {
        check_form_.by_value = true;
        pointer_focus_ = true;
    }

    ImGui::AlignTextToFramePadding();
    ui::muted(check_form_.by_value ? tr("Value", "Значение") : tr("New address", "Новый адрес"));
    ImGui::SameLine(value_x);
    ImGui::SetNextItemWidth(-FLT_MIN);
    if (pointer_focus_) {
        ImGui::SetKeyboardFocusHere();
        pointer_focus_ = false;
    }
    if (check_form_.by_value) {
        ImGui::InputTextWithHint("##check_value", tr("for example 100", "например 100"), &check_form_.value);
        ImGui::SetCursorPosX(value_x);
        ui::muted_wrapped(tr("Type ", "Тип ") + type_label(search.target) +
                          tr(". A rare value is better: a common one like 0 or 1 has many extra chains leading to it.",
                             ". Лучше редкое значение: к частому вроде 0 или 1 ведёт много лишних цепочек."));
    } else {
        ImGui::PushFont(fonts_.mono);
        ImGui::InputTextWithHint("##check_address", "0x7FF6A0001000", &check_form_.address);
        ImGui::PopFont();
        ImGui::SetCursorPosX(value_x);
        ui::muted_wrapped(numbers ? tr("The address of the same value in the new run, for example from the address list.",
                                       "Адрес того же значения в новом запуске, например из списка адресов.")
                                  : tr("The address of the same value in the new run. Text and bytes are checked by address only.",
                                       "Адрес того же значения в новом запуске. Текст и байты проверяются только по адресу."));
    }

    if (!pointer_error_.empty()) {
        ImGui::Spacing();
        ui::inverted_block(pointer_error_);
    }
    ImGui::Spacing();
    const int pressed = dialog_buttons(tr("Check", "Проверить"), tr("Cancel", "Отмена"));
    submit |= pressed == 0;
    close |= pressed == 1;

    if (submit && !close) {
        if (session_.start_pointer_check(check_form_, dialog_threads(form_))) {
            page_ = Page::Pointers;
            scroll_to_selection_ = true;
            close = true;
        } else {
            pointer_error_ = session_.notice().text;
            pointer_focus_ = true;
        }
    }
    if (close) {
        pointer_error_.clear();
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

void View::draw_clear_pointers() {
    center_next_dialog(420.0f * scale_);
    if (!ImGui::BeginPopupModal("##clear_pointers", nullptr, kDialog)) {
        return;
    }
    bool close = ImGui::IsKeyPressed(ImGuiKey_Escape, false);
    ui::heading(fonts_.heading, tr("CLEAR THE CHAINS", "ОЧИСТИТЬ ЦЕПОЧКИ"));
    ui::text(tr("Remove from the chain list: ", "Убрать из списка цепочек: ") + group_digits(session_.pointers().rows().size()) + "?");
    ui::muted(tr("Saved .mhp files are not affected.", "Сохранённые файлы .mhp не пострадают."));
    ImGui::Spacing();
    const int pressed = dialog_buttons(tr("Clear", "Очистить"), tr("Cancel", "Отмена"));
    if (pressed == 0 || (enter_pressed() && !close)) {
        session_.clear_pointers();
        session_.set_notice(tr("The chain list is cleared", "Список цепочек очищен"), false);
        close = true;
    }
    close |= pressed == 1;
    if (close) {
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

}  // namespace mh::gui
