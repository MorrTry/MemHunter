#include <imgui.h>
#include <misc/cpp/imgui_stdlib.h>

#include <algorithm>
#include <cmath>

#include "common/text.hpp"
#include "gui/lang.hpp"
#include "gui/view.hpp"
#include "gui/view_internal.hpp"
#include "gui/widgets.hpp"
#include "gui/watch_list.hpp"

namespace mh::gui {

namespace {

constexpr int kMinDisasmCount = 1;
constexpr int kMaxDisasmCount = 10000;

}  // namespace

void View::disassemble_at(std::uint64_t address) {
    disasm_address_ = format_address(address);
    disasm_error_.clear();
    page_ = Page::Disasm;
    disasm_focus_ = false;
    if (session_.disassemble(address, static_cast<std::size_t>(std::clamp(disasm_count_, kMinDisasmCount, kMaxDisasmCount)))) {
        scroll_to_selection_ = true;
    } else {
        disasm_error_ = session_.notice().text;
    }
}

void View::run_disasm() {
    if (session_.busy() || !alive_) {
        return;
    }
    const std::optional<std::uint64_t> address = parse_address(disasm_address_);
    if (!address) {
        disasm_error_ = tr("The address is a hexadecimal number, for example 0x7FF6A0001000.",
                           "Адрес — шестнадцатеричное число, например 0x7FF6A0001000.");
        disasm_focus_ = true;
        return;
    }
    disasm_count_ = std::clamp(disasm_count_, kMinDisasmCount, kMaxDisasmCount);
    ImGui::SetWindowFocus(nullptr);
    if (session_.disassemble(*address, static_cast<std::size_t>(disasm_count_))) {
        disasm_error_.clear();
        scroll_to_selection_ = true;
    } else {
        disasm_error_ = session_.notice().text;
    }
}

void View::handle_disasm_shortcuts(bool copy) {
    DisasmTable& disasm = session_.disasm();
    scroll_to_selection_ |= navigate(disasm, page_rows_);
    const DisasmLine* line = disasm.selected();
    if (line == nullptr) {
        return;
    }
    if (copy) {
        copy_address(line->address);
    } else if (ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_B)) {
        ImGui::SetClipboardText(line->bytes.c_str());
        session_.set_notice(tr("Bytes copied", "Байты скопированы"), false);
    } else if (ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_T)) {
        ImGui::SetClipboardText(line->text.c_str());
        session_.set_notice(tr("Instruction copied", "Инструкция скопирована"), false);
    } else if (line->has_target && ImGui::IsKeyPressed(ImGuiKey_Enter, false)) {
        disassemble_at(line->target_address);
    }
}

void View::draw_disasm_progress() {
    const DisasmTable& disasm = session_.disasm();
    if (!disasm.has_result()) {
        ui::progress_bar(0.0f, tr("Waiting", "Ожидание"));
        ui::muted(tr("Enter an address and press «Show» or F5 to disassemble machine code.",
                     "Введите адрес и нажмите «Показать» или F5, чтобы разобрать машинный код."));
        return;
    }
    ui::progress_bar(1.0f, tr("Done", "Готово"));
    const std::initializer_list<std::pair<const char*, std::string>> parts = {
        {tr("Address", "Адрес"), format_address(disasm.address())},
        {tr("Bitness", "Разрядность"), disasm.wow64() ? std::string("32") : std::string("64")},
        {tr("Instructions", "Инструкций"), count_instructions(disasm.rows().size())}};
    bool first = true;
    for (const auto& [label, value] : parts) {
        if (!first) {
            ImGui::SameLine(0.0f, 24.0f * scale_);
        }
        first = false;
        ui::muted(label);
        ImGui::SameLine();
        ui::text(value);
    }
}

float View::disasm_bar_width() const {
    const ImGuiStyle& style = ImGui::GetStyle();
    const float address = font_text_width(fonts_.mono, "0x0000000000000000") + style.FramePadding.x * 2.0f;
    const float count = std::floor(64.0f * scale_);
    return address + count + ImGui::CalcTextSize(tr("instr.", "инстр.")).x + button_width(tr("Show", "Показать")) + style.ItemSpacing.x * 4.0f;
}

void View::draw_disasm_bar(float right_edge) {
    (void)right_edge;
    const ImGuiStyle& style = ImGui::GetStyle();
    const bool enabled = session_.job() == nullptr && alive_;
    const float address = font_text_width(fonts_.mono, "0x0000000000000000") + style.FramePadding.x * 2.0f;

    ImGui::BeginDisabled(!enabled);
    if (disasm_focus_) {
        ImGui::SetKeyboardFocusHere();
        disasm_focus_ = false;
    }
    ImGui::SetNextItemWidth(address);
    ImGui::PushFont(fonts_.mono);
    const bool submit = ImGui::InputTextWithHint("##disasm_address", "0x7FF6A0001000", &disasm_address_, ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::PopFont();
    ImGui::SetItemTooltip("%s", tr("Address in the process's memory, hexadecimal", "Адрес в памяти процесса, шестнадцатеричный"));

    ImGui::SameLine();
    ImGui::SetNextItemWidth(std::floor(64.0f * scale_));
    const bool count_submit = ImGui::InputInt("##disasm_count", &disasm_count_, 0, 0, ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    ui::muted(tr("instr.", "инстр."));
    ImGui::SetItemTooltip(tr("How many instructions to disassemble, from %d to %d", "Сколько инструкций разобрать, от %d до %d"),
                          kMinDisasmCount, kMaxDisasmCount);

    ImGui::SameLine();
    const bool clicked = ui::button(tr("Show", "Показать"), enabled);
    ImGui::SetItemTooltip("%s", tr("Disassemble the machine code at the address.  F5", "Разобрать машинный код по адресу.  F5"));
    ImGui::EndDisabled();

    if (enabled && (submit || count_submit || clicked)) {
        run_disasm();
    }
    if (!disasm_error_.empty()) {
        ui::muted(disasm_error_);
    }
}

void View::draw_disasm_table(float height) {
    DisasmTable& disasm = session_.disasm();
    if (disasm.rows().empty()) {
        ImGui::BeginChild("##no_disasm", ImVec2(0, height), ImGuiChildFlags_Borders, kPanel);
        if (!disasm.has_result()) {
            ui::muted_wrapped(tr("Here will be x86/x64 instructions at an address: the address, bytes, the instruction, and, for jumps "
                                 "and calls, the module and offset they lead to. Enter an address above the table and press «Show» or F5.",
                                 "Здесь будут инструкции x86/x64 по адресу: адрес, байты, инструкция и, для переходов и вызовов, модуль и "
                                 "смещение, куда они ведут. Введите адрес над таблицей и нажмите «Показать» или F5."));
            ImGui::Spacing();
            ui::muted_wrapped(tr("Code can also be disassembled from the context menu on any finding, address, structure field, or match.",
                                 "Разобрать код можно и из контекстного меню на любой находке, адресе, поле структуры или совпадении."));
        } else {
            ui::text(tr("Nothing to read at ", "В ") + format_address(disasm.address()) + tr(".", " нечего читать."));
        }
        ImGui::EndChild();
        return;
    }

    const std::span<const DisasmLine> rows = disasm.rows();
    const std::optional<std::size_t> selected = disasm.selected_row();
    const ImGuiStyle& style = ImGui::GetStyle();
    const float ui_line = ImGui::GetTextLineHeight();
    const float mono_line = fonts_.mono->FontSize;
    const float row_height = std::max(ui_line, mono_line);
    const float mono_offset = std::floor((row_height - mono_line) * 0.5f);
    page_rows_ = std::max(1, static_cast<int>(height / (row_height + style.CellPadding.y * 2.0f)) - 2);

    constexpr ImGuiTableFlags flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersInnerV |
                                      ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingFixedFit;
    if (!ImGui::BeginTable("##disasm", 4, flags, ImVec2(0, height))) {
        return;
    }
    ImGui::TableSetupColumn(tr("Address", "Адрес"), 0, font_text_width(fonts_.mono, "0x0000000000000000"));
    ImGui::TableSetupColumn(tr("Bytes", "Байты"), 0, font_text_width(fonts_.mono, "00 00 00 00 00 00"));
    ImGui::TableSetupColumn(tr("Instruction", "Инструкция"), ImGuiTableColumnFlags_WidthStretch, 2.0f);
    ImGui::TableSetupColumn(tr("Jump", "Переход"), ImGuiTableColumnFlags_WidthStretch, 1.0f);
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableHeadersRow();

    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(rows.size()), row_height + style.CellPadding.y * 2.0f);
    if (selected) {
        clipper.IncludeItemByIndex(static_cast<int>(*selected));
    }
    while (clipper.Step()) {
        for (auto index = static_cast<std::size_t>(clipper.DisplayStart); index < static_cast<std::size_t>(clipper.DisplayEnd); ++index) {
            const DisasmLine& line = disasm.line(index);
            const bool is_selected = selected == index;
            ImGui::TableNextRow(ImGuiTableRowFlags_None, row_height);
            ImGui::TableSetColumnIndex(0);
            ImGui::PushID(static_cast<int>(index));
            if (is_selected) {
                ImGui::PushStyleColor(ImGuiCol_HeaderHovered, theme::kWhite);
                ImGui::PushStyleColor(ImGuiCol_HeaderActive, theme::kWhite);
            }
            const ImVec2 row_start = ImGui::GetCursorPos();
            const bool clicked = ImGui::Selectable("##row", is_selected, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap,
                                                   ImVec2(0.0f, row_height));
            if (is_selected) {
                ImGui::PopStyleColor(2);
            }
            if (clicked || ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                disasm.select_row(index);
            }
            if (ImGui::BeginPopupContextItem("##menu")) {
                if (ImGui::MenuItem(tr("Copy address", "Копировать адрес"), "Ctrl+C")) {
                    copy_address(line.address);
                }
                if (ImGui::MenuItem(tr("Copy bytes", "Копировать байты"), "Ctrl+B")) {
                    ImGui::SetClipboardText(line.bytes.c_str());
                    session_.set_notice(tr("Bytes copied", "Байты скопированы"), false);
                }
                if (ImGui::MenuItem(tr("Copy instruction", "Копировать инструкцию"), "Ctrl+T")) {
                    ImGui::SetClipboardText(line.text.c_str());
                    session_.set_notice(tr("Instruction copied", "Инструкция скопирована"), false);
                }
                if (ImGui::MenuItem(tr("Go to jump target", "Перейти к переходу"), "Enter", false, line.has_target)) {
                    disassemble_at(line.target_address);
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
            ui::text(format_address(line.address));
            ImGui::TableSetColumnIndex(1);
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + mono_offset);
            ui::text(line.bytes);
            ImGui::TableSetColumnIndex(2);
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + mono_offset);
            ui::text(line.text);
            ImGui::TableSetColumnIndex(3);
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + mono_offset);
            ui::text(line.target.empty() ? std::string_view("—") : std::string_view(line.target));
            ImGui::PopFont();
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
}

void View::draw_disasm_info(const DisasmLine& line, float value_x) {
    ui::heading(fonts_.heading, tr("INSTRUCTION", "ИНСТРУКЦИЯ"));
    ui::field(tr("Address", "Адрес"), format_address(line.address), value_x, fonts_.mono);
    ui::field(tr("Bytes", "Байты"), line.bytes, value_x, fonts_.mono);
    ui::field(tr("Size", "Размер"), plural(line.size, false, "byte", "bytes", "байт", "байта", "байт"), value_x);
    ui::field(tr("Instruction", "Инструкция"), line.text, value_x, fonts_.mono);
    if (!line.target.empty()) {
        ui::field(tr("Jump", "Переход"), line.target, value_x, fonts_.mono);
    } else if (line.has_target) {
        ui::field(tr("Jump", "Переход"), format_address(line.target_address), value_x, fonts_.mono);
    }
    ImGui::Spacing();
    if (!line.valid) {
        ui::muted_wrapped(tr("This byte could not be decoded as an instruction and is shown as «db». The disassembler continued from "
                             "the next byte.",
                             "Этот байт не удалось разобрать как инструкцию, он показан как «db». Дизассемблер продолжил со следующего байта."));
    } else if (line.has_target) {
        ui::muted_wrapped(tr("A jump or call. Enter or «Go to jump target» disassembles the code at the target address.",
                             "Переход или вызов. Enter или «Перейти к переходу» разбирает код по целевому адресу."));
    }
}

}  // namespace mh::gui
