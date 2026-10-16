#include <imgui.h>

#include <algorithm>
#include <array>
#include <cmath>

#include "common/error.hpp"
#include "common/text.hpp"
#include "gui/lang.hpp"
#include "gui/view.hpp"
#include "gui/view_internal.hpp"
#include "gui/widgets.hpp"
#include "process/privilege.hpp"

namespace mh::gui {

namespace {

constexpr std::array<FindingKind, kFindingKindCount> kKinds = {FindingKind::ExecPrivate, FindingKind::PeHeader, FindingKind::Rwx,
                                                               FindingKind::Patched, FindingKind::Hollowed};

const char* kind_label(FindingKind kind) {
    switch (kind) {
        case FindingKind::ExecPrivate: return tr("Outside modules", "Вне модулей");
        case FindingKind::PeHeader: return tr("PE header", "PE-заголовок");
        case FindingKind::Rwx: return "RWX";
        case FindingKind::Patched: return tr("Changed code", "Изменён код");
        case FindingKind::Hollowed: return tr("Replaced", "Подмена");
    }
    return "";
}

const char* kind_explanation(FindingKind kind) {
    switch (kind) {
        case FindingKind::ExecPrivate:
            return tr("Executable memory that belongs to no module (exe or dll). Injected code looks like this, but so do JIT "
                      "compilers: .NET, Java, JavaScript in browsers.",
                      "Исполняемая память, которая не принадлежит ни одному модулю (exe или dll). Так выглядит внедрённый код, но так же "
                      "работают JIT-компиляторы: .NET, Java, JavaScript в браузерах.");
        case FindingKind::PeHeader:
            return tr("A header of an exe or dll in ordinary memory rather than in a loaded module. A module loaded by hand, bypassing "
                      "the Windows loader, looks like this; some protections and packers do the same.",
                      "Заголовок exe или dll в обычной памяти, а не в загруженном модуле. Так выглядит модуль, загруженный вручную в обход "
                      "загрузчика Windows; так же делают некоторые защиты и упаковщики.");
        case FindingKind::Rwx:
            return tr("Memory that can be both written and executed. Ordinary programs almost never keep it so; it happens with JIT "
                      "compilers, packers, and injected code.",
                      "Память, в которую можно и писать, и исполнять её. Обычные программы так её почти не держат; бывает у "
                      "JIT-компиляторов, упаковщиков и внедрённого кода.");
        case FindingKind::Patched:
            return tr("A module's code in memory differs from its file on disk, relocations accounted for. Hooks look like this: "
                      "antiviruses, the Steam and Discord overlays, and browser sandboxes set them, and .NET edits its own code.",
                      "Код модуля в памяти отличается от его файла на диске с учётом перемещений. Так выглядят перехваты (hooks): их ставят "
                      "антивирусы, оверлеи Steam и Discord, песочницы браузеров, а .NET правит свой код сам.");
        case FindingKind::Hollowed:
            return tr("A module does not match its file: the file was deleted or replaced, the headers were wiped, or something else "
                      "sits where the program's main image should be. Process hollowing looks like this.",
                      "Модуль не совпадает со своим файлом: файл удалён или заменён, заголовки стёрты, или на месте главного образа "
                      "программы что-то другое. Так выглядит подмена процесса (process hollowing).");
    }
    return "";
}

// Long tooltips wrap instead of running across the window.
void wrapped_tooltip(const std::string& text, float scale) {
    if (ImGui::BeginItemTooltip()) {
        ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + 460.0f * scale);
        ImGui::TextUnformatted(text.c_str());
        ImGui::PopTextWrapPos();
        ImGui::EndTooltip();
    }
}

std::string kind_toggle(const FindingList& findings, FindingKind kind) {
    std::string label = kind_label(kind);
    if (findings.has_report()) {
        label += " " + group_digits(findings.report().count(kind));
    }
    return label + "###kind" + std::to_string(static_cast<int>(kind));
}

}  // namespace

bool View::set_debug_privilege(bool enabled) {
    try {
        if (enabled) {
            enable_debug_privilege();
        } else {
            disable_debug_privilege();
        }
        privilege_error_.clear();
    } catch (const Error& error) {
        privilege_error_ = error.code() == ErrorCode::AccessDenied
                               ? tr("Only an administrator has debug privilege. Run MemHunter as administrator and turn it on again.",
                                    "Права отладки есть только у администратора. Запустите MemHunter от имени администратора и включите их снова.")
                               : describe_error(error);
    }
    debug_privilege_ = debug_privilege_enabled();
    return debug_privilege_ == enabled;
}

void View::start_inspect() {
    if (session_.busy() || !alive_) {
        return;
    }
    ImGui::SetWindowFocus(nullptr);
    if (session_.start_inspect()) {
        page_ = Page::Inspect;
        scroll_to_selection_ = true;
    }
}

void View::handle_inspect_shortcuts(bool copy) {
    FindingList& findings = session_.findings();
    scroll_to_selection_ |= navigate(findings, page_rows_);
    if (const Finding* finding = findings.selected(); copy && finding != nullptr) {
        copy_address(finding->address);
    }
}

void View::draw_inspect_progress(const Job* running) {
    const FindingList& findings = session_.findings();
    if (running != nullptr) {
        ui::progress_bar(0.0f, std::string(running->cancel_requested() ? tr("Stopping…", "Остановка…") : tr("Checking memory", "Проверка памяти")) + "   " +
                                   format_seconds(running->elapsed_seconds()));
        ui::muted(tr("Module code is compared with its files on disk, memory with the module map.",
                     "Код модулей сравнивается с их файлами на диске, память — с картой модулей."));
        return;
    }
    if (!findings.has_report()) {
        ui::progress_bar(0.0f, tr("Waiting", "Ожидание"));
        ui::muted(tr("Press «Check» or F5 to look for injected code and changes in modules.",
                     "Нажмите «Проверить» или F5, чтобы поискать внедрённый код и изменения в модулях."));
        return;
    }
    const InspectReport& report = findings.report();
    ui::progress_bar(1.0f, report.complete ? tr("Done", "Готово") : tr("Stopped", "Остановлено"));
    const std::initializer_list<std::pair<const char*, std::string>> parts = {
        {tr("Findings", "Находок"), group_digits(report.findings.size())},
        {tr("Modules", "Модулей"), group_digits(report.stats.modules)},
        {tr("Code compared", "Сравнено кода"), format_size(report.stats.code_bytes)},
        {tr("Unchanged", "Без изменений"), format_size(report.stats.shared_bytes)}};
    bool first = true;
    for (const auto& [label, value] : parts) {
        if (!first) {
            ImGui::SameLine(0.0f, 24.0f * scale_);
        }
        first = false;
        ui::muted(label);
        ImGui::SameLine();
        ui::text(value);
        if (std::string_view(label) == tr("Unchanged", "Без изменений")) {
            ImGui::SetItemTooltip("%s", tr("Code pages Windows still shares with the module's file: nobody wrote to them, and they "
                                           "need not be compared",
                                           "Страницы кода, которые Windows по-прежнему делит с файлом модуля: в них никто не писал, и их "
                                           "не нужно сравнивать"));
        }
    }
    if (!report.warnings.empty()) {
        ImGui::SameLine(0.0f, 24.0f * scale_);
        ui::muted(tr("Warnings", "Предупреждений"));
        ImGui::SameLine();
        inverted_text(std::to_string(report.warnings.size()));
        std::string all;
        for (const std::string& warning : report.warnings) {
            all += (all.empty() ? "" : "\n") + warning;
        }
        wrapped_tooltip(all, scale_);
    }
}

float View::inspect_bar_width() const {
    float width = button_width(tr("Check", "Проверить")) + 20.0f * scale_;
    for (const FindingKind kind : kKinds) {
        width += button_width(kind_toggle(session_.findings(), kind).c_str());
    }
    return width + ImGui::GetStyle().ItemSpacing.x * static_cast<float>(kKinds.size() - 1);
}

void View::draw_inspect_bar(float right_edge) {
    FindingList& findings = session_.findings();
    if (ui::button(tr("Check", "Проверить"), session_.job() == nullptr && alive_)) {
        start_inspect();
    }
    ImGui::SetItemTooltip("%s", tr("Find injected code and changes in modules. MemHunter only reads memory.  F5",
                                   "Найти внедрённый код и изменения в модулях. MemHunter только читает память.  F5"));
    bool first = true;
    for (const FindingKind kind : kKinds) {
        const std::string label = kind_toggle(findings, kind);
        const float width = button_width(label.c_str());
        ImGui::SameLine(0.0f, first ? 20.0f * scale_ : -1.0f);
        if (ImGui::GetCursorPosX() + width > right_edge) {
            ImGui::NewLine();
        }
        first = false;
        if (ui::segment(label.c_str(), findings.shows(kind))) {
            findings.toggle(kind);
            scroll_to_selection_ = true;
        }
        wrapped_tooltip(std::string(kind_explanation(kind)) + tr("\n\nA click hides or shows this kind.", "\n\nЩелчок прячет или показывает этот вид."), scale_);
    }
}

void View::draw_inspect_table(float height) {
    FindingList& findings = session_.findings();
    if (findings.rows().empty()) {
        ImGui::BeginChild("##no_findings", ImVec2(0, height), ImGuiChildFlags_Borders, kPanel);
        const Job* job = session_.job();
        if (job != nullptr && job->kind() == JobKind::Inspect) {
            ui::muted(tr("Checking…", "Идёт проверка…"));
        } else if (!findings.has_report()) {
            ui::muted_wrapped(tr("Here will be findings: executable memory outside modules, PE headers in ordinary memory, RWX memory, "
                                 "changed module code, and replaced modules. Press «Check» or F5.",
                                 "Здесь будут находки: исполняемая память вне модулей, PE-заголовки в обычной памяти, память RWX, "
                                 "изменённый код модулей и подменённые модули. Нажмите «Проверить» или F5."));
            ImGui::Spacing();
            ui::muted_wrapped(tr("Other users' processes and services open with the «Debug privilege» mark in the process picker, if "
                                 "MemHunter is run as administrator.",
                                 "Чужие процессы и службы открываются с отметкой «Права отладки» в окне выбора процесса, если "
                                 "MemHunter запущен от имени администратора."));
        } else if (findings.report().findings.empty()) {
            ui::text(tr("Nothing suspicious found.", "Ничего подозрительного не найдено."));
        } else {
            ui::muted(tr("All findings are hidden: turn on their kinds above the table.", "Все находки скрыты: включите их виды над таблицей."));
        }
        ImGui::EndChild();
        return;
    }

    const std::span<const std::size_t> rows = findings.rows();
    const std::optional<std::size_t> selected = findings.selected_row();
    const ImGuiStyle& style = ImGui::GetStyle();
    const float ui_line = ImGui::GetTextLineHeight();
    const float mono_line = fonts_.mono->FontSize;
    const float row_height = std::max(ui_line, mono_line);
    const float ui_offset = std::floor((row_height - ui_line) * 0.5f);
    const float mono_offset = std::floor((row_height - mono_line) * 0.5f);
    page_rows_ = std::max(1, static_cast<int>(height / (row_height + style.CellPadding.y * 2.0f)) - 2);

    constexpr ImGuiTableFlags flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersInnerV |
                                      ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingFixedFit;
    if (!ImGui::BeginTable("##findings", 5, flags, ImVec2(0, height))) {
        return;
    }
    ImGui::TableSetupColumn(tr("Address", "Адрес"), 0, font_text_width(fonts_.mono, "0x0000000000000000"));
    ImGui::TableSetupColumn(tr("Size", "Размер"), 0, ImGui::CalcTextSize("1023.99 KiB").x);
    ImGui::TableSetupColumn(tr("Kind", "Вид"), 0, ImGui::CalcTextSize("PE-заголовок").x);
    ImGui::TableSetupColumn(tr("Where", "Где"), ImGuiTableColumnFlags_WidthStretch, 1.0f);
    ImGui::TableSetupColumn(tr("Details", "Подробности"), ImGuiTableColumnFlags_WidthStretch, 2.4f);
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableHeadersRow();

    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(rows.size()), row_height + style.CellPadding.y * 2.0f);
    if (selected) {
        clipper.IncludeItemByIndex(static_cast<int>(*selected));
    }
    while (clipper.Step()) {
        for (auto index = static_cast<std::size_t>(clipper.DisplayStart); index < static_cast<std::size_t>(clipper.DisplayEnd); ++index) {
            const Finding& finding = findings.finding(index);
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
                findings.select_row(index);
            }
            if (ImGui::BeginPopupContextItem("##menu")) {
                if (ImGui::MenuItem(tr("Copy address", "Копировать адрес"), "Ctrl+C")) {
                    copy_address(finding.address);
                }
                if (ImGui::MenuItem(tr("Copy details", "Копировать подробности"))) {
                    ImGui::SetClipboardText(finding.details.c_str());
                    session_.set_notice(tr("Details copied", "Подробности скопированы"), false);
                }
                if (ImGui::MenuItem(tr("Disassemble", "Дизассемблировать"))) {
                    disassemble_at(finding.address);
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
            ui::text(format_address(finding.address));
            ImGui::PopFont();
            ImGui::TableSetColumnIndex(1);
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + ui_offset);
            ui::text(finding.size == 0 ? std::string("—") : format_size(finding.size));
            ImGui::TableSetColumnIndex(2);
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + ui_offset);
            ui::text(kind_label(finding.kind));
            ImGui::TableSetColumnIndex(3);
            ImGui::PushFont(fonts_.mono);
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + mono_offset);
            ui::text(finding.where.empty() ? std::string_view("—") : std::string_view(finding.where));
            ImGui::PopFont();
            ImGui::TableSetColumnIndex(4);
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + ui_offset);
            ui::text(finding.details);
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

void View::draw_finding_info(const Finding& finding, float value_x) {
    ui::heading(fonts_.heading, tr("FINDING", "НАХОДКА"));
    ui::field(tr("Address", "Адрес"), format_address(finding.address), value_x, fonts_.mono);
    ui::field(tr("Size", "Размер"), finding.size == 0 ? std::string("—") : format_size(finding.size), value_x);
    ui::field(tr("Kind", "Вид"), std::string(kind_label(finding.kind)) + "   " + std::string(to_string(finding.kind)), value_x);
    ui::field(tr("Where", "Где"), finding.where.empty() ? std::string_view("—") : std::string_view(finding.where), value_x, fonts_.mono);
    ui::field(tr("Details", "Подробности"), finding.details, value_x);
    ImGui::Spacing();
    ui::muted_wrapped(kind_explanation(finding.kind));
}

}  // namespace mh::gui
