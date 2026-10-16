#include "gui/view.hpp"

#include <imgui.h>
#include <imgui_internal.h>
#include <misc/cpp/imgui_stdlib.h>

#include <algorithm>
#include <array>
#include <cfloat>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <span>
#include <string_view>

#include "common/error.hpp"
#include "common/text.hpp"
#include "gui/lang.hpp"
#include "gui/process_picker.hpp"
#include "gui/view_internal.hpp"
#include "gui/widgets.hpp"
#include "process/privilege.hpp"

namespace mh::gui {

namespace {

constexpr std::size_t kDumpRow = 16;
constexpr std::size_t kDumpRows = 10;
constexpr std::uint64_t kDumpLead = 32;
// Columns of a dump line: 12 address digits, 16 bytes as "XX " with a gap after the eighth, 16 characters.
constexpr float kDumpHexColumn = 14.0f;
constexpr float kDumpTextColumn = kDumpHexColumn + 49.0f + 2.0f;
constexpr float kDumpChars = kDumpTextColumn + 16.0f;

double ratio(std::uint64_t done, std::uint64_t total) {
    return total == 0 ? 0.0 : std::min(1.0, static_cast<double>(done) / static_cast<double>(total));
}

std::string percent(double fraction) {
    std::array<char, 16> buffer{};
    std::snprintf(buffer.data(), buffer.size(), "%.0f%%", fraction * 100.0);
    return buffer.data();
}

std::string dump_address(std::uint64_t address) {
    std::array<char, 24> buffer{};
    std::snprintf(buffer.data(), buffer.size(), "%012llX", static_cast<unsigned long long>(address));
    return buffer.data();
}

std::string signed_offset(std::uint64_t address, std::uint64_t base) {
    return address >= base ? "+" + format_hex(address - base) : "-" + format_hex(base - address);
}

bool contains_lower(std::string_view haystack, std::string_view lower_needle) {
    return to_lower_ascii(haystack).find(lower_needle) != std::string::npos;
}

const char* job_label(const Job& job) {
    if (job.cancel_requested()) {
        return tr("Stopping…", "Остановка…");
    }
    switch (job.kind()) {
        case JobKind::Remember: return tr("Remembering memory", "Запоминание памяти");
        case JobKind::ChangedScan:
            return job.progress().stage.load(std::memory_order_relaxed) == JobStage::Hashing
                       ? tr("Comparing with the remembered memory", "Сравнение с запомненной памятью")
                       : tr("Searching the changed memory", "Поиск в изменившейся памяти");
        case JobKind::Scan: return tr("Searching", "Поиск");
        case JobKind::ValueScan: return tr("Searching for values", "Поиск значений");
        case JobKind::PointerScan: return tr("Searching for pointers", "Поиск указателей");
        case JobKind::PointerCheck: return tr("Checking the chains", "Проверка цепочек");
        case JobKind::Inspect: return tr("Checking memory", "Проверка памяти");
    }
    return "";
}

// "Label value" pairs on one line.
void progress_line(std::initializer_list<std::pair<const char*, std::string>> parts, float scale) {
    bool first = true;
    for (const auto& [label, value] : parts) {
        if (!first) {
            ImGui::SameLine(0.0f, 24.0f * scale);
        }
        first = false;
        ui::muted(label);
        ImGui::SameLine();
        ui::text(value);
    }
}

const char* compare_hint(Compare compare) {
    switch (compare) {
        case Compare::Unknown:
            return tr("Remembers every value of the chosen type. Then change the value in the program and pick how it changed.",
                      "Запомнит все значения выбранного типа. Потом измените значение в программе и выберите, как оно изменилось.");
        case Compare::Increased: return tr("Keeps the addresses where the value grew since the last search.", "Останутся адреса, где значение стало больше, чем при прошлом поиске.");
        case Compare::Decreased: return tr("Keeps the addresses where the value shrank since the last search.", "Останутся адреса, где значение стало меньше, чем при прошлом поиске.");
        case Compare::Changed: return tr("Keeps the addresses where the value changed since the last search.", "Останутся адреса, где значение изменилось с прошлого поиска.");
        case Compare::Unchanged: return tr("Keeps the addresses where the value did not change since the last search.", "Останутся адреса, где значение не менялось с прошлого поиска.");
        default: return "";
    }
}

// A float bound with one digit more than the typed number has, so that "100" shows 99.5 to 100.5.
std::string float_bound(double value, double tolerance) {
    const int decimals = std::clamp(static_cast<int>(std::lround(-std::log10(tolerance * 2.0))) + 1, 1, 17);
    std::array<char, 64> buffer{};
    std::snprintf(buffer.data(), buffer.size(), "%.*f", decimals, value);
    return buffer.data();
}

std::string match_bytes_hex(const ResultSet& results, const Match& match) {
    const auto bytes = results.preview(match);
    return hex_preview(bytes.first(std::min<std::size_t>(bytes.size(), match.length)));
}

std::string match_text(const ResultSet& results, const Match& match) {
    const auto bytes = results.preview(match);
    const auto taken = bytes.first(std::min<std::size_t>(bytes.size(), match.length));
    return is_utf16_kind(results.patterns[match.pattern].kind) ? utf16_preview(taken) : ascii_preview(taken);
}

// Wider than the panel when the columns don't fit, so the table scrolls sideways instead of squeezing them.
float table_inner_width(std::span<const float> widths) {
    float width = 0.0f;
    for (const float column : widths) {
        width += column + ImGui::GetStyle().CellPadding.x * 2.0f + 1.0f;
    }
    return std::max(ImGui::GetContentRegionAvail().x, width);
}

}  // namespace

float button_width(const char* label) {
    return ImGui::CalcTextSize(label, nullptr, true).x + ImGui::GetStyle().FramePadding.x * 2.0f;
}

float buttons_width(std::initializer_list<const char*> labels) {
    float width = ImGui::GetStyle().ItemSpacing.x * static_cast<float>(labels.size() - 1);
    for (const char* label : labels) {
        width += button_width(label);
    }
    return width;
}

float font_text_width(ImFont* font, std::string_view text) {
    return font->CalcTextSizeA(font->FontSize, FLT_MAX, 0.0f, text.data(), text.data() + text.size()).x;
}

void inverted_text(std::string_view text) {
    const ImGuiStyle& style = ImGui::GetStyle();
    const char* begin = text.data();
    const char* end = begin + text.size();
    const ImVec2 size = ImGui::CalcTextSize(begin, end);
    const ImVec2 cursor = ImGui::GetCursorScreenPos();
    const ImVec2 min(cursor.x, cursor.y + ImGui::GetCurrentWindow()->DC.CurrLineTextBaseOffset);
    const float pad = std::floor(style.FramePadding.x * 0.5f);
    ImGui::Dummy(ImVec2(size.x + pad * 2.0f, size.y));
    ImDrawList* draw = ImGui::GetWindowDrawList();
    draw->AddRectFilled(ImVec2(min.x, min.y), ImVec2(min.x + size.x + pad * 2.0f, min.y + size.y), theme::kWhite);
    draw->AddText(ImVec2(min.x + pad, min.y), theme::kBlack, begin, end);
}

View::View(Session& session, Platform& platform, const theme::Fonts& fonts) : session_(session), platform_(platform), fonts_(fonts) {}

void View::open_from_command_line(const std::string& pid_or_name) {
    std::uint32_t pid = 0;
    try {
        pid = resolve_process(pid_or_name);
    } catch (const Error& error) {
        show_picker();
        if (error.code() == ErrorCode::ProcessNotFound) {
            picker_error_ = tr("The process «", "Процесс «") + pid_or_name + tr("» was not found. Pick it from the list.", "» не найден. Выберите его в списке.");
        } else if (pid_or_name.find_first_not_of("0123456789") == std::string::npos) {
            picker_error_ = "«" + pid_or_name + tr("» is not a valid PID. Pick a process from the list.", "» — неверный PID. Выберите процесс в списке.");
        } else {
            picker_error_ = tr("There is more than one process named «", "Процессов с именем «") + pid_or_name + tr("». Pick the right one from the list.", "» несколько. Выберите нужный в списке.");
            process_filter_ = pid_or_name;
        }
        return;
    }
    if (!attach(pid)) {
        const std::string error = picker_error_;
        show_picker();
        picker_error_ = error;
    }
}

void View::show_picker() {
    picker_requested_ = true;
    picker_focus_ = true;
    picker_error_.clear();
    debug_privilege_ = debug_privilege_enabled();
    process_filter_.clear();
    picked_pid_.reset();
    if (const Target* target = session_.target()) {
        picked_pid_ = target->summary().pid;
    }
    refresh_processes();
}

bool View::attach(std::uint32_t pid) {
    try {
        session_.attach(open_process(pid));
    } catch (const Error& error) {
        picker_error_ = describe_error(error);
        return false;
    }
    regions_.clear();
    region_rows_.clear();
    regions_loaded_ = false;
    dump_ = {};
    dump_match_.reset();
    values_time_ = {};
    editing_row_.reset();
    filter_.clear();
    only_changed_ = false;
    pointers_time_ = {};
    // After a restart the chains are checked on their page, and a structure at a chain is found again, so the page
    // stays open.
    const bool keep = (page_ == Page::Pointers && session_.pointers().has_chains()) ||
                      (page_ == Page::Structure && session_.structure().active()) || page_ == Page::Inspect;
    if (!keep) {
        page_ = Page::Results;
    }
    focus_search_ = true;
    return true;
}

unsigned View::frame_interval_ms() const {
    if (session_.busy()) {
        return 33;
    }
    if (page_ == Page::Results) {
        // The current values in the table are reread twice a second.
        if (value_mode() ? !session_.values().rows().empty() : live_dump_ && session_.table().selected_match() != nullptr) {
            return 250;
        }
    }
    if (page_ == Page::Watch && !session_.watch().empty()) {
        return 250;
    }
    if (page_ == Page::Pointers && session_.pointers().has_chains()) {
        return 250;
    }
    if (page_ == Page::Structure && session_.structure().active()) {
        return 250;
    }
    if (page_ == Page::Inspect && live_dump_ && session_.findings().selected() != nullptr) {
        return 250;
    }
    return 1000;
}

void View::start_scan() {
    if (session_.busy() || !alive_) {
        return;
    }
    // Leaves the text field, so that Esc stops the search instead of undoing the typing.
    ImGui::SetWindowFocus(nullptr);
    const bool started =
        value_mode() ? session_.start_value_scan(form_) : session_.start_scan(form_, only_changed_ && session_.baseline().has_value());
    if (started) {
        page_ = Page::Results;
        scroll_to_selection_ = true;
    }
}

bool View::can_export() const {
    if (session_.target() == nullptr) {
        return false;
    }
    if (page_ == Page::Watch) {
        return !session_.watch().empty();
    }
    // Chains and structures are saved by their own buttons, in files MemHunter can load back.
    if (page_ == Page::Pointers || page_ == Page::Structure || page_ == Page::Inspect || page_ == Page::Disasm || session_.busy()) {
        return false;
    }
    return value_mode() ? !session_.values().rows().empty() : session_.table().has_results();
}

void View::export_results() {
    if (!can_export()) {
        return;
    }
    const ProcessSummary& process = session_.target()->summary();
    const bool watch = page_ == Page::Watch;
    try {
        const auto path = platform_.ask_save_path(L"memhunter-" + std::to_wstring(process.pid) +
                                                      (watch ? L"-addresses.json" : value_mode() ? L"-values.json" : L".json"),
                                                  FileKind::Export);
        if (!path) {
            return;
        }
        std::string saved;
        if (watch) {
            export_watch(*path, process, session_.watch(), session_.target()->memory());
            saved = count_addresses(session_.watch().rows().size());
        } else if (value_mode()) {
            export_values(*path, process, session_.values());
            saved = count_addresses(session_.values().rows().size());
        } else {
            const ResultsTable& table = session_.table();
            export_rows(*path, table.results(), table.rows());
            saved = count_matches(table.rows().size());
        }
        session_.set_notice(tr("Saved ", "Сохранено ") + saved + tr(" to ", " в ") + wide_to_utf8(path->wstring()), false);
    } catch (const Error& error) {
        session_.set_notice(describe_error(error), true);
    }
}

void View::copy_address(std::uint64_t address) {
    const std::string text = format_address(address);
    ImGui::SetClipboardText(text.c_str());
    session_.set_notice(tr("Address copied: ", "Адрес скопирован: ") + text, false);
}

void View::update_title() {
    std::string title = "MemHunter";
    if (const Target* target = session_.target()) {
        title += " — " + target->summary().name + " (PID " + std::to_string(target->summary().pid) + ")";
    }
    if (title != title_) {
        title_ = title;
        platform_.set_title(title_);
    }
}

void View::handle_shortcuts() {
    if (ImGui::IsPopupOpen("", ImGuiPopupFlags_AnyPopupId)) {
        return;
    }
    const ImGuiIO& io = ImGui::GetIO();
    if (ImGui::IsKeyPressed(ImGuiKey_F5, false)) {
        if (page_ == Page::Inspect) {
            start_inspect();
        } else if (page_ == Page::Disasm) {
            run_disasm();
        } else {
            start_scan();
        }
    }
    if (ImGui::IsKeyPressed(ImGuiKey_Escape, false) && session_.busy()) {
        session_.cancel();
    }
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_O, ImGuiInputFlags_RouteGlobal)) {
        show_picker();
    }
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_S, ImGuiInputFlags_RouteGlobal)) {
        if (page_ == Page::Pointers) {
            save_pointers();
        } else if (page_ == Page::Structure) {
            save_structure();
        } else {
            export_results();
        }
    }
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiKey_F, ImGuiInputFlags_RouteGlobal) && session_.target() != nullptr && !value_mode()) {
        page_ = Page::Results;
        focus_filter_ = true;
    }
    if (io.WantTextInput) {
        return;
    }
    const bool copy = ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_C);
    if (ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_D) && page_ != Page::Regions && page_ != Page::Structure &&
        page_ != Page::Inspect && page_ != Page::Disasm) {
        open_struct_from_selection();
        return;
    }
    if (page_ == Page::Structure) {
        handle_struct_shortcuts(copy);
        return;
    }
    if (page_ == Page::Inspect) {
        handle_inspect_shortcuts(copy);
        return;
    }
    if (page_ == Page::Disasm) {
        handle_disasm_shortcuts(copy);
        return;
    }
    if (value_mode()) {
        const ValueHistory& history = session_.history();
        if (ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_Z) && history.can_undo()) {
            scroll_to_selection_ |= session_.go_to_scan(history.current() - 1);
        } else if (ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_Y) && history.can_redo()) {
            scroll_to_selection_ |= session_.go_to_scan(history.current() + 1);
        }
    }
    if (page_ == Page::Watch) {
        handle_watch_shortcuts(copy);
        return;
    }
    if (page_ == Page::Pointers) {
        handle_pointer_shortcuts(copy);
        return;
    }
    if (page_ != Page::Results) {
        return;
    }
    if (ImGui::IsKeyPressed(ImGuiKey_Insert, false)) {
        if (const auto entry = selected_as_watch()) {
            session_.add_watch(*entry);
        }
    }
    if (value_mode()) {
        ValueTable& values = session_.values();
        scroll_to_selection_ |= navigate(values, page_rows_);
        if (copy && values.selected() != nullptr) {
            copy_address(values.selected()->address);
        }
    } else {
        ResultsTable& table = session_.table();
        scroll_to_selection_ |= navigate(table, page_rows_);
        if (copy && table.selected_match() != nullptr) {
            copy_address(table.selected_match()->address);
        }
    }
}

void View::draw() {
    session_.poll();
    alive_ = session_.target_alive();
    update_title();

    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    constexpr ImGuiWindowFlags main_flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings |
                                            ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoScrollWithMouse;
    ImGui::Begin("##main", nullptr, main_flags);
    ImGui::PopStyleVar();

    handle_shortcuts();
    if (picker_requested_) {
        ImGui::OpenPopup("##picker");
        picker_requested_ = false;
    }
    if (add_watch_requested_) {
        ImGui::OpenPopup("##add_watch");
        add_watch_requested_ = false;
    }
    if (clear_watch_requested_) {
        ImGui::OpenPopup("##clear_watch");
        clear_watch_requested_ = false;
    }
    if (pointer_scan_requested_) {
        ImGui::OpenPopup("##pointer_scan");
        pointer_scan_requested_ = false;
    }
    if (pointer_check_requested_) {
        ImGui::OpenPopup("##pointer_check");
        pointer_check_requested_ = false;
    }
    if (clear_pointers_requested_) {
        ImGui::OpenPopup("##clear_pointers");
        clear_pointers_requested_ = false;
    }
    if (struct_open_requested_) {
        ImGui::OpenPopup("##struct_open");
        struct_open_requested_ = false;
    }
    if (struct_field_requested_) {
        ImGui::OpenPopup("##struct_field");
        struct_field_requested_ = false;
    }
    if (struct_instance_requested_) {
        ImGui::OpenPopup("##struct_instance");
        struct_instance_requested_ = false;
    }

    draw_top_bar();

    const ImGuiStyle& style = ImGui::GetStyle();
    const float status_height = ImGui::GetTextLineHeight() + style.ItemSpacing.y * 2.0f + 1.0f;
    const float body_height = std::max(ImGui::GetContentRegionAvail().y - status_height, 100.0f);
    draw_search_panel(std::floor(330.0f * scale_), body_height);
    ImGui::SameLine();
    ImGui::BeginChild("##right", ImVec2(0, body_height), ImGuiChildFlags_None, kPanel | ImGuiWindowFlags_NoScrollbar);
    if (session_.target() == nullptr) {
        draw_no_process(ImGui::GetContentRegionAvail().y);
    } else {
        draw_progress_panel();
        draw_page_switch();
        if (page_ != Page::Watch) {
            editing_row_.reset();
        }
        const float rest = ImGui::GetContentRegionAvail().y;
        if (page_ == Page::Regions) {
            draw_regions(rest);
        } else {
            draw_results(rest);
        }
    }
    ImGui::EndChild();

    draw_status_bar();
    draw_picker();
    draw_add_watch();
    draw_clear_watch();
    draw_pointer_scan();
    draw_pointer_check();
    draw_clear_pointers();
    draw_struct_open();
    draw_struct_field();
    draw_struct_instance();
    ImGui::End();
}

void View::draw_top_bar() {
    const ImGuiStyle& style = ImGui::GetStyle();
    const float right_edge = ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x;
    ImGui::AlignTextToFramePadding();
    ImGui::PushFont(fonts_.heading);
    ImGui::TextUnformatted("MemHunter");
    ImGui::PopFont();
    ImGui::SameLine(0.0f, 28.0f * scale_);

    if (const Target* target = session_.target()) {
        const ProcessSummary& process = target->summary();
        ImGui::AlignTextToFramePadding();
        ui::text(process.name);
        if (!process.path.empty()) {
            ImGui::SetItemTooltip("%s", process.path.c_str());
        }
        ImGui::SameLine();
        ui::muted("PID " + std::to_string(process.pid) + (process.wow64 ? tr("   32-bit", "   32-бит") : tr("   64-bit", "   64-бит")));
        ImGui::SameLine(0.0f, 28.0f * scale_);
        ui::muted(tr("State", "Состояние"));
        ImGui::SameLine();
        if (const Job* job = session_.job()) {
            ui::text(job_label(*job));
        } else if (!alive_) {
            inverted_text(tr("Process ended", "Процесс завершён"));
        } else {
            ui::text(tr("Ready", "Готово"));
        }
    } else {
        ImGui::AlignTextToFramePadding();
        ui::muted(tr("No process selected", "Процесс не выбран"));
    }

    const char* open_label = tr("Select process", "Выбрать процесс");
    const char* export_label = tr("Export", "Экспорт");
    const float lang_segment = std::floor(34.0f * scale_);
    const float buttons = lang_segment * 2.0f + style.ItemSpacing.x + button_width(open_label) + style.ItemSpacing.x + button_width(export_label);
    ImGui::SameLine(std::max(right_edge - buttons, ImGui::GetCursorPosX()));
    if (ui::segment("EN", current_language() == Lang::English, true, ImVec2(lang_segment, 0.0f)) && current_language() != Lang::English) {
        set_language(Lang::English);
        session_.clear_notice();  // the shown notice was built in the other language
    }
    ImGui::SameLine(0.0f, 0.0f);
    if (ui::segment("RU", current_language() == Lang::Russian, true, ImVec2(lang_segment, 0.0f)) && current_language() != Lang::Russian) {
        set_language(Lang::Russian);
        session_.clear_notice();  // the shown notice was built in the other language
    }
    ImGui::SetItemTooltip("%s", tr("Interface language", "Язык интерфейса"));
    ImGui::SameLine();
    if (ui::button(open_label)) {
        show_picker();
    }
    ImGui::SetItemTooltip("Ctrl+O");
    ImGui::SameLine();
    if (ui::button(export_label, can_export())) {
        export_results();
    }
    ImGui::SetItemTooltip("%s", tr("Save the shown rows as JSON, CSV or text.  Ctrl+S", "Сохранить показанные строки в JSON, CSV или текст.  Ctrl+S"));
    ImGui::Separator();
}

void View::draw_search_panel(float width, float height) {
    ImGui::BeginChild("##search", ImVec2(width, height), ImGuiChildFlags_Borders, kPanel);
    ui::heading(fonts_.heading, tr("SEARCH", "ПОИСК"));
    const bool enabled = !session_.busy();
    ui::segments(form_.mode, {{SearchMode::Text, tr("Text", "Текст")}, {SearchMode::Bytes, tr("Bytes", "Байты")}, {SearchMode::Number, tr("Number", "Число")},
                              {SearchMode::Strings, tr("Strings", "Строки")}},
                 enabled);
    ImGui::Spacing();
    if (!enabled) {
        ImGui::BeginDisabled();
    }
    draw_search_inputs();
    if (!enabled) {
        ImGui::EndDisabled();
    }
    ImGui::Spacing();
    draw_scan_button();

    const Notice& notice = session_.notice();
    if (!notice.text.empty()) {
        ImGui::Spacing();
        if (notice.error) {
            ui::inverted_block(notice.text);
        } else {
            ImGui::PushTextWrapPos(0.0f);
            ui::text(notice.text);
            ImGui::PopTextWrapPos();
        }
    }

    if (!enabled) {
        ImGui::BeginDisabled();
    }
    if (value_mode()) {
        draw_value_history();
        // A next scan rechecks the candidates of the first one, wherever they are.
        const bool fixed = session_.values().has_values();
        if (fixed) {
            ImGui::BeginDisabled();
        }
        draw_memory_options();
        if (fixed) {
            ImGui::EndDisabled();
        }
    } else {
        draw_memory_options();
        draw_compare_options();
    }
    draw_parameters();
    if (!enabled) {
        ImGui::EndDisabled();
    }
    ImGui::EndChild();
}

void View::draw_search_inputs() {
    const auto focus_here = [&] {
        if (focus_search_) {
            ImGui::SetKeyboardFocusHere();
            focus_search_ = false;
        }
    };
    constexpr ImGuiInputTextFlags enter = ImGuiInputTextFlags_EnterReturnsTrue;
    ImGui::PushItemWidth(-1.0f);
    switch (form_.mode) {
        case SearchMode::Text:
            focus_here();
            if (ImGui::InputTextWithHint("##text", tr("Text, for example Stalker", "Текст, например Stalker"), &form_.text, enter)) {
                start_scan();
            }
            ui::segments(form_.text_encoding,
                         {{TextEncoding::Both, tr("ASCII and UTF-16", "ASCII и UTF-16")}, {TextEncoding::Ascii, "ASCII"}, {TextEncoding::Utf16, "UTF-16"}});
            ImGui::Checkbox(tr("Case-insensitive", "Без учёта регистра"), &form_.ignore_case);
            ui::muted_wrapped(tr("Windows programs usually store text in UTF-16, while older and cross-platform ones use ASCII.",
                                 "Программы Windows обычно хранят текст в UTF-16, а старые и кроссплатформенные — в ASCII."));
            break;
        case SearchMode::Bytes:
            focus_here();
            ImGui::InputTextMultiline("##signatures", &form_.signatures, ImVec2(-1.0f, ImGui::GetTextLineHeight() * 5.0f));
            ui::muted_wrapped(tr("One signature per line: 48 8B ?? 89, where ?? is any byte. A name is given like this: money=98 3A 00 00",
                                 "По одной сигнатуре в строке: 48 8B ?? 89, где ?? — любой байт. Имя задаётся так: деньги=98 3A 00 00"));
            break;
        case SearchMode::Number: draw_value_inputs(); break;
        case SearchMode::Strings: {
            ImGui::AlignTextToFramePadding();
            ui::muted(tr("Min. length", "Мин. длина"));
            ImGui::SameLine();
            focus_here();
            ImGui::InputScalar("##min_length", ImGuiDataType_U32, &form_.min_length);
            ui::segments(form_.strings_encoding,
                         {{TextEncoding::Both, tr("ASCII and UTF-16", "ASCII и UTF-16")}, {TextEncoding::Ascii, "ASCII"}, {TextEncoding::Utf16, "UTF-16"}});
            ui::muted_wrapped(tr("Finds every readable string in memory. Handy when you are not sure what to search for.",
                                 "Находит все читаемые строки в памяти. Удобно, когда не знаете точно, что искать."));
            break;
        }
    }
    ImGui::PopItemWidth();
}

void View::draw_value_inputs() {
    const ValueTable& values = session_.values();
    const bool next = values.has_values();
    if (next && form_.compare == Compare::Unknown) {
        form_.compare = Compare::Changed;
    } else if (!next && needs_previous(form_.compare)) {
        form_.compare = Compare::Exact;
    }
    ui::segments(form_.compare,
                 {{Compare::Exact, tr("Equal", "Равно")}, {Compare::Greater, tr("Greater", "Больше")}, {Compare::Less, tr("Less", "Меньше")}, {Compare::Between, tr("Between", "Между")}});
    if (next) {
        ui::segments(form_.compare, {{Compare::Increased, tr("Increased", "Увеличилось")}, {Compare::Decreased, tr("Decreased", "Уменьшилось")}});
        ui::segments(form_.compare, {{Compare::Changed, tr("Changed", "Изменилось")}, {Compare::Unchanged, tr("Unchanged", "Не изменилось")}});
    } else {
        ui::segments(form_.compare, {{Compare::Unknown, tr("Unknown initial value", "Неизвестное начальное значение")}});
    }

    constexpr ImGuiInputTextFlags enter = ImGuiInputTextFlags_EnterReturnsTrue;
    const auto focus_here = [&] {
        if (focus_search_) {
            ImGui::SetKeyboardFocusHere();
            focus_search_ = false;
        }
    };
    if (form_.compare == Compare::Between) {
        const float spacing = ImGui::GetStyle().ItemSpacing.x;
        ImGui::SetNextItemWidth(std::floor((ImGui::GetContentRegionAvail().x - spacing) * 0.5f));
        focus_here();
        bool submit = ImGui::InputTextWithHint("##number", tr("from", "от"), &form_.number, enter);
        ImGui::SameLine(0.0f, spacing);
        ImGui::SetNextItemWidth(-1.0f);
        submit |= ImGui::InputTextWithHint("##number_high", tr("to", "до"), &form_.number_high, enter);
        if (submit) {
            start_scan();
        }
    } else if (takes_number(form_.compare)) {
        focus_here();
        const char* hint = next && form_.compare == Compare::Exact ? tr("The value now", "Значение сейчас") : tr("A number, for example 15000 or 0x3A98", "Число, например 15000 или 0x3A98");
        if (ImGui::InputTextWithHint("##number", hint, &form_.number, enter)) {
            start_scan();
        }
    } else {
        focus_search_ = false;
        ui::muted_wrapped(compare_hint(form_.compare));
    }

    const NumberType type = next ? values.candidates()->type : form_.number_type;
    if (next) {
        ImGui::BeginDisabled();
    }
    NumberType shown = type;
    ui::segments(shown, {{NumberType::Int8, "int8"}, {NumberType::Int16, "int16"}, {NumberType::Int32, "int32"}, {NumberType::Int64, "int64"}});
    ui::segments(shown, {{NumberType::Float, "float"}, {NumberType::Double, "double"}});
    bool aligned = next ? values.candidates()->aligned : form_.aligned;
    ImGui::Checkbox(tr("Aligned addresses only", "Только выровненные адреса"), &aligned);
    if (next) {
        ImGui::EndDisabled();
    } else {
        form_.number_type = shown;
        form_.aligned = aligned;
    }
    if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip | ImGuiHoveredFlags_AllowWhenDisabled)) {
        ImGui::SetTooltip("%s", tr("The address is a multiple of the value's size: that is how almost all programs store numbers. The search is faster, with fewer stray addresses.",
                                   "Адрес кратен размеру значения: так числа хранят почти все программы. Поиск быстрее, лишних адресов меньше."));
    }
    if (next) {
        ui::muted_wrapped(tr("Type, alignment and memory kinds are set by the first search.", "Тип, выравнивание и виды памяти заданы первым поиском."));
    }

    const bool typed = !form_.number.empty() || (form_.compare == Compare::Between && !form_.number_high.empty());
    if (!takes_number(form_.compare) || !typed) {
        return;
    }
    try {
        const ValueCondition condition = value_condition(form_, type);
        if (condition.compare != Compare::Exact) {
            return;
        }
        if (!is_float(type)) {
            ui::muted(tr("In memory:", "В памяти:"));
            ImGui::SameLine();
            ImGui::PushFont(fonts_.mono);
            ui::text(number_signature(form_.number, type));
            ImGui::PopFont();
        } else if (condition.tolerance > 0) {
            ui::muted_wrapped(tr("Matches from ", "Подойдёт от ") + float_bound(condition.number - condition.tolerance, condition.tolerance) + tr(" to ", " до ") +
                              float_bound(condition.number + condition.tolerance, condition.tolerance));
        } else {
            ui::muted(tr("Only exactly this value matches", "Подойдёт только точно это значение"));
        }
    } catch (const Error& error) {
        ui::muted_wrapped(error.what());
    }
}

void View::draw_scan_button() {
    const ImVec2 size(-1.0f, std::floor(ImGui::GetFrameHeight() * 1.3f));
    if (const Job* job = session_.job()) {
        if (ui::button(job->cancel_requested() ? tr("Stopping…", "Останавливается…") : tr("Stop   Esc", "Остановить   Esc"), !job->cancel_requested(), size)) {
            session_.cancel();
        }
        return;
    }
    const bool can_scan = session_.target() != nullptr && alive_;
    if (value_mode()) {
        if (!session_.values().has_values()) {
            if (ui::button(tr("First search   F5", "Первый поиск   F5"), can_scan, size)) {
                start_scan();
            }
            return;
        }
        const float spacing = ImGui::GetStyle().ItemSpacing.x;
        const float width = ImGui::GetContentRegionAvail().x;
        const float reset_width = std::floor(width * 0.36f);
        if (ui::button(tr("Next search   F5", "Следующий поиск   F5"), can_scan, ImVec2(width - reset_width - spacing, size.y))) {
            start_scan();
        }
        ImGui::SameLine(0.0f, spacing);
        if (ui::button(tr("New search", "Новый поиск"), true, ImVec2(reset_width, size.y))) {
            session_.reset_values();
            focus_search_ = true;
        }
        ImGui::SetItemTooltip("%s", tr("Forget the found addresses and start from the first search", "Забыть найденные адреса и начать с первого поиска"));
        return;
    }
    const char* label = only_changed_ && session_.baseline() ? tr("Find in the changed   F5", "Найти в изменившемся   F5") : tr("Find   F5", "Найти   F5");
    if (ui::button(label, can_scan, size)) {
        start_scan();
    }
}

void View::draw_value_history() {
    const ValueHistory& history = session_.history();
    if (history.empty()) {
        return;
    }
    ui::heading(fonts_.heading, tr("HISTORY", "ИСТОРИЯ"));
    std::optional<std::size_t> picked;
    float count_width = 0.0f;
    for (const HistoryStep& entry : history.steps()) {
        count_width = std::max(count_width, ImGui::CalcTextSize(group_digits(entry.count).c_str()).x);
    }
    if (ImGui::BeginTable("##history", 3, ImGuiTableFlags_SizingFixedFit)) {
        ImGui::TableSetupColumn("##scan", ImGuiTableColumnFlags_WidthFixed);
        ImGui::TableSetupColumn("##condition", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("##count", ImGuiTableColumnFlags_WidthFixed, count_width);
        for (std::size_t step = 0; step < history.steps().size(); ++step) {
            const HistoryStep& entry = history.steps()[step];
            const bool current = step == history.current();
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::PushID(static_cast<int>(step));
            if (current) {
                ImGui::PushStyleColor(ImGuiCol_Text, theme::kBlack);
                ImGui::PushStyleColor(ImGuiCol_HeaderHovered, theme::kWhite);
                ImGui::PushStyleColor(ImGuiCol_HeaderActive, theme::kWhite);
            }
            if (ImGui::Selectable(std::to_string(entry.candidates->scans).c_str(), current, ImGuiSelectableFlags_SpanAllColumns) &&
                !current) {
                picked = step;
            }
            ImGui::TableSetColumnIndex(1);
            ui::text(entry.label);
            ImGui::TableSetColumnIndex(2);
            const std::string count = group_digits(entry.count);
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x - ImGui::CalcTextSize(count.c_str()).x);
            ui::text(count);
            if (current) {
                ImGui::PopStyleColor(3);
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    if (history.trimmed()) {
        ui::muted_wrapped(tr("Early steps removed — not enough memory.", "Ранние шаги удалены — не хватило памяти."));
    }
    if (history.steps().size() > 1) {
        ui::muted(tr("Ctrl+Z — back, Ctrl+Y — forward", "Ctrl+Z — назад, Ctrl+Y — вперёд"));
    }
    if (picked) {
        scroll_to_selection_ |= session_.go_to_scan(*picked);
    }
}

void View::draw_memory_options() {
    ui::heading(fonts_.heading, tr("MEMORY", "ПАМЯТЬ"));
    const auto option = [](const char* label, bool* value, const char* hint) {
        ImGui::Checkbox(label, value);
        ImGui::SameLine();
        ui::muted(hint);
    };
    option("private", &form_.private_memory, tr("heap, stacks, VirtualAlloc", "куча, стеки, VirtualAlloc"));
    option("image", &form_.image_memory, tr("exe and dll", "exe и dll"));
    option("mapped", &form_.mapped_memory, tr("files and shared memory", "файлы и общая память"));
    ImGui::Checkbox(tr("Writable only", "Только с правом записи"), &form_.writable_only);
}

void View::draw_compare_options() {
    ui::heading(fonts_.heading, tr("COMPARE", "СРАВНЕНИЕ"));
    const bool has_target = session_.target() != nullptr && alive_;
    const auto& baseline = session_.baseline();
    const float spacing = ImGui::GetStyle().ItemSpacing.x;
    const float width = ImGui::GetContentRegionAvail().x;
    const float forget_width = std::floor(width * 0.34f);
    if (ui::button(tr("Remember memory", "Запомнить память"), has_target, ImVec2(width - forget_width - spacing, 0.0f))) {
        session_.start_remember(form_);
    }
    ImGui::SetItemTooltip("%s", tr("Saves a fingerprint of memory (page hashes), not the memory itself.",
                                   "Сохраняет отпечаток памяти (хеши страниц), а не саму память."));
    ImGui::SameLine();
    if (ui::button(tr("Reset", "Сбросить"), baseline.has_value(), ImVec2(forget_width, 0.0f))) {
        session_.forget();
        only_changed_ = false;
    }
    if (baseline) {
        ui::text(tr("Remembered ", "Запомнено ") + format_size(baseline->bytes));
    } else {
        only_changed_ = false;
        ui::muted(tr("Nothing remembered", "Ничего не запомнено"));
    }
    if (!baseline) {
        ImGui::BeginDisabled();
    }
    ImGui::Checkbox(tr("Changed memory only", "Только изменившаяся память"), &only_changed_);
    if (!baseline) {
        ImGui::EndDisabled();
    }
    ui::muted_wrapped(tr("Remember it, change the value in the program, and search again — only in the changed memory.",
                         "Запомните, измените значение в программе и ищите снова — только в изменившейся памяти."));
}

void View::draw_parameters() {
    ui::heading(fonts_.heading, tr("PARAMETERS", "ПАРАМЕТРЫ"));
    const float value_x = std::floor(170.0f * scale_);
    ImGui::AlignTextToFramePadding();
    ui::muted(tr("Threads (0 — auto)", "Потоков (0 — авто)"));
    ImGui::SameLine(value_x);
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputScalar("##threads", ImGuiDataType_U32, &form_.threads);
    if (value_mode()) {
        return;
    }
    ImGui::AlignTextToFramePadding();
    ui::muted(tr("Match limit", "Лимит совпадений"));
    ImGui::SameLine(value_x);
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputScalar("##max_matches", ImGuiDataType_U64, &form_.max_matches);
}

void View::draw_progress_panel() {
    const ImGuiStyle& style = ImGui::GetStyle();
    const float height = style.WindowPadding.y * 2.0f + ImGui::GetFrameHeight() + style.ItemSpacing.y + ImGui::GetTextLineHeight();
    ImGui::BeginChild("##progress", ImVec2(0, std::floor(height)), ImGuiChildFlags_Borders, kPanel | ImGuiWindowFlags_NoScrollbar);
    const auto line = [this](std::initializer_list<std::pair<const char*, std::string>> parts) { progress_line(parts, scale_); };
    const ResultsTable& table = session_.table();
    const Job* running = session_.job();
    if (running != nullptr && (running->kind() == JobKind::PointerScan || running->kind() == JobKind::PointerCheck)) {
        draw_pointer_progress(*running);
    } else if (running == nullptr && page_ == Page::Pointers) {
        draw_pointer_summary();
    } else if ((running != nullptr && running->kind() == JobKind::Inspect) || (running == nullptr && page_ == Page::Inspect)) {
        draw_inspect_progress(running);
    } else if (running == nullptr && page_ == Page::Disasm) {
        draw_disasm_progress();
    } else if (const Job* job = running) {
        const ScanProgress& progress = job->progress().current();
        const std::uint64_t bytes_total = progress.bytes_total.load(std::memory_order_relaxed);
        const std::uint64_t bytes_done = progress.bytes_done.load(std::memory_order_relaxed);
        const double fraction = ratio(bytes_done, bytes_total);
        const std::string overlay = std::string(job_label(*job)) + "   " + (bytes_total == 0 ? std::string(tr("preparing", "подготовка")) : percent(fraction));
        ui::progress_bar(static_cast<float>(fraction), overlay);
        const std::string regions = group_digits(progress.regions_done.load(std::memory_order_relaxed)) + tr(" of ", " из ") +
                                    group_digits(progress.regions_total.load(std::memory_order_relaxed));
        if (job->kind() == JobKind::ValueScan) {
            line({{tr("Read", "Прочитано"), format_size(bytes_done) + tr(" of ", " из ") + format_size(bytes_total)},
                  {tr("Addresses", "Адресов"), group_digits(progress.matches.load(std::memory_order_relaxed))}});
        } else if (job->kind() == JobKind::Remember || job->progress().stage.load(std::memory_order_relaxed) == JobStage::Hashing) {
            line({{tr("Read", "Прочитано"), format_size(bytes_done) + tr(" of ", " из ") + format_size(bytes_total)}, {tr("Regions", "Регионы"), regions}});
        } else {
            line({{tr("Read", "Прочитано"), format_size(bytes_done) + tr(" of ", " из ") + format_size(bytes_total)},
                  {tr("Regions", "Регионы"), regions},
                  {tr("Matches", "Совпадений"), group_digits(progress.matches.load(std::memory_order_relaxed))}});
        }
    } else if (value_mode()) {
        const ValueTable& values = session_.values();
        if (values.has_values()) {
            const ValueCandidates& candidates = *values.candidates();
            ui::progress_bar(1.0f, tr("Done", "Готово"));
            line({{tr("Search", "Поиск"), std::to_string(candidates.scans)},
                  {tr("Addresses", "Адресов"), group_digits(values.total())},
                  {tr("Type", "Тип"), std::string(to_string(candidates.type))},
                  {tr("List takes", "Список занимает"), format_size(candidates.stored_bytes())}});
        } else {
            ui::progress_bar(0.0f, tr("Waiting", "Ожидание"));
            ui::muted(tr("Enter a value or pick \"Unknown initial value\" and press \"First search\" or F5.",
                         "Введите значение или выберите «Неизвестное начальное значение» и нажмите «Первый поиск» или F5."));
        }
    } else if (table.has_results()) {
        const ScanStats& stats = table.results().stats;
        const bool complete = stats.status == ScanStatus::Completed;
        ui::progress_bar(complete ? 1.0f : static_cast<float>(ratio(stats.bytes_read + stats.bytes_unreadable, stats.bytes_planned)),
                         complete ? tr("Done", "Готово") : stats.status == ScanStatus::Cancelled ? tr("Stopped", "Остановлено") : tr("Process ended", "Процесс завершился"));
        line({{tr("Read", "Прочитано"), format_size(stats.bytes_read) + tr(" of ", " из ") + format_size(stats.bytes_planned)},
              {tr("Regions", "Регионы"), group_digits(stats.regions_selected)},
              {tr("Matches", "Совпадений"), group_digits(table.results().matches.size())}});
    } else {
        ui::progress_bar(0.0f, tr("Waiting", "Ожидание"));
        ui::muted(tr("Enter what to look for and press \"Find\" or F5.", "Введите, что искать, и нажмите «Найти» или F5."));
    }
    ImGui::EndChild();
}

void View::draw_pointer_progress(const Job& job) {
    if (job.kind() == JobKind::PointerCheck) {
        const ScanProgress& check = job.progress().scanning;
        const std::uint64_t total = check.chunks_total.load(std::memory_order_relaxed);
        const std::uint64_t done = check.chunks_done.load(std::memory_order_relaxed);
        const double fraction = ratio(done, total);
        ui::progress_bar(static_cast<float>(fraction), std::string(job_label(job)) + "   " + percent(fraction));
        progress_line({{tr("Checked", "Проверено"), group_digits(done) + tr(" of ", " из ") + group_digits(total)},
                       {tr("Match", "Подходят"), group_digits(check.matches.load(std::memory_order_relaxed))}},
                      scale_);
        return;
    }
    const PointerScanProgress& progress = job.progress().pointers;
    const std::uint64_t bytes_total = progress.reading.bytes_total.load(std::memory_order_relaxed);
    const std::uint64_t bytes_done = progress.reading.bytes_done.load(std::memory_order_relaxed);
    const unsigned level = progress.level.load(std::memory_order_relaxed);
    const auto depth = static_cast<unsigned>(std::max(pointer_depth_, 1));
    double fraction = 0.0;
    std::string stage;
    switch (progress.stage.load(std::memory_order_relaxed)) {
        case PointerStage::Reading:
            fraction = ratio(bytes_done, bytes_total);
            stage = bytes_total == 0 ? std::string(tr("preparing", "подготовка")) : tr("reading memory ", "чтение памяти ") + percent(fraction);
            break;
        case PointerStage::Sorting:
            fraction = 1.0;
            stage = tr("sorting pointers", "сортировка указателей");
            break;
        case PointerStage::Searching:
            fraction = ratio(level, depth);
            stage = tr("level ", "уровень ") + std::to_string(level) + tr(" of ", " из ") + std::to_string(depth);
            break;
        case PointerStage::Listing:
            fraction = 1.0;
            stage = tr("building the list", "составление списка");
            break;
    }
    ui::progress_bar(static_cast<float>(fraction), std::string(job_label(job)) + "   " + stage);
    progress_line({{tr("Read", "Прочитано"), format_size(bytes_done) + tr(" of ", " из ") + format_size(bytes_total)},
                   {tr("Pointers", "Указателей"), group_digits(progress.pointers.load(std::memory_order_relaxed))},
                   {tr("Addresses in chains", "Адресов в цепочках"), group_digits(progress.nodes.load(std::memory_order_relaxed))}},
                  scale_);
}

void View::draw_pointer_summary() {
    const PointerList& pointers = session_.pointers();
    if (!pointers.has_chains()) {
        ui::progress_bar(0.0f, tr("Waiting", "Ожидание"));
        ui::muted(tr("Pick an address in the address list and press \"Find pointers…\".",
                     "Выберите адрес в списке адресов и нажмите «Найти указатели…»."));
        return;
    }
    const PointerSearch& search = pointers.search();
    ui::progress_bar(1.0f, tr("Done", "Готово"));
    progress_line({{tr("Chains", "Цепочек"), group_digits(pointers.rows().size())},
                   {tr("Found", "Найдено"), group_digits(search.found)},
                   {tr("Checks", "Проверок"), std::to_string(search.checks)},
                   {tr("Target", "Цель"), format_address(search.target.address) + "  " + type_label(search.target)}},
                  scale_);
}

void View::draw_page_switch() {
    const ImGuiStyle& style = ImGui::GetStyle();
    const std::size_t watched = session_.watch().rows().size();
    const std::string watch_label = (watched == 0 ? std::string(tr("Addresses", "Адреса")) : tr("Addresses (", "Адреса (") + std::to_string(watched) + ")") + "###watch_page";
    const std::size_t chains = session_.pointers().rows().size();
    const std::string pointer_label =
        (chains == 0 ? std::string(tr("Pointers", "Указатели")) : tr("Pointers (", "Указатели (") + group_digits(chains) + ")") + "###pointer_page";
    const float right_edge = ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x;
    float segments_end = ImGui::GetCursorPosX();
    const auto segment = [&](const char* label, bool selected) {
        const float width = std::floor(std::max(ImGui::CalcTextSize(label, nullptr, true).x + style.FramePadding.x * 4.0f, 100.0f * scale_));
        segments_end += width;
        return ui::segment(label, selected, true, ImVec2(width, 0.0f));
    };
    if (segment(tr("Results", "Результаты"), page_ == Page::Results)) {
        page_ = Page::Results;
    }
    ImGui::SameLine(0.0f, 0.0f);
    if (segment(tr("Regions", "Регионы"), page_ == Page::Regions)) {
        page_ = Page::Regions;
        if (!regions_loaded_) {
            refresh_regions();
        }
    }
    ImGui::SameLine(0.0f, 0.0f);
    if (segment(watch_label.c_str(), page_ == Page::Watch)) {
        page_ = Page::Watch;
        scroll_to_selection_ = true;
    }
    ImGui::SetItemTooltip("%s", tr("The list of addresses you are watching", "Список адресов, за которыми вы следите"));
    ImGui::SameLine(0.0f, 0.0f);
    if (segment(pointer_label.c_str(), page_ == Page::Pointers)) {
        page_ = Page::Pointers;
        scroll_to_selection_ = true;
    }
    ImGui::SetItemTooltip("%s", tr("Pointer chains that find the address again even after the program restarts",
                                   "Цепочки указателей, по которым адрес находится и после перезапуска программы"));
    ImGui::SameLine(0.0f, 0.0f);
    if (segment(tr("Structure", "Структура"), page_ == Page::Structure)) {
        page_ = Page::Structure;
        scroll_to_selection_ = true;
    }
    ImGui::SetItemTooltip("%s", tr("Structure fields around the address: types, names, and values that update as you watch",
                                   "Поля структуры вокруг адреса: типы, имена и значения, которые обновляются на глазах"));
    ImGui::SameLine(0.0f, 0.0f);
    if (segment(tr("Inspect", "Проверка"), page_ == Page::Inspect)) {
        page_ = Page::Inspect;
        scroll_to_selection_ = true;
    }
    ImGui::SetItemTooltip("%s", tr("Hunt for injected code: memory outside modules, RWX, PE headers, patched code, and module hollowing",
                                   "Поиск внедрённого кода: память вне модулей, RWX, PE-заголовки, изменённый код и подмена модулей"));
    ImGui::SameLine(0.0f, 0.0f);
    if (segment(tr("Disasm", "Дизасм"), page_ == Page::Disasm)) {
        page_ = Page::Disasm;
        scroll_to_selection_ = true;
        disasm_focus_ = !session_.disasm().has_result();
    }
    ImGui::SetItemTooltip("%s", tr("Disassemble machine code at an address: x86-64 and x86, Intel syntax",
                                   "Дизассемблировать машинный код по адресу: x86-64 и x86, Intel-синтаксис"));

    const float filter_min = 150.0f * scale_;
    const float preview_width = std::floor(60.0f * scale_);
    const float preview = ImGui::CalcTextSize(tr("Preview", "Превью")).x + style.ItemSpacing.x * 3.0f + preview_width * 2.0f;
    std::string value_count;
    if (page_ == Page::Results && value_mode()) {
        const ValueTable& values = session_.values();
        value_count = !values.has_values() ? std::string(tr("No results yet", "Пока нет результатов"))
                      : values.total() > values.rows().size()
                          ? tr("Showing the first ", "Показаны первые ") + group_digits(values.rows().size()) + tr(" of ", " из ") + group_digits(values.total())
                          : tr("Showing ", "Показано ") + count_addresses(values.total());
    }
    float bar = 0.0f;
    if (page_ == Page::Watch) {
        bar = buttons_width({tr("Add address…", "Добавить адрес…"), tr("Clear", "Очистить"), tr("Find pointers…", "Найти указатели…"), tr("Structure…", "Структура…")});
    } else if (page_ == Page::Pointers) {
        bar = buttons_width({tr("Check…", "Проверить…"), tr("Save…", "Сохранить…"), tr("Load…", "Загрузить…"), tr("Clear", "Очистить")});
    } else if (page_ == Page::Inspect) {
        bar = inspect_bar_width();
    } else if (page_ == Page::Disasm) {
        bar = disasm_bar_width();
    } else if (page_ == Page::Structure) {
        bar = buttons_width({tr("Open…", "Открыть…"), tr("Compare…", "Сравнить…"), tr("Save…", "Сохранить…"), tr("Load…", "Загрузить…")});
    } else if (page_ == Page::Results) {
        bar = value_mode() ? ImGui::CalcTextSize(value_count.c_str()).x : preview + filter_min;
    } else {
        bar = buttons_width({tr("Refresh", "Обновить")}) + style.ItemSpacing.x * 2.0f + ImGui::GetFrameHeight() + style.ItemInnerSpacing.x +
              ImGui::CalcTextSize(tr("Readable only", "Только читаемые")).x + filter_min;
    }
    // In a narrow window the bar goes under the page switch instead of running off the edge.
    if (segments_end + 20.0f * scale_ + bar <= right_edge) {
        ImGui::SameLine(0.0f, 20.0f * scale_);
    }

    if (page_ == Page::Watch) {
        draw_watch_bar(right_edge);
    } else if (page_ == Page::Pointers) {
        draw_pointer_bar(right_edge);
    } else if (page_ == Page::Structure) {
        draw_struct_bar(right_edge);
    } else if (page_ == Page::Inspect) {
        draw_inspect_bar(right_edge);
    } else if (page_ == Page::Disasm) {
        draw_disasm_bar(right_edge);
    } else if (page_ == Page::Results && value_mode()) {
        const char* hint = tr("\"Now\" updates twice a second; a frame means the value changed", "«Сейчас» обновляется дважды в секунду, рамка — значение изменилось");
        const float hint_width = ImGui::CalcTextSize(hint).x;
        const float room = right_edge - ImGui::GetCursorPosX() - ImGui::CalcTextSize(value_count.c_str()).x;
        ImGui::AlignTextToFramePadding();
        ui::muted(value_count);
        if (room - 20.0f * scale_ >= hint_width) {
            ImGui::SameLine(right_edge - hint_width);
            ui::muted(hint);
        } else {
            ImGui::SetItemTooltip("%s", hint);
        }
    } else if (page_ == Page::Results) {
        ResultsTable& table = session_.table();
        const std::string count = table.has_results()
                                      ? tr("Showing ", "Показано ") + group_digits(table.rows().size()) + tr(" of ", " из ") + group_digits(table.results().matches.size())
                                      : std::string(tr("No results yet", "Пока нет результатов"));
        const float room = right_edge - ImGui::GetCursorPosX();
        const float count_width = ImGui::CalcTextSize(count.c_str()).x + 20.0f * scale_;
        // In a narrow window the filter keeps its room and the count goes.
        const bool show_count = room - count_width - preview >= filter_min;
        const float filter_width = std::floor(std::clamp(room - preview - (show_count ? count_width : 0.0f), filter_min, 260.0f * scale_));
        const float total = preview + filter_width;
        ImGui::AlignTextToFramePadding();
        if (show_count) {
            ui::muted(count);
            ImGui::SameLine(std::max(right_edge - total, ImGui::GetCursorPosX()));
        } else {
            ImGui::SetCursorPosX(std::max(right_edge - total, ImGui::GetCursorPosX()));
        }
        ui::muted(tr("Preview", "Превью"));
        ImGui::SameLine();
        if (ui::segment("Hex", preview_ == PreviewMode::Hex, true, ImVec2(preview_width, 0.0f))) {
            preview_ = PreviewMode::Hex;
        }
        ImGui::SameLine(0.0f, 0.0f);
        if (ui::segment(tr("Text", "Текст"), preview_ == PreviewMode::Text, true, ImVec2(preview_width, 0.0f))) {
            preview_ = PreviewMode::Text;
        }
        ImGui::SameLine(0.0f, style.ItemSpacing.x * 2.0f);
        if (focus_filter_) {
            ImGui::SetKeyboardFocusHere();
            focus_filter_ = false;
        }
        const char* filter_hint = tr("Filter: address, text, bytes…   Ctrl+F", "Фильтр: адрес, текст, байты…   Ctrl+F");
        if (ImGui::CalcTextSize(filter_hint).x + style.FramePadding.x * 2.0f > filter_width) {
            filter_hint = tr("Filter…   Ctrl+F", "Фильтр…   Ctrl+F");
        }
        ImGui::SetNextItemWidth(-1.0f);
        if (ImGui::InputTextWithHint("##filter", filter_hint, &filter_)) {
            table.set_filter(filter_);
            scroll_to_selection_ = true;
        }
    } else {
        if (ui::button(tr("Refresh", "Обновить"))) {
            refresh_regions();
        }
        ImGui::SameLine();
        if (ImGui::Checkbox(tr("Readable only", "Только читаемые"), &readable_regions_only_)) {
            rebuild_region_rows();
        }
        std::uint64_t bytes = 0;
        for (const std::size_t row : region_rows_) {
            bytes += regions_[row].size;
        }
        const std::string count =
            tr("Showing ", "Показано ") + group_digits(region_rows_.size()) + tr(" of ", " из ") + group_digits(regions_.size()) + ", " + format_size(bytes);
        ImGui::SameLine(0.0f, 20.0f * scale_);
        const float room = right_edge - ImGui::GetCursorPosX();
        const float count_width = ImGui::CalcTextSize(count.c_str()).x + 20.0f * scale_;
        const bool show_count = room - count_width >= filter_min;
        const float filter_width = std::floor(std::clamp(room - (show_count ? count_width : 0.0f), filter_min, 260.0f * scale_));
        if (show_count) {
            ImGui::AlignTextToFramePadding();
            ui::muted(count);
        }
        ImGui::SameLine(right_edge - filter_width);
        ImGui::SetNextItemWidth(-1.0f);
        if (ImGui::InputTextWithHint("##region_filter", tr("Filter: address, module, protection…", "Фильтр: адрес, модуль, защита…"), &region_filter_)) {
            rebuild_region_rows();
        }
        if (!show_count) {
            ImGui::SetItemTooltip("%s", count.c_str());
        }
    }
}

void View::draw_results(float height) {
    const ImGuiStyle& style = ImGui::GetStyle();
    float details = std::clamp(std::floor(height * 0.42f), std::floor(230.0f * scale_), std::floor(330.0f * scale_));
    details = std::min(details, std::floor(height * 0.55f));
    const float table_height = std::max(height - details - style.ItemSpacing.y, 60.0f * scale_);
    if (page_ == Page::Watch) {
        draw_watch_table(table_height);
    } else if (page_ == Page::Pointers) {
        draw_pointer_table(table_height);
    } else if (page_ == Page::Structure) {
        draw_struct_table(table_height);
    } else if (page_ == Page::Inspect) {
        draw_inspect_table(table_height);
    } else if (page_ == Page::Disasm) {
        draw_disasm_table(table_height);
    } else if (value_mode()) {
        draw_value_table(table_height);
    } else {
        draw_results_table(table_height);
    }
    draw_details(std::max(ImGui::GetContentRegionAvail().y, 1.0f));
}

void View::draw_results_table(float height) {
    ResultsTable& table = session_.table();
    if (!table.has_results() || table.rows().empty()) {
        ImGui::BeginChild("##empty", ImVec2(0, height), ImGuiChildFlags_Borders, kPanel);
        if (session_.busy()) {
            ui::muted(tr("Searching…", "Идёт поиск…"));
        } else if (table.has_results() && !table.filter().empty()) {
            ui::muted(tr("The filter hid every row.", "Фильтр скрыл все строки."));
        } else if (table.has_results()) {
            ui::muted(tr("Nothing found. Check the spelling, the encoding, and the memory types on the left.",
                         "Ничего не найдено. Проверьте написание, кодировку и типы памяти слева."));
        } else {
            ui::muted(tr("The addresses you find will show up here.", "Здесь появятся найденные адреса."));
        }
        ImGui::EndChild();
        return;
    }

    const ResultSet& results = table.results();
    const std::vector<std::size_t>& rows = table.rows();
    const std::optional<std::size_t> selected = table.selected_row();
    const ImGuiStyle& style = ImGui::GetStyle();
    const float ui_line = ImGui::GetTextLineHeight();
    const float mono_line = fonts_.mono->FontSize;
    const float row_height = std::max(ui_line, mono_line);
    const float ui_offset = std::floor((row_height - ui_line) * 0.5f);
    const float mono_offset = std::floor((row_height - mono_line) * 0.5f);
    page_rows_ = std::max(1, static_cast<int>(height / (row_height + style.CellPadding.y * 2.0f)) - 2);

    const std::array<float, kColumnCount> widths = {font_text_width(fonts_.mono, "0x0000000000000000"),
                                                    105.0f * scale_,
                                                    150.0f * scale_,
                                                    55.0f * scale_,
                                                    70.0f * scale_,
                                                    65.0f * scale_,
                                                    130.0f * scale_,
                                                    200.0f * scale_};
    constexpr ImGuiTableFlags flags = ImGuiTableFlags_ScrollX | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersOuter |
                                      ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_Resizable | ImGuiTableFlags_Sortable |
                                      ImGuiTableFlags_SizingFixedFit;
    if (!ImGui::BeginTable("##results", static_cast<int>(kColumnCount), flags, ImVec2(0, height), table_inner_width(widths))) {
        return;
    }
    const auto column = [&widths](const char* label, ImGuiTableColumnFlags column_flags, Column id) {
        const bool stretch = (column_flags & ImGuiTableColumnFlags_WidthStretch) != 0;
        ImGui::TableSetupColumn(label, column_flags, stretch ? 0.0f : widths[static_cast<std::size_t>(id)], static_cast<ImGuiID>(id));
    };
    column(tr("Address", "Адрес"), ImGuiTableColumnFlags_DefaultSort, Column::Address);
    column(tr("Type", "Тип"), 0, Column::Kind);
    column(tr("Pattern", "Шаблон"), 0, Column::Pattern);
    column(tr("Length", "Длина"), 0, Column::Length);
    column(tr("Protection", "Защита"), 0, Column::Protection);
    column(tr("Memory", "Память"), 0, Column::Type);
    column(tr("Module", "Модуль"), 0, Column::Module);
    column(tr("Preview", "Превью"), ImGuiTableColumnFlags_WidthStretch, Column::Preview);
    ImGui::TableSetupScrollFreeze(1, 1);
    ImGui::TableHeadersRow();

    if (ImGuiTableSortSpecs* specs = ImGui::TableGetSortSpecs(); specs != nullptr && specs->SpecsDirty) {
        if (specs->SpecsCount > 0) {
            const ImGuiTableColumnSortSpecs& spec = specs->Specs[0];
            table.sort_by(static_cast<Column>(spec.ColumnUserID), spec.SortDirection == ImGuiSortDirection_Descending);
            scroll_to_selection_ = true;
        }
        specs->SpecsDirty = false;
    }

    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(rows.size()), row_height + style.CellPadding.y * 2.0f);
    if (selected) {
        clipper.IncludeItemByIndex(static_cast<int>(*selected));
    }
    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const std::size_t index = static_cast<std::size_t>(row);
            const std::size_t match_index = rows[index];
            const Match& match = results.matches[match_index];
            const bool is_selected = selected == index;
            ImGui::TableNextRow(ImGuiTableRowFlags_None, row_height);
            ImGui::TableSetColumnIndex(0);
            ImGui::PushID(row);
            if (is_selected) {
                ImGui::PushStyleColor(ImGuiCol_HeaderHovered, theme::kWhite);
                ImGui::PushStyleColor(ImGuiCol_HeaderActive, theme::kWhite);
            }
            const ImVec2 row_start = ImGui::GetCursorPos();
            const bool clicked = ImGui::Selectable("##row", is_selected,
                                                   ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap,
                                                   ImVec2(0.0f, row_height));
            if (is_selected) {
                ImGui::PopStyleColor(2);
            }
            if (clicked || ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                table.select_row(index);
            }
            if (ImGui::BeginPopupContextItem("##menu")) {
                if (ImGui::MenuItem(tr("Copy address", "Копировать адрес"))) {
                    copy_address(match.address);
                }
                if (ImGui::MenuItem(tr("Copy bytes (hex)", "Копировать байты (hex)"))) {
                    ImGui::SetClipboardText(match_bytes_hex(results, match).c_str());
                }
                if (ImGui::MenuItem(tr("Copy text", "Копировать текст"))) {
                    ImGui::SetClipboardText(match_text(results, match).c_str());
                }
                ImGui::Separator();
                if (ImGui::MenuItem(tr("Add to the address list", "В список адресов"), "Insert")) {
                    session_.add_watch(watch_entry_for(match.address, results.patterns[match.pattern].kind, match.length));
                }
                if (ImGui::MenuItem(tr("Break down the structure…", "Разобрать структуру…"), "Ctrl+D")) {
                    open_struct_from_selection();
                }
                if (ImGui::MenuItem(tr("Disassemble", "Дизассемблировать"))) {
                    disassemble_at(match.address);
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
            for (std::size_t c = 0; c < kColumnCount; ++c) {
                const Column id = static_cast<Column>(c);
                const bool mono = id == Column::Address || (id == Column::Preview && preview_ == PreviewMode::Hex);
                ImGui::TableSetColumnIndex(static_cast<int>(c));
                if (c == 0) {
                    ImGui::SetCursorPos(row_start);
                }
                ImGui::SetCursorPosY(ImGui::GetCursorPosY() + (mono ? mono_offset : ui_offset));
                if (mono) {
                    ImGui::PushFont(fonts_.mono);
                }
                ui::text(table.cell(match_index, id, preview_));
                if (mono) {
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
}

void View::draw_value_table(float height) {
    ValueTable& values = session_.values();
    if (!values.has_values() || values.rows().empty()) {
        ImGui::BeginChild("##no_values", ImVec2(0, height), ImGuiChildFlags_Borders, kPanel);
        if (session_.busy()) {
            ui::muted(tr("Searching…", "Идёт поиск…"));
        } else if (values.has_values()) {
            ui::muted(tr("No addresses left. Press \"New search\".", "Не осталось ни одного адреса. Нажмите «Новый поиск»."));
        } else {
            ui::muted(tr("Addresses and their values will show up here: now and at the last search.",
                         "Здесь появятся адреса и их значения: сейчас и при прошлом поиске."));
        }
        ImGui::EndChild();
        return;
    }

    const MemorySource& memory = session_.target()->memory();
    const std::vector<ValueCandidate>& rows = values.rows();
    const std::optional<std::size_t> selected = values.selected_row();
    const ImGuiStyle& style = ImGui::GetStyle();
    const float ui_line = ImGui::GetTextLineHeight();
    const float mono_line = fonts_.mono->FontSize;
    const float row_height = std::max(ui_line, mono_line);
    const float ui_offset = std::floor((row_height - ui_line) * 0.5f);
    const float mono_offset = std::floor((row_height - mono_line) * 0.5f);
    page_rows_ = std::max(1, static_cast<int>(height / (row_height + style.CellPadding.y * 2.0f)) - 2);
    const auto now = std::chrono::steady_clock::now();
    const bool due = now - values_time_ >= kLiveRefresh;
    if (due) {
        values_time_ = now;
    }

    const std::array<float, 6> widths = {font_text_width(fonts_.mono, "0x0000000000000000"),
                                         150.0f * scale_,
                                         150.0f * scale_,
                                         70.0f * scale_,
                                         65.0f * scale_,
                                         130.0f * scale_};
    constexpr ImGuiTableFlags flags = ImGuiTableFlags_ScrollX | ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersOuter |
                                      ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingFixedFit;
    if (!ImGui::BeginTable("##values", 6, flags, ImVec2(0, height), table_inner_width(widths))) {
        return;
    }
    ImGui::TableSetupColumn(tr("Address", "Адрес"), 0, widths[0]);
    ImGui::TableSetupColumn(tr("Now", "Сейчас"), 0, widths[1]);
    ImGui::TableSetupColumn(tr("Was", "Было"), 0, widths[2]);
    ImGui::TableSetupColumn(tr("Protection", "Защита"), 0, widths[3]);
    ImGui::TableSetupColumn(tr("Memory", "Память"), 0, widths[4]);
    ImGui::TableSetupColumn(tr("Module", "Модуль"), ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableSetupScrollFreeze(1, 1);
    ImGui::TableHeadersRow();

    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(rows.size()), row_height + style.CellPadding.y * 2.0f);
    if (selected) {
        clipper.IncludeItemByIndex(static_cast<int>(*selected));
    }
    while (clipper.Step()) {
        const auto first = static_cast<std::size_t>(clipper.DisplayStart);
        const auto last = static_cast<std::size_t>(clipper.DisplayEnd);
        bool stale = due;
        for (std::size_t index = first; index < last && !stale; ++index) {
            stale = !values.live(index).read;
        }
        if (stale) {
            values.refresh(memory, first, last);
        }
        for (std::size_t index = first; index < last; ++index) {
            const ValueCandidate& value = rows[index];
            const LiveValue& live = values.live(index);
            const bool is_selected = selected == index;
            ImGui::TableNextRow(ImGuiTableRowFlags_None, row_height);
            ImGui::TableSetColumnIndex(0);
            ImGui::PushID(static_cast<int>(index));
            if (is_selected) {
                ImGui::PushStyleColor(ImGuiCol_HeaderHovered, theme::kWhite);
                ImGui::PushStyleColor(ImGuiCol_HeaderActive, theme::kWhite);
            }
            const ImVec2 row_start = ImGui::GetCursorPos();
            const bool clicked = ImGui::Selectable("##row", is_selected,
                                                   ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap,
                                                   ImVec2(0.0f, row_height));
            if (is_selected) {
                ImGui::PopStyleColor(2);
            }
            if (clicked || ImGui::IsItemClicked(ImGuiMouseButton_Right)) {
                values.select_row(index);
            }
            if (ImGui::BeginPopupContextItem("##menu")) {
                if (ImGui::MenuItem(tr("Copy address", "Копировать адрес"))) {
                    copy_address(value.address);
                }
                if (ImGui::MenuItem(tr("Copy value", "Копировать значение"))) {
                    const std::string text = live.readable ? values.current_text(index) : values.previous_text(index);
                    ImGui::SetClipboardText(text.c_str());
                }
                ImGui::Separator();
                if (ImGui::MenuItem(tr("Add to the address list", "В список адресов"), "Insert")) {
                    session_.add_watch(make_watch_entry(value.address, watch_type(values.candidates()->type)));
                }
                if (ImGui::MenuItem(tr("Break down the structure…", "Разобрать структуру…"), "Ctrl+D")) {
                    open_struct_from_selection();
                }
                if (ImGui::MenuItem(tr("Disassemble", "Дизассемблировать"))) {
                    disassemble_at(value.address);
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
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + mono_offset);
            ImGui::PushFont(fonts_.mono);
            ui::text(format_address(value.address));
            ImGui::PopFont();

            ImGui::TableSetColumnIndex(1);
            ImGui::SetCursorPosY(ImGui::GetCursorPosY() + ui_offset);
            if (live.read && !live.readable) {
                ui::muted("??");
            } else {
                ui::text(values.current_text(index));
                if (values.changed(index)) {
                    const ImVec2 min = ImGui::GetItemRectMin();
                    const ImVec2 max = ImGui::GetItemRectMax();
                    const float pad = std::floor(style.CellPadding.x * 0.75f);
                    ImGui::GetWindowDrawList()->AddRect(ImVec2(min.x - pad, min.y - 1.0f), ImVec2(max.x + pad, max.y + 1.0f),
                                                        is_selected ? theme::kBlack : theme::kWhite);
                }
            }
            const Region* region = values.region(index);
            const std::string cells[] = {values.previous_text(index),
                                         region != nullptr ? protection_to_string(region->protect) : std::string(),
                                         region != nullptr ? std::string(to_string(region->type)) : std::string(),
                                         region != nullptr ? region->module_name() : std::string()};
            for (std::size_t c = 0; c < std::size(cells); ++c) {
                ImGui::TableSetColumnIndex(static_cast<int>(c + 2));
                ImGui::SetCursorPosY(ImGui::GetCursorPosY() + ui_offset);
                ui::text(cells[c]);
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
}

void View::keep_selection_visible(float row_height) {
    if (!scroll_to_selection_) {
        return;
    }
    const float row = row_height + ImGui::GetStyle().CellPadding.y * 2.0f;
    const float top = ImGui::GetItemRectMin().y;
    const float bottom = ImGui::GetItemRectMax().y;
    const float view_top = ImGui::GetWindowPos().y + row;
    const float view_bottom = ImGui::GetWindowPos().y + ImGui::GetWindowHeight();
    if (top < view_top) {
        ImGui::SetScrollHereY(0.2f);
    } else if (bottom > view_bottom) {
        ImGui::SetScrollHereY(0.8f);
    }
    scroll_to_selection_ = false;
}

void View::refresh_dump(const Match& match) {
    const Target* target = session_.target();
    if (target == nullptr) {
        return;
    }
    const auto now = std::chrono::steady_clock::now();
    const bool same = dump_match_ == match.address;
    if (same && !(live_dump_ && now - dump_time_ >= kLiveRefresh)) {
        return;
    }
    const std::uint64_t row = match.address - match.address % kDumpRow;
    const std::uint64_t start = row >= kDumpLead ? row - kDumpLead : 0;
    dump_ = read_dump(target->memory(), start, kDumpRow * kDumpRows);
    dump_match_ = match.address;
    dump_time_ = now;
}

void View::draw_details(float height) {
    ImGui::BeginChild("##details", ImVec2(0, height), ImGuiChildFlags_Borders, kPanel | ImGuiWindowFlags_NoScrollbar);
    const ValueTable& values = session_.values();
    const WatchList& watch = session_.watch();
    const PointerList& pointers = session_.pointers();
    const bool watch_page = page_ == Page::Watch;
    const bool pointer_page = page_ == Page::Pointers;
    const bool struct_page = page_ == Page::Structure;
    const bool inspect_page = page_ == Page::Inspect;
    const bool disasm_page = page_ == Page::Disasm;
    const bool result_page = !watch_page && !pointer_page && !struct_page && !inspect_page && !disasm_page;
    const StructTable& structure = session_.structure();
    const std::optional<std::size_t> watch_row = watch_page ? watch.selected_row() : std::nullopt;
    const std::optional<std::size_t> pointer_row = pointer_page ? pointers.selected_row() : std::nullopt;
    const std::optional<std::size_t> struct_row = struct_page && structure.active() ? structure.selected_row() : std::nullopt;
    const Finding* finding = inspect_page ? session_.findings().selected() : nullptr;
    const DisasmLine* line = disasm_page ? session_.disasm().selected() : nullptr;
    const ValueCandidate* value = result_page && value_mode() ? values.selected() : nullptr;
    std::optional<Match> match;
    if (finding != nullptr) {
        match = Match{.address = finding->address,
                      .length = static_cast<std::uint32_t>(std::min<std::uint64_t>(finding->size, UINT32_MAX))};
    } else if (line != nullptr) {
        match = Match{.address = line->address, .length = line->size};
    } else if (watch_row) {
        const WatchEntry& entry = watch.rows()[*watch_row];
        match = Match{.address = entry.address, .length = static_cast<std::uint32_t>(entry.size())};
    } else if (pointer_row) {
        if (const auto address = pointers.address(*pointer_row)) {
            match = Match{.address = *address, .length = static_cast<std::uint32_t>(pointers.search().target.size())};
        }
    } else if (struct_row) {
        if (const auto address = structure.field_address(*struct_row, 0)) {
            match = Match{.address = *address, .length = structure.rows()[*struct_row].field.size(structure.pointer_size())};
        }
    } else if (value != nullptr) {
        match = Match{.address = value->address, .length = static_cast<std::uint32_t>(size_of(values.candidates()->type))};
    } else if (result_page && !value_mode() && session_.table().selected_match() != nullptr) {
        match = *session_.table().selected_match();
    }
    const ImGuiStyle& style = ImGui::GetStyle();
    const float value_x = std::floor((pointer_page || struct_page ? 108.0f : 84.0f) * scale_);
    if (!match && (pointer_row || struct_row)) {
        // The chain leads nowhere now, so there is no memory to show.
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(style.ItemSpacing.x, std::floor(style.ItemSpacing.y * 0.5f)));
        ImGui::AlignTextToFramePadding();
        if (pointer_row) {
            draw_pointer_info(*pointer_row, value_x);
        } else {
            draw_struct_info(*struct_row, value_x);
        }
        ImGui::PopStyleVar();
        ImGui::EndChild();
        return;
    }
    if (!match) {
        ui::heading(fonts_.heading, tr("DETAILS", "ПОДРОБНОСТИ"));
        if (watch_page) {
            ui::muted(watch.empty() ? tr("Here you will see an address from the list, its type, and the memory around it.", "Здесь будет адрес из списка, его тип и память вокруг него.")
                                    : tr("Pick a row in the list.", "Выберите строку в списке."));
        } else if (pointer_page) {
            ui::muted(pointers.has_chains() ? tr("Pick a row in the list.", "Выберите строку в списке.")
                                            : tr("Here you will see a chain, where it leads right now, and the memory there.", "Здесь будет цепочка, куда она ведёт сейчас, и память там."));
        } else if (struct_page) {
            ui::muted(structure.active() ? tr("Pick a field in the table.", "Выберите поле в таблице.")
                                         : tr("Here you will see a structure field, its address, and the memory around it.", "Здесь будет поле структуры, его адрес и память вокруг него."));
        } else if (inspect_page) {
            ui::muted(session_.findings().rows().empty() ? tr("Here you will see a finding, its details, and the memory at its address.", "Здесь будет находка, её подробности и память по её адресу.")
                                                         : tr("Pick a row in the table.", "Выберите строку в таблице."));
        } else if (disasm_page) {
            ui::muted(session_.disasm().rows().empty() ? tr("Here you will see instruction details and the memory at its address.", "Здесь будут подробности инструкции и память по её адресу.")
                                                       : tr("Pick a row in the table.", "Выберите строку в таблице."));
        } else if (value_mode()) {
            ui::muted(values.has_values() ? tr("Pick a row in the table.", "Выберите строку в таблице.")
                                          : tr("Here you will see an address, its value, and the memory around it.", "Здесь будет адрес, его значение и память вокруг него."));
        } else {
            ui::muted(session_.table().has_results() ? tr("Pick a row in the table.", "Выберите строку в таблице.")
                                                     : tr("Here you will see a match, its region, and the memory around it.", "Здесь будет совпадение, его регион и память вокруг него."));
        }
        ImGui::EndChild();
        return;
    }
    refresh_dump(*match);
    const float dump_width = font_text_width(fonts_.mono, "0") * kDumpChars;
    const float avail = ImGui::GetContentRegionAvail().x;
    const float info_width =
        std::floor(std::clamp(avail - dump_width - style.ItemSpacing.x * 3.0f - style.ScrollbarSize, 250.0f * scale_, 420.0f * scale_));

    ImGui::BeginChild("##info", ImVec2(info_width, 0), ImGuiChildFlags_None, kPanel);
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(style.ItemSpacing.x, std::floor(style.ItemSpacing.y * 0.5f)));
    ImGui::AlignTextToFramePadding();
    if (finding != nullptr) {
        draw_finding_info(*finding, value_x);
    } else if (line != nullptr) {
        draw_disasm_info(*line, value_x);
    } else if (watch_row) {
        draw_watch_info(*watch_row, value_x);
    } else if (pointer_row) {
        draw_pointer_info(*pointer_row, value_x);
    } else if (struct_row) {
        draw_struct_info(*struct_row, value_x);
    } else if (value != nullptr) {
        draw_value_info(*value, value_x);
    } else {
        draw_match_info(*match, value_x);
    }
    ImGui::PopStyleVar();
    ImGui::EndChild();

    const ImVec2 info_max = ImGui::GetItemRectMax();
    const ImVec2 info_min = ImGui::GetItemRectMin();
    const float line_x = std::floor(info_max.x + style.ItemSpacing.x * 1.5f);
    ImGui::GetWindowDrawList()->AddLine(ImVec2(line_x, info_min.y), ImVec2(line_x, info_max.y), theme::kWhite);
    ImGui::SameLine(0.0f, style.ItemSpacing.x * 3.0f);
    ImGui::BeginChild("##dump", ImVec2(0, 0), ImGuiChildFlags_None, kPanel | ImGuiWindowFlags_HorizontalScrollbar);
    draw_dump(*match);
    ImGui::EndChild();
    ImGui::EndChild();
}

void View::draw_match_info(const Match& match, float value_x) {
    const ResultsTable& table = session_.table();
    const ResultSet& results = table.results();
    ui::heading(fonts_.heading, tr("MATCH", "СОВПАДЕНИЕ"));
    ui::field(tr("Address", "Адрес"), format_address(match.address), value_x, fonts_.mono);
    const PatternInfo& pattern = results.patterns[match.pattern];
    ui::field(tr("Pattern", "Шаблон"), pattern.label, value_x);
    ui::field(tr("Type", "Тип"), kind_name(pattern.kind), value_x);
    ui::field(tr("Length", "Длина"), plural(match.length, false, "byte", "bytes", "байт", "байта", "байт"), value_x);
    ui::muted(tr("Now", "Сейчас"));
    ImGui::SameLine(value_x);
    switch (live_state(results, session_.patterns(), match, dump_)) {
        case LiveState::Same: ui::text(tr("in place", "на месте")); break;
        case LiveState::Changed: inverted_text(tr("changed", "изменилось")); break;
        case LiveState::Unreadable: ui::muted(tr("unreadable", "не читается")); break;
    }
    ImGui::Spacing();
    draw_region_fields(results.region_of(match), match.address, table.module_of(match), value_x);
}

void View::draw_value_info(const ValueCandidate& value, float value_x) {
    const ValueCandidates& candidates = *session_.values().candidates();
    const std::size_t size = size_of(candidates.type);
    ui::heading(fonts_.heading, tr("VALUE", "ЗНАЧЕНИЕ"));
    ui::field(tr("Address", "Адрес"), format_address(value.address), value_x, fonts_.mono);
    ui::field(tr("Type", "Тип"), std::string(to_string(candidates.type)) + ", " + plural(size, false, "byte", "bytes", "байт", "байта", "байт"), value_x);
    ui::muted(tr("Now", "Сейчас"));
    ImGui::SameLine(value_x);
    if (dump_.all_readable(value.address, value.address + size)) {
        std::uint64_t bits = 0;
        std::memcpy(&bits, dump_.bytes.data() + (value.address - dump_.address), size);
        const std::string text = format_value(candidates.type, bits);
        if (bits != value.previous) {
            inverted_text(text);
        } else {
            ui::text(text);
        }
    } else {
        ui::muted(tr("unreadable", "не читается"));
    }
    ui::field(tr("Was", "Было"), format_value(candidates.type, value.previous), value_x);
    ImGui::SetItemTooltip(tr("The value at search %u", "Значение при поиске %u"), candidates.scans);
    ImGui::Spacing();
    const Region* region = candidates.region_of(value.address);
    draw_region_fields(region, value.address, region != nullptr ? region->module_name() : std::string(), value_x);
}

void View::draw_region_fields(const Region* region, std::uint64_t address, std::string_view module, float value_x) {
    ui::heading(fonts_.heading, tr("REGION", "РЕГИОН"));
    if (region == nullptr) {
        ui::muted(tr("Region unknown", "Регион неизвестен"));
        return;
    }
    ui::field(tr("Start", "Начало"), format_address(region->base), value_x, fonts_.mono);
    ui::field(tr("Offset", "Смещение"), signed_offset(address, region->base), value_x, fonts_.mono);
    ui::field(tr("Size", "Размер"), format_size(region->size), value_x);
    ui::field(tr("Protection", "Защита"), protection_to_string(region->protect) + "   " + std::string(to_string(region->type)), value_x);
    ui::field(tr("Module", "Модуль"), module.empty() ? std::string_view("—") : module, value_x);
    if (!region->mapped_file.empty()) {
        ImGui::SetItemTooltip("%s", region->mapped_file.c_str());
    }
}

void View::draw_dump(const Match& match) {
    const float right_edge = ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x;
    ImGui::AlignTextToFramePadding();
    ImGui::PushFont(fonts_.heading);
    ImGui::TextUnformatted(tr("MEMORY NOW", "ПАМЯТЬ СЕЙЧАС"));
    ImGui::PopFont();
    ImGui::SetItemTooltip("%s", tr("The matched bytes are highlighted inverted; ?? means the memory is unreadable.", "Байты совпадения выделены инверсией, ?? — память не читается."));
    const float checkbox_width = ImGui::GetFrameHeight() + ImGui::GetStyle().ItemInnerSpacing.x + ImGui::CalcTextSize(tr("Live", "Обновлять")).x;
    ImGui::SameLine(std::max(right_edge - checkbox_width, ImGui::GetCursorPosX()));
    ImGui::Checkbox(tr("Live", "Обновлять"), &live_dump_);
    ImGui::SetItemTooltip("%s", tr("Re-read the memory twice a second", "Перечитывать память дважды в секунду"));
    ImGui::Separator();

    ImGui::PushFont(fonts_.mono);
    const float cw = font_text_width(fonts_.mono, "0");
    const float line = std::floor(ImGui::GetTextLineHeight() * 1.15f);
    const ImVec2 origin = ImGui::GetCursorScreenPos();
    ImDrawList* draw = ImGui::GetWindowDrawList();
    const std::uint64_t match_end = match.address + match.length;
    const std::size_t rows = (dump_.bytes.size() + kDumpRow - 1) / kDumpRow;
    std::array<char, 4> hex{};
    for (std::size_t r = 0; r < rows; ++r) {
        const float y = origin.y + static_cast<float>(r) * line;
        const std::uint64_t row_address = dump_.address + r * kDumpRow;
        const std::string address = dump_address(row_address);
        draw->AddText(ImVec2(origin.x, y), theme::kMuted, address.c_str());
        for (std::size_t b = 0; b < kDumpRow; ++b) {
            const std::size_t index = r * kDumpRow + b;
            if (index >= dump_.bytes.size()) {
                break;
            }
            const std::uint64_t at = row_address + b;
            const bool in_match = at >= match.address && at < match_end;
            const bool readable = dump_.readable[index] != 0;
            const float hex_x = origin.x + (kDumpHexColumn + static_cast<float>(b * 3 + (b >= 8 ? 1 : 0))) * cw;
            const float text_x = origin.x + (kDumpTextColumn + static_cast<float>(b)) * cw;
            if (in_match) {
                draw->AddRectFilled(ImVec2(hex_x - cw * 0.5f, y), ImVec2(hex_x + cw * 2.5f, y + line), theme::kWhite);
                draw->AddRectFilled(ImVec2(text_x, y), ImVec2(text_x + cw, y + line), theme::kWhite);
            }
            const ImU32 color = in_match ? theme::kBlack : readable ? theme::kWhite : theme::kMuted;
            const auto value = static_cast<unsigned>(std::to_integer<std::uint8_t>(dump_.bytes[index]));
            if (readable) {
                std::snprintf(hex.data(), hex.size(), "%02X", value);
            } else {
                hex = {'?', '?', '\0', '\0'};
            }
            const float text_y = y + std::floor((line - ImGui::GetTextLineHeight()) * 0.5f);
            draw->AddText(ImVec2(hex_x, text_y), color, hex.data());
            const char glyph[2] = {readable && value >= 0x20 && value < 0x7F ? static_cast<char>(value) : '.', '\0'};
            draw->AddText(ImVec2(text_x, text_y), color, glyph);
        }
    }
    ImGui::Dummy(ImVec2(cw * kDumpChars, static_cast<float>(rows) * line));
    ImGui::PopFont();
}

void View::refresh_regions() {
    regions_.clear();
    regions_loaded_ = true;
    if (const Target* target = session_.target()) {
        try {
            regions_ = target->memory().query_regions();
        } catch (const Error& error) {
            session_.set_notice(describe_error(error), true);
        }
    }
    rebuild_region_rows();
}

void View::rebuild_region_rows() {
    region_rows_.clear();
    const std::string needle = to_lower_ascii(region_filter_);
    for (std::size_t i = 0; i < regions_.size(); ++i) {
        const Region& region = regions_[i];
        if (readable_regions_only_ && !(region.state == MemState::Commit && region.readable())) {
            continue;
        }
        if (!needle.empty() && !contains_lower(format_address(region.base), needle) && !contains_lower(region.mapped_file, needle) &&
            !contains_lower(protection_to_string(region.protect), needle) && !contains_lower(to_string(region.type), needle)) {
            continue;
        }
        region_rows_.push_back(i);
    }
}

void View::draw_regions(float height) {
    constexpr ImGuiTableFlags flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersInnerV |
                                      ImGuiTableFlags_Resizable | ImGuiTableFlags_SizingFixedFit;
    if (!ImGui::BeginTable("##regions", 6, flags, ImVec2(0, height))) {
        return;
    }
    const float address_width = font_text_width(fonts_.mono, "0x0000000000000000");
    ImGui::TableSetupColumn(tr("Start", "Начало"), 0, address_width);
    ImGui::TableSetupColumn(tr("Size", "Размер"), 0, ImGui::CalcTextSize("1023.99 KiB").x);
    ImGui::TableSetupColumn(tr("State", "Состояние"), 0, ImGui::CalcTextSize(tr("State", "Состояние")).x);
    ImGui::TableSetupColumn(tr("Protection", "Защита"), 0, ImGui::CalcTextSize("rw- guard").x);
    ImGui::TableSetupColumn(tr("Type", "Тип"), 0, ImGui::CalcTextSize("private").x);
    ImGui::TableSetupColumn(tr("Module or file", "Модуль или файл"), ImGuiTableColumnFlags_WidthStretch);
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableHeadersRow();
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(region_rows_.size()));
    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const Region& region = regions_[region_rows_[static_cast<std::size_t>(row)]];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::PushFont(fonts_.mono);
            ui::text(format_address(region.base));
            ImGui::PopFont();
            ImGui::TableSetColumnIndex(1);
            ui::text(format_size(region.size));
            ImGui::TableSetColumnIndex(2);
            ui::text(to_string(region.state));
            ImGui::TableSetColumnIndex(3);
            ui::text(protection_to_string(region.protect));
            ImGui::TableSetColumnIndex(4);
            ui::text(to_string(region.type));
            ImGui::TableSetColumnIndex(5);
            ui::text(region.mapped_file);
        }
    }
    ImGui::EndTable();
}

void View::draw_no_process(float height) {
    ImGui::BeginChild("##welcome", ImVec2(0, height), ImGuiChildFlags_Borders, kPanel);
    const float width = std::min(ImGui::GetContentRegionAvail().x, 520.0f * scale_);
    const float block_height = ImGui::GetTextLineHeight() * 6.0f + ImGui::GetFrameHeight() * 1.3f;
    ImGui::SetCursorPos(ImVec2(std::floor((ImGui::GetContentRegionAvail().x - width) * 0.5f),
                               std::floor(std::max((height - block_height) * 0.4f, 0.0f))));
    ImGui::BeginGroup();
    ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + width);
    ImGui::PushFont(fonts_.heading);
    ImGui::TextUnformatted(tr("No process selected", "Процесс не выбран"));
    ImGui::PopFont();
    ui::muted_wrapped(tr("Pick the program whose memory you want to study.", "Выберите программу, память которой хотите изучить."));
    ImGui::Spacing();
    if (ui::button(tr("Select process   Ctrl+O", "Выбрать процесс   Ctrl+O"), true, ImVec2(width, std::floor(ImGui::GetFrameHeight() * 1.3f)))) {
        show_picker();
    }
    ImGui::Spacing();
    ui::muted_wrapped(tr("MemHunter only reads memory: it changes nothing in it.", "MemHunter только читает память: он ничего в ней не меняет."));
    ImGui::PopTextWrapPos();
    ImGui::EndGroup();
    ImGui::EndChild();
}

void View::draw_status_bar() {
    ImGui::Separator();
    const auto item = [&](const char* label, const std::string& value) {
        ui::muted(label);
        ImGui::SameLine();
        ui::text(value);
        ImGui::SameLine(0.0f, 24.0f * scale_);
    };
    const ResultsTable& table = session_.table();
    const Job* running = session_.job();
    const PointerRun& pointer_run = session_.pointer_run();
    if (running != nullptr && running->kind() == JobKind::Inspect) {
        item(tr("Time", "Время"), format_seconds(running->elapsed_seconds()));
    } else if (running == nullptr && page_ == Page::Inspect) {
        const FindingList& findings = session_.findings();
        item(tr("Time", "Время"), findings.has_report() ? format_seconds(findings.report().stats.seconds) : std::string("—"));
    } else if (running != nullptr && running->kind() == JobKind::PointerCheck) {
        // A check follows the chains with a few small reads each, so a speed in bytes would mean little.
        item(tr("Time", "Время"), format_seconds(running->elapsed_seconds()));
    } else if (running != nullptr && running->kind() == JobKind::PointerScan) {
        item(tr("Read errors", "Ошибок чтения"), group_digits(running->progress().pointers.reading.read_failures.load(std::memory_order_relaxed)));
        item(tr("Time", "Время"), format_seconds(running->elapsed_seconds()));
    } else if (running == nullptr && page_ == Page::Pointers && pointer_run.threads > 0) {
        item(tr("Time", "Время"), format_seconds(pointer_run.seconds));
        item(tr("Threads", "Потоков"), std::to_string(pointer_run.threads));
        if (pointer_run.kind == JobKind::PointerScan) {
            item(tr("Pointers in memory", "Указателей в памяти"), group_digits(pointer_run.pointers));
            item(tr("Read errors", "Ошибок чтения"), group_digits(pointer_run.read_failures));
        }
    } else if (const Job* job = running) {
        const ScanProgress& progress = job->progress().current();
        const double seconds = job->elapsed_seconds();
        const double bytes = static_cast<double>(progress.bytes_done.load(std::memory_order_relaxed));
        item(tr("Speed", "Скорость"), seconds > 0.0 ? format_rate(bytes / seconds) : std::string("—"));
        item(tr("Read errors", "Ошибок чтения"), group_digits(progress.read_failures.load(std::memory_order_relaxed)));
        item(tr("Time", "Время"), format_seconds(seconds));
    } else if (value_mode() && session_.value_run().threads > 0) {
        const ValueRun& run = session_.value_run();
        const double seconds = session_.last_seconds();
        item(tr("Speed", "Скорость"), seconds > 0.0 ? format_rate(static_cast<double>(run.bytes_read) / seconds) : std::string("—"));
        item(tr("Read errors", "Ошибок чтения"), group_digits(run.read_failures));
        item(tr("Time", "Время"), format_seconds(seconds));
        item(tr("Threads", "Потоков"), std::to_string(run.threads));
    } else if (!value_mode() && table.has_results()) {
        const ScanStats& stats = table.results().stats;
        const double seconds = session_.last_seconds();
        item(tr("Speed", "Скорость"), seconds > 0.0 ? format_rate(static_cast<double>(stats.bytes_read) / seconds) : std::string("—"));
        item(tr("Read errors", "Ошибок чтения"), group_digits(stats.read_failures));
        item(tr("Time", "Время"), format_seconds(seconds));
        item(tr("Threads", "Потоков"), std::to_string(stats.scan_threads));
        item(tr("Algorithm", "Алгоритм"), stats.algorithm);
    } else {
        item(tr("Speed", "Скорость"), "—");
        item(tr("Read errors", "Ошибок чтения"), "—");
        item(tr("Time", "Время"), "—");
    }
    const char* hints = page_ == Page::Watch       ? tr("Del remove    F2 note    Ctrl+C address    Ctrl+D structure    Ctrl+S export", "Del убрать    F2 описание    Ctrl+C адрес    Ctrl+D структура    Ctrl+S экспорт")
                        : page_ == Page::Pointers  ? tr("Insert to the address list    Ctrl+C chain    Ctrl+D structure    Ctrl+S save", "Insert в список адресов    Ctrl+C цепочка    Ctrl+D структура    Ctrl+S сохранить")
                        : page_ == Page::Structure ? tr("F2 field    Del reset    → ← expand    Insert to the address list    Ctrl+C address", "F2 поле    Del сбросить    → ← раскрыть    Insert в список адресов    Ctrl+C адрес")
                        : page_ == Page::Inspect   ? tr("F5 check    Esc stop    Ctrl+C address", "F5 проверить    Esc стоп    Ctrl+C адрес")
                        : page_ == Page::Disasm    ? tr("F5 refresh    Ctrl+C address    Ctrl+B bytes    Ctrl+T text", "F5 обновить    Ctrl+C адрес    Ctrl+B байты    Ctrl+T текст")
                        : value_mode()            ? tr("F5 search    Esc stop    Insert to the list    Ctrl+C address    Ctrl+S export", "F5 искать    Esc стоп    Insert в список    Ctrl+C адрес    Ctrl+S экспорт")
                                                  : tr("F5 find    Esc stop    Ctrl+F filter    Insert to the list    Ctrl+S export", "F5 найти    Esc стоп    Ctrl+F фильтр    Insert в список    Ctrl+S экспорт");
    const float hints_width = ImGui::CalcTextSize(hints).x;
    const float right_edge = ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x;
    if (right_edge - hints_width > ImGui::GetCursorPosX()) {
        ImGui::SameLine(right_edge - hints_width);
        ui::muted(hints);
    } else {
        ImGui::NewLine();
    }
}

void View::refresh_processes() {
    try {
        processes_ = list_processes();
    } catch (const Error& error) {
        processes_.clear();
        picker_error_ = describe_error(error);
    }
}

void View::draw_picker() {
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    const ImVec2 size(std::min(720.0f * scale_, viewport->WorkSize.x - 40.0f), std::min(560.0f * scale_, viewport->WorkSize.y - 40.0f));
    ImGui::SetNextWindowSize(size, ImGuiCond_Always);
    ImGui::SetNextWindowPos(ImVec2(viewport->WorkPos.x + viewport->WorkSize.x * 0.5f, viewport->WorkPos.y + viewport->WorkSize.y * 0.5f),
                            ImGuiCond_Always, ImVec2(0.5f, 0.5f));
    constexpr ImGuiWindowFlags flags =
        ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings;
    if (!ImGui::BeginPopupModal("##picker", nullptr, flags)) {
        return;
    }
    const ImGuiStyle& style = ImGui::GetStyle();
    bool close = ImGui::IsKeyPressed(ImGuiKey_Escape, false);
    std::optional<std::uint32_t> open;

    ui::heading(fonts_.heading, tr("SELECT PROCESS", "ВЫБОР ПРОЦЕССА"));
    const char* refresh_label = tr("Refresh", "Обновить");
    ImGui::SetNextItemWidth(ImGui::GetContentRegionAvail().x - button_width(refresh_label) - style.ItemSpacing.x);
    if (picker_focus_) {
        ImGui::SetKeyboardFocusHere();
        picker_focus_ = false;
    }
    ImGui::InputTextWithHint("##process_filter", tr("Name or PID", "Имя или PID"), &process_filter_);
    ImGui::SameLine();
    if (ui::button(refresh_label)) {
        refresh_processes();
    }

    std::vector<const ProcessEntry*> visible = matching_processes(processes_, process_filter_);

    if (!picker_error_.empty()) {
        ui::inverted_block(picker_error_);
    }
    if (!privilege_error_.empty()) {
        ui::inverted_block(privilege_error_);
    }

    const float footer = ImGui::GetFrameHeight() + style.ItemSpacing.y * 2.0f + 1.0f;
    constexpr ImGuiTableFlags table_flags = ImGuiTableFlags_ScrollY | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersInnerV |
                                            ImGuiTableFlags_Sortable | ImGuiTableFlags_SizingFixedFit;
    if (ImGui::BeginTable("##processes", 4, table_flags, ImVec2(0, std::max(ImGui::GetContentRegionAvail().y - footer, 60.0f)))) {
        ImGui::TableSetupColumn(tr("Name", "Имя"), ImGuiTableColumnFlags_WidthStretch | ImGuiTableColumnFlags_DefaultSort, 0.0f, 0);
        ImGui::TableSetupColumn("PID", 0, 80.0f * scale_, 1);
        ImGui::TableSetupColumn(tr("Threads", "Потоков"), 0, 80.0f * scale_, 2);
        ImGui::TableSetupColumn(tr("Parent", "Родитель"), 0, 90.0f * scale_, 3);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();
        if (ImGuiTableSortSpecs* specs = ImGui::TableGetSortSpecs(); specs != nullptr && specs->SpecsCount > 0) {
            process_sort_ = static_cast<int>(specs->Specs[0].ColumnUserID);
            process_descending_ = specs->Specs[0].SortDirection == ImGuiSortDirection_Descending;
            specs->SpecsDirty = false;
        }
        const auto key_less = [this](const ProcessEntry* a, const ProcessEntry* b) {
            switch (process_sort_) {
                case 1: return a->pid < b->pid;
                case 2: return a->threads != b->threads ? a->threads < b->threads : a->pid < b->pid;
                case 3: return a->parent_pid != b->parent_pid ? a->parent_pid < b->parent_pid : a->pid < b->pid;
                default: {
                    const std::string left = to_lower_ascii(a->name);
                    const std::string right = to_lower_ascii(b->name);
                    return left != right ? left < right : a->pid < b->pid;
                }
            }
        };
        std::stable_sort(visible.begin(), visible.end(), [&](const ProcessEntry* a, const ProcessEntry* b) {
            return process_descending_ ? key_less(b, a) : key_less(a, b);
        });

        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(visible.size()));
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const ProcessEntry& entry = *visible[static_cast<std::size_t>(row)];
                const bool is_selected = picked_pid_ == entry.pid;
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::PushID(static_cast<int>(entry.pid));
                if (is_selected) {
                    ImGui::PushStyleColor(ImGuiCol_Text, theme::kBlack);
                    ImGui::PushStyleColor(ImGuiCol_HeaderHovered, theme::kWhite);
                    ImGui::PushStyleColor(ImGuiCol_HeaderActive, theme::kWhite);
                }
                if (ImGui::Selectable(entry.name.c_str(), is_selected,
                                      ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                    picked_pid_ = entry.pid;
                    if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) {
                        open = entry.pid;
                    }
                }
                ImGui::TableSetColumnIndex(1);
                ui::text(std::to_string(entry.pid));
                ImGui::TableSetColumnIndex(2);
                ui::text(std::to_string(entry.threads));
                ImGui::TableSetColumnIndex(3);
                ui::text(std::to_string(entry.parent_pid));
                if (is_selected) {
                    ImGui::PopStyleColor(3);
                }
                ImGui::PopID();
            }
        }
        ImGui::EndTable();
    }

    const std::optional<std::uint32_t> choice = picker_choice(visible, picked_pid_);
    if (!open && (ImGui::IsKeyPressed(ImGuiKey_Enter, false) || ImGui::IsKeyPressed(ImGuiKey_KeypadEnter, false))) {
        open = choice;
    }

    ImGui::Separator();
    ImGui::AlignTextToFramePadding();
    ui::muted(group_digits(visible.size()) + tr(" of ", " из ") + group_digits(processes_.size()));
    ImGui::SameLine(0.0f, 24.0f * scale_);
    bool privileged = debug_privilege_;
    if (ImGui::Checkbox(tr("Debug rights", "Права отладки"), &privileged)) {
        if (set_debug_privilege(privileged)) {
            picker_error_.clear();
        }
    }
    ImGui::SetItemTooltip("%s", tr("SeDebugPrivilege: opens processes of other users and services. MemHunter must be run as "
                                   "administrator. Protected processes (PPL) stay closed regardless.",
                                   "SeDebugPrivilege: открывает процессы других пользователей и служб. Нужен запуск MemHunter от имени "
                                   "администратора. Защищённые процессы (PPL) не открываются и так."));
    const char* open_label = tr("Open", "Открыть");
    const char* cancel_label = tr("Cancel", "Отмена");
    const float buttons = button_width(open_label) + button_width(cancel_label) + style.ItemSpacing.x;
    ImGui::SameLine(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x - buttons);
    if (ui::button(open_label, choice.has_value())) {
        open = choice;
    }
    ImGui::SameLine();
    if (ui::button(cancel_label)) {
        close = true;
    }

    if (open) {
        picked_pid_ = *open;
        if (attach(*open)) {
            close = true;
        }
    }
    if (close) {
        picker_error_.clear();
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

}  // namespace mh::gui
