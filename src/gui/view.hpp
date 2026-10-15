#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "gui/results_table.hpp"
#include "gui/search.hpp"
#include "gui/session.hpp"
#include "gui/theme.hpp"
#include "gui/value_table.hpp"
#include "gui/watch_list.hpp"
#include "memory/region.hpp"
#include "process/process.hpp"

namespace mh::gui {

// Exported results, saved chains of pointers, or the fields of a structure.
enum class FileKind : std::uint8_t { Export, Pointers, Structure };

// What the view needs from the window it is drawn in.
class Platform {
public:
    virtual ~Platform() = default;
    // nullopt when the user cancelled; throws Error when the dialog itself failed.
    virtual std::optional<std::filesystem::path> ask_save_path(const std::wstring& suggested_name, FileKind kind) = 0;
    virtual std::optional<std::filesystem::path> ask_open_path(FileKind kind) = 0;
    virtual void set_title(const std::string& title) = 0;
};

enum class Page : std::uint8_t { Results, Regions, Watch, Pointers, Structure, Inspect };

// Draws the whole window once per frame and turns clicks and shortcuts into Session calls. All presentation
// lives here and in theme/widgets; scanning stays in Session.
class View {
public:
    View(Session& session, Platform& platform, const theme::Fonts& fonts);

    // Opens the process given on the command line (a PID or an executable name); errors land in the picker.
    void open_from_command_line(const std::string& pid_or_name);
    void show_picker();
    // Turns SeDebugPrivilege on or off for MemHunter; a failure is shown in the process picker.
    bool set_debug_privilege(bool enabled);

    void set_scale(float scale) noexcept { scale_ = scale; }
    void draw();
    // How long the window may sleep before the next frame when there is no input: short while a job runs,
    // longer while the live memory view refreshes, and about a second otherwise to notice that the target exited.
    unsigned frame_interval_ms() const;

private:
    bool attach(std::uint32_t pid);
    // The number search scans values and narrows them down by later scans.
    bool value_mode() const noexcept { return form_.mode == SearchMode::Number; }
    bool can_export() const;
    void handle_shortcuts();
    void start_scan();
    void export_results();
    void update_title();

    void draw_top_bar();
    void draw_search_panel(float width, float height);
    void draw_search_inputs();
    void draw_value_inputs();
    void draw_scan_button();
    void draw_value_history();
    void draw_memory_options();
    void draw_compare_options();
    void draw_parameters();
    void draw_progress_panel();
    void draw_page_switch();
    void draw_results(float height);
    void draw_results_table(float height);
    void draw_value_table(float height);
    void keep_selection_visible(float row_height);
    void draw_details(float height);
    void draw_match_info(const Match& match, float value_x);
    void draw_value_info(const ValueCandidate& value, float value_x);
    void draw_region_fields(const Region* region, std::uint64_t address, std::string_view module, float value_x);
    void draw_dump(const Match& match);
    void draw_regions(float height);
    void draw_status_bar();
    void draw_picker();
    void draw_no_process(float height);

    void refresh_regions();
    void rebuild_region_rows();
    void refresh_processes();
    void refresh_dump(const Match& match);
    void copy_address(std::uint64_t address);

    // The address list; drawn in watch_view.cpp.
    std::optional<WatchEntry> selected_as_watch() const;
    void open_add_watch();
    void start_editing_description(std::size_t row);
    void handle_watch_shortcuts(bool copy);
    void draw_watch_bar(float right_edge);
    void draw_watch_table(float height);
    void draw_watch_info(std::size_t row, float value_x);
    void draw_add_watch();
    void draw_clear_watch();

    // Chains of pointers; drawn in pointer_view.cpp.
    void open_pointer_scan();
    void open_pointer_check();
    void save_pointers();
    void load_pointers();
    void handle_pointer_shortcuts(bool copy);
    void draw_pointer_progress(const Job& job);
    void draw_pointer_summary();
    void draw_pointer_bar(float right_edge);
    void draw_pointer_table(float height);
    void draw_pointer_info(std::size_t row, float value_x);
    void draw_pointer_scan();
    void draw_pointer_check();
    void draw_clear_pointers();

    // The fields of a structure; drawn in struct_view.cpp.
    void open_struct_from_selection();
    void open_struct_dialog(std::optional<StructStart> start, std::optional<StructField> known = std::nullopt);
    void open_field_dialog(std::optional<std::size_t> row);
    void open_instance_dialog();
    void save_structure();
    void load_structure();
    void copy_struct_field(std::size_t row);
    void handle_struct_shortcuts(bool copy);
    void draw_struct_bar(float right_edge);
    void draw_struct_table(float height);
    void draw_struct_info(std::size_t row, float value_x);
    void draw_struct_open();
    void draw_struct_field();
    void draw_struct_instance();

    // Injected code; drawn in inspect_view.cpp.
    void start_inspect();
    void handle_inspect_shortcuts(bool copy);
    void draw_inspect_progress(const Job* running);
    float inspect_bar_width() const;
    void draw_inspect_bar(float right_edge);
    void draw_inspect_table(float height);
    void draw_finding_info(const Finding& finding, float value_x);

    Session& session_;
    Platform& platform_;
    const theme::Fonts& fonts_;

    SearchForm form_;
    bool only_changed_ = false;
    Page page_ = Page::Results;
    PreviewMode preview_ = PreviewMode::Hex;
    std::string filter_;
    bool focus_filter_ = false;
    bool scroll_to_selection_ = false;
    std::string title_;
    float scale_ = 1.0f;
    bool focus_search_ = false;
    bool alive_ = false;
    int page_rows_ = 10;

    bool picker_requested_ = false;
    bool picker_focus_ = false;
    std::vector<ProcessEntry> processes_;
    std::string process_filter_;
    std::optional<std::uint32_t> picked_pid_;
    std::string picker_error_;
    int process_sort_ = 0;
    bool process_descending_ = false;
    bool debug_privilege_ = false;
    std::string privilege_error_;

    std::vector<Region> regions_;
    bool regions_loaded_ = false;
    bool readable_regions_only_ = true;
    std::string region_filter_;
    std::vector<std::size_t> region_rows_;

    MemoryDump dump_;
    std::optional<std::uint64_t> dump_match_;
    std::chrono::steady_clock::time_point dump_time_;
    bool live_dump_ = true;
    std::chrono::steady_clock::time_point values_time_;

    std::chrono::steady_clock::time_point watch_time_;
    std::optional<std::size_t> editing_row_;
    std::string description_edit_;
    bool focus_description_ = false;
    bool add_watch_requested_ = false;
    bool add_watch_focus_ = false;
    bool clear_watch_requested_ = false;
    std::string add_address_;
    WatchType add_type_ = WatchType::Int32;
    int add_length_ = 16;
    std::string add_description_;
    std::string add_error_;

    std::chrono::steady_clock::time_point pointers_time_;
    bool pointer_scan_requested_ = false;
    bool pointer_check_requested_ = false;
    bool clear_pointers_requested_ = false;
    bool pointer_focus_ = false;
    std::size_t pointer_row_ = 0;
    int pointer_depth_ = 5;
    std::string pointer_offset_ = "0x1000";
    std::string pointer_error_;
    PointerCheckForm check_form_;

    bool struct_open_requested_ = false;
    bool struct_field_requested_ = false;
    bool struct_instance_requested_ = false;
    bool struct_focus_ = false;
    std::string struct_error_;
    std::string struct_base_;
    std::string struct_size_;
    // The focus and the known field apply while the base is the one suggested.
    std::string struct_suggested_base_;
    std::optional<std::uint32_t> struct_focus_offset_;
    std::optional<StructField> struct_known_;
    std::string field_offset_;
    FieldType field_type_ = FieldType::Int32;
    int field_length_ = 16;
    std::string field_name_;
    std::string instance_base_;
    std::string struct_resize_;
    bool struct_resizing_ = false;
};

}  // namespace mh::gui
