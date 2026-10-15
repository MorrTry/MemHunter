#include "tui/app.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <optional>

#include "common/error.hpp"
#include "common/text.hpp"
#include "results/export.hpp"
#include "tui/scan_task.hpp"
#include "tui/screen.hpp"
#include "tui/terminal.hpp"
#include "tui/view.hpp"

namespace mh::tui {

using namespace std::chrono_literals;

void save_results(State& state) {
    const std::string path = state.save_path.utf8();
    const std::vector<std::size_t> rows = rows_to_save(state);
    std::ofstream out(std::filesystem::path(utf8_to_wide(path)), std::ios::binary | std::ios::trunc);
    if (!out) {
        state.message = "Cannot create '" + path + "'";
        return;
    }
    write_results(out, format_for_path(path), state.results, rows, ExportOptions{});
    out.close();
    if (!out) {
        state.message = "Writing '" + path + "' failed; the file may be incomplete";
        return;
    }
    const std::string count = count_matches(rows.size());
    state.message = "Saved " + (state.marked_count > 0 ? count.substr(0, count.find(' ')) + " marked" + count.substr(count.find(' ')) : count) +
                    " to " + path;
}

int run_app(const MemorySource& memory, const ProcessSummary& process, const AppOptions& options) {
    Terminal terminal;
    State state(process);
    state.threads = options.threads;
    std::unique_ptr<ScanTask> task;
    std::optional<Screen> shown;

    for (;;) {
        if (task) {
            state.progress = read_progress(task->progress(), task->elapsed_seconds());
            if (task->finished()) {
                const ProgressView final_progress = state.progress;
                try {
                    finish_scan(state, task->take(), final_progress);
                } catch (const Error& error) {
                    fail_scan(state, std::string("Scan failed: ") + error.what());
                }
                task.reset();
            }
        }

        const TerminalSize size = terminal.size();
        Screen screen(size.width, size.height);
        draw(screen, state);
        terminal.write(render(screen, shown ? &*shown : nullptr));
        shown = std::move(screen);

        // Short waits while scanning keep the progress panel live; when idle the loop only wakes for input
        // and to notice a resized window.
        const std::optional<Key> key = terminal.read_key(task ? 100ms : 250ms);
        if (!key) {
            continue;
        }
        const Layout layout = layout_for(size.width, size.height);
        switch (handle_key(state, *key, layout.page_rows)) {
            case Command::StartScan:
                try {
                    ScanRequest request = build_request(state);
                    begin_scan(state);
                    task = std::make_unique<ScanTask>(memory, std::move(request), process);
                } catch (const Error& error) {
                    state.message = error.what();
                }
                break;
            case Command::CancelScan:
                if (task) {
                    task->cancel();
                    state.message = "Cancelling...";
                }
                break;
            case Command::Save: save_results(state); break;
            case Command::Quit: return 0;
            case Command::None: break;
        }
    }
}

}  // namespace mh::tui
