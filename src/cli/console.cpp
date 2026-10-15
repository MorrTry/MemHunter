#include "cli/console.hpp"

#include <windows.h>
#include <fcntl.h>
#include <io.h>
#include <shellapi.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <mutex>

#include "common/error.hpp"
#include "common/text.hpp"

namespace mh::cli {

namespace {

using namespace std::chrono_literals;

// SetConsoleCtrlHandler takes a plain function without a context argument, so the active stop source has to
// live at namespace scope. Only InterruptScope writes it.
std::atomic<std::stop_source*> g_interrupt_source{nullptr};

BOOL WINAPI on_console_control(DWORD type) {
    if (type != CTRL_C_EVENT && type != CTRL_BREAK_EVENT) {
        return FALSE;
    }
    std::stop_source* source = g_interrupt_source.load();
    if (source == nullptr || source->stop_requested()) {
        return FALSE;
    }
    source->request_stop();
    return TRUE;
}

bool is_console(DWORD which) {
    const HANDLE handle = GetStdHandle(which);
    DWORD mode = 0;
    return handle != nullptr && handle != INVALID_HANDLE_VALUE && GetFileType(handle) == FILE_TYPE_CHAR &&
           GetConsoleMode(handle, &mode) != 0;
}

std::size_t stderr_columns() {
    CONSOLE_SCREEN_BUFFER_INFO info{};
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_ERROR_HANDLE), &info) == 0) {
        return 80;
    }
    return static_cast<std::size_t>(std::max<SHORT>(info.srWindow.Right - info.srWindow.Left + 1, 20));
}

}  // namespace

ConsoleSession::ConsoleSession()
    : old_output_cp_(GetConsoleOutputCP()),
      old_input_cp_(GetConsoleCP()),
      stdout_console_(is_console(STD_OUTPUT_HANDLE)),
      stderr_console_(is_console(STD_ERROR_HANDLE)) {
    if (old_output_cp_ != 0) {
        SetConsoleOutputCP(CP_UTF8);
    }
    if (old_input_cp_ != 0) {
        SetConsoleCP(CP_UTF8);
    }
    // Writers emit exact line endings (CRLF for CSV); text mode would turn them into CR CR LF.
    _setmode(_fileno(stdout), _O_BINARY);
}

ConsoleSession::~ConsoleSession() {
    std::fflush(stdout);
    std::fflush(stderr);
    if (old_output_cp_ != 0) {
        SetConsoleOutputCP(old_output_cp_);
    }
    if (old_input_cp_ != 0) {
        SetConsoleCP(old_input_cp_);
    }
}

std::vector<std::string> utf8_arguments() {
    int count = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &count);
    if (argv == nullptr) {
        throw_win32(ErrorCode::SystemError, "cannot parse the command line", GetLastError());
    }
    std::vector<std::string> args;
    try {
        for (int i = 1; i < count; ++i) {
            args.push_back(wide_to_utf8(argv[i]));
        }
    } catch (...) {
        LocalFree(argv);
        throw;
    }
    LocalFree(argv);
    return args;
}

InterruptScope::InterruptScope(std::stop_source& source) {
    g_interrupt_source.store(&source);
    if (SetConsoleCtrlHandler(on_console_control, TRUE) == 0) {
        g_interrupt_source.store(nullptr);
        throw_win32(ErrorCode::SystemError, "cannot install the Ctrl+C handler", GetLastError());
    }
}

InterruptScope::~InterruptScope() {
    SetConsoleCtrlHandler(on_console_control, FALSE);
    g_interrupt_source.store(nullptr);
}

namespace {

std::string scan_progress_text(const ScanProgress& progress, const std::string& counter, double elapsed) {
    const std::uint64_t total = progress.bytes_total.load(std::memory_order_relaxed);
    const std::uint64_t done = progress.bytes_done.load(std::memory_order_relaxed);
    const double percent = total == 0 ? 0.0 : 100.0 * static_cast<double>(done) / static_cast<double>(total);

    std::array<char, 32> percent_text{};
    std::snprintf(percent_text.data(), percent_text.size(), "%5.1f%%", percent);
    std::string line = std::string(percent_text.data()) + "  " + format_size(done) + " / " + format_size(total) + "  " +
                       format_rate(elapsed > 0 ? static_cast<double>(done) / elapsed : 0);
    if (!counter.empty()) {
        line += "  " + counter + " " + std::to_string(progress.matches.load(std::memory_order_relaxed));
    }
    if (const auto failures = progress.read_failures.load(std::memory_order_relaxed); failures != 0) {
        line += "  unreadable ranges " + std::to_string(failures);
    }
    return line;
}

}  // namespace

ProgressLine::ProgressLine(const ScanProgress& progress, bool enabled, std::string counter)
    : ProgressLine([&progress, counter = std::move(counter)](double elapsed) { return scan_progress_text(progress, counter, elapsed); },
                   enabled) {}

ProgressLine::ProgressLine(std::function<std::string(double)> text, bool enabled)
    : text_(std::move(text)), started_(std::chrono::steady_clock::now()) {
    if (enabled) {
        thread_ = std::jthread([this](std::stop_token stop) { run(std::move(stop)); });
    }
}

ProgressLine::~ProgressLine() {
    finish();
}

void ProgressLine::finish() {
    if (!thread_.joinable()) {
        return;
    }
    thread_.request_stop();
    thread_.join();
    clear();
}

void ProgressLine::run(std::stop_token stop) {
    std::mutex mutex;
    std::condition_variable_any wake;
    std::unique_lock lock(mutex);
    while (!stop.stop_requested()) {
        wake.wait_for(lock, stop, 250ms, [] { return false; });
        if (!stop.stop_requested()) {
            draw();
        }
    }
}

void ProgressLine::draw() {
    const double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - started_).count();
    std::string line = text_(elapsed);
    line.resize(std::min(line.size(), stderr_columns() - 1));

    const std::size_t width = line.size();
    if (width < last_width_) {
        line.append(last_width_ - width, ' ');
    }
    last_width_ = width;
    std::fputc('\r', stderr);
    std::fputs(line.c_str(), stderr);
    std::fflush(stderr);
}

void ProgressLine::clear() {
    if (last_width_ == 0) {
        return;
    }
    std::fputc('\r', stderr);
    std::fputs(std::string(last_width_, ' ').c_str(), stderr);
    std::fputc('\r', stderr);
    std::fflush(stderr);
    last_width_ = 0;
}

}  // namespace mh::cli
