#pragma once

#include <chrono>
#include <cstddef>
#include <functional>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

#include "pipeline/scan_engine.hpp"

namespace mh::cli {

// Switches console code pages to UTF-8 for the lifetime of the object and restores them afterwards.
class ConsoleSession {
public:
    ConsoleSession();
    ~ConsoleSession();
    ConsoleSession(const ConsoleSession&) = delete;
    ConsoleSession& operator=(const ConsoleSession&) = delete;

    bool stdout_is_console() const noexcept { return stdout_console_; }
    bool stderr_is_console() const noexcept { return stderr_console_; }

private:
    unsigned old_output_cp_ = 0;
    unsigned old_input_cp_ = 0;
    bool stdout_console_ = false;
    bool stderr_console_ = false;
};

// Command line arguments after the program name, converted from the UTF-16 command line.
std::vector<std::string> utf8_arguments();

// Routes Ctrl+C and Ctrl+Break to `source` while alive. The first press requests a cooperative stop so that
// partial results are still written; a second press falls through to the default handler and ends the process.
class InterruptScope {
public:
    explicit InterruptScope(std::stop_source& source);
    ~InterruptScope();
    InterruptScope(const InterruptScope&) = delete;
    InterruptScope& operator=(const InterruptScope&) = delete;
};

// Redraws one status line on stderr several times per second from its own thread; never touches stdout.
class ProgressLine {
public:
    // An empty counter label hides the match counter.
    ProgressLine(const ScanProgress& progress, bool enabled, std::string counter = "matches");
    // Draws what `text` returns for the seconds since the start.
    ProgressLine(std::function<std::string(double)> text, bool enabled);
    ~ProgressLine();
    ProgressLine(const ProgressLine&) = delete;
    ProgressLine& operator=(const ProgressLine&) = delete;

    void finish();

private:
    void run(std::stop_token stop);
    void draw();
    void clear();

    std::function<std::string(double)> text_;
    std::chrono::steady_clock::time_point started_;
    std::size_t last_width_ = 0;
    std::jthread thread_;
};

}  // namespace mh::cli
