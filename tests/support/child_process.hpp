#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "process/handle.hpp"

namespace mh::testing {

std::string quote_argument(std::string_view argument);

// A child process with its stdin and stdout connected to pipes, for driving the test target line by line.
class ChildProcess {
public:
    ChildProcess(const std::string& executable, const std::vector<std::string>& args);
    ~ChildProcess();
    ChildProcess(const ChildProcess&) = delete;
    ChildProcess& operator=(const ChildProcess&) = delete;

    std::uint32_t pid() const noexcept { return pid_; }
    std::optional<std::string> read_line();
    void write_line(std::string_view line);
    void close_input();
    std::optional<std::uint32_t> wait(std::uint32_t timeout_ms);
    void kill();

private:
    UniqueHandle process_;
    UniqueHandle input_;
    UniqueHandle output_;
    std::uint32_t pid_ = 0;
    std::string pending_;
};

struct RunResult {
    std::uint32_t exit_code = 0;
    std::string out;
    std::string err;
};

// Runs a program to completion with captured stdout and stderr.
RunResult run_program(const std::string& executable, const std::vector<std::string>& args, std::uint32_t timeout_ms = 60000);

}  // namespace mh::testing
