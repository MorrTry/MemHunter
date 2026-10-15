#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "process/handle.hpp"

namespace mh {

struct ProcessEntry {
    std::uint32_t pid = 0;
    std::uint32_t parent_pid = 0;
    std::uint32_t threads = 0;
    std::string name;
};

std::vector<ProcessEntry> list_processes();

// Accepts a decimal PID or an executable name ("notepad.exe", "notepad"); throws if the name is ambiguous.
std::uint32_t resolve_process(std::string_view pid_or_name);

class Process {
public:
    static Process open(std::uint32_t pid);

    std::uint32_t pid() const noexcept { return pid_; }
    HANDLE handle() const noexcept { return handle_.get(); }
    const std::string& image_path() const noexcept { return image_path_; }
    std::string image_name() const;
    std::uint64_t creation_time() const noexcept { return creation_time_; }
    bool is_wow64() const noexcept { return wow64_; }
    bool is_running() const noexcept;

private:
    Process() = default;

    std::uint32_t pid_ = 0;
    UniqueHandle handle_;
    std::string image_path_;
    std::uint64_t creation_time_ = 0;
    bool wow64_ = false;
};

}  // namespace mh
