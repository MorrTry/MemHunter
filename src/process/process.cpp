#include "process/process.hpp"

#include <tlhelp32.h>

#include <limits>

#include "common/error.hpp"
#include "common/text.hpp"

namespace mh {

static_assert(sizeof(void*) == 8, "a 32-bit MemHunter cannot address the memory of 64-bit processes");

std::vector<ProcessEntry> list_processes() {
    UniqueHandle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (!snapshot) {
        throw_win32(ErrorCode::SystemError, "cannot list running processes", GetLastError());
    }
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    std::vector<ProcessEntry> processes;
    if (!Process32FirstW(snapshot.get(), &entry)) {
        return processes;
    }
    do {
        processes.push_back({entry.th32ProcessID, entry.th32ParentProcessID, entry.cntThreads,
                             wide_to_utf8(entry.szExeFile)});
    } while (Process32NextW(snapshot.get(), &entry));
    return processes;
}

std::uint32_t resolve_process(std::string_view pid_or_name) {
    if (!pid_or_name.empty() && pid_or_name.find_first_not_of("0123456789") == std::string_view::npos) {
        const auto pid = parse_uint(pid_or_name);
        if (!pid || *pid > std::numeric_limits<std::uint32_t>::max()) {
            throw Error(ErrorCode::InvalidArgument, "invalid PID '" + std::string(pid_or_name) + "'");
        }
        return static_cast<std::uint32_t>(*pid);
    }
    const std::string with_extension = std::string(pid_or_name) + ".exe";
    std::vector<std::uint32_t> found;
    for (const auto& entry : list_processes()) {
        if (iequals_ascii(entry.name, pid_or_name) || iequals_ascii(entry.name, with_extension)) {
            found.push_back(entry.pid);
        }
    }
    if (found.empty()) {
        throw Error(ErrorCode::ProcessNotFound, "no running process named '" + std::string(pid_or_name) + "'");
    }
    if (found.size() > 1) {
        std::string pids;
        for (const auto pid : found) {
            pids += (pids.empty() ? "" : ", ") + std::to_string(pid);
        }
        throw Error(ErrorCode::InvalidArgument, std::to_string(found.size()) + " processes are named '" +
                                                    std::string(pid_or_name) + "' (PIDs " + pids +
                                                    "); specify a PID instead");
    }
    return found.front();
}

Process Process::open(std::uint32_t pid) {
    // VirtualQueryEx needs PROCESS_QUERY_INFORMATION (the limited right is not enough), ReadProcessMemory
    // needs PROCESS_VM_READ and SYNCHRONIZE lets us detect that the target exited mid-scan.
    constexpr DWORD rights = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE;
    const std::string label = "process " + std::to_string(pid);
    HANDLE raw = OpenProcess(rights, FALSE, pid);
    if (raw == nullptr) {
        const DWORD error = GetLastError();
        if (error == ERROR_INVALID_PARAMETER) {
            throw Error(ErrorCode::ProcessNotFound, "no process with PID " + std::to_string(pid));
        }
        if (error == ERROR_ACCESS_DENIED) {
            throw Error(ErrorCode::AccessDenied,
                        "access to " + label +
                            " was denied. Processes of other users and elevated processes require an elevated "
                            "prompt; protected and system processes cannot be read at all, and a process can "
                            "also deny access to itself through its security descriptor");
        }
        throw_win32(ErrorCode::SystemError, "cannot open " + label, error);
    }

    Process process;
    process.pid_ = pid;
    process.handle_.reset(raw);
    if (!process.is_running()) {
        throw Error(ErrorCode::ProcessExited, label + " has already exited");
    }

    std::wstring path(32768, L'\0');
    DWORD length = static_cast<DWORD>(path.size());
    if (QueryFullProcessImageNameW(raw, 0, path.data(), &length)) {
        path.resize(length);
        process.image_path_ = wide_to_utf8(path);
    }

    FILETIME creation{};
    FILETIME exit{};
    FILETIME kernel{};
    FILETIME user{};
    if (GetProcessTimes(raw, &creation, &exit, &kernel, &user)) {
        process.creation_time_ = (static_cast<std::uint64_t>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
    }

    BOOL wow64 = FALSE;
    if (IsWow64Process(raw, &wow64)) {
        process.wow64_ = wow64 != FALSE;
    }
    return process;
}

std::string Process::image_name() const {
    const auto slash = image_path_.find_last_of("\\/");
    return slash == std::string::npos ? image_path_ : image_path_.substr(slash + 1);
}

bool Process::is_running() const noexcept {
    return WaitForSingleObject(handle_.get(), 0) == WAIT_TIMEOUT;
}

}  // namespace mh
