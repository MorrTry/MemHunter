#include "support/child_process.hpp"

#include <stdexcept>
#include <thread>

#include "common/error.hpp"
#include "common/text.hpp"

namespace mh::testing {

namespace {

struct Pipe {
    UniqueHandle read;
    UniqueHandle write;
};

Pipe make_pipe(bool inherit_read) {
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE};
    HANDLE read = nullptr;
    HANDLE write = nullptr;
    if (CreatePipe(&read, &write, &attributes, 0) == 0) {
        throw_win32(ErrorCode::SystemError, "CreatePipe", GetLastError());
    }
    Pipe pipe{UniqueHandle(read), UniqueHandle(write)};
    SetHandleInformation(inherit_read ? pipe.write.get() : pipe.read.get(), HANDLE_FLAG_INHERIT, 0);
    return pipe;
}

std::wstring command_line(const std::string& executable, const std::vector<std::string>& args) {
    std::string line = quote_argument(executable);
    for (const auto& arg : args) {
        line += ' ';
        line += quote_argument(arg);
    }
    return utf8_to_wide(line);
}

std::wstring native_path(const std::string& path) {
    std::wstring wide = utf8_to_wide(path);
    for (auto& c : wide) {
        if (c == L'/') {
            c = L'\\';
        }
    }
    return wide;
}

UniqueHandle spawn(const std::string& executable, const std::vector<std::string>& args, HANDLE in, HANDLE out, HANDLE err,
                   std::uint32_t& pid) {
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = in;
    startup.hStdOutput = out;
    startup.hStdError = err;
    PROCESS_INFORMATION info{};
    std::wstring line = command_line(executable, args);
    const std::wstring path = native_path(executable);
    if (CreateProcessW(path.c_str(), line.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &info) == 0) {
        throw_win32(ErrorCode::SystemError, "CreateProcess " + executable, GetLastError());
    }
    CloseHandle(info.hThread);
    pid = info.dwProcessId;
    return UniqueHandle(info.hProcess);
}

std::string read_all(HANDLE handle) {
    std::string text;
    char buffer[4096];
    DWORD got = 0;
    while (ReadFile(handle, buffer, sizeof(buffer), &got, nullptr) != 0 && got != 0) {
        text.append(buffer, got);
    }
    return text;
}

}  // namespace

std::string quote_argument(std::string_view argument) {
    if (!argument.empty() && argument.find_first_of(" \t\n\v\"") == std::string_view::npos) {
        return std::string(argument);
    }
    std::string out = "\"";
    std::size_t backslashes = 0;
    for (const char c : argument) {
        if (c == '\\') {
            ++backslashes;
            continue;
        }
        if (c == '"') {
            out.append(backslashes * 2 + 1, '\\');
        } else {
            out.append(backslashes, '\\');
        }
        backslashes = 0;
        out.push_back(c);
    }
    out.append(backslashes * 2, '\\');
    out.push_back('"');
    return out;
}

ChildProcess::ChildProcess(const std::string& executable, const std::vector<std::string>& args) {
    Pipe in = make_pipe(true);
    Pipe out = make_pipe(false);
    process_ = spawn(executable, args, in.read.get(), out.write.get(), GetStdHandle(STD_ERROR_HANDLE), pid_);
    input_ = std::move(in.write);
    output_ = std::move(out.read);
}

ChildProcess::~ChildProcess() {
    close_input();
    if (!wait(5000)) {
        kill();
    }
}

std::optional<std::string> ChildProcess::read_line() {
    for (;;) {
        if (const auto newline = pending_.find('\n'); newline != std::string::npos) {
            std::string line = pending_.substr(0, newline);
            pending_.erase(0, newline + 1);
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            return line;
        }
        char buffer[4096];
        DWORD got = 0;
        if (ReadFile(output_.get(), buffer, sizeof(buffer), &got, nullptr) == 0 || got == 0) {
            return std::nullopt;
        }
        pending_.append(buffer, got);
    }
}

void ChildProcess::write_line(std::string_view line) {
    std::string text(line);
    text += '\n';
    DWORD written = 0;
    if (WriteFile(input_.get(), text.data(), static_cast<DWORD>(text.size()), &written, nullptr) == 0 || written != text.size()) {
        throw std::runtime_error("cannot write to the child process");
    }
}

void ChildProcess::close_input() {
    input_.reset();
}

std::optional<std::uint32_t> ChildProcess::wait(std::uint32_t timeout_ms) {
    if (!process_ || WaitForSingleObject(process_.get(), timeout_ms) != WAIT_OBJECT_0) {
        return std::nullopt;
    }
    DWORD code = 0;
    GetExitCodeProcess(process_.get(), &code);
    return code;
}

void ChildProcess::kill() {
    if (process_) {
        TerminateProcess(process_.get(), 1);
        WaitForSingleObject(process_.get(), 5000);
    }
}

RunResult run_program(const std::string& executable, const std::vector<std::string>& args, std::uint32_t timeout_ms) {
    Pipe out = make_pipe(false);
    Pipe err = make_pipe(false);
    UniqueHandle null_input(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
    SetHandleInformation(null_input.get(), HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    std::uint32_t pid = 0;
    UniqueHandle process = spawn(executable, args, null_input.get(), out.write.get(), err.write.get(), pid);
    out.write.reset();
    err.write.reset();

    RunResult result;
    std::thread error_reader([&] { result.err = read_all(err.read.get()); });
    result.out = read_all(out.read.get());
    error_reader.join();
    if (WaitForSingleObject(process.get(), timeout_ms) != WAIT_OBJECT_0) {
        TerminateProcess(process.get(), 1);
        throw std::runtime_error("program timed out: " + executable);
    }
    DWORD code = 0;
    GetExitCodeProcess(process.get(), &code);
    result.exit_code = code;
    return result;
}

}  // namespace mh::testing
