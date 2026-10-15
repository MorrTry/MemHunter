#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>

namespace mh {

enum class ErrorCode {
    InvalidArgument,
    InvalidPattern,
    ProcessNotFound,
    AccessDenied,
    ProcessExited,
    SystemError,
    Io,
    CorruptSnapshot,
    IncompatibleSnapshot,
};

class Error : public std::runtime_error {
public:
    Error(ErrorCode code, const std::string& message) : std::runtime_error(message), code_(code) {}

    ErrorCode code() const noexcept { return code_; }

private:
    ErrorCode code_;
};

std::string win32_message(std::uint32_t error);

[[noreturn]] void throw_win32(ErrorCode code, const std::string& context, std::uint32_t error);

}  // namespace mh
