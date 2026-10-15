#include "common/error.hpp"

#include <windows.h>

#include "common/text.hpp"

namespace mh {

std::string win32_message(std::uint32_t error) {
    wchar_t* buffer = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD length = FormatMessageW(flags, nullptr, error, MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US),
                                        reinterpret_cast<wchar_t*>(&buffer), 0, nullptr);
    std::string text;
    if (length != 0 && buffer != nullptr) {
        text = wide_to_utf8(std::wstring_view(buffer, length));
        LocalFree(buffer);
    } else {
        // The English message table is missing on some localized systems.
        const DWORD fallback = FormatMessageW(flags, nullptr, error, 0, reinterpret_cast<wchar_t*>(&buffer), 0, nullptr);
        if (fallback != 0 && buffer != nullptr) {
            text = wide_to_utf8(std::wstring_view(buffer, fallback));
            LocalFree(buffer);
        }
    }
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r' || text.back() == ' ' || text.back() == '.')) {
        text.pop_back();
    }
    if (text.empty()) {
        text = "unknown error";
    }
    return text + " (Win32 error " + std::to_string(error) + ")";
}

void throw_win32(ErrorCode code, const std::string& context, std::uint32_t error) {
    throw Error(code, context + ": " + win32_message(error));
}

}  // namespace mh
