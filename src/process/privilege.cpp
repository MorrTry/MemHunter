#include "process/privilege.hpp"

#include <windows.h>

#include <cstddef>
#include <vector>

#include "common/error.hpp"
#include "process/handle.hpp"

namespace mh {

namespace {

UniqueHandle own_token(DWORD access) {
    HANDLE raw = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), access, &raw)) {
        throw_win32(ErrorCode::SystemError, "cannot open the access token of MemHunter", GetLastError());
    }
    return UniqueHandle(raw);
}

LUID debug_luid() {
    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid)) {
        throw_win32(ErrorCode::SystemError, "cannot look up SeDebugPrivilege", GetLastError());
    }
    return luid;
}

// True when the token holds the privilege, whatever its state was.
bool set_debug_privilege(bool enabled) {
    const UniqueHandle token = own_token(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY);
    TOKEN_PRIVILEGES privileges{};
    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = debug_luid();
    privileges.Privileges[0].Attributes = enabled ? SE_PRIVILEGE_ENABLED : 0;
    if (!AdjustTokenPrivileges(token.get(), FALSE, &privileges, sizeof(privileges), nullptr, nullptr)) {
        throw_win32(ErrorCode::SystemError, "cannot change SeDebugPrivilege", GetLastError());
    }
    return GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}

}  // namespace

void enable_debug_privilege() {
    if (!set_debug_privilege(true)) {
        throw Error(ErrorCode::AccessDenied,
                    "--debug-privilege needs MemHunter to run as administrator: only an elevated token holds SeDebugPrivilege");
    }
}

void disable_debug_privilege() {
    set_debug_privilege(false);
}

bool debug_privilege_enabled() {
    const UniqueHandle token = own_token(TOKEN_QUERY);
    DWORD size = 0;
    GetTokenInformation(token.get(), TokenPrivileges, nullptr, 0, &size);
    std::vector<std::byte> buffer(size);
    if (size == 0 || !GetTokenInformation(token.get(), TokenPrivileges, buffer.data(), size, &size)) {
        return false;
    }
    const auto* privileges = reinterpret_cast<const TOKEN_PRIVILEGES*>(buffer.data());
    const LUID luid = debug_luid();
    for (DWORD i = 0; i < privileges->PrivilegeCount; ++i) {
        const LUID_AND_ATTRIBUTES& entry = privileges->Privileges[i];
        if (entry.Luid.LowPart == luid.LowPart && entry.Luid.HighPart == luid.HighPart) {
            return (entry.Attributes & SE_PRIVILEGE_ENABLED) != 0;
        }
    }
    return false;
}

}  // namespace mh
