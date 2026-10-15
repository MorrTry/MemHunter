#pragma once

namespace mh {

// SeDebugPrivilege lets an administrator open the processes of other users and of services; protected processes
// (PPL) stay closed even then. Only MemHunter's own token changes, and only on request.

// Throws Error(AccessDenied) when the token does not hold the privilege, that is MemHunter was not run as
// administrator.
void enable_debug_privilege();
void disable_debug_privilege();
bool debug_privilege_enabled();

}  // namespace mh
