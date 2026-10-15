#pragma once

#include <string>
#include <vector>

#include "cli/console.hpp"
#include "common/error.hpp"

namespace mh::cli {

enum ExitCode : int {
    kExitSuccess = 0,
    kExitNoMatches = 1,
    kExitUsage = 2,
    kExitProcess = 3,
    kExitIo = 4,
    kExitIncomplete = 5,
    kExitSnapshot = 6,
    kExitInternal = 9,
};

int exit_code_for(ErrorCode code) noexcept;

// `args` excludes the program name. --debug-privilege anywhere before "--" enables SeDebugPrivilege first.
int run(std::vector<std::string> args, const ConsoleSession& console);

}  // namespace mh::cli
