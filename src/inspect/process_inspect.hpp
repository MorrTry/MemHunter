#pragma once

#include <mutex>
#include <stop_token>
#include <string>
#include <unordered_map>

#include "inspect/inspect.hpp"
#include "process/process.hpp"

namespace mh {

// Image files opened once for the inspections of several processes, which load mostly the same DLLs.
class ImageFileCache {
public:
    OpenedFile open(const std::string& path);

private:
    std::mutex mutex_;
    std::unordered_map<std::string, OpenedFile> files_;
};

// Throws Error when the memory map of the process cannot be read.
InspectReport inspect_process(const Process& process, ImageFileCache& files, const InspectOptions& options = {},
                              std::stop_token stop = {});

}  // namespace mh
