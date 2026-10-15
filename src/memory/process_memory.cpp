#include "memory/process_memory.hpp"

#include <windows.h>
#include <psapi.h>

#include <string>
#include <unordered_map>
#include <utility>

#include "common/error.hpp"
#include "common/text.hpp"

namespace mh {

namespace {

// GetMappedFileNameW returns NT device paths (\Device\HarddiskVolume3\...); map them back to drive letters.
class DevicePathTranslator {
public:
    DevicePathTranslator() {
        wchar_t drives[512]{};
        const DWORD length = GetLogicalDriveStringsW(static_cast<DWORD>(std::size(drives) - 1), drives);
        if (length == 0 || length >= std::size(drives)) {
            return;
        }
        for (const wchar_t* drive = drives; *drive != L'\0'; drive += wcslen(drive) + 1) {
            const std::wstring letter(drive, 2);
            wchar_t target[MAX_PATH]{};
            if (QueryDosDeviceW(letter.c_str(), target, MAX_PATH) != 0) {
                devices_.emplace_back(target, letter);
            }
        }
    }

    std::wstring translate(const std::wstring& path) const {
        for (const auto& [device, letter] : devices_) {
            if (path.size() > device.size() && path.compare(0, device.size(), device) == 0 && path[device.size()] == L'\\') {
                return letter + path.substr(device.size());
            }
        }
        return path;
    }

private:
    std::vector<std::pair<std::wstring, std::wstring>> devices_;
};

MemState to_state(DWORD state) {
    switch (state) {
        case MEM_COMMIT: return MemState::Commit;
        case MEM_RESERVE: return MemState::Reserve;
        default: return MemState::Free;
    }
}

MemType to_type(DWORD type) {
    switch (type) {
        case MEM_IMAGE: return MemType::Image;
        case MEM_MAPPED: return MemType::Mapped;
        case MEM_PRIVATE: return MemType::Private;
        default: return MemType::None;
    }
}

}  // namespace

ProcessMemory::ProcessMemory(const Process& process) : process_(process) {
    SYSTEM_INFO info{};
    GetSystemInfo(&info);
    page_size_ = info.dwPageSize;
}

std::vector<Region> ProcessMemory::query_regions() const {
    const DevicePathTranslator translator;
    std::unordered_map<std::uint64_t, std::string> file_by_allocation;
    std::vector<Region> regions;

    std::uint64_t address = 0;
    for (;;) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQueryEx(process_.handle(), reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0) {
            const DWORD error = GetLastError();
            // ERROR_INVALID_PARAMETER marks the end of the user-mode address space.
            if (error == ERROR_INVALID_PARAMETER) {
                break;
            }
            if (!process_.is_running()) {
                throw Error(ErrorCode::ProcessExited, "process " + std::to_string(process_.pid()) + " exited while its memory map was being read");
            }
            throw_win32(ErrorCode::SystemError, "VirtualQueryEx failed at " + format_address(address), error);
        }

        const auto base = reinterpret_cast<std::uint64_t>(mbi.BaseAddress);
        const auto next = base + mbi.RegionSize;
        if (mbi.State != MEM_FREE) {
            Region region;
            region.base = base;
            region.size = mbi.RegionSize;
            region.allocation_base = reinterpret_cast<std::uint64_t>(mbi.AllocationBase);
            region.protect = mbi.State == MEM_COMMIT ? mbi.Protect : 0;
            region.allocation_protect = mbi.AllocationProtect;
            region.state = to_state(mbi.State);
            region.type = to_type(mbi.Type);
            if (region.type == MemType::Image || region.type == MemType::Mapped) {
                auto [it, inserted] = file_by_allocation.try_emplace(region.allocation_base);
                if (inserted) {
                    std::wstring path(MAX_PATH * 4, L'\0');
                    const DWORD length = GetMappedFileNameW(process_.handle(), mbi.AllocationBase, path.data(),
                                                            static_cast<DWORD>(path.size()));
                    if (length != 0) {
                        path.resize(length);
                        it->second = wide_to_utf8(translator.translate(path));
                    }
                }
                region.mapped_file = it->second;
            }
            regions.push_back(std::move(region));
        }
        if (next <= address) {
            break;
        }
        address = next;
    }
    return regions;
}

ReadResult ProcessMemory::read(std::uint64_t address, std::span<std::byte> out) const {
    SIZE_T done = 0;
    if (ReadProcessMemory(process_.handle(), reinterpret_cast<LPCVOID>(address), out.data(), out.size(), &done)) {
        return {out.size(), 0};
    }
    const DWORD error = GetLastError();
    return {done <= out.size() ? static_cast<std::size_t>(done) : 0, error == 0 ? static_cast<std::uint32_t>(ERROR_PARTIAL_COPY) : error};
}

bool ProcessMemory::target_alive() const {
    return process_.is_running();
}

}  // namespace mh
