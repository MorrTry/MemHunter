#include "inspect/process_inspect.hpp"

#include <windows.h>
#include <psapi.h>

#include <optional>

#include "common/error.hpp"
#include "common/text.hpp"
#include "memory/process_memory.hpp"

namespace mh {

namespace {

constexpr std::size_t kMaxCachedFiles = 512;
constexpr ULONG kProcessBasicInformation = 0;
constexpr ULONG kProcessWow64Information = 26;
// ImageBaseAddress in the 64-bit and in the 32-bit process environment block.
constexpr std::uint64_t kPebImageBase64 = 0x10;
constexpr std::uint64_t kPebImageBase32 = 0x8;

struct BasicInformation {
    LONG exit_status;
    PVOID peb;
    ULONG_PTR affinity;
    LONG priority;
    ULONG_PTR pid;
    ULONG_PTR parent_pid;
};

using QueryInformationProcess = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

QueryInformationProcess query_information_process() {
    static const QueryInformationProcess query = [] {
        const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        const FARPROC proc = ntdll != nullptr ? GetProcAddress(ntdll, "NtQueryInformationProcess") : nullptr;
        return reinterpret_cast<QueryInformationProcess>(reinterpret_cast<void (*)()>(proc));
    }();
    return query;
}

// GLOBALROOT opens the NT device paths that could not be turned into drive letters.
std::wstring win32_path(const std::string& path) {
    const std::wstring wide = utf8_to_wide(path);
    if (wide.starts_with(L"\\Device\\")) {
        return L"\\\\?\\GLOBALROOT" + wide;
    }
    if (wide.size() > 2 && wide[1] == L':' && wide[2] == L'\\') {
        return L"\\\\?\\" + wide;
    }
    return wide;
}

UniqueHandle open_file(const std::string& path, DWORD access) {
    return UniqueHandle(CreateFileW(win32_path(path).c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                    OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
}

class Win32FileReader final : public FileReader {
public:
    Win32FileReader(UniqueHandle file, std::uint64_t size) : file_(std::move(file)), size_(size) {}

    std::uint64_t size() const override { return size_; }

    bool read(std::uint64_t offset, std::span<std::byte> out) const override {
        std::size_t done = 0;
        while (done < out.size()) {
            OVERLAPPED overlapped{};
            const std::uint64_t at = offset + done;
            overlapped.Offset = static_cast<DWORD>(at);
            overlapped.OffsetHigh = static_cast<DWORD>(at >> 32);
            const auto chunk = static_cast<DWORD>(std::min<std::size_t>(out.size() - done, 1u << 30));
            DWORD got = 0;
            if (!ReadFile(file_.get(), out.data() + done, chunk, &got, &overlapped) || got == 0) {
                return false;
            }
            done += got;
        }
        return true;
    }

private:
    UniqueHandle file_;
    std::uint64_t size_;
};

OpenedFile load_image_file(const std::string& path) {
    UniqueHandle file = open_file(path, GENERIC_READ);
    if (!file) {
        return {nullptr, "cannot open " + path + ": " + win32_message(GetLastError())};
    }
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file.get(), &size)) {
        return {nullptr, "cannot read the size of " + path + ": " + win32_message(GetLastError())};
    }
    auto image = PeFile::load(std::make_unique<Win32FileReader>(std::move(file), static_cast<std::uint64_t>(size.QuadPart)));
    if (!image) {
        return {nullptr, path + " is not a readable PE image"};
    }
    return {std::move(image), ""};
}

std::optional<BY_HANDLE_FILE_INFORMATION> identity(const std::string& path) {
    const UniqueHandle file = open_file(path, FILE_READ_ATTRIBUTES);
    BY_HANDLE_FILE_INFORMATION info{};
    if (!file || !GetFileInformationByHandle(file.get(), &info)) {
        return std::nullopt;
    }
    return info;
}

class ProcessFacts final : public InspectFacts {
public:
    ProcessFacts(const Process& process, std::size_t page_size, ImageFileCache& files)
        : process_(process), page_size_(page_size), files_(files) {}

    std::optional<std::uint64_t> main_image() const override {
        const QueryInformationProcess query = query_information_process();
        if (query == nullptr) {
            return std::nullopt;
        }
        if (process_.is_wow64()) {
            ULONG_PTR peb32 = 0;
            if (query(process_.handle(), kProcessWow64Information, &peb32, sizeof(peb32), nullptr) < 0 || peb32 == 0) {
                return std::nullopt;
            }
            return read_pointer<std::uint32_t>(peb32 + kPebImageBase32);
        }
        BasicInformation info{};
        if (query(process_.handle(), kProcessBasicInformation, &info, sizeof(info), nullptr) < 0 || info.peb == nullptr) {
            return std::nullopt;
        }
        return read_pointer<std::uint64_t>(reinterpret_cast<std::uint64_t>(info.peb) + kPebImageBase64);
    }

    std::string main_path() const override { return process_.image_path(); }

    std::vector<bool> shared_pages(std::uint64_t address, std::size_t pages) const override {
        std::vector<bool> shared(pages, false);
        std::vector<PSAPI_WORKING_SET_EX_INFORMATION> info(pages);
        for (std::size_t i = 0; i < pages; ++i) {
            info[i].VirtualAddress = reinterpret_cast<PVOID>(address + i * page_size_);
        }
        if (pages == 0 || !QueryWorkingSetEx(process_.handle(), info.data(), static_cast<DWORD>(info.size() * sizeof(info[0])))) {
            return shared;
        }
        // The bit has the same place for pages out of the working set: a page that was written to is private.
        for (std::size_t i = 0; i < pages; ++i) {
            shared[i] = info[i].VirtualAttributes.Shared != 0;
        }
        return shared;
    }

    OpenedFile open_image(const std::string& path) const override { return files_.open(path); }

    bool file_exists(const std::string& path) const override {
        if (GetFileAttributesW(win32_path(path).c_str()) != INVALID_FILE_ATTRIBUTES) {
            return true;
        }
        const DWORD error = GetLastError();
        return error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND;
    }

    // When either file cannot be opened the paths are taken to name the same file: a missing file is reported on
    // its own.
    bool same_file(const std::string& a, const std::string& b) const override {
        if (iequals_ascii(a, b)) {
            return true;
        }
        const auto first = identity(a);
        const auto second = identity(b);
        if (!first || !second) {
            return true;
        }
        return first->dwVolumeSerialNumber == second->dwVolumeSerialNumber && first->nFileIndexHigh == second->nFileIndexHigh &&
               first->nFileIndexLow == second->nFileIndexLow;
    }

private:
    template <typename T>
    std::optional<std::uint64_t> read_pointer(std::uint64_t address) const {
        T value = 0;
        SIZE_T done = 0;
        if (!ReadProcessMemory(process_.handle(), reinterpret_cast<LPCVOID>(address), &value, sizeof(value), &done) || done != sizeof(value)) {
            return std::nullopt;
        }
        return static_cast<std::uint64_t>(value);
    }

    const Process& process_;
    std::size_t page_size_;
    ImageFileCache& files_;
};

}  // namespace

OpenedFile ImageFileCache::open(const std::string& path) {
    const std::string key = to_lower_ascii(path);
    {
        const std::lock_guard lock(mutex_);
        if (const auto it = files_.find(key); it != files_.end()) {
            return it->second;
        }
    }
    OpenedFile opened = load_image_file(path);
    const std::lock_guard lock(mutex_);
    if (files_.size() >= kMaxCachedFiles) {
        files_.clear();
    }
    files_.emplace(key, opened);
    return opened;
}

InspectReport inspect_process(const Process& process, ImageFileCache& files, const InspectOptions& options, std::stop_token stop) {
    const ProcessMemory memory(process);
    const ProcessFacts facts(process, memory.page_size(), files);
    return inspect_memory(memory, facts, options, std::move(stop));
}

}  // namespace mh
