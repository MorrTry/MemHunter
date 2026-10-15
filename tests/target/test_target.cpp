// Test target for the integration tests and the process benchmark. It plants needles in memory laid out to
// exercise the hard cases of a scanner, prints where they are and then waits for commands on stdin:
//   check-guard   prints "guard 1" while the guard page is still armed
//   mutate        moves the mutable needle and prints its new address
//   set N         stores the int32 N in the counter and prints "counter N"
//   move          moves the counter to a new page, keeps its value and prints "counter ADDRESS"
//   rwx           allocates a writable and executable page and prints "rwx ADDRESS"
//   pe            copies its own PE headers into private memory and prints "pe ADDRESS"
//   patch         changes 4 bytes of its own code and prints "patched ADDRESS 4"
//   trim          removes its pages from the working set and prints "trimmed"
//   lock          denies everyone access to the process and prints "locked"
//   exit          ends the process
#include <windows.h>
#include <aclapi.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "target/needles.hpp"

namespace {

using mh::testing::kNeedleSize;
using mh::testing::kTextNeedleSize;
using mh::testing::needle_byte;
using mh::testing::needle_letter;

constexpr std::size_t kPage = 4096;

struct Options {
    std::uint64_t seed = 1;
    std::uint64_t fill = 0;
};

[[noreturn]] void fail(const char* what) {
    std::fprintf(stderr, "test_target: %s failed (error %lu)\n", what, GetLastError());
    std::exit(3);
}

std::uint8_t* allocate(std::size_t size, DWORD protect = PAGE_READWRITE) {
    void* memory = VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, protect);
    if (memory == nullptr) {
        fail("VirtualAlloc");
    }
    return static_cast<std::uint8_t*>(memory);
}

void protect(void* address, std::size_t size, DWORD protection) {
    DWORD old = 0;
    if (VirtualProtect(address, size, protection, &old) == 0) {
        fail("VirtualProtect");
    }
}

void announce(const char* name, std::uint32_t index, const char* encoding, const void* address, int expect) {
    std::printf("needle %s %u %s 0x%llX %d\n", name, index, encoding,
                static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(address)), expect);
}

void plant_bytes(std::uint8_t* at, std::uint64_t seed, std::uint32_t index) {
    for (std::size_t i = 0; i < kNeedleSize; ++i) {
        at[i] = needle_byte(seed, index, i);
    }
}

void plant_ascii(std::uint8_t* at, std::uint64_t seed, std::uint32_t index, bool lower) {
    for (std::size_t i = 0; i < kTextNeedleSize; ++i) {
        const char c = needle_letter(seed, index, i);
        at[i] = static_cast<std::uint8_t>(lower ? c - 'A' + 'a' : c);
    }
}

void plant_utf16(std::uint8_t* at, std::uint64_t seed, std::uint32_t index) {
    for (std::size_t i = 0; i < kTextNeedleSize; ++i) {
        at[2 * i] = static_cast<std::uint8_t>(needle_letter(seed, index, i));
        at[2 * i + 1] = 0;
    }
}

std::uint64_t parse_number(const char* text) {
    char* end = nullptr;
    std::uint64_t value = std::strtoull(text, &end, 0);
    if (end != nullptr) {
        switch (*end) {
            case 'K': case 'k': value <<= 10; break;
            case 'M': case 'm': value <<= 20; break;
            case 'G': case 'g': value <<= 30; break;
            default: break;
        }
    }
    return value;
}

Options parse_options(int argc, char** argv) {
    Options options;
    for (int i = 1; i + 1 < argc; i += 2) {
        if (std::strcmp(argv[i], "--seed") == 0) {
            options.seed = parse_number(argv[i + 1]);
        } else if (std::strcmp(argv[i], "--fill") == 0) {
            options.fill = parse_number(argv[i + 1]);
        }
    }
    return options;
}

struct Layout {
    std::uint8_t* guard = nullptr;
    std::uint8_t* mutable_region = nullptr;
    std::uint8_t* mutable_needle = nullptr;
};

// The counter is reachable from the data section like a game object: [[test_target.exe+g_holder]+0x10]+0x40.
struct Holder {
    std::uint64_t padding[2] = {};
    std::uint8_t* counter_page = nullptr;
};
Holder* g_holder = nullptr;

std::int32_t* counter() {
    return reinterpret_cast<std::int32_t*>(g_holder->counter_page + 64);
}

void announce_counter() {
    std::printf("counter 0x%llX\n", static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(counter())));
}

Layout plant_cases(std::uint64_t seed) {
    Layout layout;

    std::uint8_t* r1 = allocate(64 * 1024);
    plant_bytes(r1, seed, 0);
    announce("region_start", 0, "bytes", r1, 1);
    plant_bytes(r1 + 64 * 1024 - kNeedleSize, seed, 1);
    announce("region_end", 1, "bytes", r1 + 64 * 1024 - kNeedleSize, 1);

    std::uint8_t* r2 = allocate(1024 * 1024);
    for (std::size_t k = 1; k < 256; ++k) {
        std::uint8_t* at = r2 + k * kPage - 7;
        plant_bytes(at, seed, 2);
        announce("page_boundary", 2, "bytes", at, 1);
    }

    std::uint8_t* r3 = allocate(2 * kPage);
    plant_bytes(r3 + kPage - 8, seed, 3);
    protect(r3 + kPage, kPage, PAGE_READONLY);
    announce("cross_protection", 3, "bytes", r3 + kPage - 8, 1);

    std::uint8_t* r4 = allocate(3 * kPage);
    plant_bytes(r4 + kPage - 8, seed, 4);
    plant_bytes(r4 + kPage + 512, seed, 5);
    plant_bytes(r4 + 2 * kPage + 512, seed, 6);
    protect(r4 + kPage, kPage, PAGE_NOACCESS);
    announce("cross_noaccess", 4, "bytes", r4 + kPage - 8, 0);
    announce("inside_noaccess", 5, "bytes", r4 + kPage + 512, 0);
    announce("after_noaccess", 6, "bytes", r4 + 2 * kPage + 512, 1);

    layout.guard = allocate(kPage);
    plant_bytes(layout.guard + 256, seed, 7);
    protect(layout.guard, kPage, PAGE_READWRITE | PAGE_GUARD);
    announce("guard", 7, "bytes", layout.guard + 256, 0);

    std::uint8_t* r6 = allocate(kPage);
    plant_ascii(r6, seed, 8, false);
    announce("text_ascii", 8, "ascii", r6, 1);
    plant_utf16(r6 + 512, seed, 8);
    announce("text_utf16", 8, "utf16", r6 + 512, 1);
    plant_ascii(r6 + 2048, seed, 10, true);
    announce("text_lower", 10, "lower", r6 + 2048, 1);

    std::uint8_t* r7 = allocate(kPage);
    plant_bytes(r7 + 128, seed, 11);
    protect(r7, kPage, PAGE_EXECUTE_READ);
    announce("execute", 11, "bytes", r7 + 128, 1);

    layout.mutable_region = allocate(4 * kPage);
    layout.mutable_needle = layout.mutable_region;
    plant_bytes(layout.mutable_needle, seed, 12);
    announce("mutable", 12, "bytes", layout.mutable_needle, 1);

    // Alone on its page, so a value scan limited to the page sees nothing else.
    g_holder = new Holder;
    g_holder->counter_page = allocate(kPage);
    announce_counter();
    return layout;
}

void fill_memory(std::uint64_t seed, std::uint64_t total) {
    constexpr std::uint64_t kBlock = 64ull << 20;
    std::uint64_t state = seed * 0x2545F4914F6CDD1Dull | 1;
    std::uint64_t filled = 0;
    std::uint32_t planted = 0;
    while (filled < total) {
        const std::size_t size = static_cast<std::size_t>(std::min(kBlock, total - filled));
        std::uint8_t* block = allocate(size);
        auto* words = reinterpret_cast<std::uint64_t*>(block);
        for (std::size_t i = 0; i < size / 8; ++i) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            words[i] = state;
        }
        // Ten needles per block at fixed offsets, so a benchmark knows exactly how many hits to expect.
        for (std::uint32_t k = 0; k < 10 && size >= kNeedleSize * 64; ++k) {
            std::uint8_t* at = block + (size / 10) * k + 333 * (k + 1);
            plant_bytes(at, seed, 100 + k);
            ++planted;
        }
        filled += size;
    }
    std::printf("fill %llu %u\n", static_cast<unsigned long long>(filled), planted);
}

void mutate(Layout& layout, std::uint64_t seed) {
    std::memset(layout.mutable_needle, 0, kNeedleSize);
    layout.mutable_needle = layout.mutable_region + kPage + 100;
    plant_bytes(layout.mutable_needle, seed, 12);
    std::printf("mutated 0x%llX\n", static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(layout.mutable_needle)));
}

bool guard_armed(const void* address) {
    MEMORY_BASIC_INFORMATION info{};
    return VirtualQuery(address, &info, sizeof(info)) != 0 && (info.Protect & PAGE_GUARD) != 0;
}

void print_address(const char* word, const void* address) {
    std::printf("%s 0x%llX\n", word, static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(address)));
}

// Never called; only its bytes are changed by the "patch" command.
__attribute__((noinline)) int patch_site(int value) {
    return value * 7 + 3;
}

int (*volatile g_patch_site)(int) = patch_site;

void patch_code() {
    auto* code = reinterpret_cast<std::uint8_t*>(reinterpret_cast<std::uintptr_t>(g_patch_site));
    DWORD old = 0;
    if (VirtualProtect(code, 4, PAGE_EXECUTE_READWRITE, &old) == 0) {
        fail("VirtualProtect");
    }
    for (int i = 0; i < 4; ++i) {
        code[i] ^= 0xFF;
    }
    protect(code, 4, old);
    FlushInstructionCache(GetCurrentProcess(), code, 4);
    std::printf("patched 0x%llX 4\n", static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(code)));
}

void copy_headers() {
    const auto* image = reinterpret_cast<const std::uint8_t*>(GetModuleHandleW(nullptr));
    std::uint8_t* copy = allocate(kPage);
    std::memcpy(copy, image, kPage);
    print_address("pe", copy);
}

void lock_process() {
    ACL empty{};
    if (!InitializeAcl(&empty, sizeof(empty), ACL_REVISION) ||
        SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &empty, nullptr) !=
            ERROR_SUCCESS) {
        fail("SetSecurityInfo");
    }
    std::printf("locked\n");
}

}  // namespace

int main(int argc, char** argv) {
    const Options options = parse_options(argc, argv);
    std::printf("pid %lu\n", GetCurrentProcessId());
    Layout layout = plant_cases(options.seed);
    if (options.fill != 0) {
        fill_memory(options.seed, options.fill);
    }
    std::printf("ready\n");
    std::fflush(stdout);

    char line[256];
    while (std::fgets(line, sizeof(line), stdin) != nullptr) {
        const std::string command = std::string(line).substr(0, std::strcspn(line, "\r\n"));
        if (command == "check-guard") {
            std::printf("guard %d\n", guard_armed(layout.guard) ? 1 : 0);
        } else if (command == "mutate") {
            mutate(layout, options.seed);
        } else if (command.starts_with("set ")) {
            *counter() = static_cast<std::int32_t>(std::strtol(command.c_str() + 4, nullptr, 10));
            std::printf("counter %d\n", *counter());
        } else if (command == "move") {
            std::uint8_t* page = allocate(kPage);
            std::memcpy(page + 64, counter(), sizeof(std::int32_t));
            g_holder->counter_page = page;
            announce_counter();
        } else if (command == "rwx") {
            std::uint8_t* page = allocate(kPage, PAGE_EXECUTE_READWRITE);
            page[0] = 0xC3;
            print_address("rwx", page);
        } else if (command == "pe") {
            copy_headers();
        } else if (command == "patch") {
            patch_code();
        } else if (command == "trim") {
            SetProcessWorkingSetSize(GetCurrentProcess(), static_cast<SIZE_T>(-1), static_cast<SIZE_T>(-1));
            std::printf("trimmed\n");
        } else if (command == "lock") {
            lock_process();
        } else if (command == "exit") {
            break;
        } else {
            std::printf("unknown %s\n", command.c_str());
        }
        std::fflush(stdout);
    }
    return 0;
}
