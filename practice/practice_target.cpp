// Practice target for MemHunter: a small fake game that keeps meaningful data in several kinds of memory and
// switches protections on and off while it runs, so that every scan result can be explained.
#include <windows.h>

#include <aclapi.h>
#include <conio.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <memory>
#include <mutex>
#include <random>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace {

// Texts that go into the protected game state are stored encoded in the executable; otherwise a scan would still
// find them in the image section while the state itself is encrypted.
template <typename Char>
constexpr Char literal_mask(std::size_t i) {
    return static_cast<Char>(0x5A + 17 * i);
}

template <std::size_t W, typename Char, std::size_t N>
consteval std::array<Char, W> hide(const Char (&text)[N]) {
    static_assert(N <= W, "the text does not fit its field");
    std::array<Char, W> out{};
    for (std::size_t i = 0; i < W; ++i) {
        out[i] = static_cast<Char>((i < N ? text[i] : Char{}) ^ literal_mask<Char>(i));
    }
    return out;
}

// Reads through volatile so the optimizer cannot fold the decoded text back into a plain constant.
template <typename Char, std::size_t W, std::size_t M>
void reveal(const std::array<Char, W>& hidden, Char (&out)[M]) {
    static_assert(W <= M);
    const volatile Char* source = hidden.data();
    for (std::size_t i = 0; i < W; ++i) {
        out[i] = static_cast<Char>(source[i] ^ literal_mask<Char>(i));
    }
    out[M - 1] = Char{};
}

// The same for the numbers a learner searches for, so the code section holds no plain immediate of them.
constexpr std::int32_t kNumberMask = 0x5A5A5A5A;

template <typename T>
T unmask(T masked) {
    const volatile T value = masked;
    return static_cast<T>(value ^ static_cast<T>(kNumberMask));
}

struct Item {
    std::uint32_t id;
    std::uint16_t count;
    std::uint16_t condition;  // percent
    float weight;             // kg
    char name[20];
};

struct ChatLine {
    std::uint32_t minute;  // game time
    wchar_t text[62];
};

// The layout a learner reconstructs from scan previews (practice/README.md documents the same offsets).
struct GameState {
    char tag[4];
    std::uint32_t version;
    char name[24];
    wchar_t title[24];
    std::int32_t health;
    std::int32_t max_health;
    std::int32_t money;
    std::int32_t level;
    std::int64_t experience;
    float x, y, z;
    float armor;
    std::uint32_t game_seconds;
    std::uint32_t item_count;
    Item items[16];
    std::uint32_t chat_count;
    ChatLine chat[8];
};
static_assert(offsetof(GameState, name) == 0x08 && offsetof(GameState, title) == 0x20 && offsetof(GameState, health) == 0x50 &&
              offsetof(GameState, money) == 0x58 && offsetof(GameState, level) == 0x5C &&
              offsetof(GameState, experience) == 0x60 && offsetof(GameState, x) == 0x68 &&
              offsetof(GameState, armor) == 0x74 && offsetof(GameState, game_seconds) == 0x78 &&
              offsetof(GameState, items) == 0x80 && offsetof(GameState, chat_count) == 0x280 &&
              offsetof(GameState, chat) == 0x284 && sizeof(Item) == 0x20 && offsetof(Item, name) == 0x0C &&
              sizeof(ChatLine) == 0x80 && sizeof(GameState) == 0x688);

struct ItemSeed {
    std::uint32_t id;
    std::array<char, 20> name;
    std::uint16_t count;
    std::uint16_t condition;
    float weight;
};

constexpr std::uint32_t kMedkit = 2001;
constexpr auto kPlayerTag = hide<5>("PLR1");
constexpr auto kPlayerName = hide<24>("Stalker_Ivan");
constexpr auto kPlayerTitle = hide<24>(L"Вольный сталкер");
constexpr std::array kItemSeeds{
    ItemSeed{1001, hide<20>("AK-74"), 1, 78, 3.6f},
    ItemSeed{1002, hide<20>("5.45x39mm"), 120, 100, 1.2f},
    ItemSeed{kMedkit, hide<20>("Medkit"), 3, 100, 0.3f},
    ItemSeed{2002, hide<20>("Bandage"), 5, 100, 0.1f},
    ItemSeed{3001, hide<20>("Anomaly detector"), 1, 92, 0.4f},
    ItemSeed{4001, hide<20>("Bread"), 2, 100, 0.4f},
    ItemSeed{4002, hide<20>("Vodka Kazaki"), 1, 100, 0.5f},
};
constexpr std::array kChatSeeds{
    hide<62>(L"Сидорович: Есть работа, сталкер. Зайди ко мне."),
    hide<62>(L"Волк: На мосту засели бандиты, будь осторожен."),
    hide<62>(L"Радио: Выброс через десять минут! Ищите укрытие!"),
    hide<62>(L"Торговец: Куплю артефакты, плачу хорошо."),
    hide<62>(L"Бармен: Свежая водка и тушёнка, заходите."),
};

GameState initial_state() {
    GameState s{};
    char tag[5];
    reveal(kPlayerTag, tag);
    std::memcpy(s.tag, tag, 4);
    SecureZeroMemory(tag, sizeof(tag));
    s.version = 1;
    reveal(kPlayerName, s.name);
    reveal(kPlayerTitle, s.title);
    s.health = 86;
    s.max_health = 100;
    s.money = unmask<std::int32_t>(15000 ^ kNumberMask);
    s.experience = unmask<std::int64_t>(64200 ^ kNumberMask);
    s.level = static_cast<std::int32_t>(1 + s.experience / 10000);
    s.x = 102.5f;
    s.y = 4.0f;
    s.z = -37.25f;
    s.armor = 35.0f;
    s.game_seconds = 8 * 3600 + 5 * 60;
    for (const auto& seed : kItemSeeds) {
        Item& item = s.items[s.item_count++];
        item.id = seed.id;
        item.count = seed.count;
        item.condition = seed.condition;
        item.weight = seed.weight;
        reveal(seed.name, item.name);
    }
    s.chat_count = 2;
    for (std::uint32_t i = 0; i < s.chat_count; ++i) {
        s.chat[i].minute = s.game_seconds / 60 - 3 + i;
        reveal(kChatSeeds[i], s.chat[i].text);
    }
    return s;
}

// XOR with a xorshift64* keystream; key 0 copies the bytes unchanged. dst may equal src.
void xor_copy(std::byte* dst, const std::byte* src, std::size_t size, std::uint64_t key) {
    if (key == 0) {
        std::memmove(dst, src, size);
        return;
    }
    std::uint64_t state = key;
    for (std::size_t i = 0; i < size; i += 8) {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        const std::uint64_t stream = state * 0x2545F4914F6CDD1Dull;
        for (std::size_t j = 0; j < 8 && i + j < size; ++j) {
            dst[i + j] = src[i + j] ^ static_cast<std::byte>(stream >> (8 * j));
        }
    }
}

constexpr std::size_t kVaultSize = 64 * 1024;

// Owns the pages with the game state and applies the two in-memory protections: an XOR keystream whose key
// changes on every write, and PAGE_NOACCESS between accesses. Plain copies exist only on the stack while in use.
class Vault {
public:
    explicit Vault(const GameState& initial) : rng_(std::random_device{}()), base_(allocate()) {
        std::memcpy(base_, &initial, sizeof(initial));
    }
    ~Vault() { VirtualFree(base_, 0, MEM_RELEASE); }
    Vault(const Vault&) = delete;
    Vault& operator=(const Vault&) = delete;

    template <typename F>
    void update(F&& change) {
        std::lock_guard lock(mutex_);
        GameState state;
        load(state);
        change(state);
        store(state);
        SecureZeroMemory(&state, sizeof(state));
    }

    template <typename F>
    void read(F&& use) {
        std::lock_guard lock(mutex_);
        GameState state;
        load(state);
        close_pages();
        use(static_cast<const GameState&>(state));
        SecureZeroMemory(&state, sizeof(state));
    }

    void set_encrypted(bool on) {
        std::lock_guard lock(mutex_);
        GameState state;
        load(state);
        encrypted_ = on;
        store(state);
        SecureZeroMemory(&state, sizeof(state));
    }

    void set_pages_closed(bool on) {
        std::lock_guard lock(mutex_);
        pages_closed_ = on;
        protect(on ? PAGE_NOACCESS : PAGE_READWRITE);
    }

    // Moves the state to new pages, the way a game reallocates its objects when a level reloads.
    void relocate() {
        std::lock_guard lock(mutex_);
        std::byte* moved = allocate();
        protect(PAGE_READWRITE);
        std::memcpy(moved, base_, kVaultSize);
        SecureZeroMemory(base_, kVaultSize);
        VirtualFree(base_, 0, MEM_RELEASE);
        base_ = moved;
        close_pages();
    }

    std::uintptr_t address() const {
        std::lock_guard lock(mutex_);
        return reinterpret_cast<std::uintptr_t>(base_);
    }
    bool encrypted() const {
        std::lock_guard lock(mutex_);
        return encrypted_;
    }
    bool pages_closed() const {
        std::lock_guard lock(mutex_);
        return pages_closed_;
    }

private:
    static std::byte* allocate() {
        void* pages = VirtualAlloc(nullptr, kVaultSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (pages == nullptr) {
            throw std::runtime_error("VirtualAlloc failed, error " + std::to_string(GetLastError()));
        }
        return static_cast<std::byte*>(pages);
    }

    void protect(DWORD protection) {
        DWORD old = 0;
        if (!VirtualProtect(base_, kVaultSize, protection, &old)) {
            throw std::runtime_error("VirtualProtect failed, error " + std::to_string(GetLastError()));
        }
    }

    void close_pages() {
        if (pages_closed_) {
            protect(PAGE_NOACCESS);
        }
    }

    void load(GameState& state) {
        if (pages_closed_) {
            protect(PAGE_READWRITE);
        }
        auto* bytes = reinterpret_cast<std::byte*>(&state);
        xor_copy(bytes, base_, sizeof(state), encrypted_ ? key_ : 0);
    }

    void store(const GameState& state) {
        key_ = encrypted_ ? rng_() | 1 : 0;
        xor_copy(base_, reinterpret_cast<const std::byte*>(&state), sizeof(state), key_);
        close_pages();
    }

    mutable std::mutex mutex_;
    std::mt19937_64 rng_;
    std::byte* base_;
    std::uint64_t key_ = 0;
    bool encrypted_ = false;
    bool pages_closed_ = false;
};

// Replaces this process's DACL so that no other process, not even one of the same user, can open it for reading.
// Windows checks access when a handle is opened, so handles opened before the switch keep working.
class AccessLock {
public:
    AccessLock() {
        error_ = GetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr,
                                 &original_dacl_, nullptr, &original_);
    }
    ~AccessLock() { LocalFree(original_); }
    AccessLock(const AccessLock&) = delete;
    AccessLock& operator=(const AccessLock&) = delete;

    bool locked() const noexcept { return locked_; }

    // Returns a Windows error code, 0 on success.
    DWORD set(bool on) {
        if (error_ != ERROR_SUCCESS) {
            return error_;
        }
        DWORD result = ERROR_SUCCESS;
        if (on) {
            result = apply_restricted();
        } else {
            result = SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr,
                                     original_dacl_, nullptr);
        }
        if (result == ERROR_SUCCESS) {
            locked_ = on;
        }
        return result;
    }

private:
    static DWORD apply_restricted() {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
            return GetLastError();
        }
        DWORD size = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &size);
        std::vector<std::byte> user(size);
        const BOOL have_user = GetTokenInformation(token, TokenUser, user.data(), size, &size);
        const DWORD token_error = GetLastError();
        CloseHandle(token);
        if (!have_user) {
            return token_error;
        }
        std::array<std::byte, SECURITY_MAX_SID_SIZE> system{};
        DWORD system_size = system.size();
        if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, system.data(), &system_size)) {
            return GetLastError();
        }

        // The user keeps what Task Manager needs: the name, waiting for exit and ending the process.
        std::array<EXPLICIT_ACCESSW, 2> entries{};
        entries[0].grfAccessPermissions = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE | READ_CONTROL;
        entries[0].grfAccessMode = SET_ACCESS;
        entries[0].grfInheritance = NO_INHERITANCE;
        entries[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
        entries[0].Trustee.TrusteeType = TRUSTEE_IS_USER;
        entries[0].Trustee.ptstrName = static_cast<LPWSTR>(reinterpret_cast<TOKEN_USER*>(user.data())->User.Sid);
        entries[1] = entries[0];
        entries[1].grfAccessPermissions = PROCESS_ALL_ACCESS;
        entries[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        entries[1].Trustee.ptstrName = reinterpret_cast<LPWSTR>(system.data());

        PACL acl = nullptr;
        DWORD result = SetEntriesInAclW(static_cast<ULONG>(entries.size()), entries.data(), nullptr, &acl);
        if (result == ERROR_SUCCESS) {
            result = SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, acl, nullptr);
            LocalFree(acl);
        }
        return result;
    }

    PSECURITY_DESCRIPTOR original_ = nullptr;
    PACL original_dacl_ = nullptr;
    DWORD error_ = ERROR_SUCCESS;
    bool locked_ = false;
};

// Heap object that points at the player, so the pointer itself can be searched for.
struct World {
    char tag[4];
    std::uint32_t players;
    std::uintptr_t player;
    wchar_t location[16];
};
static_assert(offsetof(World, players) == 0x04 && offsetof(World, player) == 0x08 && offsetof(World, location) == 0x10);

// Lives in the data section of the exe, like the global pointers of a game, so a pointer search finds the chain
// g_world -> World::player -> health, and it still works after a restart.
World* g_world = nullptr;

// Saved game in a page-file backed section: shows up as mapped memory.
class SaveSection {
public:
    SaveSection() {
        mapping_ = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, 64 * 1024, nullptr);
        if (mapping_ == nullptr) {
            throw std::runtime_error("CreateFileMapping failed, error " + std::to_string(GetLastError()));
        }
        view_ = static_cast<char*>(MapViewOfFile(mapping_, FILE_MAP_ALL_ACCESS, 0, 0, 0));
        if (view_ == nullptr) {
            const DWORD error = GetLastError();
            CloseHandle(mapping_);
            throw std::runtime_error("MapViewOfFile failed, error " + std::to_string(error));
        }
        std::snprintf(view_, 64 * 1024, "SAVEGAME v3\nslot=1\nlocation=Cordon\nquests=Find the flash drive;Talk to Wolf\n");
    }
    ~SaveSection() {
        UnmapViewOfFile(view_);
        CloseHandle(mapping_);
    }
    SaveSection(const SaveSection&) = delete;
    SaveSection& operator=(const SaveSection&) = delete;

    const void* address() const noexcept { return view_; }

private:
    HANDLE mapping_ = nullptr;
    char* view_ = nullptr;
};

// One screen built in a fixed buffer and wiped after output, so the plain values shown on screen do not stay
// behind in this process's memory while the state is encrypted. On a console the screen is clipped to the window;
// piped output is not clipped and every screen ends with a separator line.
class Frame {
public:
    Frame(bool console, int width, int height) : console_(console), width_(width), height_(height) {
        if (console_) {
            raw(L"\x1b[H");
        }
        line_start_ = length_;
    }
    ~Frame() { SecureZeroMemory(text_.data(), sizeof(text_)); }
    Frame(const Frame&) = delete;
    Frame& operator=(const Frame&) = delete;

    void add(const wchar_t* format, ...) {
        if (full_ || length_ + 16 >= text_.size()) {
            return;
        }
        va_list args;
        va_start(args, format);
        const int n = std::vswprintf(text_.data() + length_, text_.size() - length_ - 8, format, args);
        va_end(args);
        if (n > 0) {
            length_ += static_cast<std::size_t>(n);
        }
        clip();
    }

    void ascii(const char* text) {
        while (!full_ && *text != '\0' && length_ + 16 < text_.size()) {
            text_[length_++] = static_cast<unsigned char>(*text++);
        }
        clip();
    }

    void hex(const void* data, std::size_t size) {
        const auto* bytes = static_cast<const std::uint8_t*>(data);
        for (std::size_t i = 0; i < size; ++i) {
            add(i == 0 ? L"%02X" : L" %02X", bytes[i]);
        }
    }

    void end_line() {
        if (full_) {
            return;
        }
        if (height_ > 0 && row_ + 1 >= height_) {
            raw(L"\x1b[K");
            full_ = true;
            return;
        }
        raw(console_ ? L"\x1b[K\n" : L"\n");
        ++row_;
        line_start_ = length_;
    }

    bool write(HANDLE out) {
        DWORD written = 0;
        if (console_) {
            if (!full_) {
                raw(L"\x1b[J");
            }
            return WriteConsoleW(out, text_.data(), static_cast<DWORD>(length_), &written, nullptr) != 0;
        }
        raw(L"----------------\n");
        std::array<char, kCapacity * 3> utf8{};
        const int bytes = WideCharToMultiByte(CP_UTF8, 0, text_.data(), static_cast<int>(length_), utf8.data(),
                                              static_cast<int>(utf8.size()), nullptr, nullptr);
        const bool ok = bytes > 0 && WriteFile(out, utf8.data(), static_cast<DWORD>(bytes), &written, nullptr) != 0;
        SecureZeroMemory(utf8.data(), utf8.size());
        return ok;
    }

private:
    void raw(std::wstring_view text) {
        if (length_ + text.size() < text_.size()) {
            std::copy(text.begin(), text.end(), text_.begin() + static_cast<std::ptrdiff_t>(length_));
            length_ += text.size();
        }
    }

    // The last column stays free: writing into it would make the console wrap the line.
    void clip() {
        if (width_ > 1 && length_ - line_start_ > static_cast<std::size_t>(width_ - 1)) {
            length_ = line_start_ + static_cast<std::size_t>(width_ - 1);
        }
    }

    static constexpr std::size_t kCapacity = 8192;
    std::array<wchar_t, kCapacity> text_{};
    std::size_t length_ = 0;
    std::size_t line_start_ = 0;
    bool console_;
    int width_;
    int height_;
    int row_ = 0;
    bool full_ = false;
};

struct Options {
    bool hints = true;
    bool ticking = false;
};

void write_console(HANDLE out, std::wstring_view text) {
    DWORD written = 0;
    WriteConsoleW(out, text.data(), static_cast<DWORD>(text.size()), &written, nullptr);
}

// Visible part of the console window, or 0 x 0 when it cannot be queried and the screen is not clipped.
COORD window_size(HANDLE out) {
    CONSOLE_SCREEN_BUFFER_INFO info{};
    if (!GetConsoleScreenBufferInfo(out, &info)) {
        return COORD{0, 0};
    }
    return COORD{static_cast<SHORT>(info.srWindow.Right - info.srWindow.Left + 1),
                 static_cast<SHORT>(info.srWindow.Bottom - info.srWindow.Top + 1)};
}

// Fits a 120 x 30 window with the hints shown and 120 x 22 without them.
bool render(HANDLE out, bool console, COORD size, Vault& vault, const World& world, const AccessLock& lock,
            const SaveSection& save, const std::string& config, const std::wstring& motd, const Options& options,
            const std::wstring& message) {
    Frame f(console, size.X, size.Y);
    const unsigned long pid = GetCurrentProcessId();
    const auto on_off = [](bool on) { return on ? L"ВКЛ " : L"выкл"; };
    f.add(L"PID %lu   %ls", pid, motd.c_str());
    f.end_line();
    f.add(L"Защита: [1] шифрование %ls   [2] закрытые страницы %ls   [3] запрет открытия процесса %ls",
          on_off(vault.encrypted()), on_off(vault.pages_closed()), on_off(lock.locked()));
    f.end_line();
    f.add(L"> %ls", message.c_str());
    f.end_line();
    f.end_line();

    const std::uintptr_t vault_address = vault.address();
    vault.read([&](const GameState& s) {
        f.add(L"Игрок      ");
        f.ascii(s.name);
        f.add(L", «%ls», уровень %d", s.title, s.level);
        f.end_line();
        f.add(L"Здоровье   %d / %d    Броня %.1f    Деньги %d    Опыт %lld", s.health, s.max_health,
              static_cast<double>(s.armor), s.money, static_cast<long long>(s.experience));
        f.end_line();
        const std::uint32_t t = s.game_seconds % 86400;
        f.add(L"Позиция    %.2f, %.2f, %.2f    Время в игре %02u:%02u:%02u", static_cast<double>(s.x),
              static_cast<double>(s.y), static_cast<double>(s.z), t / 3600, t / 60 % 60, t % 60);
        f.end_line();
        f.end_line();

        f.add(L"Инвентарь (%u)", s.item_count);
        f.end_line();
        const std::uint32_t rows = (s.item_count + 1) / 2;
        for (std::uint32_t row = 0; row < rows; ++row) {
            for (std::uint32_t i = row; i < s.item_count; i += rows) {
                const Item& item = s.items[i];
                f.add(i == row ? L"  %-4u " : L"      %-4u ", item.id);
                f.ascii(item.name);
                f.add(L"%*ls x%-3u %3u%%  %4.1f кг", std::max(0, 18 - static_cast<int>(std::strlen(item.name))), L"",
                      static_cast<unsigned>(item.count), static_cast<unsigned>(item.condition),
                      static_cast<double>(item.weight));
            }
            f.end_line();
        }
        f.end_line();

        constexpr std::uint32_t kShownChat = 4;
        const std::uint32_t first = s.chat_count > kShownChat ? s.chat_count - kShownChat : 0;
        f.add(first > 0 ? L"Чат (последние %u из %u)" : L"Чат", kShownChat, s.chat_count);
        f.end_line();
        for (std::uint32_t i = first; i < s.chat_count; ++i) {
            f.add(L"  [%02u:%02u] %ls", s.chat[i].minute / 60 % 24, s.chat[i].minute % 60, s.chat[i].text);
            f.end_line();
        }
        f.end_line();
        f.add(L"Клавиши: d урон  e аптечка  m +500 денег  b купить аптечку  w шаг  c сообщение  r переместить данные");
        f.end_line();
        f.add(L"         a авто-режим (%ls)  1 2 3 защиты  0 снять все  i подсказки  q выход", on_off(options.ticking));
        f.end_line();
        if (options.hints) {
            f.add(L"  memhunter scan %lu -s ", pid);
            f.ascii(s.name);
            f.add(L"                       имя игрока (ASCII)");
            f.end_line();
            f.add(L"  memhunter scan %lu -s \"%ls\" --unicode     звание (UTF-16)", pid, s.title);
            f.end_line();
            f.add(L"  memhunter scan %lu -p \"money=", pid);
            f.hex(&s.money, sizeof(s.money));
            f.add(L"\"       деньги %d как int32 little-endian", s.money);
            f.end_line();
            f.add(L"  memhunter scan %lu -p \"PLR1=50 4C 52 31\"    начало структуры игрока, сейчас 0x%llX", pid,
                  static_cast<unsigned long long>(vault_address));
            f.end_line();
            f.add(L"  memhunter scan %lu -p \"ptr=", pid);
            f.hex(&world.player, sizeof(world.player));
            f.add(L"\"   указатель на игрока в объекте мира WRLD");
            f.end_line();
            f.add(L"  memhunter scan %lu -s Cordon --type mapped    сохранение игры (mapped, 0x%llX)", pid,
                  static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(save.address())));
            f.end_line();
            f.add(L"  memhunter scan %lu -s eu-west-2 --type private    настройки сервера в куче (%zu байт)", pid,
                  config.size());
            f.end_line();
            f.add(L"  memhunter snapshot %lu -o a.mhs   затем нажмите m   затем memhunter diff %lu a.mhs", pid, pid);
            f.end_line();
        }
    });
    return f.write(out);
}

// Same physical keys on the Russian layout, so the game works without switching the keyboard.
wchar_t normalize_key(wchar_t key) {
    static constexpr std::array<std::pair<wchar_t, wchar_t>, 10> kRussian{{
        {L'в', L'd'}, {L'у', L'e'}, {L'ь', L'm'}, {L'и', L'b'}, {L'ц', L'w'}, {L'с', L'c'},
        {L'к', L'r'}, {L'ф', L'a'}, {L'ш', L'i'}, {L'й', L'q'},
    }};
    if (key >= L'А' && key <= L'Я') {
        key = static_cast<wchar_t>(key - L'А' + L'а');
    }
    for (const auto& [from, to] : kRussian) {
        if (key == from) {
            return to;
        }
    }
    return key >= L'A' && key <= L'Z' ? static_cast<wchar_t>(key - L'A' + L'a') : key;
}

// Returns the next key, 0 at the end of piped input, or -1 when wait_ms passed without one. Piped input blocks.
int read_key(HANDLE in, bool console, int wait_ms) {
    if (!console) {
        char c = 0;
        DWORD got = 0;
        return ReadFile(in, &c, 1, &got, nullptr) && got == 1 ? static_cast<unsigned char>(c) : 0;
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(wait_ms);
    while (wait_ms < 0 || std::chrono::steady_clock::now() < deadline) {
        if (_kbhit()) {
            const wint_t key = _getwch();
            if (key == 0 || key == 0xE0) {
                _getwch();
                continue;
            }
            return static_cast<int>(key);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
    }
    return -1;
}

std::wstring describe_error(const wchar_t* what, DWORD error) {
    return std::wstring(what) + L": ошибка Windows " + std::to_wstring(error);
}

int run() {
    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    const bool console_out = GetConsoleMode(out, &mode) != 0;
    if (console_out) {
        if (!SetConsoleMode(out, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
            throw std::runtime_error("the console does not support VT sequences, error " + std::to_string(GetLastError()));
        }
        SetConsoleTitleW(L"MemHunter practice target");
        write_console(out, L"\x1b[?1049h\x1b[?25l\x1b[2J");
    }
    DWORD input_mode = 0;
    const bool console_in = GetConsoleMode(in, &input_mode) != 0;

    GameState initial = initial_state();
    Vault vault(initial);
    SecureZeroMemory(&initial, sizeof(initial));

    auto world = std::make_unique<World>();
    std::memcpy(world->tag, "WRLD", 4);
    world->players = 1;
    world->player = vault.address();
    std::wcsncpy(world->location, L"Кордон", 15);
    g_world = world.get();

    const SaveSection save;
    const std::string config =
        R"({"server":"eu-west-2.example.org","port":7777,"fov":90,"language":"ru","vsync":true,"master_volume":0.8})";
    const std::wstring motd = L"Добро пожаловать в Зону! Сервер eu-west-2, онлайн 128 игроков.";
    AccessLock lock;
    Options options;
    std::jthread ticker;
    std::wstring message = L"Найдите данные игрока из другого окна: memhunter scan " + std::to_wstring(GetCurrentProcessId()) + L" ...";
    std::size_t next_chat = 2;

    for (bool running = true; running;) {
        const COORD shown = console_out ? window_size(out) : COORD{0, 0};
        if (!render(out, console_out, shown, vault, *g_world, lock, save, config, motd, options, message)) {
            throw std::runtime_error("cannot write the screen, error " + std::to_string(GetLastError()));
        }
        int raw = -1;
        while (raw == -1) {
            raw = read_key(in, console_in, 500);
            const COORD now = console_out ? window_size(out) : COORD{0, 0};
            if (raw == -1 && (options.ticking || now.X != shown.X || now.Y != shown.Y)) {
                break;
            }
        }
        if (raw == -1) {
            continue;
        }
        if (raw == 0 || raw == 27) {
            break;
        }
        const wchar_t key = normalize_key(static_cast<wchar_t>(raw));
        if (!console_in && (key == L'\r' || key == L'\n')) {
            continue;
        }
        switch (key) {
            case L'd':
                vault.update([&](GameState& s) {
                    s.health -= 13;
                    message = L"Попадание: -13 здоровья.";
                    if (s.health <= 0) {
                        s.health = s.max_health;
                        s.money -= s.money / 10;
                        message = L"Вы погибли и возродились в лагере. Потеряно 10% денег.";
                    }
                });
                break;
            case L'e':
                vault.update([&](GameState& s) {
                    for (std::uint32_t i = 0; i < s.item_count; ++i) {
                        if (s.items[i].id == kMedkit && s.items[i].count > 0) {
                            --s.items[i].count;
                            s.health = std::min(s.max_health, s.health + 40);
                            message = L"Аптечка использована: +40 здоровья.";
                            return;
                        }
                    }
                    message = L"Аптечек нет. Купите: b.";
                });
                break;
            case L'm':
                vault.update([](GameState& s) { s.money += 500; });
                message = L"Получено 500 денег за задание.";
                break;
            case L'b':
                vault.update([&](GameState& s) {
                    if (s.money < 350) {
                        message = L"Не хватает денег: аптечка стоит 350.";
                        return;
                    }
                    s.money -= 350;
                    for (std::uint32_t i = 0; i < s.item_count; ++i) {
                        if (s.items[i].id == kMedkit) {
                            ++s.items[i].count;
                        }
                    }
                    message = L"Куплена аптечка за 350.";
                });
                break;
            case L'w':
                vault.update([](GameState& s) {
                    s.x += 1.5f;
                    s.z -= 0.75f;
                    s.experience += 120;
                    s.level = static_cast<std::int32_t>(1 + s.experience / 10000);
                    s.game_seconds += 30;
                });
                message = L"Шаг вперёд: позиция, опыт и время изменились.";
                break;
            case L'c':
                vault.update([&](GameState& s) {
                    if (s.chat_count == std::size(s.chat)) {
                        std::memmove(&s.chat[0], &s.chat[1], sizeof(ChatLine) * (s.chat_count - 1));
                        --s.chat_count;
                    }
                    ChatLine& line = s.chat[s.chat_count++];
                    line.minute = s.game_seconds / 60;
                    reveal(kChatSeeds[next_chat++ % kChatSeeds.size()], line.text);
                });
                message = L"Новое сообщение в чате (UTF-16).";
                break;
            case L'r': {
                const std::uintptr_t before = vault.address();
                vault.relocate();
                g_world->player = vault.address();
                wchar_t text[160];
                std::swprintf(text, 160, L"Данные перемещены: 0x%llX -> 0x%llX. Старые адреса больше не действуют.",
                              static_cast<unsigned long long>(before), static_cast<unsigned long long>(g_world->player));
                message = text;
                break;
            }
            case L'a':
                options.ticking = !options.ticking;
                if (options.ticking) {
                    ticker = std::jthread([&vault](std::stop_token stop) {
                        for (int tick = 0; !stop.stop_requested(); ++tick) {
                            for (int i = 0; i < 10 && !stop.stop_requested(); ++i) {
                                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                            }
                            vault.update([tick](GameState& s) {
                                ++s.game_seconds;
                                if (tick % 3 == 0 && s.health < s.max_health) {
                                    ++s.health;
                                }
                            });
                        }
                    });
                } else {
                    ticker = std::jthread();
                }
                message = options.ticking ? L"Авто-режим: каждую секунду идёт время и восстанавливается здоровье."
                                          : L"Авто-режим выключен.";
                break;
            case L'1':
                vault.set_encrypted(!vault.encrypted());
                message = vault.encrypted() ? L"Шифрование включено: состояние хранится под XOR-ключом, который меняется при каждой записи."
                                            : L"Шифрование выключено: значения снова лежат в памяти как есть.";
                break;
            case L'2':
                vault.set_pages_closed(!vault.pages_closed());
                message = vault.pages_closed() ? L"Страницы закрыты (PAGE_NOACCESS): открываются только на время обращения."
                                               : L"Страницы открыты (PAGE_READWRITE).";
                break;
            case L'3': {
                const DWORD error = lock.set(!lock.locked());
                message = error != ERROR_SUCCESS ? describe_error(L"Не удалось изменить права процесса", error)
                          : lock.locked() ? L"Открытие процесса для чтения запрещено. Уже открытые дескрипторы продолжают работать."
                                          : L"Права процесса восстановлены.";
                break;
            }
            case L'0': {
                vault.set_encrypted(false);
                vault.set_pages_closed(false);
                const DWORD error = lock.locked() ? lock.set(false) : ERROR_SUCCESS;
                message = error != ERROR_SUCCESS ? describe_error(L"Не удалось восстановить права процесса", error)
                                                 : L"Все защиты сняты.";
                break;
            }
            case L'i':
                options.hints = !options.hints;
                message = options.hints ? L"Подсказки показаны." : L"Подсказки скрыты: попробуйте найти всё сами.";
                break;
            case L'q':
                running = false;
                break;
            default:
                message = L"Неизвестная клавиша.";
                break;
        }
    }
    ticker = std::jthread();
    if (console_out) {
        write_console(out, L"\x1b[?25h\x1b[?1049l");
    }
    return 0;
}

}  // namespace

int main() {
    try {
        return run();
    } catch (const std::exception& error) {
        std::fprintf(stderr, "memhunter_practice: %s\n", error.what());
        return 1;
    }
}
