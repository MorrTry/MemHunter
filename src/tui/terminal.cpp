#include "tui/terminal.hpp"

#include <windows.h>

#include <algorithm>
#include <array>
#include <string>

#include "common/error.hpp"

namespace mh::tui {

namespace {

constexpr std::wstring_view kEnter = L"\x1b[?1049h\x1b[?25l\x1b[?7l";
constexpr std::wstring_view kLeave = L"\x1b[0m\x1b[?7h\x1b[?25h\x1b[?1049l";

std::optional<Key> translate(const KEY_EVENT_RECORD& event, char16_t& surrogate) {
    const bool shift = (event.dwControlKeyState & SHIFT_PRESSED) != 0;
    switch (event.wVirtualKeyCode) {
        case VK_RETURN: return Key::of(KeyCode::Enter);
        case VK_ESCAPE: return Key::of(KeyCode::Escape);
        case VK_TAB: return Key::of(shift ? KeyCode::BackTab : KeyCode::Tab);
        case VK_UP: return Key::of(KeyCode::Up);
        case VK_DOWN: return Key::of(KeyCode::Down);
        case VK_LEFT: return Key::of(KeyCode::Left);
        case VK_RIGHT: return Key::of(KeyCode::Right);
        case VK_PRIOR: return Key::of(KeyCode::PageUp);
        case VK_NEXT: return Key::of(KeyCode::PageDown);
        case VK_HOME: return Key::of(KeyCode::Home);
        case VK_END: return Key::of(KeyCode::End);
        case VK_BACK: return Key::of(KeyCode::Backspace);
        case VK_DELETE: return Key::of(KeyCode::Delete);
        case VK_F2: return Key::of(KeyCode::F2);
        case VK_F3: return Key::of(KeyCode::F3);
        case VK_F5: return Key::of(KeyCode::F5);
        case VK_F10: return Key::of(KeyCode::F10);
        default: break;
    }
    const auto unit = static_cast<char16_t>(event.uChar.UnicodeChar);
    if (unit == 3) {
        return Key::of(KeyCode::CtrlC);
    }
    if (unit >= 0xD800 && unit <= 0xDBFF) {
        surrogate = unit;
        return std::nullopt;
    }
    if (unit >= 0xDC00 && unit <= 0xDFFF) {
        const char16_t high = surrogate;
        surrogate = 0;
        if (high == 0) {
            return std::nullopt;
        }
        return Key::character(0x10000 + ((static_cast<char32_t>(high) - 0xD800) << 10) + (static_cast<char32_t>(unit) - 0xDC00));
    }
    if (unit >= 0x20) {
        return Key::character(unit);
    }
    return std::nullopt;
}

}  // namespace

Terminal::Terminal() {
    input_ = GetStdHandle(STD_INPUT_HANDLE);
    output_ = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD input_mode = 0;
    DWORD output_mode = 0;
    if (input_ == INVALID_HANDLE_VALUE || output_ == INVALID_HANDLE_VALUE || !GetConsoleMode(input_, &input_mode) ||
        !GetConsoleMode(output_, &output_mode)) {
        throw Error(ErrorCode::InvalidArgument,
                    "'memhunter tui' needs an interactive console window; use 'memhunter scan' with pipes and scripts");
    }
    input_mode_ = input_mode;
    output_mode_ = output_mode;
    if (!SetConsoleMode(output_, output_mode | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING |
                                     DISABLE_NEWLINE_AUTO_RETURN)) {
        throw Error(ErrorCode::SystemError,
                    "this console cannot process virtual terminal sequences (Windows 10 1607 or later is needed); "
                    "use 'memhunter scan' instead");
    }
    // Raw input: no line editing or echo, Ctrl+C arrives as a key, and Quick Edit cannot freeze output.
    if (!SetConsoleMode(input_, ENABLE_WINDOW_INPUT | ENABLE_EXTENDED_FLAGS)) {
        const DWORD error = GetLastError();
        SetConsoleMode(output_, output_mode_);
        throw_win32(ErrorCode::SystemError, "cannot switch the console to raw input", error);
    }
    try {
        write(kEnter);
    } catch (...) {
        SetConsoleMode(input_, input_mode_);
        SetConsoleMode(output_, output_mode_);
        throw;
    }
}

Terminal::~Terminal() {
    // Best effort: a destructor cannot report failure, and the console is restored as far as it still allows.
    DWORD written = 0;
    WriteConsoleW(output_, kLeave.data(), static_cast<DWORD>(kLeave.size()), &written, nullptr);
    SetConsoleMode(input_, input_mode_ | ENABLE_EXTENDED_FLAGS);
    SetConsoleMode(output_, output_mode_);
}

TerminalSize Terminal::size() const {
    CONSOLE_SCREEN_BUFFER_INFO info{};
    if (!GetConsoleScreenBufferInfo(output_, &info)) {
        throw_win32(ErrorCode::SystemError, "cannot query the console size", GetLastError());
    }
    return {static_cast<std::size_t>(info.srWindow.Right - info.srWindow.Left + 1),
            static_cast<std::size_t>(info.srWindow.Bottom - info.srWindow.Top + 1)};
}

void Terminal::write(std::wstring_view text) {
    while (!text.empty()) {
        DWORD written = 0;
        const auto chunk = static_cast<DWORD>(std::min<std::size_t>(text.size(), 1u << 15));
        if (!WriteConsoleW(output_, text.data(), chunk, &written, nullptr) || written == 0) {
            throw_win32(ErrorCode::SystemError, "cannot write to the console", GetLastError());
        }
        text.remove_prefix(written);
    }
}

std::optional<Key> Terminal::read_key(std::chrono::milliseconds timeout) {
    if (keys_.empty()) {
        const DWORD wait = WaitForSingleObject(input_, static_cast<DWORD>(timeout.count()));
        if (wait == WAIT_TIMEOUT) {
            return std::nullopt;
        }
        if (wait != WAIT_OBJECT_0) {
            throw_win32(ErrorCode::SystemError, "cannot wait for console input", GetLastError());
        }
        std::array<INPUT_RECORD, 32> records{};
        DWORD count = 0;
        if (!ReadConsoleInputW(input_, records.data(), static_cast<DWORD>(records.size()), &count)) {
            throw_win32(ErrorCode::SystemError, "cannot read console input", GetLastError());
        }
        for (DWORD i = 0; i < count; ++i) {
            if (records[i].EventType != KEY_EVENT || !records[i].Event.KeyEvent.bKeyDown) {
                continue;
            }
            const KEY_EVENT_RECORD& event = records[i].Event.KeyEvent;
            if (const auto key = translate(event, pending_surrogate_)) {
                for (WORD repeat = 0; repeat < std::max<WORD>(event.wRepeatCount, 1); ++repeat) {
                    keys_.push_back(*key);
                }
            }
        }
    }
    if (keys_.empty()) {
        return std::nullopt;
    }
    const Key key = keys_.front();
    keys_.pop_front();
    return key;
}

}  // namespace mh::tui
