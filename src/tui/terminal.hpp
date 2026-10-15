#pragma once

#include <chrono>
#include <cstddef>
#include <deque>
#include <optional>
#include <string_view>

#include "tui/input.hpp"

namespace mh::tui {

struct TerminalSize {
    std::size_t width = 0;
    std::size_t height = 0;
};

// Puts the Windows console into full-screen mode for the lifetime of the object: alternate screen, hidden
// cursor, raw key input with virtual terminal output. The previous modes and screen are restored on exit.
class Terminal {
public:
    // Throws Error when stdin/stdout are not a console or the console cannot process VT sequences.
    Terminal();
    ~Terminal();
    Terminal(const Terminal&) = delete;
    Terminal& operator=(const Terminal&) = delete;

    TerminalSize size() const;
    void write(std::wstring_view text);

    // Waits up to `timeout` for a key press; nullopt on timeout or after a non-key event such as a resize.
    std::optional<Key> read_key(std::chrono::milliseconds timeout);

private:
    void* input_ = nullptr;
    void* output_ = nullptr;
    unsigned long input_mode_ = 0;
    unsigned long output_mode_ = 0;
    char16_t pending_surrogate_ = 0;
    std::deque<Key> keys_;
};

}  // namespace mh::tui
