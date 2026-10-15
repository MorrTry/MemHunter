#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace mh::tui {

enum class KeyCode : std::uint8_t {
    Char,
    Enter,
    Escape,
    Tab,
    BackTab,
    Up,
    Down,
    Left,
    Right,
    PageUp,
    PageDown,
    Home,
    End,
    Backspace,
    Delete,
    F2,
    F3,
    F5,
    F10,
    CtrlC,
};

struct Key {
    KeyCode code = KeyCode::Char;
    char32_t ch = 0;

    static Key of(KeyCode code) { return {code, 0}; }
    static Key character(char32_t ch) { return {KeyCode::Char, ch}; }
};

// Single-line text input with a cursor.
class LineEdit {
public:
    static constexpr std::size_t kMaxLength = 4096;

    explicit LineEdit(std::string placeholder = {}) : placeholder_(std::move(placeholder)) {}

    // Returns false for keys that are not editing keys, so the caller can handle them.
    bool handle(const Key& key);

    void set(std::string_view utf8);
    void clear();
    std::string utf8() const;
    bool empty() const noexcept { return text_.empty(); }

    const std::u32string& text() const noexcept { return text_; }
    std::size_t cursor() const noexcept { return cursor_; }
    const std::string& placeholder() const noexcept { return placeholder_; }

private:
    std::u32string text_;
    std::size_t cursor_ = 0;
    std::string placeholder_;
};

}  // namespace mh::tui
