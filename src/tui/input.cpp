#include "tui/input.hpp"

#include "common/text.hpp"

namespace mh::tui {

bool LineEdit::handle(const Key& key) {
    switch (key.code) {
        case KeyCode::Char:
            if (key.ch < 0x20 || text_.size() >= kMaxLength) {
                return key.ch >= 0x20;
            }
            text_.insert(text_.begin() + static_cast<std::ptrdiff_t>(cursor_), key.ch);
            ++cursor_;
            return true;
        case KeyCode::Backspace:
            if (cursor_ > 0) {
                text_.erase(--cursor_, 1);
            }
            return true;
        case KeyCode::Delete:
            if (cursor_ < text_.size()) {
                text_.erase(cursor_, 1);
            }
            return true;
        case KeyCode::Left:
            cursor_ -= cursor_ > 0 ? 1 : 0;
            return true;
        case KeyCode::Right:
            cursor_ += cursor_ < text_.size() ? 1 : 0;
            return true;
        case KeyCode::Home:
            cursor_ = 0;
            return true;
        case KeyCode::End:
            cursor_ = text_.size();
            return true;
        default:
            return false;
    }
}

void LineEdit::set(std::string_view utf8) {
    const std::wstring wide = utf8_to_wide(utf8);
    text_.clear();
    for (std::size_t i = 0; i < wide.size() && text_.size() < kMaxLength; ++i) {
        char32_t ch = wide[i];
        if (ch >= 0xD800 && ch <= 0xDBFF && i + 1 < wide.size()) {
            ch = 0x10000 + ((ch - 0xD800) << 10) + (static_cast<char32_t>(wide[++i]) - 0xDC00);
        }
        text_.push_back(ch);
    }
    cursor_ = text_.size();
}

void LineEdit::clear() {
    text_.clear();
    cursor_ = 0;
}

std::string LineEdit::utf8() const {
    std::string out;
    for (const char32_t ch : text_) {
        append_utf8(out, ch);
    }
    return out;
}

}  // namespace mh::tui
