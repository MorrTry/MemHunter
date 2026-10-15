#include "tui/screen.hpp"

#include <algorithm>

#include "common/text.hpp"

namespace mh::tui {

namespace {

// Decodes one code point and advances `i`; malformed input yields U+FFFD for one byte.
char32_t next_code_point(std::string_view s, std::size_t& i) {
    const auto lead = static_cast<unsigned char>(s[i]);
    std::size_t length = 0;
    char32_t cp = 0;
    if (lead < 0x80) {
        ++i;
        return lead;
    }
    if ((lead & 0xE0) == 0xC0) {
        length = 2;
        cp = lead & 0x1F;
    } else if ((lead & 0xF0) == 0xE0) {
        length = 3;
        cp = lead & 0x0F;
    } else if ((lead & 0xF8) == 0xF0) {
        length = 4;
        cp = lead & 0x07;
    } else {
        ++i;
        return U'�';
    }
    if (i + length > s.size()) {
        ++i;
        return U'�';
    }
    for (std::size_t k = 1; k < length; ++k) {
        const auto next = static_cast<unsigned char>(s[i + k]);
        if ((next & 0xC0) != 0x80) {
            ++i;
            return U'�';
        }
        cp = (cp << 6) | (next & 0x3F);
    }
    i += length;
    const bool overlong = (length == 2 && cp < 0x80) || (length == 3 && cp < 0x800) || (length == 4 && cp < 0x10000);
    if (overlong || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
        return U'�';
    }
    return cp;
}

char32_t printable(char32_t ch) {
    return ch < 0x20 || (ch >= 0x7F && ch < 0xA0) ? U'.' : ch;
}

void append_wide(std::wstring& out, char32_t ch) {
    if (ch >= 0x10000) {
        ch -= 0x10000;
        out.push_back(static_cast<wchar_t>(0xD800 + (ch >> 10)));
        out.push_back(static_cast<wchar_t>(0xDC00 + (ch & 0x3FF)));
    } else {
        out.push_back(static_cast<wchar_t>(ch));
    }
}

void append_ascii(std::wstring& out, std::string_view text) {
    out.append(text.begin(), text.end());
}

}  // namespace

std::size_t char_width(char32_t ch) noexcept {
    const bool wide = (ch >= 0x1100 && ch <= 0x115F) || (ch >= 0x2E80 && ch <= 0x303E) || (ch >= 0x3041 && ch <= 0x33FF) ||
                      (ch >= 0x3400 && ch <= 0x4DBF) || (ch >= 0x4E00 && ch <= 0x9FFF) || (ch >= 0xA000 && ch <= 0xA4CF) ||
                      (ch >= 0xAC00 && ch <= 0xD7A3) || (ch >= 0xF900 && ch <= 0xFAFF) || (ch >= 0xFE30 && ch <= 0xFE4F) ||
                      (ch >= 0xFF00 && ch <= 0xFF60) || (ch >= 0xFFE0 && ch <= 0xFFE6) || (ch >= 0x20000 && ch <= 0x3FFFD);
    return wide ? 2 : 1;
}

std::size_t text_width(std::string_view utf8) {
    std::size_t width = 0;
    for (std::size_t i = 0; i < utf8.size();) {
        width += char_width(next_code_point(utf8, i));
    }
    return width;
}

Screen::Screen(std::size_t width, std::size_t height) : width_(width), height_(height), cells_(width * height) {}

std::size_t Screen::text(std::size_t x, std::size_t y, std::string_view utf8, Style style, std::size_t max_width) {
    if (y >= height_ || x >= width_) {
        return 0;
    }
    const std::size_t limit = std::min(max_width, width_ - x);
    std::size_t used = 0;
    for (std::size_t i = 0; i < utf8.size();) {
        const char32_t ch = printable(next_code_point(utf8, i));
        const std::size_t w = char_width(ch);
        if (used + w > limit) {
            break;
        }
        cells_[y * width_ + x + used] = {ch, style};
        if (w == 2) {
            cells_[y * width_ + x + used + 1] = {0, style};
        }
        used += w;
    }
    return used;
}

void Screen::put(std::size_t x, std::size_t y, char32_t ch, Style style) {
    if (x < width_ && y < height_) {
        cells_[y * width_ + x] = {printable(ch), style};
    }
}

void Screen::fill(std::size_t x, std::size_t y, std::size_t w, std::size_t h, char32_t ch, Style style) {
    for (std::size_t row = y; row < std::min(y + h, height_); ++row) {
        for (std::size_t col = x; col < std::min(x + w, width_); ++col) {
            cells_[row * width_ + col] = {ch, style};
        }
    }
}

void Screen::frame(std::size_t x, std::size_t y, std::size_t w, std::size_t h, const Frame& f, Style style) {
    if (w < 2 || h < 2) {
        return;
    }
    const std::size_t right = x + w - 1;
    const std::size_t bottom = y + h - 1;
    fill(x + 1, y, w - 2, 1, f.horizontal, style);
    fill(x + 1, bottom, w - 2, 1, f.horizontal, style);
    fill(x, y + 1, 1, h - 2, f.vertical, style);
    fill(right, y + 1, 1, h - 2, f.vertical, style);
    put(x, y, f.top_left, style);
    put(right, y, f.top_right, style);
    put(x, bottom, f.bottom_left, style);
    put(right, bottom, f.bottom_right, style);
}

void Screen::restyle(std::size_t x, std::size_t y, std::size_t w, Style style) {
    if (y >= height_) {
        return;
    }
    for (std::size_t col = x; col < std::min(x + w, width_); ++col) {
        cells_[y * width_ + col].style = style;
    }
}

std::string Screen::row(std::size_t y) const {
    std::string out;
    for (std::size_t x = 0; x < width_; ++x) {
        if (const char32_t ch = at(x, y).ch; ch != 0) {
            append_utf8(out, ch);
        }
    }
    return out;
}

std::wstring render(const Screen& next, const Screen* previous) {
    const bool full = previous == nullptr || previous->width() != next.width() || previous->height() != next.height();
    std::wstring out;
    out.reserve(next.width() * next.height() + 64);
    if (full) {
        append_ascii(out, theme::kNormalSgr);
        append_ascii(out, "\x1b[2J");
    }
    bool styled = false;
    Style current = Style::Normal;
    for (std::size_t y = 0; y < next.height(); ++y) {
        if (!full) {
            bool same = true;
            for (std::size_t x = 0; x < next.width() && same; ++x) {
                same = next.at(x, y) == previous->at(x, y);
            }
            if (same) {
                continue;
            }
        }
        append_ascii(out, "\x1b[" + std::to_string(y + 1) + ";1H");
        for (std::size_t x = 0; x < next.width(); ++x) {
            const Cell& cell = next.at(x, y);
            // A half of a wide character that was partly overdrawn becomes a space, so the row never shifts.
            char32_t ch = cell.ch;
            if (ch == 0) {
                if (x > 0 && next.at(x - 1, y).ch != 0 && char_width(next.at(x - 1, y).ch) == 2) {
                    continue;
                }
                ch = U' ';
            } else if (char_width(ch) == 2 && (x + 1 == next.width() || next.at(x + 1, y).ch != 0)) {
                ch = U' ';
            }
            if (!styled || cell.style != current) {
                append_ascii(out, theme::sgr(cell.style));
                current = cell.style;
                styled = true;
            }
            append_wide(out, ch);
        }
    }
    if (styled) {
        append_ascii(out, theme::kNormalSgr);
    }
    return out;
}

}  // namespace mh::tui
