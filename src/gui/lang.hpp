#pragma once

#include <cstdint>
#include <string>

namespace mh::gui {

enum class Lang { English, Russian };

Lang current_language();
void set_language(Lang lang);

// UI string in the active language. Pass the English text and its Russian
// translation; the pair lives at the call site, so there is no key to keep in
// sync. Returns a stable pointer to a string literal.
inline const char* tr(const char* en, const char* ru) {
    return current_language() == Lang::English ? en : ru;
}

// Same for wide strings (Win32 dialog titles, filters, message boxes).
inline const wchar_t* tr(const wchar_t* en, const wchar_t* ru) {
    return current_language() == Lang::English ? en : ru;
}

// Count followed by a noun in the correct plural form for the active language.
// English uses one/other; Russian uses one/few/many. With group, the number is
// written with digit grouping (12 345), otherwise plainly.
std::string plural(std::uint64_t count, bool group,
                   const char* en_one, const char* en_other,
                   const char* ru_one, const char* ru_few, const char* ru_many);

}  // namespace mh::gui
