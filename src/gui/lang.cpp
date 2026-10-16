#include "gui/lang.hpp"

namespace mh::gui {

std::string group_digits(std::uint64_t value);

namespace {
Lang g_language = Lang::English;
}

Lang current_language() { return g_language; }

void set_language(Lang lang) { g_language = lang; }

std::string plural(std::uint64_t count, bool group,
                   const char* en_one, const char* en_other,
                   const char* ru_one, const char* ru_few, const char* ru_many) {
    const std::string number = group ? group_digits(count) : std::to_string(count);
    if (g_language == Lang::English) {
        return number + " " + (count == 1 ? en_one : en_other);
    }
    const std::uint64_t tens = count % 100;
    const std::uint64_t ones = count % 10;
    const char* word = (tens >= 11 && tens <= 14) ? ru_many
                       : ones == 1               ? ru_one
                       : (ones >= 2 && ones <= 4) ? ru_few
                                                  : ru_many;
    return number + " " + word;
}

}  // namespace mh::gui
