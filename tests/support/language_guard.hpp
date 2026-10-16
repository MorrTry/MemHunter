#pragma once

#include "gui/lang.hpp"

namespace mh::testing {

// Sets the GUI language for the current scope and restores the previous one
// when it ends. The app defaults to English, so tests that check the Russian
// wording pin the language to Russian for as long as the guard lives.
class LanguageGuard {
public:
    explicit LanguageGuard(mh::gui::Lang lang) : previous_(mh::gui::current_language()) {
        mh::gui::set_language(lang);
    }
    ~LanguageGuard() {
        mh::gui::set_language(previous_);
    }
    LanguageGuard(const LanguageGuard&) = delete;
    LanguageGuard& operator=(const LanguageGuard&) = delete;

private:
    mh::gui::Lang previous_;
};

}  // namespace mh::testing
