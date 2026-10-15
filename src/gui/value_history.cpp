#include "gui/value_history.hpp"

#include <numeric>
#include <string_view>
#include <utility>

namespace mh::gui {
namespace {

std::string_view trimmed(std::string_view text) {
    constexpr std::string_view kSpace = " \t\r\n";
    const std::size_t begin = text.find_first_not_of(kSpace);
    if (begin == std::string_view::npos) {
        return {};
    }
    return text.substr(begin, text.find_last_not_of(kSpace) - begin + 1);
}

std::string condition_text(const SearchForm& form) {
    const std::string number(trimmed(form.number));
    switch (form.compare) {
        case Compare::Exact: return "= " + number;
        case Compare::Greater: return "> " + number;
        case Compare::Less: return "< " + number;
        case Compare::Between: return "от " + number + " до " + std::string(trimmed(form.number_high));
        case Compare::Unknown: return "неизвестное";
        case Compare::Increased: return "Увеличилось";
        case Compare::Decreased: return "Уменьшилось";
        case Compare::Changed: return "Изменилось";
        case Compare::Unchanged: return "Не изменилось";
    }
    return {};
}

}  // namespace

std::string describe_scan(const SearchForm& form, NumberType type, bool first) {
    if (!first) {
        return condition_text(form);
    }
    const std::string separator = form.compare == Compare::Unknown ? ", " : " ";
    return std::string(to_string(type)) + separator + condition_text(form);
}

void ValueHistory::push(std::shared_ptr<const ValueCandidates> candidates, std::string label, std::uint64_t budget) {
    if (!steps_.empty()) {
        steps_.resize(current_ + 1);
    }
    const std::uint64_t count = candidates->count();
    steps_.push_back({std::move(candidates), std::move(label), count});
    if (budget != 0) {
        std::uint64_t stored = std::accumulate(steps_.begin(), steps_.end(), std::uint64_t{0},
                                               [](std::uint64_t sum, const HistoryStep& step) { return sum + step.candidates->stored_bytes(); });
        std::size_t dropped = 0;
        while (stored > budget && dropped + 1 < steps_.size()) {
            stored -= steps_[dropped].candidates->stored_bytes();
            ++dropped;
        }
        if (dropped > 0) {
            steps_.erase(steps_.begin(), steps_.begin() + static_cast<std::ptrdiff_t>(dropped));
            trimmed_ = true;
        }
    }
    current_ = steps_.size() - 1;
}

void ValueHistory::clear() {
    steps_.clear();
    current_ = 0;
    trimmed_ = false;
}

void ValueHistory::go_to(std::size_t step) {
    if (step < steps_.size()) {
        current_ = step;
    }
}

}  // namespace mh::gui
