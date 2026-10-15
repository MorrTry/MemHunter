#include <algorithm>

#include "scanner/matchers.hpp"

namespace mh {

NaiveMatcher::NaiveMatcher(std::vector<CompiledPattern> patterns) : patterns_(std::move(patterns)) {}

void NaiveMatcher::scan(std::span<const std::byte> data, std::uint64_t, std::size_t report_begin,
                        std::size_t report_end, std::vector<Hit>& hits) const {
    const auto* bytes = as_bytes(data.data());
    const std::size_t size = data.size();
    report_end = std::min(report_end, size);
    for (std::size_t start = report_begin; start < report_end; ++start) {
        for (const auto& pattern : patterns_) {
            if (start + pattern.size <= size && pattern.matches(bytes + start)) {
                hits.push_back({start, pattern.id, pattern.size});
            }
        }
    }
}

std::string NaiveMatcher::describe() const {
    return "naive(" + std::to_string(patterns_.size()) + ")";
}

CompositeMatcher::CompositeMatcher(std::vector<std::unique_ptr<Matcher>> parts) : parts_(std::move(parts)) {}

void CompositeMatcher::scan(std::span<const std::byte> data, std::uint64_t base_address, std::size_t report_begin,
                            std::size_t report_end, std::vector<Hit>& hits) const {
    for (const auto& part : parts_) {
        part->scan(data, base_address, report_begin, report_end, hits);
    }
}

std::string CompositeMatcher::describe() const {
    std::string text;
    for (std::size_t i = 0; i < parts_.size();) {
        const std::string name = parts_[i]->describe();
        std::size_t run = 1;
        while (i + run < parts_.size() && parts_[i + run]->describe() == name) {
            ++run;
        }
        text += (text.empty() ? "" : " + ") + (run > 1 ? std::to_string(run) + " x " : "") + name;
        i += run;
    }
    return text;
}

}  // namespace mh
