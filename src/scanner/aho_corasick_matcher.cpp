#include <algorithm>
#include <limits>
#include <stdexcept>

#include "common/error.hpp"
#include "scanner/matchers.hpp"

namespace mh {

namespace {

// Transition entries hold the next state pre-multiplied by the class count, so the hot loop needs no
// multiplication; the top bit marks states that have outputs.
constexpr std::uint32_t kOutputFlag = 0x8000'0000u;
constexpr std::uint32_t kStateMask = ~kOutputFlag;
constexpr std::uint64_t kMaxTableBytes = 512ull << 20;

}  // namespace

AhoCorasickMatcher::AhoCorasickMatcher(std::vector<CompiledPattern> patterns, std::size_t max_anchor_length)
    : patterns_(std::move(patterns)) {
    bool fold = false;
    for (const auto& pattern : patterns_) {
        fold |= pattern.folds_case;
    }
    const auto fold_table = make_fold_table(fold);

    struct Entry {
        std::vector<std::uint8_t> bytes;
        std::uint32_t pattern;
        std::uint32_t anchor_end;
    };
    std::vector<Entry> entries;
    std::array<bool, 256> used{};
    min_anchor_offset_ = std::numeric_limits<std::size_t>::max();
    for (std::uint32_t index = 0; index < patterns_.size(); ++index) {
        const auto& pattern = patterns_[index];
        const Anchor anchor = choose_anchor(pattern, max_anchor_length);
        if (anchor.empty()) {
            throw std::invalid_argument("Aho-Corasick needs at least one fixed byte per pattern");
        }
        Entry entry{{}, index, static_cast<std::uint32_t>(anchor.offset + anchor.length)};
        for (std::size_t k = 0; k < anchor.length; ++k) {
            const std::uint8_t byte = fold_table[pattern.value[anchor.offset + k]];
            entry.bytes.push_back(byte);
            used[byte] = true;
        }
        min_anchor_offset_ = std::min(min_anchor_offset_, anchor.offset);
        max_anchor_end_ = std::max<std::size_t>(max_anchor_end_, entry.anchor_end);
        entries.push_back(std::move(entry));
    }
    if (entries.empty()) {
        min_anchor_offset_ = 0;
    }

    // Byte classes shrink the table to (distinct anchor bytes + 1) columns; class 0 collects every other byte.
    std::array<std::uint16_t, 256> class_of_folded{};
    class_count_ = 1;
    for (std::size_t b = 0; b < 256; ++b) {
        if (used[b]) {
            class_of_folded[b] = static_cast<std::uint16_t>(class_count_++);
        }
    }
    for (std::size_t b = 0; b < 256; ++b) {
        classes_[b] = class_of_folded[fold_table[b]];
    }
    const std::uint32_t columns = class_count_;

    std::vector<std::int32_t> next;
    std::vector<std::vector<Output>> outputs;
    const auto add_state = [&] {
        next.insert(next.end(), columns, -1);
        outputs.emplace_back();
        return static_cast<std::int32_t>(outputs.size() - 1);
    };
    add_state();
    for (const auto& entry : entries) {
        std::int32_t state = 0;
        for (const std::uint8_t byte : entry.bytes) {
            const std::size_t slot = static_cast<std::size_t>(state) * columns + class_of_folded[byte];
            if (next[slot] < 0) {
                const std::int32_t created = add_state();
                next[slot] = created;
            }
            state = next[slot];
        }
        outputs[static_cast<std::size_t>(state)].push_back({entry.pattern, entry.anchor_end});
    }

    const std::size_t states = outputs.size();
    if (static_cast<std::uint64_t>(states) * columns * sizeof(std::uint32_t) > kMaxTableBytes ||
        static_cast<std::uint64_t>(states) * columns > kStateMask) {
        throw Error(ErrorCode::InvalidArgument, "too many patterns for a single Aho-Corasick pass (" +
                                                    std::to_string(states) + " states); split the pattern list");
    }

    // Breadth-first construction of failure links turns the trie into a complete DFA. A state's failure
    // target is shallower, so its transitions and merged outputs are final by the time they are copied.
    std::vector<std::int32_t> fail(states, 0);
    std::vector<std::int32_t> queue;
    queue.reserve(states);
    for (std::uint32_t c = 0; c < columns; ++c) {
        if (next[c] < 0) {
            next[c] = 0;
        } else {
            queue.push_back(next[c]);
        }
    }
    for (std::size_t head = 0; head < queue.size(); ++head) {
        const auto u = static_cast<std::size_t>(queue[head]);
        const auto fail_u = static_cast<std::size_t>(fail[u]);
        for (std::uint32_t c = 0; c < columns; ++c) {
            const std::int32_t v = next[u * columns + c];
            const std::int32_t fallback = next[fail_u * columns + c];
            if (v < 0) {
                next[u * columns + c] = fallback;
            } else {
                fail[static_cast<std::size_t>(v)] = fallback;
                const auto& inherited = outputs[static_cast<std::size_t>(fallback)];
                auto& own = outputs[static_cast<std::size_t>(v)];
                own.insert(own.end(), inherited.begin(), inherited.end());
                queue.push_back(v);
            }
        }
    }

    table_.resize(states * columns);
    for (std::size_t i = 0; i < table_.size(); ++i) {
        const auto target = static_cast<std::uint32_t>(next[i]);
        table_[i] = target * columns | (outputs[target].empty() ? 0u : kOutputFlag);
    }
    output_begin_.reserve(states + 1);
    for (const auto& list : outputs) {
        output_begin_.push_back(static_cast<std::uint32_t>(outputs_.size()));
        outputs_.insert(outputs_.end(), list.begin(), list.end());
    }
    output_begin_.push_back(static_cast<std::uint32_t>(outputs_.size()));
}

void AhoCorasickMatcher::scan(std::span<const std::byte> data, std::uint64_t, std::size_t report_begin,
                              std::size_t report_end, std::vector<Hit>& hits) const {
    const auto* bytes = as_bytes(data.data());
    const std::size_t size = data.size();
    report_end = std::min(report_end, size);
    if (report_begin >= report_end || patterns_.empty()) {
        return;
    }
    const std::size_t begin = report_begin + min_anchor_offset_;
    const std::size_t end = std::min(size, report_end - 1 + max_anchor_end_);
    const std::uint32_t* table = table_.data();
    const std::uint16_t* classes = classes_.data();
    std::uint32_t state = 0;
    for (std::size_t i = begin; i < end; ++i) {
        const std::uint32_t entry = table[state + classes[bytes[i]]];
        state = entry & kStateMask;
        if ((entry & kOutputFlag) != 0) [[unlikely]] {
            report(bytes, size, i, state / class_count_, report_begin, report_end, hits);
        }
    }
}

void AhoCorasickMatcher::report(const std::uint8_t* data, std::size_t size, std::size_t position, std::uint32_t state,
                                std::size_t report_begin, std::size_t report_end, std::vector<Hit>& hits) const {
    for (std::uint32_t k = output_begin_[state]; k < output_begin_[state + 1]; ++k) {
        const Output& output = outputs_[k];
        if (position + 1 < output.anchor_end) {
            continue;
        }
        const std::size_t start = position + 1 - output.anchor_end;
        const auto& pattern = patterns_[output.pattern];
        if (start >= report_begin && start < report_end && start + pattern.size <= size && pattern.matches(data + start)) {
            hits.push_back({start, pattern.id, pattern.size});
        }
    }
}

std::string AhoCorasickMatcher::describe() const {
    return "aho-corasick(" + std::to_string(patterns_.size()) + " patterns, " + std::to_string(state_count()) + " states)";
}

}  // namespace mh
