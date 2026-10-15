#pragma once

#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "common/text.hpp"
#include "pattern/pattern.hpp"
#include "support/child_process.hpp"
#include "target/needles.hpp"

namespace mh::testing {

inline constexpr std::uint64_t kTargetSeed = 0x5EED1234;

struct Needle {
    std::string name;
    std::uint32_t index = 0;
    std::string encoding;
    std::uint64_t address = 0;
    bool expect = false;
};

// A running memhunter_test_target together with the needle table it printed.
struct TargetProcess {
    std::unique_ptr<ChildProcess> child;
    std::uint32_t pid = 0;
    std::vector<Needle> needles;
    std::uint64_t fill_bytes = 0;
    std::uint32_t fill_needles = 0;
    // An int32 alone on its page, changed with the "set N" command.
    std::uint64_t counter = 0;

    std::vector<std::uint64_t> addresses(std::string_view name, bool expected = true) const {
        std::vector<std::uint64_t> out;
        for (const auto& needle : needles) {
            if (needle.name == name && needle.expect == expected) {
                out.push_back(needle.address);
            }
        }
        return out;
    }

    std::string command(std::string_view line) {
        child->write_line(line);
        return child->read_line().value_or("");
    }
};

inline TargetProcess start_target(const std::string& executable, std::vector<std::string> extra = {}) {
    std::vector<std::string> args{"--seed", std::to_string(kTargetSeed)};
    args.insert(args.end(), extra.begin(), extra.end());
    TargetProcess target;
    target.child = std::make_unique<ChildProcess>(executable, args);
    while (const auto line = target.child->read_line()) {
        std::istringstream in(*line);
        std::string word;
        in >> word;
        if (word == "pid") {
            in >> target.pid;
        } else if (word == "needle") {
            Needle needle;
            std::string address;
            int expect = 0;
            in >> needle.name >> needle.index >> needle.encoding >> address >> expect;
            needle.address = parse_uint(address).value_or(0);
            needle.expect = expect != 0;
            target.needles.push_back(needle);
        } else if (word == "counter") {
            std::string address;
            in >> address;
            target.counter = parse_uint(address).value_or(0);
        } else if (word == "fill") {
            in >> target.fill_bytes >> target.fill_needles;
        } else if (word == "ready") {
            break;
        }
    }
    return target;
}

inline std::vector<std::uint8_t> needle_bytes(std::uint32_t index) {
    std::vector<std::uint8_t> bytes;
    for (std::size_t i = 0; i < kNeedleSize; ++i) {
        bytes.push_back(needle_byte(kTargetSeed, index, i));
    }
    return bytes;
}

inline Pattern byte_needle(std::uint32_t index) {
    Pattern pattern;
    pattern.label = "n" + std::to_string(index);
    pattern.value = needle_bytes(index);
    pattern.and_mask.assign(kNeedleSize, 0xFF);
    pattern.or_mask.assign(kNeedleSize, 0x00);
    return pattern;
}

// "AB CD ..." as accepted by --pattern.
inline std::string needle_signature(std::uint32_t index) {
    const auto bytes = needle_bytes(index);
    return hex_preview(std::as_bytes(std::span(bytes)));
}

inline std::string text_needle(std::uint32_t index) {
    std::string text;
    for (std::size_t i = 0; i < kTextNeedleSize; ++i) {
        text.push_back(needle_letter(kTargetSeed, index, i));
    }
    return text;
}

}  // namespace mh::testing
