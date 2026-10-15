// Reproducible measurements behind the numbers in bench/README.md.
//
//   memhunter_bench algorithms [--size 128M] [--repeat 3] [--seed 1] [--counts 1,2,3,5,10,20,30,40,50,64,100]
//       Single-threaded matcher throughput on synthetic buffers, every algorithm cross-checked against the others.
//   memhunter_bench process [--fill 2G] [--patterns 10] [--threads 1,4,8,16] [--readers 0] [--chunk 256K] [--repeat 3]
//                           [--algorithm auto] [--target PATH]
//       Full scans of a spawned memhunter_test_target holding --fill bytes of random data with planted signatures.
//       Every configuration is also run with a matcher that does nothing, which isolates the cost of reading.
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <map>
#include <random>
#include <set>
#include <string>
#include <thread>
#include <vector>

#if defined(_MSC_VER)
#include <intrin.h>
#else
#include <cpuid.h>
#endif

#include "common/error.hpp"
#include "common/text.hpp"
#include "memory/process_memory.hpp"
#include "pipeline/scan_session.hpp"
#include "process/process.hpp"
#include "scanner/matcher_factory.hpp"
#include "support/target_process.hpp"

namespace mh::bench {
namespace {

using Clock = std::chrono::steady_clock;

constexpr std::uint64_t kGiB = 1ull << 30;

class Options {
public:
    Options(int argc, char** argv, int first) {
        for (int i = first; i < argc; ++i) {
            const std::string name = argv[i];
            if (name.rfind("--", 0) != 0 || i + 1 >= argc) {
                throw Error(ErrorCode::InvalidArgument, "expected --name value pairs, got '" + name + "'");
            }
            values_[name.substr(2)] = argv[++i];
        }
    }

    std::uint64_t size(const std::string& name, std::uint64_t fallback) const {
        const auto it = values_.find(name);
        if (it == values_.end()) {
            return fallback;
        }
        const auto value = parse_size(it->second);
        if (!value) {
            throw Error(ErrorCode::InvalidArgument, "--" + name + ": invalid size '" + it->second + "'");
        }
        return *value;
    }

    std::vector<std::uint64_t> sizes(const std::string& name, const std::string& fallback) const {
        const auto it = values_.find(name);
        const std::string& list = it == values_.end() ? fallback : it->second;
        std::vector<std::uint64_t> out;
        std::size_t start = 0;
        while (start <= list.size()) {
            const std::size_t comma = std::min(list.find(',', start), list.size());
            const auto value = parse_size(list.substr(start, comma - start));
            if (!value) {
                throw Error(ErrorCode::InvalidArgument, "--" + name + ": invalid list '" + list + "'");
            }
            out.push_back(*value);
            start = comma + 1;
        }
        return out;
    }

    std::string text(const std::string& name, const std::string& fallback) const {
        const auto it = values_.find(name);
        return it == values_.end() ? fallback : it->second;
    }

private:
    std::map<std::string, std::string> values_;
};

double median(std::vector<double> values) {
    std::sort(values.begin(), values.end());
    return values.empty() ? 0 : values[values.size() / 2];
}

double seconds_since(Clock::time_point start) {
    return std::chrono::duration<double>(Clock::now() - start).count();
}

std::string fixed(double value, int digits = 2) {
    char buffer[64];
    std::snprintf(buffer, sizeof(buffer), "%.*f", digits, value);
    return buffer;
}

std::string cpu_name() {
    unsigned int regs[12]{};
#if defined(_MSC_VER)
    for (int i = 0; i < 3; ++i) {
        __cpuid(reinterpret_cast<int*>(regs + 4 * i), static_cast<int>(0x80000002u + i));
    }
#else
    for (unsigned i = 0; i < 3; ++i) {
        __get_cpuid(0x80000002u + i, &regs[4 * i], &regs[4 * i + 1], &regs[4 * i + 2], &regs[4 * i + 3]);
    }
#endif
    std::string name(reinterpret_cast<const char*>(regs), sizeof(regs));
    name.erase(name.find_last_not_of(std::string(" \0", 2)) + 1);
    name.erase(0, name.find_first_not_of(' '));
    return name;
}

void print_environment() {
    MEMORYSTATUSEX memory{};
    memory.dwLength = sizeof(memory);
    GlobalMemoryStatusEx(&memory);
#if defined(_MSC_VER)
    const std::string compiler = "MSVC " + std::to_string(_MSC_VER);
#else
    const std::string compiler = std::string("GCC ") + __VERSION__;
#endif
    std::cout << "CPU: " << cpu_name() << ", " << std::thread::hardware_concurrency() << " hardware threads; RAM: "
              << format_size(memory.ullTotalPhys) << "; compiler: " << compiler << "; SIMD: " << mh::to_string(best_simd_level()) << "\n\n";
}

// --- algorithms --------------------------------------------------------------------------------------------------

enum class Profile { Random, ProcessLike };

std::string_view to_string(Profile profile) {
    return profile == Profile::Random ? "uniform random bytes" : "process-like pages";
}

// Process-like data mixes what dominates real address spaces: zero pages, ASCII and UTF-16 text, pointer tables
// and x64 code, so anchors on common bytes (00, FF, 48, 8B) get the false-candidate load they would get in practice.
std::vector<std::uint8_t> make_data(Profile profile, std::size_t size, std::uint64_t seed) {
    std::vector<std::uint8_t> data(size);
    std::mt19937_64 rng(seed);
    if (profile == Profile::Random) {
        for (std::size_t i = 0; i + 8 <= size; i += 8) {
            const std::uint64_t word = rng();
            std::memcpy(data.data() + i, &word, 8);
        }
        return data;
    }
    static constexpr std::uint8_t kCode[] = {0x48, 0x8B, 0x89, 0x8D, 0xE8, 0xC3, 0xCC, 0x90, 0x0F, 0x85, 0x84, 0x45, 0x33, 0xC0,
                                             0x4C, 0x24, 0x08, 0x10, 0x20, 0xFF, 0x15, 0x83, 0xEC, 0x28, 0x74, 0x75, 0x41, 0x5C};
    static constexpr char kText[] = "the quick brown fox jumps over a lazy dog Config.json https://example.org/path 0123456789";
    for (std::size_t page = 0; page < size; page += 4096) {
        const std::size_t end = std::min(size, page + 4096);
        const std::uint64_t kind = rng() % 100;
        for (std::size_t i = page; i < end; ++i) {
            if (kind < 35) {
                data[i] = 0;
            } else if (kind < 50) {
                data[i] = rng() % 16 == 0 ? 0 : static_cast<std::uint8_t>(kText[rng() % (sizeof(kText) - 1)]);
            } else if (kind < 60) {
                data[i] = (i - page) % 2 == 1 ? 0 : static_cast<std::uint8_t>(kText[rng() % (sizeof(kText) - 1)]);
            } else if (kind < 80) {
                static constexpr std::uint8_t kPointer[] = {0, 0, 0x7F, 0xF6, 0, 0, 0, 0};
                const std::size_t at = (i - page) % 8;
                data[i] = at < 3 ? static_cast<std::uint8_t>(rng()) : kPointer[7 - at];
            } else {
                data[i] = rng() % 4 == 0 ? static_cast<std::uint8_t>(rng()) : kCode[rng() % sizeof(kCode)];
            }
        }
    }
    return data;
}

// Signatures cut from the data itself so each one matches at least once: 12 bytes with a 4-byte wildcard
// displacement at positions 3..6, the shape of a typical "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ??" code signature.
// Fixed bytes must be non-zero and varied, as in signatures people actually write; windows cut from zero runs,
// pointer tables or UTF-16 text would match millions of times and measure result storage instead of matching.
std::vector<Pattern> make_signatures(const std::vector<std::uint8_t>& data, std::size_t count, std::uint64_t seed) {
    constexpr std::size_t kLength = 12;
    const auto fixed_position = [](std::size_t i) { return i < 3 || i >= 7; };
    std::mt19937_64 rng(seed);
    std::vector<Pattern> patterns;
    while (patterns.size() < count) {
        const std::size_t at = rng() % (data.size() - kLength);
        std::set<std::uint8_t> distinct;
        bool has_zero = false;
        for (std::size_t i = 0; i < kLength; ++i) {
            if (fixed_position(i)) {
                distinct.insert(data[at + i]);
                has_zero = has_zero || data[at + i] == 0;
            }
        }
        if (has_zero || distinct.size() < 6) {
            continue;
        }
        Pattern pattern;
        pattern.label = "s" + std::to_string(patterns.size());
        pattern.kind = PatternKind::Signature;
        pattern.value.assign(data.begin() + static_cast<std::ptrdiff_t>(at), data.begin() + static_cast<std::ptrdiff_t>(at + kLength));
        pattern.and_mask.assign(kLength, 0xFF);
        pattern.or_mask.assign(kLength, 0x00);
        for (std::size_t i = 0; i < kLength; ++i) {
            if (!fixed_position(i)) {
                pattern.and_mask[i] = 0;
                pattern.value[i] = 0;
            }
        }
        patterns.push_back(std::move(pattern));
    }
    return patterns;
}

struct AlgorithmRun {
    double seconds = 0;
    std::uint64_t hits = 0;
    std::string describe;
};

// Scans in engine-sized chunks with the matcher's look-ahead, as the pipeline does.
AlgorithmRun run_algorithm(const std::vector<std::uint8_t>& data, std::span<const Pattern> patterns, Algorithm algorithm,
                           int repeat) {
    const MatcherSetup setup = build_matcher(patterns, std::nullopt, {}, algorithm);
    const auto bytes = std::as_bytes(std::span(data));
    constexpr std::size_t kChunk = kDefaultChunkSize;
    std::vector<Hit> hits;
    std::vector<double> times;
    AlgorithmRun run;
    run.describe = setup.matcher->describe();
    for (int r = 0; r < repeat; ++r) {
        std::uint64_t total = 0;
        const auto start = Clock::now();
        for (std::size_t offset = 0; offset < bytes.size(); offset += kChunk) {
            const std::size_t end = std::min(bytes.size(), offset + kChunk);
            const std::size_t read_end = std::min(bytes.size(), end + setup.look_ahead);
            hits.clear();
            setup.matcher->scan(bytes.subspan(offset, read_end - offset), 0x10000 + offset, 0, end - offset, hits);
            total += hits.size();
        }
        times.push_back(seconds_since(start));
        run.hits = total;
    }
    run.seconds = median(times);
    return run;
}

int run_algorithms(const Options& options) {
    const std::size_t size = options.size("size", 128ull << 20);
    const int repeat = static_cast<int>(options.size("repeat", 3));
    const std::uint64_t seed = options.size("seed", 1);
    const auto counts = options.sizes("counts", "1,2,3,5,10,20,30,40,50,64,100");
    print_environment();
    std::cout << "Single-threaded matcher throughput in GiB/s (median of " << repeat << "), " << format_size(size)
              << " buffer scanned in " << format_size(kDefaultChunkSize) << " chunks; 12-byte signatures with 4 wildcards.\n";

    bool consistent = true;
    for (const Profile profile : {Profile::Random, Profile::ProcessLike}) {
        const auto data = make_data(profile, size, seed);
        std::cout << "\n### " << to_string(profile) << "\n\n";
        std::cout << "| patterns | naive | horspool | simd | aho-corasick | auto | auto picks | hits |\n";
        std::cout << "|---:|---:|---:|---:|---:|---:|---|---:|\n";
        for (const auto count : counts) {
            const auto patterns = make_signatures(data, count, seed + count);
            std::cout << "| " << count;
            std::uint64_t hits = 0;
            std::string auto_choice;
            bool first = true;
            for (const auto algorithm : {Algorithm::Naive, Algorithm::Horspool, Algorithm::Simd, Algorithm::AhoCorasick, Algorithm::Auto}) {
                const AlgorithmRun run = run_algorithm(data, patterns, algorithm, repeat);
                if (!first && run.hits != hits) {
                    consistent = false;
                    std::cerr << "MISMATCH: " << mh::to_string(algorithm) << " found " << run.hits << " hits, expected " << hits << '\n';
                }
                hits = run.hits;
                first = false;
                if (algorithm == Algorithm::Auto) {
                    // "10 x simd-sse2" or "aho-corasick(40 patterns, 321 states)" -> matcher name only
                    auto_choice = run.describe.substr(0, run.describe.find('('));
                    if (const auto x = auto_choice.find(" x "); x != std::string::npos) {
                        auto_choice.erase(0, x + 3);
                    }
                }
                std::cout << " | " << fixed(static_cast<double>(size) / kGiB / run.seconds);
                std::cout.flush();
            }
            std::cout << " | " << auto_choice << " | " << hits << " |\n";
        }
    }
    std::cout << (consistent ? "\nAll algorithms reported identical hit counts.\n" : "\nHIT COUNTS DIFFER between algorithms.\n");
    return consistent ? 0 : 1;
}

// --- process -----------------------------------------------------------------------------------------------------

class NullMatcher final : public Matcher {
public:
    void scan(std::span<const std::byte>, std::uint64_t, std::size_t, std::size_t, std::vector<Hit>&) const override {}
    std::string describe() const override { return "none"; }
};

int run_process(const Options& options) {
    const std::uint64_t fill = options.size("fill", 2 * kGiB);
    const std::size_t pattern_count = std::min<std::size_t>(options.size("patterns", 10), 10);
    const auto threads = options.sizes("threads", "1,4,8,16");
    const auto readers = options.sizes("readers", "0");
    const auto chunks = options.sizes("chunk", "256K");
    const int repeat = static_cast<int>(options.size("repeat", 3));
    const std::string target_exe = options.text("target", MEMHUNTER_TEST_TARGET);
    const auto algorithm = parse_algorithm(options.text("algorithm", "auto"));
    if (!algorithm) {
        throw Error(ErrorCode::InvalidArgument, "--algorithm: expected auto, naive, horspool, simd or aho-corasick");
    }
    print_environment();

    const auto started = Clock::now();
    testing::TargetProcess target = testing::start_target(target_exe, {"--fill", std::to_string(fill)});
    if (target.pid == 0 || target.fill_bytes < fill) {
        throw Error(ErrorCode::SystemError, "the test target did not start or could not allocate " + format_size(fill));
    }
    std::cout << "Target: pid " << target.pid << ", " << format_size(target.fill_bytes) << " of random data with "
              << target.fill_needles << " planted needles, ready in " << fixed(seconds_since(started)) << " s\n";

    // Needles 100..109 are planted once per 64 MiB block; each becomes a signature with a 2-byte wildcard gap.
    std::vector<Pattern> patterns;
    for (std::uint32_t k = 0; k < pattern_count; ++k) {
        Pattern pattern = testing::byte_needle(100 + k);
        pattern.kind = PatternKind::Signature;
        pattern.and_mask[4] = pattern.and_mask[5] = 0;
        pattern.value[4] = pattern.value[5] = 0;
        patterns.push_back(std::move(pattern));
    }
    const std::uint64_t expected = target.fill_needles / 10 * pattern_count;
    std::cout << pattern_count << " signatures like \"" << hex_preview(std::as_bytes(std::span(patterns[0].value)).first(4))
              << " ?? ?? ...\", " << expected << " expected matches; median of " << repeat << " runs per row.\n";
    std::cout << "Busy columns sum the time all reader or scanner threads spent working, so they can exceed wall time.\n\n";
    std::cout << "| scan threads | readers | chunk | scanned | wall s | GiB/s | enumerate s | read-only wall s | read busy s | scan busy s | matches |\n";
    std::cout << "|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n";

    const Process process = Process::open(target.pid);
    const ProcessMemory memory(process);
    const NullMatcher null_matcher;
    bool all_found = true;
    for (const auto chunk : chunks) {
        for (const auto thread_count : threads) {
            for (const auto reader_count : readers) {
                ScanRequest request;
                request.patterns = patterns;
                request.chunk_size = chunk;
                request.algorithm = *algorithm;
                request.engine.scan_threads = static_cast<unsigned>(thread_count);
                request.engine.read_threads = static_cast<unsigned>(reader_count);

                std::vector<double> wall;
                std::vector<double> read_only;
                ResultSet last;
                for (int r = 0; r < repeat; ++r) {
                    ScanProgress progress;
                    last = run_scan(memory, request, progress, {});
                    wall.push_back(last.stats.wall_seconds);

                    const ScanPlan plan = plan_scan(memory, request.filter);
                    const auto work = split_work(whole_span_targets(plan.spans), chunk, 0, 0);
                    ScanProgress null_progress;
                    EngineConfig config = request.engine;
                    read_only.push_back(run_engine(memory, null_matcher, work, config, null_progress, {}).wall_seconds);
                }
                const auto& s = last.stats;
                const bool found = s.status == ScanStatus::Completed && last.matches.size() == expected;
                all_found = all_found && found;
                std::cout << "| " << s.scan_threads << " | " << s.read_threads << " | " << format_size(chunk) << " | "
                          << format_size(s.bytes_read) << " | " << fixed(median(wall), 3) << " | "
                          << fixed(static_cast<double>(s.bytes_read) / kGiB / median(wall)) << " | " << fixed(s.enumerate_seconds, 3) << " | "
                          << fixed(median(read_only), 3) << " | " << fixed(s.read_seconds) << " | " << fixed(s.scan_seconds) << " | "
                          << last.matches.size() << (found ? "" : " (expected " + std::to_string(expected) + ")") << " |\n";
            }
        }
    }
    std::cout << "\nEngine: " << build_matcher(patterns, std::nullopt, {}, *algorithm).matcher->describe() << '\n';
    target.child->write_line("exit");
    return all_found ? 0 : 1;
}

constexpr std::string_view kUsage = R"(usage:
  memhunter_bench algorithms [--size 128M] [--repeat 3] [--seed 1] [--counts 1,2,3,5,10,20,30,40,50,64,100]
  memhunter_bench process [--fill 2G] [--patterns 10] [--threads 1,4,8,16] [--readers 0] [--chunk 256K] [--repeat 3]
                          [--algorithm auto] [--target PATH]
readers 0 means the engine default.
)";

}  // namespace
}  // namespace mh::bench

int main(int argc, char** argv) {
    using namespace mh::bench;
    try {
        const std::string mode = argc > 1 ? argv[1] : "";
        const Options options(argc, argv, 2);
        if (mode == "algorithms") {
            return run_algorithms(options);
        }
        if (mode == "process") {
            return run_process(options);
        }
        std::cerr << kUsage;
        return 2;
    } catch (const std::exception& error) {
        std::cerr << "memhunter_bench: " << error.what() << '\n';
        return 9;
    }
}
