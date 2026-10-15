#include "inspect/inspect.hpp"

#include <algorithm>
#include <array>
#include <chrono>

#include "common/error.hpp"
#include "common/text.hpp"
#include "memory/region.hpp"

namespace mh {

namespace {

constexpr std::array<std::string_view, kFindingKindCount> kKindNames = {"exec-private", "pe-header", "rwx", "patched", "hollowed"};
constexpr std::uint64_t kCompareChunk = 64 * 1024;
// Changed bytes closer than this are one change.
constexpr std::uint64_t kDiffGap = 8;
constexpr std::size_t kMaxChangesPerModule = 64;
constexpr std::size_t kShownBytes = 16;
constexpr std::size_t kHeaderPage = 4096;
constexpr std::size_t kListedUnread = 5;

bool executable(std::uint32_t protect) noexcept {
    switch (protect & 0xFF) {
        case page::Execute:
        case page::ExecuteRead:
        case page::ExecuteReadWrite:
        case page::ExecuteWriteCopy: return true;
        default: return false;
    }
}

bool writable_executable(std::uint32_t protect) noexcept {
    return (protect & 0xFF) == page::ExecuteReadWrite || (protect & 0xFF) == page::ExecuteWriteCopy;
}

// Memory that no image file backs: private, or a section of the paging file.
bool unbacked(const Region& region) noexcept {
    return region.type == MemType::Private || (region.type == MemType::Mapped && region.mapped_file.empty());
}

std::string offset_in(const std::string& module, std::uint64_t offset) {
    return module + "+" + format_hex(offset);
}

std::string protections_of(std::span<const Region> run) {
    std::vector<std::string> seen;
    for (const auto& region : run) {
        std::string text = protection_to_string(region.protect);
        if (std::find(seen.begin(), seen.end(), text) == seen.end()) {
            seen.push_back(std::move(text));
        }
    }
    std::string joined;
    for (const auto& text : seen) {
        joined += (joined.empty() ? "" : ", ") + text;
    }
    return joined;
}

// Calls `emit` for each run of adjacent regions of one allocation that `accepts` takes.
template <typename Accept, typename Emit>
void for_each_run(std::span<const Region> regions, Accept&& accepts, Emit&& emit) {
    std::size_t i = 0;
    while (i < regions.size()) {
        if (!accepts(regions[i])) {
            ++i;
            continue;
        }
        std::size_t j = i + 1;
        while (j < regions.size() && accepts(regions[j]) && regions[j].base == regions[j - 1].end() &&
               regions[j].allocation_base == regions[i].allocation_base) {
            ++j;
        }
        emit(regions.subspan(i, j - i));
        i = j;
    }
}

struct Module {
    std::uint64_t base = 0;
    std::uint64_t end = 0;
    const Region* first = nullptr;
};

std::vector<Module> images_of(std::span<const Region> regions) {
    std::vector<Module> modules;
    for (const auto& region : regions) {
        if (region.type != MemType::Image) {
            continue;
        }
        if (!modules.empty() && modules.back().base == region.allocation_base && modules.back().end == region.base) {
            modules.back().end = region.end();
        } else {
            modules.push_back({region.allocation_base, region.end(), &region});
        }
    }
    return modules;
}

std::vector<std::byte> read_prefix(const MemorySource& memory, std::uint64_t address, std::size_t size) {
    std::vector<std::byte> bytes(size);
    bytes.resize(memory.read(address, bytes).bytes);
    return bytes;
}

class Inspector {
public:
    Inspector(const MemorySource& memory, const InspectFacts& facts, const InspectOptions& options, std::stop_token stop)
        : memory_(memory), facts_(facts), options_(options), stop_(std::move(stop)) {}

    InspectReport run() {
        const auto started = std::chrono::steady_clock::now();
        regions_ = memory_.query_regions();
        if (wants(FindingKind::ExecPrivate)) {
            find_executable_private();
        }
        if (wants(FindingKind::Rwx)) {
            find_rwx();
        }
        if (wants(FindingKind::PeHeader)) {
            find_pe_headers();
        }
        if (wants(FindingKind::Patched) || wants(FindingKind::Hollowed)) {
            for (const Module& module : images_of(regions_)) {
                if (stop_.stop_requested()) {
                    report_.complete = false;
                    break;
                }
                check_module(module);
            }
        }
        if (!unread_.empty()) {
            std::string names;
            for (std::size_t i = 0; i < std::min<std::size_t>(unread_.size(), kListedUnread); ++i) {
                names += (i == 0 ? "" : ", ") + unread_[i];
            }
            if (unread_.size() > kListedUnread) {
                names += ", ...";
            }
            report_.warnings.push_back(std::to_string(unread_.size()) + (unread_.size() == 1 ? " image" : " images") +
                                       " cannot be read and " + (unread_.size() == 1 ? "was" : "were") + " not compared with the files: " + names);
        }
        if (wants(FindingKind::Hollowed) && report_.complete) {
            check_main_image();
        }
        std::stable_sort(report_.findings.begin(), report_.findings.end(), [](const Finding& a, const Finding& b) {
            return a.address != b.address ? a.address < b.address : a.kind < b.kind;
        });
        report_.stats.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
        return std::move(report_);
    }

private:
    bool wants(FindingKind kind) const noexcept { return (options_.kinds & kind_bit(kind)) != 0; }

    void add(FindingKind kind, std::uint64_t address, std::uint64_t size, std::string where, std::string details) {
        report_.findings.push_back({kind, address, size, std::move(where), std::move(details)});
    }

    static std::uint64_t run_size(std::span<const Region> run) { return run.back().end() - run.front().base; }

    void find_executable_private() {
        for_each_run(
            regions_, [](const Region& r) { return r.state == MemState::Commit && unbacked(r) && executable(r.protect); },
            [&](std::span<const Region> run) {
                add(FindingKind::ExecPrivate, run.front().base, run_size(run), run.front().mapped_file,
                    std::string(to_string(run.front().type)) + ", " + protections_of(run));
            });
    }

    void find_rwx() {
        for_each_run(
            regions_, [](const Region& r) { return r.state == MemState::Commit && writable_executable(r.protect); },
            [&](std::span<const Region> run) {
                const Region& first = run.front();
                const std::string where =
                    first.type == MemType::Image ? offset_in(first.module_name(), first.base - first.allocation_base) : first.mapped_file;
                add(FindingKind::Rwx, first.base, run_size(run), where, std::string(to_string(first.type)) + ", " + protections_of(run));
            });
    }

    void find_pe_headers() {
        for (std::size_t i = 0; i < regions_.size(); ++i) {
            const Region& region = regions_[i];
            if (!unbacked(region) || !region.readable()) {
                continue;
            }
            std::array<std::byte, 2> magic{};
            if (memory_.read(region.base, magic).bytes != magic.size() || magic[0] != std::byte{'M'} || magic[1] != std::byte{'Z'}) {
                continue;
            }
            const auto head = read_prefix(memory_, region.base, static_cast<std::size_t>(std::min<std::uint64_t>(region.size, kHeaderPage)));
            const auto headers = parse_pe_headers(head);
            // Without an image size nothing could have been loaded from these headers.
            if (!headers || headers->size_of_image == 0) {
                continue;
            }
            std::uint64_t end = region.end();
            for (std::size_t j = i + 1; j < regions_.size() && regions_[j].base == end && regions_[j].allocation_base == region.allocation_base; ++j) {
                end = regions_[j].end();
            }
            add(FindingKind::PeHeader, region.base, end - region.base, region.mapped_file,
                headers->describe() + ", image size " + format_hex(headers->size_of_image) + ", in " + std::string(to_string(region.type)) +
                    " memory " + protection_to_string(region.protect));
        }
    }

    void check_module(const Module& module) {
        const Region& first = *module.first;
        const std::string& path = first.mapped_file;
        const std::uint64_t size = module.end - module.base;
        if (path.empty()) {
            if (wants(FindingKind::Hollowed)) {
                add(FindingKind::Hollowed, module.base, size, "", "an image whose file cannot be named: it was deleted or never was on disk");
            }
            return;
        }
        const std::string name = first.module_name();
        if (!facts_.file_exists(path)) {
            if (wants(FindingKind::Hollowed)) {
                add(FindingKind::Hollowed, module.base, size, name, "the file of the image no longer exists: " + path);
            }
            return;
        }
        const OpenedFile opened = facts_.open_image(path);
        if (!opened.file) {
            report_.warnings.push_back(name + ": " + opened.error);
            return;
        }
        std::array<std::byte, 2> probe{};
        if (memory_.read(module.base, probe).bytes != probe.size()) {
            if (!first.readable()) {
                if (wants(FindingKind::Hollowed)) {
                    add(FindingKind::Hollowed, module.base, size, name,
                        "the PE headers in memory cannot be read: the page is " + protection_to_string(first.protect) + "; the file is " + path);
                }
            } else {
                unread_.push_back(name);
            }
            return;
        }
        ++report_.stats.modules;
        const PeHeaders& file = opened.file->headers();
        if (wants(FindingKind::Hollowed)) {
            compare_headers(module, name, path, file);
        }
        if (wants(FindingKind::Patched)) {
            compare_code(module, name, *opened.file);
        }
    }

    void compare_headers(const Module& module, const std::string& name, const std::string& path, const PeHeaders& file) {
        const auto head = read_prefix(memory_, module.base, kHeaderPage);
        const auto mapped = parse_pe_headers(head);
        const std::uint64_t size = module.end - module.base;
        if (!mapped) {
            add(FindingKind::Hollowed, module.base, size, name, "the PE headers in memory are erased or damaged; the file is " + path);
            return;
        }
        std::string differences;
        const auto differ = [&](const char* what, std::uint64_t in_memory, std::uint64_t in_file) {
            if (in_memory != in_file) {
                differences += std::string(differences.empty() ? "" : ", ") + what + " " + format_hex(in_memory) + " instead of " + format_hex(in_file);
            }
        };
        differ("timestamp", mapped->timestamp, file.timestamp);
        differ("image size", mapped->size_of_image, file.size_of_image);
        differ("sections", mapped->sections.size(), file.sections.size());
        if (!differences.empty()) {
            add(FindingKind::Hollowed, module.base, size, name, "the headers in memory do not match " + path + ": " + differences);
        }
    }

    struct Change {
        std::uint64_t begin = 0;
        std::uint64_t end = 0;
        std::uint64_t differing = 0;
        std::vector<std::byte> memory;
        std::vector<std::byte> file;
        bool preview_closed = false;
    };

    void compare_code(const Module& module, const std::string& name, const PeFile& file) {
        const PeHeaders& headers = file.headers();
        const std::uint64_t iat_begin = module.base + headers.iat.rva;
        const std::uint64_t iat_end = headers.iat.size != 0 ? iat_begin + headers.iat.size : iat_begin;
        const std::vector<RvaRange>& overrides = file.override_sites();
        const auto rewritten_by_loader = [&](std::uint64_t address) {
            if (address >= iat_begin && address < iat_end) {
                return true;
            }
            const std::uint64_t rva = address - module.base;
            const auto it = std::upper_bound(overrides.begin(), overrides.end(), rva,
                                             [](std::uint64_t r, const RvaRange& range) { return r < range.rva; });
            return it != overrides.begin() && rva < std::uint64_t{std::prev(it)->rva} + std::prev(it)->size;
        };
        const std::uint64_t page = memory_.page_size();
        std::size_t listed = 0;
        std::size_t unlisted = 0;
        bool file_failed = false;

        for (const PeSection& section : headers.sections) {
            if (!section.executable() || section.virtual_address >= headers.size_of_image || file_failed) {
                continue;
            }
            const std::uint64_t begin = module.base + section.virtual_address;
            const std::uint64_t end =
                std::min<std::uint64_t>(begin + section.mapped_size(), module.base + headers.size_of_image);
            if (end <= begin) {
                continue;
            }
            const std::uint64_t first_page = begin / page * page;
            const std::size_t pages = static_cast<std::size_t>((end - first_page + page - 1) / page);
            const std::vector<bool> shared = facts_.shared_pages(first_page, pages);

            std::optional<Change> change;
            const auto flush = [&] {
                if (!change) {
                    return;
                }
                if (listed < kMaxChangesPerModule) {
                    const std::uint64_t rva = change->begin - module.base;
                    const bool exports = rva >= headers.exports.rva && rva < std::uint64_t{headers.exports.rva} + headers.exports.size;
                    add(FindingKind::Patched, change->begin, change->end - change->begin, offset_in(name, rva),
                        section.name + (exports ? " (export table)" : "") + ": " + std::to_string(change->differing) + (change->differing == 1 ? " byte differs" : " bytes differ") +
                            " from the file; memory " + hex_preview(change->memory) + ", file " + hex_preview(change->file));
                    ++listed;
                } else {
                    ++unlisted;
                }
                change.reset();
            };

            std::size_t index = 0;
            while (index < pages) {
                if (index < shared.size() && shared[index]) {
                    const std::uint64_t page_begin = std::max(first_page + index * page, begin);
                    const std::uint64_t page_end = std::min(first_page + (index + 1) * page, end);
                    report_.stats.shared_bytes += page_end - page_begin;
                    ++index;
                    continue;
                }
                std::size_t last = index + 1;
                while (last < pages && (last >= shared.size() || !shared[last]) && (last - index) * page < kCompareChunk) {
                    ++last;
                }
                const std::uint64_t chunk_begin = std::max(first_page + index * page, begin);
                const std::uint64_t chunk_end = std::min(first_page + last * page, end);
                std::vector<std::byte> actual(static_cast<std::size_t>(chunk_end - chunk_begin));
                const std::size_t readable = memory_.read(chunk_begin, actual).bytes;
                std::vector<std::byte> expected(actual.size());
                if (!file.image_bytes(static_cast<std::uint32_t>(chunk_begin - module.base), expected, module.base)) {
                    report_.warnings.push_back(name + ": the file could not be read while comparing the code");
                    file_failed = true;
                    break;
                }
                report_.stats.code_bytes += readable;
                for (std::size_t i = 0; i < readable; ++i) {
                    const std::uint64_t address = chunk_begin + i;
                    if (actual[i] == expected[i] || rewritten_by_loader(address)) {
                        continue;
                    }
                    if (change && address - change->end > kDiffGap) {
                        flush();
                    }
                    if (!change) {
                        change = Change{address, address, 0, {}, {}, false};
                    }
                    // The shown bytes stay contiguous: once a change goes on into the next chunk, no more are added.
                    change->preview_closed |= change->end < chunk_begin;
                    for (std::uint64_t at = change->end; !change->preview_closed && at <= address && change->memory.size() < kShownBytes; ++at) {
                        change->memory.push_back(actual[static_cast<std::size_t>(at - chunk_begin)]);
                        change->file.push_back(expected[static_cast<std::size_t>(at - chunk_begin)]);
                    }
                    change->end = address + 1;
                    ++change->differing;
                }
                if (readable < actual.size()) {
                    // Skips the page that failed and goes on after it.
                    flush();
                    const std::uint64_t failed = (chunk_begin + readable) / page * page;
                    index = static_cast<std::size_t>((failed - first_page) / page) + 1;
                } else {
                    index = last;
                }
            }
            flush();
        }
        if (unlisted != 0) {
            report_.warnings.push_back(name + ": " + std::to_string(unlisted) + " more changed places in the code are not listed");
        }
    }

    const Region* region_at(std::uint64_t address) const {
        const auto it = std::upper_bound(regions_.begin(), regions_.end(), address, [](std::uint64_t a, const Region& r) { return a < r.base; });
        if (it == regions_.begin()) {
            return nullptr;
        }
        const Region& region = *std::prev(it);
        return address < region.end() ? &region : nullptr;
    }

    void check_main_image() {
        const auto main = facts_.main_image();
        if (!main) {
            report_.warnings.push_back("the address of the main image cannot be read from the process environment block");
            return;
        }
        const Region* region = region_at(*main);
        if (region == nullptr || region->state != MemState::Commit) {
            add(FindingKind::Hollowed, *main, 0, "", "the process environment block names this address as the main image, but nothing is mapped there");
            return;
        }
        if (region->type != MemType::Image) {
            std::string details = "the main image is " + std::string(to_string(region->type)) + " memory, not an image mapped from a file";
            if (parse_pe_headers(read_prefix(memory_, *main, kHeaderPage))) {
                details += "; it starts with a PE header";
            }
            add(FindingKind::Hollowed, *main, region->size, region->mapped_file, details);
            return;
        }
        if (region->allocation_base != *main) {
            add(FindingKind::Hollowed, *main, 0, region->module_name(), "the main image address points inside the image, not at its start");
            return;
        }
        const std::string started_from = facts_.main_path();
        if (!region->mapped_file.empty() && !started_from.empty() && !facts_.same_file(region->mapped_file, started_from)) {
            add(FindingKind::Hollowed, *main, region->size, region->module_name(),
                "the main image is mapped from " + region->mapped_file + ", but the process was started from " + started_from);
        }
    }

    const MemorySource& memory_;
    const InspectFacts& facts_;
    const InspectOptions& options_;
    std::stop_token stop_;
    std::vector<Region> regions_;
    std::vector<std::string> unread_;
    InspectReport report_;
};

}  // namespace

std::string_view to_string(FindingKind kind) {
    const auto index = static_cast<std::size_t>(kind);
    return index < kKindNames.size() ? kKindNames[index] : "?";
}

std::uint32_t parse_finding_kinds(std::string_view list) {
    std::uint32_t mask = 0;
    while (!list.empty()) {
        const auto comma = list.find(',');
        const std::string item = to_lower_ascii(list.substr(0, comma));
        list = comma == std::string_view::npos ? std::string_view{} : list.substr(comma + 1);
        if (item.empty()) {
            continue;
        }
        const auto it = std::find(kKindNames.begin(), kKindNames.end(), item);
        if (it == kKindNames.end()) {
            std::string valid;
            for (const auto name : kKindNames) {
                valid += (valid.empty() ? "" : ", ") + std::string(name);
            }
            throw Error(ErrorCode::InvalidArgument, "unknown finding kind '" + item + "'; expected one of: " + valid);
        }
        mask |= 1u << static_cast<unsigned>(it - kKindNames.begin());
    }
    if (mask == 0) {
        throw Error(ErrorCode::InvalidArgument, "empty list of finding kinds");
    }
    return mask;
}

std::size_t InspectReport::count(FindingKind kind) const noexcept {
    return static_cast<std::size_t>(std::count_if(findings.begin(), findings.end(), [kind](const Finding& f) { return f.kind == kind; }));
}

InspectReport inspect_memory(const MemorySource& memory, const InspectFacts& facts, const InspectOptions& options, std::stop_token stop) {
    return Inspector(memory, facts, options, std::move(stop)).run();
}

}  // namespace mh
