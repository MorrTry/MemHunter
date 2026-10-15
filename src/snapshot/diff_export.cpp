#include "snapshot/diff_export.hpp"

#include <algorithm>

#include "common/text.hpp"

namespace mh {

namespace {

const Region* region_at(const std::vector<Region>& regions, std::uint64_t address) {
    const auto it = std::upper_bound(regions.begin(), regions.end(), address,
                                     [](std::uint64_t a, const Region& r) { return a < r.base; });
    if (it == regions.begin()) {
        return nullptr;
    }
    const Region& region = *std::prev(it);
    return address < region.end() ? &region : nullptr;
}

const Region* region_of(const DiffReport& report, const DiffRange& range) {
    const Snapshot& owner = range.kind == RangeKind::Removed ? *report.before.snapshot : *report.after.snapshot;
    return region_at(owner.regions, range.begin);
}

std::string bitness(const ProcessSummary& process) {
    return process.wow64 ? "32-bit" : "64-bit";
}

std::string contents_text(const Snapshot& snapshot, bool live) {
    if (live) {
        return "live memory";
    }
    return snapshot.has_data ? "hashes and memory contents" : "hashes only (memory contents not saved)";
}

void text_side(std::ostream& out, std::string_view title, const SnapshotSide& side) {
    const Snapshot& s = *side.snapshot;
    out << fit_width(title, 9) << side.source << ": pid " << s.process.pid << ' ' << s.process.name << ", started "
        << format_filetime(s.process.creation_time) << ", captured " << format_filetime(s.captured_at) << '\n';
    out << std::string(9, ' ') << format_size(s.captured_bytes()) << " in " << s.spans.size() << " ranges, "
        << format_size(s.unreadable_bytes()) << " unreadable, " << format_size(s.block_size) << " blocks, "
        << contents_text(s, side.live) << '\n';
}

std::string region_brief(const Region& region) {
    std::string text = fit_width(format_address(region.base), 20) + fit_width(format_size(region.size), 12) +
                       fit_width(protection_to_string(region.protect), 6) + fit_width(to_string(region.state), 8) +
                       fit_width(to_string(region.type), 8);
    return text + region.module_name();
}

std::string region_delta(const Region& before, const Region& after) {
    std::vector<std::string> parts;
    if (before.size != after.size) {
        parts.push_back("size " + format_size(before.size) + " -> " + format_size(after.size));
    }
    if (before.protect != after.protect) {
        parts.push_back("protection " + protection_to_string(before.protect) + " -> " + protection_to_string(after.protect));
    }
    if (before.state != after.state) {
        parts.push_back("state " + std::string(to_string(before.state)) + " -> " + std::string(to_string(after.state)));
    }
    if (before.type != after.type) {
        parts.push_back("type " + std::string(to_string(before.type)) + " -> " + std::string(to_string(after.type)));
    }
    if (before.allocation_base != after.allocation_base) {
        parts.push_back("new allocation at " + format_address(after.allocation_base));
    }
    if (before.mapped_file != after.mapped_file) {
        parts.push_back("file " + before.module_name() + " -> " + after.module_name());
    }
    std::string text;
    for (const auto& part : parts) {
        text += (text.empty() ? "" : ", ") + part;
    }
    return text;
}

void write_text(std::ostream& out, const DiffReport& report, const std::vector<std::size_t>& rows) {
    const SnapshotDiff& diff = *report.diff;
    text_side(out, "Before", report.before);
    text_side(out, "After", report.after);
    for (const auto& warning : report.warnings) {
        out << "Warning: " << warning << '\n';
    }

    std::size_t counts[3] = {0, 0, 0};
    for (const auto& change : diff.regions) {
        ++counts[static_cast<std::size_t>(change.kind)];
    }
    out << "\nRegions: " << counts[0] << " added, " << counts[1] << " removed, " << counts[2] << " modified\n";
    for (const auto& change : diff.regions) {
        out << "  " << fit_width(to_string(change.kind), 10);
        if (change.kind == RegionChangeKind::Modified) {
            out << fit_width(format_address(change.after.base), 20) << region_delta(change.before, change.after) << '\n';
        } else {
            out << region_brief(change.kind == RegionChangeKind::Added ? change.after : change.before) << '\n';
        }
    }

    out << "\nMemory:";
    for (std::size_t k = 0; k < kRangeKindCount; ++k) {
        out << (k == 0 ? " " : ", ") << to_string(static_cast<RangeKind>(k)) << ' ' << format_size(diff.bytes[k]);
        if (diff.range_counts[k] != 0) {
            out << " (" << diff.range_counts[k] << (diff.range_counts[k] == 1 ? " range)" : " ranges)");
        }
    }
    out << '\n';
    if (!diff.exact) {
        out << "Changes are exact to the " << format_size(report.after.snapshot->block_size)
            << " block; byte-exact ranges need the memory contents of both sides (snapshot --with-data).\n";
    }
    if (rows.empty()) {
        return;
    }
    out << '\n'
        << fit_width("KIND", 11) << fit_width("START", 20) << fit_width("END", 20) << fit_width("SIZE", 12) << fit_width("PROT", 6)
        << fit_width("TYPE", 8) << "MODULE\n";
    for (const std::size_t row : rows) {
        const DiffRange& range = diff.ranges[row];
        const Region* region = region_of(report, range);
        out << fit_width(to_string(range.kind), 11) << fit_width(format_address(range.begin), 20)
            << fit_width(format_address(range.end), 20) << fit_width(format_size(range.end - range.begin), 12)
            << fit_width(region ? protection_to_string(region->protect) : "?", 6) << fit_width(region ? to_string(region->type) : "?", 8)
            << (region ? region->module_name() : "") << '\n';
    }
}

void json_region(std::ostream& out, const Region& r) {
    out << "{\"base\": \"" << format_address(r.base) << "\", \"size\": " << r.size << ", \"allocation_base\": \""
        << format_address(r.allocation_base) << "\", \"state\": \"" << to_string(r.state) << "\", \"protection\": \""
        << protection_to_string(r.protect) << "\", \"type\": \"" << to_string(r.type) << "\", \"module\": \""
        << json_escape(r.module_name()) << "\"}";
}

void json_side(std::ostream& out, const SnapshotSide& side) {
    const Snapshot& s = *side.snapshot;
    out << "{\"source\": \"" << json_escape(side.source) << "\", \"live\": " << (side.live ? "true" : "false") << ", \"pid\": " << s.process.pid
        << ", \"name\": \"" << json_escape(s.process.name) << "\", \"path\": \"" << json_escape(s.process.path) << "\", \"wow64\": "
        << (s.process.wow64 ? "true" : "false") << ", \"process_started\": \"" << format_filetime(s.process.creation_time)
        << "\", \"process_creation_filetime\": " << s.process.creation_time << ", \"captured\": \"" << format_filetime(s.captured_at)
        << "\", \"captured_filetime\": " << s.captured_at << ", \"block_size\": " << s.block_size
        << ", \"contents_saved\": " << (s.has_data ? "true" : "false") << ", \"captured_bytes\": " << s.captured_bytes()
        << ", \"unreadable_bytes\": " << s.unreadable_bytes() << ", \"ranges\": " << s.spans.size() << ", \"blocks\": " << s.block_count()
        << ", \"regions\": " << s.regions.size();
    if (!side.live) {
        out << ", \"file_size\": " << side.file_size;
    }
    out << '}';
}

void write_json(std::ostream& out, const DiffReport& report, const std::vector<std::size_t>& rows) {
    const SnapshotDiff& diff = *report.diff;
    out << "{\n  \"before\": ";
    json_side(out, report.before);
    out << ",\n  \"after\": ";
    json_side(out, report.after);
    out << ",\n  \"same_process\": " << (same_process_instance(report.before.snapshot->process, report.after.snapshot->process) ? "true" : "false")
        << ",\n  \"exact\": " << (diff.exact ? "true" : "false") << ",\n  \"warnings\": [";
    for (std::size_t i = 0; i < report.warnings.size(); ++i) {
        out << (i == 0 ? "" : ", ") << '"' << json_escape(report.warnings[i]) << '"';
    }
    out << "],\n  \"totals\": {";
    for (std::size_t k = 0; k < kRangeKindCount; ++k) {
        out << (k == 0 ? "" : ", ") << '"' << to_string(static_cast<RangeKind>(k)) << "\": {\"bytes\": " << diff.bytes[k]
            << ", \"ranges\": " << diff.range_counts[k] << '}';
    }
    out << "},\n  \"region_changes\": [";
    for (std::size_t i = 0; i < diff.regions.size(); ++i) {
        const RegionChange& change = diff.regions[i];
        out << (i == 0 ? "\n" : ",\n") << "    {\"change\": \"" << to_string(change.kind) << '"';
        if (change.kind != RegionChangeKind::Added) {
            out << ", \"before\": ";
            json_region(out, change.before);
        }
        if (change.kind != RegionChangeKind::Removed) {
            out << ", \"after\": ";
            json_region(out, change.after);
        }
        out << '}';
    }
    out << (diff.regions.empty() ? "" : "\n  ") << "],\n  \"ranges_total\": " << diff.ranges.size()
        << ",\n  \"ranges_shown\": " << rows.size() << ",\n  \"ranges\": [";
    for (std::size_t i = 0; i < rows.size(); ++i) {
        const DiffRange& range = diff.ranges[rows[i]];
        const Region* region = region_of(report, range);
        out << (i == 0 ? "\n" : ",\n") << "    {\"kind\": \"" << to_string(range.kind) << "\", \"start\": \"" << format_address(range.begin)
            << "\", \"end\": \"" << format_address(range.end) << "\", \"size\": " << range.end - range.begin;
        if (region != nullptr) {
            out << ", \"region\": \"" << format_address(region->base) << "\", \"protection\": \"" << protection_to_string(region->protect)
                << "\", \"type\": \"" << to_string(region->type) << "\", \"module\": \"" << json_escape(region->module_name()) << '"';
        }
        out << '}';
    }
    out << (rows.empty() ? "" : "\n  ") << "]\n}\n";
}

void write_csv(std::ostream& out, const DiffReport& report, const std::vector<std::size_t>& rows) {
    out << "kind,start,end,size,region,protection,type,module\n";
    for (const std::size_t row : rows) {
        const DiffRange& range = report.diff->ranges[row];
        const Region* region = region_of(report, range);
        out << to_string(range.kind) << ',' << format_address(range.begin) << ',' << format_address(range.end) << ','
            << range.end - range.begin << ',';
        if (region != nullptr) {
            out << format_address(region->base) << ',' << protection_to_string(region->protect) << ',' << to_string(region->type) << ','
                << csv_field(region->module_name());
        } else {
            out << ",,,";
        }
        out << '\n';
    }
}

}  // namespace

std::vector<std::size_t> diff_rows(const DiffReport& report) {
    std::vector<std::size_t> rows;
    const auto& ranges = report.diff->ranges;
    for (std::size_t i = 0; i < ranges.size(); ++i) {
        if ((report.show & range_kind_bit(ranges[i].kind)) == 0) {
            continue;
        }
        if (report.limit != 0 && rows.size() == report.limit) {
            break;
        }
        rows.push_back(i);
    }
    return rows;
}

void write_diff(std::ostream& out, OutputFormat format, const DiffReport& report) {
    const std::vector<std::size_t> rows = diff_rows(report);
    switch (format) {
        case OutputFormat::Text: write_text(out, report, rows); break;
        case OutputFormat::Json: write_json(out, report, rows); break;
        case OutputFormat::Csv: write_csv(out, report, rows); break;
    }
}

void write_snapshot_info(std::ostream& out, OutputFormat format, const SnapshotSide& side) {
    const Snapshot& s = *side.snapshot;
    if (format == OutputFormat::Json) {
        json_side(out, side);
        out << '\n';
        return;
    }
    if (format == OutputFormat::Csv) {
        out << "source,pid,name,process_started,captured,block_size,contents_saved,captured_bytes,unreadable_bytes,ranges,blocks,regions,file_size\n"
            << csv_field(side.source) << ',' << s.process.pid << ',' << csv_field(s.process.name) << ',' << format_filetime(s.process.creation_time)
            << ',' << format_filetime(s.captured_at) << ',' << s.block_size << ',' << (s.has_data ? "yes" : "no") << ',' << s.captured_bytes()
            << ',' << s.unreadable_bytes() << ',' << s.spans.size() << ',' << s.block_count() << ',' << s.regions.size() << ','
            << side.file_size << '\n';
        return;
    }
    out << fit_width("Snapshot", 11) << side.source << " (" << format_size(side.file_size) << ", format version " << kSnapshotVersion << ")\n"
        << fit_width("Process", 11) << "pid " << s.process.pid << ' ' << s.process.name << ", " << bitness(s.process) << ", started "
        << format_filetime(s.process.creation_time) << '\n'
        << fit_width("Path", 11) << (s.process.path.empty() ? "-" : s.process.path) << '\n'
        << fit_width("Captured", 11) << format_filetime(s.captured_at) << '\n'
        << fit_width("Saved", 11) << contents_text(s, false) << '\n'
        << fit_width("Memory", 11) << format_size(s.captured_bytes()) << " in " << s.spans.size() << " ranges, "
        << format_size(s.unreadable_bytes()) << " of it unreadable\n"
        << fit_width("Blocks", 11) << s.block_count() << " x " << format_size(s.block_size) << '\n'
        << fit_width("Regions", 11) << s.regions.size() << " allocated regions recorded (base, size, state, protection, type, file)\n";
}

}  // namespace mh
