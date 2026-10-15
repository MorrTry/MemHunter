#include "cli/listings.hpp"

#include <algorithm>
#include <string>

#include "common/text.hpp"

namespace mh::cli {

namespace {

void write_regions_text(std::ostream& out, std::span<const Region> regions) {
    out << fit_width("BASE", 19) << fit_width("SIZE", 11) << fit_width("STATE", 8) << fit_width("PROT", 11)
        << fit_width("TYPE", 8) << "FILE\n";
    std::uint64_t total = 0;
    for (const auto& region : regions) {
        out << fit_width(format_address(region.base), 19) << fit_width(format_size(region.size), 11)
            << fit_width(to_string(region.state), 8)
            << fit_width(region.state == MemState::Commit ? protection_to_string(region.protect) : "", 11)
            << fit_width(to_string(region.type), 8) << region.mapped_file << '\n';
        total += region.size;
    }
    out << regions.size() << " regions, " << format_size(total) << '\n';
}

void write_regions_json(std::ostream& out, const ProcessSummary& process, std::span<const Region> regions) {
    out << "{\n  \"process\": {\"pid\": " << process.pid << ", \"name\": \"" << json_escape(process.name) << "\", \"path\": \""
        << json_escape(process.path) << "\", \"wow64\": " << (process.wow64 ? "true" : "false") << "},\n  \"regions\": [";
    bool first = true;
    for (const auto& region : regions) {
        out << (first ? "\n" : ",\n") << "    {\"base\": \"" << format_address(region.base) << "\", \"size\": " << region.size
            << ", \"allocation_base\": \"" << format_address(region.allocation_base) << "\", \"state\": \"" << to_string(region.state)
            << "\", \"protection\": \"" << (region.state == MemState::Commit ? protection_to_string(region.protect) : "")
            << "\", \"allocation_protection\": \"" << protection_to_string(region.allocation_protect) << "\", \"type\": \""
            << to_string(region.type) << "\", \"file\": \"" << json_escape(region.mapped_file) << "\"}";
        first = false;
    }
    out << "\n  ]\n}\n";
}

void write_regions_csv(std::ostream& out, std::span<const Region> regions) {
    out << "base,size,allocation_base,state,protection,allocation_protection,type,file\r\n";
    for (const auto& region : regions) {
        out << format_address(region.base) << ',' << region.size << ',' << format_address(region.allocation_base) << ','
            << to_string(region.state) << ',' << (region.state == MemState::Commit ? protection_to_string(region.protect) : "") << ','
            << protection_to_string(region.allocation_protect) << ',' << to_string(region.type) << ','
            << csv_field(region.mapped_file) << "\r\n";
    }
}

std::string protection_of(const ValueRow& row) {
    return row.region != nullptr ? protection_to_string(row.region->protect) : "";
}

std::string memory_type_of(const ValueRow& row) {
    return row.region != nullptr ? std::string(to_string(row.region->type)) : "";
}

std::string module_of(const ValueRow& row) {
    return row.region != nullptr ? row.region->module_name() : "";
}

void write_values_text(std::ostream& out, const ValueListing& listing) {
    out << fit_width("ADDRESS", 20) << fit_width("VALUE", 25);
    if (listing.has_previous) {
        out << fit_width("PREVIOUS", 25);
    }
    out << fit_width("PROT", 11) << fit_width("TYPE", 9) << "MODULE\n";
    for (const ValueRow& row : listing.rows) {
        out << fit_width(format_address(row.address), 20) << fit_width(row.value, 25);
        if (listing.has_previous) {
            out << fit_width(row.previous, 25);
        }
        out << fit_width(protection_of(row), 11) << fit_width(memory_type_of(row), 9) << module_of(row) << '\n';
    }
}

void write_values_json(std::ostream& out, const ValueListing& listing) {
    const ProcessSummary& process = listing.process;
    out << "{\n  \"process\": {\"pid\": " << process.pid << ", \"name\": \"" << json_escape(process.name) << "\", \"path\": \""
        << json_escape(process.path) << "\", \"wow64\": " << (process.wow64 ? "true" : "false") << "},\n  \"type\": \""
        << to_string(listing.type) << "\",\n  \"scan\": " << listing.scan << ",\n";
    if (!listing.condition.empty()) {
        out << "  \"condition\": \"" << json_escape(listing.condition) << "\",\n";
    }
    out << "  \"count\": " << listing.count << ",\n  \"shown\": " << listing.rows.size() << ",\n  \"values\": [";
    bool first = true;
    for (const ValueRow& row : listing.rows) {
        out << (first ? "\n" : ",\n") << "    {\"address\": \"" << format_address(row.address) << "\", \"value\": \"" << row.value << '"';
        if (listing.has_previous) {
            out << ", \"previous\": \"" << row.previous << '"';
        }
        out << ", \"protection\": \"" << protection_of(row) << "\", \"type\": \"" << memory_type_of(row) << "\", \"module\": \""
            << json_escape(module_of(row)) << "\"}";
        first = false;
    }
    out << (first ? "]\n}\n" : "\n  ]\n}\n");
}

void write_values_csv(std::ostream& out, const ValueListing& listing) {
    out << "address,value,previous,protection,type,module\r\n";
    for (const ValueRow& row : listing.rows) {
        out << format_address(row.address) << ',' << row.value << ',' << row.previous << ',' << protection_of(row) << ','
            << memory_type_of(row) << ',' << csv_field(module_of(row)) << "\r\n";
    }
}

std::string pointer_base(const PointerRow& row) {
    return format_pointer_base(row.path.module, row.path.base_offset);
}

std::string pointer_address(const PointerRow& row) {
    return row.address ? format_address(*row.address) : "??";
}

void write_pointers_text(std::ostream& out, const PointerListing& listing) {
    std::size_t base_width = 6;
    std::size_t offsets_width = 9;
    for (const PointerRow& row : listing.rows) {
        base_width = std::max(base_width, pointer_base(row).size() + 2);
        offsets_width = std::max(offsets_width, format_pointer_offsets(row.path.offsets).size() + 2);
    }
    out << fit_width("BASE", base_width) << fit_width("OFFSETS", offsets_width) << fit_width("ADDRESS", 20) << "VALUE\n";
    for (const PointerRow& row : listing.rows) {
        out << fit_width(pointer_base(row), base_width) << fit_width(format_pointer_offsets(row.path.offsets), offsets_width)
            << fit_width(pointer_address(row), 20) << row.value.value_or("??") << '\n';
    }
}

void write_pointers_json(std::ostream& out, const PointerListing& listing) {
    const ProcessSummary& process = listing.process;
    out << "{\n  \"process\": {\"pid\": " << process.pid << ", \"name\": \"" << json_escape(process.name) << "\", \"path\": \""
        << json_escape(process.path) << "\", \"wow64\": " << (process.wow64 ? "true" : "false") << "},\n  \"target\": \""
        << format_address(listing.target) << "\",\n  \"type\": \"" << listing.type << "\",\n  \"depth\": " << listing.depth
        << ",\n  \"max_offset\": \"" << format_hex(listing.max_offset) << "\",\n  \"checks\": " << listing.checks
        << ",\n  \"count\": " << listing.count << ",\n  \"shown\": " << listing.rows.size() << ",\n  \"chains\": [";
    bool first = true;
    for (const PointerRow& row : listing.rows) {
        out << (first ? "\n" : ",\n") << "    {\"base\": \"" << json_escape(pointer_base(row)) << "\", \"offsets\": [";
        for (std::size_t i = 0; i < row.path.offsets.size(); ++i) {
            out << (i == 0 ? "\"" : ", \"") << format_hex(row.path.offsets[i]) << '"';
        }
        out << "], \"path\": \"" << json_escape(format_pointer_path(row.path)) << "\", \"address\": ";
        if (row.address) {
            out << '"' << format_address(*row.address) << '"';
        } else {
            out << "null";
        }
        out << ", \"value\": ";
        if (row.value) {
            out << '"' << json_escape(*row.value) << '"';
        } else {
            out << "null";
        }
        out << '}';
        first = false;
    }
    out << (first ? "]\n}\n" : "\n  ]\n}\n");
}

void write_pointers_csv(std::ostream& out, const PointerListing& listing) {
    out << "base,offsets,path,address,value\r\n";
    for (const PointerRow& row : listing.rows) {
        out << csv_field(pointer_base(row)) << ',' << csv_field(format_pointer_offsets(row.path.offsets)) << ','
            << csv_field(format_pointer_path(row.path)) << ',' << (row.address ? format_address(*row.address) : "") << ','
            << csv_field(row.value.value_or("")) << "\r\n";
    }
}

}  // namespace

void write_pointers(std::ostream& out, OutputFormat format, const PointerListing& listing) {
    switch (format) {
        case OutputFormat::Text: write_pointers_text(out, listing); break;
        case OutputFormat::Json: write_pointers_json(out, listing); break;
        case OutputFormat::Csv: write_pointers_csv(out, listing); break;
    }
}

void write_values(std::ostream& out, OutputFormat format, const ValueListing& listing) {
    switch (format) {
        case OutputFormat::Text: write_values_text(out, listing); break;
        case OutputFormat::Json: write_values_json(out, listing); break;
        case OutputFormat::Csv: write_values_csv(out, listing); break;
    }
}

void write_regions(std::ostream& out, OutputFormat format, const ProcessSummary& process, std::span<const Region> regions) {
    switch (format) {
        case OutputFormat::Text: write_regions_text(out, regions); break;
        case OutputFormat::Json: write_regions_json(out, process, regions); break;
        case OutputFormat::Csv: write_regions_csv(out, regions); break;
    }
}

void write_processes(std::ostream& out, OutputFormat format, std::span<const ProcessEntry> processes) {
    switch (format) {
        case OutputFormat::Text:
            out << fit_width("PID", 8) << fit_width("PPID", 8) << fit_width("THREADS", 9) << "NAME\n";
            for (const auto& p : processes) {
                out << fit_width(std::to_string(p.pid), 8) << fit_width(std::to_string(p.parent_pid), 8)
                    << fit_width(std::to_string(p.threads), 9) << p.name << '\n';
            }
            break;
        case OutputFormat::Json: {
            out << "[";
            bool first = true;
            for (const auto& p : processes) {
                out << (first ? "\n" : ",\n") << "  {\"pid\": " << p.pid << ", \"parent_pid\": " << p.parent_pid
                    << ", \"threads\": " << p.threads << ", \"name\": \"" << json_escape(p.name) << "\"}";
                first = false;
            }
            out << "\n]\n";
            break;
        }
        case OutputFormat::Csv:
            out << "pid,parent_pid,threads,name\r\n";
            for (const auto& p : processes) {
                out << p.pid << ',' << p.parent_pid << ',' << p.threads << ',' << csv_field(p.name) << "\r\n";
            }
            break;
    }
}

}  // namespace mh::cli
