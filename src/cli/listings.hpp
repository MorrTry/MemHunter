#pragma once

#include <optional>
#include <ostream>
#include <span>

#include "inspect/inspect.hpp"
#include "memory/region.hpp"
#include "pointer/pointer_chain.hpp"
#include "process/process.hpp"
#include "results/export.hpp"
#include "results/result_set.hpp"
#include "structure/struct_layout.hpp"
#include "value/value_scan.hpp"

namespace mh::cli {

struct ValueRow {
    std::uint64_t address = 0;
    std::string value;
    // Empty when there is no earlier value to show.
    std::string previous;
    const Region* region = nullptr;
};

struct ValueListing {
    ProcessSummary process;
    ValueType type = ValueType::Int32;
    unsigned scan = 0;
    // Empty when the candidates are only shown.
    std::string condition;
    std::uint64_t count = 0;
    bool has_previous = false;
    std::vector<ValueRow> rows;
};

struct PointerRow {
    PointerPath path;
    // Where the chain leads now and what is there; nullopt when it leads nowhere or the value cannot be read.
    std::optional<std::uint64_t> address;
    std::optional<std::string> value;
};

struct PointerListing {
    ProcessSummary process;
    std::uint64_t target = 0;
    std::string type;
    unsigned depth = 0;
    std::uint32_t max_offset = 0;
    std::uint32_t checks = 0;
    std::uint64_t count = 0;
    std::vector<PointerRow> rows;
};

struct StructRow {
    StructField field;
    std::string value;
};

struct StructListing {
    ProcessSummary process;
    std::string base;
    std::uint64_t address = 0;
    std::uint32_t size = 0;
    unsigned pointer_size = 8;
    std::vector<StructRow> rows;
};

struct InspectedProcess {
    ProcessSummary process;
    InspectReport report;
};

struct SkippedProcess {
    std::uint32_t pid = 0;
    std::string name;
    std::string error;
};

struct InspectListing {
    std::vector<InspectedProcess> processes;
    std::vector<SkippedProcess> skipped;
    // Adds PID and PROCESS columns to the text and CSV output.
    bool all = false;
};

struct DisasmRow {
    std::uint64_t address = 0;
    std::string bytes;
    std::string text;
    bool valid = true;
    // "module.dll+0x1234" when a branch or call leads into a loaded module.
    std::string target_module;
};

struct DisasmListing {
    ProcessSummary process;
    std::uint64_t address = 0;
    bool wow64 = false;
    std::vector<DisasmRow> rows;
};

void write_regions(std::ostream& out, OutputFormat format, const ProcessSummary& process, std::span<const Region> regions);
void write_inspection(std::ostream& out, OutputFormat format, const InspectListing& listing);
void write_disasm(std::ostream& out, OutputFormat format, const DisasmListing& listing);
void write_values(std::ostream& out, OutputFormat format, const ValueListing& listing);
void write_pointers(std::ostream& out, OutputFormat format, const PointerListing& listing);
void write_struct(std::ostream& out, OutputFormat format, const StructListing& listing);
void write_processes(std::ostream& out, OutputFormat format, std::span<const ProcessEntry> processes);

}  // namespace mh::cli
