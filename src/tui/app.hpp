#pragma once

#include <string>

#include "memory/memory_source.hpp"
#include "results/result_set.hpp"
#include "tui/model.hpp"

namespace mh::tui {

struct AppOptions {
    unsigned threads = 0;
};

// Writes rows_to_save(state) to state.save_path in the format its extension selects and reports the outcome in
// state.message.
void save_results(State& state);

// Runs the full-screen interface until the user quits. Scans run on a background thread, so the interface
// stays responsive and a scan can be cancelled at any time.
int run_app(const MemorySource& memory, const ProcessSummary& process, const AppOptions& options);

}  // namespace mh::tui
