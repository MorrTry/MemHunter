add_library(memhunter_core STATIC
  common/error.cpp
  common/text.cpp
  process/process.cpp
  process/privilege.cpp
  memory/region.cpp
  memory/process_memory.cpp
  memory/segmented_read.cpp
  memory/memory_dump.cpp
  pattern/pattern.cpp
  scanner/anchor.cpp
  scanner/naive_matcher.cpp
  scanner/horspool_matcher.cpp
  scanner/simd_matcher.cpp
  scanner/aho_corasick_matcher.cpp
  scanner/string_extractor.cpp
  scanner/matcher_factory.cpp
  pipeline/work_plan.cpp
  pipeline/scan_engine.cpp
  pipeline/scan_session.cpp
  results/result_set.cpp
  results/query.cpp
  results/export.cpp
  snapshot/hash.cpp
  snapshot/snapshot.cpp
  snapshot/capture.cpp
  snapshot/binary_io.cpp
  snapshot/snapshot_file.cpp
  snapshot/diff.cpp
  snapshot/diff_export.cpp
  value/value_scan.cpp
  value/value_file.cpp
  pointer/pointer_chain.cpp
  pointer/pointer_scan.cpp
  pointer/pointer_file.cpp
  structure/struct_layout.cpp
  structure/struct_file.cpp
  inspect/pe_image.cpp
  inspect/inspect.cpp
  inspect/process_inspect.cpp
)
target_include_directories(memhunter_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(memhunter_core PUBLIC memhunter_options psapi advapi32)

add_library(memhunter_tui STATIC
  tui/screen.cpp
  tui/input.cpp
  tui/model.cpp
  tui/view.cpp
  tui/scan_task.cpp
  tui/terminal.cpp
  tui/app.cpp
)
target_include_directories(memhunter_tui PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(memhunter_tui PUBLIC memhunter_core)

add_library(memhunter_gui_model STATIC
  gui/search.cpp
  gui/results_table.cpp
  gui/value_table.cpp
  gui/value_history.cpp
  gui/watch_list.cpp
  gui/pointer_list.cpp
  gui/finding_list.cpp
  gui/struct_table.cpp
  gui/process_picker.cpp
  gui/job.cpp
  gui/session.cpp
)
target_include_directories(memhunter_gui_model PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(memhunter_gui_model PUBLIC memhunter_core)

add_executable(memhunter
  cli/args.cpp
  cli/commands.cpp
  cli/console.cpp
  cli/listings.cpp
  cli/main.cpp
)
target_link_libraries(memhunter PRIVATE memhunter_core memhunter_tui shell32)

if(MEMHUNTER_BUILD_GUI)
  add_subdirectory(gui)
endif()
