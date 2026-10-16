find_package(GTest 1.14 CONFIG QUIET)
if(NOT GTest_FOUND)
  # Download in-process instead of through a sub-build: the sub-build runs via cmd.exe, which garbles
  # non-ASCII build paths.
  if(POLICY CMP0168)
    cmake_policy(SET CMP0168 NEW)
  endif()
  include(FetchContent)
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
  FetchContent_Declare(googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.17.0.zip
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  FetchContent_MakeAvailable(googletest)
endif()

add_executable(memhunter_test_target target/test_target.cpp)
target_include_directories(memhunter_test_target PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(memhunter_test_target PRIVATE memhunter_options advapi32)

add_library(memhunter_test_support STATIC support/child_process.cpp)
target_include_directories(memhunter_test_support PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(memhunter_test_support PUBLIC memhunter_core)

add_executable(memhunter_tests
  test_text.cpp
  test_pattern.cpp
  test_region.cpp
  test_matchers.cpp
  test_strings.cpp
  test_work_plan.cpp
  test_engine.cpp
  test_results.cpp
  test_process.cpp
  test_snapshot.cpp
  test_values.cpp
  test_value_file.cpp
  test_pointers.cpp
  test_structure.cpp
  test_inspect.cpp
  test_disasm.cpp
  test_tui.cpp
  test_gui.cpp
  test_gui_pointers.cpp
  test_gui_structure.cpp
  test_gui_inspect.cpp
  test_gui_disasm.cpp
  test_cli.cpp
)
target_link_libraries(memhunter_tests PRIVATE memhunter_test_support memhunter_tui memhunter_gui_model GTest::gtest_main)
target_compile_definitions(memhunter_tests PRIVATE
  MEMHUNTER_EXE="$<TARGET_FILE:memhunter>"
  MEMHUNTER_TEST_TARGET="$<TARGET_FILE:memhunter_test_target>")
add_dependencies(memhunter_tests memhunter memhunter_test_target)

include(GoogleTest)
gtest_discover_tests(memhunter_tests DISCOVERY_TIMEOUT 60)
