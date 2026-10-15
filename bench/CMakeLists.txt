if(NOT TARGET memhunter_test_target)
  message(FATAL_ERROR "memhunter_bench scans the test target process; configure with MEMHUNTER_BUILD_TESTS=ON "
                      "or turn MEMHUNTER_BUILD_BENCH off.")
endif()

add_executable(memhunter_bench bench_main.cpp)
target_link_libraries(memhunter_bench PRIVATE memhunter_test_support)
target_compile_definitions(memhunter_bench PRIVATE MEMHUNTER_TEST_TARGET="$<TARGET_FILE:memhunter_test_target>")
add_dependencies(memhunter_bench memhunter_test_target)
