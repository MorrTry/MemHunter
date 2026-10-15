cmake_minimum_required(VERSION 3.24)
project(MemHunter VERSION 1.0.0 LANGUAGES CXX)

if(NOT WIN32)
  message(FATAL_ERROR "MemHunter reads process memory through the Windows API and builds only on Windows.")
endif()
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "MemHunter must be built as a 64-bit binary to read both 32- and 64-bit processes.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

option(MEMHUNTER_BUILD_TESTS "Build unit and integration tests" ON)
option(MEMHUNTER_BUILD_BENCH "Build the benchmark tool" ON)
option(MEMHUNTER_BUILD_GUI "Build the graphical interface (downloads Dear ImGui)" ON)

add_library(memhunter_options INTERFACE)
target_compile_definitions(memhunter_options INTERFACE
  WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE _WIN32_WINNT=0x0A00
  MEMHUNTER_VERSION="${PROJECT_VERSION}")
if(MSVC)
  target_compile_options(memhunter_options INTERFACE /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc)
else()
  target_compile_options(memhunter_options INTERFACE -Wall -Wextra -Wpedantic -Wshadow -Wnon-virtual-dtor)
  # Static runtime keeps the executables self-contained outside the toolchain shell.
  target_link_options(memhunter_options INTERFACE -static)
endif()

add_subdirectory(src)

if(MEMHUNTER_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

if(MEMHUNTER_BUILD_BENCH)
  add_subdirectory(bench)
endif()
