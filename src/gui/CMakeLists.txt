enable_language(RC)

# Download in-process instead of through a sub-build: the sub-build runs via cmd.exe, which garbles
# non-ASCII build paths.
if(POLICY CMP0168)
  cmake_policy(SET CMP0168 NEW)
endif()
include(FetchContent)
FetchContent_Declare(imgui
  URL https://github.com/ocornut/imgui/archive/refs/tags/v1.91.9b.zip
  URL_HASH SHA256=fd37507c8476a6d14cc7c4b352401f31bcbd0f0d995d35390811e968c466f46e
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
FetchContent_MakeAvailable(imgui)

add_library(memhunter_imgui STATIC
  ${imgui_SOURCE_DIR}/imgui.cpp
  ${imgui_SOURCE_DIR}/imgui_draw.cpp
  ${imgui_SOURCE_DIR}/imgui_tables.cpp
  ${imgui_SOURCE_DIR}/imgui_widgets.cpp
  ${imgui_SOURCE_DIR}/misc/cpp/imgui_stdlib.cpp
  ${imgui_SOURCE_DIR}/backends/imgui_impl_win32.cpp
  ${imgui_SOURCE_DIR}/backends/imgui_impl_dx11.cpp
)
target_include_directories(memhunter_imgui SYSTEM PUBLIC
  ${imgui_SOURCE_DIR} ${imgui_SOURCE_DIR}/backends ${imgui_SOURCE_DIR}/misc/cpp)
target_compile_definitions(memhunter_imgui PUBLIC IMGUI_DISABLE_OBSOLETE_FUNCTIONS)
target_link_libraries(memhunter_imgui PUBLIC d3d11 dxgi d3dcompiler_47 dwmapi imm32 gdi32 user32)

# Icon, manifest and version info. A target of its own, so that windres gets no include directories: it passes
# them to the preprocessor without quotes, which breaks on paths with spaces.
add_library(memhunter_gui_resources OBJECT memhunter_gui.rc)

add_executable(memhunter_gui WIN32
  theme.cpp
  widgets.cpp
  view.cpp
  watch_view.cpp
  pointer_view.cpp
  struct_view.cpp
  inspect_view.cpp
  main.cpp
)
target_link_libraries(memhunter_gui PRIVATE memhunter_gui_resources memhunter_gui_model memhunter_imgui comdlg32 ole32 shell32)
if(NOT MSVC)
  target_link_options(memhunter_gui PRIVATE -municode)
endif()
# Next to memhunter.exe, so that both tools live in one folder.
set_target_properties(memhunter_gui PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PROJECT_BINARY_DIR}/src")
