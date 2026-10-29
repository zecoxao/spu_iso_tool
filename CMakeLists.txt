cmake_minimum_required(VERSION 3.15)

# Build a universal (Intel + Apple Silicon) binary on macOS.
if(APPLE AND NOT CMAKE_OSX_ARCHITECTURES)
    set(CMAKE_OSX_ARCHITECTURES "x86_64;arm64" CACHE STRING "macOS build architectures" FORCE)
endif()

project(spu_iso_tool C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Shared crypto core (used by both the CLI and the Qt GUI).
add_library(spucore STATIC
    spu_iso_tool/aes.c
    spu_iso_tool/spucore.c
)
target_include_directories(spucore PUBLIC spu_iso_tool)

if(MSVC)
    target_compile_definitions(spucore PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_options(spucore PRIVATE /O2 /W3)
else()
    target_compile_options(spucore PRIVATE -O2 -Wall)
endif()

# Command-line tool.
add_executable(spu_iso_tool spu_iso_tool/spu_iso_tool.c)
target_link_libraries(spu_iso_tool PRIVATE spucore)
if(MSVC)
    target_compile_definitions(spu_iso_tool PRIVATE _CRT_SECURE_NO_WARNINGS)
endif()

install(TARGETS spu_iso_tool RUNTIME DESTINATION bin)

# Optional Qt GUI.
#   -DSPU_BUILD_GUI=AUTO (default): build it if Qt 6 Widgets is found.
#   -DSPU_BUILD_GUI=ON:  require Qt 6 Widgets (error if missing).
#   -DSPU_BUILD_GUI=OFF: never build the GUI.
set(SPU_BUILD_GUI "AUTO" CACHE STRING "Build the Qt GUI: ON, OFF, or AUTO")
find_package(Qt6 QUIET COMPONENTS Widgets)
if(SPU_BUILD_GUI STREQUAL "ON")
    if(NOT Qt6_FOUND)
        message(FATAL_ERROR "SPU_BUILD_GUI=ON but Qt6 Widgets was not found")
    endif()
    add_subdirectory(gui)
elseif(SPU_BUILD_GUI STREQUAL "AUTO" AND Qt6_FOUND)
    add_subdirectory(gui)
endif()
