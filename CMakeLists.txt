cmake_minimum_required(VERSION 3.15)

# Build a universal (Intel + Apple Silicon) binary on macOS.
if(APPLE AND NOT CMAKE_OSX_ARCHITECTURES)
    set(CMAKE_OSX_ARCHITECTURES "x86_64;arm64" CACHE STRING "macOS build architectures" FORCE)
endif()

project(spu_iso_tool C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(spu_iso_tool
    spu_iso_tool/aes.c
    spu_iso_tool/spu_iso_tool.c
)

if(MSVC)
    target_compile_definitions(spu_iso_tool PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_compile_options(spu_iso_tool PRIVATE /O2 /W3)
else()
    target_compile_options(spu_iso_tool PRIVATE -O2 -Wall)
endif()

install(TARGETS spu_iso_tool RUNTIME DESTINATION bin)
