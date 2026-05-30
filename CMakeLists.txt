# basic info
cmake_minimum_required(VERSION 3.22 FATAL_ERROR)

# for CMake 3.30+ (normalizes install destination paths)
if(POLICY CMP0177)
    cmake_policy(SET CMP0177 NEW)
endif()

project(
    VMAware
    DESCRIPTION "VM detection library"
    LANGUAGES CXX
)

# set C++ standard
if(NOT DEFINED CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 20)
endif()
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# global compiler options
if(MSVC)
    # Globally disable specific MSVC warnings from external headers
    add_compile_options(
        /FS # if multiple cl.exe write to the same .pdb file
        /wd4626  # deleted assignment
        /wd4668  # undefined macro replaced with '0'
        /wd4820  # padding added after data member
        /wd5045  # Spectre mitigation notice
        /Zc:enumTypes  # use enum underlying type canonicalization
    )
endif()

# compiler flags
if (MSVC)
    # Visual Studio uses multi-config generators, so we must avoid CMAKE_BUILD_TYPE here
    add_compile_options(/W4 /EHsc)
else()
    # Linux and Apple
    add_compile_options(-Wextra -Wall -Wconversion -Wdouble-promotion -Wno-unused-parameter -Wno-unused-function -Wno-sign-conversion -Werror)
endif()

# find available compilers
if (LINUX)
    find_program(CLANGPP_EXECUTABLE NAMES clang++)
    find_program(GPP_EXECUTABLE NAMES g++)

    # select compiler with preference for clang++
    if(CLANGPP_EXECUTABLE)
        set(CMAKE_CXX_COMPILER "${CLANGPP_EXECUTABLE}")
        get_filename_component(COMPILER_NAME ${CLANGPP_EXECUTABLE} NAME)
    elseif(GPP_EXECUTABLE)
        set(CMAKE_CXX_COMPILER "${GPP_EXECUTABLE}")
        get_filename_component(COMPILER_NAME ${GPP_EXECUTABLE} NAME)
    endif()
elseif(APPLE)
    set(COMPILER_NAME "AppleClang")
elseif(MSVC)
    set(COMPILER_NAME "MSVC")
endif()

message(STATUS "Compiler: ${COMPILER_NAME}")

# Define preprocessor macros based on the build type
# Use generator expressions so this works correctly with Visual Studio.
add_compile_definitions(
    $<$<CONFIG:Debug>:__VMAWARE_DEBUG__>
    $<$<CONFIG:Release>:__VMAWARE_RELEASE__>
)

# export compile commands for clang-tidy
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# clang-tidy target (run separately, not during normal builds)
find_program(CLANG_TIDY_EXECUTABLE NAMES clang-tidy clang-tidy-18 clang-tidy-17 clang-tidy-16)
find_program(RUN_CLANG_TIDY_EXECUTABLE NAMES run-clang-tidy run-clang-tidy-18 run-clang-tidy-17 run-clang-tidy-16)
if(CLANG_TIDY_EXECUTABLE)
    message(STATUS "clang-tidy: ${CLANG_TIDY_EXECUTABLE}")
    if(RUN_CLANG_TIDY_EXECUTABLE)
        add_custom_target(clang-tidy
            COMMAND ${RUN_CLANG_TIDY_EXECUTABLE}
                -clang-tidy-binary ${CLANG_TIDY_EXECUTABLE}
                -p ${CMAKE_BINARY_DIR}
                -header-filter=".*/src/.*"
                -fix
            COMMENT "Running clang-tidy"
            VERBATIM
        )
    else()
        add_custom_target(clang-tidy
            COMMAND ${CLANG_TIDY_EXECUTABLE}
                -p ${CMAKE_BINARY_DIR}
                --header-filter=".*/src/.*"
                --fix
                ${CLI_SOURCES}
            COMMENT "Running clang-tidy"
            VERBATIM
        )
    endif()
endif()

# general variables
set(TARGET "vmaware")

# debug/release CXX flag options
if (MSVC)
    message(STATUS "MSVC generator detected")
elseif(APPLE)
    message(STATUS "Apple platform detected")
elseif(LINUX)
    message(STATUS "Linux platform detected")
else()
    message(STATUS "Unknown platform")
endif()

# add executable
file(GLOB CLI_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/cli/*.cpp")
add_executable(${TARGET} ${CLI_SOURCES})
set_property(TARGET ${TARGET} PROPERTY CXX_STANDARD ${CMAKE_CXX_STANDARD})

# debug/release flags (MULTI-CONFIG SAFE)
# Apply flags per-config using generator expressions

# Debug (with sanitizers) — leak sanitizer is Linux-only, not available on macOS
target_compile_options(${TARGET} PRIVATE
    $<$<AND:$<CONFIG:Debug>,$<PLATFORM_ID:Linux>>:-g;-DDEBUG;-O0;-fsanitize=address,leak>
    $<$<AND:$<CONFIG:Debug>,$<PLATFORM_ID:Darwin>>:-g;-DDEBUG;-O0;-fsanitize=address>
)

target_link_options(${TARGET} PRIVATE
    $<$<AND:$<CONFIG:Debug>,$<PLATFORM_ID:Linux>>:-fsanitize=address,leak>
    $<$<AND:$<CONFIG:Debug>,$<PLATFORM_ID:Darwin>>:-fsanitize=address>
)

# detect x86
set(IS_X86 FALSE)
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|i[3-6]86")
    set(IS_X86 TRUE)
endif()

# Dev_Release
if(IS_X86)
    target_compile_options(${TARGET} PRIVATE
        $<$<AND:$<CONFIG:Dev_Release>,$<NOT:$<CXX_COMPILER_ID:MSVC>>>:
            -g0;-O2;-mno-avx512f;-mno-avx512bw;-mno-avx512vl
        >
    )
else()
    target_compile_options(${TARGET} PRIVATE
        $<$<AND:$<CONFIG:Dev_Release>,$<NOT:$<CXX_COMPILER_ID:MSVC>>>:
            -g0;-O2
        >
    )
endif()

# Release
target_compile_options(${TARGET} PRIVATE
    $<$<AND:$<CONFIG:Release>,$<NOT:$<CXX_COMPILER_ID:MSVC>>>:-g0;-O2>
)


# extra flags
option(DEBUG_OUTPUT "Force __VMAWARE_DEBUG__ define" OFF)
if(DEBUG_OUTPUT)
    target_compile_definitions(${TARGET} PRIVATE __VMAWARE_DEBUG__)
endif()

# CTest stuff
include(CTest)
if(BUILD_TESTING)
    set(ARGUMENTS "--all")
    if(MSVC)
        add_test(NAME executable COMMAND $<TARGET_FILE:${TARGET}> ${ARGUMENTS})
    else()
        add_test(NAME TARGET COMMAND $<TARGET_FILE:${TARGET}> ${ARGUMENTS})
    endif()
endif()

# install rules
include(GNUInstallDirs)

install(TARGETS ${TARGET} RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES "src/vmaware.hpp" DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})