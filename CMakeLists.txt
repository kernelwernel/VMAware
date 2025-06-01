# basic info
cmake_minimum_required(VERSION 3.22 FATAL_ERROR)
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

if(MSVC)
    # Globally disable specific MSVC warnings from external headers
    add_compile_options(
        /wd5039  # 'TpSetCallbackCleanupGroup' potentially throwing
        /wd4820  # padding added after data member
        /wd4626  # deleted assignment operator
        /wd5045  # Spectre mitigation notice
        /wd4668  # undefined macro replaced with '0'
    )
endif()

# compiler flags
if (MSVC)
    set(CMAKE_CXX_FLAGS "/Wall /W4 /EHsc")
else()
    # Linux and Apple
    set(CMAKE_CXX_FLAGS "-Wextra -Wall -Wextra -Wconversion -Wdouble-promotion -Wno-unused-parameter -Wno-unused-function -Wno-sign-conversion")
endif()

if(CMAKE_C_COMPILER_ID STREQUAL "Clang" OR CMAKE_C_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -lstdc++ -lm")
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
endif()

message(STATUS "Compiler: ${COMPILER_NAME}")

# fetch and set build type
set(available_build_types Debug Release)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build (Debug or Release)" FORCE)
endif()

# Define preprocessor macros based on the build type
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_definitions(__VMAWARE_DEBUG__)
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_definitions(__VMAWARE_RELEASE__)
endif()

# general variables
set(PROJECT_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(BUILD_DIR "${PROJECT_DIR}/build")
set(TARGET "vmaware")

# debug/release CXX flag options
if (MSVC)
    if(CMAKE_BUILD_TYPE MATCHES "Debug")
        message(STATUS "Build set to debug mode")
    elseif(CMAKE_BUILD_TYPE MATCHES "Release")
        message(STATUS "Build set to release mode")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /O2")
    endif()
elseif(APPLE)
    if(CMAKE_BUILD_TYPE MATCHES "Debug")
        message(STATUS "Build set to debug mode")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 -fsanitize=address")
    elseif(CMAKE_BUILD_TYPE MATCHES "Release")
        message(STATUS "Build set to release mode")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g0 -O2 -march=native -mtune=native")
    endif()
elseif(LINUX)
    if(CMAKE_BUILD_TYPE MATCHES "Debug")
        message(STATUS "Build set to debug mode")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fmax-errors=5 -DDEBUG -O0 -fsanitize=address,leak")
    elseif(CMAKE_BUILD_TYPE MATCHES "Release")
        message(STATUS "Build set to release mode")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g0 -O2")
        if(${CMAKE_SYSTEM_PROCESSOR} MATCHES "x86_64")
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native -mtune=native")
        elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm")
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mcpu=native")
        endif()
    endif()
else()
    message(STATUS "Build set to release mode")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")
endif()

# add executable
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIR}")
add_executable(${TARGET} "src/cli.cpp")
if(NOT DEFINED CMAKE_CXX_STANDARD)
    set_property(TARGET ${TARGET} PROPERTY CXX_STANDARD 20)
endif()
set_property(TARGET ${TARGET} PROPERTY CXX_STANDARD_REQUIRED ON)

# CTest stuff
include(CTest)
enable_testing()
set(ARGUMENTS "--all")
if(MSVC)
    add_test(executable "${BUILD_DIR}/Release/${TARGET}")
else()
    add_test(NAME TARGET COMMAND "${BUILD_DIR}/${TARGET}" ${ARGUMENTS})
endif()

# install rules
if (NOT MSVC)
    if(CMAKE_BUILD_TYPE MATCHES "Release")
        install(TARGETS ${TARGET} DESTINATION /usr/bin)
        install(FILES "src/vmaware.hpp" DESTINATION /usr/include)
    else()
        install(TARGETS ${TARGET} DESTINATION ${CMAKE_SOURCE_DIR})
    endif()
elseif(MSVC)
    set(CMAKE_INSTALL_PREFIX "C:\\Program Files\\YourApplication")
    install(TARGETS ${TARGET} RUNTIME DESTINATION "bin")

    set(HEADER_INSTALL_PATH "C:\\Program Files (x86)\\YourLibrary\\include")
    install(FILES "src/vmaware.hpp" DESTINATION "${HEADER_INSTALL_PATH}")
endif()
