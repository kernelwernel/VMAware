# basic info
cmake_minimum_required(VERSION 3.22 FATAL_ERROR)
project(
    VMAware
    DESCRIPTION "VM detection library"
    LANGUAGES CXX
)


# set c++ standard
if(NOT DEFINED CMAKE_CXX_STANDARD)
    set(CMAKE_CXX_STANDARD 20)
endif()


# compiler flags
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (MSVC)
    set(CMAKE_CXX_FLAGS "/Wall /W4 /EHsc")
else()
    set(CMAKE_CXX_FLAGS "-Wextra -Wall -Wextra -Wconversion -Wdouble-promotion -Wno-unused-parameter -Wno-unused-function -Wno-sign-conversion -fmax-errors=20")
endif()

if(CMAKE_C_COMPILER_ID STREQUAL "Clang" OR CMAKE_C_COMPILER_ID STREQUAL "GNU")
    set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -lstdc++ -lm")
endif()


# fetch and set build type
set(available_build_types Debug Release)
if(NOT CMAKE_BUILD_TYPE)
set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build (Debug or Release)" FORCE)
endif()
if(NOT CMAKE_BUILD_TYPE IN_LIST available_build_types)
MESSAGE(FATAL_ERROR "Invalid build type: ${CMAKE_BUILD_TYPE}. Allowed values: ${available_build_types}")
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
        MESSAGE(STATUS "Build set to debug mode")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /Od")
    elseif(CMAKE_BUILD_TYPE MATCHES "Release")
        MESSAGE(STATUS "Build set to release mode")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /O2")
    endif()
elseif(LINUX)
    if(CMAKE_BUILD_TYPE MATCHES "Debug")
        MESSAGE(STATUS "Build set to debug mode")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -DDEBUG -O0 -fsanitize=address")
    elseif(CMAKE_BUILD_TYPE MATCHES "Release")
        MESSAGE(STATUS "Build set to release mode")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g0 -O3")
        if (${CMAKE_SYSTEM_PROCESSOR} MATCHES "x86_64")
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native -mtune=native")
        elseif(${CMAKE_SYSTEM_PROCESSOR} MATCHES "arm")
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mcpu=native")
        endif()
    endif()
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
#find_package(Python REQUIRED)
enable_testing()
if(MSVC)
add_test(executable, "${BUILD_DIR}/Release/${TARGET}")
else()
add_test(executable, "${BUILD_DIR}/${TARGET}")
endif()


# release stuff
if (NOT MSVC)
    if(CMAKE_BUILD_TYPE MATCHES "Release")
        install(TARGETS ${TARGET} DESTINATION /usr/local/bin)
        install(FILES "src/vmaware.hpp" DESTINATION /usr/include)
    else()
        install(TARGETS ${TARGET} DESTINATION ${CMAKE_SOURCE_DIR})
    endif()
elseif(MSVC)
    set(CMAKE_INSTALL_PREFIX "C:\\Program Files\\YourApplication")
    install(TARGETS ${TARGET} DESTINATION .)
endif()