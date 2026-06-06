#pragma once

#include <cstdint>

using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using i32 = std::int32_t;

#if defined(__linux__)
    #define CLI_LINUX 1
#else
    #define CLI_LINUX 0
#endif

#if (defined(__APPLE__) || defined(__APPLE_CPP__) || defined(__MACH__) || defined(__DARWIN))
    #define CLI_APPLE 1
#else
    #define CLI_APPLE 0
#endif

#if (defined(_MSC_VER) || defined(_WIN32) || defined(_WIN64) || defined(__MINGW32__))
    #define CLI_WINDOWS 1
#else
    #define CLI_WINDOWS 0
#endif