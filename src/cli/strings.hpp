#pragma once

#include <string>
#include <bitset>
#include "types.hpp"

#if (defined(__GNUC__) || defined(__linux__))
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

extern const std::string TH_DIM;
extern const std::string TH_MED;
extern const std::string TH_WHITE;
extern const std::string TH_RST;

#if (CLI_WINDOWS)
    extern const std::string TH_BRIGHT;
    extern const std::string TH_RED;
#endif

extern std::string bold;
extern std::string underline;
extern std::string ansi_exit;
extern std::string red;
extern std::string orange;
extern std::string green;
extern std::string red_orange;
extern std::string green_orange;
extern std::string grey;
extern std::string white;

enum arg_enum : u8 {
    HELP,
    VERSION,
    ALL,
    DETECT,
    STDOUT,
    BRAND,
    BRAND_LIST,
    PERCENT,
    CONCLUSION,
    NUMBER,
    TYPE,
    OUTPUT,
    NOTES,
    HIGH_THRESHOLD,
    NO_ANSI,
    DYNAMIC,
    VERBOSE,
    ENUMS,
    DETECTED_ONLY,
    JSON,
    NULL_ARG
};

constexpr u8 arg_bits = static_cast<u8>(NULL_ARG) + 1;
extern std::bitset<arg_bits> arg_bitset;

extern u8 unsupported_count;
extern u8 supported_count;
extern u8 no_perms_count;
extern u8 disabled_count;

extern std::string tag_detected;
extern std::string tag_not_detected;
extern std::string tag_skipped;
extern std::string tag_notes;