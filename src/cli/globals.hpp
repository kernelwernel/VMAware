#pragma once

#include <array>
#include <string>
#include <bitset>
#include "types.hpp"

extern std::string dim;
extern std::string bright;

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
    RICH,
    EXPERIMENTAL,
    NULL_ARG,
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
extern std::string tag_no_perms;
extern std::string tag_notes;

// increment this each time a new argument is introduced
constexpr std::size_t arg_count = 34;

using arg_table = std::array<std::pair<const char*, arg_enum>, arg_count>;