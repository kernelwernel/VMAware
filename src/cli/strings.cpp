#include "strings.hpp"

const std::string TH_DIM = "\x1B[38;2;60;60;60m";
const std::string TH_MED = "\x1B[38;2;120;120;120m";
const std::string TH_WHITE = "\x1B[38;2;255;255;255m";
const std::string TH_RST = "\x1B[0m";

#if (CLI_WINDOWS)
const std::string TH_BRIGHT = "\x1B[38;2;180;180;180m";
const std::string TH_RED = "\x1B[38;2;220;0;0m";
#endif

std::string bold = "\x1B[1;97m";
std::string underline = "\x1B[4m";
std::string ansi_exit = "\x1B[0m";
std::string red = "\x1B[31m";
std::string orange = "\x1B[38;2;180;50;0m";
std::string green = "\x1B[38;2;60;60;60m";
std::string red_orange = "\x1B[31m";
std::string green_orange = "\x1B[38;2;60;60;60m";
std::string grey = "\x1B[38;2;60;60;60m";
std::string white = "\x1B[38;2;255;255;255m";

std::bitset<arg_bits> arg_bitset;

u8 unsupported_count = 0;
u8 supported_count = 0;
u8 no_perms_count = 0;
u8 disabled_count = 0;

std::string tag_detected = ("\x1B[97m[\x1B[31m  DETECTED  \x1B[97m]\x1B[0m");
std::string tag_not_detected = ("   \x1B[97m[\x1B[90mNOT DETECTED\x1B[97m]\x1B[0m");
