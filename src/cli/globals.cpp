#include "globals.hpp"

std::string dim = "\x1B[38;2;120;120;120m";
std::string bright = "\x1B[38;2;180;180;180m";

std::string bold = "\x1B[1;97m";
std::string underline = "\x1B[4m";
std::string ansi_exit = "\x1B[0m";
std::string red = "\x1B[38;2;239;75;75m"; 
std::string orange = "\x1B[38;2;255;180;5m";
std::string green = "\x1B[38;2;94;214;114m";
std::string red_orange = "\x1B[38;2;247;127;40m";
std::string green_orange = "\x1B[38;2;174;197;59m";
std::string grey = "\x1B[38;2;108;108;108m";
std::string white = "\x1B[38;2;255;255;255m";

std::bitset<arg_bits> arg_bitset;

u8 unsupported_count = 0;
u8 supported_count = 0;
u8 no_perms_count = 0;
u8 disabled_count = 0;

std::string tag_detected = bold + "[" + green + "  DETECTED  " + bold + "]" + ansi_exit;
std::string tag_not_detected = "[" + red + "NOT DETECTED" + ansi_exit + "]";
std::string tag_skipped = "[" + grey + "  DISABLED  " + ansi_exit + "]";
std::string tag_no_perms = "[" + grey + "  NO PERMS  " + ansi_exit + "]";
std::string tag_notes = "[    NOTE    ]";