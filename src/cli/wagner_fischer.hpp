#pragma once

#include "globals.hpp"
#include "types.hpp"

#include <string>
#include <vector>

u8 wagner_fischer(const std::string& a_input, const std::string& b_input);
std::vector<std::string> suggest(const std::string& misspelled_word, const arg_table& dictionary);
void manage_output(const std::vector<std::string>& suggestions);