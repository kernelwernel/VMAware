#pragma once

#include "types.hpp"
#include <string>

bool is_admin();
const char* color(u8 score, bool is_hardened);
bool is_vm_brand_multiple(const std::string& vm_brand);
const char* get_vm_description(const std::string& vm_brand);

bool parse_disable_token(const char* token);
void generate_json(const char* output);
u32 get_technique_count();

int run_stdout(bool high_threshold, bool all, bool dynamic);
u32 run_percent(bool high_threshold, bool all, bool dynamic);
bool run_detect(bool high_threshold, bool all, bool dynamic);
std::string run_brand(bool high_threshold, bool all, bool dynamic);
std::string run_type(bool high_threshold, bool all, bool dynamic);
std::string run_conclusion(bool high_threshold, bool all, bool dynamic);

void general(bool high_threshold, bool all, bool dynamic, const char* output_file = nullptr);
