# 
# ██╗   ██╗███╗   ███╗ █████╗ ██╗    ██╗ █████╗ ██████╗ ███████╗
# ██║   ██║████╗ ████║██╔══██╗██║    ██║██╔══██╗██╔══██╗██╔════╝
# ██║   ██║██╔████╔██║███████║██║ █╗ ██║███████║██████╔╝█████╗  
# ╚██╗ ██╔╝██║╚██╔╝██║██╔══██║██║███╗██║██╔══██║██╔══██╗██╔══╝  
#  ╚████╔╝ ██║ ╚═╝ ██║██║  ██║╚███╔███╔╝██║  ██║██║  ██║███████╗
#   ╚═══╝  ╚═╝     ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
# 
#  C++ VM detection library
# 
# ===============================================================
# 
#  This is an internal script to update various stuff of the project automatically:
# 
#    1.  Update the line numbers for the sections header based on what
#        line they are located, so it's a (tiny) bit easier to understand
#        the structure of the headers for anybody reading it for the first
#        time, it's more of a guide to point which parts are this and that.
# 
#    2. Update the dates in the banner, example: "1.9 (Septmber 2024)"
# 
# ===============================================================
# 
#  - Made by: @kernelwernel (https://github.com/kernelwernel)
#  - Repository: https://github.com/kernelwernel/VMAware
#  - License: MIT


import sys
import re
import os
from datetime import datetime

red = "\033[31m"
bold = "\033[1m"
ansi_exit = "\033[0m"

gpl_file = os.path.join('..', 'src', 'vmaware.hpp')

def update_sections(filename):
    with open(filename, 'r') as vmaware_read:
        header_content = vmaware_read.readlines()

    enum = "enum enum_flags"
    cpu  = "struct cpu {"
    memo = "struct memo {"
    util = "struct util {"
    techniques = "private: // START OF PRIVATE VM DETECTION TECHNIQUE DEFINITIONS"
    core = "struct core {"
    public = "public: // START OF PUBLIC FUNCTIONS"
    external = "// ============= EXTERNAL DEFINITIONS ============="

    keywords = [enum, cpu, memo, util, techniques, core, public, external]
    scanner_keywords = [
        "__ENUM__",
        "__CPU__",
        "__MEMO__",
        "__UTIL__",
        "__TECHNIQUES__",
        "__CORE__",
        "__PUBLIC__",
        "__EXTERNAL__"
    ]

    pointer_array = []
    file_pointer = 0
    array_index = 0

    for line in header_content:
        if keywords[array_index] in line:
            if array_index != len(keywords) - 1:
                array_index += 1
            pointer_array.append(file_pointer)
        file_pointer += 1

    pair_array = []
    for i, scanner in enumerate(scanner_keywords):
        if i < len(pointer_array):
            pair_array.append((scanner, pointer_array[i]))

    banner = [
        " * - enums for publicly accessible techniques  => line __ENUM__",
        " * - struct for internal cpu operations        => line __CPU__",
        " * - struct for internal memoization           => line __MEMO__",
        " * - struct for internal utility functions     => line __UTIL__",
        " * - start of VM detection technique list      => line __TECHNIQUES__",
        " * - struct for internal core components       => line __CORE__",
        " * - start of public VM detection functions    => line __PUBLIC__",
        " * - start of externally defined variables     => line __EXTERNAL__"
    ]

    index = 0
    for macro, line_no in pair_array:
        for j, text in enumerate(banner):
            if macro in text:
                banner[j] = text.replace(macro, str(line_no))
                break

    banner[4], banner[5] = banner[5], banner[4]

    section_line = 0
    section_marker = " * ============================== SECTIONS =================================="
    for line in header_content:
        if section_marker in line:
            break
        section_line += 1
    section_line += 1

    for i, new_line in enumerate(banner):
        header_content[section_line + i] = new_line + '\n'

    with open(filename, 'w') as file:
        file.writelines(header_content)


def update_date(filename):
    args = sys.argv
    first_arg = args[1] if len(args) > 1 else None

    with open(filename, 'r') as file:
        header_content = file.readlines()

    banner_line = " *   ╚═══╝  ╚═╝     ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ "
    index = 0
    for line in header_content:
        if banner_line in line:
            break
        index += 1

    def find_pattern(base_str):
        pattern = r'\d+\.\d+\.\d+'
        match = re.search(pattern, base_str)
        if match:
            return match.group()
        print(f"Version number not found for {red}{bold}{base_str}{ansi_exit}, aborting")
        sys.exit(1)

    header_version = find_pattern(header_content[index])
    arg_version = find_pattern(first_arg) if first_arg else header_version
    new_date = datetime.now().strftime("%B %Y")
    new_content = banner_line + arg_version + " (" + new_date + ")"

    header_content[index] = new_content + '\n'

    with open(filename, 'w') as file:
        file.writelines(header_content)


update_sections(gpl_file)
update_date(gpl_file)