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
#    1.  Check whether all of the techniques are actually updated since 
#        keeping track of the docs, the CLI, and the table isn't easy,
#        so I'm automating the checks in case I forget to update any.
# 
#    2.  Update the line numbers for the sections header based on what
#        line they are located, so it's a (tiny) bit easier to understand
#        the structure of the headers for anybody reading it for the first
#        time, it's more of a guide to point which parts are this and that.
# 
#    3.  Convert the GPL file (vmaware.hpp) into an MIT file (vmaware_MIT.hpp).
#        In other words, it'll remove all the GPL code so that it qualifies 
#        as MIT compliant.  
# 
#    4. Update the dates in the banner, example: "1.9 (Septmber 2024)"
# 
# ===============================================================
# 
#  - Made by: @kernelwernel (https://github.com/kernelwernel)
#  - Repository: https://github.com/kernelwernel/VMAware
#  - License: GPL 3.0


import sys
import re
from datetime import datetime

red = "\033[31m"
bold = "\033[1m"
ansi_exit = "\033[0m"

def arg_check():
    # get the raw technique table which includes a lot of junk
    def fetch():
        # fetch file content
        with open("../src/vmaware.hpp", 'r') as vmaware:
            header_content = vmaware.readlines()

        # reversed since the table is at the very end of the vmaware.hpp file 
        header_content.reverse()

        # breakpoint
        keyword = "// START OF TECHNIQUE TABLE"

        # fetch index of breakpoint
        index_of_keyword = next((i for i, line in enumerate(header_content) if keyword in line), None)

        # remove everything before the breakpoint for simplification
        if index_of_keyword is not None:
            header_content = header_content[:index_of_keyword + 1]

        return header_content


    # filter the junk, and only leave the actual technique formats
    def filter(raw_content):
        trimmed_content = []

        # filter
        trimmed_content = [s for s in raw_content if not (
            s.isspace() or 
            ";" in s or
            s.lstrip().startswith("//") or
            "VM::core::custom_technique" in s or
            "VM::core::technique" in s or
            s.lstrip().startswith("}")
        )]

        # strip all whitespace
        trimmed_content = [s.strip() for s in trimmed_content]

        return trimmed_content


    # extract the flag from those technique formats
    def tokenize(trimmed_content):
        flag_array = []

        # pattern for VM::FLAG_EXAMPLE1
        pattern = r'\bVM::([A-Z0-9_]+)\b'

        # match and push to flag_array[]
        for line in trimmed_content:
            match = re.search(pattern, line)

            if match:
                flag_array.append(match.group(0))
            else:
                print(f"Unable to find flag variable for " + red + bold + line + ansi_exit)
                sys.exit(1)

        return flag_array



    def check_docs(flag_array):
        # fetch docs content
        with open("../docs/documentation.md", 'r') as docs:
            docs_content = docs.readlines()

        # strip whitespace
        docs_content = [s.strip() for s in docs_content]

        # find indices
        start = "# Flag table"
        end = "# Setting flags"

        # extract the indexes
        try:
            start_index = docs_content.index(start)
            end_index = docs_content.index(end)
        except ValueError:
            print(f"Couldn't find range index point {red}{bold}\"# Flag table\"{ansi_exit} or {red}{bold}\"# Setting flags\"{ansi_exit}")
            start_index = end_index = None
            sys.exit(1)

        # extract the range between the aforementioned indexes
        if start_index is not None and end_index is not None:
            extracted_range = docs_content[start_index + 1:end_index]
            docs_content = extracted_range

        # filter elements with whitespace
        docs_content = [s for s in docs_content if not s.isspace() and s and "VM::" in s]

        # extract flag string for every line
        docs_flags = []
        pattern = r'`([^`]+)`'
        for line in docs_content:
            match = re.search(pattern, line)

            if match:
                docs_flags.append(match.group(1))
            else:
                print(f"Pattern not found in the line {red}{bold}\"" + line + "\"{ansi_exit}")
                sys.exit(1)

        set1 = set(docs_flags)
        set2 = set(flag_array)

        # Check if every element in set1 has a corresponding element in set2
        all_elements_have_pair = set1.issubset(set2) and set2.issubset(set1)

        not_paired = set1.symmetric_difference(set2)

        if not_paired:
            if "VM::ANYRUN_DIRECTORY" in not_paired or "VM::ANYRUN_DRIVER" in not_paired:
                return

            print(f"Mismatched elements found in {red}{bold}documentation.md{bold} and {red}{bold}vmaware.hpp{bold}, make sure to include the technique in both files")
            print("Elements without a pair:", not_paired)
            sys.exit(1)




    def check_cli(flag_array):
        # fetch docs content
        with open("../src/cli.cpp", 'r') as cli:
            cli_content = cli.readlines()

        # strip whitespace
        cli_content = [s.strip() for s in cli_content]

        # filter elements with whitespace
        cli_content = [s for s in cli_content if ("checker(" in s)]

        # extract the flags
        cli_flags = []
        pattern = r'checker\((.*?),'
        for line in cli_content:
            match = re.search(pattern, line)

            if match:
                cli_flags.append(match.group(1).strip())
            else:
                print(f"{red}{bold}Pattern not found in the string.{ansi_exit}")
        
        set1 = set(cli_flags)
        set2 = set(flag_array)

        # check if every element in set1 has a corresponding element in set2
        not_paired = set1.symmetric_difference(set2)

        if not_paired:
            if "anyrun_directory" in not_paired or "anyrun_driver" in not_paired:
                return

            print(f"Mismatched elements found in {red}{bold}cli.cpp{ansi_exit} and {red}{bold}vmaware.hpp{ansi_exit}, make sure to include the technique in both files")
            print("Elements without a pair:", not_paired)
            sys.exit(1)


    raw_content = fetch()
    trimmed_content = filter(raw_content)
    flags = tokenize(trimmed_content)

    check_docs(flags)
    check_cli(flags)











def update_MIT():
    original = '../src/vmaware.hpp'
    mit = '../src/vmaware_MIT.hpp'
    gpl_string = '/* GPL */'
    license_string = ' *  - License: GPL-3.0 (https://www.gnu.org/licenses/gpl-3.0.html)'
    mit_full_license = ''' *  - License: MIT
 * 
 *                               MIT License
 *  
 *  Copyright (c) 2024 kernelwernel
 *  
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *  
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *  
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
'''

    with open(original, 'r') as file:
        lines = file.readlines()

    add_string_added = False

    filtered_lines = []
    for line in lines:
        if gpl_string in line:
            # skip
            continue
        if license_string in line:
            filtered_lines.append(mit_full_license)
        else:
            filtered_lines.append(line)

    with open(mit, 'w') as file:
        file.writelines(filtered_lines)



def update_sections(filename):
    with open(filename, 'r') as vmaware_read:
        header_content = vmaware_read.readlines()

    # fetch important portions
    enum = "enum enum_flags"
    cpu  = "struct cpu {"
    memo = "struct memo {"
    util = "struct util {"
    techniques = "private: // START OF PRIVATE VM DETECTION TECHNIQUE DEFINITIONS"
    core = "struct core {"
    public = "public: // START OF PUBLIC FUNCTIONS"
    external = "// ============= EXTERNAL DEFINITIONS ============="

    # set up the arrays
    pointer_array = []
    pair_array = []
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

    # set the indexes
    file_pointer = 0
    array_index = 0


    # loop and append if keyword is found
    for line in header_content:
        if keywords[array_index] in line:
            if array_index != len(keywords) - 1:
                array_index += 1

            pointer_array.append(file_pointer)

        file_pointer += 1


    # create the pair array
    i = 0
    for scanner in scanner_keywords:
        tmp_pair = (scanner, pointer_array[i])
        pair_array.append(tmp_pair)
        if i != len(pointer_array) - 1:
            i += 1


    MACRO = 0
    FILE_LINE = 1
    index = 0
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

    # replace the macro strings with the file line numbers
    for pair in pair_array:
        for line in banner:
            if pair[MACRO] in line:
                banner[index] = line.replace(pair[MACRO], str(pair[FILE_LINE]))
                index += 1
                continue
        
    # manual filters
    tmp = banner[4]
    banner[4] = banner[5]
    banner[5] = tmp

    # get the index file line of the section string
    section_line = 0
    section_str = " * ============================== SECTIONS =================================="
    for line in header_content:
        if section_str in line:
            break
        section_line += 1
    section_line += 1

    # write to the header file
    for i in range(len(banner)):
        header_content[section_line + i] = banner[i] + '\n'
    with open(filename, 'w') as file:
        file.writelines(header_content)



def update_date(filename):
    # fetch the first arg, which is supposed to be the new version number for a new release
    args = sys.argv
    first_arg = args[1] if len(args) > 1 else None


    with open(filename, 'r') as file:
        header_content = file.readlines()

    index = 0
    banner_line = " *   ╚═══╝  ╚═╝     ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ "

    # fetch the index of where the line should be updated
    for line in header_content:
        if (banner_line not in line):
            index += 1
        else:
            break

    # find "X.X", where X is an integral
    def find_pattern(base_str):
        pattern = r'\d+\.\d+'

        # Search for the pattern in the text
        match = re.search(pattern, base_str)

        # find match
        if match:
            return match.group()
            print("match found")
        else:
            print(f"Version number not found for {red}{bold}{base_str}{ansi_exit}, aborting")
            sys.exit(1)


    # fetch the new version
    header_version = find_pattern(header_content[index])
    if first_arg == None:
        arg_version = header_version
    else:
        arg_version = find_pattern(first_arg)

    new_version = ""
    new_date = ""

    # set the version and date
    new_version = arg_version
    new_date = datetime.now().strftime("%B") + " " + str(datetime.now().year)

    # this will be the new content
    new_content = banner_line + new_version + " (" + new_date + ")"

    if 0 < index <= len(header_content):
        header_content[index] = new_content + '\n'
    else:
        print(f"Line number {red}{line_number} is out of range.")
        sys.exit(1)

    with open(filename, 'w') as file:
        file.writelines(header_content)    



arg_check()
update_MIT()
update_sections("../src/vmaware.hpp")
update_sections("../src/vmaware_MIT.hpp")
update_date("../src/vmaware.hpp")
update_date("../src/vmaware_MIT.hpp")