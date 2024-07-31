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
# =============================================================
#
#  This is just an internal script for CI/CD. The main goal is to 
#  check whether all of the techniques are actually updated since 
#  keeping track of the docs, the cli, and the table isn't easy,
#  so I'm automating the checks in case I forget to update any.
# 
# ===============================================================
# 
#  - Made by: @kernelwernel (https://github.com/kernelwernel)
#  - Repository: https://github.com/kernelwernel/VMAware
#  - License: GPL 3.0

import sys
import re

def fetch():
    # fetch file content
    with open("../src/vmaware.hpp", 'r') as vmaware:
        header_content = vmaware.readlines()

    # reversed since the table is at the very end of the vmaware.hpp file 
    header_content.reverse()

    # breakpoint
    keyword = "const std::map<VM::u8, VM::core::technique> VM::core::technique_table = {"

    # fetch index of breakpoint
    index_of_keyword = next((i for i, line in enumerate(header_content) if keyword in line), None)

    # remove everything before the breakpoint for simplification
    if index_of_keyword is not None:
        header_content = header_content[:index_of_keyword + 1]

    return header_content



def filter(raw_content):
    trimmed_content = []

    # filter
    trimmed_content = [s for s in raw_content if not (
        s.isspace() or 
        "//" in s or 
        ";" in s or
        "VM::core::technique" in s
    )]

    # strip all whitespace
    trimmed_content = [s.strip() for s in trimmed_content]

    return trimmed_content



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
            print("Unable to find flag variable for " + line)
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
    end = "# Non-technique flags"

    # extract the indexes
    try:
        start_index = docs_content.index(start)
        end_index = docs_content.index(end)
    except ValueError:
        print("Couldn't find range index point \"# Flag table\" or \"# Non-technique flags\"")
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
            print("Pattern not found in the line \"" + line + "\"")
            sys.exit(1)

    set1 = set(docs_flags)
    set2 = set(flag_array)

    # Check if every element in set1 has a corresponding element in set2
    all_elements_have_pair = set1.issubset(set2) and set2.issubset(set1)

    not_paired = set1.symmetric_difference(set2)

    if not_paired:
        print("Mismatched elements found in documentation.md and vmaware.hpp, make sure to include the technique in both files")
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
            print("Pattern not found in the string.")
    
    set1 = set(cli_flags)
    set2 = set(flag_array)

    # check if every element in set1 has a corresponding element in set2
    not_paired = set1.symmetric_difference(set2)

    if not_paired:
        print("Mismatched elements found in cli.cpp and vmaware.hpp, make sure to include the technique in both files")
        print("Elements without a pair:", not_paired)
        sys.exit(1)


raw_content = fetch()
trimmed_content = filter(raw_content)
flags = tokenize(trimmed_content)

check_docs(flags)
check_cli(flags)