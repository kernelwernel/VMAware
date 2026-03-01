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
#    2. Update the dates in the banner, example: "1.9 (September 2024)"
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

def find_file(filename_candidates, start_dir=None, max_levels=8, walk_depth=2):
    if start_dir is None:
        start_dir = os.path.dirname(os.path.abspath(__file__))

    cur = start_dir
    for _level in range(max_levels + 1):
        # direct candidate paths at this level
        for cand in filename_candidates:
            candidate_path = os.path.join(cur, cand)
            if os.path.isfile(candidate_path):
                return os.path.normpath(os.path.abspath(candidate_path))

        # shallow walk from this level to catch files in subdirs (limited depth)
        top = cur
        top_depth = top.rstrip(os.sep).count(os.sep)
        for root, dirs, files in os.walk(top):
            depth = root.rstrip(os.sep).count(os.sep) - top_depth
            if depth > walk_depth:
                dirs[:] = []
                continue
            for cand in filename_candidates:
                base = os.path.basename(cand)
                if base in files:
                    return os.path.normpath(os.path.abspath(os.path.join(root, base)))

        parent = os.path.dirname(cur)
        if parent == cur:
            break
        cur = parent

    return None


# just some candidates in case the header is moved but still in source code tree
vmaware_candidates = [
    os.path.join('src', 'vmaware.hpp'),
    os.path.join('include', 'vmaware.hpp'),
    'vmaware.hpp'
]
docs_candidates = [
    os.path.join('docs', 'documentation.md'),
    os.path.join('doc', 'documentation.md'),
    'documentation.md'
]

vmaware_file = find_file(vmaware_candidates)
if not vmaware_file:
    print("Error: could not locate vmaware.hpp (tried src/, include/, and parent dirs).")
    sys.exit(2)

vmaware_docs = find_file(docs_candidates)
if not vmaware_docs:
    print("Warning: could not locate docs/documentation.md; documentation update will be skipped.")
    vmaware_docs = None


def update_sections(filename):
    with open(filename, 'r', encoding='utf-8', errors='ignore') as vmaware_read:
        header_content = vmaware_read.readlines()

    enum = "enum enum_flags"
    cpu  = "struct cpu {"
    memo = "struct memo {"
    util = "struct util {"
    techniques = "// START OF PRIVATE VM DETECTION TECHNIQUE DEFINITIONS"
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

    # swap two entries to keep original ordering behaviour
    banner[4], banner[5] = banner[5], banner[4]

    section_line = 0
    section_marker = " * ============================== SECTIONS =================================="
    for line in header_content:
        if section_marker in line:
            break
        section_line += 1
    section_line += 1

    for i, new_line in enumerate(banner):
        # ensure we don't index past end
        if section_line + i < len(header_content):
            header_content[section_line + i] = new_line + '\n'

    with open(filename, 'w', encoding='utf-8', errors='ignore') as file:
        file.writelines(header_content)


def update_date(filename):
    args = sys.argv
    date_arg = ""
    pattern = r'\d+\.\d+\.\d+'

    for arg in args[1:]:
        if re.fullmatch(pattern, arg):
            date_arg = arg
            break

    with open(filename, 'r', encoding='utf-8', errors='ignore') as file:
        header_content = file.readlines()

    banner_line = " *   ╚═══╝  ╚═╝     ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ "
    index = 0
    for line in header_content:
        if banner_line in line:
            break
        index += 1

    def find_pattern(base_str):
        match = re.search(pattern, base_str)
        if match:
            return match.group()
        print(f"Version number not found for {red}{bold}{base_str}{ansi_exit}, aborting")
        sys.exit(1)

    header_version = find_pattern(header_content[index])
    arg_version = find_pattern(date_arg) if date_arg else header_version
    new_date = datetime.now().strftime("%B %Y")

    experimental = ""
    if not "--release" in args:
        experimental = "Experimental post-"

    new_content = banner_line + experimental + arg_version + " (" + new_date + ")"
    header_content[index] = new_content + '\n'

    with open(filename, 'w', encoding='utf-8', errors='ignore') as file:
        file.writelines(header_content)


with open(vmaware_file, 'r', encoding='utf-8', errors='ignore') as file:
    file_content = file.readlines()


def fetch_enums():
    file_start = "// START OF TECHNIQUE LIST"
    file_end = "// END OF TECHNIQUE LIST"

    file_start_ptr = 0
    file_end_ptr = 0

    file_index = 0

    for line in file_content:
        if file_start in line:
            file_start_ptr = file_index
        elif file_end in line:
            file_end_ptr = file_index
            break

        file_index += 1

    if file_end_ptr <= file_start_ptr:
        return []

    filtered_file = [line.strip() for line in file_content[file_start_ptr + 1: file_end_ptr]]

    enum_list = []
    for enum_line in filtered_file:
        # we can tolerate empty lines and comments
        if not enum_line or enum_line.startswith('//'):
            continue
        enum_list.append(enum_line.replace("case", "").split(":")[0].strip())

    return enum_list


class options:
    def __init__(self, enum_name="", line=0, platform_emojis="", score=0, description="", is_admin=False, only_32_bit=False, notes="", code_link=""):
        self.enum_name = enum_name
        self.line = line
        self.platform_emojis = platform_emojis
        self.score = score
        self.description = description
        self.is_admin = is_admin
        self.only_32_bit = only_32_bit
        self.notes = notes
        self.code_link = code_link


class array_dict(dict):
    def __getitem__(self, key):
        return self.get(key)
    
    def init_as_list(self, key):
        self[key] = options(enum_name = key)
        return self[key]


technique = array_dict()


def fetch_lib_info(enum_list):
    if not enum_list:
        return

    for enum in enum_list:
        technique.init_as_list(enum)

    # fetch line number
    enum_marker_prefix = "* @implements VM::"
    for i, line in enumerate(file_content):
        if enum_marker_prefix in line:
            for enum in enum_list:
                # avoid repeated scans (by matching suffix)
                if enum in line:
                    # set line if not already set
                    if technique[enum].line == 0:
                        technique[enum].line = i + 1

    # generate the code implementation link 
    link_prefix = "[link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L"
    for enum in enum_list:
        line_no_str = str(technique[enum].line if technique[enum].line else 1)
        technique[enum].code_link = link_prefix + line_no_str + ")"

    # fetch scores (by scanning the technique table once)
    start = "// START OF TECHNIQUE TABLE"
    end = "// END OF TECHNIQUE TABLE"
    start_ptr = end_ptr = -1
    for index, line in enumerate(file_content):
        if start in line:
            start_ptr = index
        elif end in line and start_ptr != -1: # Only set end if start was found
            end_ptr = index
            break


    if start_ptr == -1:
        print(f"start position for technique table not found, aborting")
        sys.exit(1)

    if end_ptr == -1:
        print(f"end position for technique table not found, aborting")
        sys.exit(1)

    raw_technique_list = []

    if end_ptr > start_ptr:
        raw_technique_list = [line.strip() for line in file_content[start_ptr+1:end_ptr]]
    
    technique_list = []

    for line in raw_technique_list:
        if line.startswith("#"):
            continue
        
        if line == "":
            continue
        
        technique_list.append(line)

    for enum in enum_list:
        for enum_line in technique_list:
            if enum in enum_line:
                matches = re.findall(r'\d+', enum_line)

                if len(matches) == 0:
                    print(f"could not find score number in technique table line, aborting")
                    sys.exit(1)
                
                if len(matches) > 2:
                    print(f"found multiple score numbers in technique table line, aborting")
                    sys.exit(1)
                
                technique[enum].score = int(matches[0])
                break

    # fetch more stuff, comment block surrounding the implementation line
    for enum in enum_list:
        start_line = end_line = technique[enum].line - 1  # convert to 0-based index
        if start_line < 0 or start_line >= len(file_content):
            continue

        while start_line >= 0 and not file_content[start_line].strip().startswith('/**'):
            start_line -= 1
        
        while end_line < len(file_content) and not file_content[end_line].strip().endswith('*/'):
            end_line += 1
        
        if (start_line < 0 or end_line >= len(file_content) or
            not file_content[start_line].strip().startswith('/**') or
            not file_content[end_line].strip().endswith('*/')):
            # some entries may not follow exact comment format for some reason
            continue
        
        details = file_content[start_line : end_line + 1]

        # check inside the comment
        for line in details:
            if "@brief" in line:
                technique[enum].description = line.split("@brief", 1)[-1].strip()
            if "@warning" in line:
                technique[enum].is_admin = True
            elif "@category" in line:
                linux = "Linux" in line
                windows = "Windows" in line
                macos = "MacOS" in line

                emojis = []
                if linux:
                    emojis.append("🐧")
                if windows:
                    emojis.append("🪟")
                if macos:
                    emojis.append("🍏")
                if not emojis:
                    emojis = ["🐧", "🪟", "🍏"]

                technique[enum].platform_emojis = ''.join(emojis)

                if "x86_32" in line:
                    technique[enum].only_32_bit = True

            if "@note" in line:
                technique[enum].notes = line.split("@note", 1)[-1].strip()


def update_docs(enum_list):
    if not vmaware_docs:
        print("Skipping documentation update because documentation.md was not found.")
        return

    technique_array = []

    for enum in enum_list:
        order = [
            f"`VM::{technique[enum].enum_name}`",
            technique[enum].description,
            technique[enum].platform_emojis,
            f"{technique[enum].score}%",
            "Admin" if technique[enum].is_admin else "",
            "32-bit" if technique[enum].only_32_bit else "",
            technique[enum].notes,
            technique[enum].code_link
        ]
        technique_array.append("| " + " | ".join(str(item).strip() for item in order) + " |")

    with open(vmaware_docs, 'r', encoding='utf-8', errors='ignore') as file:
        docs_content = file.readlines()

    docs_start = "<!-- START OF TECHNIQUE DOCUMENTATION -->"
    docs_end = "<!-- END OF TECHNIQUE DOCUMENTATION -->"

    start_ptr = -1
    end_ptr = -1

    for index, line in enumerate(docs_content):
        line_stripped = line.strip()
        if docs_start in line_stripped:
            start_ptr = index
        elif docs_end in line_stripped and start_ptr != -1:
            end_ptr = index
            break

    if start_ptr == -1 or end_ptr == -1:
        print("Error: Start or end marker not found in documentation.md")
        return

    header_rows = [
        docs_start,
        "",
        "| Flag alias | Description | Supported platforms | Certainty | Admin? | 32-bit only? | Notes | Code implementation |",
        "| ---------- | ----------- | ------------------- | --------- | ------ | ------------ | ----- | ------------------- |"
    ]
    technique_array = header_rows + technique_array

    # replace the region between start_ptr and end_ptr (inclusive start, exclusive end)
    docs_content[start_ptr:end_ptr] = [line + '\n' for line in technique_array]

    with open(vmaware_docs, 'w', encoding='utf-8', errors='ignore', newline='\n') as f:
        f.writelines(docs_content)


# Run updates
update_sections(vmaware_file)
update_date(vmaware_file)
enums = fetch_enums()
fetch_lib_info(enums)
update_docs(enums)