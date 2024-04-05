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
# This is an internal script to update the VMAware
# header file's banner automatically and much more reliably.
# For example, it'll update the line numbers for the sections
# header, and other basic information.
# 
# ===============================================================
# 
#  - Made by: @kernelwernel (https://github.com/kernelwernel)
#  - Repository: https://github.com/kernelwernel/VMAware
#  - License: GPL 3.0



def update(filename):
    with open(filename, 'r') as vmaware_read:
        header_content = vmaware_read.readlines()

    # fetch important bits
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
        " * - start of internal VM detection techniques => line __TECHNIQUES__",
        " * - struct for internal core components       => line __CORE__",
        " * - start of public VM detection functions    => line __PUBLIC__",
        " * - start of externally defined variables     => line __EXTERNAL__",
        " */",
        ""
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
    section_str = " * ================================ SECTIONS =================================="
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


update("../src/vmaware.hpp")
update("../src/vmaware_MIT.hpp")