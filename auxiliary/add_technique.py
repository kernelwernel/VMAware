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
#  This is an internal script to automatically add a technique to
#  the lib with many aspects of the lib updated based on user input.
#  
#  the updated components are:
#   - documentation
#   - technique table 
#   - CLI check list
#   - technique enums
#   - flag_to_string()
#   - is_<os> functionality in CLI
#   - adding the technique itself in vmaware.hpp
# 
# ===============================================================
# 
#  - Made by: @kernelwernel (https://github.com/kernelwernel)
#  - Repository: https://github.com/kernelwernel/VMAware
#  - License: GPL 3.0

import questionary




class options:
    def __init__(self, enum_name, file_path, function_name, cross_platform, is_linux, is_win, is_mac, score, short_description, description, author, link, is_admin, is_gpl, only_32_bit, is_x86_only, notes):
        self.enum_name = enum_name
        self.file_path = file_path
        self.function_name = function_name
        self.cross_platform = cross_platform
        self.is_linux = is_linux
        self.is_win = is_win
        self.is_mac = is_mac
        self.score = score
        self.short_description = short_description
        self.description = description
        self.author = author
        self.link = link
        self.is_admin = is_admin
        self.is_gpl = is_gpl
        self.only_32_bit = only_32_bit
        self.is_x86_only = is_x86_only
        self.notes = notes




def prompt():
    # 1: enum name
    enum_answer = questionary.text("What's the name of the enum? (i.e. VBOX_REG or HYPERVISOR_STR)").ask()
    enum_answer = enum_answer.upper()


    # 2: technique file
    file_path = questionary.path("What's the path to the technique file?").ask()
    if not file_path.endswith(".cpp") and not file_path.endswith(".cc"):
        raise ValueError("file input MUST be a .cpp file")
    with open(file_path, 'r') as file:
        for line in file:
            if "#include" in line.lower():
                raise ValueError("The cpp file will be directly copied to the lib verbatim, do not add #include as this will end up in vmaware.hpp")


    # 3: function name
    function_name = questionary.text("What's the name of the technqiue function in your .cpp file?").ask()
    function_name = function_name.lower()
    if "(" in function_name or ")" in function_name:
        function_name = function_name.replace("(", "").replace(")", "")


    # 4: is it cross-platform?
    cross_platform = questionary.confirm("Is it cross-platform?").ask()
    is_linux = False
    is_win = False
    is_mac = False
    if cross_platform == True:
        is_linux = True
        is_win = True
        is_mac = True
    else:
        choices = questionary.checkbox(
            "Which OS does this technique support?",
            choices=[
                "Linux",
                "Windows",
                "MacOS"
            ]
        ).ask()
        if "Linux" in choices:
            is_linux = True
        if "Windows" in choices:
            is_win = True
        if "MacOS" in choices:
            is_mac = True
    

    # 5: certainty score
    certainty = questionary.text("What's the score of your technique?").ask()
    if certainty == "":
        raise ValueError("A score is mandatory (0 to 100)")

        
    score = int(certainty)


    # 6: description
    description = ""
    while True:
        text = questionary.text("What's the description of your technique? (50-100 characters)").ask()
        if len(text) < 50:
            print("Too short, try again\n")
            continue
        if len(text) > 100:
            print("Too long, try again\n")
            continue
        description = text
        break

    # 7: short description
    short_description = ""
    while True:
        text = questionary.text("What is your technique checking for? This will appear in the CLI, so be as minimal as you can (max 30 characters)").ask()
        if len(text) > 30:
            print("Too long, try again\n")
            continue
        if len(text) > len(description):
            print("The answer cannot be longer than the actual description from the previous question\n")
            continue
        short_description = text
        break


    # 8: author
    author = questionary.text("Who is the author? (optional, can be left empty)").ask()


    # 9: link
    link = questionary.text("If there's a source for the technique's origin, paste the link here (optional, can be left empty)").ask()


    # 10: permissions
    is_admin = questionary.confirm("Does it require admin permissions?").ask()


    # 11: GPL
    is_gpl = questionary.confirm("Is it GPL?").ask()


    # 12: 32-bit
    only_32_bit = questionary.confirm("Is it 32-bit only? (no support for 64-bit systems)").ask()


    # 13: x86
    is_x86 = questionary.confirm("Is it x86 only? (no support for ARM for example)").ask()


    # 14: notes
    notes = questionary.text("Are there any extra notes you want to add? (leave this empty if it's unnecessary)").ask()


    return options(
        enum_answer,
        file_path,
        function_name,
        cross_platform,
        is_linux,
        is_win,
        is_mac,
        score,
        short_description,
        description,
        author,
        link,
        is_admin,
        is_gpl,
        only_32_bit,
        is_x86,
        notes
    )


def write_header(options):
    with open('../src/vmaware.hpp', 'r') as file:
        lines = file.readlines()

    new_code = []

    for line in lines:
        # if the line is empty, skip
        if not line:
            new_code.append(line)
            continue


        # modify the enum
        if "// ADD NEW TECHNIQUE ENUM NAME HERE" in line:
            new_code.append("\t\t" + options.enum_name + ",\n")


        # append the technique function to the function list section
        if "// ADD NEW TECHNIQUE FUNCTION HERE" in line:
            full_technique = []

            # manage the category string of the technique
            category_list = []
            if options.cross_platform:
                if options.is_x86_only:
                    category_list.append("x86")
            else:
                if options.is_linux:
                    category_list.append("Linux")
                if options.is_win:
                    category_list.append("Windows")
                if options.is_mac:
                    category_list.append("MacOS")
            category_str = ", ".join(category_list)

            # manage the basic details of the technique
            technique_details = []
            technique_details.append("@brief " + options.description)
            if options.author:
                technique_details.append("@author " + options.author)
            if options.link:
                technique_details.append("@link " + options.link)
            
            technique_details.append("@category " + category_str)
            technique_details.append("@note " + options.notes)
            if options.is_gpl:
                technique_details.append("@copyright GPL-3.0")
            
            # modify the technique details prefix comments 
            # depending on whether it's GPL or not
            if options.is_gpl:
                for comment in technique_details:
                    full_technique.append("// " + comment + "\n")
            else:
                full_technique.append("/**\n")
                for comment in technique_details:
                    full_technique.append(" * " + comment + "\n")
                full_technique.append(" */\n")

            # read the whole technique code
            with open(options.file_path, 'r') as technique_file:
                technique_code = technique_file.readlines()
                full_technique = full_technique + technique_code

            # add the GPL specifier for every line 
            if options.is_gpl:
                for i in range(len(full_technique)):
                    full_technique[i] = "/* GPL */ " + full_technique[i]

            # commit the full technique in the buffer 
            for technique_line in full_technique:
                new_code.append("\t" + technique_line)

            # extra lines
            new_code.append("\n\n")


        # modify the technique table with the new technique appended
        if "// ADD NEW TECHNIQUE STRUCTURE HERE" in line:
            new_code.append(
                "\t" + 
                "{ VM::" + 
                options.enum_name + 
                ", { " + 
                str(options.score) + 
                ", VM::" + 
                options.function_name +
                ", false } },\n"
            )


        # modify the VM::flag_to_string function with the new technique
        if "// ADD NEW CASE HERE FOR NEW TECHNIQUE" in line:
            new_code.append(
                "\t\t\tcase " + 
                options.enum_name + 
                ": return \"" + 
                options.enum_name + 
                "\";\n"
            )

        # add the line in the buffer array
        new_code.append(line)


    # commit the new changes from the buffer array
    with open("../src/vmaware.hpp", "w") as file:
        for line in new_code:
            file.write(line)




def write_cli(options):
    with open('../src/cli.cpp', 'r') as file:
        lines = file.readlines()

    new_code = []

    for line in lines:
        # if the line is empty, skip
        if not line:
            new_code.append(line)
            continue

        # modify the checklist with the newly appended technique here
        if "// ADD NEW TECHNIQUE CHECKER HERE" in line:
            new_code.append(
                "\tchecker(VM::" + 
                options.enum_name + 
                ", \"" + 
                options.short_description +
                "\");\n"
            )

        if "// ADD LINUX FLAG" in line:
            if options.is_linux:
                new_code.append("\t\t\tcase VM::" + options.enum_name + ":\n")

        if "// ADD WINDOWS FLAG" in line:
            if options.is_win:
                new_code.append("\t\t\tcase VM::" + options.enum_name + ":\n")

        if "// ADD MACOS FLAG" in line:
            if options.is_mac:
                new_code.append("\t\t\tcase VM::" + options.enum_name + ":\n")

        # add the line in the buffer array
        new_code.append(line)


    # commit the new changes from the buffer array
    with open("../src/cli.cpp", "w") as file:
        for line in new_code:
            file.write(line)




def write_docs(options):
    with open('../docs/documentation.md', 'r') as file:
        lines = file.readlines()

    new_docs = []

    for line in lines:
        # if the line is empty, skip
        if not line:
            new_code.append(line)
            continue

        if "<!-- ADD DETAILS HERE -->" in line:
            query_list = []

            query_list.append("`VM::" + options.enum_name + "`")
            query_list.append(options.description)
            
            if options.cross_platform:
                query_list.append("")
            else:
                category_list = []
                if options.is_linux:
                    category_list.append("Linux")
                if options.is_win:
                    category_list.append("Windows")
                if options.is_mac:
                    category_list.append("MacOS")
                category_str = " and ".join(category_list)
                query_list.append(category_str)
            
            query_list.append(str(options.score) + "%")

            if options.is_admin:
                query_list.append("Admin")
            else:
                query_list.append("")

            if options.is_gpl:
                query_list.append("GPL")
            else:
                query_list.append("")

            if options.only_32_bit:
                query_list.append("32-bit")
            else:
                query_list.append("")

            if options.notes:
                query_list.append(options.notes)
            else:
                query_list.append("")

            query = "| " + " | ".join(query_list) + " |"

            new_docs.append(query)

        
        # add the line in the buffer array
        new_docs.append(line)


    # commit the new changes from the buffer array
    with open("../docs/documentation.md", "w") as file:
        for line in new_docs:
            file.write(line)




if __name__ == "__main__":
    options_object = prompt()

    write_header(options_object)
    write_cli(options_object)
    write_docs(options_object)