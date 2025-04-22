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
#   - CLI checklist
#   - technique enums
#   - flag_to_string()
#   - <os>_technique lambda functionality in CLI
#   - adding the technique itself in vmaware.hpp
# 
# ===============================================================
# 
#  - Made by: @kernelwernel (https://github.com/kernelwernel)
#  - Repository: https://github.com/kernelwernel/VMAware
#  - License: GPL 3.0

import questionary
import sys


is_dev_mode = False

if len(sys.argv) != 1:
    if sys.argv[1] == "--dev":
        is_dev_mode = True


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


# there's like some really weird shit going on with \t, so i'm doing it manually
tab = "    "


def prompt():
    # 1: enum name
    enum_answer = ""
    if is_dev_mode:
        enum_answer = "TEST"
    else:
        enum_answer = questionary.text("What's the name of the enum? (i.e. VBOX_REG or HYPERVISOR_STR)").ask()
        enum_answer = enum_answer.upper()


    # 2: technique file
    file_path = ""
    if is_dev_mode:
        file_path = "../archive/techniques/test.cpp"
    else:
        while True:
            file_path = questionary.path("What's the path to the technique file?").ask()
            if not file_path.endswith(".cpp") and not file_path.endswith(".cc"):
                print("file input MUST be a .cpp file")
                continue

            with open(file_path, 'r') as file:
                is_static = False
                for line in file:
                    if "#include" in line.lower():
                        print("The cpp file will be directly copied to the lib verbatim, so do not add #include as this will mess up include orders.")
                        continue

                    if "static" in line:
                        is_static = True
                
                if not is_static:
                    print("The function must be set as static")
                    continue

                break


    # 3: function name
    function_name = ""
    if is_dev_mode:
        function_name = "test"
    else:
        function_name = questionary.text("What's the name of the function in your .cpp file? example: new_technique()").ask()
        function_name = function_name.lower()
        if "(" in function_name or ")" in function_name:
            function_name = function_name.replace("(", "").replace(")", "")


    # 4: is it cross-platform?
    cross_platform = False

    if is_dev_mode:
        cross_platform = False
        is_linux = True
        is_win = False
        is_mac = False
    else:
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
    if is_dev_mode:
        score = 50
    else:
        certainty = ""
        while True:
            certainty = questionary.text("What's the score of your technique? (0-100)").ask()
            if certainty == "":
                print("A score is mandatory, try again")
                continue
            
            if 0 <= int(certainty) <= 100:
                break
            else:
                print("Score must be between 0 and 100, try again")
                continue

        score = int(certainty)
        


    # 6: description
    description = ""
    if is_dev_mode:
        description = "testing, this is a boilerplate technique"
    else:
        while True:
            text = questionary.text("What's the description of your technique? (30-100 characters)").ask()
            if len(text) < 30:
                print("Too short, try again\n")
                continue
            if len(text) > 100:
                print("Too long, try again\n")
                continue
            description = text
            break

    # 7: short description
    short_description = ""
    if is_dev_mode:
        short_description = "testing, ignore"
    else:
        while True:
            text = questionary.text("What is your technique checking for? This will appear in the CLI, so be as minimal as you can (max 25 characters)").ask()
            if len(text) > 25:
                print("Too long, try again\n")
                continue
            if len(text) > len(description):
                print("The answer cannot be longer than the actual description from the previous question\n")
                continue
            short_description = text
            break


    # 8: author
    author = ""
    if is_dev_mode:
        author = ""
    else:
        author = questionary.text("Who is the author? (optional, can be left empty)").ask()


    # 9: link
    link = ""
    if is_dev_mode:
        link = ""
    else:
        link = questionary.text("If there's a source for the technique's origin, paste the link here (optional, can be left empty)").ask()


    # 10: permissions
    is_admin = False
    if is_dev_mode:
        is_admin = False
    else:
        is_admin = questionary.confirm("Does it require admin permissions?").ask()


    # 11: GPL
    is_gpl = False
    if is_dev_mode:
        is_gpl = True
    else:
        is_gpl = questionary.confirm("Is it GPL?").ask()


    # 12: 32-bit
    only_32_bit = False
    if is_dev_mode:
        only_32_bit = False
    else:
        only_32_bit = questionary.confirm("Is it 32-bit only? (no support for 64-bit systems)").ask()


    # 13: x86
    is_x86 = False
    if is_dev_mode:
        is_x86 = True
    else:
        is_x86 = questionary.confirm("Is it x86 only? (no support for ARM for example)").ask()


    # 14: notes
    notes = ""
    if is_dev_mode:
        notes = ""
    else:
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


def write_header(options, header_file):
    with open(header_file, 'r') as file:
        lines = file.readlines()

    new_code = []
    update_count = 0

    if options.is_gpl and header_file == "../src/vmaware_MIT.hpp":
        return

    for line in lines:
        # if the line is empty, skip
        if not line:
            new_code.append(line)
            continue


        # modify the enum
        if "// ADD NEW TECHNIQUE ENUM NAME HERE" in line:
            if options.is_gpl:
                new_code.append("/* GPL */ " + options.enum_name + ",\n")
            else:
                new_code.append(tab + tab + options.enum_name + ",\n")
            update_count += 1


        # append the technique function to the function list section
        if "// ADD NEW TECHNIQUE FUNCTION HERE" in line:
            full_technique = []
            new_code.append("\n")

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

            if options.notes != "":
                technique_details.append("@note " + options.notes)

            if options.is_gpl:
                technique_details.append("@copyright GPL-3.0")

            technique_details.append("@implements VM::" + options.enum_name)
            
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
                    full_technique[i] = "/* GPL */     " + full_technique[i]

            # commit the full technique in the buffer 
            preprocessors = ["#endif", "#elif", "#else", "#if"]
            if options.is_gpl:
                for technique_line in full_technique:
                    if all(sub in technique_line for sub in preprocessors):
                        new_code.append(technique_line.lstrip())
                    else:
                        new_code.append(technique_line)
            else:
                for technique_line in full_technique:
                    if all(sub in technique_line for sub in preprocessors):
                        new_code.append(technique_line.lstrip())
                    else:
                        new_code.append(tab + technique_line)


            # extra lines
            new_code.append("\n\n")
            update_count += 1


        # modify the technique table with the new technique appended
        if "// ADD NEW TECHNIQUE STRUCTURE HERE" in line:
            code_str = (
                "std::make_pair(VM::" + 
                options.enum_name + 
                ", VM::core::technique(" + 
                str(options.score) + 
                ", VM::" + 
                options.function_name +
                ")),\n"
            )

            if options.is_gpl:
                new_code.append("/* GPL */ " + code_str)
            else:
                new_code.append(tab + code_str)

            update_count += 1


        # modify the VM::flag_to_string function with the new technique
        if "// ADD NEW CASE HERE FOR NEW TECHNIQUE" in line:
            new_code.append(
                tab + tab + tab +
                "case " + 
                options.enum_name + 
                ": return \"" + 
                options.enum_name + 
                "\";\n"
            )
            update_count += 1

        # add the line in the buffer array
        new_code.append(line)

    if update_count != 4:
        raise ValueError("Not all sections have been update, try to check if the search key values have been modified")


    # commit the new changes from the buffer array
    with open(header_file, "w") as file:
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
                tab +
                "checker(VM::" + 
                options.enum_name + 
                ", \"" + 
                options.short_description +
                "\");\n"
            )

        if "// ADD LINUX FLAG" in line:
            if options.is_linux:
                new_code.append(tab + tab + tab + "case VM::" + options.enum_name + ":\n")

        if "// ADD WINDOWS FLAG" in line:
            if options.is_win:
                new_code.append(tab + tab + tab + "case VM::" + options.enum_name + ":\n")

        if "// ADD MACOS FLAG" in line:
            if options.is_mac:
                new_code.append(tab + tab + tab + "case VM::" + options.enum_name + ":\n")

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
    updated = False

    for line in lines:
        # if the line is empty, skip
        if not line:
            new_code.append(line)
            continue

        if "<!-- ADD TECHNIQUE DETAILS HERE -->" in line:
            query_list = []

            query_list.append("`VM::" + options.enum_name + "`")
            query_list.append(options.description)
            
            if options.cross_platform:
                query_list.append("🐧🪟🍏")
            else:
                category_list = []
                if options.is_linux:
                    category_list.append("🐧")
                if options.is_win:
                    category_list.append("🪟")
                if options.is_mac:
                    category_list.append("🍏")
                category_str = "".join(category_list)
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

            query = "| " + " | ".join(query_list) + " |  |" # last part is meant to be the link, todo

            new_docs.append(query + "\n")
            updated = True
        
        # add the line in the buffer array
        new_docs.append(line)

    if updated == False:
        raise ValueError("Docs has not found the keyword breakpoint")

    # commit the new changes from the buffer array
    with open("../docs/documentation.md", "w") as file:
        for line in new_docs:
            file.write(line)




if __name__ == "__main__":
    options_object = prompt()

    write_header(options_object, "../src/vmaware.hpp")
    write_header(options_object, "../src/vmaware_MIT.hpp")
    write_cli(options_object)
    write_docs(options_object)