
#
# - add a warning if #include is found



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
#  the lib with mamy aspects of the lib updated based on user input.
#  
#  the updated components are:
#   - VM::type()
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
    def __init__(self, enum_name, file_path, function_name, cross_platform, is_linux, is_win, is_mac, score, description, author, is_admin, is_gpl, only_32_bit, is_x86_only, notes):
        self.enum_name = enum_name
        self.file_path = file_path
        self.function_name = function_name
        self.cross_platform = cross_platform
        self.is_linux = is_linux
        self.is_win = is_win
        self.is_mac = is_mac
        self.score = score
        self.description = description
        self.author = author
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


    # 7: author
    author = questionary.text("Who is the author? (optional, can be left empty)").ask()


    # 8: permissions
    is_admin = questionary.confirm("Does it require admin permissions?").ask()


    # 9: GPL
    is_gpl = questionary.confirm("Is it GPL?").ask()


    # 10: 32-bit
    only_32_bit = questionary.confirm("Is it 32-bit only? (no support for 64-bit systems)").ask()


    # 11: x86
    is_x86 = questionary.confirm("Is it x86 only? (no support for ARM for example)").ask()


    # 12: notes
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
        description,
        author,
        is_admin,
        is_gpl,
        only_32_bit,
        is_x86,
        notes
    )


def write(p_options):
    # Open the file in read mode
    with open('../src/vmaware.hpp', 'r') as file:
        # Read all lines into a list
        lines = file.readlines()
        


if __name__ == "__main__":
    options_object = prompt()
    write(options_object)
