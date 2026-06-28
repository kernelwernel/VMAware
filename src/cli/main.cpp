/**
 * ██╗   ██╗███╗   ███╗ █████╗ ██╗    ██╗ █████╗ ██████╗ ███████╗
 * ██║   ██║████╗ ████║██╔══██╗██║    ██║██╔══██╗██╔══██╗██╔════╝
 * ██║   ██║██╔████╔██║███████║██║ █╗ ██║███████║██████╔╝█████╗
 * ╚██╗ ██╔╝██║╚██╔╝██║██╔══██║██║███╗██║██╔══██║██╔══██╗██╔══╝
 *  ╚████╔╝ ██║ ╚═╝ ██║██║  ██║╚███╔███╔╝██║  ██║██║  ██║███████╗
 *   ╚═══╝  ╚═╝     ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
 *
 *  C++ VM detection library
 *
 * ===============================================================
 *
 *  This is the main CLI code, which demonstrates the majority
 *  of the library's capabilities while also providing as a
 *  practical and general VM detection tool for everybody to use
 *
 * ===============================================================
 *
 *  - Developed by: Requiem (https://github.com/NotRequiem)
 *  - Co-developed by: kernelwernel (https://github.com/kernelwernel)
 *  - Repository: https://github.com/NotRequiem/VMAware
 *  - License: MIT
 */

#include <vector>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <cstring>
#include <string>

#include "types.hpp"
#include "globals.hpp"
#include "output.hpp"
#include "wagner_fischer.hpp"

#if (CLI_WINDOWS)
#include "windows_tui.hpp"
#include <windows.h>
#include <shellapi.h>
#endif

constexpr const char* ver = "2.7.0";
constexpr const char* date = "April 2026";

[[noreturn]] static void help() {
    std::cout <<
R"(Usage:
 vmaware [option] [extra]
 (do not run with any options if you want the full summary)

Options:
 -h | --help        prints this help menu
 -v | --version     print CLI version and other details
 -a | --all         run the result with ALL the techniques shown and enabled
 -d | --detect      returns the result as a boolean (1 = VM, 0 = baremetal)
 -s | --stdout      returns either 0 or 1 to STDOUT without any text output (0 = VM, 1 = baremetal)
 -b | --brand       returns the VM brand string
 -l | --brand-list  returns all the possible VM brand string values
 -p | --percent     returns the VM percentage between 0 and 100
 -c | --conclusion  returns the conclusion message string
 -n | --number      returns the number of VM detection techniques it performs
 -t | --type        returns the VM type (if a VM was found)
 -o | --output      set the output path

Extra:
 --disable-notes    no notes will be provided
 --high-threshold   a higher threshold bar for a VM detection will be applied (2x higher)
 --no-ansi          removes color and ansi escape codes from the output
 --dynamic          allow the conclusion message to be dynamic (8 possibilities instead of only 2)
 --experimental     disable experimental techniques
 --verbose          add more information to the output
 --enums            display the technique enum name used by the lib
 --detected-only    only display the techniques that were detected
 --json             output a json-formatted file of the results
 --rich             output the rich TUI alternative of the output (Windows specific)

)";

    std::exit(0);
}

[[noreturn]] static void version() {
    std::cout << "vmaware " << "v" << ver << " (" << date << ")\n\n" <<
        "Derived project of VMAware library at https://github.com/NotRequiem/VMAware\n"
        "License MIT:<https://opensource.org/license/mit>.\n" <<
        "This is free software: you are free to change and redistribute it.\n" <<
        "There is NO WARRANTY, to the extent permitted by law.\n" <<
        "Developed and maintained by kernelwernel and Requiem,\n" <<
        "see https://github.com/kernelwernel and https://github.com/NotRequiem\n" <<
        "For any inquiries, contact us on Discord at shenzken or kr.nl, or email us at vmaware.support@gmail.com\n";
    std::exit(0);
}

[[noreturn]] static void brand_list() {
    std::cout <<
R"(VirtualBox
VMware
VMware Express
VMware ESX
VMware GSX
VMware Workstation
VMware Fusion
bhyve
QEMU
KVM
KVM Hyper-V Enlightenment
QEMU+KVM Hyper-V Enlightenment
QEMU+KVM
Virtual PC
Microsoft Hyper-V
Microsoft Virtual PC/Hyper-V
Parallels
Xen HVM
ACRN
QNX hypervisor
Hybrid Analysis
Sandboxie
Docker
Wine
Anubis
JoeBox
ThreatExpert
CWSandbox
Comodo
Bochs
Lockheed Martin LMHS
NVMM
OpenBSD VMM
Intel HAXM
Unisys s-Par
Cuckoo
BlueStacks
Jailhouse
Apple VZ
Intel KGT (Trusty)
Microsoft Azure Hyper-V
Xbox NanoVisor (Hyper-V)
SimpleVisor
Hyper-V artifact (host with Hyper-V enabled)
User-mode Linux
IBM PowerVM
Google Compute Engine (KVM)
OpenStack (KVM)
KubeVirt (KVM)
AWS Nitro System (KVM-based)
Podman
WSL
OpenVZ
ANY.RUN
Barevisor
HyperPlatform
MiniVisor
Intel TDX
LKVM
AMD SEV
AMD SEV-ES
AMD SEV-SNP
Neko Project II
NoirVisor
Qihoo 360 Sandbox
DBVM
UTM
Compaq FX!32
Insignia RealPC
Connectix Virtual PC
Containerd
)";
    std::exit(0);
}

int main(int argc, char* argv[]) {
#if (CLI_WINDOWS)
    bool rich_requested = false;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--rich") == 0) {
            rich_requested = true;
            break;
        }
    }

    bool already_spawned = false;
    char env_buf[16];
    if (GetEnvironmentVariableA("VMAWARE_SPAWNED", env_buf, sizeof(env_buf)) > 0) {
        if (std::strcmp(env_buf, "1") == 0) {
            already_spawned = true;
        }
    }

    if (rich_requested && !already_spawned) {
        SetEnvironmentVariableA("VMAWARE_SPAWNED", "1");

        char exePath[MAX_PATH];
        GetModuleFileNameA(NULL, exePath, MAX_PATH);

        char currentDir[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, currentDir);

        std::string args = "\"" + std::string(exePath) + "\"";
        for (int i = 1; i < argc; ++i) {
            args += " \"";
            args += argv[i];
            args += "\"";
        }

        SHELLEXECUTEINFOA sei = { sizeof(sei) };
        sei.fMask = 0;
        sei.hwnd = NULL;
        sei.lpVerb = "open";
        sei.lpFile = "conhost.exe";
        sei.lpParameters = args.c_str();
        sei.lpDirectory = currentDir;
        sei.nShow = SW_SHOWNORMAL;

        if (!IsDebuggerPresent() && ShellExecuteExA(&sei)) {
            ExitProcess(0);
        }
    }

    win_ansi_enabler_t ansi_enabler;
    AddVectoredExceptionHandler(1, VehLogger);
#endif

    const std::vector<std::string> args(argv + 1, argv + argc);
    const u32 argument_count = static_cast<u32>(argc - 1);

    if (argument_count == 0) {
        general(false, false, false);
        return 0;
    }

    static const arg_table table{ {
        { "-h", HELP },
        { "-v", VERSION },
        { "-a", ALL },
        { "-d", DETECT },
        { "-s", STDOUT },
        { "-b", BRAND },
        { "-p", PERCENT },
        { "-c", CONCLUSION },
        { "-l", BRAND_LIST },
        { "-n", NUMBER },
        { "-t", TYPE },
        { "-o", OUTPUT },
        { "help", HELP },
        { "--help", HELP },
        { "--version", VERSION },
        { "--all", ALL },
        { "--detect", DETECT },
        { "--stdout", STDOUT },
        { "--brand", BRAND },
        { "--percent", PERCENT },
        { "--conclusion", CONCLUSION },
        { "--brand-list", BRAND_LIST },
        { "--number", NUMBER },
        { "--type", TYPE },
        { "--disable-notes", NOTES },
        { "--high-threshold", HIGH_THRESHOLD },
        { "--dynamic", DYNAMIC },
        { "--experimental", EXPERIMENTAL },
        { "--verbose", VERBOSE },
        { "--enums", ENUMS },
        { "--no-ansi", NO_ANSI },
        { "--detected-only", DETECTED_ONLY },
        { "--json", JSON },
        { "--output", OUTPUT },
        { "--rich", RICH }
    } };

    std::string potential_null_arg;
    const char* potential_output_arg = "results.json";
    const char* general_output_arg = nullptr;
    bool collecting_disable = false;

    for (i32 i = 1; i < argc; ++i) {
        const char* arg_string = argv[i];

        if (collecting_disable && arg_string[0] == '-') {
            collecting_disable = false;
        }

        if (collecting_disable) {
            if (!parse_disable_token(arg_string)) {
                return 1;
            }
            continue;
        }

        if (std::strcmp(arg_string, "--disable") == 0) {
            collecting_disable = true;
            continue;
        }

        auto it = std::find_if(table.cbegin(), table.cend(), [&](const std::pair<const char*, i32>& p) {
            return (std::strcmp(p.first, arg_string) == 0);
        });

        if (it == table.end()) {
            if (arg_bitset.test(OUTPUT)) {
                const std::ofstream file(arg_string);

                if (file.good()) {
                    potential_output_arg = arg_string;
                    general_output_arg = arg_string;
                }

                arg_bitset.set(OUTPUT, false);
            } else {
                arg_bitset.set(NULL_ARG);
                potential_null_arg = arg_string;
            }
        } else {
            arg_bitset.set(it->second);
        }
    }

    if (arg_bitset.test(NULL_ARG)) {
        std::cerr << "Unknown argument \"" << potential_null_arg << "\", aborting\n";
        manage_output(suggest(potential_null_arg, table));
        return 1;
    }

    if (arg_bitset.test(HELP)) {
        help();
    }

    if (arg_bitset.test(VERSION)) {
        version();
    }

    if (arg_bitset.test(BRAND_LIST)) {
        brand_list();
    }

    if (arg_bitset.test(NUMBER)) {
        std::cout << get_technique_count() << "\n";
        return 0;
    }

    if (arg_bitset.test(JSON)) {
        generate_json(potential_output_arg);
        return 0;
    }

    const u32 returners = (
        static_cast<u32>(arg_bitset.test(STDOUT)) + static_cast<u32>(arg_bitset.test(PERCENT)) + static_cast<u32>(arg_bitset.test(DETECT)) +
        static_cast<u32>(arg_bitset.test(BRAND)) + static_cast<u32>(arg_bitset.test(TYPE)) + static_cast<u32>(arg_bitset.test(CONCLUSION))
    );

    const bool high_threshold = arg_bitset.test(HIGH_THRESHOLD);
    const bool all = arg_bitset.test(ALL);
    const bool dynamic = arg_bitset.test(DYNAMIC);

    if (returners > 0) {
        if (returners > 1) {
            std::cerr << "--stdout, --percent, --detect, --brand, --type, and --conclusion must NOT be a combination, choose only a single one\n";
            return 1;
        }

        if (arg_bitset.test(STDOUT)) {
            return run_stdout(high_threshold, all, dynamic);
        }

        if (arg_bitset.test(PERCENT)) {
            std::cout << run_percent(high_threshold, all, dynamic) << "\n";
            return 0;
        }

        if (arg_bitset.test(DETECT)) {
            std::cout << run_detect(high_threshold, all, dynamic) << "\n";
            return 0;
        }

        if (arg_bitset.test(BRAND)) {
            std::cout << run_brand(high_threshold, all, dynamic) << "\n";
            return 0;
        }

        if (arg_bitset.test(TYPE)) {
            std::cout << run_type(high_threshold, all, dynamic) << "\n";
            return 0;
        }

        if (arg_bitset.test(CONCLUSION)) {
            std::cout << run_conclusion(high_threshold, all, dynamic) << "\n";
            return 0;
        }
    }

    general(high_threshold, all, dynamic, general_output_arg);
    return 0;
}