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

#ifndef VMAWARE_DEBUG
    #if defined(_DEBUG)    /* MSVC Debug */       \
        || defined(DEBUG)     /* user or build-system */
        #define VMAWARE_DEBUG
    #endif
#endif

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
    #ifdef VMAWARE_DEBUG
        #ifndef _CRTDBG_MAP_ALLOC
            #define _CRTDBG_MAP_ALLOC
        #endif
        #include <crtdbg.h>
    #endif
#endif

constexpr const char* ver = "2.8.2";
constexpr const char* date = "September 2026";

[[noreturn]] static void help() {
    std::cout <<
        R"(Usage:
         vmaware [option] [extra]
         (do not run with any options if you want the full summary)

        Options:
         -h | --help        prints this help menu
         -v | --version     print CLI version and other details
         -a | --all         run the result with ALL the techniques shown and enabled
         -d | --detect      returns the result as a boolean (1 = VM, 0 = bare metal)
         -s | --stdout      returns either 0 or 1 to STDOUT without any text output (0 = VM, 1 = bare metal)
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
        "Developed and maintained by Requiem,\n" <<
        "For any inquiries, contact us on Discord at shenzken, or email us at vmaware.support@gmail.com\n";
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

#if (CLI_WINDOWS && defined VMAWARE_DEBUG && !CLI_ARM)
static inline void enable_crt_leak_check() noexcept
{
    std::cout << "[VMAware-Core] Running memory analysis... Performance may be decreased.\n";
    i32 flags = _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG);

    flags |= _CRTDBG_ALLOC_MEM_DF;       /* Keep debug memory allocations active */
    flags |= _CRTDBG_LEAK_CHECK_DF;      /* Perform automatic leak dump at exit */
    flags |= _CRTDBG_CHECK_ALWAYS_DF;    /* Validate heap integrity on every allocation/free */
    flags |= _CRTDBG_DELAY_FREE_MEM_DF;  /* Keep freed blocks in cache to catch use-after-free */

    _CrtSetDbgFlag(flags);

    /* Redirect WARN, ERROR, and ASSERT to both stderr and the debugger output window. This prevents blocking modal GUI popups in headless environments */
    const i32 report_modes = _CRTDBG_MODE_FILE | _CRTDBG_MODE_DEBUG;

    _CrtSetReportMode(_CRT_WARN, report_modes);
    _CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);

    _CrtSetReportMode(_CRT_ERROR, report_modes);
    _CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);

    _CrtSetReportMode(_CRT_ASSERT, report_modes);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);

    /* Support break-on-allocation via environment variable: VMAWARE_BREAK_ALLOC */
    char* break_alloc_env = nullptr;
    std::size_t break_alloc_len = 0;
    if (_dupenv_s(&break_alloc_env, &break_alloc_len, "VMAWARE_BREAK_ALLOC") == 0 && break_alloc_env != nullptr) {
        char* end_ptr = nullptr;
        long alloc_request_number = std::strtol(break_alloc_env, &end_ptr, 10);
        if (end_ptr != break_alloc_env && alloc_request_number > 0) {
            _CrtSetBreakAlloc(alloc_request_number);
        }
        std::free(break_alloc_env);
        break_alloc_env = nullptr;
    }
}

/* Captures starting heap state */
static inline void crt_checkpoint_start(_CrtMemState* state) noexcept
{
    if (state != nullptr) {
        _CrtMemCheckpoint(state);
    }
}

/* Compares state against start checkpoint and outputs leak diff */
static inline i32 crt_checkpoint_verify(const _CrtMemState * start_state) noexcept
{
    if (start_state == nullptr) {
        return 0;
    }

    _CrtMemState current_state;
    _CrtMemState diff_state;

    _CrtMemCheckpoint(&current_state);

    /* If memory differences exist between start and finish, dump statistics */
    if (_CrtMemDifference(&diff_state, start_state, &current_state) != 0) {
        std::cerr << "\n[VMAware] Memory leaks detected during execution.\n";
        _CrtMemDumpStatistics(&diff_state);
        _CrtMemDumpAllObjectsSince(start_state);
        return 1;
    }

    return 0;
}

#endif

int main(int argc, char* argv[]) {
    if (argv == nullptr || argc <= 0) {
        return 1;
    }

#if (CLI_WINDOWS && !CLI_ARM)
    #ifdef VMAWARE_DEBUG
    /*
        enable_crt_leak_check();
        _CrtMemState start_memory_checkpoint;
        crt_checkpoint_start(&start_memory_checkpoint);
    */
    #endif

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

        char exe_path[MAX_PATH];
        GetModuleFileNameA(NULL, exe_path, MAX_PATH);

        char current_directory[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, current_directory);

        std::string args = "\"" + std::string(exe_path) + "\"";
        for (int i = 1; i < argc; ++i) {
            args += " \"";
            args += argv[i];
            args += "\"";
        }

        SHELLEXECUTEINFOA sei{};
        sei.cbSize = sizeof(sei);
        sei.fMask = 0;
        sei.hwnd = NULL;
        sei.lpVerb = "open";
        sei.lpFile = "conhost.exe";
        sei.lpParameters = args.c_str();
        sei.lpDirectory = current_directory;
        sei.nShow = SW_SHOWNORMAL;

        if (!IsDebuggerPresent() && ShellExecuteExA(&sei)) {
            ExitProcess(ERROR_SUCCESS);
        }

        AddVectoredExceptionHandler(1, exception_handler_logger);
    }

    win_ansi_enabler_t ansi_enabler;
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

        auto it = std::find_if(table.cbegin(), table.cend(), [&](const std::pair<const char*, i32>& p) noexcept {
            return (std::strcmp(p.first, arg_string) == 0);
            });

        if (it == table.end()) {
            arg_bitset.set(NULL_ARG);
            potential_null_arg = arg_string;
        }
        else if (it->second == OUTPUT) {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                ++i;
                potential_output_arg = argv[i];
                general_output_arg = argv[i];
            }
            else {
                std::cerr << "Option \"" << arg_string << "\" requires a file path\n";
                return 1;
            }
        }
        else {
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

#if (defined(VMAWARE_WINDOWS) && !defined(VMAWARE_ARM) && defined(VMAWARE_DEBUG) && defined(VMAWARE_MSVC))
    /*
    i32 leak_status = crt_checkpoint_verify(&start_memory_checkpoint);
    if (leak_status != 0) {
        return 2;
    }
    */
#endif

    return 0;
}