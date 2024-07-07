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
 *  - Made by: @kernelwernel (https://github.com/kernelwernel)
 *  - Repository: https://github.com/kernelwernel/VMAware
 *  - License: GPL 3.0
 */ 

#include "vmaware.hpp"

#include <string>
#include <iostream>
#include <vector>
#include <cstdint>

#if (defined(__GNUC__) || defined(__linux__))
    #include <unistd.h>
#endif

#if (MSVC)
    #include <windows.h>
#endif

constexpr const char* ver = "1.5";
constexpr const char* date = "June 2024";

constexpr const char* bold = "\033[1m";
constexpr const char* ansi_exit = "\x1B[0m";
constexpr const char* red = "\x1B[38;2;239;75;75m";
constexpr const char* orange = "\x1B[38;2;255;180;5m";
constexpr const char* green = "\x1B[38;2;94;214;114m";
constexpr const char* red_orange = "\x1B[38;2;247;127;40m";
constexpr const char* green_orange = "\x1B[38;2;174;197;59m";

#if (MSVC)
class win_ansi_enabler_t
{
public:
  win_ansi_enabler_t()
  {
    m_set = FALSE;
    m_out = GetStdHandle(STD_OUTPUT_HANDLE);
    m_old = 0;
    if(m_out != NULL && m_out != INVALID_HANDLE_VALUE)
    {
      if(GetConsoleMode(m_out, &m_old) != FALSE)
      {
        m_set = SetConsoleMode(m_out, m_old | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
      }
    }
  }
  ~win_ansi_enabler_t()
  {
    if(m_set != FALSE)
    {
      SetConsoleMode(m_out, m_old);
    }
  }
private:
  win_ansi_enabler_t(win_ansi_enabler_t const&);
private:
  BOOL m_set;
  DWORD m_old;
  HANDLE m_out;
};
#endif

// for the technique counts
std::uint8_t detected_count = 0;


void help(void) {
    std::cout << 
R"(Usage: 
 vmaware [option] [extra]

Options:
 -h | --help        prints this help menu
 -v | --version     print cli version and other details
 -d | --detect      returns the result as a boolean (1 = VM, 0 = baremetal)
 -s | --stdout      returns either 0 or 1 to STDOUT without any text output (0 = VM, 1 = baremetal)
 -b | --brand       returns the VM brand string (consult documentation for full output list)
 -p | --percent     returns the VM percentage between 0 and 100
 -c | --conclusion  returns the conclusion message string
 -l | --brand-list  returns all the possible VM brand string values
 -n | --number      returns the number of VM detection techniques it performs

Extra:
 --disable-hyperv-host  disable the possibility of Hyper-V default virtualisation result on host OS
)";
}

void version(void) {
    std::cout << "vmaware " << "v" << ver << " (" << date << ")\n\n" <<
    "Derived project of VMAware library at https://github.com/kernelwernel/VMAware"
    "License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.\n" << 
    "This is free software: you are free to change and redistribute it.\n" <<
    "There is NO WARRANTY, to the extent permitted by law.\n" <<
    "Developed and maintained by kernelwernel, see https://github.com/kernelwernel\n";
}

const char* color(const std::uint8_t score) {
    if      (score == 0)   { return red; }
    else if (score <= 12)  { return red; }
    else if (score <= 25)  { return red_orange; }
    else if (score < 50)   { return red_orange; }
    else if (score <= 62)  { return orange; }
    else if (score <= 75)  { return green_orange; }
    else if (score < 100)  { return green; }
    else if (score == 100) { return green; }

    return "";
}

std::string message(const std::uint8_t score, const std::string &brand) {
    constexpr const char* baremetal = "Running in baremetal";
    constexpr const char* very_unlikely = "Very unlikely a VM";
    constexpr const char* unlikely = "Unlikely a VM";

    std::string potentially = "Potentially a VM";
    std::string might = "Might be a VM";
    std::string likely = "Likely a VM";
    std::string very_likely = "Very likely a VM";
    std::string inside_vm = "Running inside a VM";

    if (brand != "Unknown") {
        potentially = "Potentially a " + brand + " VM";
        might = "Might be a " + brand + " VM";
        likely = "Likely a " + brand + " VM";
        very_likely = "Very likely a " + brand + " VM";
        inside_vm = "Running inside a " + brand + " VM";
    }
    
    if      (score == 0)   { return baremetal; } 
    else if (score <= 12)  { return very_unlikely; } 
    else if (score <= 25)  { return unlikely; } 
    else if (score < 50)   { return potentially; } 
    else if (score <= 62)  { return might; } 
    else if (score <= 75)  { return likely; } 
    else if (score < 100)  { return very_likely; } 
    else if (score == 100) { return inside_vm; }

    return "Unknown error";
}


void general(const bool enable_hyperv = true) {
    const std::string detected = ("[  " + std::string(green) + "DETECTED" + std::string(ansi_exit) + "  ]");
    const std::string not_detected = ("[" + std::string(red) + "NOT DETECTED" + std::string(ansi_exit) + "]");
    const std::string note = ("[    NOTE    ]");

    auto checker = [&](const std::uint8_t flag, const char* message) -> void {
        if (VM::check(flag)) {
            std::cout << detected << " Checking " << message << "...\n";
            detected_count++;
        } else {
            std::cout << not_detected << " Checking " << message << "...\n";
        }
    };

    #if (defined(__GNUC__) || defined(__linux__))
        const uid_t uid  = getuid();
        const uid_t euid = geteuid();

        const bool is_root = (
            (uid != euid) || 
            (euid == 0)
        );

        if (!is_root) {
            std::cout << note << " Running under root might give better results\n";
        }
    #endif

    checker(VM::VMID, "VMID");
    checker(VM::CPU_BRAND, "CPU brand");
    checker(VM::HYPERVISOR_BIT, "CPUID hypervisor bit");
    checker(VM::CPUID_0X4, "CPUID 0x4 leaf");
    checker(VM::HYPERVISOR_STR, "hypervisor brand");
    checker(VM::RDTSC, "RDTSC");
    checker(VM::SIDT5, "sidt null byte");
    checker(VM::THREADCOUNT, "processor count");
    checker(VM::MAC, "MAC address");
    checker(VM::TEMPERATURE, "temperature");
    checker(VM::SYSTEMD, "systemd virtualisation");
    checker(VM::CVENDOR, "chassis vendor");
    checker(VM::CTYPE, "chassis type");
    checker(VM::DOCKERENV, "Dockerenv");
    checker(VM::DMIDECODE, "dmidecode output");
    checker(VM::DMESG, "dmesg output");
    checker(VM::HWMON, "hwmon presence");
    checker(VM::CURSOR, "cursor");
    checker(VM::VMWARE_REG, "VMware registry");
    checker(VM::VBOX_REG, "VBox registry");
    checker(VM::USER, "users");
    checker(VM::DLL, "DLLs");
    checker(VM::REGISTRY, "registry");
    checker(VM::CWSANDBOX_VM, "Sunbelt CWSandbox directory");
    checker(VM::WINE_CHECK, "Wine");
    checker(VM::VM_FILES, "VM files");
    checker(VM::HWMODEL, "hw.model");
    checker(VM::DISK_SIZE, "disk size");
    checker(VM::VBOX_DEFAULT, "VBox default specs");
    checker(VM::VBOX_NETWORK, "VBox network provider match");
    checker(VM::COMPUTER_NAME, "computer name");
    checker(VM::HOSTNAME, "hostname");
    checker(VM::MEMORY, "low memory space");
    checker(VM::VM_PROCESSES, "VM processes");
    checker(VM::LINUX_USER_HOST, "default Linux user/host");
    checker(VM::VBOX_WINDOW_CLASS, "VBox window class");
    checker(VM::GAMARUE, "gamarue ransomware technique");
    checker(VM::VMID_0X4, "0x4 leaf of VMID");
    checker(VM::PARALLELS_VM, "Parallels techniques");
    checker(VM::RDTSC_VMEXIT, "RDTSC VMEXIT");
    checker(VM::LOADED_DLLS, "loaded DLLs");
    checker(VM::QEMU_BRAND, "QEMU CPU brand");
    checker(VM::BOCHS_CPU, "BOCHS CPU techniques");
    checker(VM::VPC_BOARD, "VirtualPC motherboard");
    checker(VM::BIOS_SERIAL, "BIOS serial number");
    checker(VM::HYPERV_REG, "Hyper-V registry");
    checker(VM::HYPERV_WMI, "Hyper-V WMI output");
    checker(VM::VBOX_FOLDERS, "VirtualBox shared folders");
    checker(VM::MSSMBIOS, "MSSMBIOS");
    checker(VM::MAC_MEMSIZE, "MacOS hw.memsize");
    checker(VM::MAC_IOKIT, "MacOS registry IO-kit");
    checker(VM::IOREG_GREP, "IO registry grep");
    checker(VM::MAC_SIP, "MacOS SIP");
    checker(VM::KVM_REG, "KVM registries");
    checker(VM::KVM_DRIVERS, "KVM drivers");
    checker(VM::KVM_DIRS, "KVM directories");
    checker(VM::HKLM_REGISTRIES, "HKLM registries");
    checker(VM::AUDIO, "Audio device");
    checker(VM::QEMU_GA, "qemu-ga process");
    checker(VM::VALID_MSR, "MSR validity");
    checker(VM::QEMU_PROC, "QEMU processes");
    checker(VM::QEMU_DIR, "QEMU directories");
    checker(VM::VPC_PROC, "VPC processes");
    checker(VM::VPC_INVALID, "VPC invalid instructions");
    checker(VM::SIDT, "SIDT");
    checker(VM::SGDT, "SGDT");
    checker(VM::SLDT, "SLDT");
    checker(VM::OFFSEC_SIDT, "Offensive Security SIDT");
    checker(VM::OFFSEC_SGDT, "Offensive Security SGDT");
    checker(VM::OFFSEC_SLDT, "Offensive Security SLDT");
    checker(VM::VPC_SIDT, "VirtualPC SIDT");
    checker(VM::HYPERV_BOARD, "Hyper-V motherboard");
    checker(VM::VM_FILES_EXTRA, "Extra VM files");
    checker(VM::VMWARE_IOMEM, "/proc/iomem file");
    checker(VM::VMWARE_IOPORTS, "/proc/ioports file");
    checker(VM::VMWARE_SCSI, "/proc/scsi/scsi file");
    checker(VM::VMWARE_DMESG, "VMware dmesg");
    checker(VM::VMWARE_STR, "STR instruction");
    checker(VM::VMWARE_BACKDOOR, "VMware IO port backdoor");
    checker(VM::VMWARE_PORT_MEM, "VMware port memory");
    checker(VM::SMSW, "SMSW instruction");
    checker(VM::MUTEX, "mutex strings");
    checker(VM::UPTIME, "uptime");
    checker(VM::ODD_CPU_THREADS, "unusual thread count");
    checker(VM::INTEL_THREAD_MISMATCH, "Intel thread count mismatch");
    checker(VM::XEON_THREAD_MISMATCH, "Intel Xeon thread count mismatch");
    checker(VM::NETTITUDE_VM_MEMORY, "VM memory regions");
    checker(VM::VMWARE_DEVICES, "VMware devices");
    checker(VM::HYPERV_CPUID, "Hyper-V CPUID");
    checker(VM::CUCKOO_DIR, "Cuckoo directory");
    checker(VM::CUCKOO_PIPE, "Cuckoo pipe");
    checker(VM::HYPERV_HOSTNAME, "Hyper-V Azure hostname");
    checker(VM::GENERAL_HOSTNAME, "general VM hostnames");
    checker(VM::SCREEN_RESOLUTION, "screen resolution");
    checker(VM::DEVICE_STRING, "bogus device string");
    checker(VM::MOUSE_DEVICE, "mouse device");
    checker(VM::BLUESTACKS_FOLDERS, "BlueStacks folders");


    std::printf("\n");

#ifdef __VMAWARE_DEBUG__
    std::cout << "[DEBUG] theoretical maximum points: " << VM::total_points << "\n";
#endif

    std::string brand = VM::brand(VM::MULTIPLE);

    std::cout << "VM brand: " << (brand == "Unknown" ? red : green) << brand << ansi_exit << "\n";

    const char* percent_color = "";
    const std::uint8_t percent = (enable_hyperv ? VM::percentage(VM::ENABLE_HYPERV_HOST) : VM::percentage());

    if      (percent == 0) { percent_color = red; }
    else if (percent < 25) { percent_color = red_orange; }
    else if (percent < 50) { percent_color = orange; }
    else if (percent < 75) { percent_color = green_orange; }
    else                   { percent_color = green; }

    std::cout << "VM likeliness: " << percent_color << static_cast<std::uint32_t>(percent) << "%" << ansi_exit << "\n";

    const bool is_detected = (enable_hyperv ? VM::detect(VM::ENABLE_HYPERV_HOST) : VM::detect());

    std::cout << "VM confirmation: " << (is_detected ? green : red) << std::boolalpha << is_detected << std::noboolalpha << ansi_exit << "\n";


    const char* count_color = "";

    switch (detected_count) {
        case 0: count_color = red; break;
        case 1: count_color = red_orange; break;
        case 2: count_color = orange; break;
        case 3: count_color = orange; break;
        case 4: count_color = green_orange; break;
        default:
            // anything over 4 is green
            count_color = green;
    }

    std::cout << 
        "VM detections: " << 
        count_color << 
        static_cast<std::uint32_t>(detected_count) << 
        "/" <<
        static_cast<std::uint32_t>(VM::technique_count) << 
        ansi_exit <<
        "\n\n";


    brand = VM::brand(); // no VM::MULTIPLE this time
    
    if (
        enable_hyperv == true &&
        (
            brand == "Microsoft Hyper-V" ||
            brand == "Virtual PC" ||
            brand == "Microsoft Virtual PC/Hyper-V"
        )
    ) {
        std::cout << note << " If you know you are running on host, Hyper-V virtualises all applications by default within the host system. This result is in fact correct and NOT a false positive. If you do not want Hyper-V's default virtualisation enabled, run with the \"--discard-hyperv-host\" argument. See here https://github.com/kernelwernel/VMAware/issues/75\n";
    }

    const char* conclusion_color   = color(percent);
    std::string conclusion_message = message(percent, brand);

    std::cout 
        << bold 
        << "====== CONCLUSION: "
        << ansi_exit
        << conclusion_color << conclusion_message << " " << ansi_exit
        << bold
        << "======"
        << ansi_exit
        << "\n\n";
}


int main(int argc, char* argv[]) {
#if (MSVC)
    win_ansi_enabler_t ansi_enabler;
#endif

    const std::vector<const char*> args(argv, argv + argc); // easier this way
    const std::uint32_t arg_count = argc - 1;

    if (arg_count == 0) {
        general();
    } else if (arg_count == 1) {
        const char* argument = args.at(1);

        auto arg = [&argument](const char* option) -> bool {
            return (std::strcmp(argument, option) == 0);
        };

        if (arg("-s") || arg("--stdout")) {
            return (!VM::detect(VM::NO_MEMO, VM::ENABLE_HYPERV_HOST));
        } else if (arg("-h") || arg("--help")) {
            help();
            return 0;
        } else if (arg("-v") || arg("--version")) {
            version();
            return 0;
        } else if (arg("-b") || arg("--brand")) {
            std::cout << VM::brand(VM::NO_MEMO, VM::MULTIPLE) << "\n";
            return 0;
        } else if (arg("-p") || arg("--percent")) {
            std::cout << static_cast<std::uint32_t>(VM::percentage(VM::NO_MEMO, VM::ENABLE_HYPERV_HOST)) << "\n";
            return 0;
        } else if (arg("-d") || arg("--detect")) {
            std::cout << VM::detect(VM::NO_MEMO) << "\n";
            return 0;
        } else if (arg("-n") || arg("--number")) {
            std::cout << static_cast<std::uint32_t>(VM::technique_count) << "\n";
            return 0;
        } else if (arg("-c") || arg("--conclusion")) {
            const std::uint8_t percent = VM::percentage(VM::ENABLE_HYPERV_HOST);
            const std::string brand = VM::brand(VM::MULTIPLE);
            std::cout << message(percent, brand) << "\n";
            return 0;
        } else if (arg("-l") || arg("--brand-list")) {
            std::cout << 
R"(VirtualBox
VMware
VMware Express
VMware ESX
VMware GSX
VMware Workstation
bhyve
QEMU
KVM
KVM Hyper-V Enlightenment
QEMU+KVM
Virtual PC
Microsoft Hyper-V
Microsoft Virtual PC/Hyper-V
Microsoft x86-to-ARM
Parallels
Xen HVM
ACRN
QNX hypervisor
Hybrid Analysis
Sandboxie
Docker
Wine
Virtual Apple
Anubis
JoeBox
Thread Expert
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
)";
            return 0;
        } else if (arg("--disable-hyperv-host")) {
            general(false);
            return 0;
        } else {
            std::cerr << "Unknown argument provided, consult the help menu with --help\n";
            return 1;
        }
    } else if (arg_count == 2) {
        constexpr const char* hyperv_arg = "--disable-hyperv-host";

        auto find = [&args](const char* option) -> bool {
            for (const auto arg : args) {
                if (std::strcmp(arg, option) == 0) {
                    return true;
                }
            }

            return false;
        };

        // check if the hyperv_arg option exists
        if (!find(hyperv_arg)) {
            std::cerr << hyperv_arg << " must be used with an option combination, consult the help menu with --help\n";
            return 1;
        }

        const bool p_detect     = (find("-d") || find("--detect"));
        const bool p_stdout     = (find("-s") || find("--stdout"));
        const bool p_percent    = (find("-p") || find("--percent"));
        const bool p_conclusion = (find("-c") || find("--conclusion"));

        // check if combination of the option and hyperv exists
        if (!(p_detect || p_stdout || p_percent || p_conclusion)) {
            std::cerr << "Unknown or unsupported option with" << hyperv_arg << ", only --detect, --stdout, --percent, and --conclusion are supported\n";
            return 1;
        }

        // run that option but with hyperv modification
        if (p_detect) {
            std::cout << VM::detect() << "\n";
            return 0;
        } else if (p_stdout) {
            return (!VM::detect());
        } else if (p_percent) {
            std::cout << static_cast<std::uint32_t>(VM::percentage()) << "\n";
            return 0;
        } else if (p_conclusion) {
            const std::uint8_t percent = VM::percentage();
            const std::string brand = VM::brand();
            std::cout << message(percent, brand) << "\n";
        }
    } else if (arg_count > 2) {
        std::cerr << "Only 1, 2, or no arguments are expected, not " << arg_count << ". consult the help menu with --help\n";
        return 1;
    } else {
        std::cerr << "Encountered unknown error, aborting\n";
        return 1;
    }
    
    return 0;
}
