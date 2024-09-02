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

#include <string>
#include <iostream>
#include <vector>
#include <cstdint>
#include <bit>

#if (defined(__GNUC__) || defined(__linux__))
    #include <unistd.h>
    #define LINUX 1
#else
    #define LINUX 0
#endif

#if (defined(_MSC_VER) || defined(_WIN32) || defined(_WIN64) || defined(__MINGW32__))
    #define MSVC 1
    #include <windows.h>
#else
    #define MSVC 0
#endif

#include "vmaware.hpp"

constexpr const char* ver = "1.8";
constexpr const char* date = "August 2024";

constexpr const char* bold = "\033[1m";
constexpr const char* ansi_exit = "\x1B[0m";
constexpr const char* red = "\x1B[38;2;239;75;75m"; 
constexpr const char* orange = "\x1B[38;2;255;180;5m";
constexpr const char* green = "\x1B[38;2;94;214;114m";
constexpr const char* red_orange = "\x1B[38;2;247;127;40m";
constexpr const char* green_orange = "\x1B[38;2;174;197;59m";
constexpr const char* grey = "\x1B[38;2;108;108;108m";

enum arg_enum : std::uint8_t {
    HELP,
    VERSION,
    ALL,
    DETECT,
    STDOUT,
    BRAND,
    BRAND_LIST,
    PERCENT,
    CONCLUSION,
    NUMBER,
    TYPE,
    NOTES,
    SPOOFABLE,
    NULL_ARG
};

std::bitset<14> arg_bitset;

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


[[noreturn]] void help(void) {
    std::cout << 
R"(Usage: 
 vmaware [option] [extra]
 (do not run with any options if you want the full summary)

Options:
 -h | --help        prints this help menu
 -v | --version     print cli version and other details
 -a | --all         run the result with ALL the techniques enabled (might contain false positives)
 -d | --detect      returns the result as a boolean (1 = VM, 0 = baremetal)
 -s | --stdout      returns either 0 or 1 to STDOUT without any text output (0 = VM, 1 = baremetal)
 -b | --brand       returns the VM brand string (consult documentation for full output list)
 -p | --percent     returns the VM percentage between 0 and 100
 -c | --conclusion  returns the conclusion message string
 -l | --brand-list  returns all the possible VM brand string values
 -n | --number      returns the number of VM detection techniques it performs
 -t | --type        returns the VM type (if a VM was found)

Extra:
 --disable-notes        no notes will be provided
 --spoofable            allow spoofable techniques to be ran (not included by default)

)";
    std::exit(0);
}

[[noreturn]] void version(void) {
    std::cout << "vmaware " << "v" << ver << " (" << date << ")\n\n" <<
    "Derived project of VMAware library at https://github.com/kernelwernel/VMAware"
    "License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.\n" << 
    "This is free software: you are free to change and redistribute it.\n" <<
    "There is NO WARRANTY, to the extent permitted by law.\n" <<
    "Developed and maintained by kernelwernel, see https://github.com/kernelwernel\n";

    std::exit(0);
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
    else if (score <= 20)  { return very_unlikely; } 
    else if (score <= 35)  { return unlikely; } 
    else if (score < 50)   { return potentially; } 
    else if (score <= 62)  { return might; } 
    else if (score <= 75)  { return likely; } 
    else if (score < 100)  { return very_likely; } 
    else if (score == 100) { return inside_vm; }

    return "Unknown error";
}

[[noreturn]] void brand_list() {
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
Microsoft x86-to-ARM
Parallels
Xen HVM
ACRN
QNX hypervisor
Hybrid Analysis
Sandboxie
Docker
Wine
Apple Rosetta 2
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
Hyper-V artifact (not an actual VM)
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
)";

    std::exit(0);
}

std::string type(const std::string &brand_str) {
    if (brand_str.find(" or ") != std::string::npos) {
        return "Unknown";        
    }

    const std::map<std::string, std::string> type_table {
        // type 1
        { "Xen HVM", "Hypervisor (type 1)" },
        { "VMware ESX", "Hypervisor (type 1)" },
        { "ACRN", "Hypervisor (type 1)" },
        { "QNX hypervisor", "Hypervisor (type 1)" },
        { "Microsoft Hyper-V", "Hypervisor (type 1)" },
        { "Microsoft Azure Hyper-V", "Hypervisor (type 1)" },
        { "Xbox NanoVisor (Hyper-V)", "Hypervisor (type 1)" },
        { "KVM ", "Hypervisor (type 1)" },
        { "bhyve", "Hypervisor (type 1)" },
        { "KVM Hyper-V Enlightenment", "Hypervisor (type 1)" },
        { "QEMU+KVM Hyper-V Enlightenment", "Hypervisor (type 1)" },
        { "QEMU+KVM", "Hypervisor (type 1)" },
        { "Intel HAXM", "Hypervisor (type 1)" },
        { "Intel KGT (Trusty)", "Hypervisor (type 1)" },
        { "SimpleVisor", "Hypervisor (type 1)" },
        { "Google Compute Engine (KVM)", "Hypervisor (type 1)" },
        { "OpenStack (KVM)", "Hypervisor (type 1)" },
        { "KubeVirt (KVM)", "Hypervisor (type 1)" },
        { "IBM PowerVM", "Hypervisor (type 1)" },
        { "AWS Nitro System EC2 (KVM-based)", "Hypervisor (type 1)" },

        // type 2
        { "VirtualBox", "Hypervisor (type 2)" },
        { "VMware", "Hypervisor (type 2)" },
        { "VMware Express", "Hypervisor (type 2)" },
        { "VMware GSX", "Hypervisor (type 2)" },
        { "VMware Workstation", "Hypervisor (type 2)" },
        { "VMware Fusion", "Hypervisor (type 2)" },
        { "Parallels", "Hypervisor (type 2)" },
        { "Virtual PC", "Hypervisor (type 2)" },
        { "NetBSD NVMM", "Hypervisor (type 2)" },
        { "OpenBSD VMM", "Hypervisor (type 2)" },
        { "User-mode Linux", "Hypervisor (type 2)" },

        // sandbox
        { "Cuckoo", "Sandbox" },
        { "Sandboxie", "Sandbox" },
        { "Hybrid Analysis", "Sandbox" },
        { "CWSandbox", "Sandbox" },
        { "JoeBox", "Sandbox" },
        { "Anubis", "Sandbox" },
        { "Comodo", "Sandbox" },
        { "ThreatExpert", "Sandbox" },
        { "ANY.RUN", "Sandbox"},

        // misc
        { "Bochs", "Emulator" },
        { "BlueStacks", "Emulator" },
        { "Microsoft x86-to-ARM", "Emulator" },
        { "QEMU", "Emulator" },
        { "Jailhouse", "Partitioning Hypervisor" },
        { "Unisys s-Par", "Partitioning Hypervisor" },
        { "Docker", "Container" },
        { "Podman", "Container" },
        { "OpenVZ", "Container" },
        { "Microsoft Virtual PC/Hyper-V", "Hypervisor (either type 1 or 2)" },
        { "Lockheed Martin LMHS", "Hypervisor (unknown type)" },
        { "Wine", "Compatibility layer" },
        { "Apple VZ", "Unknown" },
        { "Hyper-V artifact (not an actual VM)", "No VM" },
        { "User-mode Linux", "Paravirtualised" },
        { "WSL", "Hybrid Hyper-V (type 1 and 2)" }, // debatable tbh
        { "Apple Rosetta 2", "Binary Translation Layer/Emulator" },
    };

    auto it = type_table.find(brand_str);

    if (it != type_table.end()) {
        return it->second;
    }

    return "Unknown";
}

bool is_spoofable(const VM::enum_flags flag) {
    if (arg_bitset.test(ALL)) {
        return false;
    }

    switch (flag) {
        case VM::MAC:
        case VM::DOCKERENV:
        case VM::HWMON:
        case VM::CURSOR:
        case VM::VMWARE_REG:
        case VM::VBOX_REG:
        case VM::USER:
        case VM::DLL:
        case VM::REGISTRY:
        case VM::CWSANDBOX_VM:
        case VM::VM_FILES:
        case VM::HWMODEL:
        case VM::COMPUTER_NAME:
        case VM::HOSTNAME:
        case VM::KVM_REG:
        case VM::KVM_DRIVERS:
        case VM::KVM_DIRS:
        case VM::LOADED_DLLS:
        case VM::QEMU_DIR:
        case VM::MOUSE_DEVICE:
        case VM::VM_PROCESSES:
        case VM::LINUX_USER_HOST:
        case VM::HYPERV_REG:
        case VM::MAC_MEMSIZE:
        case VM::MAC_IOKIT:
        case VM::IOREG_GREP:
        case VM::MAC_SIP:
        case VM::HKLM_REGISTRIES:
        case VM::QEMU_GA:
        case VM::QEMU_PROC:
        case VM::VPC_PROC:
        case VM::VM_FILES_EXTRA:
        case VM::UPTIME:
        case VM::CUCKOO_DIR:
        case VM::CUCKOO_PIPE:
        case VM::HYPERV_HOSTNAME:
        case VM::GENERAL_HOSTNAME:
        case VM::BLUESTACKS_FOLDERS: 
        case VM::EVENT_LOGS: 
        case VM::KMSG: 
        case VM::VM_PROCS: 
        case VM::PODMAN_FILE: return true;
        default: return false;
    }
}

#if (LINUX)
bool is_admin() {
    const uid_t uid  = getuid();
    const uid_t euid = geteuid();

    const bool is_root = (
        (uid != euid) || 
        (euid == 0)
    );

    return is_root;
}
#endif


bool are_perms_required(const VM::enum_flags flag) {
#if (LINUX)
    if (is_admin()) {
        return false;
    }

    switch (flag) {
        case VM::VBOX_DEFAULT: 
        case VM::VMWARE_DMESG: 
        case VM::DMIDECODE: 
        case VM::DMESG: 
        case VM::QEMU_USB: 
        case VM::KMSG: 
        case VM::SMBIOS_VM_BIT: return true;
        default: return false;
    }
#else 
    return false;
#endif
}


bool is_disabled(const VM::enum_flags flag) {
    if (arg_bitset.test(ALL)) {
        return false;
    }

    switch (flag) {
        case VM::RDTSC:
        case VM::RDTSC_VMEXIT:
        case VM::CURSOR: return true;
        default: return false;
    }
}


void general() {
    const std::string detected = ("[  " + std::string(green) + "DETECTED" + std::string(ansi_exit) + "  ]");
    const std::string not_detected = ("[" + std::string(red) + "NOT DETECTED" + std::string(ansi_exit) + "]");
    const std::string spoofable = ("[" + std::string(red) + " SPOOFABLE " + std::string(ansi_exit) + "]");
    const std::string note = ("[    NOTE    ]");               
    const std::string no_perms = ("[" + std::string(grey) + "  NO PERMS  " + std::string(ansi_exit) + "]");
    const std::string disabled = ("[" + std::string(grey) + "  DISABLED  " + std::string(ansi_exit) + "]");
    const std::string tip = (std::string(green) + "TIP: " + std::string(ansi_exit));

    auto checker = [&](const VM::enum_flags flag, const char* message) -> void {
        if (is_spoofable(flag)) {
            if (!arg_bitset.test(SPOOFABLE)) {
                std::cout << spoofable << "  Skipped " << message << "\n";
                return;
            }
        }

#if (LINUX)
        if (are_perms_required(flag)) {
            std::cout << no_perms << " Skipped " << message << "\n";
            return;
        }
#endif

        if (is_disabled(flag)) {
            std::cout << disabled << " Skipped " << message << "\n";
            return;
        }

        if (VM::check(flag)) {
            std::cout << detected << " Checking " << message << "...\n";
            detected_count++;
        } else {
            std::cout << not_detected << " Checking " << message << "...\n";
        }
    };

    bool notes_enabled = false;
    VM::enum_flags spoofable_setting;

    if (arg_bitset.test(NOTES)) {
        notes_enabled = false;
    } else {
        notes_enabled = true;
    }

    if (arg_bitset.test(SPOOFABLE)) {
        spoofable_setting = VM::SPOOFABLE;
    } else {
        spoofable_setting = VM::NULL_ARG;
    }

    #if (LINUX)
        if (notes_enabled && !is_admin()) {
            std::cout << note << " Running under root might give better results\n";
        }
    #endif

    checker(VM::VMID, "VMID");
    checker(VM::CPU_BRAND, "CPU brand");
    checker(VM::HYPERVISOR_BIT, "CPUID hypervisor bit");
    checker(VM::HYPERVISOR_STR, "hypervisor str");
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
    //checker(VM::WINE_CHECK, "Wine");
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
    //checker(VM::VBOX_WINDOW_CLASS, "VBox window class");
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
    checker(VM::CPUID_BITSET, "CPUID bitset");
    checker(VM::CUCKOO_DIR, "Cuckoo directory");
    checker(VM::CUCKOO_PIPE, "Cuckoo pipe");
    checker(VM::HYPERV_HOSTNAME, "Hyper-V Azure hostname");
    checker(VM::GENERAL_HOSTNAME, "general VM hostnames");
    checker(VM::SCREEN_RESOLUTION, "screen resolution");
    checker(VM::DEVICE_STRING, "bogus device string");
    checker(VM::MOUSE_DEVICE, "mouse device");
    checker(VM::BLUESTACKS_FOLDERS, "BlueStacks folders");
    checker(VM::CPUID_SIGNATURE, "CPUID signatures");
    checker(VM::HYPERV_BITMASK, "Hyper-V CPUID reserved bitmask");
    checker(VM::KVM_BITMASK, "KVM CPUID reserved bitmask");
    checker(VM::KGT_SIGNATURE, "Intel KGT signature");
    checker(VM::VMWARE_DMI, "VMware DMI");
    checker(VM::EVENT_LOGS, "Hyper-V event logs");
    checker(VM::QEMU_VIRTUAL_DMI, "QEMU virtual DMI directory");
    checker(VM::QEMU_USB, "QEMU USB");
    checker(VM::HYPERVISOR_DIR, "Hypervisor directory (Linux)");
    checker(VM::UML_CPU, "User-mode Linux CPU");
    checker(VM::KMSG, "/dev/kmsg hypervisor message");
    checker(VM::VM_PROCS, "various VM files in /proc");
    checker(VM::VBOX_MODULE, "VBox kernel module");
    checker(VM::SYSINFO_PROC, "/proc/sysinfo");
    checker(VM::DEVICE_TREE, "/proc/device-tree");
    checker(VM::DMI_SCAN, "DMI scan");
    checker(VM::SMBIOS_VM_BIT, "SMBIOS VM bit");
    checker(VM::PODMAN_FILE, "Podman file");
    checker(VM::WSL_PROC, "WSL string in /proc");
    checker(VM::ANYRUN_DRIVER, "ANY.RUN driver");
    checker(VM::ANYRUN_DIRECTORY, "ANY.RUN directory");

    std::printf("\n");

#ifdef __VMAWARE_DEBUG__
    std::cout << "[DEBUG] theoretical maximum points: " << VM::total_points << "\n";
#endif

    std::string brand = VM::brand(VM::MULTIPLE, spoofable_setting);

    std::cout << "VM brand: " << ((brand == "Unknown") || (brand == "Hyper-V artifact (not an actual VM)") ? red : green) << brand << ansi_exit << "\n";

    // meaning "if there's no brand conflicts" 
    if (brand.find(" or ") == std::string::npos) {
        const std::string type_value = type(brand);

        std::cout << "VM type: ";

        std::string color = "";
            
        if (type_value == "Unknown" || type_value == "No VM") {
            color = red;
        } else {
            color = green;
        }

        std::cout << color << type_value << ansi_exit << "\n";
    }

    const char* percent_color = "";
    const std::uint8_t percent = VM::percentage(spoofable_setting);

    if      (percent == 0) { percent_color = red; }
    else if (percent < 25) { percent_color = red_orange; }
    else if (percent < 50) { percent_color = orange; }
    else if (percent < 75) { percent_color = green_orange; }
    else                   { percent_color = green; }

    std::cout << "VM likeliness: " << percent_color << static_cast<std::uint32_t>(percent) << "%" << ansi_exit << "\n";

    const bool is_detected = VM::detect(spoofable_setting);

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

#if (MSVC)
    using brand_score_t = std::int32_t;
#else
    using brand_score_t = std::uint8_t;
#endif

    std::map<const char*, brand_score_t> brand_map = VM::brand_map();

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

    if ((brand == "Hyper-V artifact (not an actual VM)") && notes_enabled) {
        std::cout << note << " The result means that the CLI has found Hyper-V, but as an artifact instead of an actual VM. This means that although the hardware values in fact match with Hyper-V due to how it's designed by Microsoft, the CLI has determined you are NOT in a Hyper-V VM.\n\n";
    } else if (notes_enabled) {
        if (!arg_bitset.test(SPOOFABLE)) {
            std::cout << tip << "To enable spoofable techniques, run with the \"--spoofable\" argument\n\n";
        } else {
            std::cout << note << " If you found a false positive, please make sure to create an issue at https://github.com/kernelwernel/VMAware/issues\n\n";
        }
    }
}


int main(int argc, char* argv[]) {
#if (MSVC)
    win_ansi_enabler_t ansi_enabler;
#endif

    const std::vector<const char*> args(argv + 1, argv + argc); // easier this way
    const std::uint32_t arg_count = argc - 1;

    if (arg_count == 0) {
        general();
        std::exit(0);
    } 

    static constexpr std::array<std::pair<const char*, arg_enum>, 24> table {{
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
        { "--spoofable", SPOOFABLE }
    }};

    std::string potential_null_arg = "";

    for (const auto arg_string : args) {
        auto it = std::find_if(table.cbegin(), table.cend(), [&](const auto &p) {
            return (std::strcmp(p.first, arg_string) == 0);
        });

        if (it == table.end()) {
            arg_bitset.set(NULL_ARG);
            potential_null_arg = arg_string;
        } else {
            arg_bitset.set(it->second);
        }
    }


    // no critical returners
    if (arg_bitset.test(NULL_ARG)) {
        std::cerr << "Unknown argument \"" << potential_null_arg << "\", aborting\n";
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
        std::cout << static_cast<std::uint32_t>(VM::technique_count) << "\n";
        return 0;
    }


    // critical returners
    const std::uint32_t returners = (
        static_cast<std::uint8_t>(arg_bitset.test(STDOUT)) +
        static_cast<std::uint8_t>(arg_bitset.test(PERCENT)) +
        static_cast<std::uint8_t>(arg_bitset.test(DETECT)) +
        static_cast<std::uint8_t>(arg_bitset.test(BRAND)) +
        static_cast<std::uint8_t>(arg_bitset.test(TYPE)) +
        static_cast<std::uint8_t>(arg_bitset.test(CONCLUSION))
    );

    if (returners > 0) { // at least one of the options are set
        if (returners > 1) { // more than 2 options are set
            std::cerr << "--stdout, --percent, --detect, --brand, --type, and --conclusion must NOT be a combination, choose only a single one\n";
            return 1;
        }
            
        const std::uint8_t max_bits = static_cast<std::uint8_t>(VM::MULTIPLE) + 1;

        auto settings = [&]() -> std::bitset<max_bits> {
            std::bitset<max_bits> setting_bits;

            if (arg_bitset.test(SPOOFABLE)) {
                setting_bits.set(VM::SPOOFABLE);
            }

            if (arg_bitset.test(ALL)) {
                setting_bits |= VM::ALL;
                setting_bits.set(VM::SPOOFABLE);
            }

            setting_bits.set(NULL_ARG);

            return setting_bits;
        };

        if (arg_bitset.test(STDOUT)) {
            return (!VM::detect(VM::NO_MEMO, settings()));
        }

        if (arg_bitset.test(PERCENT)) {
            std::cout << static_cast<std::uint32_t>(VM::percentage(VM::NO_MEMO, settings())) << "\n";
            return 0;
        }

        if (arg_bitset.test(DETECT)) {
            std::cout << VM::detect(VM::NO_MEMO, settings()) << "\n";
            return 0;
        }

        if (arg_bitset.test(BRAND)) {
            std::cout << VM::brand(VM::NO_MEMO, VM::MULTIPLE, settings()) << "\n";
            return 0;
        }

        if (arg_bitset.test(TYPE)) {
            const std::string brand = VM::brand(VM::NO_MEMO, VM::MULTIPLE, settings());
            std::cout << type(brand) << "\n";
            return 0;
        }

        if (arg_bitset.test(CONCLUSION)) {
            std::uint8_t percent = 0;

            percent = VM::percentage(VM::NO_MEMO, settings());

            const std::string brand = VM::brand(VM::MULTIPLE, settings());
            std::cout << message(percent, brand) << "\n";
            return 0;
        }
    }

    // at this point, it's assumed that the user's intention is for the general summary to be ran
    general();
    return 0;
}