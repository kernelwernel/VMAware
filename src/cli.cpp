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
    #define WINDOWS 1
    #include <windows.h>
#else
    #define MSVC 0
#endif

#if (MSVC)
#pragma warning(disable : 4061)
#endif

#include "vmaware.hpp"

constexpr const char* ver = "1.9";
constexpr const char* date = "September 2024";

std::string bold = "\033[1m";
std::string ansi_exit = "\x1B[0m";
std::string red = "\x1B[38;2;239;75;75m"; 
std::string orange = "\x1B[38;2;255;180;5m";
std::string green = "\x1B[38;2;94;214;114m";
std::string red_orange = "\x1B[38;2;247;127;40m";
std::string green_orange = "\x1B[38;2;174;197;59m";
std::string grey = "\x1B[38;2;108;108;108m";

using u8  = std::uint8_t;
using u32 = std::uint32_t;

enum arg_enum : u8 {
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
    HIGH_THRESHOLD,
    NO_COLOR,
    DYNAMIC,
    NULL_ARG
};

constexpr u8 max_bits = static_cast<u8>(VM::MULTIPLE) + 1;
constexpr u8 arg_bits = static_cast<u8>(NULL_ARG) + 1;
std::bitset<arg_bits> arg_bitset;

std::string detected = ("[  " + green + "DETECTED" + ansi_exit + "  ]");
std::string not_detected = ("[" + red + "NOT DETECTED" + ansi_exit + "]");
std::string spoofable = ("[" + red + " EASY SPOOF " + ansi_exit + "]");
std::string no_perms = ("[" + grey + "  NO PERMS  " + ansi_exit + "]");
std::string note = ("[    NOTE    ]");               
std::string disabled = ("[" + grey + "  DISABLED  " + ansi_exit + "]");

#if (WINDOWS)
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
 -b | --brand       returns the VM brand string
 -l | --brand-list  returns all the possible VM brand string values
 -p | --percent     returns the VM percentage between 0 and 100
 -c | --conclusion  returns the conclusion message string
 -n | --number      returns the number of VM detection techniques it performs
 -t | --type        returns the VM type (if a VM was found)

Extra:
 --disable-notes    no notes will be provided
 --spoofable        allow spoofable techniques to be ran (not included by default)
 --high-threshold   a higher theshold bar for a VM detection will be applied
 --no-color         self explanatory
 --dynamic          allow the conclusion message to be dynamic (8 possibilities instead of only 2)

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

const char* color(const u8 score) {
    if (arg_bitset.test(NO_COLOR)) {
        return "";
    }

    if (arg_bitset.test(DYNAMIC)) {
        if      (score == 0)   { return red.c_str(); }
        else if (score <= 12)  { return red.c_str(); }
        else if (score <= 25)  { return red_orange.c_str(); }
        else if (score < 50)   { return red_orange.c_str(); }
        else if (score <= 62)  { return orange.c_str(); }
        else if (score <= 75)  { return green_orange.c_str(); }
        else if (score < 100)  { return green.c_str(); }
        else if (score == 100) { return green.c_str(); }
    } else {
        if (score == 100) {
            return green.c_str();
        } else {
            return red.c_str();
        }
    }

    return "";
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

bool is_spoofable(const VM::enum_flags flag) {
    if (arg_bitset.test(ALL)) {
        return false;
    }

    switch (flag) {
        case VM::MAC:
        case VM::DOCKERENV:
        case VM::HWMON:
        case VM::VMWARE_REG:
        case VM::VBOX_REG:
        case VM::USER:
        case VM::DLL:
        case VM::REGISTRY:
        case VM::VM_FILES:
        case VM::HWMODEL:
        case VM::COMPUTER_NAME:
        case VM::HOSTNAME:
        case VM::KVM_REG:
        case VM::KVM_DRIVERS:
        case VM::KVM_DIRS:
        case VM::LOADED_DLLS:
        case VM::QEMU_DIR:
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
        case VM::HYPERV_EVENT_LOGS:
        case VM::VMWARE_EVENT_LOGS:
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
    (void)flag;
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
        case VM::VMWARE_DMESG: return true;
        default: return false;
    }
}


std::bitset<max_bits> settings() {
    std::bitset<max_bits> tmp;

    if (arg_bitset.test(SPOOFABLE)) {
        tmp.set(VM::SPOOFABLE);
    }

    if (arg_bitset.test(HIGH_THRESHOLD)) {
        tmp.set(VM::HIGH_THRESHOLD);
    }

    if (arg_bitset.test(ALL)) {
        tmp |= VM::ALL;
        tmp.set(VM::SPOOFABLE);
    }

    if (arg_bitset.test(DYNAMIC)) {
        tmp.set(VM::DYNAMIC);
    }

    return tmp;
}


// just a simple string replacer
void replace(std::string &text, const std::string &original, const std::string &new_brand) {
    size_t start_pos = 0;
    while ((start_pos = text.find(original, start_pos)) != std::string::npos) {
        text.replace(start_pos, original.length(), new_brand);
        start_pos += new_brand.length();
    }
}


/**
 * @brief Check for any.run driver presence
 * @category Windows
 * @author kkent030315
 * @link https://github.com/kkent030315/detect-anyrun/blob/main/detect.cc
 * @copyright MIT
 */
[[nodiscard]] static bool anyrun_driver() {
#if (!WINDOWS)
    return false;
#else
    HANDLE hFile;

    hFile = CreateFileA(
        /*lpFileName*/TEXT("\\\\?\\\\A3E64E55_fl"),
        /*dwDesiredAccess*/GENERIC_READ,
        /*dwShareMode*/0,
        /*lpSecurityAttributes*/NULL,
        /*dwCreationDisposition*/OPEN_EXISTING,
        /*dwFlagsAndAttributes*/0,
        /*hTemplateFile*/NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    CloseHandle(hFile);

    return true;
#endif
}


/**
 * @brief Check for any.run directory and handle the status code
 * @category Windows
 * @author kkent030315
 * @link https://github.com/kkent030315/detect-anyrun/blob/main/detect.cc
 * @copyright MIT
 */
[[nodiscard]] static bool anyrun_directory() {
#if (!WINDOWS)
    return false;
#else
    NTSTATUS status;

    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"\\??\\C:\\Program Files\\KernelLogger");

    HANDLE hFile;
    IO_STATUS_BLOCK iosb = { 0 };
    OBJECT_ATTRIBUTES attrs{};
    InitializeObjectAttributes(&attrs, &name, 0, NULL, NULL);

    status = NtCreateFile(
        /*FileHandle*/&hFile,
        /*DesiredAccess*/GENERIC_READ | SYNCHRONIZE,
        /*ObjectAttributes*/&attrs,
        /*IoStatusBlock*/&iosb,
        /*AllocationSize*/NULL,
        /*FileAttributes*/FILE_ATTRIBUTE_DIRECTORY,
        /*ShareAccess*/FILE_SHARE_READ,
        /*CreateDisposition*/FILE_OPEN,
        /*CreateOptions*/FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        /*EaBuffer*/NULL,
        /*EaLength*/0
    );

    // ANY.RUN minifilter returns non-standard status code, STATUS_NO_SUCH_FILE
    // If this status code is returned, it means that the directory is protected
    // by the ANY.RUN minifilter driver.
    // To patch this detection, I would recommend returning STATUS_OBJECT_NAME_NOT_FOUND
    // that is a standard status code for this situation.
    if (status == 0xC000000F) // STATUS_NOT_SUCH_FILE
        return true;

    // Not actually the case, maybe conflict with other software installation.
    if (NT_SUCCESS(status))
        NtClose(hFile);

    return false;
#endif
} 


void checker(const VM::enum_flags flag, const char* message) {
    if (is_spoofable(flag)) {
        if (!arg_bitset.test(SPOOFABLE)) {
            std::cout << spoofable << " Skipped " << message << "\n";
            return;
        }
    }

#if (LINUX)
    if (are_perms_required(flag)) {
        std::cout << no_perms << " Skipped " << message << "\n";

        // memoize it, it's going to be ran later anyway with stuff like VM::detect()
        VM::check(flag);

        return;
    }
#endif

    if (is_disabled(flag)) {
        std::cout << disabled << " Skipped " << message << "\n";
        return;
    }

    std::cout << 
        (VM::check(flag) ? detected : not_detected) << 
        " Checking " << 
        message << 
        "...\n";
}


// overload for std::function, this is specific for any.run techniques
// that are embedded in the CLI because it was removed in the lib as of 2.0
void checker(const std::function<bool()> &func, const char* message) {
    std::cout << 
        (func() ? detected : not_detected) << 
        " Checking " << 
        message << 
        "...\n";
}


const bool is_anyrun_directory = anyrun_directory();
const bool is_anyrun_driver = anyrun_driver();
const bool is_anyrun = (is_anyrun_directory || is_anyrun_driver);


void general() {
    bool notes_enabled = false;

    if (arg_bitset.test(NO_COLOR)) {
        detected = ("[  DETECTED  ]");
        not_detected = ("[NOT DETECTED]");
        spoofable = ("[ EASY SPOOF ]");
        no_perms = ("[  NO PERMS  ]");
        note = ("[    NOTE    ]");               
        disabled = ("[  DISABLED  ]");

        bold = "";
        ansi_exit = "";
        red = ""; 
        orange = "";
        green = "";
        red_orange = "";
        green_orange = "";
        grey = "";
    }

    if (arg_bitset.test(NOTES)) {
        notes_enabled = false;
    } else {
        notes_enabled = true;
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
    checker(VM::VMWARE_REG, "VMware registry");
    checker(VM::VBOX_REG, "VBox registry");
    checker(VM::USER, "users");
    checker(VM::DLL, "DLLs");
    checker(VM::REGISTRY, "registry");
    checker(VM::WINE_CHECK, "Wine");
    checker(VM::VM_FILES, "VM files");
    checker(VM::HWMODEL, "hw.model");
    checker(VM::DISK_SIZE, "disk size");
    checker(VM::VBOX_DEFAULT, "VBox default specs");
    checker(VM::VBOX_NETWORK, "VBox network provider match");
    checker(VM::COMPUTER_NAME, "computer name");
    checker(VM::HOSTNAME, "hostname");
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
    checker(VM::BLUESTACKS_FOLDERS, "BlueStacks folders");
    checker(VM::CPUID_SIGNATURE, "CPUID signatures");
    checker(VM::HYPERV_BITMASK, "Hyper-V CPUID reserved bitmask");
    checker(VM::KVM_BITMASK, "KVM CPUID reserved bitmask");
    checker(VM::KGT_SIGNATURE, "Intel KGT signature");
    checker(VM::VMWARE_DMI, "VMware DMI");
    checker(VM::HYPERV_EVENT_LOGS, "Hyper-V event logs");
    checker(VM::VMWARE_EVENT_LOGS, "VMware event logs");
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
    checker(anyrun_driver, "ANY.RUN driver");
    checker(anyrun_directory, "ANY.RUN directory");
    checker(VM::GPU_CHIPTYPE, "GPU chip name");
    checker(VM::DRIVER_NAMES, "driver names");
    checker(VM::VM_SIDT, "VM SIDT");
    checker(VM::HDD_SERIAL, "HDD serial number");
    checker(VM::PORT_CONNECTORS, "Physical connection ports");
    checker(VM::VM_HDD, "VM keywords in HDD model");
    checker(VM::ACPI_DETECT, "ACPI Hyper-V");
    checker(VM::GPU_NAME, "GPU name");
    checker(VM::VMWARE_DEVICES, "VMware devices");
    checker(VM::VMWARE_MEMORY, "VM memory traces");
    checker(VM::PROCESSOR_NUMBER, "Processor count");
    checker(VM::NUMBER_OF_CORES, "CPU core count");
    checker(VM::WMI_MODEL, "Hardware model");
    checker(VM::WMI_MANUFACTURER, "Hardware manufacturer");
    checker(VM::WMI_TEMPERATURE, "WMI temperature");
    checker(VM::PROCESSOR_ID, "Processor ID");
    checker(VM::CPU_FANS, "CPU fans");
    checker(VM::POWER_CAPABILITIES, "Power capabilities");
    checker(VM::SETUPAPI_DISK, "SETUPDI diskdrive");

  
    std::printf("\n");

#ifdef __VMAWARE_DEBUG__
    std::cout << "[DEBUG] theoretical maximum points: " << VM::total_points << "\n";
#endif

    // struct containing the whole overview of the VM data
    VM::vmaware vm(VM::MULTIPLE, settings());


    // brand manager
    {
        std::string brand = vm.brand;

        if (is_anyrun && (brand == "Unknown")) {
            brand = "ANY.RUN";
        }

        const bool is_red = (
            (brand == "Unknown") || 
            (brand == "Hyper-V artifact (not an actual VM)")
        );

        std::cout << "VM brand: " << (is_red ? red : green) << brand << ansi_exit << "\n";
    }


    // type manager
    {
        if (vm.brand.find(" or ") == std::string::npos) {  // meaning "if there's no brand conflicts" 
            std::string color = "";
            std::string &type = vm.type;

            if (is_anyrun && (type == "Unknown")) {
                type = "Sandbox";
            }

            if (type == "Unknown") {
                color = red;
            } else {
                color = green;
            }

            std::cout << "VM type: " <<  color << type << ansi_exit << "\n";
        }
    }


    // percentage manager
    {
        const char* percent_color = "";

        if      (vm.percentage == 0) { percent_color = red.c_str(); }
        else if (vm.percentage < 25) { percent_color = red_orange.c_str(); }
        else if (vm.percentage < 50) { percent_color = orange.c_str(); }
        else if (vm.percentage < 75) { percent_color = green_orange.c_str(); }
        else                         { percent_color = green.c_str(); }

        std::cout << "VM likeliness: " << percent_color << static_cast<u32>(vm.percentage) << "%" << ansi_exit << "\n";
    }


    // VM confirmation manager
    {
        std::cout << "VM confirmation: " << (vm.is_vm ? green : red) << std::boolalpha << vm.is_vm << std::noboolalpha << ansi_exit << "\n";
    }


    // detection count manager
    {
        const char* count_color = "";

        switch (vm.detected_count) {
            case 0: count_color = red.c_str(); break;
            case 1: count_color = red_orange.c_str(); break;
            case 2: count_color = orange.c_str(); break;
            case 3: count_color = orange.c_str(); break;
            case 4: count_color = green_orange.c_str(); break;
            default:
                // anything over 4 is green
                count_color = green.c_str();
        }

        std::cout << 
            "VM detections: " << 
            count_color << 
            static_cast<u32>(vm.detected_count) << 
            "/" <<
            static_cast<u32>(vm.technique_count) << 
            ansi_exit <<
            "\n\n";
    }


    // conclusion manager
    {
        const char* conclusion_color = color(vm.percentage);

        std::cout
            << bold
            << "====== CONCLUSION: "
            << ansi_exit
            << conclusion_color << vm.conclusion << " " << ansi_exit
            << bold
            << "======"
            << ansi_exit
            << "\n\n";
    }


    // finishing touches with notes
    if (notes_enabled) {
        if ((vm.brand == "Hyper-V artifact (not an actual VM)")) {
            std::cout << note << " The result means that the CLI has found Hyper-V, but as an artifact instead of an actual VM. This means that although the hardware values in fact match with Hyper-V due to how it's designed by Microsoft, the CLI has determined you are NOT in a Hyper-V VM.\n\n";
        } 

        if (!arg_bitset.test(SPOOFABLE) && !arg_bitset.test(ALL)) {
            const std::string tip = (green + "TIP: " + ansi_exit);
            std::cout << tip << "To enable easily spoofable techniques, run with the \"--spoofable\" argument\n\n";
        } else if (vm.detected_count != 0) {
            std::cout << note << " If you found a false positive, please make sure to create an issue at https://github.com/kernelwernel/VMAware/issues\n\n";
        }
    }
}


int main(int argc, char* argv[]) {
#if (WINDOWS)
    win_ansi_enabler_t ansi_enabler;
#endif

    const std::vector<const char*> args(argv + 1, argv + argc); // easier this way
    const u32 arg_count = argc - 1;

    // this was removed from the lib due to ethical 
    // concerns, so it's added in the CLI instead
    VM::add_custom(65, anyrun_driver);
    VM::add_custom(35, anyrun_directory);

    if (arg_count == 0) {
        general();
        std::exit(0);
    }

    static constexpr std::array<std::pair<const char*, arg_enum>, 27> table {{
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
        { "--spoofable", SPOOFABLE },
        { "--high-threshold", HIGH_THRESHOLD },
        { "--dynamic", DYNAMIC },
        { "--no-color", NO_COLOR }
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
        std::cout << static_cast<u32>(VM::technique_count) << "\n";
        return 0;
    }

    // critical returners
    const u32 returners = (
        static_cast<u8>(arg_bitset.test(STDOUT)) +
        static_cast<u8>(arg_bitset.test(PERCENT)) +
        static_cast<u8>(arg_bitset.test(DETECT)) +
        static_cast<u8>(arg_bitset.test(BRAND)) +
        static_cast<u8>(arg_bitset.test(TYPE)) +
        static_cast<u8>(arg_bitset.test(CONCLUSION))
    );

    if (returners > 0) { // at least one of the options are set
        if (returners > 1) { // more than 2 options are set
            std::cerr << "--stdout, --percent, --detect, --brand, --type, and --conclusion must NOT be a combination, choose only a single one\n";
            return 1;
        }

        if (arg_bitset.test(STDOUT)) {
            return (!VM::detect(VM::NO_MEMO, settings()));
        }

        if (arg_bitset.test(PERCENT)) {
            std::cout << static_cast<u32>(VM::percentage(VM::NO_MEMO, settings())) << "\n";
            return 0;
        }

        if (arg_bitset.test(DETECT)) {
            std::cout << VM::detect(VM::NO_MEMO, settings()) << "\n";
            return 0;
        }

        if (arg_bitset.test(BRAND)) {
            std::string brand = VM::brand(VM::NO_MEMO, VM::MULTIPLE, settings());
            
            if (is_anyrun && (brand == "Unknown")) {
                brand = "ANY.RUN";
            }

            std::cout << brand << "\n";

            return 0;
        }

        if (arg_bitset.test(TYPE)) {
            std::string type = VM::type(VM::NO_MEMO, VM::MULTIPLE, settings());

            if (is_anyrun && (type == "Unknown")) {
                type = "Sandbox";
            }

            std::cout << type << "\n";

            return 0;
        }

        if (arg_bitset.test(CONCLUSION)) {
            std::string conclusion = VM::conclusion(VM::NO_MEMO, VM::MULTIPLE, settings());
            
            if (is_anyrun) {
                const std::string original = "Unknown";
                const std::string new_brand = "ANY.RUN";

                replace(conclusion, original, new_brand);
            }

            std::cout << conclusion << "\n";
            return 0;
        }
    }

    // at this point, it's assumed that the user's intention is for the general summary to be ran
    general();
    return 0;
}