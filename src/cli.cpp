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
    #define CLI_LINUX 1
#else
    #define CLI_LINUX 0
#endif


#if (defined(_MSC_VER) || defined(_WIN32) || defined(_WIN64) || defined(__MINGW32__))
    #define CLI_WINDOWS 1
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
#else
    #define CLI_WINDOWS 0
#endif

#if (_MSC_VER)
#pragma warning(disable : 4061)
#endif

#include "vmaware.hpp"

constexpr const char* ver = "2.2.0";
constexpr const char* date = "April 2025";

std::string bold = "\033[1m";
std::string underline = "\033[4m";
std::string ansi_exit = "\x1B[0m";
std::string red = "\x1B[38;2;239;75;75m"; 
std::string orange = "\x1B[38;2;255;180;5m";
std::string green = "\x1B[38;2;94;214;114m";
std::string red_orange = "\x1B[38;2;247;127;40m";
std::string green_orange = "\x1B[38;2;174;197;59m";
std::string grey = "\x1B[38;2;108;108;108m";

using u8  = std::uint8_t;
using u16 = std::uint16_t;
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
    HIGH_THRESHOLD,
    NO_ANSI,
    DYNAMIC,
    VERBOSE,
    COMPACT,
    MIT,
    ENUMS,
    NULL_ARG
};

constexpr u8 max_bits = static_cast<u8>(VM::MULTIPLE) + 1;
constexpr u8 arg_bits = static_cast<u8>(NULL_ARG) + 1;
std::bitset<arg_bits> arg_bitset;
u8 unsupported_count = 0;
u8 supported_count = 0;
u8 no_perms_count = 0;
u8 disabled_count = 0;


std::string detected = ("[  " + green + "DETECTED" + ansi_exit + "  ]");
std::string not_detected = ("[" + red + "NOT DETECTED" + ansi_exit + "]");
std::string no_support = ("[ " + grey + "NO SUPPORT" + ansi_exit + " ]");
std::string no_perms = ("[" + grey + "  NO PERMS  " + ansi_exit + "]");
std::string note = ("[    NOTE    ]");               
std::string disabled = ("[" + grey + "  DISABLED  " + ansi_exit + "]");
std::string running = ("[" + grey + " RUNNING... " + ansi_exit + "]");

#if (CLI_WINDOWS)
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
 -v | --version     print CLI version and other details
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
 --high-threshold   a higher theshold bar for a VM detection will be applied
 --no-ansi          removes color and ansi escape codes from the output
 --dynamic          allow the conclusion message to be dynamic (8 possibilities instead of only 2)
 --verbose          add more information to the output
 --compact          ignore the unsupported techniques from the CLI output
 --mit              ignore the GPL techniques and run only the MIT-supported ones
 --enums            display the technique enum name used by the lib
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
    if (arg_bitset.test(NO_ANSI)) {
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
nsjail
)";

    std::exit(0);
}


#if (CLI_LINUX)
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
#if (CLI_LINUX)
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
        case VM::VMWARE_DMESG: return true;
        default: return false;
    }
}


bool is_unsupported(VM::enum_flags flag) {
    auto linux_techniques = [](VM::enum_flags p_flag) {
        switch (p_flag) {
            case VM::VMID:
            case VM::CPU_BRAND:
            case VM::HYPERVISOR_BIT:
            case VM::HYPERVISOR_STR:
            case VM::TIMER:
            case VM::THREADCOUNT:
            case VM::MAC:
            case VM::TEMPERATURE:
            case VM::SYSTEMD:
            case VM::CVENDOR:
            case VM::CTYPE:
            case VM::DOCKERENV:
            case VM::DMIDECODE:
            case VM::DMESG:
            case VM::HWMON:
            case VM::SIDT5:
            case VM::DISK_SIZE:
            case VM::VBOX_DEFAULT:
            case VM::LINUX_USER_HOST:
            case VM::BOCHS_CPU:
            case VM::QEMU_GA:
            case VM::SIDT:
            case VM::VMWARE_IOMEM:
            case VM::VMWARE_IOPORTS:
            case VM::VMWARE_SCSI:
            case VM::VMWARE_DMESG:
            case VM::ODD_CPU_THREADS:
            case VM::INTEL_THREAD_MISMATCH:
            case VM::XEON_THREAD_MISMATCH:
            case VM::HYPERV_HOSTNAME:
            case VM::GENERAL_HOSTNAME:
            case VM::BLUESTACKS_FOLDERS:
            case VM::CPUID_SIGNATURE:
            case VM::KVM_BITMASK:
            case VM::KGT_SIGNATURE:
            case VM::QEMU_VIRTUAL_DMI:
            case VM::QEMU_USB:
            case VM::HYPERVISOR_DIR:
            case VM::UML_CPU:
            case VM::KMSG:
            case VM::VM_PROCS:
            case VM::VBOX_MODULE:
            case VM::SYSINFO_PROC:
            case VM::DEVICE_TREE:
            case VM::DMI_SCAN:
            case VM::SMBIOS_VM_BIT:
            case VM::PODMAN_FILE:
            case VM::WSL_PROC: 
            case VM::SYS_QEMU:
            case VM::LSHW_QEMU:
            case VM::AMD_SEV:
            case VM::AMD_THREAD_MISMATCH:
            case VM::FILE_ACCESS_HISTORY:
            case VM::UNKNOWN_MANUFACTURER:
            case VM::NSJAIL_PID:
            case VM::PCI_VM:
            // ADD LINUX FLAG
            return false;
            default: return true;
        }        
    };


    auto windows_techniques = [](VM::enum_flags p_flag) {
        switch (p_flag) {
            case VM::VMID:
            case VM::CPU_BRAND:
            case VM::HYPERVISOR_BIT:
            case VM::HYPERVISOR_STR:
            case VM::TIMER:
            case VM::THREADCOUNT:
            case VM::MAC:
            case VM::DLL:
            case VM::REGISTRY:
            case VM::VM_FILES:
            case VM::VBOX_DEFAULT:
            case VM::VBOX_NETWORK:
            case VM::COMPUTER_NAME:
            case VM::WINE_CHECK:
            case VM::HOSTNAME:
            case VM::KVM_DIRS:
            case VM::AUDIO:
            case VM::QEMU_DIR:
            case VM::VM_PROCESSES:
            case VM::GAMARUE:
            case VM::BOCHS_CPU:
            case VM::MSSMBIOS:
            case VM::HKLM_REGISTRIES:
            case VM::VPC_INVALID:
            case VM::SIDT:
            case VM::SGDT:
            case VM::SLDT:
            case VM::OFFSEC_SIDT:
            case VM::OFFSEC_SGDT:
            case VM::OFFSEC_SLDT:
            case VM::VPC_SIDT:
            case VM::VMWARE_STR:
            case VM::VMWARE_BACKDOOR:
            case VM::VMWARE_PORT_MEM:
            case VM::SMSW:
            case VM::MUTEX:
            case VM::ODD_CPU_THREADS:
            case VM::INTEL_THREAD_MISMATCH:
            case VM::XEON_THREAD_MISMATCH:
            case VM::NETTITUDE_VM_MEMORY:
            case VM::CUCKOO_DIR:
            case VM::CUCKOO_PIPE:
            case VM::HYPERV_HOSTNAME:
            case VM::GENERAL_HOSTNAME:
            case VM::SCREEN_RESOLUTION:
            case VM::DEVICE_STRING:
            case VM::CPUID_SIGNATURE:
            case VM::KVM_BITMASK:
            case VM::KGT_SIGNATURE:
            case VM::DRIVER_NAMES:
            case VM::VM_SIDT:
            case VM::HDD_SERIAL:
            case VM::PORT_CONNECTORS:
            case VM::GPU_VM_STRINGS:
            case VM::GPU_CAPABILITIES:
            case VM::IDT_GDT_SCAN:
            case VM::PROCESSOR_NUMBER:
            case VM::NUMBER_OF_CORES:
            case VM::ACPI_TEMPERATURE:
            case VM::PROCESSOR_ID:
            case VM::POWER_CAPABILITIES:
            case VM::SETUPAPI_DISK: 
            case VM::VIRTUAL_PROCESSORS:
            case VM::HYPERV_QUERY:
            case VM::BAD_POOLS:
            case VM::AMD_THREAD_MISMATCH:
            case VM::NATIVE_VHD:
            case VM::VIRTUAL_REGISTRY:
            case VM::FIRMWARE:
            case VM::UNKNOWN_MANUFACTURER:
            case VM::OSXSAVE:
            // ADD WINDOWS FLAG
            return false;
            default: return true;
        }
    };


    auto macos_techniques = [](VM::enum_flags p_flag) {
        switch (p_flag) {
            case VM::VMID:
            case VM::CPU_BRAND:
            case VM::HYPERVISOR_BIT:
            case VM::HYPERVISOR_STR:
            case VM::TIMER:
            case VM::THREADCOUNT:
            case VM::HWMODEL:
            case VM::BOCHS_CPU:
            case VM::MAC_MEMSIZE:
            case VM::MAC_IOKIT:
            case VM::IOREG_GREP:
            case VM::MAC_SIP:
            case VM::ODD_CPU_THREADS:
            case VM::INTEL_THREAD_MISMATCH:
            case VM::XEON_THREAD_MISMATCH:
            case VM::CPUID_SIGNATURE:
            case VM::KVM_BITMASK:
            case VM::KGT_SIGNATURE:
            case VM::AMD_SEV:
            case VM::AMD_THREAD_MISMATCH:
            case VM::UNKNOWN_MANUFACTURER:
            // ADD MACOS FLAG
            return false;
            default: return true;
        }
    };


#if __cplusplus >= 201703L
    if constexpr (CLI_LINUX) {
        return linux_techniques(flag);
    }
    else if constexpr (CLI_WINDOWS) {
        return windows_techniques(flag);
    }
    else if constexpr (APPLE) {
        return macos_techniques(flag);
    }
    else {
        return true;
    }
#else
    #if (CLI_LINUX)
        return linux_techniques(flag);
    #elif (CLI_WINDOWS)
        return windows_techniques(flag);
    #elif (APPLE)
        return macos_techniques(flag);
    #else
        return true;
    #endif
#endif
}


bool is_gpl(const VM::enum_flags flag) {
    switch (flag) {
        case VM::COMPUTER_NAME: 
        case VM::WINE_CHECK: 
        case VM::HOSTNAME: 
        case VM::KVM_DIRS: 
        case VM::QEMU_DIR: 
        case VM::POWER_CAPABILITIES: 
        case VM::SETUPAPI_DISK: return true;
        default: return false;
    }
}


std::bitset<max_bits> settings() {
    std::bitset<max_bits> tmp;

    if (arg_bitset.test(HIGH_THRESHOLD)) {
        tmp.set(VM::HIGH_THRESHOLD);
    }

    if (arg_bitset.test(ALL)) {
        tmp.set(VM::ALL);
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

bool is_vm_brand_multiple(const std::string& vm_brand) {
    return (vm_brand.find(" or ") != std::string::npos);
}



std::string vm_description(const std::string& vm_brand) {

    // if there's multiple brands, return null
    if (is_vm_brand_multiple(vm_brand)) {
        return "";
    }

    std::map<std::string, const char*> description_table{
        { brands::VBOX, "Oracle VirtualBox (formerly Sun VirtualBox, Sun xVM VirtualBox and InnoTek VirtualBox) is a free and commercial hosted hypervisor for x86 and Apple ARM64 virtualization developed by Oracle Corporation initially released in 2007. It supports Intel's VT-x and AMD's AMD-V hardware-assisted virtualization, while providing an extensive feature set as a staple of its flexibility and wide use cases." },
        { brands::VMWARE, "VMware is a free and commercial type 2 hypervisor initially released in 1999 and acquired by EMC, then Dell, and finally Broadcom Inc in 2023. It was the first commercially successful company to virtualize the x86 architecture, and has since produced many sub-versions of the hypervisor since its inception. It uses binary translation to re-write the code dynamically for a faster performance." },
        { brands::VMWARE_EXPRESS, "VMware Express (formerly VMware GSX Server Express) was a free entry-level version of VMware's hosted hypervisor for small-scale virtualization. Released in 2003, it offered basic VM management capabilities but lacked advanced features like VMotion. Discontinued in 2006 as VMware shifted focus to enterprise solutions like ESX and vSphere." },
        { brands::VMWARE_ESX, "VMware ESX (Elastic Sky X) was a type 1 bare-metal hypervisor released in 2001 for enterprise environments. It introduced VMFS clustered filesystems and direct hardware access through its service console. Deprecated in 2010 in favor of the lighter ESXi architecture, which removed the Linux-based service console for improved security." },
        { brands::VMWARE_GSX, "VMware GSX Server (Ground Storm X) was a commercial type 2 hypervisor (2001-2006) for Windows/Linux hosts, targeting departmental server consolidation. Supported features like VM snapshots and remote management through VI Web Access. Discontinued as VMware transitioned to ESX's bare-metal architecture for better performance in enterprise environments." },
        { brands::VMWARE_WORKSTATION, "VMware Workstation is a commercial type 2 hypervisor for Windows/Linux hosts, first released in 1999. Enables nested virtualization, 4K display support, and DirectX 11/OpenGL 4.1 acceleration. Popular with developers for testing multi-tier configurations and legacy OS compatibility through its Unity view mode." },
        { brands::VMWARE_FUSION, "VMware Fusion was a macOS-hosted hypervisor (2007-2024) that allowed Intel-based Macs to run Windows/Linux VMs with Metal graphics acceleration and Retina display support. Discontinued due to Apple's transition to ARM64 architecture with Apple Silicon chips, which required significant architectural changes incompatible with x86 virtualization." },
        { brands::VMWARE_HARD, "VMWare Hardener Loader is an open-source detection mitigation loader to harden vmware virtual machines against VM detection for Windows (vista~win10) x64 guests." },
        { brands::BHYVE, "bhyve (pronounced \"bee hive\", formerly written as BHyVe for \"BSD hypervisor\") is a free type 2 hosted hypervisor initially written for FreeBSD. It can also be used on a number of illumos based distributions including SmartOS, OpenIndiana, and OmniOS. bhyve has a modern codebase and uses fewer resources compared to its competitors. In the case of FreeBSD, the resource management is more efficient." },
        { brands::KVM, "KVM is a free and open source module of the Linux kernel released in 2007. It uses hardware virtualization extensions, and has had support for hot swappable vCPUs, dynamic memory management, and Live Migration. It also reduces the impact that memory write-intensive workloads have on the migration process. KVM emulates very little hardware components, and it defers to a higher-level client application such as QEMU." },
        { brands::QEMU, "The Quick Emulator (QEMU) is a free and open-source emulator that uses dynamic binary translation to emulate a computer's processor. It translates the emulated binary codes to an equivalent binary format which is executed by the machine. It provides a variety of hardware and device models for the VM, while often being combined with KVM. However, no concrete evidence of KVM was found for this system." },
        { brands::QEMU_KVM, "QEMU (a free and open-source emulator that uses dynamic binary translation to emulate a computer's processor) is being used with Kernel-based Virtual Machine (KVM, a free and open source module of the Linux kernel) to emulate hardware at near-native speeds." },
        { brands::KVM_HYPERV, "KVM-HyperV integration allows Linux KVM hosts to expose Hyper-V-compatible paravirtualization interfaces to Windows guests. Enables performance optimizations like enlightened VMCS (Virtual Machine Control Structure) and TSC (Time Stamp Counter) synchronization, reducing overhead for Windows VMs running on Linux hypervisors." },
        { brands::QEMU_KVM_HYPERV, "A QEMU/KVM virtual machine with Hyper-V enlightenments. These features make Windows and Hyper-V guests think they’re running on top of a Hyper-V compatible hypervisor and use Hyper-V specific features." },
        { brands::HYPERV, "Hyper-V is Microsoft's proprietary native hypervisor that can create x86 VMs on Windows. Released in 2008, it supercedes previous virtualization solutions such as Microsoft Virtual Server and Windows VirtualPC. Hyper-V uses partitioning to isolate the guest OSs, and has \"enlightenment\" features for bypassing device emulation layers, allowing for faster execution including when Windows is virtualized on Linux." },
        { brands::HYPERV_VPC, "Either Hyper-V or VirtualPC were detected. Hyper-V is Microsoft's proprietary native hypervisor that can create x86 VMs on Windows. Virtual PC is a discontinued x86 emulator software for Microsoft Windows hosts and PowerPC-based Mac hosts." },
        { brands::PARALLELS, "Parallels is a hypervisor providing hardware virtualization for Mac computers. It was released in 2006 and is developed by Parallels, a subsidiary of Corel. It is a hardware emulation virtualization software, using hypervisor technology that works by mapping the host computer's hardware resources directly to the VM's resources. Each VM thus operates with virtually all the resources of a physical computer." },
        { brands::XEN, "Xen is a free and open-source type 1 hypervisor. Originally developed by the University of Cambridge Computer Laboratory and is now being developed by the Linux Foundation with support from Intel, Arm Ltd, Huawei, AWS, Alibaba Cloud, AMD, and more. It runs in a more privileged CPU state than any other software on the machine, except for firmware. It uses GNU GRUB as its bootloader, and then loads a paravirtualized host OS into the host domain (dom0)." },
        { brands::ACRN, "ACRN is an open source reference type 1 hypervisor stack made by the Linux Foundation Project targeting the IoT, Embedded, Edge segments. Its objective is to cater to the needs of those who require to run Virtual Machines with Real-Time characteristics, or where Functional Safety workloads need to be isolated from other workloads running on the same hardware platform." },
        { brands::QNX, "QNX Hypervisor is a real-time virtualization platform for embedded systems, enabling concurrent execution of QNX Neutrino RTOS and Linux/Android on ARM/x86. Provides time partitioning with <1 microsecond interrupt latency for automotive systems, certified to ISO 26262 ASIL D safety standards. Used in Audi MIB3 and BMW iDrive systems." },
        { brands::HYBRID, "Hybrid Analysis is a sandbox that combines basic and dynamic analysis techniques to detect malicious code that is trying to hide. It extracts indicators of compromise (IOCs) from both runtime data and memory dump analysis, providing a comprehensive approach to malware analysis." },
        { brands::SANDBOXIE, "Sandboxie is an open-source OS-level virtualization solution for Microsoft Windows, an application sandbox for Windows that redirects file/registry writes to virtualized storage. Acquired by Sophos in 2019 and open-sourced in 2020, it uses kernel-mode drivers (SbieDrv.sys) to isolate processes without full VM overhead. Commonly used for testing untrusted software or browsing securely." },
        { brands::DOCKER, "Docker is a set of platform as a service (PaaS) products that use OS-level virtualization to deliver software in packages called containers. The service has both free and premium tiers. The software that hosts the containers is called Docker Engine. It's used to automate the deployment of applications in lightweight containers so that applications can work efficiently in different environments in isolation." },
        { brands::WINE, "Wine is a free and open-source compatibility layer to allow application software and computer games developed for Microsoft Windows to run on Unix-like operating systems. Developers can compile Windows applications against WineLib to help port them to Unix-like systems. Wine is predominantly written using black-box testing reverse-engineering, to avoid copyright issues. No code emulation or virtualization occurs." },
        { brands::VPC, "Microsoft Virtual PC (2004-2011) was a consumer-focused type 2 hypervisor for running Windows XP/Vista guests. Featured \"Undo Disks\" for rollback capability and host-guest integration components. Discontinued after Windows 7's XP Mode due to Hyper-V's emergence, lacking hardware-assisted virtualization support." },
        { brands::ANUBIS, "Anubis is a tool for analyzing the behavior of Windows PE-executables with special focus on the analysis of malware. Execution of Anubis results in the generation of a report file that contains enough information to give a human user a very good impression about the purpose and the actions of the analyzed binary. The generated report includes detailed data about modifications made to the Windows registry or the file system, about interactions with the Windows Service Manager or other processes and of course it logs all generated network traffic." },
        { brands::JOEBOX, "Joe Sandbox (formerly JoeBox) is a cloud-based malware analysis solution with Deep Learning classification. Features multi-OS analysis (Windows/Linux/Android), memory forensics, and MITRE ATT&CK mapping. Offers hybrid analysis combining static/dynamic techniques with 400+ behavioral indicators for enterprise threat hunting." },
        { brands::THREATEXPERT, "ThreatExpert was an automated malware analysis service (2007-2013) that provided behavioral reports via web API. Pioneered mass-scale analysis with heuristic detection of packers/rootkits. Discontinued as competing services like VirusTotal and Hybrid Analysis adopted similar cloud-based approaches with richer feature sets." },
        { brands::CWSANDBOX, "CWSandbox is a tool for malware analysis, developed by Carsten Willems as part of his thesis and Ph.D. studies." },
        { brands::COMODO, "Comodo is a proprietary sandbox running an isolated operating environment. Comodo have integrated sandboxing technology directly into the security architecture of Comodo Internet Security to complement and strengthen the Firewall, Defense+ and Antivirus modules of their product line. It features a hybrid of user mode hooks along with a kernel mode driver, preventing any modification to files or registry on the host machine." },
        { brands::BOCHS, "Bochs (pronounced \"box\") is a free and open-source portable IA-32 and x86-64 IBM PC compatible emulator and debugger mostly written in C++. Bochs is mostly used for OS development and to run other guest OSs inside already running host OSs, while emulating the hardware needed such as hard drives, CD drives, and floppy drives. It doesn't utilize any host CPU virtualization features, therefore is slower than most virtualization software." },
        { brands::NVMM, "NVMM (NetBSD Virtual Machine Monitor) is NetBSD's native hypervisor for NetBSD 9.0. It provides a virtualization API, libnvmm, that can be leveraged by emulators such as QEMU. A unique property of NVMM is that the kernel never accesses guest VM memory, only creating it. Intel's Hardware Accelerated Execution Manager (HAXM) provides an alternative solution for acceleration in QEMU for Intel CPUs only, similar to Linux's KVM." },
        { brands::BSD_VMM, "BSD VMM is FreeBSD's kernel subsystem powering the bhyve hypervisor. Implements Intel VT-x/AMD-V virtualization with direct device assignment (PCI passthrough). Supports UEFI boot and VirtIO paravirtualized devices, optimized for FreeBSD guests with FreeBSD-specific virtio_net(4) and virtio_blk(4) drivers." },
        { brands::INTEL_HAXM, "HAXM was created to bring Intel Virtualization Technology to Windows and macOS users. Today both Microsoft Hyper-V and macOS HVF have added support for Intel Virtual Machine Extensions. The project is discontinued." },
        { brands::UNISYS, "Unisys Secure Partitioning (s-Par®) is firmware made by ClearPath Forward that provides the capability to run multiple operating environments concurrently on the same computer hardware: for example, Linux and Windows operating environments. Unlike virtualization technologies and virtual machines, each s-Par operating environment has dedicated hardware resources—instruction processor cores, memory, and input/output components. Each s-Par operating environment is referred to as a secure partition (or just “partition,” for short). A secure partition is sometimes referred to as a hard partition." },
        { brands::LMHS, "LMHS is Lockheed Martin's native hypervisor. I assume you got this result because you're an employee in the company and you're doing security testing. But if you're not, how the hell did you get this result? Did you steal a US military fighter jet or something? I'm genuinely curious. I really don't expect anybody to have this result frankly but I'll assume it's just a false positive (please create an issue in the repo if it is)." },
        { brands::CUCKOO, "Cuckoo Sandbox is an open-source automated malware analysis system. Executes files in isolated environments (VirtualBox/QEMU) while monitoring API calls, network traffic, and memory changes. Features YARA rule matching and CAPE (Customized Automated Processing Engine) extensions for advanced threat hunting and IOC extraction." },
        { brands::BLUESTACKS, "BlueStacks is a chain of cloud-based cross-platform products developed by the San Francisco-based company of the same name. The BlueStacks App Player enables the execution of Android applications on computers running Microsoft Windows or macOS. It functions through an Android emulator referred to as App Player. The basic features of the software are available for free, while advanced features require a paid monthly subscription." },
        { brands::JAILHOUSE, "Jailhouse is a free and open source partitioning Hypervisor based on Linux, made by Siemens. It is able to run bare-metal applications or (adapted) operating systems besides Linux. For this purpose, it configures CPU and device virtualization features of the hardware platform in a way that none of these domains, called \"cells\", can interfere with each other in an unacceptable way." },
        { brands::APPLE_VZ, "Apple Virtualization Framework (VZ) is a macOS 12+ API for creating ARM64 VMs on Apple Silicon. Provides para-virtualized devices via VirtIO and Rosetta 2 binary translation for x86_64 Linux guests. Used by Lima and UTM to run Linux distributions natively on M1/M2 Macs without traditional hypervisor overhead." },
        { brands::INTEL_KGT, "Intel Kernel Guard Technology (KGT) is a policy specification and enforcement framework for ensuring runtime integrity of kernel and platform assets. Demonstrated secure enclaves for critical OS components using VT-x/EPT before being superseded by CET (Control-flow Enforcement Technology) and HyperGuard in Windows 10." },
        { brands::AZURE_HYPERV, "Azure Hyper-V is Microsoft's cloud-optimized hypervisor variant powering Azure VMs. Implements Azure-specific virtual devices like NVMe Accelerated Networking and vTPMs. Supports nested virtualization for running Hyper-V/containers within Azure VMs, enabling cloud-based CI/CD pipelines and dev/test environments." },
        { brands::NANOVISOR, "NanoVisor is a Hyper-V modification serving as the host OS of Xbox's devices: the Xbox System Software. It contains 2 partitions: the \"Exclusive\" partition is a custom VM for games, while the other partition, called the \"Shared\" partition is a custom VM for running multiple apps including the OS itself. The OS was based on Windows 8 Core at the Xbox One launch in 2013." },
        { brands::SIMPLEVISOR, "SimpleVisor is a minimalist Intel VT-x hypervisor by Alex Ionescu for Windows/Linux research. Demonstrates EPT-based memory isolation and hypercall handling. Used to study VM escapes and hypervisor rootkits, with hooks for intercepting CR3 changes and MSR accesses." },
        { brands::HYPERV_ARTIFACT, "The CLI detected Hyper-V operating as a Type 1 hypervisor, not as a guest virtual machine. Although your hardware/firmware signatures match Microsoft's Hyper-V architecture, we determined that you're running on baremetal, with the help of our \"Hyper-X\" mechanism that differentiates between the root partition (host OS) and guest VM environments. This prevents false positives, as Windows sometimes runs under Hyper-V (type 1) hypervisor." },
        { brands::UML, "User-Mode Linux (UML) allows running Linux kernels as user-space processes using ptrace-based virtualization. Primarily used for kernel debugging and network namespace testing. Offers lightweight isolation without hardware acceleration, but requires host/guest kernel version matching for stable operation." },
        { brands::POWERVM, "IBM PowerVM is a type 1 hypervisor for POWER9/10 systems, supporting Live Partition Mobility and Shared Processor Pools. Implements VIOS (Virtual I/O Server) for storage/networking virtualization, enabling concurrent AIX, IBM i, and Linux workloads with RAS features like predictive failure analysis." },
        { brands::GCE, "Google Compute Engine (GCE) utilizes KVM-based virtualization with custom Titanium security chips for hardware root of trust. Features live migration during host maintenance and shielded VMs with UEFI secure boot. Underpins Google Cloud's Confidential Computing offering using AMD SEV-SNP memory encryption." },
        { brands::OPENSTACK, "OpenStack is an open-source cloud OS managing compute (Nova), networking (Neutron), and storage (Cinder) resources. Supports multiple hypervisors (KVM/Xen/Hyper-V) through driver plugins. Widely used in private clouds with features like Heat orchestration and Octavia load balancing." },
        { brands::KUBEVIRT, "KubeVirt is a VM management add-on for Kubernetes. It provides a common ground for virtualization solutions on top of Kubernetes by extending its core by adding additional virtualization resource types where the Kubernetes API can be used to manage these VM resources alongside all other resources Kubernetes provides. Its functionality is to provide a runtime in order to define and manage VMs." },
        { brands::AWS_NITRO, "AWS Nitro is Amazon's hypervisor for EC2, offloading network/storage to dedicated Nitro Cards. Uses Firecracker microVMs for Lambda/Fargate serverless compute. Provides bare-metal instance types (i3en.metal) with 3x better EBS throughput compared to traditional Xen-based instances." },
        { brands::PODMAN, "Podman is a daemonless container engine by Red Hat using Linux namespaces/cgroups. Supports rootless containers and Docker-compatible CLI syntax. Integrates with systemd for service management and Quadlet for declarative container definitions. Part of the Podman Desktop suite for Kubernetes development." },
        { brands::WSL, "Windows Subsystem for Linux (WSL) is a feature of Microsoft Windows that allows for using a Linux environment without the need for a separate VM or dual booting. WSL requires fewer resources (CPU, memory, and storage) than a full virtual machine (a common alternative for using Linux in Windows), while also allowing the use of both Windows and Linux tools on the same set of files." },
        { brands::OPENVZ, "OpenVZ is a container-based virtualization for Linux using kernel-level isolation. Provides checkpointing and live migration through ploop storage. Requires matching host/guest kernel versions, largely superseded by LXC/LXD due to Docker's popularity and kernel namespace flexibility." },
        { brands::BAREVISOR, "BareVisor is a research-focused type 1 hypervisor emphasizing minimal TCB (Trusted Computing Base). Supports x86/ARM with <10K LoC for secure enclave experiments. Used in academia to study TEEs (Trusted Execution Environments) and hypervisor-based intrusion detection systems." },
        { brands::HYPERPLATFORM, "HyperPlatform is an Intel VT-x research hypervisor for Windows kernel introspection. Provides APIs for EPT hooking and MSR filtering. Used to develop anti-cheat systems and kernel exploit detectors by monitoring CR3 switches and exception handling." },
        { brands::MINIVISOR, "MiniVisor is a research hypervisor written as a UEFI and Windows driver for the educational purpose for Intel processors. This MiniVisor, as a UEFI driver, provides the ability to inspect system activities even before the operating system boots, while as a Windows driver, allows developers to debug it with familiar tools like WinDbg." },
        { brands::INTEL_TDX, "Intel TDX (Trust Domain Extensions) enhances VM confidentiality in cloud environments. Encrypts VM memory and registers using MKTME (Multi-Key Total Memory Encryption), isolating \"trust domains\" from hypervisors. Part of Intel's vPro platform for confidential computing on Xeon Scalable processors." },
        { brands::LKVM, "LKVM (Linux Kernel Virtual Machine) is a minimal KVM frontend for Linux kernel testing. Provides CLI tools like `lkvm run` for quick VM creation with built-in 9pfs support. Used alongside QEMU for rapid boot testing and kernel panic debugging." },
        { brands::AMD_SEV, "AMD Secure Encrypted Virtualization (SEV) encrypts VM memory with EPYC processor-based AES keys. Isolates guests from hypervisors using ASIDs (Address Space Identifiers), protecting against physical attacks and malicious cloud providers. Supported in Linux/KVM via libvirt SEV options." },
        { brands::AMD_SEV_ES, "AMD SEV-Encrypted State (SEV-ES) extends SEV by encrypting CPU register states during VM exits. Prevents hypervisors from inspecting guest register contents, mitigating attacks using VMRUN/VMEXIT timing side channels. Requires guest OS modifications for secure interrupt handling." },
        { brands::AMD_SEV_SNP, "AMD SEV-Secure Nested Paging (SEV-SNP) adds memory integrity protection to SEV-ES. Uses reverse map tables (RMP) to prevent hypervisor-mediated replay/spoofing attacks. Enables attested launch for cloud workloads via guest policy certificates and AMD's Key Distribution Service (KDS)." },
        { brands::NEKO_PROJECT, "Neko Project II is an emulator designed for emulating PC-98 computers. They are a lineup of Japanese 16-bit and 32-bit personal computers manufactured by NEC from 1982 to 2003. While based on Intel processors, it uses an in-house architecture making it incompatible with IBM clones." },
        { brands::NOIRVISOR, "NoirVisor is a hardware-accelerated hypervisor with support to complex functions and purposes. It is designed to support processors based on x86 architecture with hardware-accelerated virtualization feature. For example, Intel processors supporting Intel VT-x or AMD processors supporting AMD-V meet the requirement. It was made by Zero-Tang." },
        { brands::QIHOO, "360 sandbox is a part of 360 Total Security. Similar to other sandbox software, it provides a virtualized environment where potentially malicious or untrusted programs can run without affecting the actual system. Qihoo 360 Sandbox is commonly used for testing unknown applications, analyzing malware behavior, and protecting users from zero-day threats." },
        { brands::NSJAIL, "nsjail is a process isolation tool for Linux. It utilizes Linux namespace subsystem, resource limits, and the seccomp-bpf syscall filters of the Linux kernel. It can be used for isolating networking services, CTF challenges, and containing invasive syscall-level OS fuzzers." },
        { brands::NULL_BRAND, "Indicates no detectable virtualization brand. This result may occur on bare-metal systems, unsupported/obscure hypervisors, or when anti-detection techniques (e.g., VM escaping) are employed by the guest environment." }
    };

    std::map<std::string, const char*>::const_iterator it = description_table.find(vm_brand);
    if (it != description_table.end()) {
        return it->second;
    }

    return "";
}


/**
 * @brief Check for any.run driver presence
 * @category Windows
 * @author kkent030315
 * @link https://github.com/kkent030315/detect-anyrun/blob/main/detect.cc
 * @copyright MIT
 */
[[nodiscard]] static bool anyrun_driver() {
#if (!CLI_WINDOWS)
    return false;
#else
    HANDLE hFile;

    hFile = CreateFile(
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
#if (!CLI_WINDOWS)
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
    if (is_unsupported(flag)) {
        if (arg_bitset.test(COMPACT)) {
            return;
        }

        unsupported_count++;
    } else {
        supported_count++;
    }

    std::string enum_name = "";

    if (arg_bitset.test(ENUMS)) {
        enum_name = grey + " [VM::" + VM::flag_to_string(flag) + "]" + ansi_exit;
    }

#if (CLI_LINUX)
    if (are_perms_required(flag)) {
        if (arg_bitset.test(COMPACT)) {
            return;
        }

        std::cout << no_perms << " Skipped " << message << enum_name << "\n";

        no_perms_count++;

        // memoize it, it's going to be ran later anyway with stuff like VM::detect()
        VM::check(flag);

        return;
    }
#endif

    if (is_disabled(flag) || (arg_bitset.test(MIT) && is_gpl(flag))) {
        if (arg_bitset.test(COMPACT)) {
            return;
        }
        std::cout << disabled << " Skipped " << message << enum_name << "\n";
        disabled_count++;
        return;
    }

    if (VM::check(flag)) {
        std::cout << detected << bold << " Checking " << message << "..." << enum_name << ansi_exit << std::endl;
    } else {
        std::cout << not_detected << " Checking " << message << "..." << enum_name << ansi_exit << std::endl;
    }
}


// overload for std::function, this is specific for any.run techniques
// that are embedded in the CLI because it was removed in the lib as of 2.0
void checker(const std::function<bool()>& func, const char* message) {
#if __cplusplus >= 201703L
    if constexpr (!CLI_WINDOWS) {
        if (arg_bitset.test(VERBOSE)) {
            unsupported_count++;
        }
        else {
            supported_count++;
        }
    }
    else {
        supported_count++;
    }
#else
#if !CLI_WINDOWS
    if (arg_bitset.test(VERBOSE)) {
        unsupported_count++;
    }
    else {
        supported_count++;
    }
#else
    supported_count++;
#endif
#endif

    std::cout << running << " Checking " << message << "..." << ansi_exit;
    std::cout.flush();

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

    if (arg_bitset.test(NO_ANSI)) {
        detected = ("[  DETECTED  ]");
        not_detected = ("[NOT DETECTED]");
        no_support = ("[ NO SUPPORT ]");
        no_perms = ("[  NO PERMS  ]");
        note = ("[    NOTE    ]");               
        disabled = ("[  DISABLED  ]");
        running = ("[ RUNNING... ]");

        bold = "";
        underline = "";
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

    #if (CLI_LINUX)
        if (notes_enabled && !is_admin()) {
            std::cout << note << " Running under root might give better results\n";
        }
    #endif

    checker(VM::VMID, "VMID");
    checker(VM::CPU_BRAND, "CPU brand");
    checker(VM::HYPERVISOR_BIT, "CPUID hypervisor bit");
    checker(VM::HYPERVISOR_STR, "hypervisor str");
    checker(VM::TIMER, "timing anomalies");
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
    checker(VM::DLL, "DLLs");
    checker(VM::REGISTRY, "registry keys");
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
    checker(VM::GAMARUE, "gamarue ransomware technique");
    checker(VM::BOCHS_CPU, "BOCHS CPU techniques");
    checker(VM::MSSMBIOS, "MSSMBIOS data");
    checker(VM::MAC_MEMSIZE, "MacOS hw.memsize");
    checker(VM::MAC_IOKIT, "MacOS registry IO-kit");
    checker(VM::IOREG_GREP, "IO registry grep");
    checker(VM::MAC_SIP, "MacOS SIP");
    checker(VM::KVM_DIRS, "KVM directories");
    checker(VM::HKLM_REGISTRIES, "registry values");
    checker(VM::AUDIO, "audio device");
    checker(VM::QEMU_GA, "qemu-ga process");
    checker(VM::QEMU_DIR, "QEMU directories");
    checker(VM::VPC_INVALID, "VPC invalid instructions");
    checker(VM::SIDT, "SIDT");
    checker(VM::SGDT, "SGDT");
    checker(VM::SLDT, "SLDT");
    checker(VM::OFFSEC_SIDT, "Offensive Security SIDT");
    checker(VM::OFFSEC_SGDT, "Offensive Security SGDT");
    checker(VM::OFFSEC_SLDT, "Offensive Security SLDT");
    checker(VM::VPC_SIDT, "VirtualPC SIDT");
    checker(VM::VMWARE_IOMEM, "/proc/iomem file");
    checker(VM::VMWARE_IOPORTS, "/proc/ioports file");
    checker(VM::VMWARE_SCSI, "/proc/scsi/scsi file");
    checker(VM::VMWARE_DMESG, "VMware dmesg");
    checker(VM::VMWARE_STR, "STR instruction");
    checker(VM::VMWARE_BACKDOOR, "VMware IO port backdoor");
    checker(VM::VMWARE_PORT_MEM, "VMware port memory");
    checker(VM::SMSW, "SMSW instruction");
    checker(VM::MUTEX, "mutex strings");
    checker(VM::ODD_CPU_THREADS, "unusual thread count");
    checker(VM::INTEL_THREAD_MISMATCH, "Intel thread count mismatch");
    checker(VM::XEON_THREAD_MISMATCH, "Intel Xeon thread count mismatch");
    checker(VM::NETTITUDE_VM_MEMORY, "VM memory regions");
    checker(VM::CUCKOO_DIR, "Cuckoo directory");
    checker(VM::CUCKOO_PIPE, "Cuckoo pipe");
    checker(VM::HYPERV_HOSTNAME, "Hyper-V Azure hostname");
    checker(VM::GENERAL_HOSTNAME, "general VM hostnames");
    checker(VM::SCREEN_RESOLUTION, "screen resolution");
    checker(VM::DEVICE_STRING, "bogus device string");
    checker(VM::BLUESTACKS_FOLDERS, "BlueStacks folders");
    checker(VM::CPUID_SIGNATURE, "CPUID signatures");
    checker(VM::KVM_BITMASK, "KVM CPUID reserved bitmask");
    checker(VM::KGT_SIGNATURE, "Intel KGT signature");
    checker(VM::QEMU_VIRTUAL_DMI, "QEMU virtual DMI directory");
    checker(VM::QEMU_USB, "QEMU USB");
    checker(VM::HYPERVISOR_DIR, "hypervisor directory (Linux)");
    checker(VM::UML_CPU, "User-mode Linux CPU");
    checker(VM::KMSG, "/dev/kmsg hypervisor message");
    checker(VM::VM_PROCS, "various VM files in /proc");
    checker(VM::VBOX_MODULE, "VBox kernel module");
    checker(VM::SYSINFO_PROC, "/proc/sysinfo");
    checker(VM::DEVICE_TREE, "/proc/device-tree");
    checker(VM::DMI_SCAN, "DMI scan");
    checker(VM::SMBIOS_VM_BIT, "SMBIOS VM bit");
    checker(VM::PODMAN_FILE, "podman file");
    checker(VM::WSL_PROC, "WSL string in /proc");
    checker(anyrun_driver, "ANY.RUN driver");
    checker(anyrun_directory, "ANY.RUN directory");
    checker(VM::DRIVER_NAMES, "driver names");
    checker(VM::VM_SIDT, "VM SIDT");
    checker(VM::HDD_SERIAL, "HDD serial number");
    checker(VM::PORT_CONNECTORS, "physical connection ports");
    checker(VM::GPU_CAPABILITIES, "GPU capabilities");
    checker(VM::GPU_VM_STRINGS, "GPU strings");
    checker(VM::IDT_GDT_SCAN, "IDT GDT consistency");
    checker(VM::PROCESSOR_NUMBER, "processor count");
    checker(VM::NUMBER_OF_CORES, "CPU core count");
    checker(VM::ACPI_TEMPERATURE, "thermal devices");
    checker(VM::PROCESSOR_ID, "processor ID");
    checker(VM::POWER_CAPABILITIES, "Power capabilities");
    checker(VM::SETUPAPI_DISK, "SETUPDI diskdrive");
    checker(VM::SYS_QEMU, "QEMU in /sys");
    checker(VM::LSHW_QEMU, "QEMU in lshw output");
    checker(VM::VIRTUAL_PROCESSORS, "virtual processors");
    checker(VM::HYPERV_QUERY, "hypervisor query");
    checker(VM::BAD_POOLS, "bad pools");
    checker(VM::AMD_SEV, "AMD-SEV MSR");
    checker(VM::AMD_THREAD_MISMATCH, "AMD thread count mismatch");
    checker(VM::NATIVE_VHD, "VHD containers");
    checker(VM::VIRTUAL_REGISTRY, "registry emulation");
    checker(VM::FIRMWARE, "firmware signatures");
    checker(VM::FILE_ACCESS_HISTORY, "low file access count");
    checker(VM::UNKNOWN_MANUFACTURER, "unknown manufacturer ids");
    checker(VM::OSXSAVE, "xgetbv");
    checker(VM::NSJAIL_PID, "nsjail PID");
    checker(VM::PCI_VM, "PCIe bridge ports");
    // ADD NEW TECHNIQUE CHECKER HERE

    std::printf("\n");

#ifdef __VMAWARE_DEBUG__
    std::cout << "[DEBUG] theoretical maximum points: " << VM::total_points << "\n";
#endif

    // struct containing the whole overview of the VM data
    VM::vmaware vm(VM::MULTIPLE, settings());


    // brand manager
    {
        std::string brand = vm.brand;

        if (is_anyrun && (brand == brands::NULL_BRAND)) {
            brand = "ANY.RUN";
        }

        const bool is_red = (
            (brand == brands::NULL_BRAND) || 
            (brand == brands::HYPERV_ARTIFACT)
        );

        std::cout << bold << "VM brand: " << ansi_exit << (is_red ? red : green) << brand << ansi_exit << "\n";
    }


    // type manager
    {
        if (is_vm_brand_multiple(vm.brand) == false) {
            std::string color = "";
            std::string &type = vm.type;

            if (is_anyrun && (type == brands::NULL_BRAND)) {
                type = "Sandbox";
            }

            if (type == brands::NULL_BRAND) {
                color = red;
            } else {
                color = green;
            }

            std::cout << bold << "VM type: " << ansi_exit <<  color << type << ansi_exit << "\n";
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

        std::cout << bold << "VM likeliness: " << ansi_exit << percent_color << static_cast<u32>(vm.percentage) << "%" << ansi_exit << "\n";
    }


    // VM confirmation manager
    {
        std::cout << bold << "VM confirmation: " << ansi_exit << (vm.is_vm ? green : red) << std::boolalpha << vm.is_vm << std::noboolalpha << ansi_exit << "\n";
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
            bold <<
            "VM detections: " << 
            ansi_exit <<
            count_color << 
            static_cast<u32>(vm.detected_count) << 
            "/" <<
            static_cast<u32>(vm.technique_count) << 
            ansi_exit <<
            "\n";
    }


    // misc manager
    {
        if (arg_bitset.test(VERBOSE)) {
            std::cout << bold << "\nUnsupported detections: " << ansi_exit << static_cast<u32>(unsupported_count) << "\n";
            std::cout << bold << "Supported detections: " << ansi_exit << static_cast<u32>(supported_count) << "\n";
            std::cout << bold << "No permission detections: " << ansi_exit << static_cast<u32>(no_perms_count) << "\n";
            std::cout << bold << "Disabled detections: " << ansi_exit << static_cast<u32>(disabled_count) << "\n";
        }

        std::printf("\n");
    }


    // description manager
    {
        if (vm.brand != brands::NULL_BRAND) {

            const std::string description = vm_description(vm.brand);

            if (!description.empty()) {
                std::cout << bold << underline << "VM description:" << ansi_exit << "\n";

                // this basically adds a \n for every 50 characters after a space
                // so that the output doesn't wrap around the console while making
                // it harder to read. Kinda like how this comment you're reading is
                // structured by breaking the lines in a clean and organised way. 
                const u8 max_line_length = 60;
                
                std::vector<std::string> divided_description;

                std::istringstream stream(description);
                std::string word_snippet;

                // extract words separated by spaces
                while (stream >> word_snippet) {
                    divided_description.push_back(word_snippet);
                }

                std::size_t char_count = 0;

                for (auto it = divided_description.begin(); it != divided_description.end(); ++it) {
                    char_count += it->length() + 1; // +1 because of the space

                    if (char_count <= 60) {
                        continue;
                    } else {
                        if ((char_count - 1) >= (static_cast<unsigned long long>(max_line_length) + 3)) {
                            it = divided_description.insert(it + 1, "\n");
                            char_count = it->length() + 1;
                        } else {
                            continue;
                        }
                    }
                }

                for (const auto& str : divided_description) {
                    std::cout << str << ((str != "\n") ? " " : "");
                }

                std::printf("\n\n");
            }
        }
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
        if (vm.detected_count != 0) {
            std::cout << note << " If you found a false positive, please make sure to create an issue at https://github.com/kernelwernel/VMAware/issues\n\n";
        }
    }
}


int main(int argc, char* argv[]) {
#if (CLI_WINDOWS)
    win_ansi_enabler_t ansi_enabler;
#endif

    const std::vector<const char*> args(argv + 1, argv + argc); // easier to handle args this way
    const u32 arg_count = static_cast<u32>(argc - 1);

    // this was removed from the lib due to ethical 
    // concerns, so it's added in the CLI instead
    VM::add_custom(65, anyrun_driver);
    VM::add_custom(35, anyrun_directory);

    if (arg_count == 0) {
        general();
        std::exit(0);
    }

    static constexpr std::array<std::pair<const char*, arg_enum>, 31> table {{
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
        { "--verbose", VERBOSE },
        { "--compact", COMPACT },
        { "--mit", MIT },
        { "--enums", ENUMS },
        { "--no-ansi", NO_ANSI }
    }};

    std::string potential_null_arg = "";

    for (const auto arg_string : args) {
        //auto it = std::find_if(table.cbegin(), table.cend(), [&](const auto &p) {
        //    return (std::strcmp(p.first, arg_string) == 0);
        //});

        auto it = std::find_if(table.cbegin(), table.cend(), [&](const std::pair<const char*, int> &p) {
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
        static_cast<u32>(arg_bitset.test(STDOUT)) +
        static_cast<u32>(arg_bitset.test(PERCENT)) +
        static_cast<u32>(arg_bitset.test(DETECT)) +
        static_cast<u32>(arg_bitset.test(BRAND)) +
        static_cast<u32>(arg_bitset.test(TYPE)) +
        static_cast<u32>(arg_bitset.test(CONCLUSION))
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
            
            if (is_anyrun && (brand == brands::NULL_BRAND)) {
                brand = "ANY.RUN";
            }

            std::cout << brand << "\n";

            return 0;
        }

        if (arg_bitset.test(TYPE)) {
            std::string type = VM::type(VM::NO_MEMO, VM::MULTIPLE, settings());

            if (is_anyrun && (type == brands::NULL_BRAND)) {
                type = "Sandbox";
            }

            std::cout << type << "\n";

            return 0;
        }

        if (arg_bitset.test(CONCLUSION)) {
            std::string conclusion = VM::conclusion(VM::NO_MEMO, VM::MULTIPLE, settings());
            
            if (is_anyrun) {
                const std::string original = brands::NULL_BRAND;
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
