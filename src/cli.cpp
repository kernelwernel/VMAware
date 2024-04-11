#include "vmaware.hpp"
#include <string>
#include <iostream>
#include <vector>
#include <cstdint>

#if (defined(__GNUC__) || defined(__linux__))
    #include <unistd.h>
#endif

#if (MSVC)
    #include "Windows.h"
#endif

constexpr const char* ver = "1.3";
constexpr const char* date = "April 2024";
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

void help(void) {
    std::cout << 
R"(Usage: 
 vmaware [options]

Options:
 -h | --help        prints this help menu
 -v | --version     print cli version and other details
 -d | --detect      returns the result as a boolean (1 = VM, 0 = baremetal)
 -s | --stdout      returns either 0 or 1 to STDOUT without any text output (0 = VM, 1 = baremetal)
 -b | --brand       returns the VM brand string (consult documentation for full output list)
 -p | --percent     returns the VM percentage between 0 and 100
 -c | --conclusion  returns the conclusion message string
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
    if (score == 0) {
        return red;
    } else if (score <= 12) {
        return red;
    } else if (score <= 25) {
        return red_orange;
    } else if (score < 50) {
        return red_orange;
    } else if (score <= 62) {
        return orange;
    } else if (score <= 75) {
        return green_orange;
    } else if (score < 100) {
        return green;
    } else if (score == 100) {
        return green;
    }

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
    
    if (score == 0) {
        return baremetal;
    } else if (score <= 12) {
        return very_unlikely;
    } else if (score <= 25) {
        return unlikely;
    } else if (score < 50) {
        return potentially;
    } else if (score <= 62) {
        return might;
    } else if (score <= 75) {
        return likely;
    } else if (score < 100) {
        return very_likely;
    } else if (score == 100) {
        return inside_vm;
    }

    return "Unknown error";
}

int main(int argc, char* argv[]) {
#if (MSVC)
    win_ansi_enabler_t ansi_enabler;
#endif
    if (argc == 1) {
        const std::string detected = ("[  " + std::string(green) + "DETECTED" + std::string(ansi_exit) + "  ]");
        const std::string not_detected = ("[" + std::string(red) + "NOT DETECTED" + std::string(ansi_exit) + "]");
        const std::string note = ("[    NOTE    ]");

        auto checker = [&](const std::uint8_t flag, const char* message) -> void {
            std::cout << (VM::check(flag) ? detected : not_detected) << " Checking " << message << "...\n";
        };

        #if (defined(__GNUC__) || defined(__linux__))
            const uid_t uid = getuid();
            const uid_t euid = geteuid();

            const bool is_root = (
                (uid != euid) || 
                (euid == 0)
            );

            if (!is_root) {
                std::cout << note << " Running under root would give better results\n";
            }
        #endif

        checker(VM::VMID, "VMID");
        checker(VM::BRAND, "CPU brand");
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
        checker(VM::WMIC, "WMIC outputs");
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
        checker(VM::VM_DIRS, "VM directories");
        checker(VM::UPTIME, "uptime");

        std::printf("\n");

        const std::string brand = VM::brand(VM::MULTIPLE);

        std::cout << "VM brand: " << (brand == "Unknown" ? red : green) << brand << ansi_exit << "\n";

        const char* percent_color = "";
        const std::uint8_t percent = VM::percentage();

        if (percent == 0) {
            percent_color = red;
        } else if (percent < 25) {
            percent_color = red_orange;
        } else if (percent < 50) {
            percent_color = orange;
        } else if (percent < 75) {
            percent_color = green_orange;
        } else {
            percent_color = green;
        }

        std::cout << "VM certainty: " << percent_color << static_cast<std::uint32_t>(VM::percentage()) << "%" << ansi_exit << "\n";

        const bool is_detected = VM::detect();

        std::cout << "VM confirmation: " << (is_detected ? green : red) << std::boolalpha << is_detected << std::noboolalpha << ansi_exit << "\n\n";

        const char* conclusion_color = color(percent);
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
    } else if (argc == 2) {
        const std::vector<const char*> args(argv, argv + argc); // easier this way
        const char* arg = args.at(1);

        auto cmp = [](const char* a, const char* b) -> bool {
            return (std::strcmp(a, b) == 0);
        };

        if (cmp(arg, "-s") || cmp(arg, "--stdout")) {
            return (!VM::detect(VM::NO_MEMO));
        } else if (cmp(arg, "-h") || cmp(arg, "--help")) {
            help();
            return 0;
        } else if (cmp(arg, "-v") || cmp(arg, "--version")) {
            version();
            return 0;
        } else if (cmp(arg, "-b") || cmp(arg, "--brand")) {
            std::cout << VM::brand(VM::MULTIPLE) << "\n";
            return 0;
        } else if (cmp(arg, "-p") || cmp(arg, "--percent")) {
            std::cout << static_cast<std::uint32_t>(VM::percentage()) << "\n";
            return 0;
        } else if (cmp(arg, "-d") || cmp(arg, "--detect")) {
            std::cout << VM::detect() << "\n";
            return 0;
        } else if (cmp(arg, "-c") || cmp(arg, "--conclusion")) {
            const std::uint8_t percent = VM::percentage();
            const std::string brand = VM::brand();
            std::cout << message(percent, brand) << "\n";
            return 0;
        } else {
            std::cerr << "Unknown argument provided, consult the help menu with --help\n";
            return 1;
        }
    } else if (argc > 2) {
        std::cerr << "Either zero or one argument must be provided\n";
        return 1;
    } else {
        std::cerr << "Encountered unknown error, aborting\n";
        return 1;
    }
    
    return 0;
}
