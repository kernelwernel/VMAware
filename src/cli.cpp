#include "vmaware.hpp"
#include <string>
#include <iostream>
#include <vector>
#include <cstdint>

#if (defined(__GNUC__) || defined(__linux__))
    #include <unistd.h>
#endif

constexpr const char* ver = "1.1";
constexpr const char* date = "January 2024";
constexpr const char* bold = "\033[1m";
constexpr const char* ansi_exit = "\x1B[0m";
constexpr const char* red = "\x1B[38;2;239;75;75m";
constexpr const char* orange = "\x1B[38;2;255;180;5m";
constexpr const char* green = "\x1B[38;2;94;214;114m";
constexpr const char* red_orange = "\x1B[38;2;247;127;40m";
constexpr const char* green_orange = "\x1B[38;2;174;197;59m";

void help(void) {
    std::cout << 
R"(Usage: 
 vmaware [options]

Options:
 -h | --help        prints this help menu
 -v | --version     print version and other stuff
 -s | --stdout      returns either 0 or 1 to STDOUT without any text output (0 = VM, 1 = baremetal)
 -b | --brand       returns the VM brand string (consult documentation for full output list)
 -p | --percent     returns the VM percentage between 0 and 100
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

int main(int argc, char* argv[]) {
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
        checker(VM::SUNBELT_VM, "Sunbelt");
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
        checker(VM::VBOX_MSSMBIOS, "VirtualBox MSSMBIOS");
        checker(VM::MAC_HYPERTHREAD, "MacOS hyperthreading");
        checker(VM::MAC_MEMSIZE, "MacOS hw.memsize");
        checker(VM::MAC_IOKIT, "MacOS registry IO-kit");
        checker(VM::IOREG_GREP, "IO registry grep");
        checker(VM::MAC_SIP, "MacOS SIP");
        checker(VM::KVM_REG, "KVM registries");
        checker(VM::KVM_DRIVERS, "KVM drivers");
        checker(VM::KVM_DIRS, "KVM directories");
        std::printf("\n");

        std::cout << "VM brand: " << (VM::brand() == "Unknown" ? red : green) << VM::brand() << ansi_exit << "\n";

        const char* percent_color = "";
        std::uint16_t percent = VM::percentage();

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

        const char* conclusion_color = "";
        const char* conclusion_message = "";

        constexpr const char* baremetal = "Running in baremetal";
        constexpr const char* very_unlikely = "Very unlikely a VM";
        constexpr const char* unlikely = "Unlikely a VM";
        constexpr const char* potentially = "Potentially a VM";
        constexpr const char* might = "Might be a VM";
        constexpr const char* likely = "Likely a VM";
        constexpr const char* very_likely = "Very likely a VM";
        constexpr const char* inside_vm = "Running inside a VM";
        
        if (percent == 0) {
            conclusion_color = red;
            conclusion_message = baremetal;
        } else if (percent <= 12) {
            conclusion_color = red;
            conclusion_message = very_unlikely;
        } else if (percent <= 25) {
            conclusion_color = red_orange;
            conclusion_message = unlikely;
        } else if (percent < 50) { // not <= on purpose
            conclusion_color = red_orange;
            conclusion_message = potentially;
        } else if (percent <= 62) {
            conclusion_color = orange;
            conclusion_message = might;
        } else if (percent <= 75) {
            conclusion_color = green_orange;
            conclusion_message = likely;
        } else if (percent < 100) {
            conclusion_color = green_orange;
            conclusion_message = very_likely;
        } else if (percent == 100) {
            conclusion_color = green;
            conclusion_message = inside_vm;
        }

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
            return (strcmp(a, b) == 0);
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
            std::cout << VM::brand() << "\n";
            return 0;
        } else if (cmp(arg, "-p") || cmp(arg, "--percent")) {
            std::cout << VM::percentage() << "\n";
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