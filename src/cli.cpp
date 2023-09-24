#include "vmaware.hpp"
#include <string>
#include <iostream>
#include <vector>

using sv = std::string_view;

constexpr float ver = 1.0;
constexpr sv date = "September 2023";
constexpr sv bold = "\033[1m";
constexpr sv ansi_exit = "\x1B[0m";
constexpr sv red = "\x1B[38;2;239;75;75m";
constexpr sv green = "\x1B[38;2;94;214;114m";

void help(void) {
    std::cout << 
R"(Usage: 
 vmaware [options]

Options:
 -h | --help        prints this help menu
 -v | --version     print version and other stuff
 -s | --stdout      returns either 0 or 1 to STDOUT without any text output (0 = VM, 1 = baremetal)
 -b | --brand       returns the VM brand string (consult documentation for full output list)
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

        auto checker = [=](const std::uint64_t flag, const sv message) -> void {
            std::cout << (VM::check(flag) ? detected : not_detected) << " Checking " << message << "...\n";
        };

        checker(VM::VMID, "VMID");
        checker(VM::BRAND, "CPU brand");
        checker(VM::HYPERV_BIT, "CPUID hypervisor bit");
        checker(VM::CPUID_0x4, "CPUID 0x4 leaf");
        checker(VM::HYPERV_STR, "hypervisor brand");
        checker(VM::RDTSC, "RDTSC");
        checker(VM::SIDT, "sidt");
        checker(VM::SIDT5, "sidt null byte");
        checker(VM::VMWARE_PORT, "VMware port");
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
        checker(VM::SUNBELT, "Sunbelt");
        checker(VM::WINE_CHECK, "Wine");
        checker(VM::BOOT, "boot uptime");
        checker(VM::VM_FILES, "VM files");
        checker(VM::HWMODEL, "hw.model");
        checker(VM::DISK_SIZE, "disk size");
        std::printf("\n");

        std::cout << "VM brand: " << (std::string(VM::brand()) == "Unknown" ? red : green) << VM::brand() << ansi_exit << "\n\n";

        const std::string baremetal = (std::string(red) + "Running in baremetal " + std::string(ansi_exit));
        const std::string vmachine = (std::string(green) + "Running inside a VM " + std::string(ansi_exit));

        std::cout 
            << bold 
            << "====== CONCLUSION: "
            << ansi_exit
            << (VM::detect() ? vmachine : baremetal)
            << bold
            << "======"
            << ansi_exit
            << "\n\n";
    } else if (argc == 2) {
        const std::vector<sv> args(argv, argv + argc); // easier this way
        const sv arg = args.at(1);

        if (arg == "-s" || arg == "--stdout") {
            return (!VM::detect());
        } else if (arg == "-h" || arg == "--help") {
            help();
            return 0;
        } else if (arg == "-v" || arg == "--version") {
            version();
            return 0;
        } else if (arg == "-b" || arg == "--brand") {
            std::cout << VM::brand() << "\n";
            return 0;
        } else {
            std::cerr << "Unknown argument provided, aborting\n";
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