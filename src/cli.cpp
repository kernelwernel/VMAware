#include "vmaware.hpp"
#include <bits/stdc++.h> // I really can't care less about best practices

void help(void) {
    std::cout << 
R"(Usage: 
 vmaware [options]

Options:
 -h | --help        prints this help menu
 -v | --version     print version and other stuff
 -s | --silent      returns either 0 or 1 to stdout without any text output

)";
}

void version(void) {

}

int main(int argc, char* argv[]) {
    using sv = std::string_view;

    constexpr sv detected = "[  \x1B[38;2;94;214;114mDETECTED\x1B[0m  ]";
    constexpr sv not_detected = "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]";

    if (argc == 1) {
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
        checker(VM::VMWARE_PORT, "VMare port");
        checker(VM::THREADCOUNT, "processor count");
        checker(VM::MAC, "MAC address");
        checker(VM::TEMPERATURE, "temperature");
        checker(VM::SYSTEMD, "systemd virtualisation");
        checker(VM::CVENDOR, "chassis vendor");
        checker(VM::CTYPE, "chassis type");
        checker(VM::DOCKER, "Dockerenv");
        checker(VM::DMIDECODE, "dmidecode output");
        checker(VM::DMESG, "dmesg output");
        checker(VM::HWMON, "hwmon presence");
        std::printf("\n");

        const bool is_vm = VM::detect();

        std::cout << "VM brand: " << (is_vm ? "\x1B[38;2;94;214;114m" : "\x1B[38;2;239;75;75m") << VM::brand() << "\e[0m\n\n";

        std::cout 
            << "\e[1m====== CONCLUSION: \e[0m"
            << (is_vm ? 
                "\x1B[38;2;94;214;114mRunning inside a VM\x1B[0m" : 
                "\x1B[38;2;239;75;75mRunning in baremetal\x1B[0m")
            << " \e[1m======\e[0m\n\n";
    } else if (argc == 2) {
        const std::vector<sv> args(argv, argv + argc); // easier this way
        const sv arg = args.at(1);

        if (arg == "-s" || arg == "--silent") {
            return (!VM::detect());
        } else if (arg == "-h" || arg == "--help") {
            help();
            return 0;
        } else if (arg == "-v" || arg == "--version") {
            version();
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