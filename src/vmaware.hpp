/**
 * ██╗   ██╗███╗   ███╗ █████╗ ██╗    ██╗ █████╗ ██████╗ ███████╗
 * ██║   ██║████╗ ████║██╔══██╗██║    ██║██╔══██╗██╔══██╗██╔════╝
 * ██║   ██║██╔████╔██║███████║██║ █╗ ██║███████║██████╔╝█████╗  
 * ╚██╗ ██╔╝██║╚██╔╝██║██╔══██║██║███╗██║██╔══██║██╔══██╗██╔══╝  
 *  ╚████╔╝ ██║ ╚═╝ ██║██║  ██║╚███╔███╔╝██║  ██║██║  ██║███████╗
 *   ╚═══╝  ╚═╝     ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ beta version
 * 
 *  A C++ VM detection library
 * 
 *  - Made by: @kernelwernel (https://github.com/kernelwernel)
 *  - Contributed by @Requirem (https://github.com/NotRequiem)
 *  - Repository: https://github.com/kernelwernel/VMAware
 *  - Docs: https://github.com/kernelwernel/VMAware/docs/documentation.md
 *  - Full credits: https://github.com/kernelwernel/VMAware#credits
 *  - License: GPL-3.0
 */ 

#pragma once

#include <functional>
#include <cstring>
#include <string>
#include <fstream>
#include <regex>
#include <thread>
#include <filesystem>
#include <limits>
#include <cstdint>
#include <map>
#include <array>
#include <algorithm>
#include <iostream>
#include <cassert>
#include <cmath>

// shorter and succinct macros
#if __cplusplus == 202002L
    #define CPP 20
#elif __cplusplus == 201703L
    #define CPP 17
#elif __cplusplus == 201402L
    #define CPP 14
#elif __cplusplus == 201103L
    #define CPP 11
#else
    #define CPP 0
#endif
#if (__x86_64__)
    #define x86 1
#else
    #define x86 0
#endif
#if (defined(_MSC_VER) || defined(_WIN32) || defined(_WIN64) || defined(__MINGW32__))
    #define MSVC 1
#else
    #define MSVC 0
#endif
#if (defined(__GNUC__) || defined(__linux__))
    #define LINUX 1
#else
    #define LINUX 0
#endif
#if (defined(__APPLE__) || defined(__APPLE_CPP__) || defined(__MACH__) || defined(__DARWIN))
    #define APPLE 1
#else
    #define APPLE 0
#endif
#if !(defined (MSVC) || defined(LINUX) || defined(APPLE))
    #warning "Unknown OS detected, tests will be severely limited"
#endif
#if (CPP >= 20)
    #include <ranges>
#endif
#if (CPP >= 17)
    #include <bit>
    #include <optional>
#endif
#ifdef __VMAWARE_DEBUG__
    #include <iomanip>
    #include <ios>
#endif
#if (CPP < 11 && !MSVC)
    #error "VMAware only supports C++11 or above, set your compiler flag to '-std=c++20' for GCC/clang, or '/std:c++20' for MSVC"
#endif


#if (MSVC)
    #include <windows.h>
    #include <intrin.h>
    #include <tchar.h>
    #include <stdbool.h>
    #include <stdio.h>
    #include <Iphlpapi.h>
    #include <Assert.h>
    #include <excpt.h>
    #include <winternl.h>
    #include <winnetwk.h>
    #include <versionhelpers.h>
    #include <tlhelp32.h>
    #pragma comment(lib, "iphlpapi.lib")
#elif (LINUX)
    #include <cpuid.h>
    #include <x86intrin.h>
    #include <sys/stat.h>
    #include <sys/statvfs.h>
    #include <sys/ioctl.h>
    #include <net/if.h> 
    #include <netinet/in.h>
    #include <unistd.h>
    #include <string.h>
    #include <memory>
#elif (APPLE)
    #include <sys/types.h>
    #include <sys/sysctl.h>
#endif


struct VM {
private:
    using u8  = std::uint8_t;
    using u16 = std::uint16_t;
    using u32 = std::uint32_t;
    using u64 = std::uint64_t;
    using i32 = std::int32_t;
    using i64 = std::int64_t;

    #if (CPP >= 17)
        using sv = std::string_view;
    #endif

    #if (LINUX)
        // fetch file data
        [[nodiscard]] static std::string read_file(const char* dir) {
            std::ifstream file{};
            std::string data{};
            file.open(dir);
            if (file.is_open()) {
                file >> data;
            }
            file.close(); 
            return data;
        };

        // Basically std::system but it runs in the background with no output
        [[nodiscard]] static std::unique_ptr<std::string> sys_result(const char *cmd) {
            #if (CPP < 14)
                std::unique_ptr<std::string> tmp(nullptr);
                return tmp; 
            #else
                std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);

                if (!pipe) { 
                    return nullptr;
                }

                std::string result{};
                std::array<char, 128> buffer{};

                while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
                    result += buffer.data();
                }

                result.pop_back();

                return std::make_unique<std::string>(result);
            #endif
        }
    #endif

    // check if file exists
    #if (MSVC)
        [[nodiscard]] static bool exists(LPCWSTR path) {
            return (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) || (GetLastError() != ERROR_FILE_NOT_FOUND);
        }
    #else
        [[nodiscard]] static bool exists(const char* path) {
            #if (CPP >= 17)
                return std::filesystem::exists(path);
            #elif (CPP >= 11)
                struct stat buffer;
                return (stat (path, &buffer) == 0); 
            #endif
        }
    #endif
    
    /**
     * Official aliases for VM brands. This is added to avoid accidental typos 
     * which could really fuck up the result. Also, no errors/warnings are 
     * issued if the string is invalid in case of a typo. For example: 
     * scoreboard[VBOX]++; 
     * is much better and safer against typos than:
     * scoreboard["VirtualBox"]++;
     * Hopefully this makes sense. 
     * 
     * TL;DR I have wonky fingers :(
     */ 
    static constexpr const char* VMWARE = "VMware";
    static constexpr const char* VBOX = "VirtualBox";
    static constexpr const char* KVM = "KVM";
    static constexpr const char* BHYVE = "bhyve";
    static constexpr const char* QEMU = "QEMU";
    static constexpr const char* HYPERV = "Microsoft Hyper-V";
    static constexpr const char* MSXTA = "Microsoft x86-to-ARM";
    static constexpr const char* PARALLELS = "Parallels";
    static constexpr const char* XEN = "Xen HVM";
    static constexpr const char* ACRN = "ACRN";
    static constexpr const char* QNX = "QNX hypervisor";
    static constexpr const char* HYBRID = "Hybrid Analysis";
    static constexpr const char* SANDBOXIE = "Sandboxie";
    static constexpr const char* DOCKER = "Docker";
    static constexpr const char* WINE = "Wine";
    static constexpr const char* VAPPLE = "Virtual Apple";
    static constexpr const char* VPC = "Virtual PC";
    static constexpr const char* ANUBIS = "Anubis";
    static constexpr const char* JOEBOX = "JoeBox";
    static constexpr const char* THREADEXPERT = "Thread Expert";
    static constexpr const char* CWSANDBOX = "CW Sandbox";
    static constexpr const char* UNKNOWN = "Unknown";

    // VM scoreboard table specifically for VM::brand()
    #if (MSVC)
        static std::map<const char*, int> scoreboard;
    #else
        static std::map<const char*, u8> scoreboard;
    #endif

    // cross-platform wrapper function for linux and MSVC cpuid
    static void cpuid
    (
        u32 &a, u32 &b, u32 &c, u32 &d, 
        const u32 a_leaf,
        const u32 c_leaf = 0xFF  // dummy value if not set manually
    ) {
        #if (MSVC)
            i32 x[4];
            __cpuidex((i32*)x, a_leaf, c_leaf);
            a = static_cast<u32>(x[0]);
            b = static_cast<u32>(x[1]);
            c = static_cast<u32>(x[2]);
            d = static_cast<u32>(x[3]);
        #elif (LINUX)
            __cpuid_count(a_leaf, c_leaf, a, b, c, d);
        #endif
    };

    // same as above but for array type parameters (MSVC specific)
    static void cpuid
    (
        i32 x[4],
        const u32 a_leaf,
        const u32 c_leaf = 0xFF
    ) {
        #if (MSVC)
            __cpuidex((i32*)x, a_leaf, c_leaf);
        #elif (LINUX)
            __cpuid_count(a_leaf, c_leaf, x[0], x[1], x[2], x[3]);
        #endif
    };

    // cpuid leaf values
    struct leaf {
        static constexpr u32
            hyperv   = 0x40000000,
            proc_ext = 0x80000001,
            brand1   = 0x80000002,
            brand2   = 0x80000003,
            brand3   = 0x80000004;
    };

    // self-explanatory
    [[nodiscard]] static bool is_root() noexcept {
        #if (!LINUX)
            return false;
        #else
            const uid_t uid = getuid();
            const uid_t euid = geteuid();

            return (
                (uid != euid) || 
                (euid == 0)
            );
        #endif
    }

    // for debug output
    #ifdef __VMAWARE_DEBUG__
        template <typename... Args>
        static inline void debug(Args... message) noexcept {
            constexpr const char* black_bg = "\x1B[48;2;0;0;0m";
            constexpr const char* bold = "\033[1m";
            constexpr const char* blue = "\x1B[38;2;00;59;193m";
            constexpr const char* ansiexit = "\x1B[0m";

            std::cout.setf(std::ios::fixed, std::ios::floatfield);
            std::cout.setf(std::ios::showpoint);

            std::cout << black_bg << bold << "[" << blue << "DEBUG" << ansiexit << bold << black_bg << "]" << ansiexit << " ";
            ((std::cout << message),...);
            std::cout << "\n";
        }
    #endif

    // directly return when adding a brand to the scoreboard for a more succint expression
    #if (MSVC) 
        __declspec(noalias)
    #elif (LINUX)
        [[gnu::const]]
    #endif
    [[nodiscard]] static inline bool add(const char* p_brand) noexcept {
        scoreboard[p_brand]++;
        return true;
    }

    // get disk size in GB
    // TODO: finish the MSVC section
    [[nodiscard]] static u32 get_disk_size() {
        u32 size = 0;
    
        #if (LINUX)
            struct statvfs stat;

            if (statvfs("/", &stat) != 0) {
                #if __VMAWARE_DEBUG__
                    debug("private get_disk_size function: ", "failed to fetch disk size");
                #endif
                return false;
            }

            // in gigabytes
            constexpr u64 GB = (1000 * 1000 * 1000);
            size = static_cast<u32>((stat.f_blocks * stat.f_frsize) / GB);
        #elif (MSVC)

        #endif
    
        if (size == 0) {
            return false;
        }

        // round to the nearest factor of 10
        const u32 result = static_cast<u32>(std::round((size / 10.0) * 10));

        #if __VMAWARE_DEBUG__
            debug("private get_disk_size function: ", "disk size = ", result, "GB");
        #endif

        return result;
    }

    // get physical RAM size in GB
    [[nodiscard]] static u64 get_physical_ram_size() {
        #if (LINUX)
            if (!is_root()) {
                #if __VMAWARE_DEBUG__
                    debug("private get_physical_ram_size function: ", "not root, returned 0");
                #endif
                return 0;
            }

            auto result = sys_result("dmidecode --type 19 | grep 'Size' | grep '[[:digit:]]*'");

            if (result == nullptr) {
                #if __VMAWARE_DEBUG__
                    debug("private get_physical_ram_size function: ", "invalid system result from dmidecode, returned 0");
                #endif
                return 0;
            }

            const bool MB = (std::regex_search(*result, std::regex("MB")));
            const bool GB = (std::regex_search(*result, std::regex("GB")));

            if (!(MB || GB)) {
                #if __VMAWARE_DEBUG__
                    debug("private get_physical_ram_size function: ", "neither MB nor GB found, returned 0");
                #endif
                return 0;
            }

            std::string number_str;
            bool in_number = false;

            for (char c : *result) {
                if (std::isdigit(c)) {
                    number_str += c;
                    in_number = true;
                } else if (in_number) {
                    break;
                }
            }

            if (number_str.empty()) {
                #if __VMAWARE_DEBUG__
                    debug("private get_physical_ram_size function: ", "string is empty, returned 0");
                #endif
                return 0;
            }

            u64 number = 0;

            number = std::stoi(number_str);

            if (MB == true) {
                number = static_cast<u64>(std::round(number / 1024)); // 1000?
            }

            return number; // in GB
        #elif (MSVC)
            if (!IsWindowsVistaOrGreater()) {
                return 0;
            }

            ULONGLONG total_memory_kb = 0;

            if (GetPhysicallyInstalledSystemMemory(&total_memory_kb) == ERROR_INVALID_DATA) {
                return 0;
            }

            return (total_memory_kb / (1024 * 1024)); // 1000?
        #else
            return 0;
        #endif
    }

    // get available memory space
    [[nodiscard]] static u64 get_memory_space() {
        #if (MSVC)        
            MEMORYSTATUSEX statex = {0};
            statex.dwLength = sizeof(statex);
            GlobalMemoryStatusEx(&statex); // calls NtQuerySystemInformation
            return statex.ullTotalPhys;
        #elif (LINUX)
            const i64 pages = sysconf(_SC_PHYS_PAGES);
            const i64 page_size = sysconf(_SC_PAGE_SIZE);
            return (pages * page_size);
        #elif (APPLE)
            i32 mib[2] = { CTL_HW, HW_MEMSIZE };
            u32 namelen = sizeof(mib) / sizeof(mib[0]);
            u64 size = 0;
            std::size_t len = sizeof(size);

            if (sysctl(mib, namelen, &size, &len, NULL, 0) < 0) {
                return 0;
            }

            return size; // in bytes
        #endif
    }

    // memoize the value from VM::detect() in case it's ran again
    static std::map<bool, std::pair<bool, const char*>> memo;
                //  ^ VM?           

    // cpuid check value
    static bool cpuid_supported;

    // flags
    static u64 flags;

    /**
     * assert if the flag is enabled, far better expression than typing this:
     * if (!(flags & VMID)) { 
     *    return false;
     * }
     * 
     * compared to this:
     * 
     * if (disabled(VMID)) {
     *    return false;
     * }
     */
    #if (LINUX && __has_cpp_attribute(gnu::pure))
        [[gnu::pure]]
    #endif
    [[nodiscard]] static inline bool disabled(const u64 p_flag) noexcept {
        return (!(flags & p_flag));
    }

public:
    VM() = delete; // Delete default constructor
    VM(const VM&) = delete; // Delete copy constructor
    VM(VM&&) = delete; // Delete move constructor

    static constexpr u64
        VMID = 1 << 0,
        BRAND = 1 << 1,
        HYPERV_BIT = 1 << 2,
        CPUID_0x4 = 1 << 3,
        HYPERV_STR = 1 << 4,
        RDTSC = 1 << 5,
        SIDT = 1 << 6,
        VMWARE_PORT = 1 << 7,
        THREADCOUNT = 1 << 8,
        MAC = 1 << 9,

        // linux-specific
        TEMPERATURE = 1 << 10,
        SYSTEMD = 1 << 11,
        CVENDOR = 1 << 12,
        CTYPE = 1 << 13,
        DOCKERENV = 1 << 14,
        DMIDECODE = 1 << 15,
        DMESG = 1 << 16,
        HWMON = 1 << 17,
        SIDT5 = 1 << 18,
        
        // windows-specific
        CURSOR = 1 << 19,
        VMWARE_REG = 1 << 20,
        VBOX_REG = 1 << 21,
        USER = 1 << 22,
        DLL = 1 << 23,
        REGISTRY = 1 << 24,
        SUNBELT = 1 << 25,
        WINE_CHECK = 1 << 26,
        BOOT = 1 << 27,
        VM_FILES = 1 << 28,
        HWMODEL = 1 << 29,
        DISK_SIZE = 1 << 30,
        VBOX_DEFAULT = 1ULL << 31,
        VBOX_NETWORK = 1ULL << 32,
        COMPUTER_NAME = 1ULL << 33,
        HOSTNAME = 1ULL << 34,
        MEMORY = 1ULL << 35,
        VM_PROCESSES = 1ULL << 36,
        LINUX_USER_HOST = 1ULL << 37,
        WINDOWS_NUMBER = 1ULL << 38,
        VBOX_WINDOW_CLASS = 1ULL << 39,
        GAMARUE = 1ULL << 40,

        // settings
        NO_MEMO = 1ULL << 63,
        
        #if (MSVC)
            ALL = ~(NO_MEMO & 0xFFFFFFFFFFFFFFFF);
        #else
            ALL = ~(NO_MEMO & std::numeric_limits<u64>::max());
        #endif

private:
    static constexpr u64 DEFAULT = (~(CURSOR) & ALL);

    /**
     * @brief Check CPUID output of manufacturer ID for known VMs/hypervisors
     * @category x86
     */
    [[nodiscard]] static bool vmid() try {
        #if (!x86)
            return false;
        #else
            if (!cpuid_supported || disabled(VMID)) {
                #ifdef __VMAWARE_DEBUG__
                    debug("VMID: precondition return called");
                #endif
                return false;
            }

            #if (CPP >= 17)
                constexpr sv 
            #else
                const std::string
            #endif
                bhyve = "bhyve bhyve ",
                kvm = " KVMKVMKVM  ",
                qemu = "TCGTCGTCGTCG",
                hyperv = "Microsoft Hv",
                xta = "MicrosoftXTA",
                parallels = " prl hyperv ",
                parallels2 = " lrpepyh  vr",
                vmware = "VMwareVMware",
                vbox = "VBoxVBoxVBox",
                xen = "XenVMMXenVMM",
                acrn = "ACRNACRNACRN",
                qnx = " QNXQVMBSQG ",
                virtapple = "VirtualApple";

            #if (CPP >= 17)
                constexpr std::array<sv, 13> IDs {
            #else
                std::array<std::string, 13> IDs {
            #endif
                bhyve, kvm, qemu,
                hyperv, parallels, parallels,
                parallels2, vmware, vbox,
                xen, acrn, qnx,
                virtapple
            };

            auto cpuid_thingy = [](const u32 p_leaf, u32* regs, std::size_t start = 0, std::size_t end = 4) -> bool {
                u32 x[4];
                cpuid(x[0], x[1], x[2], x[3], p_leaf);

                for (; start < end; start++) { 
                    *regs++ = x[start];
                }

                return true;
            };

            std::string brand = "";

            u32 sig_reg[3] = {0};

            if (!cpuid_thingy(0, sig_reg, 1)) {
                return false;
            }

            u32 features;
            cpuid_thingy(1, &features, 2, 3);

            auto strconvert = [](u64 n) -> std::string {
                const std::string &str(reinterpret_cast<char*>(&n));
                return str;
            };

            std::stringstream ss;
            ss << strconvert(sig_reg[0]);
            ss << strconvert(sig_reg[2]);
            ss << strconvert(sig_reg[1]);

            brand = ss.str();
 
            #ifdef __VMAWARE_DEBUG__
                debug("VMID: ", brand);
            #endif

            const bool found = (std::find(std::begin(IDs), std::end(IDs), brand) != std::end(IDs));

            if (found) {
                if (brand == bhyve) { return add(BHYVE); }
                if (brand == kvm) { return add(KVM); }
                if (brand == qemu) [[likely]] { return add(QEMU); }
                if (brand == hyperv) { return add(HYPERV); }
                if (brand == xta) { return add(MSXTA); }
                if (brand == vmware) [[likely]] { return add(VMWARE); }
                if (brand == vbox) [[likely]] { return add(VBOX); }
                if (brand == parallels) { return add(PARALLELS); }
                if (brand == parallels2) { return add(PARALLELS); }
                if (brand == xen) { return add(XEN); }
                if (brand == acrn) { return add(ACRN); }
                if (brand == qnx) { return add(QNX); }
                if (brand == virtapple) { return add(VAPPLE); }
            }

            return false;
        #endif
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("VMID: catched error, returned false");
        #endif
        return false;
    }


    /**
     * @brief Check if CPU brand is a VM brand
     * @category x86
     */
    [[nodiscard]] static bool cpu_brand() try {
        #if (!x86)
            return false;
        #else
            if (!cpuid_supported || disabled(BRAND)) {
                #ifdef __VMAWARE_DEBUG__
                    debug("BRAND: ", "precondition return called");
                #endif
                return false;
            }

            // maybe not necessary but whatever
            #if (LINUX)
                if (!__get_cpuid_max(0x80000004, nullptr)) {
                    return false;
                }
            #endif

            std::array<u32, 4> buffer{};
            constexpr std::size_t buffer_size = sizeof(i32) * buffer.size();
            std::array<char, 64> charbuffer{};

            constexpr std::array<u32, 3> ids = {
                leaf::brand1,
                leaf::brand2,
                leaf::brand3
            };

            std::string brand = "";

            for (const u32 &id : ids) {
                cpuid(buffer.at(0), buffer.at(1), buffer.at(2), buffer.at(3), id);

                std::memcpy(charbuffer.data(), buffer.data(), buffer_size);

                const char* convert = charbuffer.data();
                brand += convert;
            }

            #ifdef __VMAWARE_DEBUG__
                debug("BRAND: ", "cpu brand = ", brand);
            #endif

            // TODO: might add more potential keywords, be aware that it could (theoretically) cause false positives
            constexpr std::array<const char*, 16> vmkeywords {
                "qemu", "kvm", "virtual", "vm", 
                "vbox", "virtualbox", "vmm", "monitor", 
                "bhyve", "hyperv", "hypervisor", "hvisor", 
                "parallels", "vmware", "hvm", "qnx"
            };

            u8 match_count = 0;

            for (std::size_t i = 0; i < vmkeywords.size(); i++) {
                const auto regex = std::regex(vmkeywords.at(i), std::regex::icase);
                const bool match = std::regex_search(brand, regex);
                
                #ifdef __VMAWARE_DEBUG__
                    if (match) {
                        debug("BRAND: ", "match = ", vmkeywords.at(i));
                    }
                #endif

                match_count += match;
            }

            #ifdef __VMAWARE_DEBUG__
                debug("BRAND: ", "matches: ", static_cast<u32>(match_count));
            #endif

            return (match_count >= 1);
        #endif
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("BRAND: catched error, returned false");
        #endif
        return false;
    }


    /**
     * @brief Check if hypervisor feature bit in CPUID is enabled (always false for physical CPUs)
     * @category x86
     */
    [[nodiscard]] static bool cpuid_hyperv() try {
        #if (!x86)
            return false;
        #else
            if (!cpuid_supported || disabled(HYPERV_BIT)) {
                #ifdef __VMAWARE_DEBUG__
                    debug("HYPERV_BIT: precondition return called");
                #endif
                return false;
            }

            u32 unused, ecx = 0;

            cpuid(unused, unused, ecx, unused, 1);

            return (ecx & (1 << 31));
        #endif
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("HYPERV_BIT: catched error, returned false");
        #endif
        return false;
    }


    /**
     * @brief Check if 0x40000000~0x400000FF cpuid input is present (mostly present in VMs, according to VMware)
     * @link https://kb.vmware.com/s/article/1009458
     * @category x86
     */
    [[nodiscard]] static bool cpuid_0x4() try {
        #if (!x86)
            return false;
        #else
            if (!cpuid_supported || disabled(CPUID_0x4)) {
                #ifdef __VMAWARE_DEBUG__
                    debug("CPUID_0X4: precondition return called");
                #endif
                return false;
            }

            u32 a, b, c, d = 0;

            for (u8 i = 0; i < 0xFF; i++) {
                cpuid(a, b, c, d, (leaf::hyperv + i));
                if ((a + b + c + d) != 0) {
                    return true;
                }
            }

            return false;
        #endif
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("CPUID_0x4: catched error, returned false");
        #endif
        return false;
    }


    /**
     * @brief Check for hypervisor brand string length (would be around 2 characters in a host machine)
     * @category x86
     */
    [[nodiscard]] static bool hyperv_brand() try {
        #if (!x86)
            return false;
        #else
            if (disabled(HYPERV_STR)) {
                #ifdef __VMAWARE_DEBUG__
                    debug("HYPERV_STR: precondition return called");
                #endif
                return false;
            }

            char out[sizeof(i32) * 4 + 1] = { 0 }; // e*x size + number of e*x registers + null terminator
            cpuid((int*)out, leaf::hyperv);

            #ifdef __VMAWARE_DEBUG__
                debug("HYPERV_STR: eax: ", static_cast<u32>(out[0]), 
                    "\nebx: ", static_cast<u32>(out[1]), 
                    "\necx: ", static_cast<u32>(out[2]), 
                    "\nedx: ", static_cast<u32>(out[3])
                );
            #endif

            return (std::strlen(out + 4) >= 4);
        #endif
    } catch (...) {
        #ifdef __VMAWARE_DEBUG__
            debug("HYPERV_STR: catched error, returned false");
        #endif
        return false;
    }


    /**
     * @brief Check if RDTSC is slow, if yes then it might be a VM
     * @category x86
     */
    [[nodiscard]] static bool rdtsc_check() try {
        #if (!x86)
            return false;
        #else
            if (disabled(RDTSC)) {
                #ifdef __VMAWARE_DEBUG__
                    debug("RDTSC: precondition return called");
                #endif
                return false;
            }

            #if (LINUX)
                u32 a, b, c, d = 0;

                if (!__get_cpuid(leaf::proc_ext, &a, &b, &c, &d)) {
                    if (!(d & (1 << 27))) { 
                        return false;
                    }
                }
                
                u64 s, acc = 0;
                i32 out[4];

                for (std::size_t i = 0; i < 100; ++i) {
                    s = __rdtsc();
                    cpuid(out, 0, 0);
                    acc += __rdtsc() - s;
                }

                #ifdef __VMAWARE_DEBUG__
                    debug("RDTSC: ", "acc = ", acc);
                    debug("RDTSC: ", "acc/100 = ", acc / 100);
                #endif

                return (acc / 100 > 350);
            #elif (MSVC)
                #define LODWORD(_qw)    ((DWORD)(_qw))
                u64 tsc1 = 0;
                u64 tsc2 = 0;
                u64 avg = 0;
                i32 cpuInfo[4] = {};
                for (INT i = 0; i < 10; i++) {
                    tsc1 = __rdtsc();
                    GetProcessHeap();
                    tsc2 = __rdtsc();
                    CloseHandle(0);
                    tsc3 = __rdtsc();
                    const bool conditon = ((LODWORD(tsc3) - LODWORD(tsc2)) / (LODWORD(tsc2) - LODWORD(tsc1)) >= 10);
                    if (condition) {
                        return false;
                    }
                }

                return true;
            #endif

            return false;
        #endif
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("RDTSC: catched error, returned false");
        #endif
        return false;
    }


    /**
     * @brief Check if the 5th byte after sidt is null
     * @author Matteo Malvica
     * @link https://www.matteomalvica.com/blog/2018/12/05/detecting-vmware-on-64-bit-systems/
     * @category x86
     */
    [[nodiscard]] static bool sidt5() try {
        #if (!x86 || !LINUX)
            return false;
        #else
            if (disabled(SIDT5)) {
                #ifdef __VMAWARE_DEBUG__
                    debug("SIDT5: ", "precondition return called");
                #endif
                return false;
            }

            u8 values[10];
            std::memset(values, 0, 10);

            fflush(stdout);
            __asm__ __volatile__("sidt %0" : "=m"(values));

            #ifdef __VMAWARE_DEBUG__
                u32 result = 0;

                for (u8 i = 0; i < 10; i++) {
                    result <<= 8;
                    result |= values[i];
                }

                debug("SIDT5: ", "values = 0x", std::hex, std::setw(16), std::setfill('0'), result);
            #endif

            return (values[5] == 0x00);
        #endif
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("SIDT5: catched error, returned false");
        #endif
        return false;
    }


    /**
     * @brief Check for vm presence using sidt instruction 
     * @todo: Check if this actually works
     * @author Unprotect
     * @link https://unprotect.it/technique/sidt-red-pill/
     * @category x86
     */
    [[nodiscard]] static bool sidt_check() try {
        return false; // TODO: REMOVE AFTER VERIFYING IF IT WORKS

/*
        #if (!x86 || !LINUX)
            return false;
        #else
            if (disabled(SIDT)) {
                #ifdef __VMAWARE_DEBUG__
                    debug("SIDT: ", "precondition return called");
                #endif
                return false;
            }

            u64 idtr = 0;

            __asm__ __volatile__(
                "sidt %0"
                : "=m" (idtr)
            );

            #ifdef __VMAWARE_DEBUG__
                debug("SIDT: ", "idtr = ", idtr);
            #endif

            return (idtr != 0);
        #endif
*/
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("SIDT: catched error, returned false");
        #endif
        return false;
    }


    /**
     * @brief Check if VMware port number 0x5658 is present
     * @todo Make better Linux-compatible GCC inline assembly code
     * @link https://kb.vmware.com/s/article/1009458
     * @category x86 Windows
     */
    [[nodiscard]] static bool vmware_port() try {
        #if (!x86)
            return false;
        #else
            if (disabled(VMWARE_PORT)) {
                #ifdef __VMAWARE_DEBUG__
                    debug("VMWARE_PORT: ", "precondition return called");
                #endif
                return false;
            }

            i32 is_vm = false;

            #if (LINUX)
/*
                u32 a, b, c, d = 0;

                constexpr u32 vmware_magic = 0x564D5868, // magic hypervisor ID
                            vmware_port  = 0x5658,     // hypervisor port number
                            vmware_cmd   = 10,         // Getversion command identifier
                            u32_max      = std::numeric_limits<u32>::max(); // max for u32, idk

                __asm__ __volatile__(
                    "pushq %%rdx\n\t"
                    "pushq %%rcx\n\t"
                    "pushq %%rbx\n\t"
                    "movl $0x564D5868, %%eax\n\t" // "VMXh"
                    "movb $0, %%bl\n\t"
                    "movb $10, %%cl\n\t"
                    "movl $0x5658, %%edx\n\t" // "VX"
                    "inl %%dx, %%eax\n\t"
                    "cmpl $0x564D5868, %%ebx\n\t"
                    "setz %0\n\t"
                    "popl %%ebx\n\t"
                    "popl %%ecx\n\t"
                    "popl %%edx\n\t"
                    //: "=a" (a), "=b" (b), "=c" (c), "=d" (d)
                    : "=r" (is_vm)
                    :
                    : "%eax"
                );
    
                or this:

                __asm__ __volatile__(
                    "inl (%%dx)"
                    : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                    : "0"(0x564D5868), "1"(10), "2"(0x5658), "3"(0xFFFFFFFF)
                    : "memory"
                );
*/

            #elif (MSVC)
                u16 ioports[] = { 'VX' , 'VY' };
                u16 ioport;
                for (u8 i = 0; i < _countof(ioports); ++i) {
                    ioport = ioports[i];
                    for (u8 cmd = 0; cmd < 0x2C; ++cmd) {
                        __try {
                            __asm {
                                push eax
                                push ebx
                                push ecx
                                push edx
                                mov eax, 'VMXh'
                                movzx ecx, cmd
                                mov dx, ioport
                                in eax, dx      // <- key point is here
                                pop edx
                                pop ecx
                                pop ebx
                                pop eax
                            }

                            is_vm = true;
                            break;
                        }
                        __except (EXCEPTION_EXECUTE_HANDLER) {
                            #ifdef __VMAWARE_DEBUG__
                                debug("VMWARE_PORT: exception encountered for inline assembly");
                            #endif
                        }
                    }

                    if (is_vm) {
                        break;
                    }
                }
            #endif

            if (is_vm) {
                scoreboard[VMWARE]++; 
                //scoreboard[VMWARE]++; // extra point bc it's incredibly VMware-specific, also it's not += 2 since that causes a linker error for some reason?
                return true;
            }

            return false;
        #endif
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("VMWARE_PORT: catched error, returned false");
        #endif
        return false;
    }


    /**
     * @brief Check if processor count is 1 or 2 (some VMs only have a single core)
     * @category All systems
     */
    [[nodiscard]] static bool thread_count() try {
        if (disabled(THREADCOUNT)) {
            #ifdef __VMAWARE_DEBUG__
                debug("THREADCOUNT: ", "precondition return called");
            #endif
            return false;
        }

        #ifdef __VMAWARE_DEBUG__
            debug("THREADCOUNT: ", "threads = ", std::thread::hardware_concurrency());
        #endif

        return (std::thread::hardware_concurrency() <= 2);
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("THREADCOUNT: catched error, returned false");
        #endif
        return false;
    }
    

    /**
     * @brief Check if mac address starts with certain VM designated values
     * @category All systems (I think)
     */
    [[nodiscard]] static bool mac_address_check() try {
        if (disabled(MAC)) {
            #ifdef __VMAWARE_DEBUG__
                debug("MAC: ", "precondition return called");
            #endif
            return false;
        }

        // C-style array on purpose
        u8 mac[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

        #if (LINUX)
            struct ifreq ifr;
            struct ifconf ifc;
            char buf[1024];
            i32 success = 0;

            i32 sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

            if (sock == -1) { 
                return false;
            };

            ifc.ifc_len = sizeof(buf);
            ifc.ifc_buf = buf;

            if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
                return false;
            }

            struct ifreq* it = ifc.ifc_req;
            const struct ifreq* end = it + (ifc.ifc_len / sizeof(struct ifreq));

            for (; it != end; ++it) {
                std::strcpy(ifr.ifr_name, it->ifr_name);

                if (ioctl(sock, SIOCGIFFLAGS, &ifr) != 0) { 
                    return false;
                }

                if (!(ifr.ifr_flags & IFF_LOOPBACK)) {
                    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                        success = 1;
                        break;
                    }
                }
            }

            if (success) { 
                std::memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
            } else {
                #ifdef __VMAWARE_DEBUG__
                    debug("MAC: ", "not successful");
                #endif
            }
        #elif (MSVC)
            PIP_ADAPTER_INFO AdapterInfo;
            DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);

            char *mac_addr = static_cast<char*>(std::malloc(18));

            AdapterInfo = (IP_ADAPTER_INFO *) std::malloc(sizeof(IP_ADAPTER_INFO));

            if (AdapterInfo == NULL) {
                free(mac_addr);
                return false;
            }

            if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
                std::free(AdapterInfo);
                AdapterInfo = (IP_ADAPTER_INFO *) std::malloc(dwBufLen);
                if (AdapterInfo == NULL) {
                    std::free(mac_addr);
                    return false;
                }
            }

            if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) {
                PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
                for (std::size_t i = 0; i < 6; i++) {
                    mac[i] = pAdapterInfo->Address[i];
                }
            }

            std::free(AdapterInfo);
        #endif

        #ifdef __VMAWARE_DEBUG__
            std::stringstream ss;
            ss << std::setw(2) << std::setfill('0') << std::hex
            << static_cast<i32>(mac[0]) << ":"
            << static_cast<i32>(mac[1]) << ":"
            << static_cast<i32>(mac[2]) << ":"
            << static_cast<i32>(mac[3]) << ":"
            << static_cast<i32>(mac[4]) << ":"
            << static_cast<i32>(mac[5]);
            debug("MAC: ", ss.str());
        #endif
        
        // better expression to fix code duplication
        auto compare = [=](const u8 mac1, const u8 mac2, const u8 mac3) noexcept -> bool {
            return (mac[0] == mac1 && mac[1] == mac2 && mac[2] == mac3);
        };

        if (compare(0x08, 0x00, 0x27)) {
            return add(VBOX);
        }

        if (
            (compare(0x00, 0x0C, 0x29)) ||
            (compare(0x00, 0x1C, 0x14)) ||
            (compare(0x00, 0x50, 0x56)) ||
            (compare(0x00, 0x05, 0x69))
        ) {
            return add(VMWARE);
        }

        if (compare(0x00, 0x16, 0xE3)) {
            return add(XEN);
        }

        if (compare(0x00, 0x1C, 0x42)) {
            return add(PARALLELS);
        }

        if (compare(0x0A, 0x00, 0x27)) {
            return add(HYBRID);
        }

        return false;
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("MAC: catched error, returned false");
        #endif
        return false;
    }


    /**
     * @brief Check if thermal directory is present, might not be present in VMs
     * @category Linux
     */
    [[nodiscard]] static bool temperature() try {
        #if (!LINUX)
            return false;
        #else
            if (disabled(TEMPERATURE)) {
                #ifdef __VMAWARE_DEBUG__
                    debug("TEMPERATURE: ", "precondition return called");
                #endif
                return false;
            }

            return (!exists("/sys/class/thermal/thermal_zone0/"));
        #endif
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("TEMPERATURE: catched error, returned false");
        #endif
        return false;
    }


    /**
     * @brief Check result from systemd-detect-virt tool
     * @category Linux
     */ 
    [[nodiscard]] static bool systemd_virt() try {
        #if (!LINUX)
            return false;
        #else
            if (disabled(SYSTEMD)) {
                #ifdef __VMAWARE_DEBUG__
                    debug("SYSTEMD: ", "precondition return called");
                #endif
                return false;
            }

            if (!(exists("/usr/bin/systemd-detect-virt") || exists("/bin/systemd-detect-virt"))) {
                #ifdef __VMAWARE_DEBUG__
                    debug("SYSTEMD: ", "binary doesn't exist");
                #endif
                return false;
            }

            const std::unique_ptr<std::string> result = sys_result("systemd-detect-virt");
            
            if (result == nullptr) {
                #ifdef __VMAWARE_DEBUG__
                    debug("SYSTEMD: ", "invalid stdout output from systemd-detect-virt");
                #endif
                return false;
            }

            #ifdef __VMAWARE_DEBUG__
                debug("SYSTEMD: ", "output = ", *result);
            #endif

            return (*result != "none");
        #endif
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("SYSTEMD: catched error, returned false");
        #endif
        return false;
    }


    /**
     * @brief Check if chassis vendor is a VM vendor
     * @category Linux
     */ 
    [[nodiscard]] static bool chassis_vendor() try {
        #if (!LINUX)
            return false;
        #else
            if (disabled(CVENDOR)) {
                #ifdef __VMAWARE_DEBUG__
                    debug("CVENDOR: ", "precondition return called");
                #endif
                return false;
            }

            const char* vendor_file = "/sys/devices/virtual/dmi/id/chassis_vendor";

            if (exists(vendor_file)) {
                const std::string vendor = read_file(vendor_file);

                // TODO: More can be definitely added, I only tried QEMU and VMware so far
                if (vendor == "QEMU") { return add(QEMU); }
                if (vendor == "Oracle Corporation") { return add(VMWARE); }

                #ifdef __VMAWARE_DEBUG__
                    debug("CVENDOR: ", "unknown vendor = ", vendor);
                #endif
            } else {
                #ifdef __VMAWARE_DEBUG__
                    debug("CVENDOR: ", "file doesn't exist");
                #endif
            }

            return false;
        #endif
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("CVENDOR: catched error, returned false");
        #endif
        return false;
    }


    /**
     * @brief Check if the chassis type is valid (it's very often invalid in VMs)
     * @category Linux
     */
    [[nodiscard]] static bool chassis_type() try {
        #if (!LINUX)
            return false;
        #else
            if (disabled(CTYPE)) {
                #ifdef __VMAWARE_DEBUG__
                    debug("CTYPE: ", "precondition return called");
                #endif
                return false;
            }

            const char* chassis = "/sys/devices/virtual/dmi/id/chassis_type";
            
            if (exists(chassis)) {
                return (stoi(read_file(chassis)) == 1);
            } else {
                #ifdef __VMAWARE_DEBUG__
                    debug("CTYPE: ", "file doesn't exist");
                #endif
            }

            return false;
        #endif
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("CTYPE: catched error, returned false");
        #endif
        return false;
    }


    /**
     * @brief Check if /.dockerenv or /.dockerinit file is present
     * @category Linux
     */
    [[nodiscard]] static bool dockerenv() try {
        #if (!LINUX)
            return false;
        #else
            if (disabled(DOCKERENV)) {
                #ifdef __VMAWARE_DEBUG__
                    debug("DOCKER: ", "precondition return called");
                #endif
                return false;
            }

            return (exists("/.dockerenv") || exists("/.dockerinit"));
        #endif
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("DOCKERENV: catched error, returned false");
        #endif
        return false;
    }


    /**
     * @brief Check if dmidecode output matches a VM brand
     * @category Linux
     */
    [[nodiscard]] static bool dmidecode() try {
        #if (!LINUX)
            return false;
        #else
            if (disabled(DMIDECODE) || (is_root() == false)) {
                #ifdef __VMAWARE_DEBUG__
                    debug("DMIDECODE: ", "precondition return called (root = ", is_root(), ")");
                #endif
                return false;
            }

            if (!(exists("/bin/dmidecode") || exists("/usr/bin/dmidecode"))) {
                #ifdef __VMAWARE_DEBUG__
                    debug("DMIDECODE: ", "binary doesn't exist");
                #endif
                return false;
            }
            
            const std::unique_ptr<std::string> result = sys_result("dmidecode -t system | grep 'Manufacturer|Product' | grep -c \"QEMU|VirtualBox|KVM\"");

            if (*result == "" || result == nullptr) {
                #ifdef __VMAWARE_DEBUG__
                    debug("DMIDECODE: ", "invalid output");
                #endif
                return false;
            } else if (*result == "QEMU") {
                return add(QEMU);
            } else if (*result == "VirtualBox") {
                return add(VBOX);
            } else if (*result == "KVM") {
                return add(KVM);
            } else if (std::atoi(result->c_str()) >= 1) {
                return true;
            } else {
                #ifdef __VMAWARE_DEBUG__
                    debug("DMIDECODE: ", "output = ", *result);
                #endif
            }

            return false;
        #endif
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("DMIDECODE: catched error, returned false");
        #endif
        return false;
    }


    /**
     * @brief Check if dmesg command output matches a VM brand
     * @category Linux
     */
    [[nodiscard]] static bool dmesg() try {
        #if (!LINUX || CPP <= 11)
            return false;
        #else
            if (disabled(DMESG)) {
                #ifdef __VMAWARE_DEBUG__
                    debug("DMESG: ", "precondition return called");
                #endif
                return false;
            }

            if (!exists("/bin/dmesg") && !exists("/usr/bin/dmesg")) {
                #ifdef __VMAWARE_DEBUG__
                    debug("DMESG: ", "binary doesn't exist");
                #endif
                return false;
            }

            const std::unique_ptr<std::string> result = sys_result("dmesg | grep -i hypervisor | grep -c \"KVM|QEMU\"");

            if (*result == "" || result == nullptr) {
                return false;
            } else if (*result == "KVM") {
                return add(KVM);
            } else if (*result == "QEMU") {
                return add(QEMU);
            } else if (std::atoi(result->c_str())) {
                return true;
            } else {
                #ifdef __VMAWARE_DEBUG__
                    debug("DMESG: ", "output = ", *result);
                #endif
            }

            return false;
        #endif
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("DMESG: catched error, returned false");
        #endif
        return false;
    }


    /**
     * @brief Check if /sys/class/hwmon/ directory is present. If not, likely a VM
     * @category Linux
     */
    [[nodiscard]] static bool hwmon() try {
        #if (!LINUX)
            return false;
        #else
            if (disabled(HWMON)) {
                #ifdef __VMAWARE_DEBUG__
                    debug("HWMON: ", "precondition return called");
                #endif
                return false;
            }

            return (!exists("/sys/class/hwmon/"));
        #endif
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("HWMON: catched error, returned false");
        #endif
        return false;
    }
    

    // [[nodiscard]] static bool dmi_check() try {
    //     char string[10];
    //     GET_BIOS_SERIAL(string);
    //     if (!memcmp(string, "VMware-", 7) || !memcmp(string, "VMW", 3)) { return true; }
    //     else { return false; }
    // } catch (...) { return false; }


    /**
     * @brief Check for tons of VM-specific registry values
     * @category Windows
     */
    [[nodiscard]] static bool registry_key() try {
        #if (!MSVC)
            return false;
        #else
            if (disabled(REGISTRY)) {
                #ifdef __VMAWARE_DEBUG__
                    debug("REGISTRY: ", "precondition return called");
                #endif
                return false;
            }

            u8 score = 0;

            auto key = [&score](const char* p_brand, const char* regkey_s) -> void {
                HKEY regkey;
                LONG ret;
                BOOL isWow64 = FALSE;

                if (IsWow64Process(GetCurrentProcess(), &isWow64) && isWow64) {
                    wchar_t wRegKey[MAX_PATH];
                    MultiByteToWideChar(CP_ACP, 0, regkey_s, -1, wRegKey, MAX_PATH);

                    ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, wRegKey, 0, KEY_READ | KEY_WOW64_64KEY, &regkey);
                }
                else {
                    wchar_t wRegKey[MAX_PATH];
                    MultiByteToWideChar(CP_ACP, 0, regkey_s, -1, wRegKey, MAX_PATH);

                    ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, wRegKey, 0, KEY_READ, &regkey);
                }

                if (ret == ERROR_SUCCESS) {
                    RegCloseKey(regkey);
                    score++;

                    if (std::string(p_brand) != "")
                    #if (CPP >= 20)
                        [[likely]]
                    #endif 
                    {
                        #ifdef __VMAWARE_DEBUG__
                            debug("REGISTRY: ", "detected = ", p_brand);
                        #endif
                        scoreboard[p_brand]++;
                    }
                }
            };

            // general
            key("", "HKLM\\Software\\Classes\\Folder\\shell\\sandbox");

            // hyper-v
            key("Microsoft Hyper-V", "HKLM\\SOFTWARE\\Microsoft\\Hyper-V");
            key("Microsoft Hyper-V", "HKLM\\SOFTWARE\\Microsoft\\VirtualMachine");
            key("Microsoft Hyper-V", "HKLM\\SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters");
            key("Microsoft Hyper-V", "HKLM\\SYSTEM\\ControlSet001\\Services\\vmicheartbeat");
            key("Microsoft Hyper-V", "HKLM\\SYSTEM\\ControlSet001\\Services\\vmicvss");
            key("Microsoft Hyper-V", "HKLM\\SYSTEM\\ControlSet001\\Services\\vmicshutdown");
            key("Microsoft Hyper-V", "HKLM\\SYSTEM\\ControlSet001\\Services\\vmicexchange");

            // parallels
            key("Parallels", "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_1AB8*");

            // sandboxie
            key("Sandboxie", "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SbieDrv");
            key("Sandboxie", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sandboxie");

            // virtualbox
            key("VirtualBox", "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_80EE*");
            key("VirtualBox", "HKLM\\HARDWARE\\ACPI\\DSDT\\VBOX__");
            key("VirtualBox", "HKLM\\HARDWARE\\ACPI\\FADT\\VBOX__");
            key("VirtualBox", "HKLM\\HARDWARE\\ACPI\\RSDT\\VBOX__");
            key("VirtualBox", "HKLM\\SOFTWARE\\Oracle\\VirtualBox Guest Additions");
            key("VirtualBox", "HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxGuest");
            key("VirtualBox", "HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxMouse");
            key("VirtualBox", "HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxService");
            key("VirtualBox", "HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxSF");
            key("VirtualBox", "HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxVideo");

            // virtualpc
            key("Virtual PC", "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_5333*");
            key("Virtual PC", "HKLM\\SYSTEM\\ControlSet001\\Services\\vpcbus");
            key("Virtual PC", "HKLM\\SYSTEM\\ControlSet001\\Services\\vpc-s3");
            key("Virtual PC", "HKLM\\SYSTEM\\ControlSet001\\Services\\vpcuhub");
            key("Virtual PC", "HKLM\\SYSTEM\\ControlSet001\\Services\\msvmmouf");

            // vmware
            key("VMware", "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_15AD*");
            key("VMware", "HKCU\\SOFTWARE\\VMware, Inc.\\VMware Tools");
            key("VMware", "HKLM\\SOFTWARE\\VMware, Inc.\\VMware Tools");
            key("VMware", "HKLM\\SYSTEM\\ControlSet001\\Services\\vmdebug");
            key("VMware", "HKLM\\SYSTEM\\ControlSet001\\Services\\vmmouse");
            key("VMware", "HKLM\\SYSTEM\\ControlSet001\\Services\\VMTools");
            key("VMware", "HKLM\\SYSTEM\\ControlSet001\\Services\\VMMEMCTL");
            key("VMware", "HKLM\\SYSTEM\\ControlSet001\\Services\\vmware");
            key("VMware", "HKLM\\SYSTEM\\ControlSet001\\Services\\vmci");
            key("VMware", "HKLM\\SYSTEM\\ControlSet001\\Services\\vmx86");
            key("VMware", "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\IDE\\CdRomNECVMWar_VMware_IDE_CD*");
            key("VMware", "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\IDE\\CdRomNECVMWar_VMware_SATA_CD*");
            key("VMware", "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\IDE\\DiskVMware_Virtual_IDE_Hard_Drive*");
            key("VMware", "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\IDE\\DiskVMware_Virtual_SATA_Hard_Drive*");

            // wine
            key("Wine", "HKCU\\SOFTWARE\\Wine");
            key("Wine", "HKLM\\SOFTWARE\\Wine");

            // xen
            key("Xen HVM", "HKLM\\HARDWARE\\ACPI\\DSDT\\xen");
            key("Xen HVM", "HKLM\\HARDWARE\\ACPI\\FADT\\xen");
            key("Xen HVM", "HKLM\\HARDWARE\\ACPI\\RSDT\\xen");
            key("Xen HVM", "HKLM\\SYSTEM\\ControlSet001\\Services\\xenevtchn");
            key("Xen HVM", "HKLM\\SYSTEM\\ControlSet001\\Services\\xennet");
            key("Xen HVM", "HKLM\\SYSTEM\\ControlSet001\\Services\\xennet6");
            key("Xen HVM", "HKLM\\SYSTEM\\ControlSet001\\Services\\xensvc");
            key("Xen HVM", "HKLM\\SYSTEM\\ControlSet001\\Services\\xenvdb");

            #ifdef __VMAWARE_DEBUG__
                debug("REGISTRY: ", "score = ", static_cast<u32>(score));
            #endif

            return (score >= 1);
        #endif
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("REGISTRY: catched error, returned false");
        #endif
        return false;
    }


    /**
     * @brief checks for default usernames, often a sign of a VM 
     * @author: some guy in a russian underground forum from a screenshot i saw, idk who he is but ty ¯\_(ツ)_/¯
     * @category Windows
     */ 
    [[nodiscard]] static bool user_check() try {     
        #if (!MSVC)
            return false;
        #else
            if (disabled(USER)) {
                #ifdef __VMAWARE_DEBUG__
                    debug("USER: ", "precondition return called");
                #endif
                return false;
            }

            TCHAR user[UNLEN+1];
            DWORD user_len = UNLEN+1;
            GetUserName((TCHAR*)user, &user_len);
            std::string u(user, user + user_len);

            #ifdef __VMAWARE_DEBUG__
                debug("USER: ", "output = ", u);
            #endif

            if (u == "username") {
                return add(THREADEXPERT);
            }
    
            return (
                (u == "USER") ||      // Sandbox
                (u == "user") ||      // Sandbox 2
                (u == "currentuser")  // Normal
            );
        #endif
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("USER: catched error, returned false");
        #endif
        return false;
    }


    /**
     * @brief Check if Sunbelt-specific file exists
     * @author same russian guy as above. Whoever you are, ty
     * @category Windows
     */
    [[nodiscard]] static bool sunbelt_check() try {
        #if (!MSVC)
            return false;
        #else
            if (disabled(SUNBELT)) {
                #ifdef __VMAWARE_DEBUG__
                    debug("SUNBELT: ", "precondition return called");
                #endif
                return false;
            }

            // Use wide string literal
            return exists(L"C:\\analysis");
        #endif
    } catch (...) {
        #ifdef __VMAWARE_DEBUG__
            debug("SUNBELT: catched error, returned false");
        #endif
        return false;
    }



    /**
     * @brief Check for VM-specific DLLs
     * @category Windows
     */
    [[nodiscard]] static bool DLL_check() try {
        #if (!MSVC)
            return false;
        #else
            if (disabled(DLL)) {
                #ifdef __VMAWARE_DEBUG__
                    debug("DLL: ", "precondition return called");
                #endif
                return false;
            }

            std::vector<const char*> real_dlls = {
                "kernel32.dll",
                "networkexplorer.dll",
                "NlsData0000.dll"
            };

            std::vector<const char*> false_dlls = {
                "NetProjW.dll",
                "Ghofr.dll",
                "fg122.dll"
            };

            HMODULE lib_inst;

            for (auto &dll : real_dlls) {
                lib_inst = LoadLibraryA(dll);
                if (lib_inst == nullptr) {
                    #ifdef __VMAWARE_DEBUG__
                        debug("DLL: ", "LIB_INST detected true for real dll = ", dll);
                    #endif
                    return true;
                }
                FreeLibrary(lib_inst);
            }

            for (auto &dll : false_dlls) {
                lib_inst = LoadLibraryA(dll);
                if (lib_inst != nullptr) {
                    #ifdef __VMAWARE_DEBUG__
                        debug("DLL: ", "LIB_INST detected true for false dll = ", dll);
                    #endif
                    return true;
                }
            }

            return false;
        #endif
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("DLL: catched error, returned false");
        #endif
        return false;
    }


    /**
     * @brief Check VBox RdrDN
     * @category Windows 
     */
    [[nodiscard]] static bool vbox_registry() try {
        #if (!MSVC)
            return false;
        #else
            if (disabled(VBOX_REG)) {
                #ifdef __VMAWARE_DEBUG__
                    debug("VBOX_REG: ", "precondition return called");
                #endif
                return false;
            }

            HANDLE handle = CreateFile(_T("\\\\.\\VBoxMiniRdrDN"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

            if (handle != INVALID_HANDLE_VALUE) {
                CloseHandle(handle);
                return add(VBOX);
            }

            return false;
        #endif
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("VBOX_REG: catched error, returned false");
        #endif
        return false;
    }


    /**
     * @brief Find VMware tools presence
     * @todo FIX THIS SHIT
     * @category Windows
     */
    [[nodiscard]] static bool vmware_registry() try {
        #if (!MSVC)
            return false;
        #else
            if (disabled(VMWARE_REG)) {
                #ifdef __VMAWARE_DEBUG__
                    debug("VMWARE_REG: ", "precondition return called");
                #endif
                return false;
            }

            HKEY hKey;
            // Use wide string literal
            bool result = (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS);

            #ifdef __VMAWARE_DEBUG__
                debug("VMWARE_REG: result = ", result);
            #endif

            if (result == true) {
                return add(VMWARE);
            }

            return result;
        #endif
    } catch (...) {
        #ifdef __VMAWARE_DEBUG__
            debug("VMWARE_REG: catched error, returned false");
        #endif
        return false;
    }



    /**
     * @brief Check if the mouse coordinates have changed after 5 seconds
     * @note Some VMs are automatic without a human due to mass malware scanning being a thing
     * @note Disabled by default due to performance reasons
     * @note Doing this on linux is a major pain bc it requires X11 linkage and it isn't universally supported
     * @category Windows
     */
    [[nodiscard]] static bool cursor_check() try {
        #if (!MSVC)
            return false;
        #else
            if (disabled(CURSOR)) {
                #ifdef __VMAWARE_DEBUG__
                    debug("CURSOR: ", "precondition return called");
                #endif
                return false;
            }

            POINT pos1, pos2;
            GetCursorPos(&pos1);

            #ifdef __VMAWARE_DEBUG__
                debug("CURSOR: pos1.x = ", pos1.x);
                debug("CURSOR: pos1.y = ", pos1.y);
                debug("CURSOR: pos2.x = ", pos2.x);
                debug("CURSOR: pos2.y = ", pos2.y);
            #endif
            
            Sleep(5000);
            GetCursorPos(&pos2);

            #ifdef __VMAWARE_DEBUG__
                debug("CURSOR: pos1.x = ", pos1.x);
                debug("CURSOR: pos1.y = ", pos1.y);
                debug("CURSOR: pos2.x = ", pos2.x);
                debug("CURSOR: pos2.y = ", pos2.y);
            #endif

            return ((pos1.x == pos2.x) && (pos1.y == pos2.y));
        #endif
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("CURSOR: catched error, returned false");
        #endif
        return false; 
    }


    /**
     * @brief Check wine_get_unix_file_name file for Wine
     * @author pafish project
     * @link https://github.com/a0rtega/pafish/blob/master/pafish/wine.c
     * @category Windows
     */
    [[nodiscard]] static bool wine() try {
        #if (!MSVC)
            return false;
        #else
            if (disabled(WINE_CHECK)) {
                #ifdef __VMAWARE_DEBUG__
                    debug("WINE: ", "precondition return called");
                #endif
                return false;
            }

            HMODULE k32;
            k32 = GetModuleHandle(TEXT("kernel32.dll"));

            if (k32 != NULL) {
                return (GetProcAddress(k32, "wine_get_unix_file_name") != NULL);
            } 

            return false;
        #endif
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("WINE_CHECK: catched error, returned false");
        #endif
        return false;
    }


    /**
     * @brief Check boot-time 
     * @todo: finish the linux part tomorrow
     * @category All systems
     */ 
    [[nodiscard]] static bool boot_time() try {
        if (disabled(BOOT)) {
            #ifdef __VMAWARE_DEBUG__
                debug("BOOT: ", "precondition return called");
            #endif
            return false;
        }

        #if (MSVC)
            // doesn't work for some reason, fix this whenever i have time
            /*
            SYSTEM_TIME_OF_DAY_INFORMATION  SysTimeInfo;
            LARGE_INTEGER LastBootTime;
            
            NtQuerySystemInformation(SystemTimeOfDayInformation, &SysTimeInfo, sizeof(SysTimeInfo), 0);
            LastBootTime = wmi_Get_LastBootTime();
            return ((wmi_LastBootTime.QuadPart - SysTimeInfo.BootTime.QuadPart) / 10000000 != 0); // 0 seconds
            */
        #elif (LINUX)
            // TODO: finish this shit tomorrow
            //https://stackoverflow.com/questions/349889/how-do-you-determine-the-amount-of-linux-system-ram-in-c
        #endif

        return false;
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("BOOT: catched error, returned false");
        #endif
        return false;
    }


    /**
     * @brief Find for VMware and VBox specific files
     * @category Windows
     */
    [[nodiscard]] static bool vm_files() try {
        #if (!MSVC)
            return false;
        #else
            if (disabled(VM_FILES)) {
                #ifdef __VMAWARE_DEBUG__
                    debug("VMFILES: ", "precondition return called");
                #endif
                return false;
            }

            // points
            u8 vbox = 0;
            u8 vmware = 0;

            constexpr std::array<const wchar_t*, 26> files = {
                // VMware
                L"C:\\windows\\System32\\Drivers\\Vmmouse.sys",
                L"C:\\windows\\System32\\Drivers\\vm3dgl.dll",
                L"C:\\windows\\System32\\Drivers\\vmdum.dll",
                L"C:\\windows\\System32\\Drivers\\VmGuestLibJava.dll",
                L"C:\\windows\\System32\\Drivers\\vm3dver.dll",
                L"C:\\windows\\System32\\Drivers\\vmtray.dll",
                L"C:\\windows\\System32\\Drivers\\VMToolsHook.dll",
                L"C:\\windows\\System32\\Drivers\\vmGuestLib.dll",
                L"C:\\windows\\System32\\Drivers\\vmhgfs.dll",

                // VBox
                L"C:\\windows\\System32\\Drivers\\VBoxMouse.sys",
                L"C:\\windows\\System32\\Drivers\\VBoxGuest.sys",
                L"C:\\windows\\System32\\Drivers\\VBoxSF.sys",
                L"C:\\windows\\System32\\Drivers\\VBoxVideo.sys",
                L"C:\\windows\\System32\\vboxoglpackspu.dll",
                L"C:\\windows\\System32\\vboxoglpassthroughspu.dll",
                L"C:\\windows\\System32\\vboxservice.exe",
                L"C:\\windows\\System32\\vboxoglcrutil.dll",
                L"C:\\windows\\System32\\vboxdisp.dll",
                L"C:\\windows\\System32\\vboxhook.dll",
                L"C:\\windows\\System32\\vboxmrxnp.dll",
                L"C:\\windows\\System32\\vboxogl.dll",
                L"C:\\windows\\System32\\vboxtray.exe",
                L"C:\\windows\\System32\\VBoxControl.exe",
                L"C:\\windows\\System32\\vboxoglerrorspu.dll",
                L"C:\\windows\\System32\\vboxoglfeedbackspu.dll",
            };

            for (const auto file : files) {
                if (exists(file)) {
                    const auto regex = std::wregex(file, std::regex::icase);

                    if (std::regex_search(L"vbox", regex)) {
                        #ifdef __VMAWARE_DEBUG__
                            debug("VM_FILES: found vbox file = ", file);
                        #endif
                        vbox++;
                    } else {
                        #ifdef __VMAWARE_DEBUG__
                            debug("VM_FILES: found vmware file = ", file);
                        #endif
                        vmware++;
                    }
                }
            }


            #ifdef __VMAWARE_DEBUG__
                debug("VM_FILES: vmware score: ", vmware);
                debug("VM_FILES: vbox score: ", vbox);
            #endif

            if (vbox > vmware) {
                return add(VBOX);
            } else if (vbox < vmware) {
                return add(VMWARE);
            } else if (vbox == vmware) {
                return true;
            }

            return false;
        #endif
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("VM_FILES: catched error, returned false");
        #endif
        return false;
    }


    /**
     * @brief Check for sysctl hardware model
     * @author MacRansom ransomware
     * @todo TEST IF THIS WORKS
     * @category MacOS
     */ 
    [[nodiscard]] static bool hwmodel() try {
        #if (!APPLE)
            return false;
        #else
            if (disabled(HWMODEL)) {
                #ifdef __VMAWARE_DEBUG__
                    debug("HWMODEL: ", "precondition return called");
                #endif
                return false;
            }

            auto result = sys_result("sysctl -n hw.model");

            std::smatch match;

            if (result == nullptr) {
                #ifdef __VMAWARE_DEBUG__
                    debug("HWMODEL: ", "null result received");
                #endif
                return false;
            }

            #ifdef __VMAWARE_DEBUG__
                debug("HWMODEL: ", "output = ", *result);
            #endif

            // if string contains "Mac" anywhere in the string, assume it's baremetal
            if (std::regex_search(*result, match, std::regex("Mac"))) {
                return false;
            }

            // not sure about the other VMs, more could potentially be added
            if (std::regex_search(*result, match, std::regex("VMware"))) {
                return add(VMWARE);
            }

            return true;
        #endif
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("HWMODEL: catched error, returned false");
        #endif
        return false;
    }


    /**
     * @brief Check if disk size is too low
     * @category Linux (for now)
     */
     [[nodiscard]] static bool disk_size() try {
        #if (!LINUX)
            return false;
        #else
            if (disabled(DISK_SIZE)) {
                #if __VMAWARE_DEBUG__
                    debug("DISK_SIZE: ", "precondition return called");
                #endif
                return false;
            }

            const u32 size = get_disk_size();

            #ifdef __VMAWARE_DEBUG__
                debug("DISK_SIZE: size = ", size);
            #endif

            return (size <= 60); // in GB
        #endif
     } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("DISK_SIZE: catched error, returned false");
        #endif
        return false;
    }


    /**
     * @brief Check for match with default RAM and disk size (VBOX-specific)
     * @note        RAM     DISK
     * WINDOWS 11:  4096MB, 80GB
     * WINDOWS 10:  2048MB, 50GB
     * ARCH, OPENSUSE, REDHAD, GENTOO, FEDORA, DEBIAN: 1024MB, 8GB
     * UBUNTU:      1028MB, 10GB
     * ORACLE:      1024MB, 12GB
     * OTHER LINUX: 512MB,  8GB
     
     * @todo: check if it still applies to host systems with larger RAM and disk size than what I have
     * @category Linux, Windows
     */
    [[nodiscard]] static bool vbox_default_specs() try {
        if (disabled(VBOX_DEFAULT)) {
            return false;
        }

        const u32 disk = get_disk_size();
        const u64 ram = get_physical_ram_size();

        #ifdef __VMAWARE_DEBUG__
            debug("VBOX_DEFAULT: disk = ", disk);
            debug("VBOX_DEFAULT: ram = ", ram);
        #endif

        if ((disk > 80) || (ram > 4)) {
            #ifdef __VMAWARE_DEBUG__
                debug("VBOX_DEFAULT: returned false due to lack of precondition spec comparisons");
            #endif
            return false;
        }
 
        #if (LINUX)
            auto get_distro = []() -> std::string {
                std::ifstream osReleaseFile("/etc/os-release");
                std::string line;
                
                while (std::getline(osReleaseFile, line)) {
                    if (line.find("ID=") != std::string::npos) {
                        const std::size_t start = line.find('"');
                        const std::size_t end = line.rfind('"');
                        if (start != std::string::npos && end != std::string::npos && start < end) {
                            return line.substr(start + 1, end - start - 1);
                        }
                    }
                }

                return "unknown";
            };

            const std::string distro = get_distro();

            #ifdef __VMAWARE_DEBUG__
                debug("VBOX_DEFAULT: linux, detected distro: ", distro);
            #endif

            // yoda notation ftw
            if ("unknown" == distro) {
                return false;
            }

            if (
                "arch" == distro ||
                "opensuse" == distro ||
                "redhat" == distro ||
                "gentoo" == distro ||
                "fedora" == distro ||
                "debian" == distro
            ) {
                return ((8 == disk) && (1 == ram));
            }
            
            if ("ubuntu" == distro) {
                return ((10 == disk) && (1 == ram));
            }

            if ("ol" == distro) { // ol = oracle
                return ((12 == disk) && (1 == ram));
            }
        #elif (MSVC)
            double ret = 0.0;
            NTSTATUS(WINAPI *RtlGetVersion)(LPOSVERSIONINFOEXW);
            OSVERSIONINFOEXW osInfo;

            HMODULE ntdllModule = GetModuleHandleA("ntdll");

            if (ntdllModule == nullptr) {
                return false;
            }

            *(FARPROC*)&RtlGetVersion = GetProcAddress(ntdllModule, "RtlGetVersion");

            if (NULL == RtlGetVersion) {
                return false;
            }

            // Note: At this point, RtlGetVersion may be uninitialized if the previous block failed

            if (NULL != RtlGetVersion) {
                osInfo.dwOSVersionInfoSize = sizeof(osInfo);
                RtlGetVersion(&osInfo);
                ret = static_cast<double>(osInfo.dwMajorVersion);
            }
            
            // less than windows 10
            if (ret < 10) {
                #ifdef __VMAWARE_DEBUG__
                    debug("VBOX_DEFAULT: less than windows 10 detected");
                #endif
                return false;
            }

            // windows 10
            if (10 == ret) {
                #ifdef __VMAWARE_DEBUG__
                    debug("VBOX_DEFAULT: windows 10 detected");
                #endif
                return ((50 == disk) && (2 == ram));
            }

            // windows 11
            if (11 == ret) {
                #ifdef __VMAWARE_DEBUG__
                    debug("VBOX_DEFAULT: windows 11 detected");
                #endif
                return ((80 == disk) && (4 == ram));
            }
        #endif

        return false;
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("VBOX_DEFAULT: catched error, returned false");
        #endif
        return false;
    }

    /**
     * @brief check if there are any user inputs
     * 
     * 
     */
    /*
    [[nodiscard]] static bool user_input() try {
        if (disabled(VBOX_DEFAULT)) {
            return false;
        }
        
        Sleep(30000);

        DWORD ticks = GetTickCount();

        LASTINPUTINFO li;
        li.cbSize = sizeof(LASTINPUTINFO);
        BOOL res = GetLastInputInfo(&li);

        return (ticks - li.dwTime > 6000);
    } catch (...) { return false; }
    */


   /**
    * @brief Check VBox network provider string
    * @todo fix WNetGetProviderName linker error
   */
    [[nodiscard]] static bool vbox_network_share() try {
        return false;
        /*

        if (disabled(VBOX_NETWORK)) {
            return false;
        }

        #if (!MSVC)
            return false;
        #else
            u32 pnsize = 0x1000;
            char* provider = new char[pnsize];

            i32 retv = WNetGetProviderName(WNNC_NET_RDR2SAMPLE, provider, &pnsize);
    
            if (retv == NO_ERROR) {
                return (lstrcmpi(provider, "VirtualBox Shared Folders") == 0);
            }

            return FALSE;
        #endif
        */
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("VBOX_NETWORK: catched error, returned false");
        #endif
        return false;
    }


    /**
     * @brief Check if the computer name (not username to be clear) is VM-specific
     * @category Windows
     * @author InviZzzible project
    */
    [[nodiscard]] static bool computer_name_match() try {
        if (disabled(COMPUTER_NAME)) {
            return false;
        }

        #if (!MSVC)
            return false;
        #else
            auto out_length = MAX_PATH;
            std::vector<u8> comp_name(out_length, 0);
            GetComputerNameA((LPSTR)comp_name.data(), (LPDWORD)&out_length);

            auto compare = [&](const std::string &s) -> bool {
                return (std::strcmp((LPCSTR)comp_name.data(), s.c_str()) == 0);
            };

            #ifdef __VMAWARE_DEBUG__
                debug("COMPUTER_NAME: fetched = ", (LPCSTR)comp_name.data());
            #endif

            if (compare("InsideTm") || compare("TU-4NH09SMCG1HC")) { // anubis
                #ifdef __VMAWARE_DEBUG__
                    debug("COMPUTER_NAME: detected Anubis");
                #endif

                return add(ANUBIS);
            }

            if (compare("klone_x64-pc") || compare("tequilaboomboom")) { // general
                #ifdef __VMAWARE_DEBUG__
                    debug("COMPUTER_NAME: detected general (VM but unknown)");
                #endif

                return true;
            }

            return false;
        #endif
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("COMPUTER_NAME: catched error, returned false");
        #endif

        return false;
    }


    /**
     * @brief Check if hostname is specific
     * @author InviZzzible project
     * @category Windows
     */
    [[nodiscard]] static bool hostname_match() try {
        if (disabled(HOSTNAME)) {
            return false;
        }

        #if (!MSVC)
            return false;
        #else
            auto out_length = MAX_PATH;
            std::vector<u8> dns_host_name(out_length, 0);
            GetComputerNameExA(ComputerNameDnsHostname, (LPSTR)dns_host_name.data(), (LPDWORD)&out_length);

            #ifdef __VMAWARE_DEBUG__
                debug("HOSTNAME: ", (LPCSTR)dns_host_name.data());
            #endif

            return (!lstrcmpiA((LPCSTR)dns_host_name.data(), "SystemIT"));
        #endif
    } catch (...) {
        #ifdef __VMAWARE_DEBUG__
            debug("HOSTNAME: catched error, returned false");
        #endif

        return false;
    }


    /**
     * @brief Check if memory is too low
     * @author Al-Khaser project
     * @category x86?
    */
    [[nodiscard]] static bool low_memory_space() try {
        if (disabled(MEMORY)) {
            return false;
        }

        constexpr u64 min_ram_1gb = (1024LL * (1024LL * (1024LL * 1LL)));
        const u64 ram = get_memory_space();

        #ifdef __VMAWARE_DEBUG__
            debug("MEMORY: ram size (GB) = ", ram);
            debug("MEMORY: minimum ram size (GB) = ", min_ram_1gb);
        #endif

        return (ram < min_ram_1gb);
    } catch (...) { 
        #ifdef __VMAWARE_DEBUG__
            debug("MEMORY: catched error, returned false");
        #endif
        return false; 
    }


    /**
     * @brief Check for any VM processes that are active
     * @category Windows
     */
    [[nodiscard]] static bool vm_processes() try {
        if (disabled(VM_PROCESSES)) {
            return false;
        }

        #if (!MSVC)
            return false;
        #else
            auto check_proc = [](const char* proc) -> bool {
                HANDLE hSnapshot;
                PROCESSENTRY32 pe = {};

                pe.dwSize = sizeof(pe);
                bool present = false;
                hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

                if (hSnapshot == INVALID_HANDLE_VALUE) {
                    return false;
                }

                if (Process32First(hSnapshot, &pe)) {
                    do {
                        // Use strcmp for narrow string comparison
                        if (strcmp(pe.szExeFile, proc) == 0) {
                            present = true;
                            break;
                        }
                    } while (Process32Next(hSnapshot, &pe));
                }

                CloseHandle(hSnapshot);

                return present;
            };

            auto ret = [](const char* str) -> bool {
                #ifdef __VMAWARE_DEBUG__
                    debug("VM_PROCESSES: found ", str);
                #endif
                return add(str);
            };

            if (check_proc("joeboxserver.exe") || check_proc("joeboxcontrol.exe")) {
                return ret(JOEBOX);
            }

            if (check_proc("prl_cc.exe") || check_proc("prl_tools.exe")) {
                return ret(PARALLELS);
            }

            if (check_proc("vboxservice.exe") || check_proc("vboxtray.exe")) {
                return ret(VBOX);
            }

            if (check_proc("vmsrvc.exe") || check_proc("vmusrvc.exe")) {
                return ret(VPC);
            }

            if (
                check_proc("vmtoolsd.exe") ||
                check_proc("vmacthlp.exe") ||
                check_proc("vmwaretray.exe") ||
                check_proc("vmwareuser.exe") ||
                check_proc("vmware.exe") ||
                check_proc("vmount2.exe")
                ) {
                return ret(VMWARE);
            }

            if (check_proc("xenservice.exe") || check_proc("xsvc_depriv.exe")) {
                return ret(XEN);
            }

            return false;
        #endif
    } catch (...) {
        #ifdef __VMAWARE_DEBUG__
            debug("VM_PROCESSES: caught error, returned false");
        #endif
        return false;
    }


    /**
     * @brief Check for default VM username and hostname for linux
     * @category Linux
     */ 
    [[nodiscard]] static bool linux_user_host() try {
        if (disabled(LINUX_USER_HOST)) {
            return false;
        }

        #if (!LINUX)
            return false;
        #else
            const char* username = std::getenv("USER");
            const char* hostname = std::getenv("HOSTNAME");

            #ifdef __VMAWARE_DEBUG__
                debug("LINUX_USER_HOST: user = ", username);
                debug("LINUX_USER_HOST: host = ", hostname);
            #endif

            return (
                (strcmp(username, "liveuser") == 0) &&
                (strcmp(hostname, "localhost-live") == 0)
            );
        #endif
    } catch (...) {
        #ifdef __VMAWARE_DEBUG__
            debug("LINUX_USER_HOST: catched error, returned false");
        #endif
        return false; 
    }


    /**
     * @brief default vbox window class
     * @category Windows
     * @author Al-Khaser Project
     */
    [[nodiscard]] static bool vbox_window_class() try {
        if (disabled(VBOX_WINDOW_CLASS)) {
            return false;
        }

        #if (!MSVC)
            return false;
        #else
            HWND hClass = FindWindow(_T("VBoxTrayToolWndClass"), NULL);
            HWND hWindow = FindWindow(NULL, _T("VBoxTrayToolWnd"));

            if (hClass || hWindow) {
                return add(VBOX);
            }

            return false;
        #endif
    } catch (...) {
        #ifdef __VMAWARE_DEBUG__
            debug("VBOX_WINDOW_CLASS: catched error, returned false");
        #endif
        return false;
    }


    /**
     * @brief get top-level default window level
     * @category Windows
     */
    [[nodiscard]] static bool windows_number() try {
        return false; // TODO: FIX THIS SHIT
        /*
        if (disabled(WINDOWS_NUMBER)) {
            return false;
        }

        #if (!MSVC) 
            return false;
        #else
            // this definitely doesn't fucking work
            auto enumProc = [](HWND, LPARAM lParam) -> bool
            {
                if (LPDWORD pCnt = reinterpret_cast<LPDWORD>(lParam))
                    *pCnt++;
                return true;
            };

            DWORD winCnt = 0;

            if (!EnumWindows(enumProc,LPARAM(&winCnt))) {
                #ifdef __VMAWARE_DEBUG__
                    debug("WINDOWS_NUMBER: EnumWindows() failed");
                #endif
                return false;
            }

            return (winCnt < 10);
        #endif
        */
    } catch (...) {
        #ifdef __VMAWARE_DEBUG__
            debug("WINDOWS_NUMBER: catched error, returned false");
        #endif
        return false;
    }


    /**
     * @brief Gamarue ransomware check
     * @category Windows 
     */
    [[nodiscard]] static bool gamarue() try {
        return false; // testing for segfault
        /*
        if (disabled(GAMARUE)) {
            return false;
        }

        #if (!MSVC) 
            return false;
        #else
            HKEY hOpen;
            char *szBuff;
            int iBuffSize;
            HANDLE hMod;
            LONG nRes;

            szBuff = (char*)calloc(512, sizeof(char));

            hMod = GetModuleHandle("SbieDll.dll"); // Sandboxie
            if (hMod != 0) {
                free(szBuff);
                return add(SANDBOXIE); 
            }

            hMod = GetModuleHandle("dbghelp.dll"); // Thread Expert
            if (hMod != 0) {
                free(szBuff);
                return add(THREADEXPERT);
            }

            nRes = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion", 0L, KEY_QUERY_VALUE, &hOpen);
            if (nRes == ERROR_SUCCESS) {
                iBuffSize = sizeof(szBuff);
                nRes = RegQueryValueEx(hOpen, "ProductId", NULL, NULL, (unsigned char*)szBuff, reinterpret_cast<LPDWORD>(&iBuffSize));
                if (nRes == ERROR_SUCCESS) {
                    if (strcmp(szBuff, "55274-640-2673064-23950") == 0) { // joebox
                        free(szBuff);
                        return add(JOEBOX);
                    } else if (strcmp(szBuff, "76487-644-3177037-23510") == 0) {
                        free(szBuff);
                        return add(CWSANDBOX); // CW Sandbox
                    } else if (strcmp(szBuff, "76487-337-8429955-22614") == 0) { // anubis
                        free(szBuff);
                        return add(ANUBIS);
                    } else {
                        free(szBuff);
                        return false;
                    }
                }
                RegCloseKey(hOpen);
            }
            free(szBuff);
            return false;
        #endif
        */
    } catch (...) {
        #ifdef __VMAWARE_DEBUG__
            debug("GAMARUE: catched error, returned false");
        #endif
        return false;
    }


    // __LABEL  (ignore this, it's just a label so I can easily teleport to this line on my IDE with CTRL+F)


    struct technique {
        u8 points; 
        bool(*ptr)(); // function pointer
    };

    // the points are debatable, but I think it's fine how it is. Feel free to disagree.
    static const std::map<u64, technique> table;

public:
    /**
     * @brief Check for a specific technique based on flag argument
     * @param u64 (flags from VM wrapper)
     * @return bool
     * @link https://github.com/kernelwernel/VMAware/blob/main/docs/documentation.md#vmcheck
     */
    [[nodiscard]] static bool check(const u64 p_flags = 0ULL) {
        i32 count = 0;

        #if (CPP >= 20 && !MSVC)
            count = std::popcount(p_flags);
        #elif (CPP >= 14 && !MSVC)
            count = std::__popcount(p_flags);
        #else 
            // compiler will optimise this with the x86 popcnt instruction (I hope)
            for (u64 tmp = p_flags; tmp != 0; count++) {
                tmp = (tmp & (tmp - 1));
            }
        #endif

        if (p_flags == ALL) {
            throw std::invalid_argument("Flag argument cannot be set to VM::ALL, consult the documentation's flag list");            
        }

        if (count > 1) {
            throw std::invalid_argument("Flag argument must only contain a single option, consult the documentation's flag list");
        }

        if (count == 0) {
            throw std::invalid_argument("Flag argument must contain at least a single option, consult the documentation's flag list");
        }

        if (p_flags & NO_MEMO) {
            throw std::invalid_argument("Flag argument must be a technique flag and not a settings flag, consult the documentation's flag list");
        }

        // count should only have a single flag at this stage
        assert(count == 1);

        // temporarily enable all flags so that every technique is enabled
        const u64 tmp_flags = VM::flags;
        VM::flags = (DEFAULT | CURSOR);

        bool result = false;

        auto it = table.find(p_flags);

        if (it == table.end()) {
            throw std::invalid_argument("Flag is not known, consult the documentation's flag list");
        }

        const technique &pair = it->second;
        result = pair.ptr();

        VM::flags = tmp_flags;

        return result;
    }


    /**
     * @brief Fetch the VM brand
     * @return std::string
     * @returns VMware, VirtualBox, KVM, bhyve, QEMU, Microsoft Hyper-V, Microsoft x86-to-ARM, Parallels, Xen HVM, ACRN, QNX hypervisor, Hybrid Analysis, Sandboxie, Docker, Wine, Virtual Apple, Virtual PC, Unknown
     * @link https://github.com/kernelwernel/VMAware/blob/main/docs/documentation.md#vmbrand
     */
    [[nodiscard]] static std::string brand(void) {
        // check if result hasn't been memoized already
        if (memo.find(true) == memo.end()) {
            #ifdef __VMAWARE_DEBUG__
                debug("memoization: detect() called in brand");
            #endif
            detect();
        }

        // check if no VM was detected
        if (memo[true].first == false) {
            return UNKNOWN;
        }

        return (std::string(memo[true].second));
    }


    /**
     * @brief Detect if running inside a VM
     * @param u64 (any combination of flags in VM wrapper, can be optional)
     * @return bool
     * @link https://github.com/kernelwernel/VMAware/blob/main/docs/documentation.md#vmdetect
     */
    static bool detect(const u64 p_flags = DEFAULT) {
        /**
         * load memoized value if it exists from a previous
         * execution of VM::detect(). This can save around
         * 5~10x speed depending on the circumstances.
         */
        if (
            disabled(NO_MEMO) && \
            memo.find(true) != memo.end()
        ) {
            #ifdef __VMAWARE_DEBUG__
                debug("memoization: returned cached result in detect()");
            #endif
            return memo[true].first;
        }

        // set local variables within struct scope
        VM::flags = p_flags;

        u8 points = 0;

        #ifdef __VMAWARE_DEBUG__
            debug("cpuid: is supported? : ", VM::cpuid_supported);
        #endif
    
        // invoke every technique in the table and add points for techniques detecting a VM
        for (auto it = table.cbegin(); it != table.cend(); ++it) {
            const technique &pair = it->second;
            if (pair.ptr()) { // equivalent to std::invoke, not used bc of C++11 compatibility
                points += pair.points;
            };
        }

        // threshold score
        const bool result = (points >= 100);

        const char* current_brand = "";

        // fetch the brand with the most points in the scoreboard
        #if (CPP >= 20)
            // get the highest score from the scoreboard
            auto it = std::ranges::max_element(scoreboard, {},
                [](const auto &pair) {
                    return pair.second;
                }
            );

            // find potential VM brand
            if (it != scoreboard.end()) {
                if (
                    // if all of the scores are 0
                    std::none_of(scoreboard.cbegin(), scoreboard.cend(),
                        [](const auto &pair) {
                            return pair.second;
                        }
                    )
                ) {
                    current_brand = UNKNOWN;
                } else {
                    current_brand = it->first;
                }
            } else {
                current_brand = UNKNOWN;
            }
        #else
            #if (MSVC)
                int max = 0;
            #else
                u8 max = 0;
            #endif

            for (auto it = scoreboard.cbegin(); it != scoreboard.cend(); ++it) {
                if (it->second > max) {
                    current_brand = it->first;
                    max = it->second;
                }
            }

            if (max == 0) {
                current_brand = UNKNOWN;
            }
        #endif

        #ifdef __VMAWARE_DEBUG__
            for (const auto p : scoreboard) {
                debug("scoreboard: ", (int)p.second, " : ", p.first);
            }
        #endif

        // memoize the result in case VM::detect() is executed again
        if (disabled(NO_MEMO)) {
            memo[true].first = result;
            memo[true].second = current_brand;
        }

        return result;
    }
};


// ============= EXTERNAL DEFINITIONS =============
// These are added here due to warnings related to C++17 inline variables for C++ standards that are under 17.
// It's easier to just group them together rather than having C++17<= preprocessors with inline stuff

#if (MSVC)
    std::map<const char*, int> VM::scoreboard {
#else
    std::map<const char*, VM::u8> VM::scoreboard {
#endif
    { VM::VMWARE, 0 },
    { VM::VBOX, 0 },
    { VM::KVM, 0 },
    { VM::BHYVE, 0 },
    { VM::QEMU, 0 },
    { VM::HYPERV, 0 },
    { VM::MSXTA, 0 },
    { VM::PARALLELS, 0 },
    { VM::XEN, 0 },
    { VM::ACRN, 0 },
    { VM::QNX, 0 },
    { VM::HYBRID, 0 },
    { VM::SANDBOXIE, 0 },
    { VM::DOCKER, 0 },
    { VM::WINE, 0 },
    { VM::VAPPLE, 0 },
    { VM::VPC, 0 },
    { VM::ANUBIS, 0 },
    { VM::JOEBOX, 0 },
    { VM::VPC, 0 },
    { VM::ANUBIS, 0 },
    { VM::JOEBOX, 0 },
    { VM::THREADEXPERT, 0 },
    { VM::CWSANDBOX, 0 }
};


VM::u64 VM::flags = 0;
std::map<bool, std::pair<bool, const char*>> VM::memo;


bool VM::cpuid_supported = []() -> bool {
    #if \
    ( \
        !defined(__x86_64__) && \
        !defined(__i386__) && \
        !defined(_M_IX86) && \
        !defined(_M_X64) \
    )
        return false;
    #endif

    #if (MSVC)
        i32 info[4];
        __cpuid(info, 0);
        return (info[0] >= 1);
    #elif (LINUX)
        u32 ext = 0;
        return (__get_cpuid_max(ext, nullptr) > 0);
    #else
        return false;
    #endif
}();


const std::map<VM::u64, VM::technique> VM::table = {
    { VM::VMID, { 100, VM::vmid }},
    { VM::BRAND, { 50, VM::cpu_brand }},
    { VM::HYPERV_BIT, { 95, VM::cpuid_hyperv }},
    { VM::CPUID_0x4, { 70, VM::cpuid_0x4 }},
    { VM::HYPERV_STR, { 45, VM::hyperv_brand }},
    { VM::RDTSC, { 20, VM::rdtsc_check }},
    { VM::SIDT, { 65, VM::sidt_check }},
    { VM::VMWARE_PORT, { 80, VM::vmware_port }},
    { VM::THREADCOUNT, { 35, VM::thread_count }},
    { VM::MAC, { 90, VM::mac_address_check }},
    { VM::TEMPERATURE, { 15, VM::temperature }},
    { VM::SYSTEMD, { 70, VM::systemd_virt }},
    { VM::CVENDOR, { 65, VM::chassis_vendor }},
    { VM::CTYPE, { 10, VM::chassis_type }},
    { VM::DOCKERENV, { 80, VM::dockerenv }},
    { VM::DMIDECODE, { 55, VM::dmidecode }},
    { VM::DMESG, { 55, VM::dmesg }},
    { VM::HWMON, { 75, VM::hwmon }},
    { VM::SIDT5, { 45, VM::sidt5 }},
    { VM::CURSOR, { 10, VM::cursor_check }},
    { VM::VMWARE_REG, { 65, VM::vmware_registry }},
    { VM::VBOX_REG, { 65, VM::vbox_registry }},
    { VM::USER, { 35, VM::user_check }},
    { VM::DLL, { 50, VM::DLL_check }},
    { VM::REGISTRY, { 75, VM::registry_key }},
    { VM::SUNBELT, { 10, VM::sunbelt_check }},
    { VM::WINE_CHECK, { 85, VM::wine }},
    { VM::BOOT, { 5, VM::boot_time }},
    { VM::VM_FILES, { 20, VM::vm_files }},
    { VM::HWMODEL, { 75, VM::hwmodel }},
    { VM::DISK_SIZE, { 60, VM::disk_size }},
    { VM::VBOX_DEFAULT, { 55, VM::vbox_default_specs }},
    { VM::VBOX_NETWORK, { 70, VM::vbox_network_share }},
    { VM::COMPUTER_NAME, { 15, VM::computer_name_match }},
    { VM::HOSTNAME, { 25, VM::hostname_match }},
    { VM::MEMORY, { 35, VM::low_memory_space }},
    { VM::VM_PROCESSES, { 30, VM::vm_processes }},
    { VM::LINUX_USER_HOST, { 35, VM::linux_user_host }},
    { VM::VBOX_WINDOW_CLASS, { 10, VM::vbox_window_class }},
    { VM::WINDOWS_NUMBER, { 20, VM::windows_number }},
    { VM::GAMARUE, { 40, VM::gamarue }}

    // { VM::, { ,  }}
    // ^ line template for personal use
};