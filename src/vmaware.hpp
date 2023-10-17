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
#endif
#ifdef __VMAWARE_DEBUG__
    #include <iomanip>
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

    #if (CPP <= 14)
        using sv = const char*;
    #else
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
        [[nodiscard]] static bool exists(LPCSTR path) {
            GetFileAttributes(path);
            return (!(
                (INVALID_FILE_ATTRIBUTES == GetFileAttributes(path)) && 
                (GetLastError() == ERROR_FILE_NOT_FOUND)
            ));
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

    // official aliases for VM brands. This is added to avoid accidental typos which could really fuck up the result. Also, no errors/warnings are issued if the string is invalid. 
    static constexpr sv 
        VMWARE = "VMware",
        VBOX = "VirtualBox",
        KVM = "KVM",
        BHYVE = "bhyve",
        QEMU = "QEMU",
        HYPERV = "Microsoft Hyper-V",
        MSXTA = "Microsoft x86-to-ARM",
        PARALLELS = "Parallels",
        XEN = "Xen HVM",
        ACRN = "ACRN",
        QNX = "QNX hypervisor",
        HYBRID = "Hybrid Analysis",
        SANDBOXIE = "Sandboxie",
        DOCKER = "Docker",
        WINE = "Wine",
        VAPPLE = "Virtual Apple",
        VPC = "Virtual PC",
        ANUBIS = "Anubis",
        JOEBOX = "JoeBox";

    // VM scoreboard table specifically for VM::brand()
    static inline std::map<sv, u8> scoreboard {
        { VMWARE, 0 },
        { VBOX, 0 },
        { KVM, 0 },
        { BHYVE, 0 },
        { QEMU, 0 },
        { HYPERV, 0 },
        { MSXTA, 0 },
        { PARALLELS, 0 },
        { XEN, 0 },
        { ACRN, 0 },
        { QNX, 0 },
        { HYBRID, 0 },
        { SANDBOXIE, 0 },
        { DOCKER, 0 },
        { WINE, 0 },
        { VAPPLE, 0 },
        { VPC, 0 },
        { ANUBIS, 0 },
        { JOEBOX, 0 }
    };

    // check if cpuid is supported
    [[nodiscard]] static bool check_cpuid(void) {
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
    }

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
            constexpr sv black_bg = "\x1B[48;2;0;0;0m",
                         bold = "\033[1m",
                         blue = "\x1B[38;2;00;59;193m",
                         ansiexit = "\x1B[0m";

            std::cout << black_bg << bold << "[" << blue << "DEBUG" << ansiexit << bold << black_bg << "]" << ansiexit << " ";
            ((std::cout << message),...);
            std::cout << "\n";
        }

    #else
        // this is added so the compiler doesn't scream about "auto not allowed in function prototype" or some bullshit like that when compiling with C++17 or under.
        template <typename... Args>
        static inline void debug(Args... idk) noexcept {
            return;
        }
    #endif

    // directly return when adding a brand to the scoreboard for a more succint expression
    [[nodiscard]] static inline bool add(const sv p_brand) noexcept {
        scoreboard[p_brand]++;
        return true;
    }

    // get disk size in GB
    // TODO: finish the MSVC section
    [[nodiscard]] static u32 get_disk_size() {
        constexpr u64 GB = (1000 * 1000 * 1000);
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
    [[nodiscard]] static u32 get_physical_ram_size() {
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

            u32 number = 0;

            number = std::stoi(number_str);

            if (MB == true) {
                number = static_cast<u32>(std::round(number / 1024)); // 1000?
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
            DWORDLONG ullMinRam = (1024LL * (1024LL * (1024LL * 1LL))); // 1GB
        
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
    static inline std::map<bool, std::pair<bool, sv>> memo;
    
    // cpuid check value
    static inline bool no_cpuid;

    // flags
    static inline u64 flags;

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
            if (no_cpuid || disabled(VMID)) {
                debug("VMID: precondition return called");
                return false;
            }

            constexpr sv
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

            constexpr std::array<sv, 13> IDs {
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
 
            debug("VMID: ", brand);

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
    } catch (...) { return false; }


    /**
     * @brief Check if CPU brand is a VM brand
     * @category x86
     */
    [[nodiscard]] static bool cpu_brand() try {
        #if (!x86)
            return false;
        #else
            if (no_cpuid || disabled(BRAND)) {
                debug("BRAND: ", "precondition return called");
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
                brand += sv(charbuffer.data());
            }

            // TODO: might add more potential keywords, be aware that it could (theoretically) cause false positives
            constexpr std::array<const char*, 16> vmkeywords {
                "qemu", "kvm", "virtual", "vm", 
                "vbox", "virtualbox", "vmm", "monitor", 
                "bhyve", "hyperv", "hypervisor", "hvisor", 
                "parallels", "vmware", "hvm", "qnx"
            };

            u8 matches = 0;

            for (std::size_t i = 0; i < vmkeywords.size(); i++) {
                const auto regex = std::regex(vmkeywords.at(i), std::regex::icase);
                matches += std::regex_search(brand, regex);
            }

            debug("BRAND: ", "matches: ", static_cast<u32>(matches));

            return (matches >= 1);
        #endif
    } catch (...) { return false; }


    /**
     * @brief Check if hypervisor feature bit in CPUID is enabled (always false for physical CPUs)
     * @category x86
     */
    [[nodiscard]] static bool cpuid_hyperv() try {
        #if (!x86)
            return false;
        #else
            if (no_cpuid || disabled(HYPERV_BIT)) {
                debug("HYPERV_BIT: precondition return called");
                return false;
            }

            u32 unused, ecx = 0;

            cpuid(unused, unused, ecx, unused, 1);

            return (ecx & (1 << 31));
        #endif
    } catch (...) { return false; }


    /**
     * @brief Check if 0x40000000~0x400000FF cpuid input is present (mostly present in VMs, according to VMware)
     * @link https://kb.vmware.com/s/article/1009458
     * @category x86
     */
    [[nodiscard]] static bool cpuid_0x4() try {
        #if (!x86)
            return false;
        #else
            if (no_cpuid || disabled(CPUID_0x4)) {
                debug("CPUID_0X4: precondition return called");
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
    } catch (...) { return false; }


    /**
     * @brief Check for hypervisor brand string length (would be around 2 characters in a host machine)
     * @category x86
     */
    [[nodiscard]] static bool hyperv_brand() try {
        #if (!x86)
            return false;
        #else
            if (disabled(HYPERV_STR)) {
                debug("HYPERV_STR: precondition return called");
                return false;
            }

            char out[sizeof(i32) * 4 + 1] = { 0 }; // e*x size + number of e*x registers + null terminator
            cpuid((int*)out, leaf::hyperv);

            debug("HYPERV_STR: eax: ", static_cast<u32>(out[0]), 
                "\nebx: ", static_cast<u32>(out[1]), 
                "\necx: ", static_cast<u32>(out[2]), 
                "\nedx: ", static_cast<u32>(out[3])
            );

            return (std::strlen(out + 4) >= 4);
        #endif
    } catch (...) { return false; }


    /**
     * @brief Check if RDTSC is slow, if yes then it might be a VM
     * @category x86
     */
    [[nodiscard]] static bool rdtsc_check() try {
        #if (!x86)
            return false;
        #else
            if (disabled(RDTSC)) {
                debug("RDTSC: precondition return called");
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

                debug("RDTSC: ", "acc = ", acc / 100);

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
    } catch (...) { return false; }


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
                debug("SIDT5: ", "precondition return called");
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
    } catch (...) { return false; }


    /**
     * @brief Check for vm presence using sidt instruction 
     * @todo: Check if this actually works
     * @author Unprotect
     * @link https://unprotect.it/technique/sidt-red-pill/
     * @category x86
     */
    [[nodiscard]] static bool sidt_check() try {
        return false; // TODO: REMOVE AFTER VERIFYING IF IT WORKS

        #if (!x86 || !LINUX)
            return false;
        #else
            if (disabled(SIDT)) {
                debug("SIDT: ", "precondition return called");
                return false;
            }

            u64 idtr = 0;

            __asm__ __volatile__(
                "sidt %0"
                : "=m" (idtr)
            );

            debug("SIDT: ", "idtr = ", idtr);

            return (idtr != 0);
        #endif
    } catch (...) { return false; }


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
                debug("VMWARE_PORT: ", "precondition return called");
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
                        __except (EXCEPTION_EXECUTE_HANDLER) {}
                    }

                    if (is_vm) {
                        break;
                    }
                }
            #endif

            if (is_vm) {
                scoreboard[VMWARE] += 2; // extra point bc it's incredibly VMware-specific
                return true;
            }

            return false;
        #endif
    } catch (...) { return false; }


    /**
     * @brief Check if processor count is 1 or 2 (some VMs only have a single core)
     * @category All systems
     */
    [[nodiscard]] static bool thread_count() try {
        if (disabled(THREADCOUNT)) {
            debug("THREADCOUNT: ", "precondition return called");
            return false;
        }

        debug("THREADCOUNT: ", "threads = ", std::thread::hardware_concurrency());

        return (std::thread::hardware_concurrency() <= 2);
    } catch (...) { return false; }
    

    /**
     * @brief Check if mac address starts with certain VM designated values
     * @category All systems (I think)
     */
    [[nodiscard]] static bool mac_address_check() try {
        if (disabled(MAC)) {
            debug("MAC: ", "precondition return called");

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
                debug("MAC: ", "not successful");
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
    } catch (...) { return false; }


    /**
     * @brief Check if thermal directory is present, might not be present in VMs
     * @category Linux
     */
    [[nodiscard]] static bool temperature() try {
        #if (!LINUX)
            return false;
        #else
            if (disabled(TEMPERATURE)) {
                debug("TEMPERATURE: ", "precondition return called");
                return false;
            }

            return (!exists("/sys/class/thermal/thermal_zone0/"));
        #endif
    } catch (...) { return false; }


    /**
     * @brief Check result from systemd-detect-virt tool
     * @category Linux
     */ 
    [[nodiscard]] static bool systemd_virt() try {
        #if (!LINUX)
            return false;
        #else
            if (disabled(SYSTEMD)) {
                debug("SYSTEMD: ", "precondition return called");
                return false;
            }

            if (!(exists("/usr/bin/systemd-detect-virt") || exists("/bin/systemd-detect-virt"))) {
                debug("SYSTEMD: ", "binary doesn't exist");
                return false;
            }

            const std::unique_ptr<std::string> result = sys_result("systemd-detect-virt");
            
            if (result == nullptr) {
                debug("SYSTEMD: ", "invalid stdout output from systemd-detect-virt");
                return false;
            }

            debug("SYSTEMD: ", "output = ", *result);

            return (*result != "none");
        #endif
    } catch (...) { return false; }


    /**
     * @brief Check if chassis vendor is a VM vendor
     * @category Linux
     */ 
    [[nodiscard]] static bool chassis_vendor() try {
        #if (!LINUX)
            return false;
        #else
            if (disabled(CVENDOR)) {
                debug("CVENDOR: ", "precondition return called");
                return false;
            }

            const char* vendor_file = "/sys/devices/virtual/dmi/id/chassis_vendor";

            if (exists(vendor_file)) {
                const std::string vendor = read_file(vendor_file);

                // TODO: More can be definitely added, I only tried QEMU and VMware so far
                if (vendor == "QEMU") { return add(QEMU); }
                if (vendor == "Oracle Corporation") { return add(VMWARE); }

                debug("CVENDOR: ", "unknown vendor = ", vendor);
            } else {
                debug("CVENDOR: ", "file doesn't exist");
            }

            return false;
        #endif
    } catch (...) { return false; }


    /**
     * @brief Check if the chassis type is valid (it's very often invalid in VMs)
     * @category Linux
     */
    [[nodiscard]] static bool chassis_type() try {
        #if (!LINUX)
            return false;
        #else
            if (disabled(CTYPE)) {
                debug("CTYPE: ", "precondition return called");
                return false;
            }

            const char* chassis = "/sys/devices/virtual/dmi/id/chassis_type";
            
            if (exists(chassis)) {
                return (stoi(read_file(chassis)) == 1);
            } else {
                debug("CTYPE: ", "file doesn't exist");
            }

            return false;
        #endif
    } catch (...) { return false; }


    /**
     * @brief Check if /.dockerenv or /.dockerinit file is present
     * @category Linux
     */
    [[nodiscard]] static bool dockerenv() try {
        #if (!LINUX)
            return false;
        #else
            if (disabled(DOCKERENV)) {
                debug("DOCKER: ", "precondition return called");
                return false;
            }

            return (exists("/.dockerenv") || exists("/.dockerinit"));
        #endif
    } catch (...) { return false; }


    /**
     * @brief Check if dmidecode output matches a VM brand
     * @category Linux
     */
    [[nodiscard]] static bool dmidecode() try {
        #if (!LINUX)
            return false;
        #else
            if (disabled(DMIDECODE) || (is_root() == false)) {
                debug("DMIDECODE: ", "precondition return called (root = ", is_root(), ")");
                return false;
            }

            if (!(exists("/bin/dmidecode") || exists("/usr/bin/dmidecode"))) {
                debug("DMIDECODE: ", "binary doesn't exist");
                return false;
            }
            
            const std::unique_ptr<std::string> result = sys_result("dmidecode -t system | grep 'Manufacturer|Product' | grep -c \"QEMU|VirtualBox|KVM\"");

            if (*result == "" || result == nullptr) {
                debug("DMIDECODE: ", "invalid output");
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
                debug("DMIDECODE: ", "output = ", *result);
            }

            return false;
        #endif
    } catch (...) { return false; }


    /**
     * @brief Check if dmesg command output matches a VM brand
     * @category Linux
     */
    [[nodiscard]] static bool dmesg() try {
        #if (!LINUX)
            return false;
        #else
            if (disabled(DMESG)) {
                debug("DMESG: ", "precondition return called");
                return false;
            }

            if (!exists("/bin/dmesg") && !exists("/usr/bin/dmesg")) {
                debug("DMESG: ", "binary doesn't exist");
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
                debug("DMESG: ", "output = ", *result);
            }

            return false;
        #endif
    } catch (...) { return false; }


    /**
     * @brief Check if /sys/class/hwmon/ directory is present. If not, likely a VM
     * @category Linux
     */
    [[nodiscard]] static bool hwmon() try {
        #if (!LINUX)
            return false;
        #else
            if (disabled(HWMON)) {
                debug("HWMON: ", "precondition return called");
                return false;
            }

            return (!exists("/sys/class/hwmon/"));
        #endif
    } catch (...) { return false; }
    

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
                debug("REGISTRY: ", "precondition return called");
                return false;
            }

            u8 score = 0;

            auto key = [&score](const sv p_brand, LPCSTR regkey_s) -> void {
                HKEY regkey;
                LONG ret;
                BOOL isWow64 = FALSE;

                if (IsWow64Process(GetCurrentProcess(), &isWow64) && isWow64) { 
                    ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, regkey_s, 0, KEY_READ | KEY_WOW64_64KEY, &regkey);
                } else { 
                    ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, regkey_s, 0, KEY_READ, &regkey);
                }

                if (ret == ERROR_SUCCESS) {
                    RegCloseKey(regkey);
                    score++;

                    if (std::string(p_brand) != "") [[likely]] {
                        debug("REGISTRY: ", "detected = ", p_brand);
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

            debug("REGISTRY: ", "score = ", score);

            return (score >= 1);
        #endif
    } catch (...) { return false; }


    /**
     * @brief checks for default usernames, often a sign of a VM 
     * @author: Some guy in a russian underground forum from a screenshot I saw, idk I don't speak russian ¯\_(ツ)_/¯
     * @category Windows
     */ 
    [[nodiscard]] static bool user_check() try {     
        #if (!MSVC)
            return false;
        #else
            if (disabled(USER)) {
                debug("USER: ", "precondition return called");
                return false;
            }

            TCHAR user[UNLEN+1];
            DWORD user_len = UNLEN+1;
            GetUserName((TCHAR*)user, &user_len);
            std::string u = user;

            debug("USER: ", "output = ", u);

            return (
                (u == "username") ||  // ThreadExpert
                (u == "USER") ||      // Sandbox
                (u == "user") ||      // Sandbox 2
                (u == "currentuser")  // Normal
            );
        #endif
    } catch (...) { return false; }


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
                debug("SUNBELT: ", "precondition return called");
                return false;
            }

            return (exists("C:\\analysis"));
        #endif
    } catch (...) { return false; }


    /**
     * @brief Check for VM-specific DLLs
     * @category Windows
     */
    [[nodiscard]] static bool DLL_check() try {
        #if (!MSVC)
            return false;
        #else
            if (disabled(DLL)) {
                debug("DLL: ", "precondition return called");
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
                    debug("DLL: ", "LIB_INST detected true for real dll = ", dll);
                    return true;
                }
                FreeLibrary(lib_inst);
            }

            for (auto &dll : false_dlls) {
                lib_inst = LoadLibraryA(dll);
                if (lib_inst != nullptr) {
                    debug("DLL: ", "LIB_INST detected true for false dll = ", dll);
                    return true;
                }
            }

            return false;
        #endif
    } catch (...) { return false; }


    /**
     * @brief Check VBox RdrDN
     * @category Windows 
     */
    [[nodiscard]] static bool vbox_registry() try {
        #if (!MSVC)
            return false;
        #else
            if (disabled(VBOX_REG)) {
                debug("VBOX_REG: ", "precondition return called");
                return false;
            }

            HANDLE handle = CreateFile(_T("\\\\.\\VBoxMiniRdrDN"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

            if (handle != INVALID_HANDLE_VALUE) {
                CloseHandle(handle);
                return add(VBOX);
            }

            return false;
        #endif
    } catch (...) { return false; }


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
                debug("VMWARE_REG: ", "precondition return called");
                return false;
            }

            return false; // TODO: fix
            /*

            HKEY hKey = 0;
            DWORD dwType = REG_SZ;
            char buf[0xFF] = {0};
            DWORD dwBufSize = sizeof(buf);
            bool result = (RegOpenKeyEx(TEXT("SOFTWARE\\VMware, Inc.\\VMware Tools"), 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS);

            if (result == true) {
                return add(VMWARE);
            }

            return result;
            */
        #endif
    } catch (...) { return false; }


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
                debug("CURSOR: ", "precondition return called");
                return false;
            }

            POINT pos1, pos2;
            GetCursorPos(&pos1);
            Sleep(5000);
            GetCursorPos(&pos2);

            return ((pos1.x == pos2.x) && (pos1.y == pos2.y));
        #endif
    } catch (...) { return false; }


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
                debug("WINE: ", "precondition return called");
                return false;
            }

            HMODULE k32;
            k32 = GetModuleHandle("kernel32.dll");

            if (k32 != NULL) {
                return (GetProcAddress(k32, "wine_get_unix_file_name") != NULL);
            } 

            return false;
        #endif
    } catch (...) { return false; }


    /**
     * @brief Check boot-time 
     * @todo: finish the linux part tomorrow
     * @category All systems
     */ 
    [[nodiscard]] static bool boot_time() try {
        if (disabled(BOOT)) {
            debug("BOOT: ", "precondition return called");
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
    } catch (...) { return false; }


    /**
     * @brief Find for VMware and VBox specific files
     * @category Windows
     */
    [[nodiscard]] static bool vm_files() try {
        #if (!MSVC)
            return false;
        #else
            if (disabled(VM_FILES)) {
                debug("VMFILES: ", "precondition return called");
                return false;
            }

            // points
            u8 vbox = 0;
            u8 vmware = 0;

            constexpr std::array<const char*, 26> files = {
                // VMware
                "C:\\windows\\System32\\Drivers\\Vmmouse.sys",
                "C:\\windows\\System32\\Drivers\\vm3dgl.dll",
                "C:\\windows\\System32\\Drivers\\vmdum.dll",
                "C:\\windows\\System32\\Drivers\\VmGuestLibJava.dll",
                "C:\\windows\\System32\\Drivers\\vm3dver.dll",
                "C:\\windows\\System32\\Drivers\\vmtray.dll",
                "C:\\windows\\System32\\Drivers\\VMToolsHook.dll",
                "C:\\windows\\System32\\Drivers\\vmGuestLib.dll",
                "C:\\windows\\System32\\Drivers\\vmhgfs.dll",
                "C:\\windows\\System32\\Driversvmhgfs.dll",
                
                // VBox
                "C:\\windows\\System32\\Drivers\\VBoxMouse.sys",
                "C:\\windows\\System32\\Drivers\\VBoxGuest.sys",
                "C:\\windows\\System32\\Drivers\\VBoxSF.sys",
                "C:\\windows\\System32\\Drivers\\VBoxVideo.sys",
                "C:\\windows\\System32\\vboxoglpackspu.dll",
                "C:\\windows\\System32\\vboxoglpassthroughspu.dll",
                "C:\\windows\\System32\\vboxservice.exe",
                "C:\\windows\\System32\\vboxoglcrutil.dll",
                "C:\\windows\\System32\\vboxdisp.dll",
                "C:\\windows\\System32\\vboxhook.dll",
                "C:\\windows\\System32\\vboxmrxnp.dll",
                "C:\\windows\\System32\\vboxogl.dll",
                "C:\\windows\\System32\\vboxtray.exe",
                "C:\\windows\\System32\\VBoxControl.exe",
                "C:\\windows\\System32\\vboxoglerrorspu.dll",
                "C:\\windows\\System32\\vboxoglfeedbackspu.dll",
            };

            for (const sv file : files) {
                if (exists(file)) {
                    const auto regex = std::regex(file, std::regex::icase);

                    if (std::regex_search("vbox", regex)) {
                        vbox++;
                    } else {
                        vmware++;
                    }
                }
            }

            if (vbox > vmware) {
                return add(VBOX);
            } else if (vbox < vmware) {
                return add(VMWARE);
            } else if (vbox == vmware) {
                return true;
            }

            return false;
        #endif
    } catch (...) { return false; }


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
                debug("HWMODEL: ", "precondition return called");
                return false;
            }

            auto result = sys_result("sysctl -n hw.model");

            std::smatch match;

            if (result == nullptr) {
                debug("HWMODEL: ", "null result received");
                return false;
            }

            debug("HWMODEL: ", "output = ", *result);

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
    } catch (...) { return false; }


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

            return (get_disk_size() <= 50); // 50 GB
        #endif
     } catch (...) { return false;}



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
        const u32 ram = get_physical_ram_size();

        if ((disk > 80) || (ram > 4)) {
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

            *(FARPROC*)&RtlGetVersion = GetProcAddress(GetModuleHandleA("ntdll"), "RtlGetVersion");

            if (NULL != RtlGetVersion) {
                osInfo.dwOSVersionInfoSize = sizeof(osInfo);
                RtlGetVersion(&osInfo);
                ret = static_cast<double>(osInfo.dwMajorVersion);
            }
            
            // less than windows 10
            if (ret < 10) {
                return false;
            }

            // windows 10
            if (10 == ret) {
                return ((50 == disk) && (2 == ram));
            }

            // windows 11
            if (11 == ret) {
                return ((80 == disk) && (4 == ram));
            }
        #endif

        return false;
    } catch (...) { return false; }

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
    } catch (...) { return false; }


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
                return !lstrcmpiA((LPCSTR)comp_name.data(), s.c_str());
            };

            if (compare("InsideTm") || compare("TU-4NH09SMCG1HC")) { // anubis
                return add(ANUBIS);
            }

            return (compare("klone_x64-pc") || compare("tequilaboomboom")); // general
        #endif
    } catch (...) { return false; }


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

            return (!lstrcmpiA((LPCSTR)dns_host_name.data(), "SystemIT"));
        #endif
    } catch (...) { return false; }

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
        return (ram < min_ram_1gb);
    } catch (...) { return false; }


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
                        if (!StrCmpI(pe.szExeFile, proc_name.c_str())) {
                            present = true;
                            break;
                        }
                    } while (Process32Next(hSnapshot, &pe));
                }
    
                CloseHandle(hSnapshot);

                return present;
            };

            if (check_proc("joeboxserver.exe") || check_proc("joeboxcontrol.exe")) {
                return add(JOEBOX);
            }

            if (check_proc("prl_cc.exe") || check_proc("prl_tools.exe")) {
                return add(PARALLELS);
            }

            if (check_proc("vboxservice.exe") || check_proc("vboxtray.exe")) {
                return add(VBOX);
            }

            if (check_proc("vmsrvc.exe") || check_proc("vmusrvc.exe")) {
                return add(VPC);
            }

            if (
                check_proc("vmtoolsd.exe") ||
                check_proc("vmacthlp.exe") ||
                check_proc("vmwaretray.exe") ||
                check_proc("vmwareuser.exe") ||
                check_proc("vmware.exe") ||
                check_proc("vmount2.exe")
            ) {
                return add(VMWARE);
            }

            if (check_proc("xenservice.exe") || check_proc("xsvc_depriv.exe")) {
                return add(XEN);
            }

            return false;
        #endif
    } catch (...) { return false; }


    // __LABEL  (ignore this, it's just a label so I can easily teleport to this line on my IDE with CTRL+F)


    struct technique {
        u8 points; 
        bool(*ptr)(); // function pointer
    };

    // the points are debatable, but I think it's fine how it is. Feel free to disagree.
    static inline std::map<u64, technique> table = {
        { VM::VMID, { 100, vmid }},
        { VM::BRAND, { 50, cpu_brand }},
        { VM::HYPERV_BIT, { 95, cpuid_hyperv }},
        { VM::CPUID_0x4, { 70, cpuid_0x4 }},
        { VM::HYPERV_STR, { 45, hyperv_brand }},
        { VM::RDTSC, { 20, rdtsc_check }},
        { VM::SIDT, { 65, sidt_check }},
        { VM::VMWARE_PORT, { 80, vmware_port }},
        { VM::THREADCOUNT, { 35, thread_count }},
        { VM::MAC, { 90, mac_address_check }},
        { VM::TEMPERATURE, { 15, temperature }},
        { VM::SYSTEMD, { 70, systemd_virt }},
        { VM::CVENDOR, { 65, chassis_vendor }},
        { VM::CTYPE, { 10, chassis_type }},
        { VM::DOCKERENV, { 80, dockerenv }},
        { VM::DMIDECODE, { 55, dmidecode }},
        { VM::DMESG, { 55, dmesg }},
        { VM::HWMON, { 75, hwmon }},
        { VM::SIDT5, { 45, sidt5 }},
        { VM::CURSOR, { 10, cursor_check }},
        { VM::VMWARE_REG, { 65, vmware_registry }},
        { VM::VBOX_REG, { 65, vbox_registry }},
        { VM::USER, { 35, user_check }},
        { VM::DLL, { 50, DLL_check }}, // i genuinely have no idea
        { VM::REGISTRY, { 75, registry_key }},
        { VM::SUNBELT, { 10, sunbelt_check }},
        { VM::WINE_CHECK, { 85, wine }},
        { VM::BOOT, { 5, boot_time }},
        { VM::VM_FILES, { 80, vm_files }},
        { VM::HWMODEL, { 75, hwmodel }},
        { VM::DISK_SIZE, { 60, disk_size }},
        { VM::VBOX_DEFAULT, { 55, vbox_default_specs }},
        { VM::VBOX_NETWORK, { 70, vbox_network_share }},
        { VM::COMPUTER_NAME, { 40, computer_name_match }},
        { VM::HOSTNAME, { 25, hostname_match }},
        { VM::MEMORY, { 35, low_memory_space }},
        { VM::VM_PROCESSES, { 30, vm_processes }}

        // { VM::, { ,  }}
        // ^ line template for personal use
    };

public:
    /**
     * @brief Check for a specific technique based on flag argument
     * @param u64 (flags from VM wrapper)
     * @return bool
     * @link https://github.com/kernelwernel/VMAware/blob/main/docs/documentation.md#vmcheck
     */
    [[nodiscard]] static bool check(const u64 p_flags = 0ULL) {
        i32 count = 0;

        #if (CPP >= 20)
            count = std::popcount(p_flags);
        #elif (CPP >= 14)
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
     * @returns VMware, VirtualBox, KVM, bhyve, QEMU, Microsoft Hyper-V, Microsoft x86-to-ARM, Parallels, Xen HVM, ACRN, QNX hypervisor, Hybrid Analysis, Sandboxie, Docker, Wine, Virtual Apple, Virtual PC, Unknown
     * @link https://github.com/kernelwernel/VMAware/blob/main/docs/documentation.md#vmbrand
     */
    [[nodiscard]] static sv brand(void) {
        // check if result hasn't been memoized already
        if (memo.find(true) == memo.end()) {
            debug("memoization: detect() called in brand");
            detect();
        }

        // check if no VM was detected
        if (memo[true].first == false) {
            return "Unknown";
        }

        return (memo[true].second);
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
            debug("memoization: returned cached result in detect()");
            return memo[true].first;
        }

        // set local variables within struct scope
        VM::no_cpuid = !check_cpuid();
        VM::flags = p_flags;

        u8 points = 0;
    
        for (auto it = table.cbegin(); it != table.cend(); ++it) {
            const technique &pair = it->second;
            if (pair.ptr()) {
                points += pair.points;
            };
        }

        // threshold score
        const bool result = (points >= 100);

        sv current_brand = "";

        #ifdef __VMAWARE_DEBUG__
            for (const auto p : scoreboard) {
                debug("scoreboard: ", (int)p.second, " : ", p.first);
            }
        #endif

        // fetch the brand with the most points in the scoreboard
        #if (CPP >= 20)
            auto it = std::ranges::max_element(scoreboard, {},
                [](const auto &pair) {
                    return pair.second;
                }
            );

            if (it != scoreboard.end()) {
                if (
                    std::none_of(scoreboard.cbegin(), scoreboard.cend(),
                        [](const auto &pair) {
                            return pair.second;
                        }
                    )
                ) {
                    current_brand = "Unknown";
                } else {
                    current_brand = it->first;
                }
            } else {
                current_brand = "Unknown";
            }
        #else
            u8 max = 0;

            for (auto it = scoreboard.cbegin(); it != scoreboard.cend(); ++it) {
                if (it->second > max) {
                    current_brand = it->first;
                    max = it->second;
                }
            }

            if (max == 0) {
                current_brand = "Unknown";
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