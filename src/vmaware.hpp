/**
 * ██╗   ██╗███╗   ███╗ █████╗ ██╗    ██╗ █████╗ ██████╗ ███████╗
 * ██║   ██║████╗ ████║██╔══██╗██║    ██║██╔══██╗██╔══██╗██╔════╝
 * ██║   ██║██╔████╔██║███████║██║ █╗ ██║███████║██████╔╝█████╗  
 * ╚██╗ ██╔╝██║╚██╔╝██║██╔══██║██║███╗██║██╔══██║██╔══██╗██╔══╝  
 *  ╚████╔╝ ██║ ╚═╝ ██║██║  ██║╚███╔███╔╝██║  ██║██║  ██║███████╗
 *   ╚═══╝  ╚═╝     ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ v1.0
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
#if (CPP < 11)
    #error "VMAware only supports C++14 or above, set your compiler flag to '-std=c++20' for GCC/clang, or '/std:c++20' for MSVC"
#endif


#if (MSVC)
    #include <intrin.h>
    #include <windows.h>
    #include <tchar.h>
    #include <stdbool.h>
    #include <stdio.h>
    #include <Iphlpapi.h>
    #include <Assert.h>
    #include <excpt.h>
    #pragma comment(lib, "iphlpapi.lib")
#elif (LINUX)
    #include <cpuid.h>
    #include <x86intrin.h>
    #include <sys/stat.h>
    #include <sys/ioctl.h>
    #include <net/if.h> 
    #include <unistd.h>
    #include <netinet/in.h>
    #include <string.h>
    #include <memory>
#endif


struct VM {
private:
    using u8  = std::uint8_t;
    using u32 = std::uint32_t;
    using u64 = std::uint64_t;
    using i32 = std::int32_t;
    using f64 = double;

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
    [[nodiscard]] static bool exists(const char* path) {
        #if (CPP >= 17)
            return std::filesystem::exists(path);
        #elif (CPP >= 11)
            struct stat buffer;   
            return (stat (path, &buffer) == 0); 
        #endif
    }

    // VM scoreboard table specifically for VM::brand()
    static inline std::map<sv, u8> scoreboard {
        { "VMware", 0 },
        { "VirtualBox", 0 },
        { "KVM", 0 },
        { "bhyve", 0 },
        { "QEMU", 0 },
        { "Microsoft Hyper-V", 0 },
        { "Microsoft x86-to-ARM", 0 },
        { "Parallels", 0 },
        { "Xen HVM", 0 },
        { "ACRN", 0 },
        { "QNX hypervisor", 0 },
        { "Hybrid Analysis", 0 },
        { "Sandboxie", 0 },
        { "Docker", 0 },
        { "Wine", 0 },
        { "Virtual Apple", 0 },
        { "Virtual PC", 0 }
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
        #endif

        uid_t uid = getuid();
        uid_t euid = geteuid();

        return (
            (uid != euid) || 
            (euid == 0)
        );
    }

    // directly return when adding a brand to the scoreboard for a more succint expression
    [[nodiscard]] static inline bool add(const sv p_brand) noexcept {
        scoreboard[p_brand]++;
        return true;
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
     * over this:
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
        VMID  = 1 << 0,
        BRAND = 1 << 1,
        HYPERV_BIT = 1 << 2,
        CPUID_0x4 = 1 << 3,
        HYPERV_STR = 1 << 4,
        RDTSC = 1 << 5,
        SIDT = 1 << 6,
        VMWARE_PORT = 1 << 7,
        THREADCOUNT = 1 << 8,
        MAC = 1 << 9,
        TEMPERATURE = 1 << 10,
        SYSTEMD = 1 << 11,
        CVENDOR = 1 << 12,
        CTYPE = 1 << 13,
        DOCKER = 1 << 14,
        DMIDECODE = 1 << 15,
        DMESG = 1 << 16,
        HWMON = 1 << 17,
        SIDT5 = 1 << 18,
        
        CURSOR = 1ULL << 40,
        VMWARE_REG = 1ULL << 41,
        VBOX_REG = 1ULL << 42,
        USER = 1ULL << 43,
        DLL = 1ULL << 44,
        REGISTRY = 1ULL << 45,
        SUNBELT = 1ULL << 46,

        // settings
        NO_MEMO = 1ULL << 63,

        ALL = ~(NO_MEMO & std::numeric_limits<u64>::max());

private:
    static constexpr u64 DEFAULT = (~(CURSOR | NO_MEMO) & ALL);

    #if __x86_64__
        /**
         * @brief Check CPUID output of manufacturer ID for known VMs/hypervisors
         * @category x86
         */
        [[nodiscard]] static bool vmid() try {
            #if (!x86)
                return false;
            #else

                if (no_cpuid || disabled(VMID)) {
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

                const bool found = (std::find(std::begin(IDs), std::end(IDs), brand) != std::end(IDs));
                
                if (found) {
                    if (brand == bhyve) { scoreboard["bhyve"]++; }
                    if (brand == kvm) { scoreboard["KVM"]++; }
                    if (brand == qemu) [[likely]] { scoreboard["QEMU"]++; }
                    if (brand == hyperv) { scoreboard["Microsoft Hyper-V"]++; }
                    if (brand == xta) { scoreboard["Microsoft x86-to-ARM"]++; }
                    if (brand == vmware) [[likely]] { scoreboard["VMware"]++; }
                    if (brand == vbox) [[likely]] { scoreboard["VirtualBox"]++; }
                    if (brand == parallels) { scoreboard["Parallels"]++; }
                    if (brand == parallels2) { scoreboard["Parallels"]++; }
                    if (brand == xen) { scoreboard["Xen HVM"]++; }
                    if (brand == acrn) { scoreboard["ACRN"]++; }
                    if (brand == qnx) { scoreboard["QNX hypervisor"]++; }
                    if (brand == virtapple) { scoreboard["Virtual Apple"]++; }
                }

                return found;
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
                    auto const regex = std::regex(vmkeywords.at(i), std::regex::icase);
                    matches += std::regex_search(brand, regex);
                }

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
                    return false;
                }

                u32 a, b, c, d = 0;

                for (u8 i = 0; i < 0xFF; i++) {
                    cpuid(a, b, c, d, (leaf::hyperv + i));
                    if ((a + b + c + d) != 0) { return true; }
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
                    return false;
                }

                char out[sizeof(i32) * 4 + 1] = { 0 }; // e*x size + number of e*x registers + null terminator
                cpuid((int*)out, leaf::hyperv);
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
                    return false;
                }

                #if (LINUX)
                    u32 a, b, c, d = 0;

                    if (!__get_cpuid(leaf::proc_ext, &a, &b, &c, &d)) {
                        if (!(d & (1 << 27))) { return false; }
                    }
                    
                    u64 s, acc = 0;
                    i32 out[4];

                    for (std::size_t i = 0; i < 100; ++i) {
                        s = __rdtsc();
                        cpuid(out, 0, 0);
                        acc += __rdtsc() - s;
                    }

                    return (acc / 100 > 350);
                #elif (MSVC)
                    #define LODWORD(_qw)    ((DWORD)(_qw))
                    u64 tsc1 = 0;
                    u64 tsc2 = 0;
                    u64 avg = 0;
                    i32 cpuInfo[4] = {};
                    for (INT i = 0; i < 10; i++)
                    {
                        tsc1 = __rdtsc();
                        GetProcessHeap();
                        tsc2 = __rdtsc();
                        CloseHandle(0);
                        tsc3 = __rdtsc();
                        if ((LODWORD(tsc3) - LODWORD(tsc2)) / (LODWORD(tsc2) - LODWORD(tsc1)) >= 10) {
                            return false;
                        }
                    }

                    return true;
                #endif
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
                    return false;
                }

                u8 warehouse[10];
                std::memset(warehouse, 0, 10);

                fflush(stdout);
                __asm__ __volatile__("sidt %0" : "=m"(warehouse));

                return (warehouse[5] == 0x00);
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
                    return false;
                }

                u64 idtr = 0;

                __asm__ __volatile__(
                    "sidt %0"
                    : "=m" (idtr)
                );

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
                    __asm {
                        push edx
                        push ecx
                        push ebx
                        mov eax, 'VMXh'
                        mov ebx, 0
                        mov ecx, 10
                        mov edx, 'VX'
                        in eax, dx
                        cmp ebx, 'VMXh'
                        setz[is_vm]
                        pop ebx
                        pop ecx
                        pop edx
                    }
                #endif

                if (is_vm) {
                    scoreboard["VMware"] += 2; // extra point bc it's incredibly VMware-specific
                }

                return is_vm;
            #endif
        } catch (...) { return false; }
    #endif


    /**
     * @brief Check if processor count is 1 or 2 (some VMs only have a single core)
     * @category All systems
     */
    [[nodiscard]] static bool thread_count() try {
        if (disabled(THREADCOUNT)) {
            return false;
        }

        return (std::thread::hardware_concurrency() <= 2);
    } catch (...) { return false; }
    

    /**
     * @brief Check if mac address starts with certain VM designated values
     * @category All systems (I think)
     */
    [[nodiscard]] static bool mac_address_check() try {
        if (disabled(MAC)) {
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

        // better expression to fix code duplication
        auto compare = [=](const u8 mac1, const u8 mac2, const u8 mac3) noexcept -> bool {
            return (mac[0] == mac1 && mac[1] == mac2 && mac[2] == mac3);
        };

        if (compare(0x08, 0x00, 0x27)) {
            return add("VirtualBox");
        }

        if (
            (compare(0x00, 0x0C, 0x29)) ||
            (compare(0x00, 0x1C, 0x14)) ||
            (compare(0x00, 0x50, 0x56)) ||
            (compare(0x00, 0x05, 0x69))
        ) {
            return add("VMware");
        }

        if (compare(0x00, 0x16, 0xE3)) {
            return add("Xen HVM");
        }

        if (compare(0x00, 0x1C, 0x42)) {
            return add("Parallels");
        }

        if (compare(0x0A, 0x00, 0x27)) {
            return add("Hybrid Analysis");
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
                return false;
            }

            if (!(exists("/usr/bin/systemd-detect-virt") || exists("/bin/systemd-detect-virt"))) {
                return false;
            }

            const std::unique_ptr<std::string> result = sys_result("systemd-detect-virt");
            
            if (result == nullptr) {
                return false;
            }

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
                return false;
            }

            const char* vendor_file = "/sys/devices/virtual/dmi/id/chassis_vendor";

            if (exists(vendor_file)) {
                const std::string vendor = read_file(vendor_file);

                // TODO: More can be definitely added, I only tried QEMU and VMware so far
                if (vendor == "QEMU") { return add("QEMU"); }
                if (vendor == "Oracle Corporation") { return add("VMware"); }
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
                return false;
            }

            const char* chassis = "/sys/devices/virtual/dmi/id/chassis_type";
            
            if (exists(chassis)) {
                return (stoi(read_file(chassis)) == 1);
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
            if (disabled(DOCKER)) {
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
                return false;
            }

            if (!(exists("/bin/dmidecode") || exists("/usr/bin/dmidecode"))) {
                return false;
            }
            
            const std::unique_ptr<std::string> result = sys_result("dmidecode -t system | grep 'Manufacturer|Product' | grep -c \"QEMU|VirtualBox|KVM\"");

            if (*result == "" || result == nullptr) {
                return false;
            } else if (*result == "QEMU") {
                return add("QEMU");
            } else if (*result == "VirtualBox") {
                return add("VirtualBox");
            } else if (*result == "KVM") {
                return add("KVM");
            } else if (std::atoi(result->c_str()) >= 1) {
                return true;
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
                return false;
            }

            if (!exists("/bin/dmesg") && !exists("/usr/bin/dmesg")) {
                return false;
            }

            const std::unique_ptr<std::string> result = sys_result("dmesg | grep -i hypervisor | grep -c \"KVM|QEMU\"");

            if (*result == "" || result == nullptr) {
                return false;
            } else if (*result == "KVM") {
                return add("KVM");
            } else if (*result == "QEMU") {
                return add("QEMU");
            } else if (std::atoi(result->c_str())) {
                return true;
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
                return false;
            }

            u8 score = 0;

            auto key = [&score](const sv p_brand, const sv regkey_sv) -> void {
                HKEY regkey;
                LONG ret;
                BOOL isWow64 = FALSE;
                LPCSTR regkey_s = regkey_sv.data();

                if (IsWow64Process(GetCurrentProcess(), &isWow64) && isWow64) { 
                    ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, regkey_s, 0, KEY_READ | KEY_WOW64_64KEY, &regkey);
                } else { 
                    ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, regkey_s, 0, KEY_READ, &regkey);
                }

                if (ret == ERROR_SUCCESS) {
                    RegCloseKey(regkey);
                    score++;

                    if (p_brand != "") [[likely]] {
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
                return false;
            }

            char user[UNLEN+1];
            DWORD user_len = UNLEN+1;
            GetUserName(user, &user_len);

            return (
                (user == "username") || // ThreadExpert
                (user == "USER") ||      // Sandbox
                (user == "user") ||      // Sandbox 2
                (user == "currentuser")  // Normal
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
                    return true;
                }
                FreeLibrary(lib_inst);
            }

            for (auto &dll : false_dlls) {
                lib_inst = LoadLibraryA(dll);
                if (lib_inst != nullptr) {
                    return true;
                }
            }

            return false;
        #endif
    } catch (...) { return false; }


    /**
     * @brief Check vbox RdrDN
     * @category Windows 
     */
    [[nodiscard]] static bool vbox_registry() try {
        #if (!MSVC)
            return false;
        #else
            if (disabled(VBOX_REG)) {
                return false;
            }

            HANDLE handle = CreateFile(_T("\\\\.\\VBoxMiniRdrDN"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

            if (handle != INVALID_HANDLE_VALUE) {
                CloseHandle(handle);
                scoreboard["VirtualBox"]++;
                return true;
            }

            return false;
        #endif
    } catch (...) { return false; }


    /**
     * @brief Find VMware tools presence
     * @category Windows
     */
    [[nodiscard]] static bool vmware_registry() try {
        #if (!MSVC)
            return false;
        #else
            if (disabled(VMWARE_REG)) {
                return false;
            }

            HKEY hKey = 0;
            DWORD dwType = REG_SZ;
            char buf[0xFF] = {0};
            DWORD dwBufSize = sizeof(buf);
            bool result = RegOpenKeyEx(TEXT("SOFTWARE\\VMware, Inc.\\VMware Tools"), 0, KEY_QUERY_VALUE, &hKey ) == ERROR_SUCCESS);

            if (result == true) {
                scoreboard["VMware"]++;
            }

            return result;
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
                return false;
            }

            POINT pos1, pos2;
            GetCursorPos(&pos1);
            Sleep(5000);
            GetCursorPos(&pos2);

            return ((pos1.x == pos2.x) && (pos1.y == pos2.y));
        #endif
    } catch (...) { return false; }

    // __WINDOWS (label so I can easily teleport to this line on my IDE)

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
        {
            // compiler will optimise this with the x86 popcnt instruction (I hope)
            u64 tmp = p_flags;
            for (; tmp != 0; count++) {
                tmp = (tmp & (tmp - 1));
            }
        }
        #endif

        if (count > 1) {
            throw std::invalid_argument("Flag argument must only contain a single option, consult the documentation's flag list");
        }

        if (count == 0) {
            throw std::invalid_argument("Flag argument must contain at least a single option, consult the documentation's flag list");
        }

        if (p_flags & NO_MEMO) {
            throw std::invalid_argument("Flag argument must be a technique flag and not a settings flag, consult the documentation's flag list");
        }

        // count should only have a single flag at this point
        assert(count == 1);

        // temporarily enable all flags so that every technique is enabled
        const u64 tmp_flags = VM::flags;
        VM::flags = (DEFAULT | CURSOR);

        bool result = false;

        switch (p_flags) {
            case VM::VMID: result = vmid(); break;
            case VM::BRAND: result = cpu_brand(); break;
            case VM::HYPERV_BIT: result = cpuid_hyperv(); break;
            case VM::CPUID_0x4: result = cpuid_0x4(); break;
            case VM::HYPERV_STR: result = hyperv_brand(); break;
            case VM::SIDT5: result = sidt5(); break;
            case VM::SIDT: result = sidt_check(); break;
            case VM::TEMPERATURE: result = temperature(); break;
            case VM::CVENDOR: result = chassis_vendor(); break;
            case VM::CTYPE: result = chassis_type(); break;
            case VM::DOCKER: result = dockerenv(); break;
            case VM::DMIDECODE: result = dmidecode(); break;
            case VM::DMESG: result = dmesg(); break;
            case VM::HWMON: result = hwmon(); break;
            case VM::RDTSC: result = rdtsc_check(); break;
            case VM::MAC: result = mac_address_check(); break; 
            case VM::VMWARE_PORT: return vmware_port();
            case VM::CURSOR: result = cursor_check(); break;
            case VM::VMWARE_REG: result = vmware_registry(); break;
            case VM::VBOX_REG: result = vbox_registry(); break;
            case VM::USER: result = user_check(); break;
            case VM::DLL: result = DLL_check(); break;
            case VM::REGISTRY: result = registry_key(); break;
            case VM::SUNBELT: result = sunbelt_check(); break;
            case VM::THREADCOUNT: result = thread_count(); break;
        }

        VM::flags = tmp_flags;

        return result;
    }

    /**
     * @brief Fetch the VM brand
     * @returns VMware, VirtualBox, KVM, bhyve, QEMU, Microsoft Hyper-V, Microsoft x86-to-ARM, Parallels, Xen HVM, ACRN, QNX hypervisor, Hybrid Analysis, Sandboxie, Docker, Wine, Virtual Apple, Unknown
     * @link https://github.com/kernelwernel/VMAware/blob/main/docs/documentation.md#vmbrand
     */
    [[nodiscard]] static sv brand(void) {
        // check if result hasn't been memoized already
        if (memo.find(true) == memo.end()) {
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
        if (!(p_flags & NO_MEMO) && memo.find(true) != memo.end()) {
            return memo[true].first;
        }

        // set local variables within struct scope
        VM::no_cpuid = !check_cpuid();
        VM::flags = p_flags;

        f64 points = 0;

        if (thread_count()) { points += 1.5; }
        if (mac_address_check()) { points += 3.5; }

        #if (__x86_64__)
            if (vmid()) { points += 6.5; }
            if (cpu_brand()) { points += 3; }
            if (cpuid_hyperv()) { points += 5.5; }
            if (cpuid_0x4()) { points += 4; }
            if (hyperv_brand()) { points += 4; }
            if (rdtsc_check()) { points += 1.5; }
            if (sidt_check()) { points += 4; }
            if (vmware_port()) { points += 3; }
            if (sidt5()) { points += 2; }
        #endif

        #if (LINUX)
            if (temperature()) { points += 1; }
            if (systemd_virt()) { points += 5; }
            if (chassis_vendor()) { points += 4.5; }
            if (chassis_type()) { points += 1; }
            if (dockerenv()) { points += 3; }
            if (dmidecode()) { points += 4; }
            if (dmesg()) { points += 3.5; }
            if (hwmon()) { points += 0.5; }
        #elif (MSVC)
            if (cursor_check()) { points += 0.5; }
            if (vmware_registry()) { points += 4.5; }
            if (vbox_registry()) { points += 4.5; }
            if (user_check()) { points += 1; }
            if (DLL_check()) { points += 3; } // might update this, idk
            if (registry_key()) { points += 5; }
            if (sunbelt_check()) { points += 1; }
        #endif

        /** 
         * you can change this threshold score to a maximum
         * of something like 10~14 if you want to be extremely
         * sure, but this can risk the result to be a false
         * negative if the detection bar is far too high.
         */
        const bool result = (points >= 6.5);

        sv current_brand = "";

/* (left for debug stuff)
        for (const auto p : scoreboard) {
            std::cout << "\n" << (int)p.second << " : " << p.first;
        }
*/

        // fetch the brand with the most points in the scoreboard
        #if (CPP >= 20)
            auto it = std::ranges::max_element(scoreboard, {},
                [](const auto &pair) {
                    return pair.second;
                }
            );

            if (it != scoreboard.end()) {
                current_brand = it->first;
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