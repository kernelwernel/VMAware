/**
 * ██╗   ██╗███╗   ███╗ █████╗ ██╗    ██╗ █████╗ ██████╗ ███████╗
 * ██║   ██║████╗ ████║██╔══██╗██║    ██║██╔══██╗██╔══██╗██╔════╝
 * ██║   ██║██╔████╔██║███████║██║ █╗ ██║███████║██████╔╝█████╗
 * ╚██╗ ██╔╝██║╚██╔╝██║██╔══██║██║███╗██║██╔══██║██╔══██╗██╔══╝
 *  ╚████╔╝ ██║ ╚═╝ ██║██║  ██║╚███╔███╔╝██║  ██║██║  ██║███████╗
 *   ╚═══╝  ╚═╝     ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ 1.5 (June 2024)
 *
 *  C++ VM detection library
 *
 *  - Made by: @kernelwernel (https://github.com/kernelwernel)
 *  - Contributed by:
 *      - Requiem (https://github.com/NotRequiem)
 *      - Alex (https://github.com/greenozon)
 *      - Marek Knápek (https://github.com/MarekKnapek)
 *      - Vladyslav Miachkov (https://github.com/fameowner99)
 *      - Alan Tse (https://github.com/alandtse)
 *  - Repository: https://github.com/kernelwernel/VMAware
 *  - Docs: https://github.com/kernelwernel/VMAware/docs/documentation.md
 *  - Full credits: https://github.com/kernelwernel/VMAware#credits-and-contributors-%EF%B8%8F
 *  - License: GPL-3.0
 *
 *
 * ================================ SECTIONS ==================================
 * - enums for publicly accessible techniques  => line 293
 * - struct for internal cpu operations        => line 488
 * - struct for internal memoization           => line 859
 * - struct for internal utility functions     => line 949
 * - struct for internal core components       => line 7337
 * - start of internal VM detection techniques => line 1727
 * - start of public VM detection functions    => line 7693
 * - start of externally defined variables     => line 8038
 *
 *
 * ================================ EXAMPLE ==================================
 * #include "vmaware.hpp"
 * #include <iostream>
 *
 * int main() {
 *     if (VM::detect()) {
 *         std::cout << "Virtual machine detected!" << std::endl;
 *         std::cout << "VM name: " << VM::brand() << std::endl;
 *     } else {
 *         std::cout << "Running in baremetal" << std::endl;
 *     }
 *
 *     std::cout << "VM certainty: " << (int)VM::percentage() << "%" << std::endl;
 * }
 */


#if (defined(_MSC_VER) || defined(_WIN32) || defined(_WIN64) || defined(__MINGW32__))
#define MSVC 1
#define LINUX 0
#define APPLE 0
#elif (defined(__linux__))
#define MSVC 0
#define LINUX 1
#define APPLE 0
#elif (defined(__APPLE__) || defined(__APPLE_CPP__) || defined(__MACH__) || defined(__DARWIN))
#define MSVC 0
#define LINUX 0
#define APPLE 1
#else
#define MSVC 0
#define LINUX 0
#define APPLE 0
#endif

 // shorter and succinct macros
#if __cplusplus > 202100L
#define CPP 23
#ifdef __VMAWARE_DEBUG__
#pragma message("using post-C++23, set back to C++23 standard")
#endif
#elif __cplusplus == 202100L
#define CPP 23
#ifdef __VMAWARE_DEBUG__
#pragma message("using C++23")
#endif
#elif __cplusplus == 202002L
#define CPP 20
#ifdef __VMAWARE_DEBUG__
#pragma message("using C++20")
#endif
#elif __cplusplus == 201703L
#define CPP 17
#ifdef __VMAWARE_DEBUG__
#pragma message("using C++17")
#endif
#elif __cplusplus == 201402L
#define CPP 14
#ifdef __VMAWARE_DEBUG__
#pragma message("using C++14")
#endif
#elif __cplusplus == 201103L
#define CPP 11
#ifdef __VMAWARE_DEBUG__
#pragma message("using C++11")
#endif
#elif __cplusplus < 201103L
#define CPP 1
#ifdef __VMAWARE_DEBUG__
#pragma message("using pre-C++11")
#endif
#else
#define CPP 0
#ifdef __VMAWARE_DEBUG__
#pragma message("Unknown C++ standard")
#endif
#endif

#if (CPP < 11 && !MSVC)
#error "VMAware only supports C++11 or above, set your compiler flag to '-std=c++20' for gcc/clang, or '/std:c++20' for MSVC"
#endif

#if (defined(__x86_64__) || defined(__i386__) || defined(_M_IX86) || defined(_M_X64))
#define x86 1
#else
#define x86 0
#endif
#if (defined(_M_IX86))
#define x86_32 1
#else
#define x86_32 0
#endif
#if (defined(__arm__) || defined(__ARM_LINUX_COMPILER__) || defined(__aarch64__) || defined(_M_ARM64))
#define ARM 1
#else
#define ARM 0
#endif

#if defined(__clang__)
#define GCC 0
#define CLANG 1
#elif defined(__GNUC__)
#define GCC 1
#define CLANG 0
#else
#define GCC 0
#define CLANG 0
#endif

#if !(defined(MSVC) || defined(LINUX) || defined(APPLE))
#warning "Unknown OS detected, tests will be severely limited"
#endif

#if (CPP >= 23)
#include <limits>
#endif
#if (CPP >= 20)
#include <bit>
#include <ranges>
#include <source_location>
#endif
#if (CPP >= 17)
#include <filesystem>
#endif
#ifdef __VMAWARE_DEBUG__
#include <iomanip>
#include <ios>
#endif

#if (MSVC)
#pragma warning(push, 0) // disable the windows SDK errors temporarily
#endif

#include <functional>
#include <cstring>
#include <string>
#include <fstream>
#include <regex>
#include <thread>
#include <cstdint>
#include <map>
#include <unordered_map>
#include <array>
#include <algorithm>
#include <iostream>
#include <cassert>
#include <cmath>
#include <sstream>
#include <bitset>
#include <type_traits>

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
#include <winuser.h>
#include <versionhelpers.h>
#include <psapi.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <shlwapi.h>
#include <shlobj_core.h>
#include <strmif.h>
#include <dshow.h>
#include <stdio.h>
#include <io.h>
#include <winspool.h>
#include <wtypes.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "MPR")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "strmiids.lib")
#pragma comment(lib, "uuid.lib")
#pragma comment(lib, "ntdll.lib")

#ifdef _UNICODE
#define tregex std::wregex
#else
#define tregex std::regex
#endif

#elif (LINUX)
#if (x86)
#include <cpuid.h>
#include <x86intrin.h>
#include <immintrin.h>
#endif
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <net/if.h> 
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <memory>
#include <cctype>
#include <fcntl.h>
#include <limits.h>
#elif (APPLE)
#include <sys/types.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <chrono>
#endif

#if (!MSVC)
#define TCHAR char
#endif

#if (MSVC)
#pragma warning(pop) // enable all warnings
#endif

// macro shortcut to disable MSVC warnings
#if (MSVC)
#define MSVC_DISABLE_WARNING(...) __pragma(warning(disable : __VA_ARGS__))
#define MSVC_ENABLE_WARNING(...) __pragma(warning(default : __VA_ARGS__))
#else
#define MSVC_DISABLE_WARNING(...)
#define MSVC_ENABLE_WARNING(...)
#endif

// MSVC-specific errors
#define SPECTRE 5045
#define ASSIGNMENT_OPERATOR 4626
#define NO_INLINE_FUNC 4514
#define PADDING 4820
#define FS_HANDLE 4733

MSVC_DISABLE_WARNING(ASSIGNMENT_OPERATOR NO_INLINE_FUNC SPECTRE)

#ifdef __VMAWARE_DEBUG__
#define debug(...) VM::util::debug_msg(__VA_ARGS__)
#define core_debug(...) VM::util::core_debug_msg(__VA_ARGS__)
#else
#define debug(...)
#define core_debug(...)
#endif

struct VM {
private:
    using u8  = std::uint8_t;
    using u16 = std::uint16_t;
    using u32 = std::uint32_t;
    using u64 = std::uint64_t;
    using i8  = std::int8_t;
    using i16 = std::int16_t;
    using i32 = std::int32_t;
    using i64 = std::int64_t;

public:
    enum enum_flags : u8 {
        VMID = 0,
        CPU_BRAND,
        HYPERVISOR_BIT,
        CPUID_0X4,
        HYPERVISOR_STR,
        RDTSC,
        THREADCOUNT,
        MAC,
        TEMPERATURE,
        SYSTEMD,
        CVENDOR,
        CTYPE,
        DOCKERENV,
        DMIDECODE,
        DMESG,
        HWMON,
        SIDT5,
        CURSOR,
        VMWARE_REG,
        VBOX_REG,
        USER,
        DLL,
        REGISTRY,
        CWSANDBOX_VM,
        VM_FILES,
        HWMODEL,
        DISK_SIZE,
        VBOX_DEFAULT,
        VBOX_NETWORK,
        COMPUTER_NAME,     // GPL
        WINE_CHECK,        // GPL
        HOSTNAME,          // GPL
        MEMORY,            // GPL
        VBOX_WINDOW_CLASS, // GPL
        LOADED_DLLS,       // GPL
        KVM_REG,           // GPL
        KVM_DRIVERS,       // GPL
        KVM_DIRS,          // GPL
        AUDIO,             // GPL
        QEMU_DIR,          // GPL 
        VMWARE_DEVICES,    // GPL
        MOUSE_DEVICE,      // GPL
        VM_PROCESSES,
        LINUX_USER_HOST,
        GAMARUE,
        VMID_0X4,
        PARALLELS_VM,
        RDTSC_VMEXIT,
        QEMU_BRAND,
        BOCHS_CPU,
        VPC_BOARD,
        HYPERV_WMI,
        HYPERV_REG,
        BIOS_SERIAL,
        VBOX_FOLDERS,
        MSSMBIOS,
        MAC_MEMSIZE,
        MAC_IOKIT,
        IOREG_GREP,
        MAC_SIP,
        HKLM_REGISTRIES,
        QEMU_GA,
        VALID_MSR,
        QEMU_PROC,
        VPC_PROC,
        VPC_INVALID,
        SIDT,
        SGDT,
        SLDT,
        OFFSEC_SIDT,
        OFFSEC_SGDT,
        OFFSEC_SLDT,
        HYPERV_BOARD,
        VM_FILES_EXTRA,
        VPC_SIDT,
        VMWARE_IOMEM,
        VMWARE_IOPORTS,
        VMWARE_SCSI,
        VMWARE_DMESG,
        VMWARE_STR,
        VMWARE_BACKDOOR,
        VMWARE_PORT_MEM,
        SMSW,
        MUTEX,
        UPTIME,
        ODD_CPU_THREADS,
        INTEL_THREAD_MISMATCH,
        XEON_THREAD_MISMATCH,
        NETTITUDE_VM_MEMORY,
        HYPERV_CPUID,
        CUCKOO_DIR,
        CUCKOO_PIPE,
        HYPERV_HOSTNAME,
        GENERAL_HOSTNAME,
        SCREEN_RESOLUTION,
        DEVICE_STRING,

        // start of non-technique flags (THE ORDERING IS VERY SPECIFIC AND MIGHT BREAK SOMETHING IDK)
        EXTREME,
        NO_MEMO,
        HIGH_THRESHOLD,
        ENABLE_HYPERV_HOST,
        WIN_HYPERV_DEFAULT [[deprecated("Use VM::ENABLE_HYPERV_HOST instead")]],
        MULTIPLE
    };

private:
    static constexpr u8 enum_size = MULTIPLE; // get enum size through value of last element
    static constexpr u8 non_technique_count = MULTIPLE - EXTREME + 1; // get number of non-technique flags like VM::NO_MEMO for example
    static constexpr u8 WIN_HYPERV_DEFAULT_MACRO = ENABLE_HYPERV_HOST + 1; // can't use orignal enum value because that would give compiler warnings of deprecated usage
    static constexpr u8 INVALID = 255; // explicit invalid technique macro
    static constexpr u16 maximum_points = 4765; // theoretical total points if all VM detections returned true (which is practically impossible)
    static constexpr u16 high_threshold_score = 350; // new threshold score from 100 to 350 if VM::HIGH_THRESHOLD flag is enabled
    static constexpr bool SHORTCUT = true; // macro for whether VM::core::run_all() should take a shortcut by skipping the rest of the techniques if the threshold score is already met

    // intended for loop indexes
    static constexpr u8 enum_begin = 0;
    static constexpr u8 enum_end = enum_size + 1;
    static constexpr u8 technique_begin = enum_begin;
    static constexpr u8 technique_end = EXTREME;
    static constexpr u8 non_technique_begin = EXTREME;
    static constexpr u8 non_technique_end = enum_end;

public:
    static constexpr u8 technique_count = EXTREME; // get total number of techniques
    static std::vector<u8> technique_vector;
#ifdef __VMAWARE_DEBUG__
    static u16 total_points;
#endif

private:

#if (MSVC)
    using brand_score_t = i32;
#else
    using brand_score_t = u8;
#endif

    // for the flag bitset structure
    using flagset = std::bitset<enum_size + 1>;

public:
    // this will allow the enum to be used in the public interface as "VM::TECHNIQUE"
    enum enum_flags tmp_ignore_this = NO_MEMO;

    // constructor shit ignore this
    VM() = delete;
    VM(const VM&) = delete;
    VM(VM&&) = delete;

    static flagset DEFAULT; // default bitset that will be run if no parameters are specified
    static flagset ALL; // same as default, but with cursor check included

private:

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
    static constexpr const char* VBOX = "VirtualBox";
    static constexpr const char* VMWARE = "VMware";
    static constexpr const char* VMWARE_EXPRESS = "VMware Express";
    static constexpr const char* VMWARE_ESX = "VMware ESX";
    static constexpr const char* VMWARE_GSX = "VMware GSX";
    static constexpr const char* VMWARE_WORKSTATION = "VMware Workstation";
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
    static constexpr const char* CWSANDBOX = "CWSandbox";
    static constexpr const char* COMODO = "Comodo";
    static constexpr const char* BOCHS = "Bochs";
    static constexpr const char* KVM_HYPERV = "KVM Hyper-V Enlightenment";
    static constexpr const char* NVMM = "NVMM";
    static constexpr const char* BSD_VMM = "OpenBSD VMM";
    static constexpr const char* INTEL_HAXM = "Intel HAXM";
    static constexpr const char* UNISYS = "Unisys s-Par";
    static constexpr const char* LMHS = "Lockheed Martin LMHS"; // yes, you read that right. The library can now detect VMs running on US military fighter jets, apparently.
    static constexpr const char* CUCKOO = "Cuckoo";

    // macro for bypassing unused parameter/variable warnings
#define UNUSED(x) ((void)(x))

// likely and unlikely macros
#if (LINUX)
#define VMAWARE_UNLIKELY(x) __builtin_expect(!!(x), 0)
#define VMAWARE_LIKELY(x)   __builtin_expect(!!(x), 1)
#else
#define VMAWARE_UNLIKELY
#define VMAWARE_LIKELY
#endif

    // various cpu operation stuff
    struct cpu {
        // cpuid leaf values
        struct leaf {
            static constexpr u32
                func_ext = 0x80000000,
                proc_ext = 0x80000001,
                brand1 = 0x80000002,
                brand2 = 0x80000003,
                brand3 = 0x80000004,
                hypervisor = 0x40000000,
                amd_easter_egg = 0x8fffffff;
        };

        // cross-platform wrapper function for linux and MSVC cpuid
        static void cpuid
        (
            u32& a, u32& b, u32& c, u32& d,
            const u32 a_leaf,
            const u32 c_leaf = 0xFF  // dummy value if not set manually
        ) {
#if (x86)
            // may be unmodified for older 32-bit processors, clearing just in case
            b = 0;
            c = 0;
#if (MSVC)
            int32_t x[4]{};
            __cpuidex((int32_t*)x, static_cast<int>(a_leaf), static_cast<int>(c_leaf));
            a = static_cast<u32>(x[0]);
            b = static_cast<u32>(x[1]);
            c = static_cast<u32>(x[2]);
            d = static_cast<u32>(x[3]);
#elif (LINUX)
            __cpuid_count(a_leaf, c_leaf, a, b, c, d);
#endif
#else
            return;
#endif
        };

        // same as above but for array type parameters (MSVC specific)
        static void cpuid
        (
            int32_t x[4],
            const u32 a_leaf,
            const u32 c_leaf = 0xFF
        ) {
#if (x86)
            // may be unmodified for older 32-bit processors, clearing just in case
            x[1] = 0;
            x[2] = 0;
#if (MSVC)
            __cpuidex((int32_t*)x, static_cast<int>(a_leaf), static_cast<int>(c_leaf));
#elif (LINUX)
            __cpuid_count(a_leaf, c_leaf, x[0], x[1], x[2], x[3]);
#endif
#else
            return;
#endif
        };

        // check for maximum function leaf
        static bool is_leaf_supported(const u32 p_leaf) {
            u32 eax, unused = 0;
            cpu::cpuid(eax, unused, unused, unused, cpu::leaf::func_ext);

            debug("CPUID function: highest leaf = ", eax);

            return (p_leaf <= eax);
        }

        // check AMD
        [[nodiscard]] static bool is_amd() {
            constexpr u32 amd_ecx = 0x69746e65;

            u32 unused, ecx = 0;
            cpuid(unused, unused, ecx, unused, 0);

            return (ecx == amd_ecx);
        }

        // check Intel
        [[nodiscard]] static bool is_intel() {
            constexpr u32 intel_ecx = 0x6c65746e;

            u32 unused, ecx = 0;
            cpuid(unused, unused, ecx, unused, 0);

            return (ecx == intel_ecx);
        }

        // check for POSSIBILITY of hyperthreading, I don't think there's a 
        // full-proof method to detect if you're actually hyperthreading imo.
        [[nodiscard]] static bool has_hyperthreading() {
            u32 eax, ebx, ecx, edx;

            cpuid(eax, ebx, ecx, edx, 1);

            bool htt_available = (edx & (1 << 28));

            if (!htt_available) {
                return false;
            }

            i32 logical_cores = ((ebx >> 16) & 0xFF);
            i32 physical_cores = 0;

#if (MSVC)
            SYSTEM_INFO sysinfo;
            GetSystemInfo(&sysinfo);
            physical_cores = sysinfo.dwNumberOfProcessors;
#elif (LINUX)
            physical_cores = static_cast<i32>(sysconf(_SC_NPROCESSORS_CONF));
#elif (APPLE)
            sysctlbyname("hw.physicalcpu", &physical_cores, sizeof(physical_cores), NULL, 0);
#else
            return false;
#endif

            return (logical_cores > physical_cores);
        }

        // get the CPU product
        [[nodiscard]] static std::string get_brand() {
            if (memo::cpu_brand::is_cached()) {
                return memo::cpu_brand::fetch();
            }

            if (!core::cpuid_supported) {
                return "Unknown";
            }

#if (!x86)
            return "Unknown";
#else
            if (!cpu::is_leaf_supported(cpu::leaf::brand3)) {
                return "Unknown";
            }

            std::array<u32, 4> buffer{};
            constexpr std::size_t buffer_size = sizeof(int32_t) * buffer.size();
            std::array<char, 64> charbuffer{};

            constexpr std::array<u32, 3> ids = { {
                cpu::leaf::brand1,
                cpu::leaf::brand2,
                cpu::leaf::brand3
            } };

            std::string brand = "";

            for (const u32& id : ids) {
                cpu::cpuid(buffer.at(0), buffer.at(1), buffer.at(2), buffer.at(3), id);

                std::memcpy(charbuffer.data(), buffer.data(), buffer_size);

                const char* convert = charbuffer.data();
                brand += convert;
            }

            debug("BRAND: ", "cpu brand = ", brand);

            memo::cpu_brand::store(brand);

            return brand;
#endif
        }

        struct model_struct {
            bool found;
            bool is_xeon;
            bool is_i_series;
            bool is_ryzen;
            std::string string;
        };

        [[nodiscard]] static model_struct get_model() {
            const std::string brand = get_brand();

            constexpr const char* intel_i_series_regex = "i[0-9]-[A-Z0-9]{1,7}";
            constexpr const char* intel_xeon_series_regex = "[DEW]-[A-Z0-9]{1,7}";
            constexpr const char* amd_ryzen_regex = "^(PRO)?[A-Z0-9]{1,7}";

            std::string match_str = "";

            auto match = [&](const char* regex) -> bool {
                std::regex pattern(regex);

                auto words_begin = std::sregex_iterator(brand.begin(), brand.end(), pattern);
                auto words_end = std::sregex_iterator();

                for (std::sregex_iterator i = words_begin; i != words_end; ++i) {
                    std::smatch match = *i;
                    match_str = match.str();
                }

                if (!match_str.empty()) {
                    return true;
                }

                return false;
            };

            bool found = false;
            bool is_xeon = false;
            bool is_i_series = false;
            bool is_ryzen = false;

            if (cpu::is_intel()) {
                if (match(intel_i_series_regex)) {
                    found = true;
                    is_i_series = true;
                } else if (match(intel_xeon_series_regex)) {
                    found = true;
                    is_xeon = true;
                }
            }

            if (cpu::is_amd()) {
                if (match(amd_ryzen_regex)) {
                    found = true;
                    is_ryzen = true;
                }
            }

            return model_struct{ found, is_xeon, is_i_series, is_ryzen, match_str };
        };

#if (CPP >= 17)
        [[nodiscard]] static bool vmid_template(const u32 p_leaf, [[maybe_unused]] const char* technique_name) {
#else 
        [[nodiscard]] static bool vmid_template(const u32 p_leaf, const char* technique_name) {
#endif
#if (CPP >= 17)
            constexpr std::string_view
#else
            const std::string
#endif
                bhyve = "bhyve bhyve ",
                bhyve2 = "BHyVE BHyVE ",
                kvm = "KVMKVMKVM\0\0\0",
                kvm_hyperv = "Linux KVM Hv",
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
                qnx2 = "QXNQSBMV",
                nvmm = "___ NVMM ___",
                openbsd_vmm = "OpenBSDVMM58",
                intel_haxm = "HAXMHAXMHAXM",
                virtapple = "VirtualApple",
                unisys = "UnisysSpar64",
                lmhs = "SRESRESRESRE";

            auto cpuid_thingy = [](const u32 p_leaf, u32* regs, std::size_t start = 0, std::size_t end = 4) -> bool {
                u32 x[4]{};
                cpu::cpuid(x[0], x[1], x[2], x[3], p_leaf);

                for (; start < end; start++) {
                    *regs++ = x[start];
                }

                return true;
                };

            std::string brand = "";
            u32 sig_reg[3] = { 0 };

            if (!cpuid_thingy(p_leaf, sig_reg, 1)) {
                return false;
            }

            auto strconvert = [](u64 n) -> std::string {
                const std::string& str(reinterpret_cast<char*>(&n));
                return str;
                };

            std::stringstream ss1;
            std::stringstream ss2;

            ss1 << strconvert(sig_reg[0]);
            ss1 << strconvert(sig_reg[1]);
            ss1 << strconvert(sig_reg[2]);

            ss2 << strconvert(sig_reg[0]);
            ss2 << strconvert(sig_reg[2]);
            ss2 << strconvert(sig_reg[1]);

            std::string brand1 = ss1.str();
            std::string brand2 = ss2.str();

            if (brand1.empty() && brand2.empty()) {
                return false;
            }

            debug(technique_name, brand1);
            debug(technique_name, brand2);

#if (CPP < 17)
            // bypass compiler warning about unused parameter, ignore this
            UNUSED(technique_name);
#endif

            const std::vector<std::string> brand_streams = { brand1, brand2 };

            for (const auto& tmp_brand : brand_streams) {
                if (tmp_brand == qemu) { return core::add(QEMU); }
                if (tmp_brand == vmware) { return core::add(VMWARE); }
                if (tmp_brand == vbox) { return core::add(VBOX); }
                if (tmp_brand == bhyve) { return core::add(BHYVE); }
                if (tmp_brand == bhyve2) { return core::add(BHYVE); }
                if (tmp_brand == kvm) { return core::add(KVM); }
                if (tmp_brand == kvm_hyperv) { return core::add(KVM_HYPERV); }
                if (tmp_brand == xta) { return core::add(MSXTA); }
                if (tmp_brand == parallels) { return core::add(PARALLELS); }
                if (tmp_brand == parallels2) { return core::add(PARALLELS); }
                if (tmp_brand == xen) { return core::add(XEN); }
                if (tmp_brand == acrn) { return core::add(ACRN); }
                if (tmp_brand == qnx) { return core::add(QNX); }
                if (tmp_brand == virtapple) { return core::add(VAPPLE); }
                if (tmp_brand == nvmm) { return core::add(NVMM); }
                if (tmp_brand == openbsd_vmm) { return core::add(BSD_VMM); }
                if (tmp_brand == intel_haxm) { return core::add(INTEL_HAXM); }
                if (tmp_brand == unisys) { return core::add(UNISYS); }
                if (tmp_brand == lmhs) { return core::add(LMHS); }

                // both Hyper-V and VirtualPC have the same string value
                if (tmp_brand == hyperv) {
                    bool tmp = core::add(VPC);
                    UNUSED(tmp);
                    return core::add(HYPERV);
                }

                /**
                 * this is added because there are inconsistent string
                 * values for KVM's manufacturer ID. For example,
                 * it gives me "KVMKMVMKV" when I run it under QEMU
                 * but the Wikipedia article on CPUID says it's
                 * "KVMKVMKVM\0\0\0", like wtf????
                 */
                if (util::find(tmp_brand, "KVM")) {
                    return core::add(KVM);
                }

                /**
                 * i'm honestly not sure about this one,
                 * it's supposed to have 12 characters but
                 * Wikipedia tells me it has 8, so i'm just
                 * going to scan for the entire string ig
                 */
#if (CPP >= 17)
                const char* qnx_sample = qnx2.data();
#else
                const char* qnx_sample = qnx2.c_str();
#endif

                if (util::find(tmp_brand, qnx_sample)) {
                    return core::add(QNX);
                }
            }

            return false;
        }
        };

    // memoization
    struct memo {
    private:
        using result_t = bool;
        using points_t = u8;

    public:
        struct data_t {
            result_t result;
            points_t points;
        };

    private:
        static std::map<u8, data_t> cache_table;
        static flagset cache_keys;

    public:
        static void cache_store(const u8 technique_macro, const result_t result, const points_t points) {
            cache_table[technique_macro] = { result, points };
            cache_keys.set(technique_macro);
        }

        static bool is_cached(const u8 technique_macro) {
            return cache_keys.test(technique_macro);
        }

        static data_t cache_fetch(const u8 technique_macro) {
            return cache_table.at(technique_macro);
        }

        // basically checks whether all the techniques were cached (with exception of VM::CURSOR)
        static bool all_present() {
            if (cache_table.size() == technique_count) {
                return true;
            }
            else if (cache_table.size() == static_cast<std::size_t>(technique_count) - 1) {
                return (!cache_keys.test(CURSOR));
            }

            return false;
        }

        struct brand {
            static std::string brand_cache;

            static std::string fetch() {
                return brand_cache;
            }

            static void store(const std::string& p_brand) {
                brand_cache = p_brand;
            }

            static bool is_cached() {
                return (!brand_cache.empty());
            }
        };

        struct multi_brand {
            static std::string brand_cache;

            static std::string fetch() {
                return brand_cache;
            }

            static void store(const std::string& p_brand) {
                brand_cache = p_brand;
            }

            static bool is_cached() {
                return (!brand_cache.empty());
            }
        };

        struct cpu_brand {
            static std::string brand_cache;

            static std::string fetch() {
                return brand_cache;
            }

            static void store(const std::string& p_brand) {
                brand_cache = p_brand;
            }

            static bool is_cached() {
                return (!brand_cache.empty());
            }
        };
    };

    // miscellaneous functionalities
    struct util {
#if (LINUX)
        // fetch file data
        [[nodiscard]] static std::string read_file(const char* dir) {
            if (!exists(dir)) {
                return "";
            }

            std::ifstream file{};
            std::string data{};
            file.open(dir);

            if (file.is_open()) {
                file >> data;
            }

            file.close();
            return data;
        }
#endif

        [[nodiscard]] static bool exists(const char* path) {
#if (MSVC)
            return (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) || (GetLastError() != ERROR_FILE_NOT_FOUND);
#else 
#if (CPP >= 17)
            return std::filesystem::exists(path);
#elif (CPP >= 11)
            struct stat buffer;
            return (stat(path, &buffer) == 0);
#endif
#endif
        }

#if (MSVC) && (_UNICODE)
        // handle TCHAR conversion
        [[nodiscard]] static bool exists(const TCHAR* path)
        {
            char c_szText[_MAX_PATH];
            wcstombs(c_szText, path, wcslen(path) + 1);
            return exists(c_szText);
        }
#endif

        // wrapper for std::make_unique because it's not available for C++11
        template<typename T, typename... Args>
        [[nodiscard]] static std::unique_ptr<T> make_unique(Args&&... args) {
#if (CPP < 14)
            return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
#else
            return std::make_unique<T>(std::forward<Args>(args)...);
#endif
        }

        // self-explanatory
        [[nodiscard]] static bool is_admin() noexcept {
#if (LINUX || APPLE)
            const uid_t uid = getuid();
            const uid_t euid = geteuid();

            return (
                (uid != euid) ||
                (euid == 0)
                );
#elif (MSVC)
            BOOL is_admin = FALSE;
            HANDLE hToken = NULL;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
                DWORD dwSize = 0;
                if (!GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwSize) && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                    PTOKEN_MANDATORY_LABEL pTIL = (PTOKEN_MANDATORY_LABEL)malloc(dwSize);
                    if (pTIL != NULL) {
                        if (GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwSize, &dwSize)) {
                            SID* pSID = (SID*)GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));
                            DWORD dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid, (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));

                            if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
                                is_admin = TRUE;
                            }

                            UNUSED(pSID);
                        }
                        free(pTIL);
                    }
                }
            }

            if (hToken) {
                CloseHandle(hToken);
            }

            return is_admin;
#endif
        }

        // scan for keyword in string
        [[nodiscard]] static bool find(const std::string& base_str, const char* keyword) noexcept {
            return (base_str.find(keyword) != std::string::npos);
        };

        // for debug output
#ifdef __VMAWARE_DEBUG__
#if (CPP < 17)
        // Helper function to handle the recursion
        static inline void print_to_stream(std::ostream&) noexcept {
            // Base case: do nothing
        }

        template <typename T, typename... Args>
        static void print_to_stream(std::ostream& os, T&& first, Args&&... args) noexcept {
            os << std::forward<T>(first);
            using expander = int[];
            (void)expander {
                0, (void(os << std::forward<Args>(args)), 0)...
            };
        }
#endif

        template <typename... Args>
        static inline void debug_msg(Args... message) noexcept {
#if (LINUX || APPLE)
            constexpr const char* black_bg = "\x1B[48;2;0;0;0m";
            constexpr const char* bold = "\033[1m";
            constexpr const char* blue = "\x1B[38;2;00;59;193m";
            constexpr const char* ansiexit = "\x1B[0m";

            std::cout.setf(std::ios::fixed, std::ios::floatfield);
            std::cout.setf(std::ios::showpoint);

            std::cout << black_bg << bold << "[" << blue << "DEBUG" << ansiexit << bold << black_bg << "]" << ansiexit << " ";
#else       
            std::cout << "[DEBUG] ";
#endif

#if (CPP >= 17)
            ((std::cout << message), ...);
#else
            print_to_stream(std::cout, message...);
#endif

            std::cout << "\n";
        }

        template <typename... Args>
        static inline void core_debug_msg(Args... message) noexcept {
#if (LINUX || APPLE)
            constexpr const char* black_bg = "\x1B[48;2;0;0;0m";
            constexpr const char* bold = "\033[1m";
            constexpr const char* blue = "\x1B[38;2;255;180;5m";
            constexpr const char* ansiexit = "\x1B[0m";

            std::cout.setf(std::ios::fixed, std::ios::floatfield);
            std::cout.setf(std::ios::showpoint);

            std::cout << black_bg << bold << "[" << blue << "CORE DEBUG" << ansiexit << bold << black_bg << "]" << ansiexit << " ";
#else       
            std::cout << "[CORE DEBUG] ";
#endif

#if (CPP >= 17)
            ((std::cout << message), ...);
#else
            print_to_stream(std::cout, message...);
#endif

            std::cout << "\n";
        }
#endif

        // basically std::system but it runs in the background with std::string output
        [[nodiscard]] static std::unique_ptr<std::string> sys_result(const TCHAR* cmd) try {
#if (CPP < 14)
            std::unique_ptr<std::string> tmp(nullptr);
            UNUSED(cmd);
            return tmp;
#else
#if (LINUX || APPLE)
#if (ARM)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wignored-attributes"
#endif
            std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);

#if (ARM)
#pragma GCC diagnostic pop
#endif

            if (!pipe) {
                return nullptr;
            }

            std::string result{};
            std::array<char, 128> buffer{};

            while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
                result += buffer.data();
            }

            result.pop_back();

            return util::make_unique<std::string>(result);
#elif (MSVC)
            // Set up the structures for creating the process
            STARTUPINFO si = { 0 };
            PROCESS_INFORMATION pi = { 0 };
            si.cb = sizeof(si);

            // Create a pipe to capture the command output
            HANDLE hReadPipe, hWritePipe;
            SECURITY_ATTRIBUTES sa;
            sa.nLength = sizeof(SECURITY_ATTRIBUTES);
            sa.bInheritHandle = TRUE;
            sa.lpSecurityDescriptor = NULL;

            if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
                debug("sys_result: ", "error creating pipe");

                return nullptr;
            }

            // Set up the startup information with the write end of the pipe as the standard output
            si.hStdError = hWritePipe;
            si.hStdOutput = hWritePipe;
            si.dwFlags |= STARTF_USESTDHANDLES;

            // Create the process
            if (!CreateProcess(NULL, const_cast<TCHAR*>(cmd), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
                debug("sys_result: ", "error creating process");

                CloseHandle(hReadPipe);
                CloseHandle(hWritePipe);
                return nullptr;
            }

            // Close the write end of the pipe as it's not needed in this process
            CloseHandle(hWritePipe);

            // Read the output from the pipe
            char buffer[4096];
            DWORD bytesRead;
            std::string result;

            while (ReadFile(hReadPipe, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
                result.append(buffer, bytesRead);
            }

            // Close handles
            CloseHandle(hReadPipe);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);

            // Return the result as a unique_ptr<string>
            return util::make_unique<std::string>(result);
#endif
#endif
        }
        catch (...) {
            debug("sys_result: ", "caught error, returning nullptr");
            std::unique_ptr<std::string> tmp(nullptr);
            return tmp;
        }

        // get disk size in GB
        [[nodiscard]] static u32 get_disk_size() {
            u32 size = 0;
            constexpr u64 GB = (static_cast<u64>(1024 * 1024) * 1024);

#if (LINUX)
            struct statvfs stat;

            if (statvfs("/", &stat) != 0) {
                debug("private util::get_disk_size( function: ", "failed to fetch disk size");
                return false;
            }

            // in gigabytes
            size = static_cast<u32>((stat.f_blocks * stat.f_frsize) / GB);
#elif (MSVC)
            ULARGE_INTEGER totalNumberOfBytes;

            if (GetDiskFreeSpaceExW(
                L"C:",                      // Drive or directory path (use wide character string)
                nullptr,                    // Free bytes available to the caller (not needed for total size)
                reinterpret_cast<PULARGE_INTEGER>(&totalNumberOfBytes),  // Total number of bytes on the disk
                nullptr                     // Total number of free bytes on the disk (not needed for total size)
            )) {
                size = static_cast<u32>(totalNumberOfBytes.QuadPart) / GB;
            }

            else {
                debug("util::get_disk_size(: ", "failed to fetch size in GB");
            }
#endif

            if (size == 0) {
                return false;
            }

            // round to the nearest factor of 10
            const u32 result = static_cast<u32>(std::round((size / 10.0) * 10));

            debug("private util::get_disk_size( function: ", "disk size = ", result, "GB");

            return result;
        }

        // get physical RAM size in GB
        [[nodiscard]] static u64 get_physical_ram_size() {
#if (LINUX)
            if (!util::is_admin()) {
                debug("private get_physical_ram_size function: ", "not root, returned 0");
                return 0;
            }

            auto result = util::sys_result("dmidecode --type 19 | grep 'Size' | grep '[[:digit:]]*'");

            if (result == nullptr) {
                debug("private get_physical_ram_size function: ", "invalid system result from dmidecode, returned 0");
                return 0;
            }

            const bool MB = (std::regex_search(*result, std::regex("MB")));
            const bool GB = (std::regex_search(*result, std::regex("GB")));

            if (!(MB || GB)) {
                debug("private get_physical_ram_size function: ", "neither MB nor GB found, returned 0");
                return 0;
            }

            std::string number_str;
            bool in_number = false;

            for (char c : *result) {
                if (std::isdigit(c)) {
                    number_str += c;
                    in_number = true;
                }
                else if (in_number) {
                    break;
                }
            }

            if (number_str.empty()) {
                debug("private get_physical_ram_size_gb function: ", "string is empty, returned 0");
                return 0;
            }

            u64 number = 0;

            number = std::stoull(number_str);

            if (MB == true) {
                number = static_cast<u64>(std::round(number / 1024));
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

            return (total_memory_kb / (static_cast<unsigned long long>(1024) * 1024)); // MB
#else
            return 0;
#endif
        }

        // get available memory space
        [[nodiscard]] static u64 get_memory_space() {
#if (MSVC)
            MEMORYSTATUSEX statex = { 0 };
            statex.dwLength = sizeof(statex);
            GlobalMemoryStatusEx(&statex); // calls NtQuerySystemInformation
            return statex.ullTotalPhys;
#elif (LINUX)
            const i64 pages = sysconf(_SC_PHYS_PAGES);
            const i64 page_size = sysconf(_SC_PAGE_SIZE);
            return (pages * page_size);
#elif (APPLE)
            int32_t mib[2] = { CTL_HW, HW_MEMSIZE };
            u32 namelen = sizeof(mib) / sizeof(mib[0]);
            u64 size = 0;
            std::size_t len = sizeof(size);

            if (sysctl(mib, namelen, &size, &len, NULL, 0) < 0) {
                return 0;
            }

            return size; // in bytes
#endif
        }


        [[nodiscard]] static bool is_proc_running(const TCHAR* executable) {
#if (MSVC)
            DWORD processes[1024], bytesReturned;

            if (!EnumProcesses(processes, sizeof(processes), &bytesReturned))
                return false;

            DWORD numProcesses = bytesReturned / sizeof(DWORD);

            for (DWORD i = 0; i < numProcesses; ++i) {
                HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
                if (process != nullptr) {
                    TCHAR processName[MAX_PATH];
                    if (GetModuleBaseName(process, nullptr, processName, sizeof(processName) / sizeof(TCHAR))) {
                        if (!_tcsicmp(processName, executable)) {
                            CloseHandle(process);
                            return true;
                        }
                    }
                    CloseHandle(process);
                }
            }

            return false;
#elif (LINUX)
#if (CPP >= 17)
            for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
                if (!(entry.is_directory())) {
                    continue;
                }

                const std::string filename = entry.path().filename().string();
#else
            //DIR* dir = opendir("/proc/");
            std::unique_ptr<DIR, decltype(&closedir)> dir(opendir("/proc"), closedir);
            if (!dir) {
                debug("util::is_proc_running: ", "failed to open /proc directory");
                return false;
            }

            struct dirent* entry;
            while ((entry = readdir(dir.get())) != nullptr) {
                std::string filename(entry->d_name);
                if (filename == "." || filename == "..") {
                    continue;
                }
#endif
                if (!(std::all_of(filename.begin(), filename.end(), ::isdigit))) {
                    continue;
                }

                const std::string cmdline_file = "/proc/" + filename + "/cmdline";
                std::ifstream cmdline(cmdline_file);
                if (!(cmdline.is_open())) {
                    continue;
                }

                std::string line;
                std::getline(cmdline, line);
                cmdline.close();

                if (line.empty()) {
                    continue;
                }

                //std::cout << "\n\nLINE = " << line << "\n";
                if (line.find(executable) == std::string::npos) {
                    //std::cout << "skipped\n";
                    continue;
                }

                std::cout << "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\nNOT SKIPPED\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n";

                const std::size_t slash_index = line.find_last_of('/');

                if (slash_index == std::string::npos) {
                    continue;
                }

                line = line.substr(slash_index + 1);

                const std::size_t space_index = line.find_first_of(' ');

                if (space_index != std::string::npos) {
                    line = line.substr(0, space_index);
                }

                if (line != executable) {
                    continue;
                }
                //#if (CPP < 17)
                //                closedir(dir);
                //                free(dir);
                //#endif
                return true;
            }

            return false;
#else
            return false;
#endif
            }

            [[nodiscard]] static std::string get_hostname() {
#if (MSVC)
                char ComputerName[MAX_COMPUTERNAME_LENGTH + 1];
                DWORD cbComputerName = sizeof(ComputerName);

                if (GetComputerName(ComputerName, &cbComputerName)) {
                    return std::string(ComputerName);
                }
#elif (LINUX)
                char hostname[HOST_NAME_MAX];

                if (gethostname(hostname, sizeof(hostname)) == 0) {
                    return std::string(hostname);
                }
#endif

                return std::string();
            }


#if (MSVC)
        /**
         * @link: https://codereview.stackexchange.com/questions/249034/systeminfo-a-c-class-to-retrieve-system-management-data-from-the-bios
         * @author: arcomber
         */
        class sys_info {
        private:
#pragma pack(push) 
#pragma pack(1)
            /*
            SMBIOS Structure header (System Management BIOS) spec:
            https ://www.dmtf.org/sites/default/files/standards/documents/DSP0134_3.3.0.pdf
            */
            struct SMBIOSHEADER
            {
                uint8_t type;
                uint8_t length;
                uint16_t handle;
            };

            /*
            Structure needed to get the SMBIOS table using GetSystemFirmwareTable API.
            see https://docs.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemfirmwaretable
            */
            struct SMBIOSData {
                uint8_t  Used20CallingMethod;
                uint8_t  SMBIOSMajorVersion;
                uint8_t  SMBIOSMinorVersion;
                uint8_t  DmiRevision;
                uint32_t  Length;
                uint8_t  SMBIOSTableData[1];
            };

            // System Information (Type 1)
            struct SYSTEMINFORMATION {
                SMBIOSHEADER Header;
                uint8_t Manufacturer;
                uint8_t ProductName;
                uint8_t Version;
                uint8_t SerialNumber;
                uint8_t UUID[16];
                uint8_t WakeUpType;  // Identifies the event that caused the system to power up
                uint8_t SKUNumber;   // identifies a particular computer configuration for sale
                uint8_t Family;
            };
#pragma pack(pop) 

            // helper to retrieve string at string offset. Optional null string description can be set.
            const char* get_string_by_index(const char* str, int index, const char* null_string_text = "")
            {
                if (0 == index || 0 == *str) {
                    return null_string_text;
                }

                while (--index) {
                    str += strlen(str) + 1;
                }
                return str;
            }

            // retrieve the BIOS data block from the system
            SMBIOSData* get_bios_data() {
                SMBIOSData* bios_data = nullptr;

                // GetSystemFirmwareTable with arg RSMB retrieves raw SMBIOS firmware table
                // return value is either size of BIOS table or zero if function fails
                DWORD bios_size = GetSystemFirmwareTable('RSMB', 0, NULL, 0);

                if (bios_size > 0) {
                    if (bios_data != nullptr) {
                        bios_data = (SMBIOSData*)malloc(bios_size);

                        // Retrieve the SMBIOS table
                        DWORD bytes_retrieved = GetSystemFirmwareTable('RSMB', 0, bios_data, bios_size);

                        if (bytes_retrieved != bios_size) {
                            free(bios_data);
                            bios_data = nullptr;
                        }
                    }
                }

                return bios_data;
            }


            // locates system information memory block in BIOS table
            SYSTEMINFORMATION* find_system_information(SMBIOSData* bios_data) {
                uint8_t* data = bios_data->SMBIOSTableData;

                while (data < bios_data->SMBIOSTableData + bios_data->Length)
                {
                    uint8_t* next;
                    SMBIOSHEADER* header = (SMBIOSHEADER*)data;

                    if (header->length < 4)
                        break;

                    //Search for System Information structure with type 0x01 (see para 7.2)
                    if (header->type == 0x01 && header->length >= 0x19)
                    {
                        return (SYSTEMINFORMATION*)header;
                    }

                    //skip over formatted area
                    next = data + header->length;

                    //skip over unformatted area of the structure (marker is 0000h)
                    while (next < bios_data->SMBIOSTableData + bios_data->Length && (next[0] != 0 || next[1] != 0)) {
                        next++;
                    }
                    next += 2;

                    data = next;
                }
                return nullptr;
            }

        public:
            // System information data retrieved on construction and string members populated
            sys_info() {
                SMBIOSData* bios_data = get_bios_data();

                if (bios_data) {
                    SYSTEMINFORMATION* sysinfo = find_system_information(bios_data);
                    if (sysinfo) {
                        const char* str = (const char*)sysinfo + sysinfo->Header.length;

                        manufacturer_ = get_string_by_index(str, sysinfo->Manufacturer);
                        productname_ = get_string_by_index(str, sysinfo->ProductName);
                        serialnumber_ = get_string_by_index(str, sysinfo->SerialNumber);
                        version_ = get_string_by_index(str, sysinfo->Version);

                        // for v2.1 and later
                        if (sysinfo->Header.length > 0x08)
                        {
                            static const int max_uuid_size{ 50 };
                            char uuid[max_uuid_size] = {};
                            _snprintf_s(uuid, max_uuid_size, static_cast<size_t>(max_uuid_size) - 1, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                                sysinfo->UUID[0], sysinfo->UUID[1], sysinfo->UUID[2], sysinfo->UUID[3],
                                sysinfo->UUID[4], sysinfo->UUID[5], sysinfo->UUID[6], sysinfo->UUID[7],
                                sysinfo->UUID[8], sysinfo->UUID[9], sysinfo->UUID[10], sysinfo->UUID[11],
                                sysinfo->UUID[12], sysinfo->UUID[13], sysinfo->UUID[14], sysinfo->UUID[15]);

                            uuid_ = uuid;
                        }

                        if (sysinfo->Header.length > 0x19)
                        {
                            // supported in v 2.4 spec
                            sku_ = get_string_by_index(str, sysinfo->SKUNumber);
                            family_ = get_string_by_index(str, sysinfo->Family);
                        }
                    }
                    free(bios_data);
                }
            }

            // get product family
            const std::string get_family() const {
                return family_;
            }

            // get manufacturer - generally motherboard or system assembler name
            const std::string get_manufacturer() const {
                return manufacturer_;
            }

            // get product name
            const std::string get_productname() const {
                return productname_;
            }

            // get BIOS serial number
            const std::string get_serialnumber() const {
                return serialnumber_;
            }

            // get SKU / system configuration
            const std::string get_sku() const {
                return sku_;
            }

            // get a universally unique identifier for system
            const std::string get_uuid() const {
                return uuid_;
            }

            // get version of system information
            const std::string get_version() const {
                return version_;
            }

            sys_info(sys_info const&) = delete;
            sys_info& operator=(sys_info const&) = delete;

        private:
            std::string family_;
            std::string manufacturer_;
            std::string productname_;
            std::string serialnumber_;
            std::string sku_;
            std::string uuid_;
            std::string version_;
        };

        [[nodiscard]] static bool is_wow64() {
            BOOL isWow64 = FALSE;
            BOOL tmp = IsWow64Process(GetCurrentProcess(), &isWow64);
            return (tmp && isWow64);
        }

        // backup function in case the main get_windows_version function fails
        [[nodiscard]] static u8 get_windows_version_backup() {
            u8 ret = 0;
            NTSTATUS(WINAPI * RtlGetVersion)(LPOSVERSIONINFOEXW) = nullptr;
            OSVERSIONINFOEXW osInfo{};

            HMODULE ntdllModule = GetModuleHandleA("ntdll");

            if (ntdllModule == nullptr) {
                return false;
            }

            *(FARPROC*)&RtlGetVersion = GetProcAddress(ntdllModule, "RtlGetVersion");

            if (RtlGetVersion == nullptr) {
                return false;
            }

            if (RtlGetVersion != nullptr) {
                osInfo.dwOSVersionInfoSize = sizeof(osInfo);
                RtlGetVersion(&osInfo);
                ret = static_cast<u8>(osInfo.dwMajorVersion);
            }

            return ret;
        }

        // credits to @Requiem for the code, thanks man :)
        [[nodiscard]] static u8 get_windows_version() {
            typedef NTSTATUS(WINAPI* RtlGetVersionFunc)(PRTL_OSVERSIONINFOW);

            const std::map<DWORD, u8> windowsVersions = {
                { 6002, 6 }, // windows vista, technically no number but this function is just for great than operations anyway so it doesn't matter
                { 7601, 7 },
                { 9200, 8 },
                { 9600, 8 },
                { 10240, 10 },
                { 10586, 10 },
                { 14393, 10 },
                { 15063, 10 },
                { 16299, 10 },
                { 17134, 10 },
                { 17763, 10 },
                { 18362, 10 },
                { 18363, 10 },
                { 19041, 10 },
                { 19042, 10 },
                { 19043, 10 },
                { 19044, 10 },
                { 19045, 10 },
                { 22000, 11 },
                { 22621, 11 },
                { 22631, 11 }
            };

            HMODULE ntdll = LoadLibraryW(L"ntdll.dll");
            if (!ntdll) {
                return util::get_windows_version_backup();
            }

            RtlGetVersionFunc pRtlGetVersion = (RtlGetVersionFunc)GetProcAddress(ntdll, "RtlGetVersion");
            if (!pRtlGetVersion) {
                return util::get_windows_version_backup();
            }

            RTL_OSVERSIONINFOW osvi{};
            osvi.dwOSVersionInfoSize = sizeof(osvi);

            if (pRtlGetVersion(&osvi) != 0) {
                return util::get_windows_version_backup();
            }

            u8 major_version = 0;

            if (windowsVersions.find(osvi.dwBuildNumber) != windowsVersions.end()) {
                major_version = windowsVersions.at(osvi.dwBuildNumber);
            }

            FreeLibrary(ntdll);

            if (major_version == 0) {
                return util::get_windows_version_backup();
            }

            return major_version;
        }
#endif
        };

private: // START OF PRIVATE VM DETECTION TECHNIQUE DEFINITIONS
    /**
     * @brief Check CPUID output of manufacturer ID for known VMs/hypervisors
     * @category x86
     */
    [[nodiscard]] static bool vmid() try {
#if (!x86)
        return false;
#else
        if (!core::cpuid_supported) {
            return false;
        }

        return cpu::vmid_template(0, "VMID: ");
#endif
    }
    catch (...) {
        debug("VMID: caught error, returned false");
        return false;
    }


    /**
     * @brief Check CPUID output of manufacturer ID for known VMs/hypervisors with leaf value 0x40000000
     * @category x86
     */
    [[nodiscard]] static bool vmid_0x4() try {
#if (!x86)
        return false;
#else
        if (!core::cpuid_supported) {
            return false;
        }

        return cpu::vmid_template(cpu::leaf::hypervisor, "VMID_0x4: ");
#endif
    }
    catch (...) {
        debug("VMID_0x4: caught error, returned false");
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
        if (!core::cpuid_supported) {
            return false;
        }

        std::string brand = cpu::get_brand();

        // TODO: might add more potential keywords, be aware that it could (theoretically) cause false positives
        constexpr std::array<const char*, 16> vmkeywords{ {
            "qemu", "kvm", "virtual", "vm",
            "vbox", "virtualbox", "vmm", "monitor",
            "bhyve", "hyperv", "hypervisor", "hvisor",
            "parallels", "vmware", "hvm", "qnx"
        } };

        u8 match_count = 0;

        for (auto it = vmkeywords.cbegin(); it != vmkeywords.cend(); it++) {
            const auto regex = std::regex(*it, std::regex::icase);
            const bool match = std::regex_search(brand, regex);

            if (match) {
                debug("BRAND_KEYWORDS: ", "match = ", *it);
                match_count++;
            }
        }

        debug("BRAND_KEYWORDS: ", "matches: ", static_cast<u32>(match_count));

        if (match_count > 0) {
            const auto qemu_regex = std::regex("QEMU", std::regex::icase);
            const bool qemu_match = std::regex_search(brand, qemu_regex);

            if (qemu_match) {
                return core::add(QEMU);
            }
        }

        return (match_count >= 1);
#endif
    }
    catch (...) {
        debug("BRAND_KEYWORDS: caught error, returned false");
        return false;
    }


    /**
     * @brief Match for QEMU CPU brand
     * @category x86
     */
    [[nodiscard]] static bool cpu_brand_qemu() try {
#if (!x86)
        return false;
#else
        if (!core::cpuid_supported) {
            return false;
        }

        std::string brand = cpu::get_brand();

        std::regex pattern("QEMU Virtual CPU", std::regex_constants::icase);

        if (std::regex_match(brand, pattern)) {
            return core::add(QEMU);
        }

        return false;
#endif
    }
    catch (...) {
        debug("QEMU_BRAND: caught error, returned false");
        return false;
    }


    /**
     * @brief Check if hypervisor feature bit in CPUID is enabled (always false for physical CPUs)
     * @category x86
     */
    [[nodiscard]] static bool hypervisor_bit() try {
#if (!x86)
        return false;
#else
        if (!core::cpuid_supported) {
            return false;
        }

        constexpr u8 hyperv_bit = 31;

        u32 unused, ecx = 0;
        cpu::cpuid(unused, unused, ecx, unused, 1);

        return (ecx & (1 << hyperv_bit));
#endif
    }
    catch (...) {
        debug("HYPERVISOR_BIT: caught error, returned false");
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
        if (!core::cpuid_supported) {
            return false;
        }

        u32 a, b, c, d = 0;

        for (u8 i = 0; i < 0xFF; ++i) {
            cpu::cpuid(a, b, c, d, (cpu::leaf::hypervisor + i));
            if ((a + b + c + d) != 0) {
                return true;
            }
        }

        return false;
#endif
    }
    catch (...) {
        debug("CPUID_0x4: caught error, returned false");
        return false;
    }


    /**
     * @brief Check for hypervisor brand string length (would be around 2 characters in a host machine)
     * @category x86
     */
    [[nodiscard]] static bool hypervisor_brand() try {
#if (!x86)
        return false;
#else
        char out[sizeof(int32_t) * 4 + 1] = { 0 }; // e*x size + number of e*x registers + null terminator
        cpu::cpuid((int*)out, cpu::leaf::hypervisor);

        debug("HYPERV_STR: eax: ", static_cast<u32>(out[0]),
            "\nebx: ", static_cast<u32>(out[1]),
            "\necx: ", static_cast<u32>(out[2]),
            "\nedx: ", static_cast<u32>(out[3])
        );

        return (std::strlen(out + 4) >= 4);
#endif
    }
    catch (...) {
        debug("HYPERVISOR_STR: caught error, returned false");
        return false;
    }


    /**
     * @brief Check if RDTSC is slow, if yes then it might be a VM
     * @category x86
     */
    [[nodiscard]]
#if (LINUX)
    // this is added so no sanitizers can potentially cause unwanted delays while measuring rdtsc in a debug compilation
    __attribute__((no_sanitize("address", "leak", "thread", "undefined")))
#endif
        static bool rdtsc_check() try {
#if (!x86)
        return false;
#else
#if (LINUX)
        u32 a, b, c, d = 0;

        // check if rdtsc is available
        if (!__get_cpuid(cpu::leaf::proc_ext, &a, &b, &c, &d)) {
            if (!(d & (1 << 27))) {
                return false;
            }
        }

        u64 s, acc = 0;
        int32_t out[4];

        for (std::size_t i = 0; i < 100; ++i) {
            s = __rdtsc();
            cpu::cpuid(out, 0, 0);
            acc += __rdtsc() - s;
        }

        debug("RDTSC: ", "acc = ", acc);
        debug("RDTSC: ", "acc/100 = ", acc / 100);

        return (acc / 100 > 350);
#elif (MSVC)
#define LODWORD(_qw)    ((DWORD)(_qw))
        u64 tsc1 = 0;
        u64 tsc2 = 0;
        u64 tsc3 = 0;
        for (INT i = 0; i < 10; i++) {
            tsc1 = __rdtsc();
            GetProcessHeap();  // delay
            tsc2 = __rdtsc();
#pragma warning(push)
#pragma warning(disable: 6387)
            CloseHandle(0);
#pragma warning(pop)
            tsc3 = __rdtsc();
            const bool condition = ((LODWORD(tsc3) - LODWORD(tsc2)) / (LODWORD(tsc2) - LODWORD(tsc1)) >= 10);
            if (condition) {
                return false;
            }
        }

        return true;
#else
        return false;
#endif
#endif
    }
    catch (...) {
        debug("RDTSC: caught error, returned false");
        return false;
    }


    /**
     * @brief Check if the 5th byte after sidt is null
     * @author Matteo Malvica
     * @link https://www.matteomalvica.com/blog/2018/12/05/detecting-vmware-on-64-bit-systems/
     * @category x86
     */
    [[nodiscard]] static bool sidt5() try {
#if (!x86 || !LINUX || GCC)
        return false;
#else
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
    }
    catch (...) {
        debug("SIDT5: caught error, returned false");
        return false;
    }


    /**
     * @brief Check if processor count is 1 or 2 (some VMs only have a single core)
     * @category All systems
     */
    [[nodiscard]] static bool thread_count() try {
        debug("THREADCOUNT: ", "threads = ", std::thread::hardware_concurrency());

        return (std::thread::hardware_concurrency() <= 2);
    }
    catch (...) {
        debug("THREADCOUNT: caught error, returned false");
        return false;
    }


    /**
     * @brief Check if mac address starts with certain VM designated values
     * @category All systems (I think)
     */
    [[nodiscard]] static bool mac_address_check() try {
        // C-style array on purpose
        u8 mac[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

#if (LINUX)
        struct ifreq ifr;
        struct ifconf ifc;
        char buf[1024];
        int32_t success = 0;

        int32_t sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

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
        else {
            debug("MAC: ", "not successful");
        }
#elif (MSVC)
        PIP_ADAPTER_INFO AdapterInfo;
        DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);

        AdapterInfo = (IP_ADAPTER_INFO*)std::malloc(sizeof(IP_ADAPTER_INFO));

        if (AdapterInfo == NULL) {
            return false;
        }

        if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
            std::free(AdapterInfo);
            AdapterInfo = (IP_ADAPTER_INFO*)std::malloc(dwBufLen);
            if (AdapterInfo == NULL) {
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
#else
        return false;
#endif

#ifdef __VMAWARE_DEBUG__
        std::stringstream ss;
        ss << std::setw(2) << std::setfill('0') << std::hex
            << static_cast<int32_t>(mac[0]) << ":"
            << static_cast<int32_t>(mac[1]) << ":"
            << static_cast<int32_t>(mac[2]) << ":"
            << static_cast<int32_t>(mac[3]) << ":"
            << static_cast<int32_t>(mac[4]) << ":"
            << static_cast<int32_t>(mac[5]);
        debug("MAC: ", ss.str());
#endif

        // better expression to fix code duplication
        auto compare = [=](const u8 mac1, const u8 mac2, const u8 mac3) noexcept -> bool {
            return (mac[0] == mac1 && mac[1] == mac2 && mac[2] == mac3);
            };

        if (compare(0x08, 0x00, 0x27)) {
            return core::add(VBOX);
        }

        if (
            (compare(0x00, 0x0C, 0x29)) ||
            (compare(0x00, 0x1C, 0x14)) ||
            (compare(0x00, 0x50, 0x56)) ||
            (compare(0x00, 0x05, 0x69))
            ) {
            return core::add(VMWARE);
        }

        if (compare(0x00, 0x16, 0xE3)) {
            return core::add(XEN);
        }

        if (compare(0x00, 0x1C, 0x42)) {
            return core::add(PARALLELS);
        }

        if (compare(0x0A, 0x00, 0x27)) {
            return core::add(HYBRID);
        }

        return false;
    }
    catch (...) {
        debug("MAC: caught error, returned false");
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
        return (!util::exists("/sys/class/thermal/thermal_zone0/"));
#endif
    }
    catch (...) {
        debug("TEMPERATURE: caught error, returned false");
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
        if (!(util::exists("/usr/bin/systemd-detect-virt") || util::exists("/bin/systemd-detect-virt"))) {
            debug("SYSTEMD: ", "binary doesn't exist");
            return false;
        }

        const std::unique_ptr<std::string> result = util::sys_result("systemd-detect-virt");

        if (result == nullptr) {
            debug("SYSTEMD: ", "invalid stdout output from systemd-detect-virt");
            return false;
        }

        debug("SYSTEMD: ", "output = ", *result);

        return (*result != "none");
#endif
    }
    catch (...) {
        debug("SYSTEMD: caught error, returned false");
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
        const char* vendor_file = "/sys/devices/virtual/dmi/id/chassis_vendor";

        if (!util::exists(vendor_file)) {
            debug("CVENDOR: ", "file doesn't exist");
            return false;
        }

        const std::string vendor = util::read_file(vendor_file);

        // TODO: More can definitely be added, I only tried QEMU and VMware so far
        if (vendor == "QEMU") { return core::add(QEMU); }
        if (vendor == "Oracle Corporation") { return core::add(VMWARE); }

        debug("CVENDOR: ", "unknown vendor = ", vendor);

        return false;
#endif
    }
    catch (...) {
        debug("CVENDOR: caught error, returned false");
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
        const char* chassis = "/sys/devices/virtual/dmi/id/chassis_type";

        if (util::exists(chassis)) {
            return (stoi(util::read_file(chassis)) == 1);
        }
        else {
            debug("CTYPE: ", "file doesn't exist");
        }

        return false;
#endif
    }
    catch (...) {
        debug("CTYPE: caught error, returned false");
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
        return (util::exists("/.dockerenv") || util::exists("/.dockerinit"));
#endif
    }
    catch (...) {
        debug("DOCKERENV: caught error, returned false");
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
        if (!util::is_admin()) {
            debug("DMIDECODE: ", "precondition return called (root = ", util::is_admin(), ")");
            return false;
        }

        if (!(util::exists("/bin/dmidecode") || util::exists("/usr/bin/dmidecode"))) {
            debug("DMIDECODE: ", "binary doesn't exist");
            return false;
        }

        const std::unique_ptr<std::string> result = util::sys_result("dmidecode -t system | grep 'Manufacturer|Product' | grep -c \"QEMU|VirtualBox|KVM\"");

        if (*result == "" || result == nullptr) {
            debug("DMIDECODE: ", "invalid output");
            return false;
        }
        else if (*result == "QEMU") {
            return core::add(QEMU);
        }
        else if (*result == "VirtualBox") {
            return core::add(VBOX);
        }
        else if (*result == "KVM") {
            return core::add(KVM);
        }
        else if (std::atoi(result->c_str()) >= 1) {
            return true;
        }
        else {
            debug("DMIDECODE: ", "output = ", *result);
        }

        return false;
#endif
    }
    catch (...) {
        debug("DMIDECODE: caught error, returned false");
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
        if (!util::is_admin()) {
            return false;
        }

        if (!util::exists("/bin/dmesg") && !util::exists("/usr/bin/dmesg")) {
            debug("DMESG: ", "binary doesn't exist");
            return false;
        }

        const std::unique_ptr<std::string> result = util::sys_result("dmesg | grep -i hypervisor | grep -c \"KVM|QEMU\"");

        if (*result == "" || result == nullptr) {
            return false;
        }
        else if (*result == "KVM") {
            return core::add(KVM);
        }
        else if (*result == "QEMU") {
            return core::add(QEMU);
        }
        else if (std::atoi(result->c_str())) {
            return true;
        }
        else {
            debug("DMESG: ", "output = ", *result);
        }

        return false;
#endif
    }
    catch (...) {
        debug("DMESG: caught error, returned false");
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
        return (!util::exists("/sys/class/hwmon/"));
#endif
    }
    catch (...) {
        debug("HWMON: caught error, returned false");
        return false;
    }


    /**
     * @brief Check for tons of VM-specific registry values
     * @category Windows
     */
    [[nodiscard]] static bool registry_key() try {
#if (!MSVC)
        return false;
#else
        u8 score = 0;

        auto key = [&score](const char* p_brand, const char* regkey_s) -> void {
            HKEY regkey;
            LONG ret;

            if (util::is_wow64()) {
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

                if (std::string(p_brand) != "") {
                    debug("REGISTRY: ", "detected = ", p_brand);
                    core::add(p_brand);
                }
            }
            };

        // general
        key("", "HKLM\\Software\\Classes\\Folder\\shell\\sandbox");

        // hyper-v
        key(HYPERV, "HKLM\\SOFTWARE\\Microsoft\\Hyper-V");
        key(HYPERV, "HKLM\\SOFTWARE\\Microsoft\\VirtualMachine");
        key(HYPERV, "HKLM\\SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters");
        key(HYPERV, "HKLM\\SYSTEM\\ControlSet001\\Services\\vmicheartbeat");
        key(HYPERV, "HKLM\\SYSTEM\\ControlSet001\\Services\\vmicvss");
        key(HYPERV, "HKLM\\SYSTEM\\ControlSet001\\Services\\vmicshutdown");
        key(HYPERV, "HKLM\\SYSTEM\\ControlSet001\\Services\\vmicexchange");

        // parallels
        key(PARALLELS, "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_1AB8*");

        // sandboxie
        key(SANDBOXIE, "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SbieDrv");
        key(SANDBOXIE, "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sandboxie");

        // virtualbox
        key(VBOX, "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_80EE*");
        key(VBOX, "HKLM\\HARDWARE\\ACPI\\DSDT\\VBOX__");
        key(VBOX, "HKLM\\HARDWARE\\ACPI\\FADT\\VBOX__");
        key(VBOX, "HKLM\\HARDWARE\\ACPI\\RSDT\\VBOX__");
        key(VBOX, "HKLM\\SOFTWARE\\Oracle\\VirtualBox Guest Additions");
        key(VBOX, "HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxGuest");
        key(VBOX, "HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxMouse");
        key(VBOX, "HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxService");
        key(VBOX, "HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxSF");
        key(VBOX, "HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxVideo");

        // virtualpc
        key(VPC, "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_5333*");
        key(VPC, "HKLM\\SYSTEM\\ControlSet001\\Services\\vpcbus");
        key(VPC, "HKLM\\SYSTEM\\ControlSet001\\Services\\vpc-s3");
        key(VPC, "HKLM\\SYSTEM\\ControlSet001\\Services\\vpcuhub");
        key(VPC, "HKLM\\SYSTEM\\ControlSet001\\Services\\msvmmouf");

        // vmware
        key(VMWARE, "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_15AD*");
        key(VMWARE, "HKCU\\SOFTWARE\\VMware, Inc.\\VMware Tools");
        key(VMWARE, "HKLM\\SOFTWARE\\VMware, Inc.\\VMware Tools");
        key(VMWARE, "HKLM\\SYSTEM\\ControlSet001\\Services\\vmdebug");
        key(VMWARE, "HKLM\\SYSTEM\\ControlSet001\\Services\\vmmouse");
        key(VMWARE, "HKLM\\SYSTEM\\ControlSet001\\Services\\VMTools");
        key(VMWARE, "HKLM\\SYSTEM\\ControlSet001\\Services\\VMMEMCTL");
        key(VMWARE, "HKLM\\SYSTEM\\ControlSet001\\Services\\vmware");
        key(VMWARE, "HKLM\\SYSTEM\\ControlSet001\\Services\\vmci");
        key(VMWARE, "HKLM\\SYSTEM\\ControlSet001\\Services\\vmx86");
        key(VMWARE, "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\IDE\\CdRomNECVMWar_VMware_IDE_CD*");
        key(VMWARE, "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\IDE\\CdRomNECVMWar_VMware_SATA_CD*");
        key(VMWARE, "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\IDE\\DiskVMware_Virtual_IDE_Hard_Drive*");
        key(VMWARE, "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\IDE\\DiskVMware_Virtual_SATA_Hard_Drive*");

        // wine
        key(WINE, "HKCU\\SOFTWARE\\Wine");
        key(WINE, "HKLM\\SOFTWARE\\Wine");

        // xen
        key(XEN, "HKLM\\HARDWARE\\ACPI\\DSDT\\xen");
        key(XEN, "HKLM\\HARDWARE\\ACPI\\FADT\\xen");
        key(XEN, "HKLM\\HARDWARE\\ACPI\\RSDT\\xen");
        key(XEN, "HKLM\\SYSTEM\\ControlSet001\\Services\\xenevtchn");
        key(XEN, "HKLM\\SYSTEM\\ControlSet001\\Services\\xennet");
        key(XEN, "HKLM\\SYSTEM\\ControlSet001\\Services\\xennet6");
        key(XEN, "HKLM\\SYSTEM\\ControlSet001\\Services\\xensvc");
        key(XEN, "HKLM\\SYSTEM\\ControlSet001\\Services\\xenvdb");

        debug("REGISTRY: ", "score = ", static_cast<u32>(score));

        return (score >= 1);
#endif
    }
    catch (...) {
        debug("REGISTRY: caught error, returned false");
        return false;
    }


    /**
     * @brief checks for default usernames, often a sign of a VM
     * @author: Some guy in a russian underground forum from a screenshot I saw, idk I don't speak russian ¯\_(ツ)_/¯
     * @category Windows
     */
    [[nodiscard]] static bool user_check() try {
#if (!MSVC)
        return false;
#else
        TCHAR user[UNLEN + 1]{};
        DWORD user_len = UNLEN + 1;
        GetUserName(user, &user_len);

        //TODO Ansi: debug("USER: ", "output = ", user);

        if (0 == _tcscmp(user, _T("username"))) {
            return core::add(THREADEXPERT);
        }

        if (0 == _tcscmp(user, _T("vmware"))) {
            return core::add(VMWARE);
        }

        if (0 == _tcscmp(user, _T("user"))) {
            return core::add(SANDBOXIE);
        }

        return (
            (0 == _tcscmp(user, _T("USER"))) ||      // Sandbox
            (0 == _tcscmp(user, _T("currentuser")))  // Normal
            );
#endif
    }
    catch (...) {
        debug("USER: caught error, returned false");
        return false;
    }


    /**
     * @brief Check if CWSandbox-specific file exists
     * @author same russian guy as above. Whoever you are, ty
     * @category Windows
     */
    [[nodiscard]] static bool cwsandbox_check() try {
#if (!MSVC)
        return false;
#else
        if (util::exists(_T("C:\\analysis"))) {
            return core::add(CWSANDBOX);
        }

        return false;
#endif
    }
    catch (...) {
        debug("CWSANDBOX_VM: caught error, returned false");
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

        for (auto& dll : real_dlls) {
            lib_inst = LoadLibraryA(dll);
            if (lib_inst == nullptr) {
                debug("DLL: ", "LIB_INST detected true for real dll = ", dll);
                return true;
            }
            FreeLibrary(lib_inst);
        }

        for (auto& dll : false_dlls) {
            lib_inst = LoadLibraryA(dll);
            if (lib_inst != nullptr) {
                debug("DLL: ", "LIB_INST detected true for false dll = ", dll);
                return true;
            }
        }

        return false;
#endif
    }
    catch (...) {
        debug("DLL: caught error, returned false");
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
        HANDLE handle = CreateFile(_T("\\\\.\\VBoxMiniRdrDN"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if (handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
            return core::add(VBOX);
        }

        return false;
#endif
    }
    catch (...) {
        debug("VBOX_REG: caught error, returned false");
        return false;
    }


    /**
     * @brief Find VMware tools presence
     * @category Windows
     */
    [[nodiscard]] static bool vmware_registry() try {
#if (!MSVC)
        return false;
#else
        HKEY hKey;
        // Use wide string literal
        bool result = (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS);

        debug("VMWARE_REG: result = ", result);

        if (result == true) {
            return core::add(VMWARE);
        }

        return result;
#endif
    }
    catch (...) {
        debug("VMWARE_REG: caught error, returned false");
        return false;
    }


    /**
     * @brief Check if the mouse coordinates have changed after 5 seconds
     * @note Some VMs are automatic without a human due to mass malware scanning being a thing
     * @note Disabled by default due to performance reasons
     * @category Windows
     */
    [[nodiscard]] static bool cursor_check() try {
#if (!MSVC)
        return false;
#else
        POINT pos1, pos2;
        GetCursorPos(&pos1);

        debug("CURSOR: pos1.x = ", pos1.x);
        debug("CURSOR: pos1.y = ", pos1.y);

        Sleep(5000);
        GetCursorPos(&pos2);

        debug("CURSOR: pos1.x = ", pos1.x);
        debug("CURSOR: pos1.y = ", pos1.y);
        debug("CURSOR: pos2.x = ", pos2.x);
        debug("CURSOR: pos2.y = ", pos2.y);

        return ((pos1.x == pos2.x) && (pos1.y == pos2.y));
#endif
    }
    catch (...) {
        debug("CURSOR: caught error, returned false");
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
        // points
        u8 vbox = 0;
        u8 vmware = 0;

        constexpr std::array<const TCHAR*, 26> files = { {
                // VMware
                _T("C:\\windows\\System32\\Drivers\\Vmmouse.sys"),
                _T("C:\\windows\\System32\\Drivers\\vm3dgl.dll"),
                _T("C:\\windows\\System32\\Drivers\\vmdum.dll"),
                _T("C:\\windows\\System32\\Drivers\\VmGuestLibJava.dll"),
                _T("C:\\windows\\System32\\Drivers\\vm3dver.dll"),
                _T("C:\\windows\\System32\\Drivers\\vmtray.dll"),
                _T("C:\\windows\\System32\\Drivers\\VMToolsHook.dll"),
                _T("C:\\windows\\System32\\Drivers\\vmGuestLib.dll"),
                _T("C:\\windows\\System32\\Drivers\\vmhgfs.dll"),

                // VBox
                _T("C:\\windows\\System32\\Drivers\\VBoxMouse.sys"),
                _T("C:\\windows\\System32\\Drivers\\VBoxGuest.sys"),
                _T("C:\\windows\\System32\\Drivers\\VBoxSF.sys"),
                _T("C:\\windows\\System32\\Drivers\\VBoxVideo.sys"),
                _T("C:\\windows\\System32\\vboxoglpackspu.dll"),
                _T("C:\\windows\\System32\\vboxoglpassthroughspu.dll"),
                _T("C:\\windows\\System32\\vboxservice.exe"),
                _T("C:\\windows\\System32\\vboxoglcrutil.dll"),
                _T("C:\\windows\\System32\\vboxdisp.dll"),
                _T("C:\\windows\\System32\\vboxhook.dll"),
                _T("C:\\windows\\System32\\vboxmrxnp.dll"),
                _T("C:\\windows\\System32\\vboxogl.dll"),
                _T("C:\\windows\\System32\\vboxtray.exe"),
                _T("C:\\windows\\System32\\VBoxControl.exe"),
                _T("C:\\windows\\System32\\vboxoglerrorspu.dll"),
                _T("C:\\windows\\System32\\vboxoglfeedbackspu.dll"),
                _T("c:\\windows\\system32\\vboxoglarrayspu.dll")
            } };

        for (const auto file : files) {
            if (util::exists(file)) {
                const auto regex = tregex(file, std::regex::icase);

                if (std::regex_search(_T("vbox"), regex)) {
                    //TODO Ansi: debug("VM_FILES: found vbox file = ", file);
                    vbox++;
                }
                else {
                    //TODO Ansi: debug("VM_FILES: found vmware file = ", file);
                    vmware++;
                }
            }
        }

        debug("VM_FILES: vmware score: ", static_cast<u32>(vmware));
        debug("VM_FILES: vbox score: ", static_cast<u32>(vbox));

        if (vbox > vmware) {
            return core::add(VBOX);
        }
        else if (vbox < vmware) {
            return core::add(VMWARE);
        }
        else if (
            vbox > 0 &&
            vmware > 0 &&
            vbox == vmware
            ) {
            return true;
        }

        // general VM file, not sure which brand it belongs to though
        if (util::exists("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\agent.pyw")) {
            return true;
        }

        return false;
#endif
    }
    catch (...) {
        debug("VM_FILES: caught error, returned false");
        return false;
    }


    /**
     * @brief Check for sysctl hardware model
     * @author MacRansom ransomware
     * @category MacOS
     */
    [[nodiscard]] static bool hwmodel() try {
#if (!APPLE)
        return false;
#else
        auto result = util::sys_result("sysctl -n hw.model");

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
            return core::add(VMWARE);
        }

        // assumed true since it doesn't contain "Mac" string
        return true;
#endif
    }
    catch (...) {
        debug("HWMODEL: caught error, returned false");
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
        const u32 size = util::get_disk_size();

        debug("DISK_SIZE: size = ", size);

        return (size <= 60); // in GB
#endif
    }
    catch (...) {
        debug("DISK_SIZE: caught error, returned false");
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
#if (APPLE)
        return false;
#else
        const u32 disk = util::get_disk_size();
        const u64 ram = util::get_physical_ram_size();

        debug("VBOX_DEFAULT: disk = ", disk);
        debug("VBOX_DEFAULT: ram = ", ram);

        if ((disk > 80) || (ram > 4)) {
            debug("VBOX_DEFAULT: returned false due to lack of precondition spec comparisons");
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

        debug("VBOX_DEFAULT: linux, detected distro: ", distro);

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
        const u8 version = util::get_windows_version();

        if (version == 0) {
            return false;
        }

        // less than windows 10
        if (version < 10) {
            debug("VBOX_DEFAULT: less than windows 10 detected");
            return false;
        }

        // windows 10
        if (10 == version) {
            debug("VBOX_DEFAULT: windows 10 detected");
            return ((50 == disk) && (2 == ram));
        }

        // windows 11
        if (11 == version) {
            debug("VBOX_DEFAULT: windows 11 detected");
            return ((80 == disk) && (4 == ram));
        }
#endif
#endif
        return false;
    }
    catch (...) {
        debug("VBOX_DEFAULT: caught error, returned false");
        return false;
    }


    /**
     * @brief Check VBox network provider string
     * @category Windows
     */
    [[nodiscard]] static bool vbox_network_share() try {
#if (!MSVC)
        return false;
#else
        u32 pnsize = 0x1000;
        TCHAR* provider = new TCHAR[pnsize];

        u32 retv = WNetGetProviderName(WNNC_NET_RDR2SAMPLE, provider, reinterpret_cast<LPDWORD>(&pnsize));

        if (retv == NO_ERROR) {
            bool result = (lstrcmpi(provider, _T("VirtualBox Shared Folders")) == 0);
            delete[] provider;
            return result;
        }

        delete[] provider;
        return false;
#endif
    }
    catch (...) {
        debug("VBOX_NETWORK: caught error, returned false");
        return false;
    }


    /**
     * @brief Check wine_get_unix_file_name file for Wine
     * @author pafish project
     * @link https://github.com/a0rtega/pafish/blob/master/pafish/wine.c
     * @category Windows
     * @copyright GPL-3.0
     */
    [[nodiscard]] static bool wine() try {
#if (!MSVC)
        return false;
#else
        HMODULE k32;
        k32 = GetModuleHandle(TEXT("kernel32.dll"));

        if (k32 != NULL) {
            return (GetProcAddress(k32, "wine_get_unix_file_name") != NULL);
        }

        return false;
#endif
    }
    catch (...) {
        debug("WINE_CHECK: caught error, returned false");
        return false;
    }


    /**
     * @brief Check if the computer name (not username to be clear) is VM-specific
     * @category Windows
     * @author InviZzzible project
     * @copyright GPL-3.0
     */
    [[nodiscard]] static bool computer_name_match() try {
#if (!MSVC)
        return false;
#else
        auto out_length = MAX_PATH;
        std::vector<u8> comp_name(static_cast<u32>(out_length), 0);
        GetComputerNameA((LPSTR)comp_name.data(), (LPDWORD)&out_length);

        auto compare = [&](const std::string& s) -> bool {
            return (std::strcmp((LPCSTR)comp_name.data(), s.c_str()) == 0);
            };

        debug("COMPUTER_NAME: fetched = ", (LPCSTR)comp_name.data());

        if (compare("InsideTm") || compare("TU-4NH09SMCG1HC")) { // anubis
            debug("COMPUTER_NAME: detected Anubis");
            return core::add(ANUBIS);
        }

        if (compare("klone_x64-pc") || compare("tequilaboomboom")) { // general
            debug("COMPUTER_NAME: detected general (VM but unknown)");
            return true;
        }

        return false;
#endif
    }
    catch (...) {
        debug("COMPUTER_NAME: caught error, returned false");
        return false;
    }


    /**
     * @brief Check if hostname is specific
     * @author InviZzzible project
     * @category Windows
     */
    [[nodiscard]] static bool hostname_match() try {
#if (!MSVC)
        return false;
#else
        auto out_length = MAX_PATH;
        std::vector<u8> dns_host_name(static_cast<u32>(out_length), 0);
        GetComputerNameExA(ComputerNameDnsHostname, (LPSTR)dns_host_name.data(), (LPDWORD)&out_length);

        debug("HOSTNAME: ", (LPCSTR)dns_host_name.data());

        return (!lstrcmpiA((LPCSTR)dns_host_name.data(), "SystemIT"));
#endif
    }
    catch (...) {
        debug("HOSTNAME: caught error, returned false");
        return false;
    }


    /**
     * @brief Check if memory is too low
     * @author Al-Khaser project
     * @category x86?
     * @copyright GPL-3.0
     */
    [[nodiscard]] static bool low_memory_space() try {
        constexpr u64 min_ram_1gb = (1024LL * (1024LL * (1024LL * 1LL)));
        const u64 ram = util::get_memory_space();

        debug("MEMORY: ram size (GB) = ", ram);
        debug("MEMORY: minimum ram size (GB) = ", min_ram_1gb);

        return (ram < min_ram_1gb);
    }
    catch (...) {
        debug("MEMORY: caught error, returned false");
        return false;
    }


    /**
     * @brief default vbox window class
     * @category Windows
     * @author Al-Khaser Project
     * @copyright GPL-3.0
     */
    [[nodiscard]] static bool vbox_window_class() try {
#if (!MSVC)
        return false;
#else
        HWND hClass = FindWindow(_T("VBoxTrayToolWndClass"), NULL);
        HWND hWindow = FindWindow(NULL, _T("VBoxTrayToolWnd"));

        if (hClass || hWindow) {
            return core::add(VBOX);
        }

        return false;
#endif
    }
    catch (...) {
        debug("VBOX_WINDOW_CLASS: caught error, returned false");
        return false;
    }


    /**
     * @brief check for loaded dlls in the process
     * @category Windows
     * @author LordNoteworthy
     * @note modified code from Al-Khaser project
     * @link https://github.com/LordNoteworthy/al-khaser/blob/c68fbd7ba0ba46315e819b490a2c782b80262fcd/al-khaser/Anti%20VM/Generic.cpp
     */
    [[nodiscard]] static bool loaded_dlls() try {
#if (!MSVC)
        return false;
#else
        HMODULE hDll;

        constexpr std::array<const char*, 12> szDlls = { {
            "avghookx.dll",    // AVG
            "avghooka.dll",    // AVG
            "snxhk.dll",       // Avast
            "sbiedll.dll",     // Sandboxie
            "dbghelp.dll",     // WindBG
            "api_log.dll",     // iDefense Lab
            "dir_watch.dll",   // iDefense Lab
            "pstorec.dll",     // SunBelt CWSandbox
            "vmcheck.dll",     // Virtual PC
            "wpespy.dll",      // WPE Pro
            "cmdvrt64.dll",    // Comodo Container
            "cmdvrt32.dll",    // Comodo Container
        } };

        for (const auto& key : szDlls) {
            const char* dll = key;

            hDll = GetModuleHandleA(dll);  // Use GetModuleHandleA for ANSI strings

            if (hDll != NULL && dll != NULL) {
                if (strcmp(dll, "sbiedll.dll") == 0) { return core::add(SANDBOXIE); }
                if (strcmp(dll, "pstorec.dll") == 0) { return core::add(CWSANDBOX); }
                if (strcmp(dll, "vmcheck.dll") == 0) { return core::add(VPC); }
                if (strcmp(dll, "cmdvrt32.dll") == 0) { return core::add(COMODO); }
                if (strcmp(dll, "cmdvrt64.dll") == 0) { return core::add(COMODO); }

                return true;
            }
        }

        return false;
#endif
    }
    catch (...) {
        debug("LOADED_DLLS:", "caught error, returned false");
        return false;
    }


    /**
     * @brief Check for KVM-specific registries
     * @category Windows
     * @note idea is from Al-Khaser, slightly modified code
     * @author LordNoteWorthy
     * @link https://github.com/LordNoteworthy/al-khaser/blob/0f31a3866bafdfa703d2ed1ee1a242ab31bf5ef0/al-khaser/AntiVM/KVM.cpp
     */
    [[nodiscard]] static bool kvm_registry() try {
#if (!MSVC)
        return false;
#else
        auto registry_exists = [](const TCHAR* key) -> bool {
            HKEY keyHandle;

            if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, key, 0, KEY_QUERY_VALUE, &keyHandle) == ERROR_SUCCESS) {
                RegCloseKey(keyHandle);
                return true;
            }

            return false;
            };

        constexpr std::array<const TCHAR*, 7> keys = { {
            _T("SYSTEM\\ControlSet001\\Services\\vioscsi"),
            _T("SYSTEM\\ControlSet001\\Services\\viostor"),
            _T("SYSTEM\\ControlSet001\\Services\\VirtIO-FS Service"),
            _T("SYSTEM\\ControlSet001\\Services\\VirtioSerial"),
            _T("SYSTEM\\ControlSet001\\Services\\BALLOON"),
            _T("SYSTEM\\ControlSet001\\Services\\BalloonService"),
            _T("SYSTEM\\ControlSet001\\Services\\netkvm"),
        } };

        for (const auto& key : keys) {
            if (registry_exists(key)) {
                return core::add(KVM);
            }
        }

        return false;
#endif
    }
    catch (...) {
        debug("KVM_REG: ", "caught error, returned false");
        return false;
    }


    /**
     * @brief Check for KVM driver files
     * @category Windows
     * @note idea is from Al-Khaser, slightly modified code
     * @author LordNoteWorthy
     * @link https://github.com/LordNoteworthy/al-khaser/blob/0f31a3866bafdfa703d2ed1ee1a242ab31bf5ef0/al-khaser/AntiVM/KVM.cpp
     */
    [[nodiscard]] static bool kvm_drivers() try {
#if (!MSVC)
        return false;
#else
        constexpr std::array<const TCHAR*, 10> keys = { {
            _T("System32\\drivers\\balloon.sys"),
            _T("System32\\drivers\\netkvm.sys"),
            _T("System32\\drivers\\pvpanic.sys"),
            _T("System32\\drivers\\viofs.sys"),
            _T("System32\\drivers\\viogpudo.sys"),
            _T("System32\\drivers\\vioinput.sys"),
            _T("System32\\drivers\\viorng.sys"),
            _T("System32\\drivers\\vioscsi.sys"),
            _T("System32\\drivers\\vioser.sys"),
            _T("System32\\drivers\\viostor.sys"),
        } };

        TCHAR szWinDir[MAX_PATH] = _T("");
        TCHAR szPath[MAX_PATH] = _T("");
        PVOID OldValue = NULL;

        if (GetWindowsDirectory(szWinDir, MAX_PATH) == 0) {
            return false;
        }

        if (util::is_wow64()) {
            Wow64DisableWow64FsRedirection(&OldValue);
        }

        bool is_vm = false;

        for (const auto& key : keys) {
            PathCombine(szPath, szWinDir, key);
            if (util::exists(szPath)) {
                is_vm = true;
                break;
            }
        }

        if (util::is_wow64()) {
            Wow64RevertWow64FsRedirection(&OldValue);
        }

        return is_vm;
#endif
    }
    catch (...) {
        debug("KVM_DRIVERS: ", "caught error, returned false");
        return false;
    }


    /**
     * @brief Check KVM directories
     * @category Windows
     * @author LordNoteWorthy
     * @note from Al-Khaser project
     * @link https://github.com/LordNoteworthy/al-khaser/blob/0f31a3866bafdfa703d2ed1ee1a242ab31bf5ef0/al-khaser/AntiVM/KVM.cpp
     */
    [[nodiscard]] static bool kvm_directories() try {
#if (!MSVC)
        return false;
#else
        TCHAR szProgramFile[MAX_PATH];
        TCHAR szPath[MAX_PATH] = _T("");
        TCHAR szTarget[MAX_PATH] = _T("Virtio-Win\\");

        if (util::is_wow64()) {
            ExpandEnvironmentStrings(_T("%ProgramW6432%"), szProgramFile, ARRAYSIZE(szProgramFile));
        }
        else {
            SHGetSpecialFolderPath(NULL, szProgramFile, CSIDL_PROGRAM_FILES, FALSE);
        }

        PathCombine(szPath, szProgramFile, szTarget);
        return util::exists(szPath);
#endif
    }
    catch (...) {
        debug("KVM_DIRS: ", "caught error, returned false");
        return false;
    }


    /**
     * @brief Check for audio device
     * @category Windows
     * @author CheckPointSW (InviZzzible project)
     * @link https://github.com/CheckPointSW/InviZzzible/blob/master/SandboxEvasion/helper.cpp
     * @copyright GPL-3.0
     */
    [[nodiscard]] static bool check_audio() try {
#if (!MSVC)
        return false;
#else
        PCWSTR wszfilterName = L"audio_device_random_name";

        if (FAILED(CoInitialize(NULL)))
            return false;

        IGraphBuilder* pGraph = nullptr;
        if (FAILED(CoCreateInstance(CLSID_FilterGraph, NULL, CLSCTX_INPROC_SERVER, IID_IGraphBuilder, (void**)&pGraph)))
            return false;

        // First anti-emulation check: If AddFilter is called with NULL as a first argument it should return the E_POINTER error code. 
        // Some emulators may implement unknown COM interfaces in a generic way, so they will probably fail here.
        if (E_POINTER != pGraph->AddFilter(NULL, wszfilterName))
            return true;

        // Initializes a simple Audio Renderer, error code is not checked, 
        // but pBaseFilter will be set to NULL upon failure and the code will eventually fail later.
        IBaseFilter* pBaseFilter = nullptr;

        HRESULT hr = CoCreateInstance(CLSID_AudioRender, NULL, CLSCTX_INPROC_SERVER, IID_IBaseFilter, (void**)&pBaseFilter);
        if (FAILED(hr)) {
            return false;
        }

        // Adds the previously created Audio Renderer to the Filter Graph, no error checks
        pGraph->AddFilter(pBaseFilter, wszfilterName);

        // Tries to find the filter that was just added; in case of any previously not checked error (or wrong emulation) 
        // this function won't find the filter and the sandbox/emulator will be successfully detected.
        IBaseFilter* pBaseFilter2 = nullptr;
        pGraph->FindFilterByName(wszfilterName, &pBaseFilter2);
        if (nullptr == pBaseFilter2)
            return true;

        // Checks if info.achName is equal to the previously added filterName, if not - poor API emulation
        FILTER_INFO info = { 0 };
        pBaseFilter2->QueryFilterInfo(&info);
        if (0 != wcscmp(info.achName, wszfilterName))
            return false;

        // Checks if the API sets a proper IReferenceClock pointer
        IReferenceClock* pClock = nullptr;
        if (0 != pBaseFilter2->GetSyncSource(&pClock))
            return false;
        if (0 != pClock)
            return false;

        // Checks if CLSID is different from 0
        CLSID clsID = { 0 };
        pBaseFilter2->GetClassID(&clsID);
        if (clsID.Data1 == 0)
            return true;

        if (nullptr == pBaseFilter2)
            return true;

        // Just checks if the call was successful
        IEnumPins* pEnum = nullptr;
        if (0 != pBaseFilter2->EnumPins(&pEnum))
            return true;

        // The reference count returned by AddRef has to be higher than 0
        if (0 == pBaseFilter2->AddRef())
            return true;

        return false;
#endif
    }
    catch (...) {
        debug("AUDIO: ", "caught error, returned false");
        return false;
    }


    /**
     * @brief Check for QEMU-specific blacklisted directories
     * @author LordNoteworthy
     * @link https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/AntiVM/Qemu.cpp
     * @category Windows
     * @note from al-khaser project
     * @copyright GPL-3.0
     */
    [[nodiscard]] static bool qemu_dir() try {
#if (!MSVC)
        return false;
#else
        TCHAR szProgramFile[MAX_PATH];
        TCHAR szPath[MAX_PATH] = _T("");

        const TCHAR* szDirectories[] = {
            _T("qemu-ga"),	// QEMU guest agent.
            _T("SPICE Guest Tools"), // SPICE guest tools.
        };

        WORD iLength = sizeof(szDirectories) / sizeof(szDirectories[0]);
        for (int i = 0; i < iLength; i++)
        {
            TCHAR msg[256] = _T("");

            if (util::is_wow64())
                ExpandEnvironmentStrings(_T("%ProgramW6432%"), szProgramFile, ARRAYSIZE(szProgramFile));
            else
                SHGetSpecialFolderPath(NULL, szProgramFile, CSIDL_PROGRAM_FILES, FALSE);

            PathCombine(szPath, szProgramFile, szDirectories[i]);

            if (util::exists(szPath))
                return core::add(QEMU);
        }

        return false;
#endif
    }
    catch (...) {
        debug("QEMU_DIR: ", "caught error, returned false");
        return false;
    }


    /**
     * @brief Check for any VM processes that are active
     * @author a0rtega
     * @category Windows
     * @link https://github.com/a0rtega/pafish/blob/master/pafish/vmware.c
     * @note from pafish project
     * @copyright GPL
     */
    [[nodiscard]] static bool vmware_devices() try {
#if (!MSVC)
        return false;
#else
        HANDLE h;
        const u8 count = 2;
        std::string strs[count];

        strs[0] = "\\\\.\\HGFS";
        strs[1] = "\\\\.\\vmci";

        for (int i = 0; i < count; i++) {
            h = CreateFile(strs[i].c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h != INVALID_HANDLE_VALUE) {
                debug("VMWare traced using device ", strs[i]);
                return true;
            }
        }

        return false;
#endif
    }
    catch (...) {
        debug("QEMU_DIR: ", "caught error, returned false");
        return false;
    }

    /**
     * @brief Check for any VM processes that are active
     * @category Windows
     */
    [[nodiscard]] static bool vm_processes() try {
#if (!MSVC)
        return false;
#else
        auto check_proc = [](const TCHAR* proc) -> bool {
            DWORD processes[1024], bytesReturned;

            // Retrieve the list of process identifiers
            if (!EnumProcesses(processes, sizeof(processes), &bytesReturned))
                return false;

            // Calculate how many process identifiers were returned
            DWORD numProcesses = bytesReturned / sizeof(DWORD);

            for (DWORD i = 0; i < numProcesses; ++i) {
                // Open the process
                HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
                if (process != nullptr) {
                    // Get the process name
                    TCHAR processName[MAX_PATH];
                    if (GetModuleBaseName(process, nullptr, processName, sizeof(processName) / sizeof(TCHAR))) {
                        // Check if the process name matches the desired executable
                        if (_tcscmp(processName, proc) == 0) {
                            CloseHandle(process);
                            return true;
                        }
                    }
                    CloseHandle(process);
                }
            }

            return false;
            };

        if (check_proc(_T("joeboxserver.exe")) || check_proc(_T("joeboxcontrol.exe"))) {
            return core::add(JOEBOX);
        }

        if (check_proc(_T("prl_cc.exe")) || check_proc(_T("prl_tools.exe"))) {
            return core::add(PARALLELS);
        }

        if (check_proc(_T("vboxservice.exe")) || check_proc(_T("vboxtray.exe"))) {
            return core::add(VBOX);
        }

        if (check_proc(_T("vmsrvc.exe")) || check_proc(_T("vmusrvc.exe"))) {
            return core::add(VPC);
        }

        if (
            check_proc(_T("vmtoolsd.exe")) ||
            check_proc(_T("vmwaretrat.exe")) ||
            check_proc(_T("vmacthlp.exe")) ||
            check_proc(_T("vmwaretray.exe")) ||
            check_proc(_T("vmwareuser.exe")) ||
            check_proc(_T("vmware.exe")) ||
            check_proc(_T("vmount2.exe"))
            ) {
            return core::add(VMWARE);
        }

        if (check_proc(_T("xenservice.exe")) || check_proc(_T("xsvc_depriv.exe"))) {
            return core::add(XEN);
        }

        return false;
#endif
    }
    catch (...) {
        debug("VM_PROCESSES: caught error, returned false");
        return false;
    }


    /**
     * @brief Check for default VM username and hostname for linux
     * @category Linux
     */
    [[nodiscard]] static bool linux_user_host() try {
#if (!LINUX)
        return false;
#else
        if (util::is_admin()) {
            return false;
        }

        const char* username = std::getenv("USER");
        const char* hostname = std::getenv("HOSTNAME");

        debug("LINUX_USER_HOST: user = ", username);
        debug("LINUX_USER_HOST: host = ", hostname);

        return (
            (strcmp(username, "liveuser") == 0) &&
            (strcmp(hostname, "localhost-live") == 0)
            );
#endif
    }
    catch (...) {
        debug("LINUX_USER_HOST: caught error, returned false");
        return false;
    }


    /**
     * @brief Gamarue ransomware check
     * @category Windows
     */
    [[nodiscard]] static bool gamarue() try {
#if (!MSVC) 
        return false;
#else
        HKEY hOpen;
        char* szBuff;
        int iBuffSize;
        HANDLE hMod;
        LONG nRes;

        szBuff = (char*)calloc(512, sizeof(char));

        hMod = GetModuleHandleW(L"SbieDll.dll"); // Sandboxie
        if (hMod != 0) {
            free(szBuff);
            return core::add(SANDBOXIE);
        }

        hMod = GetModuleHandleW(L"dbghelp.dll"); // Thread Expert
        if (hMod != 0) {
            free(szBuff);
            return core::add(THREADEXPERT);
        }

        nRes = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion", 0L, KEY_QUERY_VALUE, &hOpen);
        if (nRes == ERROR_SUCCESS) {
            iBuffSize = sizeof(szBuff);
            nRes = RegQueryValueExW(hOpen, L"ProductId", NULL, NULL, (unsigned char*)szBuff, reinterpret_cast<LPDWORD>(&iBuffSize));
            if (nRes == ERROR_SUCCESS) {
                // Check if szBuff is not NULL before using strcmp
                if (szBuff == NULL) {
                    RegCloseKey(hOpen);
                    return false;
                }

                if (strcmp(szBuff, "55274-640-2673064-23950") == 0) { // joebox
                    free(szBuff);
                    return core::add(JOEBOX);
                }
                else if (strcmp(szBuff, "76487-644-3177037-23510") == 0) { // CW Sandbox
                    free(szBuff);
                    return core::add(CWSANDBOX);
                }
                else if (strcmp(szBuff, "76487-337-8429955-22614") == 0) { // anubis
                    free(szBuff);
                    return core::add(ANUBIS);
                }
                else {
                    free(szBuff);
                    return false;
                }
            }
            RegCloseKey(hOpen);
        }
        // Set szBuff to NULL after freeing to avoid double free issues
        free(szBuff);
        return false;
#endif
    }
    catch (...) {
        debug("GAMARUE: caught error, returned false");
        return false;
    }


    /**
     * @brief Check if the BIOS serial is valid
     * @category Linux
     */
    [[nodiscard]] static bool bios_serial() try {
#if (!MSVC)
        return false;
#else
        std::unique_ptr<util::sys_info> info = util::make_unique<util::sys_info>();

        const std::string str = info->get_serialnumber();
        const std::size_t nl_pos = str.find('\n');

        if (nl_pos == std::string::npos) {
            return false;
        }

        debug("BIOS_SERIAL: ", str);

        const std::string extract = str.substr(nl_pos + 1);

        const bool all_digits = std::all_of(extract.cbegin(), extract.cend(), [](const char c) {
            return std::isdigit(c);
            });

        if (all_digits) {
            if (extract == "0") {
                return true;
            }
        }

        return false;
#endif
    }
    catch (...) {
        debug("BIOS_SERIAL: caught error, returned false");
        return false;
    }


    /**
     * @brief check for any indication of parallels through BIOS stuff
     * @link https://stackoverflow.com/questions/1370586/detect-if-windows-is-running-from-within-parallels
     * @category Windows
     */
    [[nodiscard]] static bool parallels() try {
#if (!MSVC)
        return false;
#else
        std::unique_ptr<util::sys_info> info = util::make_unique<util::sys_info>();

#ifdef __VMAWARE_DEBUG__
        std::cout << std::left << ::std::setw(14) << "Manufacturer: " << info->get_manufacturer() << '\n'
            << std::left << ::std::setw(14) << "Product Name: " << info->get_productname() << '\n'
            << std::left << ::std::setw(14) << "Serial No: " << info->get_serialnumber() << '\n'
            << std::left << ::std::setw(14) << "UUID: " << info->get_uuid() << '\n'
            << std::left << ::std::setw(14) << "Version: " << info->get_version() << std::endl;

        if (!info->get_family().empty()) {
            std::cout << std::left << ::std::setw(14) << "Product family: " << info->get_family() << std::endl;
        }

        if (!info->get_sku().empty()) {
            std::cout << std::left << ::std::setw(14) << "SKU/Configuration: " << info->get_sku() << std::endl;
        }
#endif

        auto compare = [](const std::string& str) -> bool {
            std::regex pattern("Parallels", std::regex_constants::icase);
            return std::regex_match(str, pattern);
            };

        if (
            compare(info->get_manufacturer()) ||
            compare(info->get_productname()) ||
            compare(info->get_family())
            ) {
            return core::add(PARALLELS);
        }

        return false;
#endif
    }
    catch (...) {
        debug("PARALLELS_VM:", "caught error, returned false");
        return false;
    }


    /**
     * @brief check VM through alternative RDTSC technique with VMEXIT
     * @category x86
     */
    [[nodiscard]]
#if (LINUX)
    // this is added so no sanitizers can potentially cause unwanted delays while measuring rdtsc in a debug compilation
    __attribute__((no_sanitize("address", "leak", "thread", "undefined")))
#endif
        static bool rdtsc_vmexit() try {

#if (!x86)
        return false;
#else
        u64 tsc1 = 0;
        u64 tsc2 = 0;
        u64 avg = 0;
        i32 reg[4] = {};

        for (std::size_t i = 0; i < 10; i++) {
            tsc1 = __rdtsc();
            cpu::cpuid(reg, 0);
            tsc2 = __rdtsc();
            avg += (tsc2 - tsc1);
        }

        avg /= 10;

        return (avg >= 1500 || avg == 0);
#endif
    }
    catch (...) {
        debug("RDTSC_VMEXIT:", "caught error, returned false");
        return false;
    }


    /**
     * @brief Do various Bochs-related CPU stuff
     * @category x86
     * @note Discovered by Peter Ferrie, Senior Principal Researcher, Symantec Advanced Threat Research peter_ferrie@symantec.com
     */
    [[nodiscard]] static bool bochs_cpu() try {
#if (!x86)
        return false;
#else
        if (!core::cpuid_supported) {
            return false;
        }

        const bool intel = cpu::is_intel();
        const bool amd = cpu::is_amd();

        // if neither amd or intel, return false
        if (!(intel ^ amd)) {
            debug("BOCHS_CPU: neither AMD or Intel detect, returned false");
            return false;
        }

        const std::string brand = cpu::get_brand();

        if (intel) {
            // technique 1: not a valid brand 
            if (brand == "              Intel(R) Pentium(R) 4 CPU        ") {
                return core::add(BOCHS);
            }
        }
        else if (amd) {
            // technique 2: "processor" should have a capital P
            if (brand == "AMD Athlon(tm) processor") {
                return core::add(BOCHS);
            }

            // technique 3: Check for absence of AMD easter egg for K7 and K8 CPUs
            u32 unused, eax = 0;
            cpu::cpuid(eax, unused, unused, unused, 1);

            constexpr u8 AMD_K7 = 6;
            constexpr u8 AMD_K8 = 15;

            const u32 family = ((eax >> 8) & 0xF);

            if (family != AMD_K7 && family != AMD_K8) {
                return false;
            }

            u32 ecx_bochs = 0;
            cpu::cpuid(unused, unused, ecx_bochs, unused, cpu::leaf::amd_easter_egg);

            if (ecx_bochs == 0) {
                return core::add(BOCHS);
            }
        }

        return false;
#endif
    }
    catch (...) {
        debug("BOCHS_CPU:", "caught error, returned false");
        return false;
    }


    /**
     * @brief Go through the motherboard and match for VPC-specific string
     * @category Windows
     */
    [[nodiscard]] static bool vpc_board() try {
#if (!MSVC)
        return false;
#else
        HRESULT hres;

        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) {
            debug("VPC_BOARD: Failed to initialize COM library. Error code: ", hres);
            return false;
        }

        hres = CoInitializeSecurity(
            NULL,
            -1,                          // use the default authentication service
            NULL,                        // use the default authorization service
            NULL,                        // reserved
            RPC_C_AUTHN_LEVEL_DEFAULT,   // authentication
            RPC_C_IMP_LEVEL_IMPERSONATE, // impersonation
            NULL,                        // authentication info
            EOAC_NONE,                   // additional capabilities
            NULL                         // reserved
        );

        if (FAILED(hres)) {
            debug("VPC_BOARD: Failed to initialize security. Error code: ", hres);
            CoUninitialize();
            return false;
        }

        IWbemLocator* pLoc = NULL;
        IWbemServices* pSvc = NULL;

        hres = CoCreateInstance(
            CLSID_WbemLocator,
            0,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator,
            (LPVOID*)&pLoc
        );

        if (FAILED(hres)) {
            debug("VPC_BOARD: Failed to create IWbemLocator object. Error code: ", hres);
            CoUninitialize();
            return false;
        }

        hres = pLoc->ConnectServer(
            _bstr_t(L"ROOT\\CIMV2"), // Namespace
            NULL,                    // User name
            NULL,                    // User password
            0,                       // Locale
            NULL,                    // Security flags
            0,                       // Authority
            0,                       // Context object pointer
            &pSvc
        );

        if (FAILED(hres)) {
            debug("VPC_BOARD: Failed to connect to WMI. Error code: ", hres);
            pLoc->Release();
            CoUninitialize();
            return false;
        }

        hres = CoSetProxyBlanket(
            pSvc,                        // Indicates the proxy to set
            RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
            RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
            NULL,                        // Server principal name
            RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx
            RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
            NULL,                        // client identity
            EOAC_NONE                    // proxy capabilities
        );

        if (FAILED(hres)) {
            debug("VPC_BOARD: Failed to set proxy blanket. Error code: ", hres);
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return false;
        }

        IEnumWbemClassObject* enumerator = NULL;
        hres = pSvc->ExecQuery(
            bstr_t("WQL"),
            bstr_t("SELECT * FROM Win32_BaseBoard"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &enumerator
        );

        if (FAILED(hres)) {
            debug("VPC_BOARD: Query for Win32_BaseBoard failed. Error code: ", hres);
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return false;
        }

        IWbemClassObject* pclsObj = NULL;
        ULONG uReturn = 0;
        bool is_vm = false;

        while (enumerator) {
            HRESULT hr = enumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

            if (uReturn == 0) {
                break;
            }

            VARIANT vtProp;
            VariantInit(&vtProp);
            hr = pclsObj->Get(L"Manufacturer", 0, &vtProp, 0, 0);

            if (SUCCEEDED(hr)) {
                if (vtProp.vt == VT_BSTR && _wcsicmp(vtProp.bstrVal, L"Microsoft Corporation") == 0) {
                    is_vm = true;
                    VariantClear(&vtProp);
                    break;
                }

                VariantClear(&vtProp);
            }

            pclsObj->Release();
        }

        enumerator->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();

        if (is_vm) {
            return core::add(VPC);
        }

        return false;
#endif
    }
    catch (...) {
        debug("VPC_BOARD:", "caught error, returned false");
        return false;
    }


    /**
     * @brief get WMI query for HYPERV name
     * @category Windows
     * @note idea is from nettitude
     * @link https://labs.nettitude.com/blog/vm-detection-tricks-part-3-hyper-v-raw-network-protocol/
     */
    [[nodiscard]] static bool hyperv_wmi() try {
#if (!MSVC)
        return false;
#else
        HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) {
            debug("HYPERV_WMI: Failed to initialize COM library. Error code = ", hres);
            return false;
        }

        hres = CoInitializeSecurity(
            NULL,
            -1,                          // COM authentication
            NULL,                        // Authentication services
            NULL,                        // Reserved
            RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication
            RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
            NULL,                        // Authentication info
            EOAC_NONE,                   // Additional capabilities
            NULL                         // Reserved
        );

        if (FAILED(hres)) {
            debug("HYPERV_WMI: Failed to initialize security. Error code = ", hres);
            CoUninitialize();
            return false;
        }

        // Connect to WMI
        IWbemLocator* pLoc = NULL;
        hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);

        if (FAILED(hres)) {
            debug("HYPERV_WMI: Failed to create IWbemLocator object. Error code = ", hres);
            CoUninitialize();
            return false;
        }

        IWbemServices* pSvc = NULL;
        hres = pLoc->ConnectServer(
            _bstr_t(L"\\\\.\\root\\CIMV2"),   // Object path of WMI namespace
            NULL,                             // User name. NULL = current user
            NULL,                             // User password. NULL = current
            0,                                // Locale. NULL indicates current
            NULL,                             // Security flags.
            0,                                // Authority (e.g. Kerberos)
            0,                                // Context object
            &pSvc                             // pointer to IWbemServices proxy
        );

        if (FAILED(hres)) {
            debug("HYPERV_WMI: Could not connect. Error code = ", hres);
            pLoc->Release();
            CoUninitialize();
            return false;
        }

        hres = CoSetProxyBlanket(
            pSvc,                        // Indicates the proxy to set
            RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
            RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
            NULL,                        // Server principal name
            RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx
            RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
            NULL,                        // client identity
            EOAC_NONE                    // proxy capabilities
        );

        if (FAILED(hres)) {
            debug("HYPERV_WMI: Could not set proxy blanket. Error code = ", hres);
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return false;
        }

        IEnumWbemClassObject* pEnumerator = NULL;
        hres = pSvc->ExecQuery(
            _bstr_t(L"WQL"),
            _bstr_t(L"SELECT * FROM Win32_NetworkProtocol"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &pEnumerator
        );

        if (FAILED(hres)) {
            debug("HYPERV_WMI: ExecQuery failed. Error code = ", hres);
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return false;
        }

        IWbemClassObject* pclsObj = NULL;
        ULONG uReturn = 0;
        bool is_vm = false;

        while (pEnumerator) {
            HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

            if (uReturn == 0 || FAILED(hr)) {
                break;
            }

            VARIANT vtProp;
            VariantInit(&vtProp);
            hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);

            if (!FAILED(hr)) {
                if (vtProp.vt == VT_BSTR) {
                    is_vm = (wcscmp(vtProp.bstrVal, L"Hyper-V RAW") == 0);
                }
            }

            VariantClear(&vtProp);
            pclsObj->Release();
            pclsObj = NULL;
        }

        pSvc->Release();
        pLoc->Release();
        pEnumerator->Release();
        CoUninitialize();

        return is_vm;
#endif
    }
    catch (...) {
        debug("HYPERV_WMI: ", "caught error, returned false");
        return false;
    }


    /**
     * @brief compare for hyperv-specific string in registry
     * @category Windows
     * @note idea is from nettitude
     * @link https://labs.nettitude.com/blog/vm-detection-tricks-part-3-hyper-v-raw-network-protocol/
     */
    [[nodiscard]] static bool hyperv_registry() try {
#if (!MSVC)
        return false;
#else
        constexpr const char* registryPath = "SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries";

        HKEY hKey;
        LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, reinterpret_cast<LPCWSTR>(registryPath), 0, KEY_READ, &hKey);

        if (result != ERROR_SUCCESS) {
            debug("HYPERV_WMI: Error opening registry key. Code: ", result);
            return false;
        }

        bool is_vm = false;

        DWORD index = 0;
        wchar_t subkeyName[256];
        DWORD subkeyNameSize = sizeof(subkeyName) / sizeof(subkeyName[0]);

        while (RegEnumKeyExW(hKey, index++, subkeyName, &subkeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            HKEY subkey;
            result = RegOpenKeyExW(hKey, subkeyName, 0, KEY_READ, &subkey);

            if (result == ERROR_SUCCESS) {
                wchar_t protocolName[256]{};
                DWORD dataSize = sizeof(protocolName);

                // Check if the "ProtocolName" value exists
                result = RegQueryValueExW(subkey, L"ProtocolName", NULL, NULL, reinterpret_cast<LPBYTE>(protocolName), &dataSize);

                if (result == ERROR_SUCCESS) {
                    if (wcscmp(protocolName, L"Hyper-V RAW") == 0) {
                        is_vm = true;
                        break;
                    }
                }

                RegCloseKey(subkey);
            }

            subkeyNameSize = sizeof(subkeyName) / sizeof(subkeyName[0]);
        }

        RegCloseKey(hKey);

        return is_vm;
#endif 
    }
    catch (...) {
        debug("HYPERV_WMI: ", "caught error, returned false");
        return false;
    }


    /**
     * @brief Check for VirtualBox-specific string for shared folder ID
     * @category Windows
     * @note slightly modified code from original
     * @author @waleedassar
     * @link https://pastebin.com/xhFABpPL
     */
    [[nodiscard]] static bool vbox_shared_folders() try {
#if (!MSVC)
        return false;
#else
        DWORD pnsize = 0;  // Initialize to 0 to query the required size
        wchar_t* provider = nullptr;

        // Query the required size
        DWORD retv = WNetGetProviderNameW(WNNC_NET_RDR2SAMPLE, nullptr, &pnsize);

        if (retv == ERROR_MORE_DATA) {
            // Allocate a buffer of the required size
            provider = static_cast<wchar_t*>(LocalAlloc(LMEM_ZEROINIT, pnsize));

            if (provider != nullptr) {
                // Retrieve the actual data
                retv = WNetGetProviderNameW(WNNC_NET_RDR2SAMPLE, provider, &pnsize);
            }
        }

        if (retv == NO_ERROR && provider != nullptr) {
            if (lstrcmpiW(provider, L"VirtualBox Shared Folders") == 0) {
                LocalFree(provider);
                return core::add(VBOX);
            }
        }

        // Clean up the allocated buffer
        LocalFree(provider);

        return false;

#endif
    }
    catch (...) {
        debug("VBOX_FOLDERS: ", "caught error, returned false");
        return false;
    }


    /**
     * @brief Check MSSMBIOS registry for VM-specific strings
     * @category Windows
     * @note slightly modified from original code
     * @author @waleedassar
     * @link https://pastebin.com/fPY4MiYq
     */
    [[nodiscard]] static bool mssmbios() try {
#if (!MSVC)
        return false;
#else
        HKEY hk = 0;
        int ret = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\mssmbios\\data", 0, KEY_ALL_ACCESS, &hk);
        if (ret != ERROR_SUCCESS) {
            return false;
        }

        bool is_vm = false;
        unsigned long type = 0;
        unsigned long length = 0;
        ret = RegQueryValueExW(hk, L"SMBiosData", 0, &type, 0, &length);

        if (ret != ERROR_SUCCESS) {
            RegCloseKey(hk);
            return false;
        }

        if (length == 0) {
            RegCloseKey(hk);
            return false;
        }

        char* p = static_cast<char*>(LocalAlloc(LMEM_ZEROINIT, length));

        if (p == nullptr) {
            RegCloseKey(hk);
            return false;
        }

        ret = RegQueryValueExW(hk, L"SMBiosData", 0, &type, (unsigned char*)p, &length);

        if (ret != ERROR_SUCCESS) {
            LocalFree(p);
            RegCloseKey(hk);
            return false;
        }

        auto ScanDataForString = [](unsigned char* data, unsigned long data_length, unsigned char* string2) -> unsigned char* {
            std::size_t string_length = strlen(reinterpret_cast<char*>(string2));

            for (std::size_t i = 0; i <= (data_length - string_length); i++) {
                if (strncmp(reinterpret_cast<char*>(&data[i]), reinterpret_cast<char*>(string2), string_length) == 0) {
                    return &data[i];
                }
            }

            return 0;
            };

        auto AllToUpper = [](char* str, std::size_t len) {
            for (std::size_t i = 0; i < len; ++i) {
                str[i] = static_cast<char>(std::toupper(static_cast<unsigned char>(str[i])));
            }
            };

        AllToUpper(p, length);

        // cleaner and better shortcut than typing reinterpret_cast<unsigned char*> a million times
        auto cast = [](char* p) -> unsigned char* {
            return reinterpret_cast<unsigned char*>(p);
            };

        unsigned char* x1 = ScanDataForString(cast(p), length, (unsigned char*)("INNOTEK GMBH"));
        unsigned char* x2 = ScanDataForString(cast(p), length, (unsigned char*)("VIRTUALBOX"));
        unsigned char* x3 = ScanDataForString(cast(p), length, (unsigned char*)("SUN MICROSYSTEMS"));
        unsigned char* x4 = ScanDataForString(cast(p), length, (unsigned char*)("VBOXVER"));
        unsigned char* x5 = ScanDataForString(cast(p), length, (unsigned char*)("VIRTUAL MACHINE"));

        if (x1 || x2 || x3 || x4 || x5) {
            is_vm = true;
#ifdef __VMAWARE_DEBUG__
            if (x1) { debug("VBOX_MSSMBIOS: x1 = ", x1); }
            if (x2) { debug("VBOX_MSSMBIOS: x2 = ", x2); }
            if (x3) { debug("VBOX_MSSMBIOS: x3 = ", x3); }
            if (x4) { debug("VBOX_MSSMBIOS: x4 = ", x4); }
            if (x5) { debug("VBOX_MSSMBIOS: x5 = ", x5); }
#endif
        }

        LocalFree(p);
        RegCloseKey(hk);

        if (is_vm) {
            if (x5) {
                return true;
            }

            return core::add(VBOX);
        }

        return false;
#endif
    }
    catch (...) {
        debug("VBOX_MSSMBIOS: ", "caught error, returned false");
        return false;
    }


    /**
     * @brief Check if memory is too low for MacOS system
     * @category MacOS
     * @link https://evasions.checkpoint.com/techniques/macos.html
     */
    [[nodiscard]] static bool hw_memsize() try {
#if (!APPLE)
        return false;
#else
        std::unique_ptr<std::string> result = util::sys_result("sysctl -n hw.memsize");
        const std::string ram = *result;

        if (ram == "0") {
            return false;
        }

        debug("MAC_MEMSIZE: ", "ram size = ", ram);

        for (const char c : ram) {
            if (!std::isdigit(c)) {
                debug("MAC_MEMSIZE: ", "found non-digit character, returned false");
                return false;
            }
        }

        const u64 ram_u64 = std::stoull(ram);

        debug("MAC_MEMSIZE: ", "ram size in u64 = ", ram_u64);

        constexpr u64 limit = 4000000000; // 4GB 

        return (ram_u64 <= limit);
#endif
    }
    catch (...) {
        debug("MAC_MEMSIZE: ", "caught error, returned false");
        return false;
    }


    /**
     * @brief Check MacOS' IO kit registry for VM-specific strings
     * @category MacOS
     * @link https://evasions.checkpoint.com/techniques/macos.html
     */
    [[nodiscard]] static bool io_kit() try {
#if (!APPLE)
        return false;
#else
        // board_ptr and manufacturer_ptr empty
        std::unique_ptr<std::string> platform_ptr = util::sys_result("ioreg -rd1 -c IOPlatformExpertDevice");
        std::unique_ptr<std::string> board_ptr = util::sys_result("ioreg -rd1 -c board-id");
        std::unique_ptr<std::string> manufacturer_ptr = util::sys_result("ioreg -rd1 -c manufacturer");

        const std::string platform = *platform_ptr;
        const std::string board = *board_ptr;
        const std::string manufacturer = *manufacturer_ptr;

        auto check_platform = [&]() -> bool {
            debug("IO_KIT: ", "platform = ", platform);

            if (platform.empty()) {
                return false;
            }

            for (const char c : platform) {
                if (!std::isdigit(c)) {
                    return false;
                }
            }

            return (platform == "0");
            };

        auto check_board = [&]() -> bool {
            debug("IO_KIT: ", "board = ", board);

            if (board.empty()) {
                return false;
            }

            if (util::find(board, "Mac")) {
                return false;
            }

            if (util::find(board, "VirtualBox")) {
                return core::add(VBOX);
            }

            if (util::find(board, "VMware")) {
                return core::add(VMWARE);
            }

            return false;
            };

        auto check_manufacturer = [&]() -> bool {
            debug("IO_KIT: ", "manufacturer = ", manufacturer);

            if (manufacturer.empty()) {
                return false;
            }

            if (util::find(manufacturer, "Apple")) {
                return false;
            }

            if (util::find(manufacturer, "innotek")) {
                return core::add(VBOX);
            }

            return false;
            };

        return (
            check_platform() ||
            check_board() ||
            check_manufacturer()
            );

        return false;
#endif            
    }
    catch (...) {
        debug("MAC_IOKIT: ", "caught error, returned false");
        return false;
    }


    /**
     * @brief Check for VM-strings in ioreg commands for MacOS
     * @category MacOS
     * @link https://evasions.checkpoint.com/techniques/macos.html
     */
    [[nodiscard]] static bool ioreg_grep() try {
#if (!APPLE)
        return false;
#else
        auto check_usb = []() -> bool {
            std::unique_ptr<std::string> result = util::sys_result("ioreg -rd1 -c IOUSBHostDevice | grep \"USB Vendor Name\"");
            const std::string usb = *result;

            if (util::find(usb, "Apple")) {
                return false;
            }

            if (util::find(usb, "VirtualBox")) {
                return core::add(VBOX);
            }

            return false;
            };

        auto check_general = []() -> bool {
            std::unique_ptr<std::string> sys_vbox = util::sys_result("ioreg -l | grep -i -c -e \"virtualbox\" -e \"oracle\"");

            if (std::stoi(*sys_vbox) > 0) {
                return core::add(VBOX);
            }

            std::unique_ptr<std::string> sys_vmware = util::sys_result("ioreg -l | grep -i -c -e \"vmware\"");

            if (std::stoi(*sys_vmware) > 0) {
                return core::add(VMWARE);
            }

            return false;
            };

        auto check_rom = []() -> bool {
            std::unique_ptr<std::string> sys_rom = util::sys_result("system_profiler SPHardwareDataType | grep \"Boot ROM Version\"");
            const std::string rom = *sys_rom;

            if (util::find(rom, "VirtualBox")) {
                return core::add(VBOX);
            }

            return false;
            };

        return (
            check_usb() ||
            check_general() ||
            check_rom()
            );
#endif
    }
    catch (...) {
        debug("IOREG_GREP: ", "caught error, returned false");
        return false;
    }


    /**
     * @brief Check if System Integrity Protection is disabled (likely a VM if it is)
     * @category MacOS
     * @link https://evasions.checkpoint.com/techniques/macos.html
     */
    [[nodiscard]] static bool mac_sip() try {
#if (!APPLE)
        return false;
#else
        std::unique_ptr<std::string> result = util::sys_result("csrutil status");
        const std::string tmp = *result;

        debug("MAC_SIP: ", "result = ", tmp);

        return (util::find(tmp, "disabled") || (!util::find(tmp, "enabled")));
#endif
    }
    catch (...) {
        debug("MAC_SIP: ", "caught error, returned false");
        return false;
    }


    /**
     * @brief Fetch HKLM registries for specific VM strings
     * @category Windows
     */
    [[nodiscard]] static bool hklm_registries() try {
#if (!MSVC)
        return false;
#else
        u8 count = 0;

        auto check_key = [&count](const char* p_brand, const char* subKey, const char* valueName, const char* comp_string) {
            HKEY hKey;
            DWORD dwType = REG_SZ;
            char buffer[1024]{};
            DWORD bufferSize = sizeof(buffer);

            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                if (RegQueryValueExA(hKey, valueName, NULL, &dwType, reinterpret_cast<LPBYTE>(buffer), &bufferSize) == ERROR_SUCCESS) {
                    if (strcmp(buffer, comp_string) == 0) {
                        core::add(p_brand);
                        count++;
                    }
                }
                else {
                    debug("Failed to query value for \"", subKey, "\"");
                }

                RegCloseKey(hKey);
            }
            else {
                debug("Failed to open registry key for \"", subKey, "\"");
            }
            };

        check_key(BOCHS, "HARDWARE\\Description\\System", "SystemBiosVersion", "BOCHS");
        check_key(BOCHS, "HARDWARE\\Description\\System", "VideoBiosVersion", "BOCHS");

        check_key(ANUBIS, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "ProductID", "76487-337-8429955-22614");
        check_key(ANUBIS, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductID", "76487-337-8429955-22614");

        check_key(CWSANDBOX, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "ProductID", "76487-644-3177037-23510");
        check_key(CWSANDBOX, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductID", "76487-644-3177037-23510");

        check_key(JOEBOX, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "ProductID", "55274-640-2673064-23950");
        check_key(JOEBOX, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductID", "55274-640-2673064-23950");

        check_key(PARALLELS, "HARDWARE\\Description\\System", "SystemBiosVersion", "PARALLELS");
        check_key(PARALLELS, "HARDWARE\\Description\\System", "VideoBiosVersion", "PARALLELS");

        check_key(QEMU, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier", "QEMU");
        check_key(QEMU, "HARDWARE\\Description\\System", "SystemBiosVersion", "QEMU");
        check_key(QEMU, "HARDWARE\\Description\\System", "VideoBiosVersion", "QEMU");
        check_key(QEMU, "HARDWARE\\Description\\System\\BIOS", "SystemManufacturer", "QEMU");

        check_key(VBOX, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier", "VBOX");
        check_key(VBOX, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier", "VBOX");
        check_key(VBOX, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier", "VBOX");
        check_key(VBOX, "HARDWARE\\Description\\System", "SystemBiosVersion", "VBOX");
        check_key(VBOX, "HARDWARE\\Description\\System", "VideoBiosVersion", "VIRTUALBOX");
        check_key(VBOX, "HARDWARE\\Description\\System\\BIOS", "SystemProductName", "VIRTUAL");
        check_key(VBOX, "SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "DeviceDesc", "VBOX");
        check_key(VBOX, "SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "FriendlyName", "VBOX");
        check_key(VBOX, "SYSTEM\\ControlSet002\\Services\\Disk\\Enum", "DeviceDesc", "VBOX");
        check_key(VBOX, "SYSTEM\\ControlSet002\\Services\\Disk\\Enum", "FriendlyName", "VBOX");
        check_key(VBOX, "SYSTEM\\ControlSet003\\Services\\Disk\\Enum", "DeviceDesc", "VBOX");
        check_key(VBOX, "SYSTEM\\ControlSet003\\Services\\Disk\\Enum", "FriendlyName", "VBOX");
        check_key(VBOX, "SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemProductName", "VIRTUAL");
        check_key(VBOX, "SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemProductName", "VIRTUALBOX");

        check_key(VMWARE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier", "VMWARE");
        check_key(VMWARE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier", "VMWARE");
        check_key(VMWARE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier", "VMWARE");
        check_key(VMWARE, "HARDWARE\\Description\\System", "SystemBiosVersion", "VMWARE");
        check_key(VMWARE, "HARDWARE\\Description\\System", "SystemBiosVersion", "INTEL - 6040000");
        check_key(VMWARE, "HARDWARE\\Description\\System", "VideoBiosVersion", "VMWARE");
        check_key(VMWARE, "HARDWARE\\Description\\System\\BIOS", "SystemProductName", "VMware");
        check_key(VMWARE, "SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "0", "VMware");
        check_key(VMWARE, "SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "1", "VMware");
        check_key(VMWARE, "SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "DeviceDesc", "VMware");
        check_key(VMWARE, "SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "FriendlyName", "VMware");
        check_key(VMWARE, "SYSTEM\\ControlSet002\\Services\\Disk\\Enum", "DeviceDesc", "VMware");
        check_key(VMWARE, "SYSTEM\\ControlSet002\\Services\\Disk\\Enum", "FriendlyName", "VMware");
        check_key(VMWARE, "SYSTEM\\ControlSet003\\Services\\Disk\\Enum", "DeviceDesc", "VMware");
        check_key(VMWARE, "SYSTEM\\ControlSet003\\Services\\Disk\\Enum", "FriendlyName", "VMware");
        //check_key(HKCR\Installer\Products 	ProductName 	vmware tools
        //check_key(HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall 	DisplayName 	vmware tools
        check_key(VMWARE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "DisplayName", "vmware tools");
        check_key(VMWARE, "SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000", "CoInstallers32", "*vmx*");
        check_key(VMWARE, "SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000", "DriverDesc", "VMware*");
        check_key(VMWARE, "SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000", "InfSection", "vmx*");
        check_key(VMWARE, "SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000", "ProviderName", "VMware*");
        check_key(VMWARE, "SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\Settings", "Device Description", "VMware*");
        check_key(VMWARE, "SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemProductName", "VMWARE");
        check_key(VMWARE, "SYSTEM\\CurrentControlSet\\Control\\Video\\{GUID}\\Video", "Service", "vm3dmp");
        check_key(VMWARE, "SYSTEM\\CurrentControlSet\\Control\\Video\\{GUID}\\Video", "Service", "vmx_svga");
        check_key(VMWARE, "SYSTEM\\CurrentControlSet\\Control\\Video\\{GUID}\\0000", "Device Description", "VMware SVGA*");

        check_key(XEN, "HARDWARE\\Description\\System\\BIOS", "SystemProductName", "Xen");

        return (count > 0);
#endif
    }
    catch (...) {
        debug("KHLM_REGISTRIES: ", "caught error, returned false");
        return false;
    }


    /**
     * @brief Check for qemu-ga process
     * @category Linux
     */
    [[nodiscard]] static bool qemu_ga() try {
#if (!LINUX)
        return false;
#else
        constexpr const char* process = "qemu-ga";

        if (util::is_proc_running(process)) {
            return core::add(QEMU);
        }

        return false;
#endif
    }
    catch (...) {
        debug("QEMU_GA: ", "caught error, returned false");
        return false;
    }


    /**
     * @brief check for valid MSR value
     * @category Windows
     * @author LukeGoule
     * @link https://github.com/LukeGoule/compact_vm_detector/tree/main
     * @copyright MIT
     */
    [[nodiscard]] static bool valid_msr() {
#if (!MSVC)
        return false;
#else
        __try
        {
            __readmsr(cpu::leaf::hypervisor);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }

        return true;
#endif
    }


    /**
     * @brief Check for QEMU processes
     * @category Windows
     */
    [[nodiscard]] static bool qemu_processes() try {
#if (!MSVC)
        return false;
#else
        constexpr std::array<const TCHAR*, 3> qemu_proc_strings = { {
            _T("qemu-ga.exe"),
            _T("vdagent.exe"),
            _T("vdservice.exe")
        } };

        for (const auto str : qemu_proc_strings) {
            if (util::is_proc_running(str)) {
                return core::add(QEMU);
            }
        }

        return false;
#endif
    }
    catch (...) {
        debug("QEMU_PROC: ", "caught error, returned false");
        return false;
    }


    /**
     * @brief Check for VPC processes
     * @category Windows
     */
    [[nodiscard]] static bool vpc_proc() try {
#if (!MSVC)
        return false;
#else
        constexpr std::array<const TCHAR*, 2> vpc_proc_strings = { {
            _T("VMSrvc.exe"),
            _T("VMUSrvc.exe")
        } };

        for (const auto str : vpc_proc_strings) {
            if (util::is_proc_running(str)) {
                return core::add(VPC);
            }
        }

        return false;
#endif
    }
    catch (...) {
        debug("VPC_PROC: ", "caught error, returned false");
        return false;
    }


    /**
     * @brief Check for official VPC method
     * @category Windows, x86
     */
    [[nodiscard]] static bool vpc_invalid() {
#if (!MSVC || !x86)
        return false;
#elif (x86_32)
        bool rc = false;

        auto IsInsideVPC_exceptionFilter = [](PEXCEPTION_POINTERS ep) -> DWORD {
            PCONTEXT ctx = ep->ContextRecord;

            ctx->Ebx = static_cast<DWORD>(-1); // Not running VPC
            ctx->Eip += 4; // skip past the "call VPC" opcodes
            return static_cast<DWORD>(EXCEPTION_CONTINUE_EXECUTION);
            // we can safely resume execution since we skipped faulty instruction
            };

        __try {
            __asm {
                push eax
                push ebx
                push ecx
                push edx

                mov ebx, 0h
                mov eax, 01h

                __emit 0Fh
                __emit 3Fh
                __emit 07h
                __emit 0Bh

                test ebx, ebx
                setz[rc]

                pop edx
                pop ecx
                pop ebx
                pop eax
            }
        }
        __except (IsInsideVPC_exceptionFilter(GetExceptionInformation())) {
            rc = false;
        }

        return rc;
#else
        return false;
#endif
    }


    /**
     * @brief Check for sidt method
     * @category Linux, Windows, x86
     */
    [[nodiscard]] static bool sidt() try {
        // gcc/g++ causes a stack smashing error at runtime for some reason
        if (GCC) {
            return false;
        }

        u8 idtr[10]{};
        u32 idt_entry = 0;

#if (MSVC)
#if (x86_32)
        _asm sidt idtr
#elif (x86)
#pragma pack(1)
        struct IDTR {
            u16 limit;
            u64 base;
        };
#pragma pack()

        IDTR idtrStruct;
        __sidt(&idtrStruct);
        std::memcpy(idtr, &idtrStruct, sizeof(IDTR));
#else
        return false;
#endif

        idt_entry = *reinterpret_cast<unsigned long*>(&idtr[2]);
#elif (LINUX)
        // false positive with root for some reason
        if (util::is_admin()) {
            return false;
        }

        struct IDTR {
            u16 limit;
            u32 base;
        } __attribute__((packed));

        IDTR idtr_struct;

        __asm__ __volatile__(
            "sidt %0"
            : "=m" (idtr_struct)
        );

        std::ifstream mem("/dev/mem", std::ios::binary);
        mem.seekg(idtr_struct.base + 8, std::ios::beg);
        mem.read(reinterpret_cast<char*>(&idt_entry), sizeof(idt_entry));
        mem.close();
        UNUSED(idtr);
#else
        UNUSED(idtr);
        UNUSED(idt_entry);
        return false;
#endif

        if ((idt_entry >> 24) == 0xFF) {
            return core::add(VMWARE);
        }

        return false;
    }
    catch (...) {
        debug("SIDT: ", "caught error, returned false");
        return false;
    }


    /**
     * @brief Check for sldt
     * @category Windows, x86
     */
    [[nodiscard]] static bool sldt() try {
#if (x86_32 && MSVC)
        unsigned short ldtr[5] = { 0xEF, 0xBE, 0xAD, 0xDE };
        unsigned int ldt = 0;

        _asm sldt ldtr;
        ldt = *((u32*)&ldtr[0]);

        return (ldt != 0xDEAD0000);
#else
        return false;
#endif
    }
    catch (...) {
        debug("SLDT: ", "caught error, returned false");
        return false;
    }


    /**
     * @brief Check for sgdt
     * @category Windows, x86
     */
    [[nodiscard]] static bool sgdt() try {
#if (x86_32 && MSVC)
        u8 gdtr[6]{};
        u32 gdt = 0;

        _asm sgdt gdtr
        gdt = *((unsigned long*)&gdtr[2]);

        return ((gdt >> 24) == 0xFF);
#else
        return false;
#endif
    }
    catch (...) {
        debug("SGDT: ", "caught error, returned false");
        return false;
    }


    /**
     * @brief Go through the motherboard and match for Hyper-V string
     * @category Windows
     */
    [[nodiscard]] static bool hyperv_board() try {
#if (!MSVC)
        return false;
#else
        HRESULT hres;

        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) {
            debug("VPC_BOARD: Failed to initialize COM library. Error code: ", hres);
            return false;
        }

        hres = CoInitializeSecurity(
            NULL,
            -1,                          // use the default authentication service
            NULL,                        // use the default authorization service
            NULL,                        // reserved
            RPC_C_AUTHN_LEVEL_DEFAULT,   // authentication
            RPC_C_IMP_LEVEL_IMPERSONATE, // impersonation
            NULL,                        // authentication info
            EOAC_NONE,                   // additional capabilities
            NULL                         // reserved
        );

        if (FAILED(hres)) {
            debug("VPC_BOARD: Failed to initialize security. Error code: ", hres);
            CoUninitialize();
            return false;
        }

        IWbemLocator* pLoc = NULL;
        IWbemServices* pSvc = NULL;

        hres = CoCreateInstance(
            CLSID_WbemLocator,
            0,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator,
            (LPVOID*)&pLoc
        );

        if (FAILED(hres)) {
            debug("VPC_BOARD: Failed to create IWbemLocator object. Error code: ", hres);
            CoUninitialize();
            return false;
        }

        hres = pLoc->ConnectServer(
            _bstr_t(L"ROOT\\CIMV2"), // Namespace
            NULL,                    // User name
            NULL,                    // User password
            0,                       // Locale
            NULL,                    // Security flags
            0,                       // Authority
            0,                       // Context object pointer
            &pSvc
        );

        if (FAILED(hres)) {
            debug("VPC_BOARD: Failed to connect to WMI. Error code: ", hres);
            pLoc->Release();
            CoUninitialize();
            return false;
        }

        hres = CoSetProxyBlanket(
            pSvc,                        // Indicates the proxy to set
            RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
            RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
            NULL,                        // Server principal name
            RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx
            RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
            NULL,                        // client identity
            EOAC_NONE                    // proxy capabilities
        );

        if (FAILED(hres)) {
            debug("VPC_BOARD: Failed to set proxy blanket. Error code: ", hres);
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return false;
        }

        IEnumWbemClassObject* enumerator = NULL;
        hres = pSvc->ExecQuery(
            bstr_t("WQL"),
            bstr_t("SELECT * FROM Win32_BaseBoard"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &enumerator
        );

        if (FAILED(hres)) {
            debug("VPC_BOARD: Query for Win32_BaseBoard failed. Error code: ", hres);
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return false;
        }

        IWbemClassObject* pclsObj = NULL;
        ULONG uReturn = 0;
        bool is_vm = false;

        while (enumerator) {
            HRESULT hr = enumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

            if (uReturn == 0) {
                break;
            }

            VARIANT vtProp;
            VariantInit(&vtProp);
            hr = pclsObj->Get(L"Manufacturer", 0, &vtProp, 0, 0);

            if (SUCCEEDED(hr)) {
                if (vtProp.vt == VT_BSTR && _wcsicmp(vtProp.bstrVal, L"Microsoft Corporation Virtual Machine") == 0) {
                    is_vm = true;
                    VariantClear(&vtProp);
                    break;
                }

                VariantClear(&vtProp);
            }

            pclsObj->Release();
        }

        enumerator->Release();
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();

        if (is_vm) {
            return core::add(HYPERV);
        }

        return false;
#endif
    }
    catch (...) {
        debug("HYPERV_BOARD:", "caught error, returned false");
        return false;
    }


    /**
     * @brief Check for offensive security sidt method
     * @category Windows, x86
     * @author Danny Quist (chamuco@gmail.com)
     * @author Val Smith (mvalsmith@metasploit.com)
     * @note code documentation paper in /papers/www.offensivecomputing.net_vm.pdf
     */
    [[nodiscard]] static bool offsec_sidt() try {
#if (!MSVC || !x86)
        return false;
#elif (x86_32)
        unsigned char m[6]{};
        __asm sidt m;

        return (m[5] > 0xD0);
#else
        return false;
#endif
    }
    catch (...) {
        debug("OFFSEC_SIDT: ", "caught error, returned false");
        return false;
    }


    /**
     * @brief Check for offensive security sgdt method
     * @category Windows, x86
     * @author Danny Quist (chamuco@gmail.com)
     * @author Val Smith (mvalsmith@metasploit.com)
     * @note code documentation paper in /papers/www.offensivecomputing.net_vm.pdf
     */
    [[nodiscard]] static bool offsec_sgdt() try {
#if (!MSVC || !x86)
        return false;
#elif (x86_32)
        unsigned char m[6]{};
        __asm sgdt m;

        return (m[5] > 0xD0);
#else
        return false;
#endif
    }
    catch (...) {
        debug("OFFSEC_SGDT: ", "caught error, returned false");
        return false;
    }


    /**
     * @brief Check for Offensive Security sldt method
     * @category Windows, x86
     * @author Danny Quist (chamuco@gmail.com)
     * @author Val Smith (mvalsmith@metasploit.com)
     * @note code documentation paper in /papers/www.offensivecomputing.net_vm.pdf
     */
    [[nodiscard]] static bool offsec_sldt() try {
#if (!MSVC || !x86)
        return false;
#elif (x86_32)
        unsigned short m[6]{};
        __asm sldt m;

        return (m[0] != 0x00 && m[1] != 0x00);
#else
        return false;
#endif
    }
    catch (...) {
        debug("OFFSEC_SLDT: ", "caught error, returned false");
        return false;
    }


    /**
     * @brief Check for sidt method with VPC's 0xE8XXXXXX range
     * @category Windows, x86
     * @note Idea from Tom Liston and Ed Skoudis' paper "On the Cutting Edge: Thwarting Virtual Machine Detection"
     * @note Paper situated at /papers/ThwartingVMDetection_Liston_Skoudis.pdf
     */
    [[nodiscard]] static bool vpc_sidt() try {
#if (!MSVC || !x86)
        return false;
#elif (x86_32)
        u8	idtr[6]{};
        u32	idt = 0;

        _asm sidt idtr
        idt = *((unsigned long*)&idtr[2]);

        if ((idt >> 24) == 0xE8) {
            return core::add(VPC);
        }

        return false;
#else
        return false;
#endif
    }
    catch (...) {
        debug("VPC_SIDT: ", "caught error, returned false");
        return false;
    }


    /**
     * @brief Find for VPC and Parallels specific VM files
     * @category Windows
     */
    [[nodiscard]] static bool vm_files_extra() try {
#if (!MSVC)
        return false;
#else
        constexpr std::array<std::pair<const char*, const char*>, 9> files = { {
            { VPC, "c:\\windows\\system32\\drivers\\vmsrvc.sys" },
            { VPC, "c:\\windows\\system32\\drivers\\vpc-s3.sys" },
            { PARALLELS, "c:\\windows\\system32\\drivers\\prleth.sys" },
            { PARALLELS, "c:\\windows\\system32\\drivers\\prlfs.sys" },
            { PARALLELS, "c:\\windows\\system32\\drivers\\prlmouse.sys" },
            { PARALLELS, "c:\\windows\\system32\\drivers\\prlvideo.sys" },
            { PARALLELS, "c:\\windows\\system32\\drivers\\prltime.sys" },
            { PARALLELS, "c:\\windows\\system32\\drivers\\prl_pv32.sys" },
            { PARALLELS, "c:\\windows\\system32\\drivers\\prl_paravirt_32.sys" }
        } };

        for (const auto& file_pair : files) {
            if (util::exists(file_pair.second)) {
                return core::add(file_pair.first);
            }
        }

        return false;
#endif
    }
    catch (...) {
        debug("VM_FILES_EXTRA: caught error, returned false");
        return false;
    }


    /**
     * @brief Find for VMware string in /proc/iomem
     * @category Linux
     * @note idea from ScoopyNG by Tobias Klein
     */
    [[nodiscard]] static bool vmware_iomem() try {
#if (!LINUX)
        return false;
#else
        const std::string iomem_file = util::read_file("/proc/iomem");

        if (util::find(iomem_file, "VMware")) {
            return core::add(VMWARE);
        }

        return false;
#endif
    }
    catch (...) {
        debug("VMWARE_IOMEM: caught error, returned false");
        return false;
    }


    /**
     * @brief Find for VMware string in /proc/ioports
     * @category Windows
     * @note idea from ScoopyNG by Tobias Klein
     */
    [[nodiscard]] static bool vmware_ioports() try {
#if (!LINUX)
        return false;
#else
        const std::string ioports_file = util::read_file("/proc/ioports");

        if (util::find(ioports_file, "VMware")) {
            return core::add(VMWARE);
        }

        return false;
#endif
    }
    catch (...) {
        debug("VMWARE_IOPORTS: caught error, returned false");
        return false;
    }


    /**
     * @brief Find for VMware string in /proc/scsi/scsi
     * @category Windows
     * @note idea from ScoopyNG by Tobias Klein
     */
    [[nodiscard]] static bool vmware_scsi() try {
#if (!LINUX)
        return false;
#else
        const std::string scsi_file = util::read_file("/proc/scsi/scsi");

        if (util::find(scsi_file, "VMware")) {
            return core::add(VMWARE);
        }

        return false;
#endif
    }
    catch (...) {
        debug("VMWARE_SCSI: caught error, returned false");
        return false;
    }


    /**
     * @brief Find for VMware-specific device name in dmesg output
     * @category Windows
     * @note idea from ScoopyNG by Tobias Klein
     */
    [[nodiscard]] static bool vmware_dmesg() try {
#if (!LINUX)
        return false;
#else
        if (!util::is_admin()) {
            return false;
        }

        auto dmesg_output = util::sys_result("dmesg");
        const std::string dmesg = *dmesg_output;

        if (dmesg.empty()) {
            return false;
        }

        if (util::find(dmesg, "BusLogic BT-958")) {
            return core::add(VMWARE);
        }

        if (util::find(dmesg, "pcnet32")) {
            return core::add(VMWARE);
        }

        return false;
#endif
    }
    catch (...) {
        debug("VMWARE_DMESG: caught error, returned false");
        return false;
    }


    /**
     * @brief Check using str assembly instruction
     * @note Alfredo Omella's (S21sec) STR technique
     * @note paper describing this technique is located at /papers/www.s21sec.com_vmware-eng.pdf (2006)
     * @category Windows
     */
    [[nodiscard]] static bool vmware_str() try {
#if (!MSVC || !x86)
        return false;
#elif (x86_32)
        unsigned short mem[4] = { 0, 0, 0, 0 };

        __asm str mem;

        if ((mem[0] == 0x00) && (mem[1] == 0x40)) {
            return core::add(VMWARE);
        }
#else
        return false;
#endif
    }
    catch (...) {
        debug("VMWARE_STR: caught error, returned false");
        return false;
    }


    /**
     * @brief Check for official VMware io port backdoor technique
     * @category Windows, x86
     * @note Code from ScoopyNG by Tobias Klein
     * @note Technique founded by Ken Kato
     * @copyright BSD clause 2
     */
    [[nodiscard]] static bool vmware_backdoor() {
#if (!MSVC || !x86)
        return false;
#elif (x86_32)
        u32 a = 0;
        u32 b = 0;

        constexpr std::array<i16, 2> ioports = { 'VX' , 'VY' };
        i16 ioport;
        bool is_vm = false;

        for (u8 i = 0; i < ioports.size(); ++i) {
            ioport = ioports[i];
            for (u8 cmd = 0; cmd < 0x2c; ++cmd) {
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

                        mov a, ebx
                        mov b, ecx

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
        }

        if (is_vm) {
            switch (b) {
            case 1:  return core::add(VMWARE_EXPRESS);
            case 2:  return core::add(VMWARE_ESX);
            case 3:  return core::add(VMWARE_GSX);
            case 4:  return core::add(VMWARE_WORKSTATION);
            default: return core::add(VMWARE);
            }
        }

        return false;
#else
        return false;
#endif
    }


    /**
     * @brief Check for VMware memory using IO port backdoor
     * @category Windows, x86
     * @note Code from ScoopyNG by Tobias Klein
     * @copyright BSD clause 2
     */
    [[nodiscard]] static bool vmware_port_memory() {
#if (!MSVC || !x86)
        return false;
#elif (x86_32)
        unsigned int a = 0;

        __try {
            __asm {
                push eax
                push ebx
                push ecx
                push edx

                mov eax, 'VMXh'
                mov ecx, 14h
                mov dx, 'VX'
                in eax, dx
                mov a, eax

                pop edx
                pop ecx
                pop ebx
                pop eax
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {}

        if (a > 0) {
            return core::add(VMWARE);
        }

        return false;
#else
        return false;
#endif
    }


    /**
     * @brief Check for SMSW assembly instruction technique
     * @category Windows, x86
     * @author Danny Quist from Offensive Computing
     */
    [[nodiscard]] static bool smsw() try {
#if (!MSVC || !x86)
        return false;
#elif (x86_32)
        unsigned int reax = 0;

        __asm
        {
            mov eax, 0xCCCCCCCC;
            smsw eax;
            mov DWORD PTR[reax], eax;
        }

        return (
            (((reax >> 24) & 0xFF) == 0xCC) &&
            (((reax >> 16) & 0xFF) == 0xCC)
            );
#else
        return false;
#endif
    }
    catch (...) {
        debug("SMSW: caught error, returned false");
        return false;
    }


    /**
     * @brief Check for mutex strings of VM brands
     * @category Windows, x86
     * @note from VMDE project
     * @author hfiref0x
     * @copyright MIT
     */
    [[nodiscard]] static bool mutex() try {
#if (!MSVC)
        return false;
#else
        auto supMutexExist = [](const char* lpMutexName) -> bool {
            DWORD dwError;
            HANDLE hObject = NULL;
            if (lpMutexName == NULL) {
                return false;
            }

            SetLastError(0);
            hObject = CreateMutexA(NULL, FALSE, lpMutexName);
            dwError = GetLastError();

            if (hObject) {
                CloseHandle(hObject);
            }

            return (dwError == ERROR_ALREADY_EXISTS);
            };

        if (
            supMutexExist("Sandboxie_SingleInstanceMutex_Control") ||
            supMutexExist("SBIE_BOXED_ServiceInitComplete_Mutex1")
            ) {
            return core::add(SANDBOXIE);
        }

        if (supMutexExist("MicrosoftVirtualPC7UserServiceMakeSureWe'reTheOnlyOneMutex")) {
            return core::add(VPC);
        }

        if (supMutexExist("Frz_State")) {
            return true;
        }

        return false;
#endif
    }
    catch (...) {
        debug("MUTEX: caught error, returned false");
        return false;
    }


    /**
     * @brief Check for uptime of less than or equal to 2 minutes
     * @category Windows, Linux
     * @note https://stackoverflow.com/questions/30095439/how-do-i-get-system-up-time-in-milliseconds-in-c
     */
    [[nodiscard]] static bool uptime() try {
        constexpr u32 uptime_ms = 1000 * 60 * 2;
        constexpr u32 uptime_s = 60 * 2;

#if (MSVC)
        UNUSED(uptime_s);
        return (GetTickCount64() <= uptime_ms);
#elif (LINUX)
        UNUSED(uptime_ms);
        struct sysinfo info;

        if (sysinfo(&info) != 0) {
            debug("UPTIME: sysinfo failed");
            return false;
        }

        return (info.uptime < uptime_s);
#elif (APPLE)
        UNUSED(uptime_s);
        std::chrono::milliseconds uptime(0u);

        struct timeval ts;
        std::size_t len = sizeof(ts);

        int mib[2] = { CTL_KERN, KERN_BOOTTIME };

        if (sysctl(mib, 2, &ts, &len, NULL, 0) != 0) {
            return false;
        }

        uptime = std::chrono::milliseconds(
            (static_cast<u64>(ts.tv_sec) * 1000ULL) +
            (static_cast<u64>(ts.tv_usec) / 1000ULL)
        );

        return (uptime < uptime_ms);
#else
        return false;
#endif
    }
    catch (...) {
        debug("UPTIME: caught error, returned false");
        return false;
    }


    /**
     * @brief Check for odd CPU threads, usually a sign of modification through VM setting because 99% of CPUs have even numbers of threads
     * @category All, x86
     */
    [[nodiscard]] static bool odd_cpu_threads() try {
#if (!x86)
        return false;
#else
        const u32 threads = std::thread::hardware_concurrency();

        struct stepping_struct {
            u8 model;
            u8 family;
            u8 extmodel;
        };

        struct stepping_struct steps {};

        u32 unused, eax = 0;
        cpu::cpuid(eax, unused, unused, unused, 1);
        UNUSED(unused);

        steps.model = ((eax >> 4) & 0b1111);
        steps.family = ((eax >> 8) & 0b1111);
        steps.extmodel = ((eax >> 16) & 0b1111);

        debug("ODD_CPU_THREADS: model    = ", static_cast<u32>(steps.model));
        debug("ODD_CPU_THREADS: family   = ", static_cast<u32>(steps.family));
        debug("ODD_CPU_THREADS: extmodel = ", static_cast<u32>(steps.extmodel));

        // check if the CPU is an intel celeron
        auto is_celeron = [&steps]() -> bool {
            if (!cpu::is_intel()) {
                return false;
            }

            constexpr u8 celeron_family = 0x6;
            constexpr u8 celeron_extmodel = 0x2;
            constexpr u8 celeron_model = 0xA;

            return (
                steps.family == celeron_family &&
                steps.extmodel == celeron_extmodel &&
                steps.model == celeron_model
                );
            };

        // check if the microarchitecture was made before 2006, which was around the time multi-core processors were implemented
        auto old_microarchitecture = [&steps]() -> bool {
            constexpr std::array<std::array<u8, 3>, 32> old_archs = { {
                    // 80486
                    {{ 0x4, 0x0, 0x1 }},
                    {{ 0x4, 0x0, 0x2 }},
                    {{ 0x4, 0x0, 0x3 }},
                    {{ 0x4, 0x0, 0x4 }},
                    {{ 0x4, 0x0, 0x5 }},
                    {{ 0x4, 0x0, 0x7 }},
                    {{ 0x4, 0x0, 0x8 }},
                    {{ 0x4, 0x0, 0x9 }},

                    // P5
                    {{ 0x5, 0x0, 0x1 }},
                    {{ 0x5, 0x0, 0x2 }},
                    {{ 0x5, 0x0, 0x4 }},
                    {{ 0x5, 0x0, 0x7 }},
                    {{ 0x5, 0x0, 0x8 }},

                    // P6
                    {{ 0x6, 0x0, 0x1 }},
                    {{ 0x6, 0x0, 0x3 }},
                    {{ 0x6, 0x0, 0x5 }},
                    {{ 0x6, 0x0, 0x6 }},
                    {{ 0x6, 0x0, 0x7 }},
                    {{ 0x6, 0x0, 0x8 }},
                    {{ 0x6, 0x0, 0xA }},
                    {{ 0x6, 0x0, 0xB }},

                    // Netburst
                    {{ 0xF, 0x0, 0x6 }},
                    {{ 0xF, 0x0, 0x4 }},
                    {{ 0xF, 0x0, 0x3 }},
                    {{ 0xF, 0x0, 0x2 }},
                    {{ 0xF, 0x0, 0x10 }},

                    {{ 0x6, 0x1, 0x5 }}, // Pentium M (Talopai)
                    {{ 0x6, 0x1, 0x6 }}, // Core (Client)
                    {{ 0x6, 0x0, 0x9 }}, // Pentium M
                    {{ 0x6, 0x0, 0xD }}, // Pentium M
                    {{ 0x6, 0x0, 0xE }}, // Modified Pentium M
                    {{ 0x6, 0x0, 0xF }}  // Core (Client)
                } };

            constexpr u8 FAMILY = 0;
            constexpr u8 EXTMODEL = 1;
            constexpr u8 MODEL = 2;

            for (const auto& arch : old_archs) {
                if (
                    steps.family == arch.at(FAMILY) &&
                    steps.extmodel == arch.at(EXTMODEL) &&
                    steps.model == arch.at(MODEL)
                    ) {
                    return true;
                }
            }

            return false;
            };

        // self-explanatory
        if (!(cpu::is_intel() || cpu::is_amd())) {
            return false;
        }

        // intel celeron CPUs are relatively modern, but they can contain a single or odd thread count
        if (is_celeron()) {
            return false;
        }

        // CPUs before 2006 had no official multi-core processors
        if (old_microarchitecture()) {
            return false;
        }

        // is the count odd?
        return (threads & 1);
#endif
    }
    catch (...) {
        debug("ODD_CPU_THREADS: caught error, returned false");
        return false;
    }


    /**
     * @brief Check for CPUs that don't match their thread count
     * @category All, x86
     * @link https://en.wikipedia.org/wiki/List_of_Intel_Core_processors
     */
    [[nodiscard]] static bool intel_thread_mismatch() try {
#if (!x86)
        return false;
#else
        if (!cpu::is_intel()) {
            return false;
        }

        if (cpu::has_hyperthreading()) {
            return false;
        }

        const cpu::model_struct model = cpu::get_model();

        if (!model.found) {
            return false;
        }

        if (!model.is_i_series) {
            return false;
        }

        debug("INTEL_THREAD_MISMATCH: CPU model = ", model.string);

        auto thread_database = util::make_unique<std::unordered_map<std::string, uint8_t>>();

        auto push = [&thread_database](const char* brand_str, const u8 thread_count) -> void {
            thread_database->emplace(brand_str, thread_count);
            };

        // i3 series
        push("i3-1000G1", 4);
        push("i3-1000G4", 4);
        push("i3-1000NG4", 4);
        push("i3-1005G1", 4);
        push("i3-10100", 8);
        push("i3-10100E", 8);
        push("i3-10100F", 8);
        push("i3-10100T", 8);
        push("i3-10100TE", 8);
        push("i3-10100Y", 4);
        push("i3-10105", 8);
        push("i3-10105F", 8);
        push("i3-10105T", 8);
        push("i3-10110U", 4);
        push("i3-10110Y", 4);
        push("i3-10300", 8);
        push("i3-10300T", 8);
        push("i3-10305", 8);
        push("i3-10305T", 8);
        push("i3-10320", 8);
        push("i3-10325", 8);
        push("i3-11100B", 8);
        push("i3-11100HE", 8);
        push("i3-1110G4", 4);
        push("i3-1115G4E", 4);
        push("i3-1115GRE", 4);
        push("i3-1120G4", 8);
        push("i3-12100", 8);
        push("i3-12100F", 8);
        push("i3-12100T", 8);
        push("i3-1210U", 4);
        push("i3-1215U", 4);
        push("i3-1215UE", 4);
        push("i3-1215UL", 4);
        push("i3-12300", 8);
        push("i3-12300T", 8);
        push("i3-13100", 8);
        push("i3-13100F", 8);
        push("i3-13100T", 8);
        push("i3-1315U", 4);
        push("i3-1315UE", 4);
        push("i3-14100", 8);
        push("i3-14100F", 8);
        push("i3-14100T", 8);
        push("i3-2100", 4);
        push("i3-2100T", 4);
        push("i3-2102", 4);
        push("i3-2105", 4);
        push("i3-2120", 4);
        push("i3-2120T", 4);
        push("i3-2125", 4);
        push("i3-2130", 4);
        push("i3-2308M", 4);
        push("i3-2310E", 4);
        push("i3-2310M", 4);
        push("i3-2312M", 4);
        push("i3-2328M", 4);
        push("i3-2330E", 4);
        push("i3-2330M", 4);
        push("i3-2332M", 4);
        push("i3-2340UE", 4);
        push("i3-2348M", 4);
        push("i3-2350LM", 4);
        push("i3-2350M", 4);
        push("i3-2355M", 4);
        push("i3-2357M", 4);
        push("i3-2365M", 4);
        push("i3-2367M", 4);
        push("i3-2370LM", 4);
        push("i3-2370M", 4);
        push("i3-2375M", 4);
        push("i3-2377M", 4);
        push("i3-2390M", 4);
        push("i3-2393M", 4);
        push("i3-2394M", 4);
        push("i3-2395M", 4);
        push("i3-2397M", 4);
        push("i3-3110M", 4);
        push("i3-3115C", 4);
        push("i3-3120M", 4);
        push("i3-3120ME", 4);
        push("i3-3130M", 4);
        push("i3-3210", 4);
        push("i3-3217U", 4);
        push("i3-3217UE", 4);
        push("i3-3220", 4);
        push("i3-3220T", 4);
        push("i3-3225", 4);
        push("i3-3227U", 4);
        push("i3-3229Y", 4);
        push("i3-3240", 4);
        push("i3-3240T", 4);
        push("i3-3245", 4);
        push("i3-3250", 4);
        push("i3-3250T", 4);
        push("i3-330E", 4);
        push("i3-330M", 4);
        push("i3-330UM", 4);
        push("i3-350M", 4);
        push("i3-370M", 4);
        push("i3-380M", 4);
        push("i3-380UM", 4);
        push("i3-390M", 4);
        push("i3-4000M", 4);
        push("i3-4005U", 4);
        push("i3-4010M", 4);
        push("i3-4010U", 4);
        push("i3-4010Y", 4);
        push("i3-4012Y", 4);
        push("i3-4020Y", 4);
        push("i3-4025U", 4);
        push("i3-4030U", 4);
        push("i3-4030Y", 4);
        push("i3-4100E", 4);
        push("i3-4100M", 4);
        push("i3-4100U", 4);
        push("i3-4102E", 4);
        push("i3-4110E", 4);
        push("i3-4110M", 4);
        push("i3-4112E", 4);
        push("i3-4120U", 4);
        push("i3-4130", 4);
        push("i3-4130T", 4);
        push("i3-4150", 4);
        push("i3-4150T", 4);
        push("i3-4158U", 4);
        push("i3-4160", 4);
        push("i3-4160T", 4);
        push("i3-4170", 4);
        push("i3-4170T", 4);
        push("i3-4330", 4);
        push("i3-4330T", 4);
        push("i3-4330TE", 4);
        push("i3-4340", 4);
        push("i3-4340TE", 4);
        push("i3-4350", 4);
        push("i3-4350T", 4);
        push("i3-4360", 4);
        push("i3-4360T", 4);
        push("i3-4370", 4);
        push("i3-4370T", 4);
        push("i3-5005U", 4);
        push("i3-5010U", 4);
        push("i3-5015U", 4);
        push("i3-5020U", 4);
        push("i3-5157U", 4);
        push("i3-530", 4);
        push("i3-540", 4);
        push("i3-550", 4);
        push("i3-560", 4);
        push("i3-6006U", 4);
        push("i3-6098P", 4);
        push("i3-6100", 4);
        push("i3-6100E", 4);
        push("i3-6100H", 4);
        push("i3-6100T", 4);
        push("i3-6100TE", 4);
        push("i3-6100U", 4);
        push("i3-6102E", 4);
        push("i3-6120T", 4);
        push("i3-6157U", 4);
        push("i3-6167U", 4);
        push("i3-6300", 4);
        push("i3-6300T", 4);
        push("i3-6320", 4);
        push("i3-6320T", 4);
        push("i3-7007U", 4);
        push("i3-7020U", 4);
        push("i3-7100", 4);
        push("i3-7100E", 4);
        push("i3-7100H", 4);
        push("i3-7100T", 4);
        push("i3-7100U", 4);
        push("i3-7101E", 4);
        push("i3-7101TE", 4);
        push("i3-7102E", 4);
        push("i3-7110U", 4);
        push("i3-7120", 4);
        push("i3-7120T", 4);
        push("i3-7130U", 4);
        push("i3-7167U", 4);
        push("i3-7300", 4);
        push("i3-7300T", 4);
        push("i3-7310T", 4);
        push("i3-7310U", 4);
        push("i3-7320", 4);
        push("i3-7320T", 4);
        push("i3-7340", 4);
        push("i3-7350K", 4);
        push("i3-8000", 4);
        push("i3-8000T", 4);
        push("i3-8020", 4);
        push("i3-8020T", 4);
        push("i3-8100", 4);
        push("i3-8100B", 4);
        push("i3-8100F", 4);
        push("i3-8100H", 4);
        push("i3-8100T", 4);
        push("i3-8109U", 4);
        push("i3-8120", 4);
        push("i3-8120T", 4);
        push("i3-8121U", 4);
        push("i3-8130U", 4);
        push("i3-8130U", 4);
        push("i3-8140U", 4);
        push("i3-8145U", 4);
        push("i3-8145UE", 4);
        push("i3-8300", 4);
        push("i3-8300T", 4);
        push("i3-8320", 4);
        push("i3-8320T", 4);
        push("i3-8350K", 4);
        push("i3-9100", 4);
        push("i3-9100E", 4);
        push("i3-9100F", 4);
        push("i3-9100HL", 4);
        push("i3-9100T", 4);
        push("i3-9100TE", 4);
        push("i3-9300", 4);
        push("i3-9300T", 4);
        push("i3-9320", 4);
        push("i3-9350K", 4);
        push("i3-9350KF", 4);
        push("i3-N300", 8);
        push("i3-N305", 8);

        // i5 series
        push("i5-10200H", 8);
        push("i5-10210U", 4);
        push("i5-10210Y", 8);
        push("i5-10300H", 8);
        push("i5-1030G4", 8);
        push("i5-1030G7", 8);
        push("i5-1030NG7", 8);
        push("i5-10310U", 4);
        push("i5-10310Y", 8);
        push("i5-1035G1", 8);
        push("i5-1035G4", 8);
        push("i5-1035G7", 8);
        push("i5-1038NG7", 8);
        push("i5-10400", 12);
        push("i5-10400F", 12);
        push("i5-10400H", 8);
        push("i5-10400T", 12);
        push("i5-10500", 12);
        push("i5-10500E", 12);
        push("i5-10500H", 12);
        push("i5-10500T", 12);
        push("i5-10500TE", 12);
        push("i5-10505", 12);
        push("i5-10600", 12);
        push("i5-10600K", 12);
        push("i5-10600KF", 12);
        push("i5-10600T", 12);
        push("i5-1115G4", 4);
        push("i5-1125G4", 8);
        push("i5-11260H", 12);
        push("i5-11300H", 8);
        push("i5-1130G7", 8);
        push("i5-11320H", 8);
        push("i5-1135G7", 8);
        push("i5-11400", 12);
        push("i5-11400F", 12);
        push("i5-11400H", 12);
        push("i5-11400T", 12);
        push("i5-1140G7", 8);
        push("i5-1145G7", 8);
        push("i5-1145G7E", 8);
        push("i5-1145GRE", 8);
        push("i5-11500", 12);
        push("i5-11500B", 12);
        push("i5-11500H", 12);
        push("i5-11500HE", 12);
        push("i5-11500T", 12);
        push("i5-1155G7", 8);
        push("i5-11600", 12);
        push("i5-11600K", 12);
        push("i5-11600KF", 12);
        push("i5-11600T", 12);
        push("i5-1230U", 4);
        push("i5-1235U", 4);
        push("i5-12400", 12);
        push("i5-12400F", 12);
        push("i5-12400T", 12);
        push("i5-1240P", 8);
        push("i5-1240U", 4);
        push("i5-1245U", 4);
        push("i5-12490F", 12);
        push("i5-12500", 12);
        push("i5-12500H", 8);
        push("i5-12500HL", 8);
        push("i5-12500T", 12);
        push("i5-1250P", 8);
        push("i5-1250PE", 8);
        push("i5-12600", 12);
        push("i5-12600H", 8);
        push("i5-12600HE", 8);
        push("i5-12600HL", 8);
        push("i5-12600HX", 8);
        push("i5-12600K", 12);
        push("i5-12600KF", 12);
        push("i5-12600T", 12);
        push("i5-13400", 12);
        push("i5-13400F", 12);
        push("i5-13400T", 12);
        push("i5-1340P", 8);
        push("i5-1340PE", 8);
        push("i5-13490F", 12);
        push("i5-13500", 12);
        push("i5-13500H", 8);
        push("i5-13500T", 12);
        push("i5-13505H", 8);
        push("i5-1350P", 8);
        push("i5-1350PE", 8);
        push("i5-13600", 12);
        push("i5-13600H", 8);
        push("i5-13600HE", 8);
        push("i5-13600K", 12);
        push("i5-13600K", 20);
        push("i5-13600KF", 12);
        push("i5-13600KF", 20);
        push("i5-13600T", 12);
        push("i5-2300", 4);
        push("i5-2310", 4);
        push("i5-2320", 4);
        push("i5-2380P", 4);
        push("i5-2390T", 4);
        push("i5-2400", 4);
        push("i5-2400S", 4);
        push("i5-2405S", 4);
        push("i5-2410M", 4);
        push("i5-2415M", 4);
        push("i5-2430M", 4);
        push("i5-2435M", 4);
        push("i5-2450M", 4);
        push("i5-2450P", 4);
        push("i5-2467M", 4);
        push("i5-2475M", 4);
        push("i5-2477M", 4);
        push("i5-2487M", 4);
        push("i5-2490M", 4);
        push("i5-2497M", 4);
        push("i5-2500", 4);
        push("i5-2500K", 4);
        push("i5-2500S", 4);
        push("i5-2500T", 4);
        push("i5-2510E", 4);
        push("i5-2515E", 4);
        push("i5-2520M", 4);
        push("i5-2537M", 4);
        push("i5-2540LM", 4);
        push("i5-2540M", 4);
        push("i5-2547M", 4);
        push("i5-2550K", 4);
        push("i5-2557M", 4);
        push("i5-2560LM", 4);
        push("i5-2560M", 4);
        push("i5-2580M", 4);
        push("i5-3210M", 4);
        push("i5-3230M", 4);
        push("i5-3317U", 4);
        push("i5-3320M", 4);
        push("i5-3330", 4);
        push("i5-3330S", 4);
        push("i5-3335S", 4);
        push("i5-3337U", 4);
        push("i5-3339Y", 4);
        push("i5-3340", 4);
        push("i5-3340M", 4);
        push("i5-3340S", 4);
        push("i5-3350P", 4);
        push("i5-3360M", 4);
        push("i5-3380M", 4);
        push("i5-3427U", 4);
        push("i5-3437U", 4);
        push("i5-3439Y", 4);
        push("i5-3450", 4);
        push("i5-3450S", 4);
        push("i5-3470", 4);
        push("i5-3470S", 4);
        push("i5-3470T", 4);
        push("i5-3475S", 4);
        push("i5-3550", 4);
        push("i5-3550S", 4);
        push("i5-3570", 4);
        push("i5-3570K", 4);
        push("i5-3570S", 4);
        push("i5-3570T", 4);
        push("i5-3610ME", 4);
        push("i5-4200H", 4);
        push("i5-4200M", 4);
        push("i5-4200U", 4);
        push("i5-4200Y", 4);
        push("i5-4202Y", 4);
        push("i5-4210H", 4);
        push("i5-4210M", 4);
        push("i5-4210U", 4);
        push("i5-4210Y", 4);
        push("i5-4220Y", 4);
        push("i5-4250U", 4);
        push("i5-4258U", 4);
        push("i5-4260U", 4);
        push("i5-4278U", 4);
        push("i5-4288U", 4);
        push("i5-4300M", 4);
        push("i5-4300U", 4);
        push("i5-4300Y", 4);
        push("i5-4302Y", 4);
        push("i5-4308U", 4);
        push("i5-430M", 4);
        push("i5-430UM", 4);
        push("i5-4310M", 4);
        push("i5-4310U", 4);
        push("i5-4330M", 4);
        push("i5-4340M", 4);
        push("i5-4350U", 4);
        push("i5-4360U", 4);
        push("i5-4400E", 4);
        push("i5-4402E", 4);
        push("i5-4402EC", 4);
        push("i5-4410E", 4);
        push("i5-4422E", 4);
        push("i5-4430", 4);
        push("i5-4430S", 4);
        push("i5-4440", 4);
        push("i5-4440S", 4);
        push("i5-4460", 4);
        push("i5-4460S", 4);
        push("i5-4460T", 4);
        push("i5-4470", 4);
        push("i5-450M", 4);
        push("i5-4570", 4);
        push("i5-4570R", 4);
        push("i5-4570S", 4);
        push("i5-4570T", 4);
        push("i5-4570TE", 4);
        push("i5-4590", 4);
        push("i5-4590S", 4);
        push("i5-4590T", 4);
        push("i5-460M", 4);
        push("i5-4670", 4);
        push("i5-4670K", 4);
        push("i5-4670R", 4);
        push("i5-4670S", 4);
        push("i5-4670T", 4);
        push("i5-4690", 4);
        push("i5-4690K", 4);
        push("i5-4690S", 4);
        push("i5-4690T", 4);
        push("i5-470UM", 4);
        push("i5-480M", 4);
        push("i5-5200U", 4);
        push("i5-520E", 4);
        push("i5-520M", 4);
        push("i5-520UM", 4);
        push("i5-5250U", 4);
        push("i5-5257U", 4);
        push("i5-5287U", 4);
        push("i5-5300U", 4);
        push("i5-5350H", 4);
        push("i5-5350U", 4);
        push("i5-540M", 4);
        push("i5-540UM", 4);
        push("i5-5575R", 4);
        push("i5-560M", 4);
        push("i5-560UM", 4);
        push("i5-5675C", 4);
        push("i5-5675R", 4);
        push("i5-580M", 4);
        push("i5-6198DU", 4);
        push("i5-6200U", 4);
        push("i5-6260U", 4);
        push("i5-6267U", 4);
        push("i5-6287U", 4);
        push("i5-6300HQ", 4);
        push("i5-6300U", 4);
        push("i5-6350HQ", 4);
        push("i5-6360U", 4);
        push("i5-6400", 4);
        push("i5-6400T", 4);
        push("i5-6402P", 4);
        push("i5-6440EQ", 4);
        push("i5-6440HQ", 4);
        push("i5-6442EQ", 4);
        push("i5-650", 4);
        push("i5-6500", 4);
        push("i5-6500T", 4);
        push("i5-6500TE", 4);
        push("i5-655K", 4);
        push("i5-6585R", 4);
        push("i5-660", 4);
        push("i5-6600", 4);
        push("i5-6600K", 4);
        push("i5-6600T", 4);
        push("i5-661", 4);
        push("i5-6685R", 4);
        push("i5-670", 4);
        push("i5-680", 4);
        push("i5-7200U", 4);
        push("i5-7210U", 4);
        push("i5-7260U", 4);
        push("i5-7267U", 4);
        push("i5-7287U", 4);
        push("i5-7300HQ", 4);
        push("i5-7300U", 4);
        push("i5-7360U", 4);
        push("i5-7400", 4);
        push("i5-7400T", 4);
        push("i5-7440EQ", 4);
        push("i5-7440HQ", 4);
        push("i5-7442EQ", 4);
        push("i5-750", 4);
        push("i5-7500", 4);
        push("i5-7500T", 4);
        push("i5-750S", 4);
        push("i5-760", 4);
        push("i5-7600", 4);
        push("i5-7600K", 4);
        push("i5-7600T", 4);
        push("i5-7640X", 4);
        push("i5-7Y54", 4);
        push("i5-7Y57", 4);
        push("i5-8200Y", 4);
        push("i5-8210Y", 4);
        push("i5-8250U", 8);
        push("i5-8257U", 8);
        push("i5-8259U", 8);
        push("i5-8260U", 8);
        push("i5-8265U", 8);
        push("i5-8269U", 8);
        push("i5-8279U", 8);
        push("i5-8300H", 8);
        push("i5-8305G", 8);
        push("i5-8310Y", 4);
        push("i5-8350U", 8);
        push("i5-8365U", 8);
        push("i5-8365UE", 8);
        push("i5-8400", 6);
        push("i5-8400B", 6);
        push("i5-8400H", 8);
        push("i5-8400T", 6);
        push("i5-8420", 6);
        push("i5-8420T", 6);
        push("i5-8500", 6);
        push("i5-8500B", 6);
        push("i5-8500T", 6);
        push("i5-8550", 6);
        push("i5-8600", 6);
        push("i5-8600K", 6);
        push("i5-8600T", 6);
        push("i5-8650", 6);
        push("i5-9300H", 8);
        push("i5-9300HF", 8);
        push("i5-9400", 6);
        push("i5-9400F", 6);
        push("i5-9400H", 8);
        push("i5-9400T", 6);
        push("i5-9500", 6);
        push("i5-9500E", 6);
        push("i5-9500F", 6);
        push("i5-9500T", 6);
        push("i5-9500TE", 6);
        push("i5-9600", 6);
        push("i5-9600K", 6);
        push("i5-9600KF", 6);
        push("i5-9600T", 6);

        // i7 series
        push("i7-10510U", 8);
        push("i7-10510Y", 8);
        push("i7-1060G7", 8);
        push("i7-10610U", 8);
        push("i7-1065G7", 8);
        push("i7-1068G7", 8);
        push("i7-1068NG7", 8);
        push("i7-10700", 16);
        push("i7-10700E", 16);
        push("i7-10700F", 16);
        push("i7-10700K", 16);
        push("i7-10700KF", 16);
        push("i7-10700T", 16);
        push("i7-10700TE", 16);
        push("i7-10710U", 8);
        push("i7-10750H", 12);
        push("i7-10810U", 12);
        push("i7-10850H", 12);
        push("i7-10870H", 16);
        push("i7-10875H", 16);
        push("i7-11370H", 8);
        push("i7-11375H", 8);
        push("i7-11390H", 8);
        push("i7-11600H", 12);
        push("i7-1160G7", 8);
        push("i7-1165G7", 8);
        push("i7-11700", 16);
        push("i7-11700B", 16);
        push("i7-11700F", 16);
        push("i7-11700K", 16);
        push("i7-11700KF", 16);
        push("i7-11700T", 16);
        push("i7-11800H", 16);
        push("i7-1180G7", 8);
        push("i7-11850H", 16);
        push("i7-11850HE", 16);
        push("i7-1185G7", 8);
        push("i7-1185G7E", 8);
        push("i7-1185GRE", 8);
        push("i7-1195G7", 8);
        push("i7-1250U", 4);
        push("i7-1255U", 4);
        push("i7-1260P", 8);
        push("i7-1260U", 4);
        push("i7-1265U", 4);
        push("i7-12700", 16);
        push("i7-12700F", 16);
        push("i7-12700KF", 16);
        push("i7-12700T", 16);
        push("i7-1270P", 8);
        push("i7-1270PE", 8);
        push("i7-1360P", 8);
        push("i7-13700", 16);
        push("i7-13700F", 16);
        push("i7-13700K", 16);
        push("i7-13700KF", 16);
        push("i7-13700T", 16);
        push("i7-13790F", 16);
        push("i7-2535QM", 8);
        push("i7-2570QM", 8);
        push("i7-2600", 8);
        push("i7-2600K", 8);
        push("i7-2600S", 8);
        push("i7-2610UE", 4);
        push("i7-2617M", 4);
        push("i7-2620M", 4);
        push("i7-2627M", 4);
        push("i7-2629M", 4);
        push("i7-2630QM", 8);
        push("i7-2635QM", 8);
        push("i7-2637M", 4);
        push("i7-2640M", 4);
        push("i7-2649M", 4);
        push("i7-2655LE", 4);
        push("i7-2655QM", 8);
        push("i7-2657M", 4);
        push("i7-2660M", 4);
        push("i7-2667M", 4);
        push("i7-2669M", 4);
        push("i7-2670QM", 8);
        push("i7-2675QM", 8);
        push("i7-2677M", 4);
        push("i7-2685QM", 8);
        push("i7-2689M", 4);
        push("i7-2700K", 8);
        push("i7-2710QE", 8);
        push("i7-2715QE", 8);
        push("i7-2720QM", 8);
        push("i7-2740QM", 8);
        push("i7-2760QM", 8);
        push("i7-2820QM", 8);
        push("i7-2840QM", 8);
        push("i7-2860QM", 8);
        push("i7-2920XM", 8);
        push("i7-2960XM", 8);
        push("i7-3517U", 4);
        push("i7-3517UE", 4);
        push("i7-3520M", 4);
        push("i7-3537U", 4);
        push("i7-3540M", 4);
        push("i7-3555LE", 4);
        push("i7-3610QE", 8);
        push("i7-3610QM", 8);
        push("i7-3612QE", 8);
        push("i7-3612QM", 8);
        push("i7-3615QE", 8);
        push("i7-3615QM", 8);
        push("i7-3630QM", 8);
        push("i7-3632QM", 8);
        push("i7-3635QM", 8);
        push("i7-3667U", 4);
        push("i7-3687U", 4);
        push("i7-3689Y", 4);
        push("i7-3720QM", 8);
        push("i7-3740QM", 8);
        push("i7-3770", 8);
        push("i7-3770K", 8);
        push("i7-3770S", 8);
        push("i7-3770T", 8);
        push("i7-3820", 8);
        push("i7-3820QM", 8);
        push("i7-3840QM", 8);
        push("i7-3920XM", 8);
        push("i7-3930K", 12);
        push("i7-3940XM", 8);
        push("i7-3960X", 12);
        push("i7-3970X", 12);
        push("i7-4500U", 4);
        push("i7-4510U", 4);
        push("i7-4550U", 4);
        push("i7-4558U", 4);
        push("i7-4578U", 4);
        push("i7-4600M", 4);
        push("i7-4600U", 4);
        push("i7-4610M", 8);
        push("i7-4610Y", 4);
        push("i7-4650U", 4);
        push("i7-4700EC", 8);
        push("i7-4700EQ", 8);
        push("i7-4700HQ", 8);
        push("i7-4700MQ", 8);
        push("i7-4701EQ", 8);
        push("i7-4702EC", 8);
        push("i7-4702HQ", 8);
        push("i7-4702MQ", 8);
        push("i7-4710HQ", 8);
        push("i7-4710MQ", 8);
        push("i7-4712HQ", 8);
        push("i7-4712MQ", 8);
        push("i7-4720HQ", 8);
        push("i7-4722HQ", 8);
        push("i7-4750HQ", 8);
        push("i7-4760HQ", 8);
        push("i7-4765T", 8);
        push("i7-4770", 8);
        push("i7-4770HQ", 8);
        push("i7-4770K", 8);
        push("i7-4770R", 8);
        push("i7-4770S", 8);
        push("i7-4770T", 8);
        push("i7-4770TE", 8);
        push("i7-4771", 8);
        push("i7-4785T", 8);
        push("i7-4790", 8);
        push("i7-4790K", 8);
        push("i7-4790S", 8);
        push("i7-4790T", 8);
        push("i7-4800MQ", 8);
        push("i7-4810MQ", 8);
        push("i7-4820K", 8);
        push("i7-4850EQ", 8);
        push("i7-4850HQ", 8);
        push("i7-4860EQ", 8);
        push("i7-4860HQ", 8);
        push("i7-4870HQ", 8);
        push("i7-4900MQ", 8);
        push("i7-4910MQ", 8);
        push("i7-4930K", 12);
        push("i7-4930MX", 8);
        push("i7-4940MX", 8);
        push("i7-4950HQ", 8);
        push("i7-4960HQ", 8);
        push("i7-4960X", 12);
        push("i7-4980HQ", 8);
        push("i7-5500U", 4);
        push("i7-5550U", 4);
        push("i7-5557U", 4);
        push("i7-5600U", 4);
        push("i7-5650U", 4);
        push("i7-5700EQ", 8);
        push("i7-5700HQ", 8);
        push("i7-5750HQ", 8);
        push("i7-5775C", 8);
        push("i7-5775R", 8);
        push("i7-5820K", 12);
        push("i7-5850EQ", 8);
        push("i7-5850HQ", 8);
        push("i7-5930K", 12);
        push("i7-5950HQ", 8);
        push("i7-5960X", 16);
        push("i7-610E", 4);
        push("i7-620LE", 4);
        push("i7-620LM", 4);
        push("i7-620M", 4);
        push("i7-620UE", 4);
        push("i7-620UM", 4);
        push("i7-640LM", 4);
        push("i7-640M", 4);
        push("i7-640UM", 4);
        push("i7-6498DU", 4);
        push("i7-6500U", 4);
        push("i7-6560U", 4);
        push("i7-6567U", 4);
        push("i7-6600U", 4);
        push("i7-660LM", 4);
        push("i7-660UE", 4);
        push("i7-660UM", 4);
        push("i7-6650U", 4);
        push("i7-6660U", 4);
        push("i7-6700", 8);
        push("i7-6700HQ", 8);
        push("i7-6700K", 8);
        push("i7-6700T", 8);
        push("i7-6700TE", 8);
        push("i7-6770HQ", 8);
        push("i7-6785R", 8);
        push("i7-6800K", 12);
        push("i7-680UM", 4);
        push("i7-6820EQ", 8);
        push("i7-6820HK", 8);
        push("i7-6820HQ", 8);
        push("i7-6822EQ", 8);
        push("i7-6850K", 12);
        push("i7-6870HQ", 8);
        push("i7-6900K", 16);
        push("i7-6920HQ", 8);
        push("i7-6950X", 20);
        push("i7-6970HQ", 8);
        push("i7-720QM", 8);
        push("i7-740QM", 8);
        push("i7-7500U", 4);
        push("i7-7510U", 4);
        push("i7-7560U", 4);
        push("i7-7567U", 4);
        push("i7-7600U", 4);
        push("i7-7660U", 4);
        push("i7-7700", 8);
        push("i7-7700HQ", 8);
        push("i7-7700K", 8);
        push("i7-7700T", 8);
        push("i7-7740X", 8);
        push("i7-7800X", 12);
        push("i7-7820EQ", 8);
        push("i7-7820HK", 8);
        push("i7-7820HQ", 8);
        push("i7-7820X", 16);
        push("i7-7920HQ", 8);
        push("i7-7Y75", 4);
        push("i7-8086K", 12);
        push("i7-820QM", 8);
        push("i7-840QM", 8);
        push("i7-8500Y", 4);
        push("i7-8550U", 8);
        push("i7-8557U", 8);
        push("i7-8559U", 8);
        push("i7-8565U", 8);
        push("i7-8569U", 8);
        push("i7-860", 8);
        push("i7-860S", 8);
        push("i7-8650U", 8);
        push("i7-8665U", 8);
        push("i7-8665UE", 8);
        push("i7-8670", 12);
        push("i7-8670T", 12);
        push("i7-870", 8);
        push("i7-8700", 12);
        push("i7-8700B", 12);
        push("i7-8700K", 12);
        push("i7-8700T", 12);
        push("i7-8705G", 8);
        push("i7-8706G", 8);
        push("i7-8709G", 8);
        push("i7-870S", 8);
        push("i7-8750H", 12);
        push("i7-875K", 8);
        push("i7-880", 8);
        push("i7-8809G", 8);
        push("i7-8850H", 12);
        push("i7-920", 8);
        push("i7-920XM", 8);
        push("i7-930", 8);
        push("i7-940", 8);
        push("i7-940XM", 8);
        push("i7-950", 8);
        push("i7-960", 8);
        push("i7-965", 8);
        push("i7-970", 12);
        push("i7-9700", 8);
        push("i7-9700E", 8);
        push("i7-9700F", 8);
        push("i7-9700K", 8);
        push("i7-9700KF", 8);
        push("i7-9700T", 8);
        push("i7-9700TE", 8);
        push("i7-975", 8);
        push("i7-9750H", 12);
        push("i7-9750HF", 12);
        push("i7-980", 12);
        push("i7-9800X", 16);
        push("i7-980X", 12);
        push("i7-9850H", 12);
        push("i7-9850HE", 12);
        push("i7-9850HL", 12);
        push("i7-990X", 12);

        // i9 series
        push("i9-10850K", 20);
        push("i9-10885H", 16);
        push("i9-10900", 20);
        push("i9-10900E", 20);
        push("i9-10900F ", 20);
        push("i9-10900K", 20);
        push("i9-10900KF", 20);
        push("i9-10900T", 20);
        push("i9-10900TE", 20);
        push("i9-10900X", 20);
        push("i9-10910", 20);
        push("i9-10920X", 24);
        push("i9-10940X", 28);
        push("i9-10980HK", 16);
        push("i9-10980XE", 36);
        push("i9-11900", 16);
        push("i9-11900F", 16);
        push("i9-11900H", 16);
        push("i9-11900K", 16);
        push("i9-11900KB", 16);
        push("i9-11900KF", 16);
        push("i9-11900T", 16);
        push("i9-11950H", 16);
        push("i9-11980HK", 16);
        push("i9-12900", 16);
        push("i9-12900F", 16);
        push("i9-12900K", 16);
        push("i9-12900KF", 16);
        push("i9-12900KS", 16);
        push("i9-12900T", 16);
        push("i9-13900", 16);
        push("i9-13900E", 16);
        push("i9-13900F", 16);
        push("i9-13900HX", 16);
        push("i9-13900K", 16);
        push("i9-13900KF", 16);
        push("i9-13900KS", 16);
        push("i9-13900T", 16);
        push("i9-13900TE", 16);
        push("i9-13950HX", 16);
        push("i9-13980HX", 16);
        push("i9-14900", 16);
        push("i9-14900F", 16);
        push("i9-14900HX", 16);
        push("i9-14900K", 16);
        push("i9-14900KF", 16);
        push("i9-14900KS", 16);
        push("i9-14900T", 16);
        push("i9-7900X", 20);
        push("i9-7920X", 24);
        push("i9-7940X", 28);
        push("i9-7960X", 32);
        push("i9-7980XE", 36);
        push("i9-8950HK", 12);
        push("i9-9820X", 20);
        push("i9-9880H", 16);
        push("i9-9900", 16);
        push("i9-9900K", 16);
        push("i9-9900KF", 16);
        push("i9-9900KS", 16);
        push("i9-9900T", 16);
        push("i9-9900X", 20);
        push("i9-9920X", 24);
        push("i9-9940X", 28);
        push("i9-9960X", 32);
        push("i9-9980HK", 16);
        push("i9-9980XE", 36);
        push("i9-9990XE", 28);

        // basically means "if there's 0 matches in the database, return false"
        if (thread_database->count(model.string) == 0) {
            return false;
        }

        const u8 threads = thread_database->at(model.string);

        debug("INTEL_THREAD_MISMATCH: thread in database = ", static_cast<u32>(threads));

        return (std::thread::hardware_concurrency() != threads);
#endif
    }
    catch (...) {
        debug("INTEL_THREAD_MISMATCH: caught error, returned false");
        return false;
    }


    /**
     * @brief Check for Intel Xeon CPUs that don't match their thread count
     * @category All, x86
     * @link https://en.wikipedia.org/wiki/List_of_Intel_Core_processors
     */
    [[nodiscard]] static bool xeon_thread_mismatch() try {
#if (!x86)
        return false;
#else
        if (!cpu::is_intel()) {
            return false;
        }

        if (cpu::has_hyperthreading()) {
            return false;
        }

        const cpu::model_struct model = cpu::get_model();

        if (!model.found) {
            return false;
        }

        if (!model.is_xeon) {
            return false;
        }

        debug("XEON_THREAD_MISMATCH: CPU model = ", model.string);

        auto xeon_thread_database = util::make_unique<std::unordered_map<std::string, uint8_t>>();

        auto xeon_push = [&xeon_thread_database](const char* brand_str, const u8 thread_count) -> void {
            xeon_thread_database->emplace(brand_str, thread_count);
            };

        // Xeon D
        xeon_push("D-1518", 8);
        xeon_push("D-1520", 8);
        xeon_push("D-1521", 8);
        xeon_push("D-1527", 8);
        xeon_push("D-1528", 12);
        xeon_push("D-1529", 8);
        xeon_push("D-1531", 12);
        xeon_push("D-1537", 16);
        xeon_push("D-1539", 16);
        xeon_push("D-1540", 16);
        xeon_push("D-1541", 16);
        xeon_push("D-1548", 16);
        xeon_push("D-1557", 24);
        xeon_push("D-1559", 24);
        xeon_push("D-1567", 24);
        xeon_push("D-1571", 32);
        xeon_push("D-1577", 32);
        xeon_push("D-1581", 32);
        xeon_push("D-1587", 32);
        xeon_push("D-1513N", 8);
        xeon_push("D-1523N", 8);
        xeon_push("D-1533N", 12);
        xeon_push("D-1543N", 16);
        xeon_push("D-1553N", 16);
        xeon_push("D-1602", 4);
        xeon_push("D-1612", 8);
        xeon_push("D-1622", 8);
        xeon_push("D-1627", 8);
        xeon_push("D-1632", 16);
        xeon_push("D-1637", 12);
        xeon_push("D-1623N", 8);
        xeon_push("D-1633N", 12);
        xeon_push("D-1649N", 16);
        xeon_push("D-1653N", 16);
        xeon_push("D-2141I", 16);
        xeon_push("D-2161I", 24);
        xeon_push("D-2191", 36);
        xeon_push("D-2123IT", 8);
        xeon_push("D-2142IT", 16);
        xeon_push("D-2143IT", 16);
        xeon_push("D-2163IT", 24);
        xeon_push("D-2173IT", 28);
        xeon_push("D-2183IT", 32);
        xeon_push("D-2145NT", 16);
        xeon_push("D-2146NT", 16);
        xeon_push("D-2166NT", 24);
        xeon_push("D-2177NT", 28);
        xeon_push("D-2187NT", 32);

        // Xeon E
        xeon_push("E-2104G", 4);
        xeon_push("E-2124", 4);
        xeon_push("E-2124G", 4);
        xeon_push("E-2126G", 6);
        xeon_push("E-2134", 8);
        xeon_push("E-2136", 12);
        xeon_push("E-2144G", 8);
        xeon_push("E-2146G", 12);
        xeon_push("E-2174G", 8);
        xeon_push("E-2176G", 12);
        xeon_push("E-2186G", 12);
        xeon_push("E-2176M", 12);
        xeon_push("E-2186M", 12);
        xeon_push("E-2224", 4);
        xeon_push("E-2224G", 4);
        xeon_push("E-2226G", 6);
        xeon_push("E-2234", 8);
        xeon_push("E-2236", 12);
        xeon_push("E-2244G", 8);
        xeon_push("E-2246G", 12);
        xeon_push("E-2274G", 8);
        xeon_push("E-2276G", 12);
        xeon_push("E-2278G", 16);
        xeon_push("E-2286G", 12);
        xeon_push("E-2288G", 16);
        xeon_push("E-2276M", 12);
        xeon_push("E-2286M", 16);

        // Xeon W
        xeon_push("W-2102", 4);
        xeon_push("W-2104", 4);
        xeon_push("W-2123", 8);
        xeon_push("W-2125", 8);
        xeon_push("W-2133", 12);
        xeon_push("W-2135", 12);
        xeon_push("W-2140B", 16);
        xeon_push("W-2145", 16);
        xeon_push("W-2150B", 20);
        xeon_push("W-2155", 20);
        xeon_push("W-2170B", 28);
        xeon_push("W-2175", 28);
        xeon_push("W-2191B", 36);
        xeon_push("W-2195", 36);
        xeon_push("W-3175X", 56);
        xeon_push("W-3223", 16);
        xeon_push("W-3225", 16);
        xeon_push("W-3235", 24);
        xeon_push("W-3245", 32);
        xeon_push("W-3245M", 32);
        xeon_push("W-3265", 48);
        xeon_push("W-3265M", 48);
        xeon_push("W-3275", 56);
        xeon_push("W-3275M", 56);

        if (xeon_thread_database->count(model.string) == 0) {
            return false;
        }

        const u8 threads = xeon_thread_database->at(model.string);

        debug("XEON_THREAD_MISMATCH: thread in database = ", static_cast<u32>(threads));

        return (std::thread::hardware_concurrency() != threads);
#endif
    }
    catch (...) {
        debug("XEON_THREAD_MISMATCH: caught error, returned false");
        return false;
    }


    /**
     * @brief Check for memory regions to detect VM-specific brands
     * @category Windows
     * @author Graham Sutherland
     * @link https://labs.nettitude.com/blog/vm-detection-tricks-part-1-physical-memory-resource-maps/
     */
    [[nodiscard]] static bool nettitude_vm_memory() try {
#if (!MSVC)
        return false;
#else
        typedef LARGE_INTEGER PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;

#pragma pack(push,4)
        typedef struct _CM_PARTIAL_RESOURCE_DESCRIPTOR {
            UCHAR Type;
            UCHAR ShareDisposition;
            USHORT Flags;
            union {
                struct {
                    PHYSICAL_ADDRESS Start;
                    ULONG Length;
                } Generic;
                struct {
                    PHYSICAL_ADDRESS Start;
                    ULONG Length;
                } Port;
                struct {
#if defined(NT_PROCESSOR_GROUPS)
                    USHORT Level;
                    USHORT Group;
#else
                    ULONG Level;
#endif
                    ULONG Vector;
                    KAFFINITY Affinity;
                } Interrupt;
                struct {
                    union {
                        struct {
#if defined(NT_PROCESSOR_GROUPS)
                            USHORT Group;
#else
                            USHORT Reserved;
#endif
                            USHORT MessageCount;
                            ULONG Vector;
                            KAFFINITY Affinity;
                        } Raw;
                        struct {
#if defined(NT_PROCESSOR_GROUPS)
                            USHORT Level;
                            USHORT Group;
#else
                            ULONG Level;
#endif
                            ULONG Vector;
                            KAFFINITY Affinity;
                        } Translated;
                    } DUMMYUNIONNAME;
                } MessageInterrupt;
                struct {
                    PHYSICAL_ADDRESS Start;
                    ULONG Length;
                } Memory;
                struct {
                    ULONG Channel;
                    ULONG Port;
                    ULONG Reserved1;
                } Dma;
                struct {
                    ULONG Channel;
                    ULONG RequestLine;
                    UCHAR TransferWidth;
                    UCHAR Reserved1;
                    UCHAR Reserved2;
                    UCHAR Reserved3;
                } DmaV3;
                struct {
                    ULONG Data[3];
                } DevicePrivate;
                struct {
                    ULONG Start;
                    ULONG Length;
                    ULONG Reserved;
                } BusNumber;
                struct {
                    ULONG DataSize;
                    ULONG Reserved1;
                    ULONG Reserved2;
                } DeviceSpecificData;
                struct {
                    PHYSICAL_ADDRESS Start;
                    ULONG Length40;
                } Memory40;
                struct {
                    PHYSICAL_ADDRESS Start;
                    ULONG Length48;
                } Memory48;
                struct {
                    PHYSICAL_ADDRESS Start;
                    ULONG Length64;
                } Memory64;
                struct {
                    UCHAR Class;
                    UCHAR Type;
                    UCHAR Reserved1;
                    UCHAR Reserved2;
                    ULONG IdLowPart;
                    ULONG IdHighPart;
                } Connection;
            } u;
        } CM_PARTIAL_RESOURCE_DESCRIPTOR, *PCM_PARTIAL_RESOURCE_DESCRIPTOR;
#pragma pack(pop,4)
        typedef enum _INTERFACE_TYPE {
            InterfaceTypeUndefined,
            Internal,
            Isa,
            Eisa,
            MicroChannel,
            TurboChannel,
            PCIBus,
            VMEBus,
            NuBus,
            PCMCIABus,
            CBus,
            MPIBus,
            MPSABus,
            ProcessorInternal,
            InternalPowerBus,
            PNPISABus,
            PNPBus,
            Vmcs,
            ACPIBus,
            MaximumInterfaceType
        } INTERFACE_TYPE, *PINTERFACE_TYPE;
        typedef struct _CM_PARTIAL_RESOURCE_LIST {
            USHORT                         Version;
            USHORT                         Revision;
            ULONG                          Count;
            CM_PARTIAL_RESOURCE_DESCRIPTOR PartialDescriptors[1];
        } CM_PARTIAL_RESOURCE_LIST, *PCM_PARTIAL_RESOURCE_LIST;
        typedef struct _CM_FULL_RESOURCE_DESCRIPTOR {
            INTERFACE_TYPE           InterfaceType;
            ULONG                    BusNumber;
            CM_PARTIAL_RESOURCE_LIST PartialResourceList;
        } *PCM_FULL_RESOURCE_DESCRIPTOR, CM_FULL_RESOURCE_DESCRIPTOR;
        typedef struct _CM_RESOURCE_LIST {
            ULONG                       Count;
            CM_FULL_RESOURCE_DESCRIPTOR List[1];
        } *PCM_RESOURCE_LIST, CM_RESOURCE_LIST;
        struct memory_region {
            ULONG64 size;
            ULONG64 address;
        };
        struct map_key {
            LPTSTR KeyPath;
            LPTSTR ValueName;
        };

        /* registry keys for resource maps */
#define VM_RESOURCE_CHECK_REGKEY_PHYSICAL 0
#define VM_RESOURCE_CHECK_REGKEY_RESERVED 1
#define VM_RESOURCE_CHECK_REGKEY_LOADER_RESERVED 2
#define ResourceRegistryKeysLength 3

        const struct map_key ResourceRegistryKeys[ResourceRegistryKeysLength] = {
            {
                const_cast<LPTSTR>("Hardware\\ResourceMap\\System Resources\\Physical Memory"),
                const_cast<LPTSTR>(".Translated")
            },
            {
                const_cast<LPTSTR>("Hardware\\ResourceMap\\System Resources\\Reserved"),
                const_cast<LPTSTR>(".Translated")
            },
            {
                const_cast<LPTSTR>("Hardware\\ResourceMap\\System Resources\\Loader Reserved"),
                const_cast<LPTSTR>(".Raw")
            }
        };

        /* parse a REG_RESOURCE_LIST value for memory descriptors */
        auto parse_memory_map = [](
            struct memory_region* regions,
            struct map_key key
            ) -> DWORD {
                HKEY hKey = NULL;
                LPTSTR pszSubKey = key.KeyPath;
                LPTSTR pszValueName = key.ValueName;
                LPBYTE lpData = NULL;
                DWORD dwLength = 0, count = 0, type = 0;;
                DWORD result;
                if ((result = RegOpenKeyW(HKEY_LOCAL_MACHINE, reinterpret_cast<LPCWSTR>(pszSubKey), &hKey)) != ERROR_SUCCESS) {
                    debug("NETTITUDE_VM_MEMORY: Could not get reg key: ", result, " / ", GetLastError());
                    return 0;
                }

                if ((result = RegQueryValueExW(hKey, reinterpret_cast<LPCWSTR>(pszValueName), 0, &type, NULL, &dwLength)) != ERROR_SUCCESS) {
                    debug("NETTITUDE_VM_MEMORY: Could not query hardware key: ", result, " / ", GetLastError());
                    return 0;
                }

                lpData = (LPBYTE)malloc(dwLength);
                RegQueryValueEx(hKey, pszValueName, 0, &type, lpData, &dwLength);
                CM_RESOURCE_LIST* resource_list = (CM_RESOURCE_LIST*)lpData;
                for (DWORD i = 0; i < resource_list->Count; i++)
                {
                    for (DWORD j = 0; j < resource_list->List[0].PartialResourceList.Count; j++)
                    {
                        if (resource_list->List[i].PartialResourceList.PartialDescriptors[j].Type == 3)
                        {
                            if (regions != NULL)
                            {
                                regions->address = resource_list->List[i].PartialResourceList.PartialDescriptors[j].u.Memory.Start.QuadPart;
                                regions->size = resource_list->List[i].PartialResourceList.PartialDescriptors[j].u.Memory.Length;
                                regions++;
                            }
                            count++;
                        }
                    }
                }
                return count;
            };

#define VM_RESOURCE_CHECK_ERROR -1
#define VM_RESOURCE_CHECK_NO_VM 0
#define VM_RESOURCE_CHECK_HYPERV 1
#define VM_RESOURCE_CHECK_VBOX 2
#define VM_RESOURCE_CHECK_UNKNOWN_PLATFORM 99

        auto vm_resource_check = [](
            struct memory_region* phys, int phys_count,
            struct memory_region* reserved, int reserved_count,
            struct memory_region* loader_reserved, int loader_reserved_count
            ) -> int {
                const ULONG64 VBOX_PHYS_LO = 0x0000000000001000ULL;
                const ULONG64 VBOX_PHYS_HI = 0x000000000009f000ULL;
                const ULONG64 HYPERV_PHYS_LO = 0x0000000000001000ULL;
                const ULONG64 HYPERV_PHYS_HI = 0x00000000000a0000ULL;

                const ULONG64 RESERVED_ADDR_LOW = 0x0000000000001000ULL;
                const ULONG64 LOADER_RESERVED_ADDR_LOW = 0x0000000000000000ULL;
                if (phys_count <= 0 || reserved_count <= 0 || loader_reserved_count <= 0)
                {
                    return VM_RESOURCE_CHECK_ERROR;
                }
                if (phys == NULL || reserved == NULL || loader_reserved == NULL)
                {
                    return VM_RESOURCE_CHECK_ERROR;
                }

                /* find the reserved address range starting
                RESERVED_ADDR_LOW, and record its end address */
                ULONG64 lowestReservedAddrRangeEnd = 0;
                for (int i = 0; i < reserved_count; i++)
                {
                    if (reserved[i].address == RESERVED_ADDR_LOW)
                    {
                        lowestReservedAddrRangeEnd = reserved[i].address + reserved[i].size;
                        break;
                    }
                }
                if (lowestReservedAddrRangeEnd == 0)
                {
                    /* every system tested had a range starting at RESERVED_ADDR_LOW */
                    /* this is an outlier. error. */
                    return VM_RESOURCE_CHECK_ERROR;
                }

                /* find the loader reserved address range starting
                LOADER_RESERVED_ADDR_LOW, and record its end address */
                ULONG64 lowestLoaderReservedAddrRangeEnd = 0;
                for (int i = 0; i < loader_reserved_count; i++)
                {
                    if (loader_reserved[i].address == LOADER_RESERVED_ADDR_LOW)
                    {
                        lowestLoaderReservedAddrRangeEnd = loader_reserved[i].address + loader_reserved[i].size;
                        break;
                    }
                }
                if (lowestLoaderReservedAddrRangeEnd == 0)
                {
                    /* every system tested had a range starting at LOADER_RESERVED_ADDR_LOW */
                    /* this is an outlier. error. */
                    return VM_RESOURCE_CHECK_ERROR;
                }

                /* check if the end addresses are equal. if not, we haven't detected a VM */
                if (lowestReservedAddrRangeEnd != lowestLoaderReservedAddrRangeEnd)
                {
                    return VM_RESOURCE_CHECK_NO_VM;
                }

                /* now find the type of VM by its known physical memory range */
                for (int i = 0; i < phys_count; i++)
                {
                    if (phys[i].address == HYPERV_PHYS_LO && (phys[i].address + phys[i].size) == HYPERV_PHYS_HI)
                    {
                        /* hyper-v */
                        return VM_RESOURCE_CHECK_HYPERV;
                    }
                    if (phys[i].address == VBOX_PHYS_LO && (phys[i].address + phys[i].size) == VBOX_PHYS_HI)
                    {
                        /* vbox */
                        return VM_RESOURCE_CHECK_VBOX;
                    }
                }
                /* pretty sure it's a VM, but we don't know what type */
                return VM_RESOURCE_CHECK_UNKNOWN_PLATFORM;
            };

        DWORD count;

        struct memory_region* regions[ResourceRegistryKeysLength]{};
        int region_counts[ResourceRegistryKeysLength]{};

        for (int i = 0; i < ResourceRegistryKeysLength; i++)
        {
            debug(
                "NETTITUDE_VM_MEMORY: Reading data from ",
                ResourceRegistryKeys[i].KeyPath,
                "\\",
                ResourceRegistryKeys[i].ValueName
            );

            count = parse_memory_map(NULL, ResourceRegistryKeys[i]);
            if (count == 0)
            {
                debug("NETTITUDE_VM_MEMORY: Could not find memory region, returning 0.");
                return 0;
            }
            regions[i] = (struct memory_region*)malloc(sizeof(struct memory_region) * count);

            count = parse_memory_map(regions[i], ResourceRegistryKeys[i]);
            region_counts[i] = count;
            for (DWORD r = 0; r < count; r++)
            {
                debug(
                    "NETTITUDE_VM_MEMORY: --> Memory region found: ",
                    regions[i][r].address,
                    " - ",
                    regions[i][r].address + regions[i][r].size
                );
            }
        }

        int check_result = vm_resource_check(
            regions[VM_RESOURCE_CHECK_REGKEY_PHYSICAL],
            region_counts[VM_RESOURCE_CHECK_REGKEY_PHYSICAL],
            regions[VM_RESOURCE_CHECK_REGKEY_RESERVED],
            region_counts[VM_RESOURCE_CHECK_REGKEY_RESERVED],
            regions[VM_RESOURCE_CHECK_REGKEY_LOADER_RESERVED],
            region_counts[VM_RESOURCE_CHECK_REGKEY_LOADER_RESERVED]
        );

        switch (check_result)
        {
            // error
        case VM_RESOURCE_CHECK_ERROR:
            debug("NETTITUDE_VM_MEMORY: unknown error, returned false");
            return false;
            break;

            // no VM
        case VM_RESOURCE_CHECK_NO_VM:
            debug("NETTITUDE_VM_MEMORY: no VM detected");
            return false;
            break;

            // Hyper-V
        case VM_RESOURCE_CHECK_HYPERV:
            debug("NETTITUDE_VM_MEMORY: Hyper-V detected");
            return core::add(HYPERV);
            break;

            // VirtualBox
        case VM_RESOURCE_CHECK_VBOX:
            debug("NETTITUDE_VM_MEMORY: Vbox detected");
            return core::add(VBOX);
            break;

            // Unknown brand, but likely VM
        case VM_RESOURCE_CHECK_UNKNOWN_PLATFORM:
            debug("NETTITUDE_VM_MEMORY: unknown brand, but likely VM (returned true)");
            return true;
            break;

        default:
            debug("NETTITUDE_VM_MEMORY: returned false as default case");
            return false;
            break;
        }
#endif
    }
    catch (...) {
        debug("NETTITUDE_VM_MEMORY: caught error, returned false");
        return false;
    }


    /**
     * @brief Check for Hyper-V CPUID technique by checking whether all the bits equate to more than 4000 (not sure how this works if i'm honest)
     * @category x86
     * @author 一半人生
     * @link https://unprotect.it/snippet/vmcpuid/195/
     * @copyright MIT
     */
    [[nodiscard]] static bool hyperv_cpuid() try {
#if (!x86)
        return false;
#else
        /// See: Feature Information Returned in the ECX Register
        union CpuFeaturesEcx {
            u32 all;
            struct {
                u32 sse3 : 1;       //!< [0] Streaming SIMD Extensions 3 (SSE3)
                u32 pclmulqdq : 1;  //!< [1] PCLMULQDQ
                u32 dtes64 : 1;     //!< [2] 64-bit DS Area
                u32 monitor : 1;    //!< [3] MONITOR/WAIT
                u32 ds_cpl : 1;     //!< [4] CPL qualified Debug Store
                u32 vmx : 1;        //!< [5] Virtual Machine Technology
                u32 smx : 1;        //!< [6] Safer Mode Extensions
                u32 est : 1;        //!< [7] Enhanced Intel Speedstep Technology
                u32 tm2 : 1;        //!< [8] Thermal monitor 2
                u32 ssse3 : 1;      //!< [9] Supplemental Streaming SIMD Extensions 3
                u32 cid : 1;        //!< [10] L1 context ID
                u32 sdbg : 1;       //!< [11] IA32_DEBUG_INTERFACE MSR
                u32 fma : 1;        //!< [12] FMA extensions using YMM state
                u32 cx16 : 1;       //!< [13] CMPXCHG16B
                u32 xtpr : 1;       //!< [14] xTPR Update Control
                u32 pdcm : 1;       //!< [15] Performance/Debug capability MSR
                u32 reserved : 1;   //!< [16] Reserved
                u32 pcid : 1;       //!< [17] Process-context identifiers
                u32 dca : 1;        //!< [18] prefetch from a memory mapped device
                u32 sse4_1 : 1;     //!< [19] SSE4.1
                u32 sse4_2 : 1;     //!< [20] SSE4.2
                u32 x2_apic : 1;    //!< [21] x2APIC feature
                u32 movbe : 1;      //!< [22] MOVBE instruction
                u32 popcnt : 1;     //!< [23] POPCNT instruction
                u32 reserved3 : 1;  //!< [24] one-shot operation using a TSC deadline
                u32 aes : 1;        //!< [25] AESNI instruction
                u32 xsave : 1;      //!< [26] XSAVE/XRSTOR feature
                u32 osxsave : 1;    //!< [27] enable XSETBV/XGETBV instructions
                u32 avx : 1;        //!< [28] AVX instruction extensions
                u32 f16c : 1;       //!< [29] 16-bit floating-point conversion
                u32 rdrand : 1;     //!< [30] RDRAND instruction
                u32 not_used : 1;   //!< [31] Always 0 (a.k.a. HypervisorPresent)
            } fields;
        };

        i32 cpu_info[4] = {};
        cpu::cpuid(cpu_info, 0x40000001);
        i32 vid = 0;
        vid = (i32)cpu_info[0];

        if (vid >= 4000) {
            return core::add(HYPERV);
        }

        return false;
#endif
    }
    catch (...) {
        debug("HYPERV_CPUID: caught error, returned false");
        return false;
    }


    /**
     * @brief Check for cuckoo directory using crt and win api directory functions
     * @category Windows
     * @author 一半人生
     * @link https://unprotect.it/snippet/checking-specific-folder-name/196/
     * @copyright MIT
     */
    [[nodiscard]] static bool cuckoo_dir() try {
#if (!MSVC)
        return false;
#else
        // win api
        auto IsDirectory2 = [](std::string& strDirName) -> bool {
            const auto iCode = CreateDirectoryA(strDirName.c_str(), NULL);

            if (ERROR_ALREADY_EXISTS == GetLastError()) {
                return true;
            }

            if (iCode) {
                RemoveDirectoryA(strDirName.c_str());
            }

            return false;
            };

        // win api
        auto IsDirectory1 = [](std::string& strDirName) -> bool {
            const HANDLE hFile = CreateFileA(
                strDirName.c_str(),
                GENERIC_READ,
                0,
                NULL,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                NULL
            );

            if (!hFile || (INVALID_HANDLE_VALUE == hFile)) {
                return false;
            }

            if (hFile) {
                CloseHandle(hFile);
            }

            return true;
            };

        // crt
        auto IsDirectory = [](std::string& strDirName) -> bool {
            if (0 == _access(strDirName.c_str(), 0)) {
                return true;
            }

            return false;
            };

        std::string strDirName = "C:\\Cuckoo";

        if (
            IsDirectory(strDirName) ||
            IsDirectory1(strDirName) ||
            IsDirectory2(strDirName)
            ) {
            return core::add(CUCKOO);
        }

        return false;
#endif
    }
    catch (...) {
        debug("CUCKOO_DIR: caught error, returned false");
        return false;
    }


    /**
     * @brief Check for cuckoo pipe
     * @category Windows
     * @author Thomas Roccia (fr0gger)
     * @link https://unprotect.it/snippet/checking-specific-folder-name/196/
     * @copyright MIT
     */
    [[nodiscard]] static bool cuckoo_pipe() try {
#if (!LINUX)
        return false;
#else
        int fd = open("\\\\.\\pipe\\cuckoo", O_RDONLY);
        bool is_cuckoo = false;

        if (fd >= 0) {
            is_cuckoo = true;
        }

        close(fd);

        if (is_cuckoo) {
            return core::add(CUCKOO);
        }

        return false;
#endif
    }
    catch (...) {
        debug("CUCKOO_PIPE: caught error, returned false");
        return false;
    }




    /**
     * @brief Check for Azure Hyper-V utilisation through hostname regex check
     * @category Windows, Linux
     */
    [[nodiscard]] static bool hyperv_hostname() try {
#if (!(MSVC || LINUX))
        return false;
#else
        std::string hostname = util::get_hostname();

        // most Hyper-V hostnames under Azure have the hostname format of fv-azXXX-XXX where the X is a digit
        std::regex pattern("fv-az\\d+-\\d+");

        if (std::regex_match(hostname, pattern)) {
            return core::add(HYPERV);
        }

        return false;
#endif
    }
    catch (...) {
        debug("HYPERV_HOSTNAME: caught error, returned false");
        return false;
    }


    /**
     * @brief Check for commonly set hostnames by certain VM brands
     * @category Windows, Linux
     * @note Idea from Thomas Roccia (fr0gger)
     * @link https://unprotect.it/technique/detecting-hostname-username/
     * @copyright MIT
     */
    [[nodiscard]] static bool general_hostname() try {
#if (!(MSVC || LINUX))
        return false;
#else
        std::string hostname = util::get_hostname();

        auto cmp = [&](const char* str2) -> bool {
            return (hostname == str2);
            };

        if (
            cmp("Sandbox") ||
            cmp("Maltest") ||
            cmp("Malware") ||
            cmp("malsand") ||
            cmp("ClonePC")
            ) {
            return true;
        }

        if (cmp("Cuckoo")) {
            return core::add(CUCKOO);
        }

        return false;
#endif
    }
    catch (...) {
        debug("GENERAL_HOSTNAME: caught error, returned false");
        return false;
    }


    /**
     * @brief Check for known window resolutions in VMs
     * @category Windows
     * @note Idea from Thomas Roccia (fr0gger)
     * @link https://unprotect.it/technique/checking-screen-resolution/
     * @copyright MIT
     */
    [[nodiscard]] static bool screen_resolution() try {
#if (!MSVC)
        return false;
#else
        RECT desktop;
        const HWND hDesktop = GetDesktopWindow();
        GetWindowRect(hDesktop, &desktop);
        const i32 horiz = desktop.right;
        const i32 verti = desktop.bottom;

        debug("SCREEN_RESOLUTION: horizontal = ", horiz, ", vertical = ", verti);

        if (
            (horiz == 1024 && verti == 768) ||
            (horiz == 800 && verti == 600) ||
            (horiz == 640 && verti == 480)
            ) {
            return true;
        }

        return false;
#endif
    }
    catch (...) {
        debug("SCREEN_RESOLUTION: caught error, returned false");
        return false;
    }


    /**
     * @brief Check if bogus device string would succeed
     * @category Windows
     * @author Huntress Research Team
     * @link https://unprotect.it/technique/buildcommdcbandtimeouta/
     * @copyright MIT
     */
    [[nodiscard]] static bool device_string() try {
    #if (!MSVC)
            return false;
    #else
            DCB dcb = { 0 };
            COMMTIMEOUTS timeouts = { 0 };

            if (BuildCommDCBAndTimeouts("jhl46745fghb", &dcb, &timeouts)) {
                return true;
            }
            else {
                debug("DEVICE_STRING: BuildCommDCBAndTimeouts failed");
                return false;
            }
    #endif
    }
    catch (...) {
        debug("DEVICE_STRING: caught error, returned false");
        return false;
    }

    /**
     * @brief Check for the presence of a mouse device
     * @category Windows
     * @author a0rtega
     * @link https://github.com/a0rtega/pafish/blob/master/pafish/rtt.c
     * @note from pafish project
     * @copyright GPL
     */
    [[nodiscard]] static bool mouse_device() try {
#if (!MSVC)
        return false;
#else
        int res;
        res = GetSystemMetrics(SM_MOUSEPRESENT);
        return (res == 0);
#endif
    }
    catch (...) {
        debug("MOUSE_DEVICE: caught error, returned false");
        return false;
    }












    struct core {
        MSVC_DISABLE_WARNING(PADDING)
            struct technique {
            u8 points;                 // this is the certainty score between 0 and 100
            std::function<bool()> run; // this is the technique function itself
        };
        MSVC_ENABLE_WARNING(PADDING)

            static const std::map<u8, technique> technique_table;

        static std::vector<technique> custom_table;

        static bool cpuid_supported;

        // VM scoreboard table specifically for VM::brand()
        static std::map<const char*, brand_score_t> brand_scoreboard;

        // directly return when adding a brand to the scoreboard for a more succint expression
#if (MSVC)
        __declspec(noalias)
#elif (LINUX)
        [[gnu::const]]
#endif
        static inline bool add(const char* p_brand) noexcept {
            core::brand_scoreboard.at(p_brand)++;
            return true;
        }

        // assert if the flag is enabled, far better expression than typing std::bitset member functions
#if (LINUX && __has_cpp_attribute(gnu::pure))
        [[gnu::pure]]
#endif
        [[nodiscard]] static inline bool is_disabled(const flagset& flags, const u8 flag_bit) noexcept {
            return (!flags.test(flag_bit));
        }

        // same as above but for checking enabled flags
#if (LINUX && __has_cpp_attribute(gnu::pure))
        [[gnu::pure]]
#endif
        [[nodiscard]] static inline bool is_enabled(const flagset& flags, const u8 flag_bit) noexcept {
            return (flags.test(flag_bit));
        }

        [[nodiscard]] static bool is_technique_set(const flagset& flags) {
            for (std::size_t i = technique_begin; i < technique_end; i++) {
                if (flags.test(i)) {
                    return true;
                }
            }

            return false;
        }

        [[nodiscard]] static bool is_non_technique_set(const flagset& flags) {
            for (std::size_t i = non_technique_begin; i < non_technique_end; i++) {
                if (flags.test(i)) {
                    return true;
                }
            }

            return false;
        }

        // manage the flag to handle edgecases
        static void flag_sanitizer(flagset& flags) {
            if (flags.count() == 0) {
                flags |= DEFAULT;
                return;
            }

            if (flags == DEFAULT) {
                return;
            }

            // check if any technique flag is set, which is the "correct" way
            if (core::is_technique_set(flags)) {
                return;
            }

            if (!core::is_non_technique_set(flags)) {
                throw std::invalid_argument("Invalid flag option for function parameter found, either leave it empty or add the VM::DEFAULT flag");
            }

            // at this stage, only non-technique flags are asserted to be set
            if (
                flags.test(EXTREME) ||
                flags.test(NO_MEMO) ||
                flags.test(HIGH_THRESHOLD) ||
                flags.test(ENABLE_HYPERV_HOST) ||
                flags.test(WIN_HYPERV_DEFAULT_MACRO) || // deprecated
                flags.test(MULTIPLE)
                ) {
                flags |= DEFAULT;
            }
        }

        // run every VM detection mechanism in the technique table
        static u16 run_all(const flagset& flags, const bool shortcut = false) {
            u16 points = 0;
            const bool memo_enabled = core::is_disabled(flags, NO_MEMO);

            const u16 threshold_points = (core::is_enabled(flags, HIGH_THRESHOLD) ? maximum_points : 200);

            // for main technique table
            for (const auto& tmp : technique_table) {
                const u8 technique_macro = tmp.first;

                // check if it's disabled
                if (core::is_disabled(flags, technique_macro)) {
                    continue;
                }

                // check if the technique is cached already
                if (memo_enabled && memo::is_cached(technique_macro)) {
                    const memo::data_t data = memo::cache_fetch(technique_macro);

                    if (data.result) {
                        points += data.points;
                    }

                    continue;
                }

                // initialise the technique structure
                technique pair = tmp.second;

                // run the technique
                const bool result = pair.run();

                // accumulate the points if technique detected a VM
                if (result) {
                    points += pair.points;
                }

                /**
                 * for things like VM::detect() and VM::percentage(),
                 * a score of 200+ is guaranteed to be a VM, so
                 * there's no point in running the rest of the techniques
                 */
                if (shortcut && points >= threshold_points) {
                    core_debug("VM::run_all(): returned points early due to shortcut option");
                    return points;
                }

                // store the current technique result to the cache
                if (memo_enabled) {
                    memo::cache_store(technique_macro, result, pair.points);
                }
            }

            // for custom VM techniques
            if (!custom_table.empty()) {
                for (const auto& pair : custom_table) {
                    if (pair.run()) {
                        points += pair.points;
                    }
                }
            }

            return points;
        }

        // check if Hyper-V is running 
        static bool hyperv_default_check(const flagset& flags) {
            if (
                core::is_enabled(flags, ENABLE_HYPERV_HOST) ||
                core::is_enabled(flags, WIN_HYPERV_DEFAULT_MACRO) // deprecated
                ) {
                core_debug("HYPERV_CHECK: returned false through flag check");
                return false;
            }

#if (MSVC)
            const u8 version = util::get_windows_version();

            if (version == 0) {
                return true;
            }

            if (version < 10) {
                core_debug("HYPERV_CHECK: returned false through insufficient windows version (version ", static_cast<u32>(version), ")");
                return false;
            }
#endif
            std::string tmp_brand;

            if (memo::brand::is_cached()) {
                tmp_brand = memo::brand::fetch();
            }
            else {
                tmp_brand = brand();
            }

            const bool result = (
                tmp_brand == HYPERV ||
                tmp_brand == VPC ||
                tmp_brand == "Microsoft Virtual PC/Hyper-V"
                );

            core_debug("HYPERV_CHECK: is Hyper-V brand check = ", result);

            return result;
        }

        /**
         * basically what this entire template fuckery does is manage the
         * variadic arguments being given through the arg_handler function,
         * which could either be a std::bitset<N>, a uint8_t, or a combination
         * of both of them. This will handle both argument types and implement
         * them depending on what their types are. If it's a std::bitset<N>,
         * do the |= operation. If it's a uint8_t, simply .set() that into
         * the flag_collector bitset. That's the gist of it.
         *
         * Also I won't even deny, the majority of this section was 90% generated
         * by chatgpt. Can't be arsed with this C++ templatisation shit.
         */
    private:
        static flagset flag_collector;

        static void flagset_manager(const flagset& flags) {
            flag_collector |= flags;
        }

        static void flag_manager(const enum_flags flag) {
            if (
                (flag == INVALID) ||
                (flag > enum_size)
                ) {
                throw std::invalid_argument("Non-flag or invalid flag provided for VM::detect(), aborting");
            }

            flag_collector.set(flag);
        }

        // Define a base class for different types
        struct TestHandler {
            virtual void handle(const flagset& flags) {
                flagset_manager(flags);
            }

            virtual void handle(const enum_flags flag) {
                flag_manager(flag);
            }
        };

        // Define derived classes for specific type implementations
        struct TestBitsetHandler : public TestHandler {
            void handle(const flagset& flags) override {
                flagset_manager(flags);
            }
        };

        struct TestUint8Handler : public TestHandler {
            void handle(const enum_flags flag) override {
                flag_manager(flag);
            }
        };

        // Define a function to dispatch handling based on type
        template <typename T>
        static void dispatch(const T& value, TestHandler& handler) {
            handler.handle(value);
        }

        // Base case for the recursive handling
        static void handleArgs() {
            // Base case: Do nothing
        }

        // Base case for the recursive handling
        static void handle_disabled_args() {
            // Base case: Do nothing
        }

        // Helper function to check if a given argument is of a specific type
        template <typename T, typename U>
        static bool isType(U&&) {
            return std::is_same<T, typename std::decay<U>::type>::value;
        }

        // Recursive case to handle each argument based on its type
        template <typename First, typename... Rest>
        static void handleArgs(First&& first, Rest&&... rest) {
            TestBitsetHandler bitsetHandler;
            TestUint8Handler uint8Handler;

            if (isType<flagset>(first)) {
                dispatch(first, bitsetHandler);
            }
            else if (isType<enum_flags>(first)) {
                dispatch(first, uint8Handler);
            }
            else {
                const std::string msg =
                    "Arguments must either be a std::bitset<" +
                    std::to_string(static_cast<u32>(enum_size + 1)) +
                    "> such as VM::DEFAULT, or a flag such as VM::RDTSC for example";

                throw std::invalid_argument(msg);
            }

            // Recursively handle the rest of the arguments
            handleArgs(std::forward<Rest>(rest)...);
        }

        // Recursive case to handle each argument based on its type
        template <typename First, typename... Rest>
        static void handle_disabled_args(First&& first, Rest&&... rest) {
            TestUint8Handler uint8Handler;

            if (isType<flagset>(first)) {
                throw std::invalid_argument("Arguments must not contain VM::DEFAULT or VM::ALL, only technique flags are accepted (view the documentation for a full list)");
            }
            else if (isType<enum_flags>(first)) {
                dispatch(first, uint8Handler);
            }
            else {
                throw std::invalid_argument("Arguments must be a technique flag, aborting");
            }

            // Recursively handle the rest of the arguments
            handle_disabled_args(std::forward<Rest>(rest)...);
        }

        template <typename... Args>
        static constexpr bool is_empty() {
            return (sizeof...(Args) == 0);
        }

#if (CPP >= 17)
#define VMAWARE_CONSTEXPR constexpr
#else
#define VMAWARE_CONSTEXPR
#endif

    public:
        // Function template to test variadic arguments
        template <typename... Args>
        static flagset arg_handler(Args&&... args) {
            if VMAWARE_CONSTEXPR (is_empty<Args...>()) {
                return DEFAULT;
            }

            flag_collector.reset();

            handleArgs(std::forward<Args>(args)...);

            core::flag_sanitizer(flag_collector);

            return flag_collector;
        }

        // same as above but for VM::disable which only accepts technique flags
        template <typename... Args>
        static flagset disabled_arg_handler(Args&&... args) {
            flag_collector.reset();

            if VMAWARE_CONSTEXPR (is_empty<Args...>()) {
                throw std::invalid_argument("VM::DISABLE must contain a flag");
            }

            handle_disabled_args(std::forward<Args>(args)...);

            if (core::is_non_technique_set(flag_collector)) {
                throw std::invalid_argument("VM::DISABLE must not contain a non-technique flag, they are disabled by default anyway");
            }

            return flag_collector;
        }
    };


public: // START OF PUBLIC FUNCTIONS
    /**
     * @brief Check for a specific technique based on flag argument
     * @param u8 (flags from VM wrapper)
     * @return bool
     * @link https://github.com/kernelwernel/VMAware/blob/main/docs/documentation.md#vmcheck
     */
    [[nodiscard]] static bool check(const u8 flag_bit
        // clang doesn't support std::source_location for some reason
#if (CPP >= 20 && !CLANG)
        , const std::source_location& loc = std::source_location::current()
#endif
    ) {
        // lambda to manage exceptions
        auto throw_error = [&](const char* text) -> void {
            std::stringstream ss;
#if (CPP >= 20 && !CLANG)
            ss << ", error in " << loc.function_name() << " at " << loc.file_name() << ":" << loc.line() << ")";
#endif
            ss << ". Consult the documentation's flag handler for VM::check()";
            throw std::invalid_argument(std::string(text) + ss.str());
            };

        // check if flag is out of range
        if (flag_bit > enum_size) {
            throw_error("Flag argument must be a valid");
        }

        // check if the bit is a non-technique flag, which shouldn't be allowed
        if (
            (flag_bit == NO_MEMO) ||
            (flag_bit == EXTREME) ||
            (flag_bit == HIGH_THRESHOLD) ||
            (flag_bit == ENABLE_HYPERV_HOST) ||
            (flag_bit == WIN_HYPERV_DEFAULT_MACRO) ||  // deprecated
            (flag_bit == MULTIPLE)
            ) {
            throw_error("Flag argument must be a technique flag and not a settings flag");
        }

#if (CPP >= 23)
        [[assume(flag_bit < technique_end)]];
#endif

        // if the technique is already cached, return the cached value instead
        if (memo::is_cached(flag_bit)) {
            const memo::data_t data = memo::cache_fetch(flag_bit);
            return data.result;
        }

        // check if the flag even exists
        auto it = core::technique_table.find(flag_bit);
        if (it == core::technique_table.end()) {
            throw_error("Flag is not known");
        }

        // initialise and run the technique
        const core::technique& pair = it->second;
        const bool result = pair.run();

#ifdef __VMAWARE_DEBUG__
        total_points += pair.points;
#endif

        // store the technique result in the cache table
        memo::cache_store(flag_bit, result, pair.points);

        return result;
    }


    /**
     * @brief Fetch the VM brand
     * @param any flag combination in VM structure or nothing (VM::MULTIPLE can be added)
     * @return std::string
     * @link https://github.com/kernelwernel/VMAware/blob/main/docs/documentation.md#vmbrand
     */
    template <typename ...Args>
    [[nodiscard]] static std::string brand(Args ...args) {
        flagset flags = core::arg_handler(args...);

        const bool is_multiple = core::is_enabled(flags, MULTIPLE);

        // are all the techiques already run? if not, run all of them to get the necessary info to fetch the brand
        if (!memo::all_present() || core::is_enabled(flags, NO_MEMO)) {
            u16 tmp = core::run_all(flags);
            UNUSED(tmp);
        }

#define brands core::brand_scoreboard

        // this gets annoying really fast 
        //#ifdef __VMAWARE_DEBUG__
        //    for (const auto p : brands) {
        //        core_debug("scoreboard: ", (int)p.second, " : ", p.first);
        //    }
        //#endif

        // check if it's already cached and return that instead
        if (core::is_disabled(flags, NO_MEMO)) {
            if (is_multiple) {
                if (memo::multi_brand::is_cached()) {
                    core_debug("VM::brand(): returned multi brand from cache");
                    return memo::multi_brand::fetch();
                }
            }
            else {
                if (memo::brand::is_cached()) {
                    core_debug("VM::brand(): returned brand from cache");
                    return memo::brand::fetch();
                }
            }
        }

        std::string current_brand = "";
        i32 max = 0;

        // fetch the brand with the highest score
        for (auto it = brands.cbegin(); it != brands.cend(); ++it) {
            const char* brand = it->first;
            const brand_score_t points = it->second;

            if (points > max) {
                current_brand = brand;
                max = points;
            }
        }

        // if no brand had a single point, return "Unknown"
        if (max == 0) {
            return "Unknown";
        }

        // goofy ass C++11 and C++14 linker error workaround
#if (CPP <= 14)
        constexpr const char* TMP_QEMU = "QEMU";
        constexpr const char* TMP_KVM = "KVM";
        constexpr const char* TMP_KVM_HYPERV = "KVM Hyper-V Enlightenment";

        constexpr const char* TMP_VMWARE = "VMware";
        constexpr const char* TMP_EXPRESS = "VMware Express";
        constexpr const char* TMP_ESX = "VMware ESX";
        constexpr const char* TMP_GSX = "VMware GSX";
        constexpr const char* TMP_WORKSTATION = "VMware Workstation";

        constexpr const char* TMP_VPC = "Virtual PC";
        constexpr const char* TMP_HYPERV = "Microsoft Hyper-V";
#else
        constexpr const char* TMP_QEMU = QEMU;
        constexpr const char* TMP_KVM = KVM;
        constexpr const char* TMP_KVM_HYPERV = KVM_HYPERV;

        constexpr const char* TMP_VMWARE = VMWARE;
        constexpr const char* TMP_EXPRESS = VMWARE_EXPRESS;
        constexpr const char* TMP_ESX = VMWARE_ESX;
        constexpr const char* TMP_GSX = VMWARE_GSX;
        constexpr const char* TMP_WORKSTATION = VMWARE_WORKSTATION;

        constexpr const char* TMP_VPC = VPC;
        constexpr const char* TMP_HYPERV = HYPERV;
#endif

        if (
            brands.at(TMP_KVM) > 0 &&
            brands.at(TMP_KVM_HYPERV) > 0
            ) {
            current_brand = TMP_KVM_HYPERV;
        }
        else if (
            brands.at(TMP_QEMU) > 0 &&
            brands.at(TMP_KVM) > 0
            ) {
            current_brand = "QEMU+KVM";
        }
        else if (
            brands.at(TMP_VPC) > 0 &&
            brands.at(TMP_HYPERV) > 0
            ) {
#if (MSVC)
            const u8 version = util::get_windows_version();

            if (
                (version < 10) &&
                (version != 0)
                ) {
                current_brand = TMP_VPC;
            }
            else {
                current_brand = TMP_HYPERV;
            }
#else
            current_brand = "Microsoft Virtual PC/Hyper-V";
#endif
        }
        else if (brands.at(TMP_VMWARE) > 0) {
            if (brands.at(TMP_EXPRESS) > 0) {
                current_brand = TMP_EXPRESS;
            }
            else if (brands.at(TMP_ESX) > 0) {
                current_brand = TMP_ESX;
            }
            else if (brands.at(TMP_GSX) > 0) {
                current_brand = TMP_GSX;
            }
            else if (brands.at(TMP_WORKSTATION) > 0) {
                current_brand = TMP_WORKSTATION;
            }
        }
        else if (is_multiple) {
            std::vector<std::string> potential_brands;

            for (auto it = brands.cbegin(); it != brands.cend(); ++it) {
                const brand_score_t points = it->second;
                const std::string brand = it->first;

                if (points > 0) {
                    potential_brands.push_back(brand);
                }
            }

            std::stringstream ss;
            u8 i = 1;

            ss << potential_brands.front();
            for (; i < potential_brands.size(); i++) {
                ss << " or ";
                ss << potential_brands.at(i);
            }
            current_brand = ss.str();
        }

        if (core::is_disabled(flags, NO_MEMO)) {
            if (is_multiple) {
                core_debug("VM::brand(): cached multiple brand string");
                memo::multi_brand::store(current_brand);
            }
            else {
                core_debug("VM::brand(): cached brand string");
                memo::brand::store(current_brand);
            }
        }

        return current_brand;
    }


    /**
     * @brief Detect if running inside a VM
     * @param any flag combination in VM structure or nothing
     * @return bool
     * @link https://github.com/kernelwernel/VMAware/blob/main/docs/documentation.md#vmdetect
     */
    template <typename ...Args>
    static bool detect(Args ...args) {
        flagset flags = core::arg_handler(args...);

        if (
            core::is_enabled(flags, EXTREME) && \
            core::is_enabled(flags, HIGH_THRESHOLD)
            ) {
            throw std::invalid_argument("VM::EXTREME and VM::HIGH_THRESHOLD should not be set at the same time. Use either options instead of both");
        }

        const u16 points = core::run_all(flags, SHORTCUT);

#if (CPP >= 23)
        [[assume(points < maximum_points)]];
#endif

        bool result = false;

        if (core::is_enabled(flags, EXTREME)) {
            result = (points > 0);
        }
        else if (core::is_enabled(flags, HIGH_THRESHOLD)) {
            result = (points > high_threshold_score);
        }
        else {
            result = (points >= 100);
        }

        if (core::hyperv_default_check(flags)) {
            core_debug("VM::detect(): returned false due to Hyper-V default check");
            return false;
        }

        return result;
    }


    /**
     * @brief Get the percentage of how likely it's a VM
     * @param any flag combination in VM structure or nothing
     * @return std::uint8_t
     * @link https://github.com/kernelwernel/VMAware/blob/main/docs/documentation.md#vmpercentage
     */
    template <typename ...Args>
    static u8 percentage(Args ...args) {
        flagset flags = core::arg_handler(args...);

        if (
            core::is_enabled(flags, EXTREME) && \
            core::is_enabled(flags, HIGH_THRESHOLD)
            ) {
            throw std::invalid_argument("VM::EXTREME and VM::HIGH_THRESHOLD should not be set at the same time. Use either options instead of both");
        }

        const u16 points = core::run_all(flags, SHORTCUT);
        u8 percent = 0;

#if (CPP >= 23)
        [[assume(points < maximum_points)]];
#endif

        u16 threshold = 200;

        if (core::is_enabled(flags, HIGH_THRESHOLD)) {
            threshold = high_threshold_score;
        }

        if (core::is_enabled(flags, EXTREME)) {
            threshold = 0;
        }

        if (points >= threshold) {
            percent = 100;
        }
        else if (points >= 100) {
            percent = 99;
        }
        else {
            percent = static_cast<u8>(points);
        }

        if (core::hyperv_default_check(flags)) {
            core_debug("VM::percentage(): returned 0 due to Hyper-V default check");
            return 0;
        }

        return percent;
    }


    /**
     * @brief Add a custom technique to the VM detection technique collection
     * @param either a function pointer, lambda function, or std::function<bool()>
     * @link https://github.com/kernelwernel/VMAware/blob/main/docs/documentation.md#vmaddcustom
     * @return void
     */
    static void add_custom(
        const std::uint8_t percent,
        std::function<bool()> detection_func
        // clang doesn't support std::source_location for some reason
#if (CPP >= 20 && !CLANG)
        , const std::source_location& loc = std::source_location::current()
#endif
    ) {
        auto throw_error = [&](const char* text) -> void {
            std::stringstream ss;
#if (CPP >= 20 && !CLANG)
            ss << ", error in " << loc.function_name() << " at " << loc.file_name() << ":" << loc.line() << ")";
#endif
            ss << ". Consult the documentation's parameters for VM::add_custom()";
            throw std::invalid_argument(std::string(text) + ss.str());
            };

        if (percent > 100) {
            throw_error("Percentage parameter must be between 0 and 100");
        }

#if (CPP >= 23)
        [[assume(percent > 0 && percent <= 100)]];
#endif

        core::technique query{
            percent,
            detection_func
        };

        core::custom_table.emplace_back(query);
    }


    /**
     * @brief disable the provided technique flags so they are not counted to the overall result
     * @param technique flag(s) only
     * @link https://github.com/kernelwernel/VMAware/blob/main/docs/documentation.md#vmdetect
     * @return flagset
     */
    template <typename ...Args>
    static flagset DISABLE(Args ...args) {
        flagset flags = core::disabled_arg_handler(args...);

        flags.flip();
        flags.set(NO_MEMO, 0);
        flags.set(EXTREME, 0);
        flags.set(HIGH_THRESHOLD, 0);
        flags.set(ENABLE_HYPERV_HOST, 0);
        flags.set(WIN_HYPERV_DEFAULT_MACRO, 0); // deprecated
        flags.set(MULTIPLE, 0);

        return flags;
    }
    };

MSVC_ENABLE_WARNING(ASSIGNMENT_OPERATOR NO_INLINE_FUNC SPECTRE)


// ============= EXTERNAL DEFINITIONS =============
// These are added here due to warnings related to C++17 inline variables for C++ standards that are under 17.
// It's easier to just group them together rather than having C++17<= preprocessors with inline stuff


// scoreboard list of brands, if a VM detection technique detects a brand, that will be incremented here as a single point.
std::map<const char*, VM::brand_score_t> VM::core::brand_scoreboard {
    { VM::VBOX, 0 },
    { VM::VMWARE, 0 },
    { VM::VMWARE_EXPRESS, 0 },
    { VM::VMWARE_ESX, 0 },
    { VM::VMWARE_GSX, 0 },
    { VM::VMWARE_WORKSTATION, 0 },
    { VM::BHYVE, 0 },
    { VM::QEMU, 0 },
    { VM::KVM, 0 },
    { VM::KVM_HYPERV, 0 },
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
    { VM::THREADEXPERT, 0 },
    { VM::CWSANDBOX, 0 },
    { VM::COMODO, 0 },
    { VM::BOCHS, 0 },
    { VM::NVMM, 0},
    { VM::BSD_VMM, 0 },
    { VM::INTEL_HAXM, 0 },
    { VM::UNISYS, 0 },
    { VM::LMHS, 0 },
    { VM::CUCKOO, 0 }
};


// initial definitions for cache items
std::map<VM::u8, VM::memo::data_t> VM::memo::cache_table;
VM::flagset VM::memo::cache_keys = 0;
std::string VM::memo::brand::brand_cache = "";
std::string VM::memo::multi_brand::brand_cache = "";
std::string VM::memo::cpu_brand::brand_cache = "";
#ifdef __VMAWARE_DEBUG__
VM::u16 VM::total_points = 0;
#endif

// not even sure how to explain honestly, just pretend this doesn't exist idfk
VM::flagset VM::core::flag_collector;


// default flags 
VM::flagset VM::DEFAULT = []() -> flagset {
    flagset tmp;

    // set all bits to 1
    tmp.set();

    // disable all the non-default flags
    tmp.flip(EXTREME);
    tmp.flip(NO_MEMO);
    tmp.flip(CURSOR);
    tmp.flip(HIGH_THRESHOLD);
    tmp.flip(ENABLE_HYPERV_HOST);
    tmp.flip(WIN_HYPERV_DEFAULT_MACRO); // deprecated
    tmp.flip(MULTIPLE);

    return tmp;
    }();


// flag to enable every technique, basically VM::DEFAULT but with VM::CURSOR technique
VM::flagset VM::ALL = []() -> flagset {
    flagset tmp = DEFAULT;
    tmp.set(CURSOR);
    return tmp;
    }();


std::vector<VM::u8> VM::technique_vector = []() -> std::vector<VM::u8> {
    std::vector<VM::u8> tmp{};

    // all the techniques have a macro value starting from 0 to ~90, hence why it's a classic loop
    for (u8 i = VM::technique_begin; i < VM::technique_end; i++) {
        tmp.push_back(i);
    }

    return tmp;
    }();


// check if cpuid is supported
bool VM::core::cpuid_supported = []() -> bool {
#if (x86)
#if (MSVC)
    int32_t info[4];
    __cpuid(info, 0);
    return (info[0] > 0);
#elif (LINUX)
    u32 ext = 0;
    return (__get_cpuid_max(ext, nullptr) > 0);
#else
    return false;
#endif
#else
    return false;
#endif
    }();


// this is initialised as empty, because this is where custom techniques can be added at runtime 
std::vector<VM::core::technique> VM::core::custom_table = {

};


// the 0~100 points are debatable, but I think it's fine how it is. Feel free to disagree.
const std::map<VM::u8, VM::core::technique> VM::core::technique_table = {
    { VM::VMID, { 100, VM::vmid }},
    { VM::CPU_BRAND, { 50, VM::cpu_brand }},
    { VM::HYPERVISOR_BIT, { 100, VM::hypervisor_bit }},
    { VM::CPUID_0X4, { 70, VM::cpuid_0x4 }},
    { VM::HYPERVISOR_STR, { 45, VM::hypervisor_brand }},
    { VM::RDTSC, { 10, VM::rdtsc_check }},
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
    { VM::CURSOR, { 5, VM::cursor_check }},
    { VM::VMWARE_REG, { 65, VM::vmware_registry }},
    { VM::VBOX_REG, { 65, VM::vbox_registry }},
    { VM::USER, { 35, VM::user_check }},
    { VM::DLL, { 50, VM::DLL_check }},
    { VM::REGISTRY, { 75, VM::registry_key }},
    { VM::CWSANDBOX_VM, { 10, VM::cwsandbox_check }},
    { VM::VM_FILES, { 60, VM::vm_files }},
    { VM::HWMODEL, { 75, VM::hwmodel }},
    { VM::DISK_SIZE, { 60, VM::disk_size }},
    { VM::VBOX_DEFAULT, { 55, VM::vbox_default_specs }},
    { VM::VBOX_NETWORK, { 70, VM::vbox_network_share }},
    { VM::WINE_CHECK, { 85, VM::wine }},                     // GPL
    { VM::COMPUTER_NAME, { 15, VM::computer_name_match }},   // GPL
    { VM::HOSTNAME, { 25, VM::hostname_match }},             // GPL
    { VM::MEMORY, { 35, VM::low_memory_space }},             // GPL
    { VM::VBOX_WINDOW_CLASS, { 10, VM::vbox_window_class }}, // GPL
    { VM::KVM_REG, { 75, VM::kvm_registry }},                // GPL
    { VM::KVM_DRIVERS, { 55, VM::kvm_drivers }},             // GPL
    { VM::KVM_DIRS, { 55, VM::kvm_directories }},            // GPL
    { VM::LOADED_DLLS, { 75, VM::loaded_dlls }},             // GPL
    { VM::AUDIO, { 35, VM::check_audio }},                   // GPL
    { VM::QEMU_DIR, { 45, VM::qemu_dir }},                   // GPL
    { VM::VMWARE_DEVICES, { 60, VM::vmware_devices }},       // GPL
    { VM::MOUSE_DEVICE, { 20, VM::mouse_device }},           // GPL
    { VM::VM_PROCESSES, { 30, VM::vm_processes }},
    { VM::LINUX_USER_HOST, { 25, VM::linux_user_host }},
    { VM::GAMARUE, { 40, VM::gamarue }},
    { VM::VMID_0X4, { 90, VM::vmid_0x4 }},
    { VM::PARALLELS_VM, { 50, VM::parallels }},
    { VM::RDTSC_VMEXIT, { 25, VM::rdtsc_vmexit }},
    { VM::QEMU_BRAND, { 100, VM::cpu_brand_qemu }},
    { VM::BOCHS_CPU, { 95, VM::bochs_cpu }},
    { VM::VPC_BOARD, { 20, VM::vpc_board }},
    { VM::HYPERV_WMI, { 80, VM::hyperv_wmi }},
    { VM::HYPERV_REG, { 80, VM::hyperv_registry }},
    { VM::BIOS_SERIAL, { 60, VM::bios_serial }},
    { VM::VBOX_FOLDERS, { 45, VM::vbox_shared_folders }},
    { VM::MSSMBIOS, { 75, VM::mssmbios }},
    { VM::MAC_MEMSIZE, { 30, VM::hw_memsize }},
    { VM::MAC_IOKIT, { 80, VM::io_kit }},
    { VM::IOREG_GREP, { 75, VM::ioreg_grep }},
    { VM::MAC_SIP, { 85, VM::mac_sip }},
    { VM::HKLM_REGISTRIES, { 70, VM::hklm_registries }},
    { VM::QEMU_GA, { 20, VM::qemu_ga }},
    { VM::VALID_MSR, { 35, VM::valid_msr }},
    { VM::QEMU_PROC, { 30, VM::qemu_processes }},
    { VM::VPC_PROC, { 30, VM::vpc_proc }},
    { VM::VPC_INVALID, { 75, VM::vpc_invalid }},
    { VM::SIDT, { 30, VM::sidt }},
    { VM::SGDT, { 30, VM::sgdt }},
    { VM::SLDT, { 15, VM::sldt }},
    { VM::OFFSEC_SIDT, { 60, VM::offsec_sidt }},
    { VM::OFFSEC_SGDT, { 60, VM::offsec_sgdt }},
    { VM::OFFSEC_SLDT, { 20, VM::offsec_sldt }},
    { VM::VPC_SIDT, { 15, VM::vpc_sidt }},
    { VM::HYPERV_BOARD, { 45, VM::hyperv_board }},
    { VM::VM_FILES_EXTRA, { 70, VM::vm_files_extra }},
    { VM::VMWARE_IOMEM, { 65, VM::vmware_iomem }},
    { VM::VMWARE_IOPORTS, { 70, VM::vmware_ioports }},
    { VM::VMWARE_SCSI, { 40, VM::vmware_scsi }},
    { VM::VMWARE_DMESG, { 65, VM::vmware_dmesg }},
    { VM::VMWARE_STR, { 35, VM::vmware_str }},
    { VM::VMWARE_BACKDOOR, { 100, VM::vmware_backdoor }},
    { VM::VMWARE_PORT_MEM, { 85, VM::vmware_port_memory }},
    { VM::SMSW, { 30, VM::smsw }},
    { VM::MUTEX, { 85, VM::mutex }},
    { VM::UPTIME, { 10, VM::uptime }},
    { VM::ODD_CPU_THREADS, { 80, VM::odd_cpu_threads }},
    { VM::INTEL_THREAD_MISMATCH, { 85, VM::intel_thread_mismatch }},
    { VM::XEON_THREAD_MISMATCH, { 85, VM::xeon_thread_mismatch }},
    { VM::NETTITUDE_VM_MEMORY, { 75, VM::nettitude_vm_memory }},
    { VM::HYPERV_CPUID, { 35, VM::hyperv_cpuid }},
    { VM::CUCKOO_DIR, { 15, VM::cuckoo_dir }},
    { VM::CUCKOO_PIPE, { 20, VM::cuckoo_pipe }},
    { VM::HYPERV_HOSTNAME, { 50, VM::hyperv_hostname }},
    { VM::GENERAL_HOSTNAME, { 20, VM::general_hostname }},
    { VM::SCREEN_RESOLUTION, { 30, VM::screen_resolution }},
    { VM::DEVICE_STRING, { 25, VM::device_string }},

    // __TABLE_LABEL, add your technique above
    // { VM::FUNCTION, { POINTS, FUNCTION_POINTER }}
    // ^ template 
};
