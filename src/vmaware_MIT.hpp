/**
 * ██╗   ██╗███╗   ███╗ █████╗ ██╗    ██╗ █████╗ ██████╗ ███████╗
 * ██║   ██║████╗ ████║██╔══██╗██║    ██║██╔══██╗██╔══██╗██╔════╝
 * ██║   ██║██╔████╔██║███████║██║ █╗ ██║███████║██████╔╝█████╗
 * ╚██╗ ██╔╝██║╚██╔╝██║██╔══██║██║███╗██║██╔══██║██╔══██╗██╔══╝
 *  ╚████╔╝ ██║ ╚═╝ ██║██║  ██║╚███╔███╔╝██║  ██║██║  ██║███████╗
 *   ╚═══╝  ╚═╝     ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ 2.0 (January 2025)
 *
 *  C++ VM detection library
 *
 *  - Made by: kernelwernel (https://github.com/kernelwernel)
 *  - Co-maintained by: Requiem (https://github.com/NotRequiem)
 *  - Contributed by:
 *      - Alex (https://github.com/greenozon)
 *      - Marek Knápek (https://github.com/MarekKnapek)
 *      - Vladyslav Miachkov (https://github.com/fameowner99)
 *      - Alan Tse (https://github.com/alandtse)
 *      - Georgii Gennadev (https://github.com/D00Movenok)
 *      - utoshu (https://github.com/utoshu)
 *  - Repository: https://github.com/kernelwernel/VMAware
 *  - Docs: https://github.com/kernelwernel/VMAware/docs/documentation.md
 *  - Full credits: https://github.com/kernelwernel/VMAware#credits-and-contributors-%EF%B8%8F
 *  - License: MIT
 * 
 *                               MIT License
 *  
 *  Copyright (c) 2024 kernelwernel
 *  
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *  
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *  
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 *
 *
 * ================================ SECTIONS ==================================
 * - enums for publicly accessible techniques  => line 348
 * - struct for internal cpu operations        => line 621
 * - struct for internal memoization           => line 1081
 * - struct for internal utility functions     => line 1464
 * - struct for internal core components       => line 9200
 * - start of internal VM detection techniques => line 2941
 * - start of public VM detection functions    => line 9598
 * - start of externally defined variables     => line 10469
 *
 *
 * ================================ EXAMPLE ==================================
 * #include "vmaware.hpp"
 * #include <iostream>
 * 
 * int main() {
 *     if (VM::detect()) {
 *         std::cout << "Virtual machine detected!" << "\n";
 *     } else {
 *         std::cout << "Running on baremetal" << "\n";
 *     }
 * 
 *     std::cout << "VM name: " << VM::brand() << "\n";
 *     std::cout << "VM type: " << VM::type() << "\n";
 *     std::cout << "VM certainty: " << (int)VM::percentage() << "%" << "\n";
 * }
 */

#pragma once

#if defined(_WIN32) || defined(_WIN64)
#define WINDOWS 1
#define LINUX 0
#define APPLE 0
#elif (defined(__linux__))
#define WINDOWS 0
#define LINUX 1
#define APPLE 0
#elif (defined(__APPLE__) || defined(__APPLE_CPP__) || defined(__MACH__) || defined(__DARWIN))
#define WINDOWS 0
#define LINUX 0
#define APPLE 1
#else
#define WINDOWS 0
#define LINUX 0
#define APPLE 0
#endif

#ifdef _MSC_VER
#define MSVC 1
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

#if (CPP < 11 && !WINDOWS)
#error "VMAware only supports C++11 or above, set your compiler flag to '-std=c++20' for gcc/clang, or '/std:c++20' for MSVC"
#endif

// unused for now, maybe in the future idk
#if (WINVER == 0x0501) // Windows XP, (0x0701 for Windows 7)
#define WIN_XP 1
#else 
#define WIN_XP 0
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

#if !(defined(WINDOWS) || defined(LINUX) || defined(APPLE))
#warning "Unknown OS detected, tests will be severely limited"
#endif

#ifdef _MSC_VER
#pragma warning(push) // Save current warning state and disable all warnings for external header files
#pragma warning(disable : 4820)
#pragma warning(disable : 4365)
#pragma warning(disable : 4668)
#pragma warning(disable : 5204)
#pragma warning(disable : 5039)
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

#if (WINDOWS)
#include <windows.h>
#include <intrin.h>
#include <tchar.h>
#include <stdbool.h>
#include <stdio.h>
#include <iphlpapi.h>
#include <assert.h>
#include <excpt.h>
#include <winternl.h>
#include <winnetwk.h>
#include <winuser.h>
#include <psapi.h>
#include <comdef.h>
#include <wbemidl.h>
#include <shlwapi.h>
#include <shlobj_core.h>
#include <strmif.h>
#include <dshow.h>
#include <io.h>
#include <winspool.h>
#include <wtypes.h>
#include <winevt.h>
#include <powerbase.h>
#include <setupapi.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "MPR")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "strmiids.lib")
#pragma comment(lib, "uuid.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "powrprof.lib")

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

#ifdef _MSC_VER
#pragma warning(pop)  // Restore external header file warnings
#endif

#if (!WINDOWS)
#define TCHAR char
#endif

#ifdef _UNICODE
#define tregex std::wregex
#else
#define tregex std::regex
#endif

// macro shortcut to disable MSVC warnings
#if (WINDOWS)
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
        VMWARE_REG,
        VBOX_REG,
        USER,
        DLL,
        REGISTRY,
        VM_FILES,
        HWMODEL,
        DISK_SIZE,
        VBOX_DEFAULT,
        VBOX_NETWORK,
        VM_PROCESSES,
        LINUX_USER_HOST,
        GAMARUE,
        VMID_0X4,
        PARALLELS_VM,
        QEMU_BRAND,
        BOCHS_CPU,
        VPC_BOARD,
        HYPERV_WMI,
        HYPERV_REG,
        BIOS_SERIAL,
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
        CPUID_BITSET,
        CUCKOO_DIR,
        CUCKOO_PIPE,
        HYPERV_HOSTNAME,
        GENERAL_HOSTNAME,
        SCREEN_RESOLUTION,
        DEVICE_STRING,
        BLUESTACKS_FOLDERS,
        CPUID_SIGNATURE,
        HYPERV_BITMASK,
        KVM_BITMASK,
        KGT_SIGNATURE,
        VMWARE_DMI,
        HYPERV_EVENT_LOGS,
        VMWARE_EVENT_LOGS,
        QEMU_VIRTUAL_DMI,
        QEMU_USB,
        HYPERVISOR_DIR,
        UML_CPU,
        KMSG,
        VM_PROCS,
        VBOX_MODULE,
        SYSINFO_PROC,
        DEVICE_TREE,
        DMI_SCAN,
        SMBIOS_VM_BIT,
        PODMAN_FILE,
        WSL_PROC,
        GPU_CHIPTYPE,
        DRIVER_NAMES,
        VM_SIDT,
        HDD_SERIAL,
        PORT_CONNECTORS,
        VM_HDD,
        ACPI_DETECT,
        GPU_NAME,
        VMWARE_DEVICES,
        VMWARE_MEMORY,
        IDT_GDT_MISMATCH,
        PROCESSOR_NUMBER,
        NUMBER_OF_CORES,
        WMI_MODEL,
        WMI_MANUFACTURER,
        WMI_TEMPERATURE,
        PROCESSOR_ID,
        CPU_FANS,
        VMWARE_HARDENER,
        WMI_QUERIES,
        SYS_QEMU,
        LSHW_QEMU,
        // ADD NEW TECHNIQUE ENUM NAME HERE

        // start of settings technique flags (THE ORDERING IS VERY SPECIFIC HERE AND MIGHT BREAK SOMETHING IF RE-ORDERED)
        NO_MEMO,
        HIGH_THRESHOLD,
        DYNAMIC,
        NULL_ARG, // does nothing, just a placeholder flag mainly for the CLI
        MULTIPLE
    };

private:
    static constexpr u8 enum_size = MULTIPLE; // get enum size through value of last element
    static constexpr u8 settings_count = MULTIPLE - NO_MEMO + 1; // get number of settings technique flags like VM::NO_MEMO for example
    static constexpr u8 INVALID = 255; // explicit invalid technique macro
    static constexpr u16 base_technique_count = NO_MEMO; // original technique count, constant on purpose (can also be used as a base count value if custom techniques are added)
    static constexpr u16 maximum_points = 4765; // theoretical total points if all VM detections returned true (which is practically impossible)
    static constexpr u16 high_threshold_score = 300; // new threshold score from 100 to 350 if VM::HIGH_THRESHOLD flag is enabled
    static constexpr bool SHORTCUT = true; // macro for whether VM::core::run_all() should take a shortcut by skipping the rest of the techniques if the threshold score is already met


    // intended for loop indexes
    static constexpr u8 enum_begin = 0;
    static constexpr u8 enum_end = enum_size + 1;
    static constexpr u8 technique_begin = enum_begin;
    static constexpr u8 technique_end = NO_MEMO;
    static constexpr u8 settings_begin = NO_MEMO;
    static constexpr u8 settings_end = enum_end;


    // this is specifically meant for VM::detected_count() to 
    // get the total number of techniques that detected a VM
    static u8 detected_count_num; 

private:

#if (WINDOWS)
    using brand_score_t = i32;
#else
    using brand_score_t = u8;
#endif

    // for the flag bitset structure
    using flagset = std::bitset<enum_size + 1>;

public:
    // this will allow the enum to be used in the public interface as "VM::TECHNIQUE"
    enum enum_flags tmp_ignore_this = NO_MEMO;

    // constructor stuff ignore this
    VM() = delete;
    VM(const VM&) = delete;
    VM(VM&&) = delete;

    static flagset DEFAULT; // default bitset that will be run if no parameters are specified
    static flagset ALL; // same as default, but with disabled techniques included

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
    struct brands {
        static constexpr const char* VBOX = "VirtualBox";
        static constexpr const char* VMWARE = "VMware";
        static constexpr const char* VMWARE_EXPRESS = "VMware Express";
        static constexpr const char* VMWARE_ESX = "VMware ESX";
        static constexpr const char* VMWARE_GSX = "VMware GSX";
        static constexpr const char* VMWARE_WORKSTATION = "VMware Workstation";
        static constexpr const char* VMWARE_FUSION = "VMware Fusion";
        static constexpr const char* VMWARE_HARD = "VMware (with VmwareHardenedLoader)";
        static constexpr const char* BHYVE = "bhyve";
        static constexpr const char* KVM = "KVM";
        static constexpr const char* QEMU = "QEMU";
        static constexpr const char* QEMU_KVM = "QEMU+KVM";
        static constexpr const char* KVM_HYPERV = "KVM Hyper-V Enlightenment";
        static constexpr const char* QEMU_KVM_HYPERV = "QEMU+KVM Hyper-V Enlightenment";
        static constexpr const char* HYPERV = "Microsoft Hyper-V";
        static constexpr const char* HYPERV_VPC = "Microsoft Virtual PC/Hyper-V";
        static constexpr const char* MSXTA = "Microsoft x86-to-ARM";
        static constexpr const char* PARALLELS = "Parallels";
        static constexpr const char* XEN = "Xen HVM";
        static constexpr const char* ACRN = "ACRN";
        static constexpr const char* QNX = "QNX hypervisor";
        static constexpr const char* HYBRID = "Hybrid Analysis";
        static constexpr const char* SANDBOXIE = "Sandboxie";
        static constexpr const char* DOCKER = "Docker";
        static constexpr const char* WINE = "Wine";
        static constexpr const char* APPLE_ROSETTA = "Apple Rosetta 2";
        static constexpr const char* VPC = "Virtual PC";
        static constexpr const char* ANUBIS = "Anubis";
        static constexpr const char* JOEBOX = "JoeBox";
        static constexpr const char* THREATEXPERT = "ThreatExpert";
        static constexpr const char* CWSANDBOX = "CWSandbox";
        static constexpr const char* COMODO = "Comodo";
        static constexpr const char* BOCHS = "Bochs";
        static constexpr const char* NVMM = "NetBSD NVMM";
        static constexpr const char* BSD_VMM = "OpenBSD VMM";
        static constexpr const char* INTEL_HAXM = "Intel HAXM";
        static constexpr const char* UNISYS = "Unisys s-Par";
        static constexpr const char* LMHS = "Lockheed Martin LMHS"; // lol
        static constexpr const char* CUCKOO = "Cuckoo";
        static constexpr const char* BLUESTACKS = "BlueStacks";
        static constexpr const char* JAILHOUSE = "Jailhouse";
        static constexpr const char* APPLE_VZ = "Apple VZ";
        static constexpr const char* INTEL_KGT = "Intel KGT (Trusty)";
        static constexpr const char* AZURE_HYPERV = "Microsoft Azure Hyper-V";
        static constexpr const char* NANOVISOR = "Xbox NanoVisor (Hyper-V)";
        static constexpr const char* SIMPLEVISOR = "SimpleVisor";
        static constexpr const char* HYPERV_ARTIFACT = "Hyper-V artifact (not an actual VM)";
        static constexpr const char* UML = "User-mode Linux";
        static constexpr const char* POWERVM = "IBM PowerVM";
        static constexpr const char* GCE = "Google Compute Engine (KVM)";
        static constexpr const char* OPENSTACK = "OpenStack (KVM)";
        static constexpr const char* KUBEVIRT = "KubeVirt (KVM)";
        static constexpr const char* AWS_NITRO = "AWS Nitro System EC2 (KVM-based)";
        static constexpr const char* PODMAN = "Podman";
        static constexpr const char* WSL = "WSL";
        static constexpr const char* OPENVZ = "OpenVZ";
        static constexpr const char* BAREVISOR = "Barevisor";
        static constexpr const char* HYPERPLATFORM = "HyperPlatform";
        static constexpr const char* MINIVISOR = "MiniVisor";
        static constexpr const char* NULL_BRAND = "Unknown";
    };


    // macro for bypassing unused parameter/variable warnings
    #define UNUSED(x) ((void)(x))

// likely and unlikely macros
#if (LINUX)
#   define VMAWARE_UNLIKELY(x) __builtin_expect(!!(x), 0)
#   define VMAWARE_LIKELY(x)   __builtin_expect(!!(x), 1)
#else
#   define VMAWARE_UNLIKELY
#   define VMAWARE_LIKELY
#endif

    // specifically for util::hyper_x() and memo::hyperv
    enum hyperx_state : u8 {
        HYPERV_UNKNOWN_VM = 0,
        HYPERV_REAL_VM,
        HYPERV_ARTIFACT_VM,
    };

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
#if (WINDOWS)
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
#if (WINDOWS)
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
            constexpr u32 amd_ecx = 0x444d4163; // "cAMD"

            u32 unused, ecx = 0;
            cpuid(unused, unused, ecx, unused, 0);

            return (ecx == amd_ecx);
        }

        // check Intel
        [[nodiscard]] static bool is_intel() {
            constexpr u32 intel_ecx1 = 0x6c65746e; // "ntel"
            constexpr u32 intel_ecx2 = 0x6c65746f; // "otel", this is because some Intel CPUs have a rare manufacturer string of "GenuineIotel"

            u32 unused, ecx = 0;
            cpuid(unused, unused, ecx, unused, 0);

            return ((ecx == intel_ecx1) || (ecx == intel_ecx2));
        }

        // check for POSSIBILITY of hyperthreading, I don't think there's a 
        // full-proof method to detect if you're actually hyperthreading imo.
        [[nodiscard]] static bool has_hyperthreading() {
            u32 unused, ebx, edx;

            cpuid(unused, ebx, unused, edx, 1);
            UNUSED(unused);

            bool htt_available = (edx & (1 << 28));

            if (!htt_available) {
                return false;
            }

            i32 logical_cores = ((ebx >> 16) & 0xFF);
            i32 physical_cores = 0;

#if (WINDOWS)
            SYSTEM_INFO sysinfo;
            GetSystemInfo(&sysinfo);
            physical_cores = sysinfo.dwNumberOfProcessors;
#elif (LINUX)
            physical_cores = static_cast<i32>(sysconf(_SC_NPROCESSORS_CONF));
#elif (APPLE)
            // sysctlbyname("hw.physicalcpu", &physical_cores, sizeof(physical_cores), NULL, 0);
            // the code under this is the same as the one commented right above, removed due to non-backwards compatibility

            i32 mib[2];
            std::size_t size = sizeof(physical_cores);

            mib[0] = CTL_HW;         // hardware information
            mib[1] = HW_NCPU; // physical CPU count

            if (sysctl(mib, 2, &physical_cores, &size, NULL, 0) != 0) {
                debug("HAS_HYPERTHREADING(): sysctl failed, returned false");
                return false;
            }
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

            constexpr std::array<u32, 3> ids = {{
                cpu::leaf::brand1,
                cpu::leaf::brand2,
                cpu::leaf::brand3
            }};

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


        [[nodiscard]] static std::array<std::string, 2> cpu_manufacturer(const u32 p_leaf) {
            auto cpuid_thingy = [](const u32 p_leaf, u32* regs, std::size_t start = 0, std::size_t end = 4) -> bool {
                u32 x[4]{};
                cpu::cpuid(x[0], x[1], x[2], x[3], p_leaf);

                for (; start < end; start++) {
                    *regs++ = x[start];
                }

                return true;
            };

            u32 sig_reg[3] = { 0 };

            if (
                (sig_reg[0] == 0) &&
                (sig_reg[1] == 0) &&
                (sig_reg[2] == 0)
            ) {
                return { "", "" };
            }

            if (!cpuid_thingy(p_leaf, sig_reg, 1)) {
                return { "", "" };
            }

            auto strconvert = [](u64 n) -> std::string {
                const std::string& str(reinterpret_cast<char*>(&n));
                return str;
            };

            // the reason why there's 2 is because depending on the leaf, 
            // the last 4 characters might be switched with the middle 
            // characters for some fuckin reason, idk why this is even a thing
            // so this function basically returns the same string but with 
            // the 4~8 and 8~12 characters switched for one, and the other isn't.
            std::stringstream ss;
            std::stringstream ss2;

            ss << strconvert(sig_reg[0]);
            ss << strconvert(sig_reg[2]);
            ss << strconvert(sig_reg[1]);

            ss2 << strconvert(sig_reg[0]);
            ss2 << strconvert(sig_reg[1]);
            ss2 << strconvert(sig_reg[2]);

            std::string brand_str = ss.str();
            std::string brand_str2 = ss2.str();

            const std::array<std::string, 2> result = { brand_str, brand_str2 };

            return result;
        }

        struct stepping_struct {
            u8 model;
            u8 family;
            u8 extmodel;
        };

        [[nodiscard]] static stepping_struct fetch_steppings() {
            struct stepping_struct steps {};

            u32 unused, eax = 0;
            cpu::cpuid(eax, unused, unused, unused, 1);
            UNUSED(unused);

            steps.model = ((eax >> 4) & 0b1111);
            steps.family = ((eax >> 8) & 0b1111);
            steps.extmodel = ((eax >> 16) & 0b1111);

            return steps;
        }

        // check if the CPU is an intel celeron
        [[nodiscard]] static bool is_celeron(const stepping_struct steps) {
            if (!cpu::is_intel()) {
                return false;
            }

            constexpr u8 celeron_model = 0xA;
            constexpr u8 celeron_family = 0x6;
            constexpr u8 celeron_extmodel = 0x2;

            return (
                steps.model == celeron_model &&
                steps.family == celeron_family &&
                steps.extmodel == celeron_extmodel
            );
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
                lmhs = "SRESRESRESRE",
                jailhouse = "Jailhouse\0\0\0",
                apple_vz = "Apple VZ",
                intel_kgt = "EVMMEVMMEVMM",
                barevisor = "Barevisor!\0\0",
                hyperplatform = "PpyH",
                minivisor = "MiniVisor\0\0\0";

            const std::array<std::string, 2> brand_strings = cpu_manufacturer(p_leaf);

            debug(technique_name, brand_strings.at(0));
            debug(technique_name, brand_strings.at(1));

#if (CPP < 17)
            // bypass compiler warning about unused parameter, ignore this
            UNUSED(technique_name);
#endif

            for (const std::string &brand_str : brand_strings) {
                if (brand_str == qemu) { return core::add(brands::QEMU); }
                if (brand_str == vmware) { return core::add(brands::VMWARE); }
                if (brand_str == vbox) { return core::add(brands::VBOX); }
                if (brand_str == bhyve) { return core::add(brands::BHYVE); }
                if (brand_str == bhyve2) { return core::add(brands::BHYVE); }
                if (brand_str == kvm) { return core::add(brands::KVM); }
                if (brand_str == kvm_hyperv) { return core::add(brands::KVM_HYPERV); }
                if (brand_str == xta) { return core::add(brands::MSXTA); }
                if (brand_str == parallels) { return core::add(brands::PARALLELS); }
                if (brand_str == parallels2) { return core::add(brands::PARALLELS); }
                if (brand_str == xen) { return core::add(brands::XEN); }
                if (brand_str == acrn) { return core::add(brands::ACRN); }
                if (brand_str == qnx) { return core::add(brands::QNX); }
                if (brand_str == virtapple) { return core::add(brands::APPLE_ROSETTA); }
                if (brand_str == nvmm) { return core::add(brands::NVMM); }
                if (brand_str == openbsd_vmm) { return core::add(brands::BSD_VMM); }
                if (brand_str == intel_haxm) { return core::add(brands::INTEL_HAXM); }
                if (brand_str == unisys) { return core::add(brands::UNISYS); }
                if (brand_str == lmhs) { return core::add(brands::LMHS); }
                if (brand_str == jailhouse) { return core::add(brands::JAILHOUSE); }
                if (brand_str == intel_kgt) { return core::add(brands::INTEL_KGT); }
                if (brand_str == barevisor) { return core::add(brands::BAREVISOR); }
                if (brand_str == minivisor) { return core::add(brands::MINIVISOR); }

                // both Hyper-V and VirtualPC have the same string value
                if (brand_str == hyperv) {
                    if (util::hyper_x()) {
                        return false;
                    }
                    return core::add(brands::HYPERV, brands::VPC);
                }

                /**
                 * this is added because there are inconsistent string
                 * values for KVM's manufacturer ID. For example,
                 * it gives me "KVMKMVMKV" when I run it under QEMU
                 * but the Wikipedia article on CPUID says it's
                 * "KVMKVMKVM\0\0\0", like wtf????
                 */
                if (util::find(brand_str, "KVM")) {
                    return core::add(brands::KVM);
                }

                /**
                 * i'm honestly not sure about this one,
                 * they're supposed to have 12 characters but
                 * Wikipedia tells me it these brands have
                 * less characters (both 8), so i'm just
                 * going to scan for the entire string ig
                 */
#if (CPP >= 17)
                const char* qnx_sample = qnx2.data();
                const char* applevz_sample = apple_vz.data();
#else
                const char* qnx_sample = qnx2.c_str();
                const char* applevz_sample = apple_vz.c_str();
#endif

                if (util::find(brand_str, qnx_sample)) {
                    return core::add(brands::QNX);
                }

                if (util::find(brand_str, applevz_sample)) {
                    return core::add(brands::APPLE_VZ);
                }

                if (util::find(brand_str, hyperplatform.data())) {
                    return core::add(brands::HYPERPLATFORM);
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
        static std::map<u16, data_t> cache_table;
        static flagset cache_keys;

    public:
        static void cache_store(const u16 technique_macro, const result_t result, const points_t points) {
            cache_table[technique_macro] = { result, points };
            cache_keys.set(technique_macro);
        }

        static bool is_cached(const u16 technique_macro) {
            return cache_keys.test(technique_macro);
        }

        static data_t cache_fetch(const u16 technique_macro) {
            return cache_table.at(technique_macro);
        }

        static std::vector<u16> cache_fetch_all() {
            std::vector<u16> vec;

            for (auto it = cache_table.cbegin(); it != cache_table.cend(); ++it) {
                const data_t data = it->second;

                if (data.result == true) {
                    const u16 macro = it->first;
                    vec.push_back(macro);
                }
            }

            return vec;
        }

        // basically checks whether all the techniques were cached (with exception of techniques disabled by default)
        static bool all_present() {
            if (cache_table.size() == technique_count) {
                return true;
            } else if (cache_table.size() == static_cast<std::size_t>(technique_count) - 3) {
                return (
                    !cache_keys.test(VMWARE_DMESG)
                );
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

        struct hyperx {
            static hyperx_state state;
            static bool cached;

            static hyperx_state fetch() {
                return state;
            }

            static void store(const hyperx_state p_state) {
                state = p_state;
                cached = true;
            }

            static bool is_cached() {
                return cached;
            }
        };

#if (WINDOWS)
        struct wmi {
            static bool cached;
            static bool status;

            static void store(const bool p_status) {
                cached = true;
                status = p_status;
            }

            static bool is_cached() {
                return cached;
            }

            static bool fetch() {
                return status;
            }
        };
#endif
    };

#if (WINDOWS)
    struct wmi {
        static IWbemLocator* pLoc;
        static IWbemServices* pSvc;

        enum class result_type {
            String,
            Integer,
            Double,
            None
        };

        struct result {
            result_type type;
            union {
                std::string strValue;
                int intValue;
                double doubleValue;
            };

            result(const std::string& str) : type(result_type::String), strValue(str) {}

            result(int integer) : type(result_type::Integer), intValue(integer) {}

            result(double dbl) : type(result_type::Double), doubleValue(dbl) {}

            result(const result& other) : type(other.type), strValue() {
                if (type == result_type::String) {
                    new (&strValue) std::string(other.strValue);
                }
                else if (type == result_type::Integer) {
                    intValue = other.intValue;
                }
                else if (type == result_type::Double) {
                    doubleValue = other.doubleValue;
                }
            }

            result& operator=(const result& other) {
                if (this != &other) {
                    if (type == result_type::String) {
                        strValue.~basic_string();
                    }
                    type = other.type;
                    if (type == result_type::String) {
                        new (&strValue) std::string(other.strValue);
                    } else if (type == result_type::Integer) {
                        intValue = other.intValue;
                    } else if (type == result_type::Double) {
                        doubleValue = other.doubleValue;
                    }
                }
                return *this;
            }

            ~result() {
                if (type == result_type::String) {
                    strValue.~basic_string();
                }
            }
        };

        static bool initialize() {
            if (memo::wmi::is_cached()) {
                return memo::wmi::fetch();
            }

            // this will clean up wmi when the program terminates
            std::atexit(wmi::cleanup);

            if (pSvc != nullptr) {
                memo::wmi::store(true);
                return true;
            }

            HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
            if (FAILED(hres)) {
                debug("wmi: Failed to initialize COM library. Error code = ", hres);
                memo::wmi::store(false);
                return false;
            }

            hres = CoInitializeSecurity(
                NULL,
                -1,
                NULL,
                NULL,
                RPC_C_AUTHN_LEVEL_DEFAULT,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                NULL,
                EOAC_NONE,
                NULL
            );

            if (FAILED(hres)) {
                CoUninitialize();
                debug("wmi: Failed to initialize security. Error code = ", hres);
                memo::wmi::store(false);
                return false;
            }

            hres = CoCreateInstance(
                CLSID_WbemLocator,
                0,
                CLSCTX_INPROC_SERVER,
                IID_IWbemLocator,
                (LPVOID*)&pLoc
            );

            if (FAILED(hres)) {
                CoUninitialize();
                debug("wmi: Failed to create IWbemLocator object. Error code = ", hres);
                memo::wmi::store(false);
                return false;
            }

            hres = pLoc->ConnectServer(
                _bstr_t(L"ROOT\\CIMV2"),
                NULL,
                NULL,
                0,
                NULL,
                0,
                0,
                &pSvc
            );

            if (FAILED(hres)) {
                pLoc->Release();
                CoUninitialize();
                debug("wmi: Could not connect to WMI server. Error code = ", hres);
                memo::wmi::store(false);
                return false;
            }

            hres = CoSetProxyBlanket(
                pSvc,
                RPC_C_AUTHN_WINNT,
                RPC_C_AUTHZ_NONE,
                NULL,
                RPC_C_AUTHN_LEVEL_CALL,
                RPC_C_IMP_LEVEL_IMPERSONATE,
                NULL,
                EOAC_NONE
            );

            if (FAILED(hres)) {
                pSvc->Release();
                pLoc->Release();
                CoUninitialize();
                debug("wmi: Could not set proxy blanket. Error code = ", hres);
                memo::wmi::store(false);
                return false;
            }

            memo::wmi::store(true);
            return true;
        }

        static std::vector<result> execute(const std::wstring& query, const std::vector<std::wstring>& properties) {
            std::vector<result> results;

            if (!pSvc) {
                debug("wmi: pSvc is nullptr, attempting to initialize WMI.");
                if (!initialize()) {
                    debug("wmi: Failed to initialize WMI.");
                    return results;
                }
            }

            IEnumWbemClassObject* pEnumerator = NULL;
            HRESULT hres = pSvc->ExecQuery(
                _bstr_t(L"WQL"),
                _bstr_t(query.c_str()),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                NULL,
                &pEnumerator
            );

            if (FAILED(hres)) {
                debug("wmi: ExecQuery failed. Error code = ", hres);
                return results;
            }

            IWbemClassObject* pclsObj = NULL;
            ULONG uReturn = 0;

            while (pEnumerator) {
                HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

                if (0 == uReturn || FAILED(hr)) {
                    break;
                }

                for (const auto& prop : properties) {
                    VARIANT vtProp;
                    VariantInit(&vtProp);
                    hr = pclsObj->Get(prop.c_str(), 0, &vtProp, 0, 0);

                    if (SUCCEEDED(hr)) {
                        if (vtProp.vt == VT_BSTR) {
                            results.emplace_back(_com_util::ConvertBSTRToString(vtProp.bstrVal));
                        }
                        else if (vtProp.vt == VT_I4) {
                            results.emplace_back(vtProp.intVal);
                        }
                        else if (vtProp.vt == VT_R8) {
                            results.emplace_back(vtProp.dblVal);
                        }
                    }
                    VariantClear(&vtProp);
                }

                pclsObj->Release();
            }

            pEnumerator->Release();
            return results;
        }

        static void cleanup() noexcept {
            if (pSvc) {
                pSvc->Release();
                pSvc = nullptr;
            }

            if (pLoc) {
                pLoc->Release();
                pLoc = nullptr;
            }

            CoUninitialize();
        }
    };

    using wmi_result = std::vector<wmi::result>;
#endif

    // miscellaneous functionalities
    struct util {
#if (LINUX)
        // fetch file data
        [[nodiscard]] static std::string read_file(const char* file_path) {
            if (!exists(file_path)) {
                return "";
            }

            std::ifstream file{};
            std::string data{};
            file.open(file_path);

            if (file.is_open()) {
                file >> data;
            }

            file.close();
            return data;
        }
#endif

        // fetch the file but in binary form
        [[nodiscard]] static std::vector<u8> read_file_binary(const char* file_path) {
            std::ifstream file(file_path, std::ios::binary);
    
            if (!file) {
                std::vector<u8> tmp{};
                return tmp;
            }

            std::vector<u8> buffer((std::istreambuf_iterator<char>(file)),
                                    std::istreambuf_iterator<char>());

            file.close();

            return buffer;
        }

        // check if file exists
        [[nodiscard]] static bool exists(const char* path) {
#if (WINDOWS)
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

#if (WINDOWS) && (_UNICODE)
        // handle TCHAR conversion
        [[nodiscard]] static bool exists(const TCHAR* path) {
            char c_szText[_MAX_PATH]{};
            size_t convertedChars = 0;
            wcstombs_s(&convertedChars, c_szText, path, _MAX_PATH);
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
#elif (WINDOWS)
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

            CloseHandle(hToken); 

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

            std::cout << std::dec << "\n";
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

            std::cout << std::dec << "\n";
        }
#endif

        // basically std::system but it runs in the background with std::string output
        [[nodiscard]] static std::unique_ptr<std::string> sys_result(const TCHAR* cmd) {
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
#elif (WINDOWS)
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

        /**
         * @brief Get the disk size in GB
         * @category Linux, Windows
         * @returns Disk size in GB
         */
        [[nodiscard]] static u32 get_disk_size() {
            u32 size = 0;
            constexpr u64 GB = (static_cast<u64>(1024) * 1024 * 1024);  // Size of 1 GB in bytes

#if (LINUX)
            struct statvfs stat;

            if (statvfs("/", &stat) != 0) {
                debug("private util::get_disk_size( function: ", "failed to fetch disk size");
                return 0; // Return 0 to indicate failure
            }

            // in gigabytes
            size = static_cast<u32>((stat.f_blocks * stat.f_frsize) / GB);
#elif (WINDOWS)
            ULARGE_INTEGER totalNumberOfBytes;

            if (GetDiskFreeSpaceExW(
                L"C:",  // Drive or directory path (use wide character string)
                nullptr,  // Free bytes available to the caller (not needed for total size)
                &totalNumberOfBytes,  // Total number of bytes on the disk
                nullptr  // Total number of free bytes on the disk (not needed for total size)
            )) {
                // Convert bytes to GB
                size = static_cast<u32>(totalNumberOfBytes.QuadPart / GB);
            }
            else {
                debug("util::get_disk_size(: ", "failed to fetch size in GB");
            }
#endif

            if (size == 0)
                return 81;
            
            debug("private util::get_disk_size( function: ", "disk size = ", size, "GB");

            return size;  // Return disk size in GB
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
                } else if (in_number) {
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
#elif (WINDOWS)
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
#if (WINDOWS)
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
#if (WINDOWS)
            DWORD processes[1024], bytesReturned;

            if (!EnumProcesses(processes, sizeof(processes), &bytesReturned))
                return false;

            DWORD numProcesses = bytesReturned / sizeof(DWORD);

            for (DWORD i = 0; i < numProcesses; ++i) {
                const HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processes[i]);
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

                //std::cout << "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\nNOT SKIPPED\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n";

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
#if (WINDOWS)
            char ComputerName[MAX_COMPUTERNAME_LENGTH + 1];
            DWORD cbComputerName = sizeof(ComputerName);

            if (GetComputerNameA(ComputerName, &cbComputerName)) {
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


        /**
         * @brief Checks whether Hyper-V host artifacts are present instead of an actual Hyper-V VM
         * @note Hyper-V has an obscure feature where if it's enabled in the host system, the CPU 
         *       hardware values makes it look like the whole system is running inside Hyper-V, 
         *       which isn't true. This makes it a challenge to determine whether the hardware 
         *       values the library is collecting is either a real Hyper-V VM, or just the artifacts 
         *       of what Hyper-V has left as a consequence of having it enabled in the host system. 
         *       The reason why this is a problem is because the library might falsely conclude that 
         *       your the host system is running in Hyper-V, which is a false positive. This is where 
         *       the Hyper-X mechanism comes into play to distinguish between these two.
         * @author idea by Requiem (https://github.com/NotRequiem)
         * @returns boolean, true = Hyper-V artifact, false = Real Hyper-V VM
         * @link graph to explain how this works: https://github.com/kernelwernel/VMAware/blob/main/assets/hyper-x/v4/Hyper-X_version_4.drawio.png
         */
        [[nodiscard]] static bool hyper_x() {
#if (!WINDOWS)
            return false;
#else
            if (memo::hyperx::is_cached()) {
                core_debug("HYPER_X: returned from cache");
                return (memo::hyperx::fetch() == HYPERV_ARTIFACT_VM);
            }


            // SMBIOS check
            auto is_smbios_hyperv = []() -> bool {
                const std::string smbios = SMBIOS_string();
                const bool result = (smbios == "VIRTUAL MACHINE");

                if (result) {
                    core_debug("HYPER_X: SMBIOS string = ", smbios);
                    core_debug("HYPER_X: SMBIOS string returned true");
                }

                return result;
            };

            // ACPI Data check
            auto is_acpi_hyperv = []() -> bool {
                const std::string acpi_data = AcpiData_string();
                const bool result = (acpi_data == "VRTUAL MICROSFT");

                if (result) {
                    core_debug("HYPER_X: ACPI string = ", acpi_data);
                    core_debug("HYPER_X: ACPI string returned true");
                }

                return result;
            };

            // motherboard check
            auto is_motherboard_hyperv = []() -> bool {
                const bool motherboard = motherboard_string("Microsoft Corporation");

                if (motherboard) {
                    core_debug("HYPER_X: motherboard string match = ", motherboard);
                }

                return motherboard;
            };


            // event log check (slow, so in last place)
            auto is_event_log_hyperv = []() -> bool {
                std::wstring logName = L"Microsoft-Windows-Kernel-PnP/Configuration";
                std::vector<std::wstring> searchStrings = { L"Virtual_Machine", L"VMBUS" };
                const bool result = (util::query_event_logs(logName, searchStrings));

                if (result) {
                    core_debug("HYPER_X: event log returned true");
                }

                return result;
            };


            // VMProtect method for Hyper-V artifact detection
            auto is_root_partition = []() -> bool {
                u32 ebx, unused = 0;
                cpu::cpuid(unused, ebx, unused, unused, 0x40000003);
                const bool result = (ebx & 1);

                if (result) {
                    core_debug("HYPER_X: root partition returned true");
                }

                return result;
            };


            // check if eax is either 11 or 12 after running VM::HYPERVISOR_STR technique
            auto eax = []() -> u32 {
                char out[sizeof(int32_t) * 4 + 1] = { 0 }; // e*x size + number of e*x registers + null terminator
                cpu::cpuid((int*)out, cpu::leaf::hypervisor);

                const u32 eax = static_cast<u32>(out[0]);

                core_debug("HYPER_X: eax = ", eax);

                return eax;
            };

            bool run_mechanism = false;

            switch (eax()) {
                case 11: run_mechanism = false; break; // real hyper-v vm
                case 12: run_mechanism = true; break; // artifact hyper-v vm
                default:
                    // fallback in case eax fails
                    if (is_root_partition()) {
                        run_mechanism = true;
                    }
            }

            enum hyperx_state state;

            if (run_mechanism) {
                const bool has_hyperv_indications = (
                    is_smbios_hyperv() || 
                    is_acpi_hyperv() ||
                    is_motherboard_hyperv() || 
                    is_event_log_hyperv()
                );

                const bool eax_result = (eax() == 11 || eax() == 12);

                const bool is_real_hyperv_vm = (eax_result && has_hyperv_indications);

                if (is_real_hyperv_vm) {
                    state = HYPERV_REAL_VM;
                } else {
                    state = HYPERV_ARTIFACT_VM;
                }
            } else if (eax() == 11) {
                state = HYPERV_REAL_VM;
            } else {
                core_debug("HYPER_X: none detected");
                state = HYPERV_UNKNOWN_VM;
            }

            memo::hyperx::store(state);
            core_debug("HYPER_X: cached");

            // false means it's an artifact, which is what the 
            // point of this whole function is supposed to do
            switch (state) {
                case HYPERV_ARTIFACT_VM:
                    core_debug("HYPER_X: added Hyper-V artifact VM");
                    core::add(brands::HYPERV_ARTIFACT);
                    return true;

                case HYPERV_REAL_VM:
                    core_debug("HYPER_X: added Hyper-V real VM");
                    core::add(brands::HYPERV);
                    return false;

                case HYPERV_UNKNOWN_VM:
                    core_debug("HYPER_X: none detected");
                    return false;

                default: 
                    return false;
            }
#endif
        }

#if (WINDOWS)
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

            const HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");

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
                { 6002, static_cast<u8>(6) }, // windows vista, technically no number but this function is just for great than operations anyway so it doesn't matter
                { 7601, static_cast<u8>(7) },
                { 9200, static_cast<u8>(8) },
                { 9600, static_cast<u8>(8) },
                { 10240, static_cast<u8>(10) },
                { 10586, static_cast<u8>(10) },
                { 14393, static_cast<u8>(10) },
                { 15063, static_cast<u8>(10) },
                { 16299, static_cast<u8>(10) },
                { 17134, static_cast<u8>(10) },
                { 17763, static_cast<u8>(10) },
                { 18362, static_cast<u8>(10) },
                { 18363, static_cast<u8>(10) },
                { 19041, static_cast<u8>(10) },
                { 19042, static_cast<u8>(10) },
                { 19043, static_cast<u8>(10) },
                { 19044, static_cast<u8>(10) },
                { 19045, static_cast<u8>(10) },
                { 22000, static_cast<u8>(11) },
                { 22621, static_cast<u8>(11) },
                { 22631, static_cast<u8>(11) }
            };

            const HMODULE ntdll = GetModuleHandleA("ntdll.dll");
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

            if (major_version == 0) {
                return util::get_windows_version_backup();
            }

            return major_version;
        }


        [[nodiscard]] static std::string SMBIOS_string() {
            HKEY hk = 0;
            int ret = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data", 0, KEY_ALL_ACCESS, &hk);
            if (ret != ERROR_SUCCESS) {
                debug("SMBIOS_string(): ret = error");
                return "";
            }

            unsigned long type = 0;
            unsigned long length = 0;

            ret = RegQueryValueExA(hk, "SMBiosData", 0, &type, 0, &length);

            if (ret != ERROR_SUCCESS) {
                RegCloseKey(hk);
                debug("SMBIOS_string(): ret = error 2");
                return "";
            }

            if (length == 0) {
                RegCloseKey(hk);
                debug("SMBIOS_string(): length = 0");
                return "";
            }

            char* p = static_cast<char*>(LocalAlloc(LMEM_ZEROINIT, length));
            if (p == nullptr) {
                RegCloseKey(hk);
                debug("SMBIOS_string(): p = nullptr");
                return "";
            }

            ret = RegQueryValueExA(hk, "SMBiosData", 0, &type, reinterpret_cast<unsigned char*>(p), &length);

            if (ret != ERROR_SUCCESS) {
                LocalFree(p);
                RegCloseKey(hk);
                debug("SMBIOS_string(): ret = error 3");
                return "";
            }

            auto ScanDataForString = [](const unsigned char* data, unsigned long data_length, const unsigned char* string2) -> const unsigned char* {
                std::size_t string_length = strlen(reinterpret_cast<const char*>(string2));
                for (std::size_t i = 0; i <= (data_length - string_length); i++) {
                    if (strncmp(reinterpret_cast<const char*>(&data[i]), reinterpret_cast<const char*>(string2), string_length) == 0) {
                        return &data[i];
                    }
                }
                return nullptr;
            };

            auto AllToUpper = [](char* str, std::size_t len) {
                for (std::size_t i = 0; i < len; ++i) {
                    str[i] = static_cast<char>(std::toupper(static_cast<unsigned char>(str[i])));
                }
            };

            AllToUpper(p, length);

            auto cast = [](char* p) -> unsigned char* {
                return reinterpret_cast<unsigned char*>(p);
            };

            const unsigned char* x1 = ScanDataForString(cast(p), length, reinterpret_cast<const unsigned char*>("INNOTEK GMBH"));
            const unsigned char* x2 = ScanDataForString(cast(p), length, reinterpret_cast<const unsigned char*>("VIRTUALBOX"));
            const unsigned char* x3 = ScanDataForString(cast(p), length, reinterpret_cast<const unsigned char*>("SUN MICROSYSTEMS"));
            const unsigned char* x4 = ScanDataForString(cast(p), length, reinterpret_cast<const unsigned char*>("VBOXVER"));
            const unsigned char* x5 = ScanDataForString(cast(p), length, reinterpret_cast<const unsigned char*>("VIRTUAL MACHINE"));
            const unsigned char* x6 = ScanDataForString(cast(p), length, reinterpret_cast<const unsigned char*>("VMware"));

            std::string result = "";
            bool is_vm = false;

            if (x1 || x2 || x3 || x4 || x5 || x6) {
                is_vm = true;
#ifdef __VMAWARE_DEBUG__
                if (x1) { debug("SMBIOS: x1 = ", x1); result = std::string(reinterpret_cast<const char*>(x1)); }
                if (x2) { debug("SMBIOS: x2 = ", x2); result = std::string(reinterpret_cast<const char*>(x2)); }
                if (x3) { debug("SMBIOS: x3 = ", x3); result = std::string(reinterpret_cast<const char*>(x3)); }
                if (x4) { debug("SMBIOS: x4 = ", x4); result = std::string(reinterpret_cast<const char*>(x4)); }
                if (x5) { debug("SMBIOS: x5 = ", x5); result = std::string(reinterpret_cast<const char*>(x5)); }
                if (x6) { debug("SMBIOS: x6 = ", x6); result = std::string(reinterpret_cast<const char*>(x6)); }
#endif
            }

            LocalFree(p);
            RegCloseKey(hk);

            if (is_vm) {
                return result;
            }

            return "";
        }


        [[nodiscard]] static std::string AcpiData_string() {
            HKEY hk = 0;
            int ret = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data", 0, KEY_ALL_ACCESS, &hk);
            if (ret != ERROR_SUCCESS) {
                debug("AcpiData_string(): ret = error");
                return "";
            }

            unsigned long type = 0;
            unsigned long length = 0;

            ret = RegQueryValueExA(hk, "AcpiData", 0, &type, 0, &length);

            if (ret != ERROR_SUCCESS) {
                RegCloseKey(hk);
                debug("AcpiData_string(): ret = error 2");
                return "";
            }

            if (length == 0) {
                RegCloseKey(hk);
                debug("AcpiData_string(): length = 0");
                return "";
            }

            char* p = static_cast<char*>(LocalAlloc(LMEM_ZEROINIT, length));
            if (p == nullptr) {
                RegCloseKey(hk);
                debug("AcpiData_string(): p = nullptr");
                return "";
            }

            ret = RegQueryValueExA(hk, "AcpiData", 0, &type, reinterpret_cast<unsigned char*>(p), &length);

            if (ret != ERROR_SUCCESS) {
                LocalFree(p);
                RegCloseKey(hk);
                debug("AcpiData_string(): ret = error 3");
                return "";
            }

            auto ScanDataForString = [](const unsigned char* data, unsigned long data_length, const unsigned char* string2) -> const unsigned char* {
                std::size_t string_length = strlen(reinterpret_cast<const char*>(string2));
                for (std::size_t i = 0; i <= (data_length - string_length); i++) {
                    if (strncmp(reinterpret_cast<const char*>(&data[i]), reinterpret_cast<const char*>(string2), string_length) == 0) {
                        return &data[i];
                    }
                }
                return nullptr;
                };

            auto AllToUpper = [](char* str, std::size_t len) {
                for (std::size_t i = 0; i < len; ++i) {
                    str[i] = static_cast<char>(std::toupper(static_cast<unsigned char>(str[i])));
                }
                };

            AllToUpper(p, length);

            auto cast = [](char* p) -> unsigned char* {
                return reinterpret_cast<unsigned char*>(p);
            };

            const unsigned char* x1 = ScanDataForString(cast(p), length, reinterpret_cast<const unsigned char*>("VRTUAL MICROSFT"));

            std::string result = "";
            bool is_virtual = false;

            if (x1) {
                is_virtual = true;
#ifdef __VMAWARE_DEBUG__
                debug("AcpiData: x1 = ", x1);
                result = std::string(reinterpret_cast<const char*>(x1));
#endif
            }

            LocalFree(p);
            RegCloseKey(hk);

            if (is_virtual) {
                return result;
            }

            return "";
        }


        [[nodiscard]] static bool motherboard_string(const char* vm_string) {
            if (!wmi::initialize()) {
                core_debug("Failed to initialize WMI in motherboard_string");
                return false;
            }

            wmi_result results = wmi::execute(L"SELECT * FROM Win32_BaseBoard", { L"Manufacturer" });

            for (const auto& res : results) {
                if (res.type == wmi::result_type::String) {
                    if (_stricmp(res.strValue.c_str(), vm_string) == 0) {
                        return true;
                    }
                }
            }

            return false;
        }


        /**
         * @brief Retrieves the last error message from the Windows API. Useful for __VMAWARE_DEBUG__
         * @author Requiem (https://github.com/NotRequiem)
         * @return A std::wstring containing the error message.
         */
        [[nodiscard]] static std::wstring GetLastErrorString() {
            const DWORD error = GetLastError();
            LPWSTR messageBuffer = nullptr;
            size_t size = FormatMessageW(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                nullptr, error, 0, (LPWSTR)&messageBuffer, 0, nullptr
            );

            std::wstring message(messageBuffer, size);
            LocalFree(messageBuffer);
            return message;
        }


        /**
         * @brief Searches for specific strings within events in a Windows Event Log.
         *
         * @param logName The name or path of the event log to search (e.g., "System", "Application", "Security", or a custom path).
         * @param searchStrings A vector of strings to search for within the event messages.
         * @param flags Query flags that define the direction of the search; default is EvtQueryReverseDirection.
         * @param timeout The maximum amount of time (in milliseconds) to wait for events; default is INFINITE.
         * @param maxEvents The maximum number of events to process; default is 1000.
         *
         * @author Requiem (https://github.com/NotRequiem)
         * 
         * @return True if any of the search strings are found in the events; otherwise, false.
         */
        [[nodiscard]] static bool query_event_logs(const std::wstring& logName,
            const std::vector<std::wstring>& searchStrings,
            DWORD flags = EvtQueryReverseDirection,
            DWORD timeout = INFINITE,
            const DWORD maxEvents = 1000) {

            EVT_HANDLE hLog = EvtOpenLog(nullptr, logName.c_str(), EvtOpenChannelPath);
            if (!hLog) {
                std::wcerr << L"Failed to open event log: " << logName << L". Error: " << GetLastErrorString() << "\n";
                return false;
            }

            EVT_HANDLE hResults = EvtQuery(nullptr, logName.c_str(), nullptr, flags);
            if (!hResults) {
                std::wcerr << L"Failed to query event log: " << logName << L". Error: " << GetLastErrorString() << "\n";
                EvtClose(hLog);
                return false;
            }

            EVT_HANDLE hEvent = nullptr;
            DWORD bufferUsed = 0;
            DWORD bufferSize = 0;
            DWORD count = 0;
            WCHAR* pBuffer = nullptr;

            // Iterate over events up to the maximum number specified
            for (DWORD eventCount = 0; eventCount < maxEvents; ++eventCount) {
                if (!EvtNext(hResults, 1, &hEvent, timeout, 0, &count)) {
                    if (GetLastError() == ERROR_NO_MORE_ITEMS) {
                        break; // No more events to process
                    }
                    std::wcerr << L"EvtNext failed. Error: " << GetLastErrorString() << "\n";
                    EvtClose(hResults);
                    EvtClose(hLog);
                    return false;
                }

                if (!EvtRender(nullptr, hEvent, EvtRenderEventXml, 0, nullptr, &bufferUsed, &count) &&
                    GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                    bufferSize = bufferUsed;
                    pBuffer = new WCHAR[bufferSize];
                    if (!pBuffer) {
                        std::cerr <<"Memory allocation failed.\n";
                        EvtClose(hResults);
                        EvtClose(hLog);
                        return false;
                    }

                    if (!EvtRender(nullptr, hEvent, EvtRenderEventXml, bufferSize, pBuffer, &bufferUsed, &count)) {
                        std::wcerr << L"EvtRender failed. Error: " << GetLastErrorString() << "\n";
                        delete[] pBuffer;
                        EvtClose(hResults);
                        EvtClose(hLog);
                        return false;
                    }
                }
                else {
                    std::wcerr << L"EvtRender failed. Error: " << GetLastErrorString() << "\n";
                    EvtClose(hResults);
                    EvtClose(hLog);
                    return false;
                }

                std::wstring eventMessage(pBuffer);
                delete[] pBuffer;

                // Check if any of the search strings are found in the event message, not in the event name
                bool found = false;
                for (const auto& searchString : searchStrings) {
                    if (eventMessage.find(searchString) != std::wstring::npos) {
                        found = true;
                        break;
                    }
                }

                if (found) {
                    EvtClose(hResults);
                    EvtClose(hLog);
                    return true;
                }

                EvtClose(hEvent);
            }

            EvtClose(hResults);
            EvtClose(hLog);

            return false;
        }


        /**
         * @brief Enable SE_DEBUG_PRIVILEGE for the current process to access other processes.
         */
        static bool EnableDebugPrivilege() {
            HANDLE hToken;
            TOKEN_PRIVILEGES tp{};
            LUID luid;

            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
                return false;
            }

            if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
                CloseHandle(hToken);
                return false;
            }

            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
                CloseHandle(hToken);
                return false;
            }

            if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
                CloseHandle(hToken);
                return false;
            }

            CloseHandle(hToken);
            return true;
        }


        /**
         * @brief Sliding window substring search to handle wide-character strings using the KMP algorithm.
         */
        static bool findSubstring(const wchar_t* buffer, size_t bufferSize, const std::wstring& searchString) {
            size_t searchLength = searchString.length();
            if (searchLength > bufferSize) return false;

            // Knuth-Morris-Pratt algorithm: Precompute the "partial match" table
            std::vector<size_t> lps(searchLength, 0);
            size_t j = 0; // Length of the previous longest prefix suffix
            for (size_t i = 1; i < searchLength; ++i) {
                while (j > 0 && searchString[i] != searchString[j]) {
                    j = lps[j - 1];
                }
                if (searchString[i] == searchString[j]) {
                    ++j;
                }
                lps[i] = j;
            }

            // Sliding window to search the substring
            size_t i = 0; // Index for buffer
            j = 0;        // Index for searchString
            while (i < bufferSize) {
                if (buffer[i] == searchString[j]) {
                    ++i;
                    ++j;
                    if (j == searchLength) {
                        return true;
                    }
                }
                else if (j > 0) {
                    j = lps[j - 1];
                }
                else {
                    ++i;
                }
            }

            return false;
        }


        static DWORD FindProcessIdByServiceName(const std::string& serviceName) {
            const std::wstring query = L"SELECT ProcessId, Name FROM Win32_Service WHERE Name='" +
                std::wstring(serviceName.begin(), serviceName.end()) + L"'";
            const std::vector<std::wstring> properties = { L"ProcessId" };

            auto results = wmi::execute(query, properties);
            for (const auto& res : results) {
                if (res.type == wmi::result_type::Integer) {
                    return static_cast<DWORD>(res.intValue);
                }
            }

            return 0;
        }


        [[nodiscard]] static bool does_threadcount_mismatch() {
            auto GetThreadsUsingOSAPI = []() -> unsigned long long {
                DWORD bufferSize = 0;
                GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &bufferSize);
            
                std::vector<char> buffer(bufferSize);
                if (!GetLogicalProcessorInformationEx(RelationProcessorCore, reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(buffer.data()), &bufferSize)) {
                    return 0;
                }
            
                unsigned long long threadCount = 0; 
                char* ptr = buffer.data();
                while (ptr < buffer.data() + bufferSize) {
                    auto info = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(ptr);
                    if (info->Relationship == RelationProcessorCore) {
                        u64 mask = info->Processor.GroupMask[0].Mask;

                        u32 low = static_cast<u32>(mask); // low 32-bits
                        u32 high = static_cast<u32>(mask >> 32); // high 32-bits

                        threadCount += __popcnt(low);
                        threadCount += __popcnt(high);
                    }
                    ptr += info->Size;
                }
            
                return threadCount;
		    };

            auto GetThreadsUsingWMI = []() -> int {
                if (!wmi::initialize()) {
                    std::cerr << "Failed to initialize WMI in GetThreadsUsingWMI.\n";
                    return -1;
                }

                wmi_result results = wmi::execute(L"SELECT NumberOfLogicalProcessors FROM Win32_Processor", { L"NumberOfLogicalProcessors" });
                for (const auto& res : results) {
                    if (res.type == wmi::result_type::Integer) {
                        return res.intValue;
                    }
                }

                return -1;
            };

            auto GetThreadsUsingCPUID = []() -> int {
                int cpuInfo[4] = { 0 };
                __cpuid(cpuInfo, 0x0B);

                // CPUID leaf 0x0B, EBX contains logical processors per package
                int threadsPerPackage = cpuInfo[1] & 0xFFFF;
                return threadsPerPackage;
            };

            int cpuidThreads = GetThreadsUsingCPUID();
            int wmiThreads = GetThreadsUsingWMI();
            unsigned __int64 osThreads = GetThreadsUsingOSAPI();

            return !(cpuidThreads == wmiThreads && wmiThreads == osThreads);
        }
#endif
    };


private: // START OF PRIVATE VM DETECTION TECHNIQUE DEFINITIONS
    /**
     * @brief Check CPUID output of manufacturer ID for known VMs/hypervisors at leaf 0
     * @category x86
     */
    [[nodiscard]] static bool vmid() {
#if (!x86)
        return false;
#else
        if (!core::cpuid_supported) {
            return false;
        }

        return cpu::vmid_template(0, "VMID: ");
#endif
    }


    /**
     * @brief Check if CPU brand model contains any VM-specific string snippets
     * @category x86
     */
    [[nodiscard]] static bool cpu_brand() {
#if (!x86)
        return false;
#else
        if (!core::cpuid_supported) {
            return false;
        }

        std::string brand = cpu::get_brand();

        // TODO: might add more potential keywords, be aware that it could (theoretically) cause false positives
        constexpr std::array<const char*, 12> vmkeywords {{
            "qemu", "kvm", "virtual",
            "vbox", "virtualbox", "monitor",
            "bhyve", "hyperv", "hypervisor", 
            "hvisor", "parallels", "vmware"
        }};

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
                return core::add(brands::QEMU);
            }
        }

        return (match_count >= 1);
#endif
    }


    /**
     * @brief Check if hypervisor feature bit in CPUID eax bit 31 is enabled (always false for physical CPUs)
     * @category x86
     */
    [[nodiscard]] static bool hypervisor_bit() {
#if (!x86)
        return false;
#else
        if (!core::cpuid_supported) {
            return false;
        }

        if (util::hyper_x()) {
            return false;
        }

        u32 unused, ecx = 0;
        cpu::cpuid(unused, unused, ecx, unused, 1);

        return (ecx & (1 << 31));
#endif
    }


    /**
     * @brief Check for hypervisor brand string length (would be around 2 characters in a host machine)
     * @category x86
     */
    [[nodiscard]] static bool hypervisor_str() {
#if (!x86)
        return false;
#else
        if (util::hyper_x()) {
            return false;
        }

        char out[sizeof(int32_t) * 4 + 1] = { 0 }; // e*x size + number of e*x registers + null terminator
        cpu::cpuid((int*)out, cpu::leaf::hypervisor);

        debug("HYPERVISOR_STR: eax: ", static_cast<u32>(out[0]),
            "\nebx: ", static_cast<u32>(out[1]),
            "\necx: ", static_cast<u32>(out[2]),
            "\nedx: ", static_cast<u32>(out[3])
        );

        return (std::strlen(out + 4) >= 4);
#endif
    }


    /**
     * @brief Check if there are only 1 or 2 threads, which is a common pattern in VMs with default settings (nowadays physical CPUs should have at least 4 threads for modern CPUs
     * @category x86 (ARM might have very low thread counts, which is why it should be only for x86)
     */
    [[nodiscard]] static bool thread_count() {
#if (x86)
        debug("THREADCOUNT: ", "threads = ", std::thread::hardware_concurrency());

        struct cpu::stepping_struct steps = cpu::fetch_steppings();

        if (cpu::is_celeron(steps)) {
            return false;
        }

        return (std::thread::hardware_concurrency() <= 2);
#else 
        return false;
#endif
    }


    /**
     * @brief Check if mac address starts with certain VM designated values
     * @category All systems (I think)
     */
    [[nodiscard]] static bool mac_address_check() {
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
        } else {
            debug("MAC: ", "not successful");
        }
#elif (WINDOWS)
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
            << static_cast<int32_t>(mac[2]) << ":XX:XX:XX";
        // removed for privacy reasons, cuz only the first 3 bytes are needed
        //<< static_cast<int32_t>(mac[3]) << ":"  
        //<< static_cast<int32_t>(mac[4]) << ":"
        //<< static_cast<int32_t>(mac[5]);
        debug("MAC: ", ss.str());
#endif

        // better expression to fix code duplication
        auto compare = [=](const u8 mac1, const u8 mac2, const u8 mac3) noexcept -> bool {
            return (mac[0] == mac1 && mac[1] == mac2 && mac[2] == mac3);
        };

        if (compare(0x08, 0x00, 0x27)) {
            return core::add(brands::VBOX);
        }

        if (
            (compare(0x00, 0x0C, 0x29)) ||
            (compare(0x00, 0x1C, 0x14)) ||
            (compare(0x00, 0x50, 0x56)) ||
            (compare(0x00, 0x05, 0x69))
        ) {
            return core::add(brands::VMWARE);
        }

        if (compare(0x00, 0x16, 0xE3)) {
            return core::add(brands::XEN);
        }

        if (compare(0x00, 0x1C, 0x42)) {
            return core::add(brands::PARALLELS);
        }

        /*
        see https://github.com/kernelwernel/VMAware/issues/105

        if (compare(0x0A, 0x00, 0x27)) {
            return core::add(brands::HYBRID);
        }
        */

        return false;
    }


    /**
     * @brief Check if thermal directory in linux is present, might not be present in VMs
     * @category Linux
     */
    [[nodiscard]] static bool temperature() {
#if (!LINUX)
        return false;
#else
        return (!util::exists("/sys/class/thermal/thermal_zone0/"));
#endif
    }


    /**
     * @brief Check result from systemd-detect-virt tool
     * @category Linux
     */
    [[nodiscard]] static bool systemd_virt() {
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


    /**
     * @brief Check if the chassis vendor is a VM vendor
     * @category Linux
     */
    [[nodiscard]] static bool chassis_vendor() {
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
        if (vendor == "QEMU") { return core::add(brands::QEMU); }
        if (vendor == "Oracle Corporation") { return core::add(brands::VMWARE); }

        debug("CVENDOR: ", "unknown vendor = ", vendor);

        return false;
#endif
    }


    /**
     * @brief Check if the chassis type is valid (it's very often invalid in VMs)
     * @category Linux
     */
    [[nodiscard]] static bool chassis_type() {
#if (!LINUX)
        return false;
#else
        const char* chassis = "/sys/devices/virtual/dmi/id/chassis_type";

        if (util::exists(chassis)) {
            return (stoi(util::read_file(chassis)) == 1);
        } else {
            debug("CTYPE: ", "file doesn't exist");
        }

        return false;
#endif
    }


    /**
     * @brief Check if /.dockerenv or /.dockerinit file is present
     * @category Linux
     */
    [[nodiscard]] static bool dockerenv() {
#if (!LINUX)
        return false;
#else
        if (util::exists("/.dockerenv") || util::exists("/.dockerinit")) {
            return core::add(brands::DOCKER);
        }

        return false;
#endif
    }


    /**
     * @brief Check if dmidecode output matches a VM brand
     * @category Linux
     */
    [[nodiscard]] static bool dmidecode() {
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
        } else if (*result == "QEMU") {
            return core::add(brands::QEMU);
        } else if (*result == "VirtualBox") {
            return core::add(brands::VBOX);
        } else if (*result == "KVM") {
            return core::add(brands::KVM);
        } else if (std::atoi(result->c_str()) >= 1) {
            return true;
        } else {
            debug("DMIDECODE: ", "output = ", *result);
        }

        return false;
#endif
    }


    /**
     * @brief Check if dmesg output matches a VM brand
     * @category Linux
     */
    [[nodiscard]] static bool dmesg() {
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
        } else if (*result == "KVM") {
            return core::add(brands::KVM);
        } else if (*result == "QEMU") {
            return core::add(brands::QEMU);
        } else if (std::atoi(result->c_str())) {
            return true;
        } else {
            debug("DMESG: ", "output = ", *result);
        }

        return false;
#endif
    }


    /**
     * @brief Check if /sys/class/hwmon/ directory is present. If not, likely a VM
     * @category Linux
     */
    [[nodiscard]] static bool hwmon() {
#if (!LINUX)
        return false;
#else
        return (!util::exists("/sys/class/hwmon/"));
#endif
    }


    /**
     * @brief Check if the 5th byte after sidt is null
     * @author Matteo Malvica
     * @link https://www.matteomalvica.com/blog/2018/12/05/detecting-vmware-on-64-bit-systems/
     * @category x86
     */
    [[nodiscard]] static bool sidt5() {
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


    /**
     * @brief Find for registries of VMware tools
     * @category Windows
     */
    [[nodiscard]] static bool vmware_registry() {
#if (!WINDOWS)
        return false;
#else
        HKEY hKey;
        // Use wide string literal
        bool result = (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS);

        debug("VMWARE_REG: result = ", result);

        if (result == true) {
            return core::add(brands::VMWARE);
        }

        return result;
#endif
    }


    /**
     * @brief Check for VBox RdrDN
     * @category Windows
     */
    [[nodiscard]] static bool vbox_registry() {
#if (!WINDOWS)
        return false;
#else
        const HANDLE handle1 = CreateFile(_T("\\\\.\\VBoxMiniRdrDN"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        const HANDLE handle2 = CreateFile(_T("\\\\.\\pipe\\VBoxMiniRdDN"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        const HANDLE handle3 = CreateFile(_T("\\\\.\\VBoxTrayIPC"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        const HANDLE handle4 = CreateFile(_T("\\\\.\\pipe\\VBoxTrayIPC"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        
        bool result = false;

        if (
            (handle1 != INVALID_HANDLE_VALUE) ||
            (handle2 != INVALID_HANDLE_VALUE) ||
            (handle3 != INVALID_HANDLE_VALUE) ||
            (handle4 != INVALID_HANDLE_VALUE)
        ) {
            result = true;
        }

        CloseHandle(handle1);
        CloseHandle(handle2);
        CloseHandle(handle3);
        CloseHandle(handle4);

        if (result) {
            return core::add(brands::VBOX);
        }

        return false;
#endif
    }


    /**
     * @brief checks for default usernames, often a sign of a VM
     * @category Windows
     */
    [[nodiscard]] static bool user_check() {
#if (!WINDOWS)
        return false;
#else
        TCHAR user[UNLEN + 1]{};
        DWORD user_len = UNLEN + 1;
        GetUserName(user, &user_len);

        //TODO Ansi: debug("USER: ", "output = ", user);

        if (0 == _tcscmp(user, _T("vmware"))) {
            return core::add(brands::VMWARE);
        }

        return false;
#endif
    }


    /**
     * @brief Check for VM-specific DLLs
     * @category Windows
     */
    [[nodiscard]] static bool DLL_check() {
#if (!WINDOWS)
        return false;
#else
        const char* false_dlls[] = {
            "NetProjW.dll",
            "Ghofr.dll",
            "fg122.dll",
        };

        for (const char* dll : false_dlls) {
            if (GetModuleHandleA(dll) != nullptr) {
                debug("DLL: ", "LIB_INST detected true for false dll = ", dll);
                return true;
            }
        }

        return false;
#endif
    }


    /**
     * @brief Check for VM-specific registry values
     * @category Windows
     */
    [[nodiscard]] static bool registry_key() {
#if (!WINDOWS)
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
            } else {
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
        key(brands::HYPERV, "HKLM\\SOFTWARE\\Microsoft\\Hyper-V");
        key(brands::HYPERV, "HKLM\\SOFTWARE\\Microsoft\\VirtualMachine");
        key(brands::HYPERV, "HKLM\\SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters");
        key(brands::HYPERV, "HKLM\\SYSTEM\\ControlSet001\\Services\\vmicheartbeat");
        key(brands::HYPERV, "HKLM\\SYSTEM\\ControlSet001\\Services\\vmicvss");
        key(brands::HYPERV, "HKLM\\SYSTEM\\ControlSet001\\Services\\vmicshutdown");
        key(brands::HYPERV, "HKLM\\SYSTEM\\ControlSet001\\Services\\vmicexchange");

        // parallels
        key(brands::PARALLELS, "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_1AB8*");

        // sandboxie
        key(brands::SANDBOXIE, "HKLM\\SYSTEM\\CurrentControlSet\\Services\\SbieDrv");
        key(brands::SANDBOXIE, "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sandboxie");

        // virtualbox
        key(brands::VBOX, "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_80EE*");
        key(brands::VBOX, "HKLM\\HARDWARE\\ACPI\\DSDT\\VBOX__");
        key(brands::VBOX, "HKLM\\HARDWARE\\ACPI\\FADT\\VBOX__");
        key(brands::VBOX, "HKLM\\HARDWARE\\ACPI\\RSDT\\VBOX__");
        key(brands::VBOX, "HKLM\\SOFTWARE\\Oracle\\VirtualBox Guest Additions");
        key(brands::VBOX, "HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxGuest");
        key(brands::VBOX, "HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxMouse");
        key(brands::VBOX, "HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxService");
        key(brands::VBOX, "HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxSF");
        key(brands::VBOX, "HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxVideo");

        // virtualpc
        key(brands::VPC, "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_5333*");
        key(brands::VPC, "HKLM\\SYSTEM\\ControlSet001\\Services\\vpcbus");
        key(brands::VPC, "HKLM\\SYSTEM\\ControlSet001\\Services\\vpc-s3");
        key(brands::VPC, "HKLM\\SYSTEM\\ControlSet001\\Services\\vpcuhub");
        key(brands::VPC, "HKLM\\SYSTEM\\ControlSet001\\Services\\msvmmouf");

        // vmware
        key(brands::VMWARE, "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_15AD*");
        key(brands::VMWARE, "HKCU\\SOFTWARE\\VMware, Inc.\\VMware Tools");
        key(brands::VMWARE, "HKLM\\SOFTWARE\\VMware, Inc.\\VMware Tools");
        key(brands::VMWARE, "HKLM\\SYSTEM\\ControlSet001\\Services\\vmdebug");
        key(brands::VMWARE, "HKLM\\SYSTEM\\ControlSet001\\Services\\vmmouse");
        key(brands::VMWARE, "HKLM\\SYSTEM\\ControlSet001\\Services\\VMTools");
        key(brands::VMWARE, "HKLM\\SYSTEM\\ControlSet001\\Services\\VMMEMCTL");
        key(brands::VMWARE, "HKLM\\SYSTEM\\ControlSet001\\Services\\vmware");
        key(brands::VMWARE, "HKLM\\SYSTEM\\ControlSet001\\Services\\vmci");
        key(brands::VMWARE, "HKLM\\SYSTEM\\ControlSet001\\Services\\vmx86");
        key(brands::VMWARE, "HKLM\\SYSTEM\\CurrentControlSet\\Services\\vmmouse");
        key(brands::VMWARE, "HKLM\\SYSTEM\\CurrentControlSet\\Services\\vmusbmouse");
        key(brands::VMWARE, "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\IDE\\CdRomNECVMWar_VMware_IDE_CD*");
        key(brands::VMWARE, "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\IDE\\CdRomNECVMWar_VMware_SATA_CD*");
        key(brands::VMWARE, "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\IDE\\DiskVMware_Virtual_IDE_Hard_Drive*");
        key(brands::VMWARE, "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\IDE\\DiskVMware_Virtual_SATA_Hard_Drive*");
        key(brands::VMWARE, "SYSTEM\\ControlSet001\\Enum\\ACPI\\VMW0003");
        key(brands::VMWARE, "SYSTEM\\ControlSet001\\Enum\\ACPI\\VMW0003");
        key(brands::VMWARE, "SYSTEM\\CurrentControlSet\\Services\\vmmouse");
        key(brands::VMWARE, "SYSTEM\\CurrentControlSet\\Services\\vmusbmouse");

        // wine
        key(brands::WINE, "HKCU\\SOFTWARE\\Wine");
        key(brands::WINE, "HKLM\\SOFTWARE\\Wine");

        // xen
        key(brands::XEN, "HKLM\\HARDWARE\\ACPI\\DSDT\\xen");
        key(brands::XEN, "HKLM\\HARDWARE\\ACPI\\FADT\\xen");
        key(brands::XEN, "HKLM\\HARDWARE\\ACPI\\RSDT\\xen");
        key(brands::XEN, "HKLM\\SYSTEM\\ControlSet001\\Services\\xenevtchn");
        key(brands::XEN, "HKLM\\SYSTEM\\ControlSet001\\Services\\xennet");
        key(brands::XEN, "HKLM\\SYSTEM\\ControlSet001\\Services\\xennet6");
        key(brands::XEN, "HKLM\\SYSTEM\\ControlSet001\\Services\\xensvc");
        key(brands::XEN, "HKLM\\SYSTEM\\ControlSet001\\Services\\xenvdb");

        debug("REGISTRY: ", "score = ", static_cast<u32>(score));

        return (score >= 1);
#endif
    }


    /**
     * @brief Find for VMware and VBox specific files
     * @category Windows
     */
    [[nodiscard]] static bool vm_files() {
#if (!WINDOWS)
        return false;
#else
        // points
        u8 vbox = 0;
        u8 vmware = 0;

        constexpr std::array<const TCHAR*, 27> files = {{
                // VMware
                _T("C:\\windows\\System32\\Drivers\\Vmmouse.sys"),
                _T("C:\\windows\\System32\\Drivers\\Vmusbmouse.sys"),
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
            }};

        for (const auto file : files) {
            if (util::exists(file)) {
                const auto regex = tregex(file, std::regex::icase);

                if (std::regex_search(_T("vbox"), regex)) {
                    //TODO Ansi: debug("VM_FILES: found vbox file = ", file);
                    vbox++;
                } else {
                    //TODO Ansi: debug("VM_FILES: found vmware file = ", file);
                    vmware++;
                }
            }
        }

        debug("VM_FILES: vmware score: ", static_cast<u32>(vmware));
        debug("VM_FILES: vbox score: ", static_cast<u32>(vbox));

        if (vbox > vmware) {
            return core::add(brands::VBOX);
        } else if (vbox < vmware) {
            return core::add(brands::VMWARE);
        } else if (
            vbox > 0 &&
            vmware > 0 &&
            vbox == vmware
            ) {
            return true;
        }

        // general VM file
        if (util::exists("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\agent.pyw")) {
            return core::add(brands::CUCKOO);
        }

        return false;
#endif
    }


    /**
     * @brief Check if the sysctl for the hwmodel does not contain the "Mac" string
     * @author MacRansom ransomware
     * @category MacOS
     */
    [[nodiscard]] static bool hwmodel() {
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
            return core::add(brands::VMWARE);
        }

        // assumed true since it doesn't contain "Mac" string
        return true;
#endif
    }


    /**
     * @brief Check if disk size is under or equal to 50GB
     * @category Linux, Windows
     */
    [[nodiscard]] static bool disk_size() {
#if (!LINUX && !WINDOWS)
        return false;
#else
        const u32 size = util::get_disk_size();

        debug("DISK_SIZE: size = ", size);

        return (size <= 80); // Check if disk size is <= 80GB
#endif
    }


    /**
     * @brief Check for default RAM and DISK sizes set by VirtualBox
     * @note        RAM     DISK
     * WINDOWS 11:  4096MB, 80GB
     * WINDOWS 10:  2048MB, 50GB
     * ARCH, OPENSUSE, REDHAD, GENTOO, FEDORA, DEBIAN: 1024MB, 8GB
     * UBUNTU:      1028MB, 10GB
     * ORACLE:      1024MB, 12GB
     * OTHER LINUX: 512MB,  8GB

     * @category Linux, Windows
     */
    [[nodiscard]] static bool vbox_default_specs() {
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
#elif (WINDOWS)
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


    /**
     * @brief Check for VirtualBox network provider string
     * @category Windows
     */
    [[nodiscard]] static bool vbox_network_share() {
#if (!WINDOWS)
        return false;
#else
        u32 pnsize = 0x1000;
        TCHAR* provider = new TCHAR[pnsize];

        u32 retv = WNetGetProviderName(WNNC_NET_RDR2SAMPLE, provider, reinterpret_cast<LPDWORD>(&pnsize));
        bool result = false;

        if (retv == NO_ERROR) {
            result = (lstrcmpi(provider, _T("VirtualBox Shared Folders")) == 0);
        }

        delete[] provider;

        return result;
#endif
    }





    /**
     * @brief Check for any VM processes that are active
     * @category Windows
     */
    [[nodiscard]] static bool vm_processes() {
#if (!WINDOWS)
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
                const HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processes[i]);
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
            return core::add(brands::JOEBOX);
        }

        if (check_proc(_T("prl_cc.exe")) || check_proc(_T("prl_tools.exe"))) {
            return core::add(brands::PARALLELS);
        }

        if (check_proc(_T("vboxservice.exe")) || check_proc(_T("vboxtray.exe"))) {
            return core::add(brands::VBOX);
        }

        if (check_proc(_T("vmsrvc.exe")) || check_proc(_T("vmusrvc.exe"))) {
            return core::add(brands::VPC);
        }
        /*
                removed due to potential false positives

                if (
                    check_proc(_T("vmtoolsd.exe")) ||
                    check_proc(_T("vmwaretrat.exe")) ||
                    check_proc(_T("vmacthlp.exe")) ||
                    check_proc(_T("vmwaretray.exe")) ||
                    check_proc(_T("vmwareuser.exe")) ||
                    check_proc(_T("vmware.exe")) ||
                    check_proc(_T("vmount2.exe"))
                ) {
                    return core::add(brands::VMWARE);
                }
        */

        if (check_proc(_T("xenservice.exe")) || check_proc(_T("xsvc_depriv.exe"))) {
            return core::add(brands::XEN);
        }

        if (check_proc(_T("vm3dservice.exe"))) {
            return core::add(brands::VMWARE);
        }

        return false;
#endif
    }


    /**
     * @brief Check for default VM username and hostname for linux
     * @category Linux
     */
    [[nodiscard]] static bool linux_user_host() {
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


    /**
     * @brief Check for Gamarue ransomware technique which compares VM-specific Window product IDs
     * @category Windows
     */
    [[nodiscard]] static bool gamarue() {
#if (!WINDOWS) 
        return false;
#else
        HKEY hOpen;
        char* szBuff;
        int iBuffSize;
        LONG nRes;

        szBuff = (char*)calloc(512, sizeof(char));

        const HANDLE hMod = GetModuleHandleA("SbieDll.dll"); // Sandboxie
        if (hMod != 0) {
            free(szBuff);
            return core::add(brands::SANDBOXIE);
        }

        /* this gave a false positive
        hMod = GetModuleHandleA("dbghelp.dll"); // ThreatExpert
        if (hMod != 0) {
            free(szBuff);
            return core::add(brands::THREATEXPERT);
        }
        */

        nRes = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion", 0L, KEY_QUERY_VALUE, &hOpen);
        if (nRes == ERROR_SUCCESS) {
            iBuffSize = sizeof(szBuff);
            nRes = RegQueryValueExA(hOpen, "ProductId", NULL, NULL, (unsigned char*)szBuff, reinterpret_cast<LPDWORD>(&iBuffSize));
            if (nRes == ERROR_SUCCESS) {
                // Check if szBuff is not NULL before using strcmp
                if (szBuff == NULL) {
                    RegCloseKey(hOpen);
                    return false;
                }

                if (strcmp(szBuff, "55274-640-2673064-23950") == 0) { // joebox
                    free(szBuff);
                    return core::add(brands::JOEBOX);
                } else if (strcmp(szBuff, "76487-644-3177037-23510") == 0) { // CW Sandbox
                    free(szBuff);
                    return core::add(brands::CWSANDBOX);
                } else if (strcmp(szBuff, "76487-337-8429955-22614") == 0) { // anubis
                    free(szBuff);
                    return core::add(brands::ANUBIS);
                } else {
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


    /**
     * @brief Check if the CPU manufacturer ID matches that of a VM brand with leaf 0x40000000
     * @category x86
     */
    [[nodiscard]] static bool vmid_0x4() {
#if (!x86)
        return false;
#else
        if (!core::cpuid_supported) {
            return false;
        }

        return (
            cpu::vmid_template(cpu::leaf::hypervisor, "VMID_0x4: ") ||
            cpu::vmid_template(cpu::leaf::hypervisor + 1, "VMID_0x4 + 1: ")
        );
#endif
    }


    /**
     * @brief Check for any indication of Parallels VM through BIOS data
     * @link https://stackoverflow.com/questions/1370586/detect-if-windows-is-running-from-within-parallels
     * @category Windows
     */
    [[nodiscard]] static bool parallels() {
#if (!WINDOWS)
        return false;
#else
        std::unique_ptr<util::sys_info> info = util::make_unique<util::sys_info>();

#ifdef __VMAWARE_DEBUG__
        debug("Manufacturer: ", info->get_manufacturer());
        debug("Product Name: ", info->get_productname());
        debug("Serial No: ", info->get_serialnumber());
        debug("UUID: ", info->get_uuid());
        debug("Version: ", info->get_version());

        if (!info->get_family().empty()) {
            debug("Product family: ", info->get_family());
        }

        if (!info->get_sku().empty()) {
            debug("SKU/Configuration: ", info->get_sku());
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
            return core::add(brands::PARALLELS);
        }

        return false;
#endif
    }


    /**
     * @brief Match for QEMU CPU brands with "QEMU Virtual CPU" string
     * @category x86
     */
    [[nodiscard]] static bool cpu_brand_qemu() {
#if (!x86)
        return false;
#else
        if (!core::cpuid_supported) {
            return false;
        }

        const std::string brand = cpu::get_brand();

        std::regex qemu_pattern("QEMU Virtual CPU", std::regex_constants::icase);

        if (std::regex_match(brand, qemu_pattern)) {
            return core::add(brands::QEMU);
        }

        return false;
#endif
    }


    /**
     * @brief Check for various Bochs-related emulation oversights through CPU checks
     * @category x86
     * @note Discovered by Peter Ferrie, Senior Principal Researcher, Symantec Advanced Threat Research peter_ferrie@symantec.com
     */
    [[nodiscard]] static bool bochs_cpu() {
#if (!x86)
        return false;
#else
        if (!core::cpuid_supported) {
            return false;
        }

        const bool intel = cpu::is_intel();
        const bool amd = cpu::is_amd();

        // if neither amd or intel, return false
        if (!(intel || amd)) {
            debug("BOCHS_CPU: neither AMD or Intel detected, returned false");
            return false;
        }

        const std::string brand = cpu::get_brand();

        if (intel) {
            // technique 1: not a valid brand 
            if (brand == "              Intel(R) Pentium(R) 4 CPU        ") {
                debug("BOCHS_CPU: technique 1 found");
                return core::add(brands::BOCHS);
            }
        } else if (amd) {
            // technique 2: "processor" should have a capital P
            if (brand == "AMD Athlon(tm) processor") {
                debug("BOCHS_CPU: technique 2 found");
                return core::add(brands::BOCHS);
            }

            // technique 3: Check for absence of AMD easter egg for K7 and K8 CPUs
            constexpr u32 AMD_EASTER_EGG = 0x8fffffff; // this is the CPUID leaf of the AMD easter egg

            if (!cpu::is_leaf_supported(AMD_EASTER_EGG)) {
                return false;
            }

            u32 unused, eax = 0;
            cpu::cpuid(eax, unused, unused, unused, 1);

            auto is_k7 = [](const u32 eax) -> bool {
                const u32 family = (eax >> 8) & 0xF;
                const u32 model = (eax >> 4) & 0xF;
                const u32 extended_family = (eax >> 20) & 0xFF;

                if (family == 6 && extended_family == 0) {
                    if (model == 1 || model == 2 || model == 3 || model == 4) {
                        return true;
                    }
                }

                return false;
            };

            auto is_k8 = [](const u32 eax) -> bool {
                const u32 family = (eax >> 8) & 0xF;
                const u32 extended_family = (eax >> 20) & 0xFF;

                if (family == 0xF) {
                    if (extended_family == 0x00 || extended_family == 0x01) {
                        return true;
                    }
                }

                return false;
            };

            if (!(is_k7(eax) || is_k8(eax))) {
                return false;
            }

            u32 ecx_bochs = 0;
            cpu::cpuid(unused, unused, ecx_bochs, unused, AMD_EASTER_EGG);

            if (ecx_bochs == 0) {
                return true;
            }
        }

        return false;
#endif
    }


    /**
     * @brief Check through the motherboard and match for VirtualPC-specific string
     * @category Windows
     */
    [[nodiscard]] static bool vpc_board() {
#if (!WINDOWS)
        return false;
#else
        const bool is_vm = util::motherboard_string("Microsoft Corporation");

        if (is_vm) {
            return core::add(brands::VPC);
        }

        return false;
#endif
    }



    /**
     * @brief Check if the BIOS serial is valid (null = VM)
     * @category Windows
     */
    [[nodiscard]] static bool bios_serial() {
#if (!WINDOWS)
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


    /**
     * @brief Check for VirtualBox-specific string for shared folder ID
     * @category Windows
     * @note slightly modified code from original
     * @author @waleedassar
     * @link https://pastebin.com/xhFABpPL
     */
    [[nodiscard]] static bool vbox_shared_folders() {
#if (!WINDOWS)
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
                return core::add(brands::VBOX);
            }
        }

        // Clean up the allocated buffer
        LocalFree(provider);

        return false;

#endif
    }


    /**
     * @brief Check MSSMBIOS registry for VM-specific strings
     * @category Windows
     * @note slightly modified from original code
     * @author @waleedassar
     * @link https://pastebin.com/fPY4MiYq
     */
    [[nodiscard]] static bool mssmbios() {
#if (!WINDOWS)
        return false;
#else
        const std::string p = util::SMBIOS_string();

        if (p.empty()) {
            debug("MSSMBIOS: empty, returned false");
            return false;
        }

#ifdef __VMAWARE_DEBUG__
        debug("MSSMBIOS: string = ", p);
#endif

        bool is_vm = false;

        const bool x1 = (p == "INNOTEK GMBH");
        const bool x2 = (p == "VIRTUALBOX");
        const bool x3 = (p == "SUN MICROSYSTEMS");
        const bool x4 = (p == "VBOXVER");
        const bool x5 = (p == "VIRTUAL MACHINE");
        const bool x6 = (p == "VMware");

        if (x1 || x2 || x3 || x4 || x5 || x6) {
            is_vm = true;
        }

        if (is_vm) {
            if (x5) {
                return true; // Hyper-V and VirtualBox both have the same BIOS string with "VIRTUAL MACHINE"
            }

            if (x6) {
                return core::add(brands::VMWARE);
            } else {
                return core::add(brands::VBOX);
            }
        }

        return false;
#endif
    }


    /**
     * @brief Check if memory is too low for MacOS system
     * @category MacOS
     * @link https://evasions.checkpoint.com/techniques/macos.html
     */
    [[nodiscard]] static bool hw_memsize() {
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


    /**
     * @brief Check MacOS' IO kit registry for VM-specific strings
     * @category MacOS
     * @link https://evasions.checkpoint.com/techniques/macos.html
     */
    [[nodiscard]] static bool io_kit() {
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
                return core::add(brands::VBOX);
            }

            if (util::find(board, "VMware")) {
                return core::add(brands::VMWARE);
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
                return core::add(brands::VBOX);
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


    /**
     * @brief Check for VM-strings in ioreg commands for MacOS
     * @category MacOS
     * @link https://evasions.checkpoint.com/techniques/macos.html
     */
    [[nodiscard]] static bool ioreg_grep() {
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
                return core::add(brands::VBOX);
            }

            return false;
            };

        auto check_general = []() -> bool {
            std::unique_ptr<std::string> sys_vbox = util::sys_result("ioreg -l | grep -i -c -e \"virtualbox\" -e \"oracle\"");

            if (std::stoi(*sys_vbox) > 0) {
                return core::add(brands::VBOX);
            }

            std::unique_ptr<std::string> sys_vmware = util::sys_result("ioreg -l | grep -i -c -e \"vmware\"");

            if (std::stoi(*sys_vmware) > 0) {
                return core::add(brands::VMWARE);
            }

            return false;
            };

        auto check_rom = []() -> bool {
            std::unique_ptr<std::string> sys_rom = util::sys_result("system_profiler SPHardwareDataType | grep \"Boot ROM Version\"");
            const std::string rom = *sys_rom;

            if (util::find(rom, "VirtualBox")) {
                return core::add(brands::VBOX);
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


    /**
     * @brief Check if System Integrity Protection is disabled (likely a VM if it is)
     * @category MacOS
     * @link https://evasions.checkpoint.com/techniques/macos.html
     */
    [[nodiscard]] static bool mac_sip() {
#if (!APPLE)
        return false;
#else
        std::unique_ptr<std::string> result = util::sys_result("csrutil status");
        const std::string tmp = *result;

        debug("MAC_SIP: ", "result = ", tmp);

        return (util::find(tmp, "disabled") || (!util::find(tmp, "enabled")));
#endif
    }


    /**
     * @brief Check HKLM registries for specific VM strings
     * @category Windows
     */
    [[nodiscard]] static bool hklm_registries() {
#if (!WINDOWS)
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
                    if (strstr(buffer, comp_string) != nullptr) {
                        core::add(p_brand);
                        count++;
                    }
                } else {
                    debug("Failed to query value for \"", subKey, "\"");
                }

                RegCloseKey(hKey);
            } else {
                debug("Failed to open registry key for \"", subKey, "\"");
            }
        };

        check_key(brands::BOCHS, "HARDWARE\\Description\\System", "SystemBiosVersion", "BOCHS");
        check_key(brands::BOCHS, "HARDWARE\\Description\\System", "VideoBiosVersion", "BOCHS");

        check_key(brands::ANUBIS, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "ProductID", "76487-337-8429955-22614");
        check_key(brands::ANUBIS, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductID", "76487-337-8429955-22614");

        check_key(brands::CWSANDBOX, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "ProductID", "76487-644-3177037-23510");
        check_key(brands::CWSANDBOX, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductID", "76487-644-3177037-23510");

        check_key(brands::JOEBOX, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion", "ProductID", "55274-640-2673064-23950");
        check_key(brands::JOEBOX, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductID", "55274-640-2673064-23950");

        check_key(brands::PARALLELS, "HARDWARE\\Description\\System", "SystemBiosVersion", "PARALLELS");
        check_key(brands::PARALLELS, "HARDWARE\\Description\\System", "VideoBiosVersion", "PARALLELS");

        check_key(brands::QEMU, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier", "QEMU");
        check_key(brands::QEMU, "HARDWARE\\Description\\System", "SystemBiosVersion", "QEMU");
        check_key(brands::QEMU, "HARDWARE\\Description\\System", "VideoBiosVersion", "QEMU");
        check_key(brands::QEMU, "HARDWARE\\Description\\System\\BIOS", "SystemManufacturer", "QEMU");

        check_key(brands::VBOX, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier", "VBOX");
        check_key(brands::VBOX, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier", "VBOX");
        check_key(brands::VBOX, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier", "VBOX");
        check_key(brands::VBOX, "HARDWARE\\Description\\System", "SystemBiosVersion", "VBOX");
        check_key(brands::VBOX, "HARDWARE\\DESCRIPTION\\System", "SystemBiosDate", "06/23/99");
        check_key(brands::VBOX, "HARDWARE\\Description\\System", "VideoBiosVersion", "VIRTUALBOX");
        check_key(brands::VBOX, "HARDWARE\\Description\\System\\BIOS", "SystemProductName", "VIRTUAL");
        check_key(brands::VBOX, "SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "DeviceDesc", "VBOX");
        check_key(brands::VBOX, "SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "FriendlyName", "VBOX");
        check_key(brands::VBOX, "SYSTEM\\ControlSet002\\Services\\Disk\\Enum", "DeviceDesc", "VBOX");
        check_key(brands::VBOX, "SYSTEM\\ControlSet002\\Services\\Disk\\Enum", "FriendlyName", "VBOX");
        check_key(brands::VBOX, "SYSTEM\\ControlSet003\\Services\\Disk\\Enum", "DeviceDesc", "VBOX");
        check_key(brands::VBOX, "SYSTEM\\ControlSet003\\Services\\Disk\\Enum", "FriendlyName", "VBOX");
        check_key(brands::VBOX, "SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemProductName", "VIRTUAL");
        check_key(brands::VBOX, "SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemProductName", "VIRTUALBOX");

        check_key(brands::VMWARE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier", "VMWARE");
        check_key(brands::VMWARE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier", "VMWARE");
        check_key(brands::VMWARE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier", "VMWARE");
        check_key(brands::VMWARE, "HARDWARE\\Description\\System", "SystemBiosVersion", "VMWARE");
        check_key(brands::VMWARE, "HARDWARE\\Description\\System", "SystemBiosVersion", "INTEL - 6040000");
        check_key(brands::VMWARE, "HARDWARE\\Description\\System", "VideoBiosVersion", "VMWARE");
        check_key(brands::VMWARE, "HARDWARE\\Description\\System\\BIOS", "SystemProductName", "VMware");
        check_key(brands::VMWARE, "HARDWARE\\Description\\System\\BIOS", "SystemManufacturer", "VMware, Inc.");
        check_key(brands::VMWARE, "SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "0", "VMware");
        check_key(brands::VMWARE, "SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "1", "VMware");
        check_key(brands::VMWARE, "SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "DeviceDesc", "VMware");
        check_key(brands::VMWARE, "SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "FriendlyName", "VMware");
        check_key(brands::VMWARE, "SYSTEM\\ControlSet002\\Services\\Disk\\Enum", "DeviceDesc", "VMware");
        check_key(brands::VMWARE, "SYSTEM\\ControlSet002\\Services\\Disk\\Enum", "FriendlyName", "VMware");
        check_key(brands::VMWARE, "SYSTEM\\ControlSet003\\Services\\Disk\\Enum", "DeviceDesc", "VMware");
        check_key(brands::VMWARE, "SYSTEM\\ControlSet003\\Services\\Disk\\Enum", "FriendlyName", "VMware");
        //check_key(HKCR\Installer\Products 	ProductName 	vmware tools
        //check_key(HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall 	DisplayName 	vmware tools
        check_key(brands::VMWARE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", "DisplayName", "vmware tools");
        check_key(brands::VMWARE, "SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000", "CoInstallers32", "*vmx*");
        check_key(brands::VMWARE, "SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000", "DriverDesc", "VMware*");
        check_key(brands::VMWARE, "SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000", "InfSection", "vmx*");
        check_key(brands::VMWARE, "SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000", "ProviderName", "VMware*");
        check_key(brands::VMWARE, "SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\Settings", "Device Description", "VMware*");
        check_key(brands::VMWARE, "SYSTEM\\CurrentControlSet\\Control\\SystemInformation", "SystemProductName", "VMWARE");
        check_key(brands::VMWARE, "SYSTEM\\CurrentControlSet\\Control\\Video\\{GUID}\\Video", "Service", "vm3dmp");
        check_key(brands::VMWARE, "SYSTEM\\CurrentControlSet\\Control\\Video\\{GUID}\\Video", "Service", "vmx_svga");
        check_key(brands::VMWARE, "SYSTEM\\CurrentControlSet\\Control\\Video\\{GUID}\\0000", "Device Description", "VMware SVGA*");
        check_key(brands::VMWARE, "SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum", "0", "VMWare");
        check_key(brands::VMWARE, "HARDWARE\\ACPI\\DSDT\\PTLTD_\\CUSTOM__\\00000000", "00000000", "VMWARE");

        check_key(brands::XEN, "HARDWARE\\Description\\System\\BIOS", "SystemProductName", "Xen");

        return (count > 0);
#endif
    }


    /**
     * @brief Check for "qemu-ga" process
     * @category Linux
     */
    [[nodiscard]] static bool qemu_ga() {
#if (!LINUX)
        return false;
#else
        constexpr const char* process = "qemu-ga";

        if (util::is_proc_running(process)) {
            return core::add(brands::QEMU);
        }

        return false;
#endif
    }


    /**
     * @brief Check for valid MSR value 0x40000000
     * @category Windows
     * @author LukeGoule
     * @link https://github.com/LukeGoule/compact_vm_detector/tree/main
     * @copyright MIT
     */
    [[nodiscard]] static bool valid_msr() {
    #if (!WINDOWS)
            return false;
    #else
            if (!util::is_admin()) {
                return false;
            }

            __try {
                __readmsr(0x40000000);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                return false;
            }

            return true;
    #endif
    }


    /**
     * @brief Check for QEMU processes
     * @category Windows
     */
    [[nodiscard]] static bool qemu_processes() {
#if (!WINDOWS)
        return false;
#else
        constexpr std::array<const TCHAR*, 3> qemu_proc_strings = {{
            _T("qemu-ga.exe"),
            _T("vdagent.exe"),
            _T("vdservice.exe")
        }};

        for (const auto str : qemu_proc_strings) {
            if (util::is_proc_running(str)) {
                return core::add(brands::QEMU);
            }
        }

        return false;
#endif
    }


    /**
     * @brief Check for VPC processes
     * @category Windows
     */
    [[nodiscard]] static bool vpc_proc() {
#if (!WINDOWS)
        return false;
#else
        constexpr std::array<const TCHAR*, 2> vpc_proc_strings = {{
            _T("VMSrvc.exe"),
            _T("VMUSrvc.exe")
        }};

        for (const auto str : vpc_proc_strings) {
            if (util::is_proc_running(str)) {
                return core::add(brands::VPC);
            }
        }

        return false;
#endif
    }


    /**
     * @brief Check for official VPC method
     * @category Windows, x86
     */
    [[nodiscard]] static bool vpc_invalid() {
#if (!WINDOWS || !x86)
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
     * @brief Check for sidt instruction method
     * @category Linux, Windows, x86
     */
    [[nodiscard]] static bool sidt() {
        // gcc/g++ causes a stack smashing error at runtime for some reason
        if (GCC) {
            return false;
        }

        u8 idtr[10]{};
        u32 idt_entry = 0;

#if (WINDOWS)
#   if (x86_32)
        _asm sidt idtr
#   elif (x86)
#       pragma pack(1)
        struct IDTR {
            u16 limit;
            u64 base;
        };
#       pragma pack()

        IDTR idtrStruct;
        __sidt(&idtrStruct);
        std::memcpy(idtr, &idtrStruct, sizeof(IDTR));
#   else
        return false;
#   endif

        idt_entry = *reinterpret_cast<unsigned long*>(&idtr[2]);
#elif (LINUX)
        // false positive with root for some reason
        if (util::is_admin()) {
            return false;
        }

        if (!util::exists("/dev/mem")) {
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
            return core::add(brands::VMWARE);
        }

        return false;
    }


    /**
     * @brief Check for sgdt instruction method
     * @category Windows, x86
     */
    [[nodiscard]] static bool sgdt() {
#if (x86_32 && WINDOWS)
        u8 gdtr[6]{};
        u32 gdt = 0;

        _asm sgdt gdtr
        gdt = *((unsigned long*)&gdtr[2]);

        return ((gdt >> 24) == 0xFF);
#else
        return false;
#endif
    }


    /**
     * @brief Check for sldt instruction method
     * @category Windows, x86
     * @note code documentation paper in https://www.aldeid.com/wiki/X86-assembly/Instructions/sldt
     */
    [[nodiscard]] static bool sldt() {
#if (!MSVC && WINDOWS)
        unsigned char ldtr[5] = "\xef\xbe\xad\xde";
        unsigned long ldt = 0;

        __asm {
            sldt word ptr ldtr  // 'word ptr' to indicate that we're working with a 16-bit value and avoid compiler warnings
        }

        ldt = *((unsigned long*)&ldtr[0]);

        return (ldt != 0xdead0000);
#else
        return false;
#endif
    }


    /**
     * @brief Check for Offensive Security sidt method
     * @category Windows, x86
     * @author Danny Quist (chamuco@gmail.com)
     * @author Val Smith (mvalsmith@metasploit.com)
     * @note code documentation paper in /papers/www.offensivecomputing.net_vm.pdf
     */
    [[nodiscard]] static bool offsec_sidt() {
#if (!MSVC && WINDOWS)
        unsigned char m[6]{};
        __asm sidt m;

        return (m[5] > 0xD0);
#else
        return false;
#endif
    }


    /**
     * @brief Check for Offensive Security sgdt method
     * @category Windows, x86
     * @author Danny Quist (chamuco@gmail.com)
     * @author Val Smith (mvalsmith@metasploit.com)
     * @note code documentation paper in /papers/www.offensivecomputing.net_vm.pdf
     */
    [[nodiscard]] static bool offsec_sgdt() {
#if (!MSVC && WINDOWS)
        unsigned char m[6]{};
        __asm sgdt m;

        return (m[5] > 0xD0);
#else
        return false;
#endif
    }


    /**
     * @brief Check for Offensive Security sldt method
     * @category Windows, x86
     * @author Danny Quist (chamuco@gmail.com)
     * @author Val Smith (mvalsmith@metasploit.com)
     * @note code documentation paper in /papers/www.offensivecomputing.net_vm.pdf
     */
    [[nodiscard]] static bool offsec_sldt() {
#if (!WINDOWS || !x86)
        return false;
#elif (x86_32)
        unsigned short m[6]{};
        __asm sldt m;

        return (m[0] != 0x00 && m[1] != 0x00);
#else
        return false;
#endif
    }


    /**
     * @brief Check for Hyper-V specific string in motherboard
     * @category Windows
     */
    [[nodiscard]] static bool hyperv_board() {
#if (!WINDOWS)
        return false;
#else
        if (!wmi::initialize()) {
            core_debug("Failed to initialize WMI in hyperv_board");
            return false;
        }

        wmi_result results = wmi::execute(L"SELECT * FROM Win32_BaseBoard", { L"Manufacturer" });

        for (const auto& res : results) {
            if (res.type == wmi::result_type::String) {
                if (_stricmp(res.strValue.c_str(), "Microsoft Corporation Virtual Machine") == 0) {
                    return core::add(brands::HYPERV);
                }
            }
        }

        return false; // No match found
#endif
    }


    /**
     * @brief Check for VPC and Parallels files
     * @category Windows
     */
    [[nodiscard]] static bool vm_files_extra() {
#if (!WINDOWS)
        return false;
#else
        constexpr std::array<std::pair<const char*, const char*>, 9> files = {{
            { brands::VPC, "c:\\windows\\system32\\drivers\\vmsrvc.sys" },
            { brands::VPC, "c:\\windows\\system32\\drivers\\vpc-s3.sys" },
            { brands::PARALLELS, "c:\\windows\\system32\\drivers\\prleth.sys" },
            { brands::PARALLELS, "c:\\windows\\system32\\drivers\\prlfs.sys" },
            { brands::PARALLELS, "c:\\windows\\system32\\drivers\\prlmouse.sys" },
            { brands::PARALLELS, "c:\\windows\\system32\\drivers\\prlvideo.sys" },
            { brands::PARALLELS, "c:\\windows\\system32\\drivers\\prltime.sys" },
            { brands::PARALLELS, "c:\\windows\\system32\\drivers\\prl_pv32.sys" },
            { brands::PARALLELS, "c:\\windows\\system32\\drivers\\prl_paravirt_32.sys" }
        }};

        for (const auto& file_pair : files) {
            if (util::exists(file_pair.second)) {
                return core::add(file_pair.first);
            }
        }

        return false;
#endif
    }


    /**
     * @brief Check for sidt method with VPC's 0xE8XXXXXX range
     * @category Windows, x86
     * @note Idea from Tom Liston and Ed Skoudis' paper "On the Cutting Edge: Thwarting Virtual Machine Detection"
     * @note Paper situated at /papers/ThwartingVMDetection_Liston_Skoudis.pdf
     */
    [[nodiscard]] static bool vpc_sidt() {
#if (!WINDOWS || !x86)
        return false;
#elif (x86_32)
        u8	idtr[6]{};
        u32	idt = 0;

        _asm sidt idtr
        idt = *((unsigned long*)&idtr[2]);

        if ((idt >> 24) == 0xE8) {
            return core::add(brands::VPC);
        }

        return false;
#else
        return false;
#endif
    }


    /**
     * @brief Check for VMware string in /proc/iomem
     * @category Linux
     * @note idea from ScoopyNG by Tobias Klein
     */
    [[nodiscard]] static bool vmware_iomem() {
#if (!LINUX)
        return false;
#else
        const std::string iomem_file = util::read_file("/proc/iomem");

        if (util::find(iomem_file, "VMware")) {
            return core::add(brands::VMWARE);
        }

        return false;
#endif
    }


    /**
     * @brief Check for VMware string in /proc/ioports
     * @category Windows
     * @note idea from ScoopyNG by Tobias Klein
     */
    [[nodiscard]] static bool vmware_ioports() {
#if (!LINUX)
        return false;
#else
        const std::string ioports_file = util::read_file("/proc/ioports");

        if (util::find(ioports_file, "VMware")) {
            return core::add(brands::VMWARE);
        }

        return false;
#endif
    }


    /**
     * @brief Check for VMware string in /proc/scsi/scsi
     * @category Windows
     * @note idea from ScoopyNG by Tobias Klein
     */
    [[nodiscard]] static bool vmware_scsi() {
#if (!LINUX)
        return false;
#else
        const std::string scsi_file = util::read_file("/proc/scsi/scsi");

        if (util::find(scsi_file, "VMware")) {
            return core::add(brands::VMWARE);
        }

        return false;
#endif
    }


    /**
     * @brief Check for VMware-specific device name in dmesg output
     * @category Windows
     * @note idea from ScoopyNG by Tobias Klein
     */
    [[nodiscard]] static bool vmware_dmesg() {
#if (!LINUX)
        return false;
#else
        if (!util::is_admin()) {
            return false;
        }

        if (!util::exists("/usr/bin/dmesg")) {
            return false;
        }

        auto dmesg_output = util::sys_result("dmesg");
        const std::string dmesg = *dmesg_output;

        if (dmesg.empty()) {
            return false;
        }

        if (util::find(dmesg, "BusLogic BT-958")) {
            return core::add(brands::VMWARE);
        }

        if (util::find(dmesg, "pcnet32")) {
            return core::add(brands::VMWARE);
        }

        return false;
#endif
    }


    /**
     * @brief Check str assembly instruction method for VMware
     * @note Alfredo Omella's (S21sec) STR technique
     * @note paper describing this technique is located at /papers/www.s21sec.com_vmware-eng.pdf (2006)
     * @category Windows
     */
        [[nodiscard]] static bool vmware_str() {
#if (WINDOWS && x86_32)
        unsigned short tr = 0;
        __asm {
            str ax
            mov tr, ax
        }
        if ((tr & 0xFF) == 0x00 && ((tr >> 8) & 0xFF) == 0x40) {
            return core::add(brands::VMWARE);
        }
#endif
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
#if (!WINDOWS || !x86)
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
                case 1:  return core::add(brands::VMWARE_EXPRESS);
                case 2:  return core::add(brands::VMWARE_ESX);
                case 3:  return core::add(brands::VMWARE_GSX);
                case 4:  return core::add(brands::VMWARE_WORKSTATION);
                default: return core::add(brands::VMWARE);
            }
        }
#endif
        return false;
    }


    /**
     * @brief Check for VMware memory using IO port backdoor
     * @category Windows, x86
     * @note Code from ScoopyNG by Tobias Klein
     * @copyright BSD clause 2
     */
    [[nodiscard]] static bool vmware_port_memory() {
#if (!WINDOWS || !x86)
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
            return core::add(brands::VMWARE);
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
    [[nodiscard]] static bool smsw() {
#if (!WINDOWS || !x86)
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


    /**
     * @brief Check for mutex strings of VM brands
     * @category Windows, x86
     * @note from VMDE project
     * @author hfiref0x
     * @copyright MIT
     */
    [[nodiscard]] static bool mutex() {
#if (!WINDOWS)
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
            return core::add(brands::SANDBOXIE);
        }

        if (supMutexExist("MicrosoftVirtualPC7UserServiceMakeSureWe'reTheOnlyOneMutex")) {
            return core::add(brands::VPC);
        }

        if (supMutexExist("Frz_State")) {
            return true;
        }

        return false;
#endif
    }


    /**
     * @brief Check if uptime is less than or equal to 2 minutes
     * @category Windows, Linux
     * @note https://stackoverflow.com/questions/30095439/how-do-i-get-system-up-time-in-milliseconds-in-c
     */
    [[nodiscard]] static bool uptime() {
        constexpr u32 uptime_ms = 1000 * 60 * 2;
        constexpr u32 uptime_s = 60 * 2;

#if (WINDOWS)
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

        return (uptime < std::chrono::milliseconds(uptime_ms));
#else
        return false;
#endif
    }


    /**
     * @brief Check for odd CPU threads, usually a sign of modification through VM setting because 99% of CPUs have even numbers of threads
     * @category All, x86
     */
    [[nodiscard]] static bool odd_cpu_threads() {
#if (!x86)
        return false;
#else
        const u32 threads = std::thread::hardware_concurrency();

        struct cpu::stepping_struct steps = cpu::fetch_steppings();

        debug("ODD_CPU_THREADS: model    = ", static_cast<u32>(steps.model));
        debug("ODD_CPU_THREADS: family   = ", static_cast<u32>(steps.family));
        debug("ODD_CPU_THREADS: extmodel = ", static_cast<u32>(steps.extmodel));

        // check if the microarchitecture was made before 2006, which was around the time multi-core processors were implemented
        auto old_microarchitecture = [&steps]() -> bool {
            constexpr std::array<std::array<u8, 3>, 32> old_archs = {{
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
            }};

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
        if (cpu::is_celeron(steps)) {
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


    /**
     * @brief Check for Intel CPU thread count database if it matches the system's thread count
     * @category All, x86
     * @link https://en.wikipedia.org/wiki/List_of_Intel_Core_processors
     */
    [[nodiscard]] static bool intel_thread_mismatch() {
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

#if (WINDOWS)
        if (util::does_threadcount_mismatch()) {
            debug("INTEL_THREAD_MISMATCH: Thread tampering detected");
            return true;
        }
#endif

        debug("INTEL_THREAD_MISMATCH: CPU model = ", model.string);

        std::map<const char*, u8> thread_database = {
            // i3 series
            { "i3-1000G1", 4 },
            { "i3-1000G4", 4 },
            { "i3-1000NG4", 4 },
            { "i3-1005G1", 4 },
            { "i3-10100", 8 },
            { "i3-10100E", 8 },
            { "i3-10100F", 8 },
            { "i3-10100T", 8 },
            { "i3-10100TE", 8 },
            { "i3-10100Y", 4 },
            { "i3-10105", 8 },
            { "i3-10105F", 8 },
            { "i3-10105T", 8 },
            { "i3-10110U", 4 },
            { "i3-10110Y", 4 },
            { "i3-10300", 8 },
            { "i3-10300T", 8 },
            { "i3-10305", 8 },
            { "i3-10305T", 8 },
            { "i3-10320", 8 },
            { "i3-10325", 8 },
            { "i3-11100B", 8 },
            { "i3-11100HE", 8 },
            { "i3-1110G4", 4 },
            { "i3-1115G4E", 4 },
            { "i3-1115GRE", 4 },
            { "i3-1120G4", 8 },
            { "i3-12100", 8 },
            { "i3-12100F", 8 },
            { "i3-12100T", 8 },
            { "i3-1210U", 4 },
            { "i3-1215U", 4 },
            { "i3-1215UE", 4 },
            { "i3-1215UL", 4 },
            { "i3-12300", 8 },
            { "i3-12300T", 8 },
            { "i3-13100", 8 },
            { "i3-13100F", 8 },
            { "i3-13100T", 8 },
            { "i3-1315U", 4 },
            { "i3-1315UE", 4 },
            { "i3-14100", 8 },
            { "i3-14100F", 8 },
            { "i3-14100T", 8 },
            { "i3-2100", 4 },
            { "i3-2100T", 4 },
            { "i3-2102", 4 },
            { "i3-2105", 4 },
            { "i3-2120", 4 },
            { "i3-2120T", 4 },
            { "i3-2125", 4 },
            { "i3-2130", 4 },
            { "i3-2308M", 4 },
            { "i3-2310E", 4 },
            { "i3-2310M", 4 },
            { "i3-2312M", 4 },
            { "i3-2328M", 4 },
            { "i3-2330E", 4 },
            { "i3-2330M", 4 },
            { "i3-2332M", 4 },
            { "i3-2340UE", 4 },
            { "i3-2348M", 4 },
            { "i3-2350LM", 4 },
            { "i3-2350M", 4 },
            { "i3-2355M", 4 },
            { "i3-2357M", 4 },
            { "i3-2365M", 4 },
            { "i3-2367M", 4 },
            { "i3-2370LM", 4 },
            { "i3-2370M", 4 },
            { "i3-2375M", 4 },
            { "i3-2377M", 4 },
            { "i3-2390M", 4 },
            { "i3-2393M", 4 },
            { "i3-2394M", 4 },
            { "i3-2395M", 4 },
            { "i3-2397M", 4 },
            { "i3-3110M", 4 },
            { "i3-3115C", 4 },
            { "i3-3120M", 4 },
            { "i3-3120ME", 4 },
            { "i3-3130M", 4 },
            { "i3-3210", 4 },
            { "i3-3217U", 4 },
            { "i3-3217UE", 4 },
            { "i3-3220", 4 },
            { "i3-3220T", 4 },
            { "i3-3225", 4 },
            { "i3-3227U", 4 },
            { "i3-3229Y", 4 },
            { "i3-3240", 4 },
            { "i3-3240T", 4 },
            { "i3-3245", 4 },
            { "i3-3250", 4 },
            { "i3-3250T", 4 },
            { "i3-330E", 4 },
            { "i3-330M", 4 },
            { "i3-330UM", 4 },
            { "i3-350M", 4 },
            { "i3-370M", 4 },
            { "i3-380M", 4 },
            { "i3-380UM", 4 },
            { "i3-390M", 4 },
            { "i3-4000M", 4 },
            { "i3-4005U", 4 },
            { "i3-4010M", 4 },
            { "i3-4010U", 4 },
            { "i3-4010Y", 4 },
            { "i3-4012Y", 4 },
            { "i3-4020Y", 4 },
            { "i3-4025U", 4 },
            { "i3-4030U", 4 },
            { "i3-4030Y", 4 },
            { "i3-4100E", 4 },
            { "i3-4100M", 4 },
            { "i3-4100U", 4 },
            { "i3-4102E", 4 },
            { "i3-4110E", 4 },
            { "i3-4110M", 4 },
            { "i3-4112E", 4 },
            { "i3-4120U", 4 },
            { "i3-4130", 4 },
            { "i3-4130T", 4 },
            { "i3-4150", 4 },
            { "i3-4150T", 4 },
            { "i3-4158U", 4 },
            { "i3-4160", 4 },
            { "i3-4160T", 4 },
            { "i3-4170", 4 },
            { "i3-4170T", 4 },
            { "i3-4330", 4 },
            { "i3-4330T", 4 },
            { "i3-4330TE", 4 },
            { "i3-4340", 4 },
            { "i3-4340TE", 4 },
            { "i3-4350", 4 },
            { "i3-4350T", 4 },
            { "i3-4360", 4 },
            { "i3-4360T", 4 },
            { "i3-4370", 4 },
            { "i3-4370T", 4 },
            { "i3-5005U", 4 },
            { "i3-5010U", 4 },
            { "i3-5015U", 4 },
            { "i3-5020U", 4 },
            { "i3-5157U", 4 },
            { "i3-530", 4 },
            { "i3-540", 4 },
            { "i3-550", 4 },
            { "i3-560", 4 },
            { "i3-6006U", 4 },
            { "i3-6098P", 4 },
            { "i3-6100", 4 },
            { "i3-6100E", 4 },
            { "i3-6100H", 4 },
            { "i3-6100T", 4 },
            { "i3-6100TE", 4 },
            { "i3-6100U", 4 },
            { "i3-6102E", 4 },
            { "i3-6120T", 4 },
            { "i3-6157U", 4 },
            { "i3-6167U", 4 },
            { "i3-6300", 4 },
            { "i3-6300T", 4 },
            { "i3-6320", 4 },
            { "i3-6320T", 4 },
            { "i3-7007U", 4 },
            { "i3-7020U", 4 },
            { "i3-7100", 4 },
            { "i3-7100E", 4 },
            { "i3-7100H", 4 },
            { "i3-7100T", 4 },
            { "i3-7100U", 4 },
            { "i3-7101E", 4 },
            { "i3-7101TE", 4 },
            { "i3-7102E", 4 },
            { "i3-7110U", 4 },
            { "i3-7120", 4 },
            { "i3-7120T", 4 },
            { "i3-7130U", 4 },
            { "i3-7167U", 4 },
            { "i3-7300", 4 },
            { "i3-7300T", 4 },
            { "i3-7310T", 4 },
            { "i3-7310U", 4 },
            { "i3-7320", 4 },
            { "i3-7320T", 4 },
            { "i3-7340", 4 },
            { "i3-7350K", 4 },
            { "i3-8000", 4 },
            { "i3-8000T", 4 },
            { "i3-8020", 4 },
            { "i3-8020T", 4 },
            { "i3-8100", 4 },
            { "i3-8100B", 4 },
            { "i3-8100F", 4 },
            { "i3-8100H", 4 },
            { "i3-8100T", 4 },
            { "i3-8109U", 4 },
            { "i3-8120", 4 },
            { "i3-8120T", 4 },
            { "i3-8121U", 4 },
            { "i3-8130U", 4 },
            { "i3-8130U", 4 },
            { "i3-8140U", 4 },
            { "i3-8145U", 4 },
            { "i3-8145UE", 4 },
            { "i3-8300", 4 },
            { "i3-8300T", 4 },
            { "i3-8320", 4 },
            { "i3-8320T", 4 },
            { "i3-8350K", 4 },
            { "i3-9100", 4 },
            { "i3-9100E", 4 },
            { "i3-9100F", 4 },
            { "i3-9100HL", 4 },
            { "i3-9100T", 4 },
            { "i3-9100TE", 4 },
            { "i3-9300", 4 },
            { "i3-9300T", 4 },
            { "i3-9320", 4 },
            { "i3-9350K", 4 },
            { "i3-9350KF", 4 },
            { "i3-N300", 8 },
            { "i3-N305", 8 },

            // i5 series
            { "i5-10200H", 8 },
            { "i5-10210U", 4 },
            { "i5-10210Y", 8 },
            { "i5-10300H", 8 },
            { "i5-1030G4", 8 },
            { "i5-1030G7", 8 },
            { "i5-1030NG7", 8 },
            { "i5-10310U", 4 },
            { "i5-10310Y", 8 },
            { "i5-1035G1", 8 },
            { "i5-1035G4", 8 },
            { "i5-1035G7", 8 },
            { "i5-1038NG7", 8 },
            { "i5-10400", 12 },
            { "i5-10400F", 12 },
            { "i5-10400H", 8 },
            { "i5-10400T", 12 },
            { "i5-10500", 12 },
            { "i5-10500E", 12 },
            { "i5-10500H", 12 },
            { "i5-10500T", 12 },
            { "i5-10500TE", 12 },
            { "i5-10505", 12 },
            { "i5-10600", 12 },
            { "i5-10600K", 12 },
            { "i5-10600KF", 12 },
            { "i5-10600T", 12 },
            { "i5-1115G4", 4 },
            { "i5-1125G4", 8 },
            { "i5-11260H", 12 },
            { "i5-11300H", 8 },
            { "i5-1130G7", 8 },
            { "i5-11320H", 8 },
            { "i5-1135G7", 8 },
            { "i5-11400", 12 },
            { "i5-11400F", 12 },
            { "i5-11400H", 12 },
            { "i5-11400T", 12 },
            { "i5-1140G7", 8 },
            { "i5-1145G7", 8 },
            { "i5-1145G7E", 8 },
            { "i5-1145GRE", 8 },
            { "i5-11500", 12 },
            { "i5-11500B", 12 },
            { "i5-11500H", 12 },
            { "i5-11500HE", 12 },
            { "i5-11500T", 12 },
            { "i5-1155G7", 8 },
            { "i5-11600", 12 },
            { "i5-11600K", 12 },
            { "i5-11600KF", 12 },
            { "i5-11600T", 12 },
            { "i5-1230U", 4 },
            { "i5-1235U", 4 },
            { "i5-12400", 12 },
            { "i5-12400F", 12 },
            { "i5-12400T", 12 },
            { "i5-1240P", 8 },
            { "i5-1240U", 4 },
            { "i5-1245U", 4 },
            { "i5-12490F", 12 },
            { "i5-12500", 12 },
            { "i5-12500H", 8 },
            { "i5-12500HL", 8 },
            { "i5-12500T", 12 },
            { "i5-1250P", 8 },
            { "i5-1250PE", 8 },
            { "i5-12600", 12 },
            { "i5-12600H", 8 },
            { "i5-12600HE", 8 },
            { "i5-12600HL", 8 },
            { "i5-12600HX", 8 },
            { "i5-12600K", 12 },
            { "i5-12600KF", 12 },
            { "i5-12600T", 12 },
            { "i5-13400", 12 },
            { "i5-13400F", 12 },
            { "i5-13400T", 12 },
            { "i5-1340P", 8 },
            { "i5-1340PE", 8 },
            { "i5-13490F", 12 },
            { "i5-13500", 12 },
            { "i5-13500H", 8 },
            { "i5-13500T", 12 },
            { "i5-13505H", 8 },
            { "i5-1350P", 8 },
            { "i5-1350PE", 8 },
            { "i5-13600", 12 },
            { "i5-13600H", 8 },
            { "i5-13600HE", 8 },
            { "i5-13600K", 12 },
            { "i5-13600K", 20 },
            { "i5-13600KF", 12 },
            { "i5-13600KF", 20 },
            { "i5-13600T", 12 },
            { "i5-2300", 4 },
            { "i5-2310", 4 },
            { "i5-2320", 4 },
            { "i5-2380P", 4 },
            { "i5-2390T", 4 },
            { "i5-2400", 4 },
            { "i5-2400S", 4 },
            { "i5-2405S", 4 },
            { "i5-2410M", 4 },
            { "i5-2415M", 4 },
            { "i5-2430M", 4 },
            { "i5-2435M", 4 },
            { "i5-2450M", 4 },
            { "i5-2450P", 4 },
            { "i5-2467M", 4 },
            { "i5-2475M", 4 },
            { "i5-2477M", 4 },
            { "i5-2487M", 4 },
            { "i5-2490M", 4 },
            { "i5-2497M", 4 },
            { "i5-2500", 4 },
            { "i5-2500K", 4 },
            { "i5-2500S", 4 },
            { "i5-2500T", 4 },
            { "i5-2510E", 4 },
            { "i5-2515E", 4 },
            { "i5-2520M", 4 },
            { "i5-2537M", 4 },
            { "i5-2540LM", 4 },
            { "i5-2540M", 4 },
            { "i5-2547M", 4 },
            { "i5-2550K", 4 },
            { "i5-2557M", 4 },
            { "i5-2560LM", 4 },
            { "i5-2560M", 4 },
            { "i5-2580M", 4 },
            { "i5-3210M", 4 },
            { "i5-3230M", 4 },
            { "i5-3317U", 4 },
            { "i5-3320M", 4 },
            { "i5-3330", 4 },
            { "i5-3330S", 4 },
            { "i5-3335S", 4 },
            { "i5-3337U", 4 },
            { "i5-3339Y", 4 },
            { "i5-3340", 4 },
            { "i5-3340M", 4 },
            { "i5-3340S", 4 },
            { "i5-3350P", 4 },
            { "i5-3360M", 4 },
            { "i5-3380M", 4 },
            { "i5-3427U", 4 },
            { "i5-3437U", 4 },
            { "i5-3439Y", 4 },
            { "i5-3450", 4 },
            { "i5-3450S", 4 },
            { "i5-3470", 4 },
            { "i5-3470S", 4 },
            { "i5-3470T", 4 },
            { "i5-3475S", 4 },
            { "i5-3550", 4 },
            { "i5-3550S", 4 },
            { "i5-3570", 4 },
            { "i5-3570K", 4 },
            { "i5-3570S", 4 },
            { "i5-3570T", 4 },
            { "i5-3610ME", 4 },
            { "i5-4200H", 4 },
            { "i5-4200M", 4 },
            { "i5-4200U", 4 },
            { "i5-4200Y", 4 },
            { "i5-4202Y", 4 },
            { "i5-4210H", 4 },
            { "i5-4210M", 4 },
            { "i5-4210U", 4 },
            { "i5-4210Y", 4 },
            { "i5-4220Y", 4 },
            { "i5-4250U", 4 },
            { "i5-4258U", 4 },
            { "i5-4260U", 4 },
            { "i5-4278U", 4 },
            { "i5-4288U", 4 },
            { "i5-4300M", 4 },
            { "i5-4300U", 4 },
            { "i5-4300Y", 4 },
            { "i5-4302Y", 4 },
            { "i5-4308U", 4 },
            { "i5-430M", 4 },
            { "i5-430UM", 4 },
            { "i5-4310M", 4 },
            { "i5-4310U", 4 },
            { "i5-4330M", 4 },
            { "i5-4340M", 4 },
            { "i5-4350U", 4 },
            { "i5-4360U", 4 },
            { "i5-4400E", 4 },
            { "i5-4402E", 4 },
            { "i5-4402EC", 4 },
            { "i5-4410E", 4 },
            { "i5-4422E", 4 },
            { "i5-4430", 4 },
            { "i5-4430S", 4 },
            { "i5-4440", 4 },
            { "i5-4440S", 4 },
            { "i5-4460", 4 },
            { "i5-4460S", 4 },
            { "i5-4460T", 4 },
            { "i5-4470", 4 },
            { "i5-450M", 4 },
            { "i5-4570", 4 },
            { "i5-4570R", 4 },
            { "i5-4570S", 4 },
            { "i5-4570T", 4 },
            { "i5-4570TE", 4 },
            { "i5-4590", 4 },
            { "i5-4590S", 4 },
            { "i5-4590T", 4 },
            { "i5-460M", 4 },
            { "i5-4670", 4 },
            { "i5-4670K", 4 },
            { "i5-4670R", 4 },
            { "i5-4670S", 4 },
            { "i5-4670T", 4 },
            { "i5-4690", 4 },
            { "i5-4690K", 4 },
            { "i5-4690S", 4 },
            { "i5-4690T", 4 },
            { "i5-470UM", 4 },
            { "i5-480M", 4 },
            { "i5-5200U", 4 },
            { "i5-520E", 4 },
            { "i5-520M", 4 },
            { "i5-520UM", 4 },
            { "i5-5250U", 4 },
            { "i5-5257U", 4 },
            { "i5-5287U", 4 },
            { "i5-5300U", 4 },
            { "i5-5350H", 4 },
            { "i5-5350U", 4 },
            { "i5-540M", 4 },
            { "i5-540UM", 4 },
            { "i5-5575R", 4 },
            { "i5-560M", 4 },
            { "i5-560UM", 4 },
            { "i5-5675C", 4 },
            { "i5-5675R", 4 },
            { "i5-580M", 4 },
            { "i5-6198DU", 4 },
            { "i5-6200U", 4 },
            { "i5-6260U", 4 },
            { "i5-6267U", 4 },
            { "i5-6287U", 4 },
            { "i5-6300HQ", 4 },
            { "i5-6300U", 4 },
            { "i5-6350HQ", 4 },
            { "i5-6360U", 4 },
            { "i5-6400", 4 },
            { "i5-6400T", 4 },
            { "i5-6402P", 4 },
            { "i5-6440EQ", 4 },
            { "i5-6440HQ", 4 },
            { "i5-6442EQ", 4 },
            { "i5-650", 4 },
            { "i5-6500", 4 },
            { "i5-6500T", 4 },
            { "i5-6500TE", 4 },
            { "i5-655K", 4 },
            { "i5-6585R", 4 },
            { "i5-660", 4 },
            { "i5-6600", 4 },
            { "i5-6600K", 4 },
            { "i5-6600T", 4 },
            { "i5-661", 4 },
            { "i5-6685R", 4 },
            { "i5-670", 4 },
            { "i5-680", 4 },
            { "i5-7200U", 4 },
            { "i5-7210U", 4 },
            { "i5-7260U", 4 },
            { "i5-7267U", 4 },
            { "i5-7287U", 4 },
            { "i5-7300HQ", 4 },
            { "i5-7300U", 4 },
            { "i5-7360U", 4 },
            { "i5-7400", 4 },
            { "i5-7400T", 4 },
            { "i5-7440EQ", 4 },
            { "i5-7440HQ", 4 },
            { "i5-7442EQ", 4 },
            { "i5-750", 4 },
            { "i5-7500", 4 },
            { "i5-7500T", 4 },
            { "i5-750S", 4 },
            { "i5-760", 4 },
            { "i5-7600", 4 },
            { "i5-7600K", 4 },
            { "i5-7600T", 4 },
            { "i5-7640X", 4 },
            { "i5-7Y54", 4 },
            { "i5-7Y57", 4 },
            { "i5-8200Y", 4 },
            { "i5-8210Y", 4 },
            { "i5-8250U", 8 },
            { "i5-8257U", 8 },
            { "i5-8259U", 8 },
            { "i5-8260U", 8 },
            { "i5-8265U", 8 },
            { "i5-8269U", 8 },
            { "i5-8279U", 8 },
            { "i5-8300H", 8 },
            { "i5-8305G", 8 },
            { "i5-8310Y", 4 },
            { "i5-8350U", 8 },
            { "i5-8365U", 8 },
            { "i5-8365UE", 8 },
            { "i5-8400", 6 },
            { "i5-8400B", 6 },
            { "i5-8400H", 8 },
            { "i5-8400T", 6 },
            { "i5-8420", 6 },
            { "i5-8420T", 6 },
            { "i5-8500", 6 },
            { "i5-8500B", 6 },
            { "i5-8500T", 6 },
            { "i5-8550", 6 },
            { "i5-8600", 6 },
            { "i5-8600K", 6 },
            { "i5-8600T", 6 },
            { "i5-8650", 6 },
            { "i5-9300H", 8 },
            { "i5-9300HF", 8 },
            { "i5-9400", 6 },
            { "i5-9400F", 6 },
            { "i5-9400H", 8 },
            { "i5-9400T", 6 },
            { "i5-9500", 6 },
            { "i5-9500E", 6 },
            { "i5-9500F", 6 },
            { "i5-9500T", 6 },
            { "i5-9500TE", 6 },
            { "i5-9600", 6 },
            { "i5-9600K", 6 },
            { "i5-9600KF", 6 },
            { "i5-9600T", 6 },

            // i7 series
            { "i7-10510U", 8 },
            { "i7-10510Y", 8 },
            { "i7-1060G7", 8 },
            { "i7-10610U", 8 },
            { "i7-1065G7", 8 },
            { "i7-1068G7", 8 },
            { "i7-1068NG7", 8 },
            { "i7-10700", 16 },
            { "i7-10700E", 16 },
            { "i7-10700F", 16 },
            { "i7-10700K", 16 },
            { "i7-10700KF", 16 },
            { "i7-10700T", 16 },
            { "i7-10700TE", 16 },
            { "i7-10710U", 8 },
            { "i7-10750H", 12 },
            { "i7-10810U", 12 },
            { "i7-10850H", 12 },
            { "i7-10870H", 16 },
            { "i7-10875H", 16 },
            { "i7-11370H", 8 },
            { "i7-11375H", 8 },
            { "i7-11390H", 8 },
            { "i7-11600H", 12 },
            { "i7-1160G7", 8 },
            { "i7-1165G7", 8 },
            { "i7-11700", 16 },
            { "i7-11700B", 16 },
            { "i7-11700F", 16 },
            { "i7-11700K", 16 },
            { "i7-11700KF", 16 },
            { "i7-11700T", 16 },
            { "i7-11800H", 16 },
            { "i7-1180G7", 8 },
            { "i7-11850H", 16 },
            { "i7-11850HE", 16 },
            { "i7-1185G7", 8 },
            { "i7-1185G7E", 8 },
            { "i7-1185GRE", 8 },
            { "i7-1195G7", 8 },
            { "i7-1250U", 4 },
            { "i7-1255U", 4 },
            { "i7-1260P", 8 },
            { "i7-1260U", 4 },
            { "i7-1265U", 4 },
            { "i7-12700", 16 },
            { "i7-12700F", 16 },
            { "i7-12700KF", 16 },
            { "i7-12700T", 16 },
            { "i7-1270P", 8 },
            { "i7-1270PE", 8 },
            { "i7-1360P", 8 },
            { "i7-13700", 16 },
            { "i7-13700F", 16 },
            { "i7-13700K", 16 },
            { "i7-13700KF", 16 },
            { "i7-13700T", 16 },
            { "i7-13790F", 16 },
            { "i7-2535QM", 8 },
            { "i7-2570QM", 8 },
            { "i7-2600", 8 },
            { "i7-2600K", 8 },
            { "i7-2600S", 8 },
            { "i7-2610UE", 4 },
            { "i7-2617M", 4 },
            { "i7-2620M", 4 },
            { "i7-2627M", 4 },
            { "i7-2629M", 4 },
            { "i7-2630QM", 8 },
            { "i7-2635QM", 8 },
            { "i7-2637M", 4 },
            { "i7-2640M", 4 },
            { "i7-2649M", 4 },
            { "i7-2655LE", 4 },
            { "i7-2655QM", 8 },
            { "i7-2657M", 4 },
            { "i7-2660M", 4 },
            { "i7-2667M", 4 },
            { "i7-2669M", 4 },
            { "i7-2670QM", 8 },
            { "i7-2675QM", 8 },
            { "i7-2677M", 4 },
            { "i7-2685QM", 8 },
            { "i7-2689M", 4 },
            { "i7-2700K", 8 },
            { "i7-2710QE", 8 },
            { "i7-2715QE", 8 },
            { "i7-2720QM", 8 },
            { "i7-2740QM", 8 },
            { "i7-2760QM", 8 },
            { "i7-2820QM", 8 },
            { "i7-2840QM", 8 },
            { "i7-2860QM", 8 },
            { "i7-2920XM", 8 },
            { "i7-2960XM", 8 },
            { "i7-3517U", 4 },
            { "i7-3517UE", 4 },
            { "i7-3520M", 4 },
            { "i7-3537U", 4 },
            { "i7-3540M", 4 },
            { "i7-3555LE", 4 },
            { "i7-3610QE", 8 },
            { "i7-3610QM", 8 },
            { "i7-3612QE", 8 },
            { "i7-3612QM", 8 },
            { "i7-3615QE", 8 },
            { "i7-3615QM", 8 },
            { "i7-3630QM", 8 },
            { "i7-3632QM", 8 },
            { "i7-3635QM", 8 },
            { "i7-3667U", 4 },
            { "i7-3687U", 4 },
            { "i7-3689Y", 4 },
            { "i7-3720QM", 8 },
            { "i7-3740QM", 8 },
            { "i7-3770", 8 },
            { "i7-3770K", 8 },
            { "i7-3770S", 8 },
            { "i7-3770T", 8 },
            { "i7-3820", 8 },
            { "i7-3820QM", 8 },
            { "i7-3840QM", 8 },
            { "i7-3920XM", 8 },
            { "i7-3930K", 12 },
            { "i7-3940XM", 8 },
            { "i7-3960X", 12 },
            { "i7-3970X", 12 },
            { "i7-4500U", 4 },
            { "i7-4510U", 4 },
            { "i7-4550U", 4 },
            { "i7-4558U", 4 },
            { "i7-4578U", 4 },
            { "i7-4600M", 4 },
            { "i7-4600U", 4 },
            { "i7-4610M", 8 },
            { "i7-4610Y", 4 },
            { "i7-4650U", 4 },
            { "i7-4700EC", 8 },
            { "i7-4700EQ", 8 },
            { "i7-4700HQ", 8 },
            { "i7-4700MQ", 8 },
            { "i7-4701EQ", 8 },
            { "i7-4702EC", 8 },
            { "i7-4702HQ", 8 },
            { "i7-4702MQ", 8 },
            { "i7-4710HQ", 8 },
            { "i7-4710MQ", 8 },
            { "i7-4712HQ", 8 },
            { "i7-4712MQ", 8 },
            { "i7-4720HQ", 8 },
            { "i7-4722HQ", 8 },
            { "i7-4750HQ", 8 },
            { "i7-4760HQ", 8 },
            { "i7-4765T", 8 },
            { "i7-4770", 8 },
            { "i7-4770HQ", 8 },
            { "i7-4770K", 8 },
            { "i7-4770R", 8 },
            { "i7-4770S", 8 },
            { "i7-4770T", 8 },
            { "i7-4770TE", 8 },
            { "i7-4771", 8 },
            { "i7-4785T", 8 },
            { "i7-4790", 8 },
            { "i7-4790K", 8 },
            { "i7-4790S", 8 },
            { "i7-4790T", 8 },
            { "i7-4800MQ", 8 },
            { "i7-4810MQ", 8 },
            { "i7-4820K", 8 },
            { "i7-4850EQ", 8 },
            { "i7-4850HQ", 8 },
            { "i7-4860EQ", 8 },
            { "i7-4860HQ", 8 },
            { "i7-4870HQ", 8 },
            { "i7-4900MQ", 8 },
            { "i7-4910MQ", 8 },
            { "i7-4930K", 12 },
            { "i7-4930MX", 8 },
            { "i7-4940MX", 8 },
            { "i7-4950HQ", 8 },
            { "i7-4960HQ", 8 },
            { "i7-4960X", 12 },
            { "i7-4980HQ", 8 },
            { "i7-5500U", 4 },
            { "i7-5550U", 4 },
            { "i7-5557U", 4 },
            { "i7-5600U", 4 },
            { "i7-5650U", 4 },
            { "i7-5700EQ", 8 },
            { "i7-5700HQ", 8 },
            { "i7-5750HQ", 8 },
            { "i7-5775C", 8 },
            { "i7-5775R", 8 },
            { "i7-5820K", 12 },
            { "i7-5850EQ", 8 },
            { "i7-5850HQ", 8 },
            { "i7-5930K", 12 },
            { "i7-5950HQ", 8 },
            { "i7-5960X", 16 },
            { "i7-610E", 4 },
            { "i7-620LE", 4 },
            { "i7-620LM", 4 },
            { "i7-620M", 4 },
            { "i7-620UE", 4 },
            { "i7-620UM", 4 },
            { "i7-640LM", 4 },
            { "i7-640M", 4 },
            { "i7-640UM", 4 },
            { "i7-6498DU", 4 },
            { "i7-6500U", 4 },
            { "i7-6560U", 4 },
            { "i7-6567U", 4 },
            { "i7-6600U", 4 },
            { "i7-660LM", 4 },
            { "i7-660UE", 4 },
            { "i7-660UM", 4 },
            { "i7-6650U", 4 },
            { "i7-6660U", 4 },
            { "i7-6700", 8 },
            { "i7-6700HQ", 8 },
            { "i7-6700K", 8 },
            { "i7-6700T", 8 },
            { "i7-6700TE", 8 },
            { "i7-6770HQ", 8 },
            { "i7-6785R", 8 },
            { "i7-6800K", 12 },
            { "i7-680UM", 4 },
            { "i7-6820EQ", 8 },
            { "i7-6820HK", 8 },
            { "i7-6820HQ", 8 },
            { "i7-6822EQ", 8 },
            { "i7-6850K", 12 },
            { "i7-6870HQ", 8 },
            { "i7-6900K", 16 },
            { "i7-6920HQ", 8 },
            { "i7-6950X", 20 },
            { "i7-6970HQ", 8 },
            { "i7-720QM", 8 },
            { "i7-740QM", 8 },
            { "i7-7500U", 4 },
            { "i7-7510U", 4 },
            { "i7-7560U", 4 },
            { "i7-7567U", 4 },
            { "i7-7600U", 4 },
            { "i7-7660U", 4 },
            { "i7-7700", 8 },
            { "i7-7700HQ", 8 },
            { "i7-7700K", 8 },
            { "i7-7700T", 8 },
            { "i7-7740X", 8 },
            { "i7-7800X", 12 },
            { "i7-7820EQ", 8 },
            { "i7-7820HK", 8 },
            { "i7-7820HQ", 8 },
            { "i7-7820X", 16 },
            { "i7-7920HQ", 8 },
            { "i7-7Y75", 4 },
            { "i7-8086K", 12 },
            { "i7-820QM", 8 },
            { "i7-840QM", 8 },
            { "i7-8500Y", 4 },
            { "i7-8550U", 8 },
            { "i7-8557U", 8 },
            { "i7-8559U", 8 },
            { "i7-8565U", 8 },
            { "i7-8569U", 8 },
            { "i7-860", 8 },
            { "i7-860S", 8 },
            { "i7-8650U", 8 },
            { "i7-8665U", 8 },
            { "i7-8665UE", 8 },
            { "i7-8670", 12 },
            { "i7-8670T", 12 },
            { "i7-870", 8 },
            { "i7-8700", 12 },
            { "i7-8700B", 12 },
            { "i7-8700K", 12 },
            { "i7-8700T", 12 },
            { "i7-8705G", 8 },
            { "i7-8706G", 8 },
            { "i7-8709G", 8 },
            { "i7-870S", 8 },
            { "i7-8750H", 12 },
            { "i7-875K", 8 },
            { "i7-880", 8 },
            { "i7-8809G", 8 },
            { "i7-8850H", 12 },
            { "i7-920", 8 },
            { "i7-920XM", 8 },
            { "i7-930", 8 },
            { "i7-940", 8 },
            { "i7-940XM", 8 },
            { "i7-950", 8 },
            { "i7-960", 8 },
            { "i7-965", 8 },
            { "i7-970", 12 },
            { "i7-9700", 8 },
            { "i7-9700E", 8 },
            { "i7-9700F", 8 },
            { "i7-9700K", 8 },
            { "i7-9700KF", 8 },
            { "i7-9700T", 8 },
            { "i7-9700TE", 8 },
            { "i7-975", 8 },
            { "i7-9750H", 12 },
            { "i7-9750HF", 12 },
            { "i7-980", 12 },
            { "i7-9800X", 16 },
            { "i7-980X", 12 },
            { "i7-9850H", 12 },
            { "i7-9850HE", 12 },
            { "i7-9850HL", 12 },
            { "i7-990X", 12 },

            // i9 series
            { "i9-10850K", 20 },
            { "i9-10885H", 16 },
            { "i9-10900", 20 },
            { "i9-10900E", 20 },
            { "i9-10900F ", 20 },
            { "i9-10900K", 20 },
            { "i9-10900KF", 20 },
            { "i9-10900T", 20 },
            { "i9-10900TE", 20 },
            { "i9-10900X", 20 },
            { "i9-10910", 20 },
            { "i9-10920X", 24 },
            { "i9-10940X", 28 },
            { "i9-10980HK", 16 },
            { "i9-10980XE", 36 },
            { "i9-11900", 16 },
            { "i9-11900F", 16 },
            { "i9-11900H", 16 },
            { "i9-11900K", 16 },
            { "i9-11900KB", 16 },
            { "i9-11900KF", 16 },
            { "i9-11900T", 16 },
            { "i9-11950H", 16 },
            { "i9-11980HK", 16 },
            { "i9-12900", 16 },
            { "i9-12900F", 16 },
            { "i9-12900K", 16 },
            { "i9-12900KF", 16 },
            { "i9-12900KS", 16 },
            { "i9-12900T", 16 },
            { "i9-13900", 16 },
            { "i9-13900E", 16 },
            { "i9-13900F", 16 },
            { "i9-13900HX", 16 },
            { "i9-13900K", 16 },
            { "i9-13900KF", 16 },
            { "i9-13900KS", 16 },
            { "i9-13900T", 16 },
            { "i9-13900TE", 16 },
            { "i9-13950HX", 16 },
            { "i9-13980HX", 16 },
            { "i9-14900", 16 },
            { "i9-14900F", 16 },
            { "i9-14900HX", 16 },
            { "i9-14900K", 16 },
            { "i9-14900KF", 16 },
            { "i9-14900KS", 16 },
            { "i9-14900T", 16 },
            { "i9-7900X", 20 },
            { "i9-7920X", 24 },
            { "i9-7940X", 28 },
            { "i9-7960X", 32 },
            { "i9-7980XE", 36 },
            { "i9-8950HK", 12 },
            { "i9-9820X", 20 },
            { "i9-9880H", 16 },
            { "i9-9900", 16 },
            { "i9-9900K", 16 },
            { "i9-9900KF", 16 },
            { "i9-9900KS", 16 },
            { "i9-9900T", 16 },
            { "i9-9900X", 20 },
            { "i9-9920X", 24 },
            { "i9-9940X", 28 },
            { "i9-9960X", 32 },
            { "i9-9980HK", 16 },
            { "i9-9980XE", 36 },
            { "i9-9990XE", 28 }
        };

        // if it doesn't exist, return false
        if (thread_database.find(model.string.c_str()) == thread_database.end()) {
            return false;
        }

        const u8 threads = thread_database.at(model.string.c_str());

        debug("INTEL_THREAD_MISMATCH: thread in database = ", static_cast<u32>(threads));

        return (std::thread::hardware_concurrency() != threads);
#endif
    }


    /**
     * @brief Same as above, but for Xeon Intel CPUs
     * @category All, x86
     * @link https://en.wikipedia.org/wiki/List_of_Intel_Core_processors
     */
    [[nodiscard]] static bool xeon_thread_mismatch() {
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

        #if (WINDOWS)
            if (util::does_threadcount_mismatch()) {
                debug("INTEL_THREAD_MISMATCH: Thread tampering detected");
                return false;
            }
        #endif

        std::map<const char*, u8> thread_database = {
            // Xeon D
            { "D-1518", 8 },
            { "D-1520", 8 },
            { "D-1521", 8 },
            { "D-1527", 8 },
            { "D-1528", 12 },
            { "D-1529", 8 },
            { "D-1531", 12 },
            { "D-1537", 16 },
            { "D-1539", 16 },
            { "D-1540", 16 },
            { "D-1541", 16 },
            { "D-1548", 16 },
            { "D-1557", 24 },
            { "D-1559", 24 },
            { "D-1567", 24 },
            { "D-1571", 32 },
            { "D-1577", 32 },
            { "D-1581", 32 },
            { "D-1587", 32 },
            { "D-1513N", 8 },
            { "D-1523N", 8 },
            { "D-1533N", 12 },
            { "D-1543N", 16 },
            { "D-1553N", 16 },
            { "D-1602", 4 },
            { "D-1612", 8 },
            { "D-1622", 8 },
            { "D-1627", 8 },
            { "D-1632", 16 },
            { "D-1637", 12 },
            { "D-1623N", 8 },
            { "D-1633N", 12 },
            { "D-1649N", 16 },
            { "D-1653N", 16 },
            { "D-2141I", 16 },
            { "D-2161I", 24 },
            { "D-2191", 36 },
            { "D-2123IT", 8 },
            { "D-2142IT", 16 },
            { "D-2143IT", 16 },
            { "D-2163IT", 24 },
            { "D-2173IT", 28 },
            { "D-2183IT", 32 },
            { "D-2145NT", 16 },
            { "D-2146NT", 16 },
            { "D-2166NT", 24 },
            { "D-2177NT", 28 },
            { "D-2187NT", 32 },

            // Xeon E
            { "E-2104G", 4 },
            { "E-2124", 4 },
            { "E-2124G", 4 },
            { "E-2126G", 6 },
            { "E-2134", 8 },
            { "E-2136", 12 },
            { "E-2144G", 8 },
            { "E-2146G", 12 },
            { "E-2174G", 8 },
            { "E-2176G", 12 },
            { "E-2186G", 12 },
            { "E-2176M", 12 },
            { "E-2186M", 12 },
            { "E-2224", 4 },
            { "E-2224G", 4 },
            { "E-2226G", 6 },
            { "E-2234", 8 },
            { "E-2236", 12 },
            { "E-2244G", 8 },
            { "E-2246G", 12 },
            { "E-2274G", 8 },
            { "E-2276G", 12 },
            { "E-2278G", 16 },
            { "E-2286G", 12 },
            { "E-2288G", 16 },
            { "E-2276M", 12 },
            { "E-2286M", 16 },

            // Xeon W
            { "W-2102", 4 },
            { "W-2104", 4 },
            { "W-2123", 8 },
            { "W-2125", 8 },
            { "W-2133", 12 },
            { "W-2135", 12 },
            { "W-2140B", 16 },
            { "W-2145", 16 },
            { "W-2150B", 20 },
            { "W-2155", 20 },
            { "W-2170B", 28 },
            { "W-2175", 28 },
            { "W-2191B", 36 },
            { "W-2195", 36 },
            { "W-3175X", 56 },
            { "W-3223", 16 },
            { "W-3225", 16 },
            { "W-3235", 24 },
            { "W-3245", 32 },
            { "W-3245M", 32 },
            { "W-3265", 48 },
            { "W-3265M", 48 },
            { "W-3275", 56 },
            { "W-3275M", 56 }
        };

        // if it doesn't exist, return false
        if (thread_database.find(model.string.c_str()) == thread_database.end()) {
            return false;
        }

        const u8 threads = thread_database.at(model.string.c_str());

        debug("XEON_THREAD_MISMATCH: thread in database = ", static_cast<u32>(threads));

        return (std::thread::hardware_concurrency() != threads);
#endif
    }


    /**
     * @brief Check for memory regions to detect VM-specific brands
     * @category Windows
     * @author Graham Sutherland
     * @link https://labs.nettitude.com/blog/vm-detection-tricks-part-1-physical-memory-resource-maps/
     */
    [[nodiscard]] static bool nettitude_vm_memory() {
#if (!WINDOWS)
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

        /* registry keys for resource maps */
#define VM_RESOURCE_CHECK_REGKEY_PHYSICAL 0
#define VM_RESOURCE_CHECK_REGKEY_RESERVED 1
#define VM_RESOURCE_CHECK_REGKEY_LOADER_RESERVED 2
#define ResourceRegistryKeysLength 3

        const struct map_key {
            LPCTSTR KeyPath;
            LPCTSTR ValueName;
        } ResourceRegistryKeys[ResourceRegistryKeysLength] = {
            {
                _T("Hardware\\ResourceMap\\System Resources\\Physical Memory"),
                _T(".Translated")
            },
            {
                _T("Hardware\\ResourceMap\\System Resources\\Reserved"),
                _T(".Translated")
            },
            {
                _T("Hardware\\ResourceMap\\System Resources\\Loader Reserved"),
                _T(".Raw")
            }
        };

        /* parse a REG_RESOURCE_LIST value for memory descriptors */
        auto parse_memory_map = [](
            struct memory_region* regions,
            struct map_key key
        ) -> DWORD {
            HKEY hKey = NULL;
            LPCTSTR pszSubKey = key.KeyPath;
            LPCTSTR pszValueName = key.ValueName;
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
                if (phys_count <= 0 || reserved_count <= 0 || loader_reserved_count <= 0) {
                    return VM_RESOURCE_CHECK_ERROR;
                }

                if (phys == NULL || reserved == NULL || loader_reserved == NULL) {
                    return VM_RESOURCE_CHECK_ERROR;
                }

                /* find the reserved address range starting
                RESERVED_ADDR_LOW, and record its end address */
                ULONG64 lowestReservedAddrRangeEnd = 0;
                for (int i = 0; i < reserved_count; i++) {
                    if (reserved[i].address == RESERVED_ADDR_LOW) {
                        lowestReservedAddrRangeEnd = reserved[i].address + reserved[i].size;
                        break;
                    }
                }

                if (lowestReservedAddrRangeEnd == 0) {
                    /* every system tested had a range starting at RESERVED_ADDR_LOW */
                    /* this is an outlier. error. */
                    return VM_RESOURCE_CHECK_ERROR;
                }

                /* find the loader reserved address range starting
                LOADER_RESERVED_ADDR_LOW, and record its end address */
                ULONG64 lowestLoaderReservedAddrRangeEnd = 0;
                for (int i = 0; i < loader_reserved_count; i++) {
                    if (loader_reserved[i].address == LOADER_RESERVED_ADDR_LOW) {
                        lowestLoaderReservedAddrRangeEnd = loader_reserved[i].address + loader_reserved[i].size;
                        break;
                    }
                }

                if (lowestLoaderReservedAddrRangeEnd == 0) {
                    /* every system tested had a range starting at LOADER_RESERVED_ADDR_LOW */
                    /* this is an outlier. error. */
                    return VM_RESOURCE_CHECK_ERROR;
                }

                /* check if the end addresses are equal. if not, we haven't detected a VM */
                if (lowestReservedAddrRangeEnd != lowestLoaderReservedAddrRangeEnd) {
                    return VM_RESOURCE_CHECK_NO_VM;
                }

                /* now find the type of VM by its known physical memory range */
                for (int i = 0; i < phys_count; i++) {
                    if (phys[i].address == HYPERV_PHYS_LO && (phys[i].address + phys[i].size) == HYPERV_PHYS_HI) {
                        /* hyper-v */
                        return VM_RESOURCE_CHECK_HYPERV;
                    }

                    if (phys[i].address == VBOX_PHYS_LO && (phys[i].address + phys[i].size) == VBOX_PHYS_HI) {
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

        for (int i = 0; i < ResourceRegistryKeysLength; i++) {
            debug(
                "NETTITUDE_VM_MEMORY: Reading data from ",
                ResourceRegistryKeys[i].KeyPath,
                "\\",
                ResourceRegistryKeys[i].ValueName
            );

            count = parse_memory_map(NULL, ResourceRegistryKeys[i]);

            if (count == 0) {
                debug("NETTITUDE_VM_MEMORY: Could not find memory region, returning 0.");
                return 0;
            }

            regions[i] = (struct memory_region*)malloc(sizeof(struct memory_region) * count);

            if (regions[i] == NULL) {
                debug("NETTITUDE_VM_MEMORY: Memory allocation failed for regions[i].");
                return 0;
            }

            count = parse_memory_map(regions[i], ResourceRegistryKeys[i]);

            if (count <= 0) {
                debug("NETTITUDE_VM_MEMORY: No regions parsed, freeing allocated memory.");
                free(regions[i]);  
                regions[i] = NULL;
                continue;
            }

            region_counts[i] = count;
            for (DWORD r = 0; r < count; r++) {
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

        switch (check_result) {
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
                return core::add(brands::HYPERV);
                break;

            // VirtualBox
            case VM_RESOURCE_CHECK_VBOX:
                debug("NETTITUDE_VM_MEMORY: Vbox detected");
                return core::add(brands::VBOX);
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


    /**
     * @brief Check for CPUID technique by checking whether all the bits equate to more than 4000
     * @category x86
     * @author 一半人生
     * @link https://unprotect.it/snippet/vmcpuid/195/
     * @copyright MIT
     */
    [[nodiscard]] static bool cpuid_bitset() {
#if (!x86)
        return false;
#else
        if (util::hyper_x()) {
            return false;
        }

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
            return true;
        }

        return false;
#endif
    }


    /**
     * @brief Check for cuckoo directory using crt and WIN API directory functions
     * @category Windows
     * @author 一半人生
     * @link https://unprotect.it/snippet/checking-specific-folder-name/196/
     * @copyright MIT
     */
    [[nodiscard]] static bool cuckoo_dir() {
#if (!WINDOWS)
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

            CloseHandle(hFile);

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
            return core::add(brands::CUCKOO);
        }

        return false;
#endif
    }


    /**
     * @brief Check for Cuckoo specific piping mechanism
     * @category Windows
     * @author Thomas Roccia (fr0gger)
     * @link https://unprotect.it/snippet/checking-specific-folder-name/196/
     * @copyright MIT
     */
    [[nodiscard]] static bool cuckoo_pipe() {
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
            return core::add(brands::CUCKOO);
        }

        return false;
#endif
    }


    /**
     * @brief Check for default Azure hostname format regex (Azure uses Hyper-V as their base VM brand)
     * @category Windows, Linux
     */
    [[nodiscard]] static bool hyperv_hostname() {
#if (!(WINDOWS || LINUX))
        return false;
#else
        std::string hostname = util::get_hostname();

        // most Hyper-V hostnames under Azure have the hostname format of fv-azXXX-XXX where the X is a digit
        std::regex pattern("fv-az\\d+-\\d+");

        if (std::regex_match(hostname, pattern)) {
            return core::add(brands::AZURE_HYPERV);
        }

        return false;
#endif
    }


    /**
     * @brief Check for commonly set hostnames by certain VM brands
     * @category Windows, Linux
     * @note Idea from Thomas Roccia (fr0gger)
     * @link https://unprotect.it/technique/detecting-hostname-username/
     * @copyright MIT
     */
    [[nodiscard]] static bool general_hostname() {
#if (!(WINDOWS || LINUX))
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
            return core::add(brands::CUCKOO);
        }

        return false;
#endif
    }


    /**
     * @brief Check for pre-set screen resolutions commonly found in VMs
     * @category Windows
     * @note Idea from Thomas Roccia (fr0gger)
     * @link https://unprotect.it/technique/checking-screen-resolution/
     * @copyright MIT
     */
    [[nodiscard]] static bool screen_resolution() {
#if (!WINDOWS)
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


    /**
     * @brief Check if bogus device string would be accepted
     * @category Windows
     * @author Huntress Research Team
     * @link https://unprotect.it/technique/buildcommdcbandtimeouta/
     * @copyright MIT
     */
    [[nodiscard]] static bool device_string() {
#if (!WINDOWS)
        return false;
#else
        DCB dcb = { 0 };
        COMMTIMEOUTS timeouts = { 0 };

        if (BuildCommDCBAndTimeoutsA("jhl46745fghb", &dcb, &timeouts)) {
            return true;
        } else {
            debug("DEVICE_STRING: BuildCommDCBAndTimeouts failed");
            return false;
        }
#endif
    }


    /**
     * @brief Check for the presence of BlueStacks-specific folders
     * @category ARM, Linux
     */
    [[nodiscard]] static bool bluestacks() {
#if (!(ARM && LINUX))
        return false;
#else
        if (
            util::exists("/mnt/windows/BstSharedFolder") ||
            util::exists("/sdcard/windows/BstSharedFolder")
        ) {
            return core::add(brands::BLUESTACKS);
        }

        return false;
#endif
    }


    /**
     * @brief Check for signatures in leaf 0x40000001 in CPUID
     * @link https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/shared/hvgdk_mini/hv_hypervisor_interface.htm
     * @link https://github.com/ionescu007/SimpleVisor/blob/master/shvvp.c
     * @category x86
     */
    [[nodiscard]] static bool cpuid_signature() {
#if (!x86)
        return false;
#else
        if (util::hyper_x()) {
            return false;
        }

        u32 eax, unused = 0;
        cpu::cpuid(eax, unused, unused, unused, 0x40000001);
        UNUSED(unused);

        constexpr u32 hyperv = 0x31237648; // "Hv#1"
        constexpr u32 nanovisor = 0x766E6258; // "Xbnv" 
        constexpr u32 simplevisor = 0x00766853; // " vhS"

        debug("CPUID_SIGNATURE: eax = ", eax);

        switch (eax) {
            case hyperv: return core::add(brands::HYPERV);
            case nanovisor: return core::add(brands::NANOVISOR);
            case simplevisor: return core::add(brands::SIMPLEVISOR);
        }

        return false;
#endif
    }


    /**
     * @brief Check for Hyper-V CPUID bitmask range for reserved values
     * @link https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/feature-discovery
     * @category x86
     */
    [[nodiscard]] static bool hyperv_bitmask() {
#if (!x86)
        return false;
#else
        if (util::hyper_x()) {
            return false;
        }

        enum registers : u8 {
            EAX = 1,
            EBX,
            ECX,
            EDX
        };

        auto fetch_register = [](const registers register_id, const u32 leaf) -> u32 {
            u32 eax, ebx, ecx, edx = 0;
            cpu::cpuid(eax, ebx, ecx, edx, leaf);

            switch (register_id) {
                case EAX: return eax;
                case EBX: return ebx;
                case ECX: return ecx;
                case EDX: return edx;
            }

            return 0;
        };

        const u32 max_leaf = fetch_register(EAX, 0x40000000);

        debug("HYPERV_BITMASK: max leaf = ", std::hex, max_leaf);

        if (max_leaf < 0x4000000A) {
            return false; // returned false because we want the most feature leafs as possible for Hyper-V
        }

/* this is just an ascii tool to check if all the arrows (^) are aligned correctly based on bit position, think of it as a ruler. (ignore this btw)
||||||||||||||||||||||9876543210
|||||||||||||||||||||10 
||||||||||||||||||||11 
|||||||||||||||||||12 
||||||||||||||||||13 
|||||||||||||||||14 
||||||||||||||||15 
|||||||||||||||16 
||||||||||||||17 
|||||||||||||18 
||||||||||||19 
|||||||||||20 
||||||||||21 
|||||||||22 
||||||||23 
|||||||24 
||||||25 
|||||26 
||||27 
|||28 
||29 
|30 
31 
*/

        auto leaf_01 = [&]() -> bool {
            u32 eax, ebx, ecx, edx = 0;
            cpu::cpuid(eax, ebx, ecx, edx, 0x40000001);

            debug("01 eax = ", std::bitset<32>(eax));
            debug("01 ebx = ", std::bitset<32>(ebx));
            debug("         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
            debug("01 ecx = ", std::bitset<32>(ecx));
            debug("         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
            debug("01 edx = ", std::bitset<32>(edx));
            debug("         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");

            return (
                (eax != 0) &&
                (ebx == 0) &&
                (ecx == 0) &&
                (edx == 0)
            );
        };

        auto leaf_03 = [&]() -> bool {
            const u32 ecx = fetch_register(ECX, 0x40000003);
            const u32 edx = fetch_register(EDX, 0x40000003);

            debug("03 ecx = ", std::bitset<32>(ecx));
            debug("         ^^^^^^^^^^^^^^^^^^^^^^^    ^^^^^");
            debug("03 edx = ", std::bitset<32>(edx));
            debug("         ^^^^^ ^^ ^     ^                ");

            if (ecx == 0 || edx == 0) {
                return false;
            } else {
                return (
                    ((ecx & 0b11111) == 0) &&
                    ((ecx >> 9) == 0) &&
                    ((edx & (1 << 16)) == 0) &&
                    ((edx & (1 << 22)) == 0) &&
                    (((edx >> 24) & 0b11) == 0) &&
                    ((edx >> 27) == 0)
                );
            }
        };

        auto leaf_04 = [&]() -> bool {
            const u32 eax = fetch_register(EAX, 0x40000004);
            const u32 ecx = fetch_register(ECX, 0x40000004);
            const u32 edx = fetch_register(EDX, 0x40000004);

            debug("04 eax = ", std::bitset<32>(eax));
            debug("         ^^^^^^^^^^^^^  ^       ^        ");
            debug("04 ecx = ", std::bitset<32>(ecx));
            debug("         ^^^^^^^^^^^^^^^^^^^^^^^^^       ");
            debug("04 edx = ", std::bitset<32>(edx));
            debug("         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");

            if (
                eax == 0 ||
                ecx == 0 ||
                edx != 0   // edx is supposed to be null
            ) {
                return false;
            } else {
                return (
                    ((eax & (1 << 8)) == 0) &&
                    ((eax & (1 << 16)) == 0) &&
                    ((eax >> 19) == 0) &&
                    ((ecx >> 7) == 0) &&
                    (edx == 0)
                );
            }
        };

        auto leaf_05 = [&]() -> bool {
            const u32 edx = fetch_register(EDX, 0x40000005);
            debug("05 edx = ", std::bitset<32>(edx));
            debug("         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
            return (edx == 0);
        };

        auto leaf_06 = [&]() -> bool {
            u32 eax, ebx, ecx, edx = 0;
            cpu::cpuid(eax, ebx, ecx, edx, 0x40000006);

            debug("06 eax = ", std::bitset<32>(eax));
            debug("         ^^^^^^^         ^               ");
            debug("06 ebx = ", std::bitset<32>(ebx));
            debug("         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
            debug("06 ecx = ", std::bitset<32>(ecx));
            debug("         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
            debug("06 edx = ", std::bitset<32>(edx));
            debug("         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");

            if (
                eax == 0 ||
                ebx != 0 ||
                ecx != 0 ||
                edx != 0   // edx is supposed to be null
            ) {
                return false;
            } else {
                return (
                    ((eax & (1 << 15)) == 0) &&
                    ((eax >> 25) == 0) &&
                    (ebx == 0) &&
                    (ecx == 0) &&
                    (edx == 0)
                );
            }
        };

        auto leaf_09 = [&]() -> bool {
            u32 eax, ebx, ecx, edx = 0;
            cpu::cpuid(eax, ebx, ecx, edx, 0x40000009);

            debug("09 eax = ", std::bitset<32>(eax));
            debug("         ^^^^^^^^^^^^^^^^^^^ ^^^^^   ^ ^^");
            debug("09 ebx = ", std::bitset<32>(ebx));
            debug("         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
            debug("09 ecx = ", std::bitset<32>(ecx));
            debug("         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
            debug("09 edx = ", std::bitset<32>(edx));
            debug("         ^^^^^^^^^^^^^^ ^ ^^^^^^^^^^ ^^^^");

            if (
                eax == 0 ||
                ebx != 0 ||
                ecx != 0 ||
                edx == 0
            ) {
                return false;
            } else {
                return (
                    ((eax & 0b11) == 0) &&
                    ((eax & (1 << 3)) == 0) &&
                    (((eax >> 7) & 0b11111) == 0) &&
                    ((eax >> 13) == 0) &&
                    (ebx == 0) &&
                    (ecx == 0) &&
                    ((edx & 0b1111) == 0) &&
                    (((edx >> 5) & 0b1111111111) == 0) &&
                    ((edx & (1 << 16)) == 0) &&
                    ((edx >> 18) == 0)
                );
            }
        };

        auto leaf_0A = [&]() -> bool {
            u32 eax, ebx, ecx, edx = 0;
            cpu::cpuid(eax, ebx, ecx, edx, 0x40000009);

            debug("0A eax = ", std::bitset<32>(eax));
            debug("         ^^^^^^^^^^^    ^                ");
            debug("0A eax = ", std::bitset<32>(ebx));
            debug("         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ ");
            debug("0A ecx = ", std::bitset<32>(ecx));
            debug("         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
            debug("0A edx = ", std::bitset<32>(edx));
            debug("         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");

            // ebx is left out on purpose due to how likely it can result the overall result to be a false negative
            if (
                eax == 0 ||
                ecx != 0 ||
                edx != 0
            ) {
                return false;
            } else {
                return (
                    ((eax & (1 << 16)) == 0) &&
                    ((eax >> 21) == 0) &&
                    ((ebx >> 30) == 0) &&
                    (ecx == 0) &&
                    (edx == 0)
                );
            }
        };

        debug("01: ", leaf_01());
        debug("03: ", leaf_03());
        debug("04: ", leaf_04());
        debug("05: ", leaf_05());
        debug("06: ", leaf_06());
        debug("09: ", leaf_09());
        debug("0A: ", leaf_0A());

        if (
            leaf_01() &&
            leaf_03() &&
            leaf_04() &&
            leaf_05() &&
            leaf_06() &&
            leaf_09() &&
            leaf_0A()
        ) {
            return core::add(brands::HYPERV);
        }

        return false;
#endif
    }


    /**
     * @brief Check for KVM CPUID bitmask range for reserved values
     * @category x86
     */
    [[nodiscard]] static bool kvm_bitmask() {
#if (!x86)
        return false;
#else
        u32 eax, ebx, ecx, edx = 0;
        cpu::cpuid(eax, ebx, ecx, edx, 0x40000000);

        // KVM brand and max leaf check
        if (!(
            (eax == 0x40000001) &&
            (ebx == 0x4b4d564b) &&
            (ecx == 0x564b4d56) &&
            (edx == 0x4d)
        )) {
            return false;
        }

        cpu::cpuid(eax, ebx, ecx, edx, 0x40000001);

        if (
            (eax & (1 << 8)) &&
            (((eax >> 13) & 0b1111111111) == 0) &&
            ((eax >> 24) == 0)
        ) {
            return core::add(brands::KVM);
        }

        return false;
#endif
    }


    /**
     * @brief Check for Intel KGT (Trusty branch) hypervisor signature in CPUID
     * @link https://github.com/intel/ikgt-core/blob/7dfd4d1614d788ec43b02602cce7a272ef8d5931/vmm/vmexit/vmexit_cpuid.c
     * @category x86
     */
    [[nodiscard]] static bool intel_kgt_signature() {
#if (!x86)
        return false;
#else
        u32 unused, ecx, edx = 0;
        cpu::cpuid(unused, unused, ecx, edx, 3);

        if (
            // ecx should be "EVMM" and edx is "INTC".
            // Not sure if it's little endian or big endian, so i'm comparing both
            ((ecx == 0x4D4D5645) && (edx == 0x43544E49)) ||
            ((ecx == 0x45564D4D) && (edx == 0x494E5443))
        ) {
            return core::add(brands::INTEL_KGT);
        }

        return false;
#endif
    }


    /**
     * @brief Check for VMware DMI strings in BIOS serial number
     * @link https://knowledge.broadcom.com/external/article?legacyId=1009458
     * @category Windows
     */
    [[nodiscard]] static bool vmware_dmi() {
#if (!WINDOWS)
        return false;
#else
        std::unique_ptr<util::sys_info> info = util::make_unique<util::sys_info>();

        const std::string str = info->get_serialnumber();

        if (util::find(str, "VMware-")) {
            return core::add(brands::VMWARE);
        }

        if (util::find(str, "VMW")) {
            return core::add(brands::VMWARE_FUSION);
        }

        return false;
#endif
    } 


    /**
     * @brief Check for presence of Hyper-V in the Windows Event Logs
     * @category Windows
     * @author Requiem (https://github.com/NotRequiem)
     */
    [[nodiscard]] static bool hyperv_event_logs() {
#if (!WINDOWS)
        return false;
#else
        std::wstring logName = L"Microsoft-Windows-Kernel-PnP/Configuration"; // Example: "System", "Application", "Security", or a custom path. In this case, we use Microsoft-Windows-Kernel-PnP/Configuration as a Hyper-V VM artifact
        std::vector<std::wstring> searchStrings = { L"Virtual_Machine", L"VMBUS" };

        const bool found = util::query_event_logs(logName, searchStrings);

        if (found) {
            return core::add(brands::HYPERV);
        }

        return false;
#endif
    } 


    /**
     * @brief Check for presence of VMware in the Windows Event Logs
     * @category Windows
     * @author Requiem (https://github.com/NotRequiem)
     */
    [[nodiscard]] static bool vmware_event_logs() {
#if (!WINDOWS)
        return false;
#else
        std::vector<std::wstring> logNames = {
            L"Microsoft-Windows-Kernel-PnP/Configuration",
            L"Microsoft-Windows-StorageSpaces-Driver/Operational",
            L"Microsoft-Windows-Ntfs/Operational",
            L"Microsoft-Windows-DeviceSetupManager/Admin"
        };
        std::vector<std::wstring> searchStrings = { L"VMware Virtual NVMe Disk", L"_VMware_" };

        for (const auto& logName : logNames) {
            const bool found = util::query_event_logs(logName, searchStrings);
            if (found) {
                return core::add(brands::VMWARE);
            }
        }

        return false;
#endif
    }


    /**
     * @brief Check for presence of QEMU in the /sys/devices/virtual/dmi/id directory
     * @category Linux
     */
    [[nodiscard]] static bool qemu_virtual_dmi() {
#if (!LINUX)
        return false;
#else
        const char* sys_vendor = "/sys/devices/virtual/dmi/id/sys_vendor";
        const char* modalias = "/sys/devices/virtual/dmi/id/modalias";

        if (
            util::exists(sys_vendor) &&
            util::exists(modalias)
        ) {
            const std::string sys_vendor_str = util::read_file(sys_vendor);
            const std::string modalias_str = util::read_file(modalias);

            return (
                util::find(sys_vendor_str, "QEMU") &&
                util::find(modalias_str, "QEMU")
            );
        }

        return false;
#endif
    } 


    /**
     * @brief Check for presence of QEMU in the /sys/kernel/debug/usb/devices directory
     * @category Linux
     */
    [[nodiscard]] static bool qemu_USB() {
#if (!LINUX)
        return false;
#else
        if (!util::is_admin()) {
            return false;
        }

        const char* usb_path = "/sys/kernel/debug/usb/devices";

        if (util::exists(usb_path)) {
            const std::string usb_path_str = util::read_file(usb_path);
            return (util::find(usb_path_str, "QEMU"));
        }

        return false;
#endif
    } 


    /**
     * @brief Check for presence of any files in /sys/hypervisor directory
     * @category Linux
     */
    [[nodiscard]] static bool hypervisor_dir() {
#if (!LINUX)
        return false;
#else
        DIR* dir = opendir("/sys/hypervisor");

        if (dir == nullptr) {
            return false;
        }

        struct dirent* entry;
        int count = 0;

        while ((entry = readdir(dir)) != nullptr) {
            if (
                (entry->d_name[0] == '.' && entry->d_name[1] == '\0') || 
                (entry->d_name[1] == '.' && entry->d_name[2] == '\0')
            ) {
                continue;
            }

            count++;
            break;
        }

        closedir(dir);

        bool type = false;

        if (util::exists("/sys/hypervisor/type")) {
            type = true;
        }

        if (type) {
            const std::string content = util::read_file("/sys/hypervisor/type");
            if (util::find(content, "xen")) {
                return core::add(brands::XEN);
            }
        }

        // check if there's a few files in that directory
        return ((count != 0) && type);
#endif
    } 


    /**
     * @brief Check for the "UML" string in the CPU brand
     * @note idea from https://github.com/ShellCode33/VM-Detection/blob/master/vmdetect/linux.go
     * @category Linux
     */
    [[nodiscard]] static bool uml_cpu() {
#if (!LINUX)
        return false;
#else
        // method 1, get the CPU brand model
        const std::string brand = cpu::get_brand();

        if (brand == "UML") {
            return core::add(brands::UML);
        }

        // method 2, match for the "User Mode Linux" string in /proc/cpuinfo
        const char* file = "/proc/cpuinfo";

        if (util::exists(file)) {
            const std::string file_content = util::read_file(file);

            if (util::find(file_content, "User Mode Linux")) {
                return core::add(brands::UML);
            }
        }

        return false;
#endif
    } 


    /**
     * @brief Check for any indications of hypervisors in the kernel message logs
     * @note idea from https://github.com/ShellCode33/VM-Detection/blob/master/vmdetect/linux.go
     * @category Linux
     */
    [[nodiscard]] static bool kmsg() {
#if (!LINUX)
        return false;
#else
        if (!util::is_admin()) {
            return false;
        }

        // Open /dev/kmsg
        int fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
        if (fd < 0) {
            debug("KMSG: Failed to open /dev/kmsg");
            return 1;
        }

        char buffer[1024];
        std::stringstream ss;

        while (true) {
            ssize_t bytes_read = read(fd, buffer, sizeof(buffer) - 1);

            if (bytes_read > 0) {
                buffer[bytes_read] = '\0';
                ss << buffer;
            } else if (bytes_read == 0) {
                usleep(100000); // Sleep for 100 milliseconds
            } else {
                if (errno == EAGAIN) {
                    usleep(100000); // Sleep for 100 milliseconds
                } else {
                    debug("KMSG: Error reading /dev/kmsg");
                    break;
                }
            }

            if (bytes_read < 0) {
                break;
            }
        }

        close(fd);

        const std::string content = ss.str();

        if (content.empty()) {
            return false;
        }

        return (util::find(content, "Hypervisor detected"));
#endif
    } 


    /**
     * @brief Check for a Xen VM process
     * @note idea from https://github.com/ShellCode33/VM-Detection/blob/master/vmdetect/linux.go
     * @category Linux
     */
    [[nodiscard]] static bool vm_procs() {
#if (!LINUX)
        return false;
#else
        if (util::exists("/proc/xen")) {
            return core::add(brands::XEN);
        }

        if (util::exists("/proc/vz")) {
            return core::add(brands::OPENVZ);
        }

        return false;
#endif
    } 


    /**
     * @brief Check for a VBox kernel module
     * @note idea from https://github.com/ShellCode33/VM-Detection/blob/master/vmdetect/linux.go
     * @category Linux
     */
    [[nodiscard]] static bool vbox_module() {
#if (!LINUX)
        return false;
#else
        const char* file = "/proc/modules";

        if (!util::exists(file)) {
            return false;
        }

        const std::string content = util::read_file(file);

        if (util::find(content, "vboxguest")) {
            return core::add(brands::VBOX);
        }

        return false;
#endif
    }


    /**
     * @brief Check for potential VM info in /proc/sysinfo
     * @note idea from https://github.com/ShellCode33/VM-Detection/blob/master/vmdetect/linux.go
     * @category Linux
     */
    [[nodiscard]] static bool sysinfo_proc() {
#if (!LINUX)
        return false;
#else
        const char* file = "/proc/sysinfo";

        if (!util::exists(file)) {
            return false;
        }

        const std::string content = util::read_file(file);

        if (util::find(content, "VM00")) {
            return true;
        }

        return false;
#endif
    } 


    /**
     * @brief Check for specific files in /proc/device-tree directory
     * @note idea from https://github.com/ShellCode33/VM-Detection/blob/master/vmdetect/linux.go
     * @category Linux
     */
    [[nodiscard]] static bool device_tree() {
#if (!LINUX)
        return false;
#else
        if (util::exists("/proc/device-tree/fw-cfg")) {
            return core::add(brands::QEMU);
        }

        return (util::exists("/proc/device-tree/hypervisor/compatible"));
#endif
    } 


    /**
     * @brief Check for string matches of VM brands in the linux DMI
     * @category Linux
     */
    [[nodiscard]] static bool dmi_scan() {
#if (!LINUX)
        return false;
#else
        /*
        cat: /sys/class/dmi/id/board_serial: Permission denied
        cat: /sys/class/dmi/id/chassis_serial: Permission denied
        cat: /sys/class/dmi/id/product_serial: Permission denied
        cat: /sys/class/dmi/id/product_uuid: Permission denied
        */

        constexpr std::array<const char*, 7> dmi_array {
            "/sys/class/dmi/id/bios_vendor",
            "/sys/class/dmi/id/board_name",
            "/sys/class/dmi/id/board_vendor",
            "/sys/class/dmi/id/chassis_asset_tag",
            "/sys/class/dmi/id/product_family",
            "/sys/class/dmi/id/product_sku",
            "/sys/class/dmi/id/sys_vendor"
        };

        constexpr std::array<std::pair<const char*, const char*>, 15> vm_table {{
            { "kvm", brands::KVM },
            { "openstack", brands::OPENSTACK },
            { "kubevirt", brands::KUBEVIRT },
            { "amazon ec2", brands::AWS_NITRO },
            { "qemu", brands::QEMU },
            { "vmware", brands::VMWARE },
            { "innotek gmbh", brands::VBOX },
            { "virtualbox", brands::VBOX },
            { "oracle corporation", brands::VBOX },
            //{ "xen", XEN },
            { "bochs", brands::BOCHS },
            { "parallels", brands::PARALLELS },
            { "bhyve", brands::BHYVE },
            { "hyper-v", brands::HYPERV },
            { "apple virtualization", brands::APPLE_VZ },
            { "google compute engine", brands::GCE }
        }};

        auto to_lower = [](std::string &str) {
            for (auto& c : str) {
                if (c == ' ') {
                    continue;
                }

                c = static_cast<char>(tolower(c));
            }
        };

        for (const auto &vm_string : vm_table) {
            for (const auto file : dmi_array) {
                if (!util::exists(file)) {
                    continue;
                }

                std::string content = util::read_file(file);

                to_lower(content);

                if (std::regex_search(content, std::regex(vm_string.first))) {
                    debug("DMI_SCAN: content = ", content);
                    if (std::strcmp(vm_string.second, brands::AWS_NITRO) == 0) {
                        if (smbios_vm_bit()) {
                            return core::add(brands::AWS_NITRO);
                        }
                    } else {
                        return core::add(vm_string.second);
                    }
                }
            }
        }

        return false;
#endif
    } 


    /**
     * @brief Check for the VM bit in the SMBIOS data
     * @note idea from https://github.com/systemd/systemd/blob/main/src/basic/virt.c
     * @category Linux
     */
    [[nodiscard]] static bool smbios_vm_bit() {
#if (!LINUX)
        return false;
#else
        if (!util::is_admin()) {
            return false;
        }

        const char* file = "/sys/firmware/dmi/entries/0-0/raw";

        if (!util::exists(file)) {
            return false;
        }

        const std::vector<u8> content = util::read_file_binary(file);

        if (content.size() < 20 || content.at(1) < 20) {
            debug("SMBIOS_VM_BIT: ", "only read ", content.size(), " bytes, expected 20");
            return false;
        }

        debug("SMBIOS_VM_BIT: ", "content.at(19) = ", static_cast<int>(content.at(19)));

        return (content.at(19) & (1 << 4));
#endif
    } 


    /**
     * @brief Check for podman file in /run/
     * @note idea from https://github.com/systemd/systemd/blob/main/src/basic/virt.c
     * @category Linux
     */
    [[nodiscard]] static bool podman_file() {
#if (!LINUX)
        return false;
#else
        if (util::exists("/run/.containerenv")) {
            return core::add(brands::PODMAN);
        }

        return false;
#endif
    }


    /**
     * @brief Check for WSL or microsoft indications in /proc/ subdirectories
     * @note idea from https://github.com/systemd/systemd/blob/main/src/basic/virt.c
     * @category Linux
     */
    [[nodiscard]] static bool wsl_proc_subdir() {
#if (!LINUX)
        return false;
#else
        const char* osrelease = "/proc/sys/kernel/osrelease";
        const char* version = "/proc/version";

        if (
            util::exists(osrelease) &&
            util::exists(version)
        ) {
            const std::string osrelease_content = util::read_file(osrelease);
            const std::string version_content = util::read_file(version);

            if (
                (util::find(osrelease_content, "WSL") || util::find(osrelease_content, "Microsoft")) &&
                (util::find(version, "WSL") || util::find(version, "Microsoft"))
            ) {
                return core::add(brands::WSL);
            }
        }

        return false;
#endif
    } 


    /**
     * @brief Use wmic to get the GPU/videocontrollers chip type.
     * @category Windows
     * @author utoshu
     */
    [[nodiscard]] static bool gpu_chiptype() {
#if (!WINDOWS)
        return false;
#else
        if (!wmi::initialize()) {
            core_debug("Failed to initialize WMI in gpu_chiptype");
            return false;
        }

        wmi_result results = wmi::execute(L"SELECT * FROM Win32_VideoController", { L"VideoProcessor" });

        std::string result = "";
        for (const auto& res : results) {
            if (res.type == wmi::result_type::String) {
                result += res.strValue + "\n"; // Collect video processor names
            }
        }

        std::transform(result.begin(), result.end(), result.begin(), 
            [](unsigned char c) { 
                return static_cast<char>(::tolower(c));
            }
        );

        if (util::find(result, "vmware")) {
            return core::add(brands::VMWARE);
        }

        if (util::find(result, "virtualbox")) {
            return core::add(brands::VBOX);
        }

        if (util::find(result, "hyper-v")) {
            return core::add(brands::HYPERV);
        }

        return false;
#endif
    }


    /**
     * @brief Check for VM-specific names for drivers
     * @category Windows
     * @author Requiem (https://github.com/NotRequiem)
     */
    [[nodiscard]] static bool driver_names() {
#if (!WINDOWS)
        return false;
#else
        const int maxDrivers = 1024;
        std::vector<LPVOID> drivers(maxDrivers);
        DWORD cbNeeded;

        if (!EnumDeviceDrivers(drivers.data(), maxDrivers * sizeof(LPVOID), &cbNeeded)) {
            debug("Failed to enumerate device drivers");
            return false;
        }

        int count = cbNeeded / sizeof(LPVOID);
        char driverName[MAX_PATH];

        for (int i = 0; i < count; ++i) {
            if (GetDeviceDriverBaseNameA(drivers[i], driverName, static_cast<DWORD>(sizeof(driverName)))) {
                if (
                    strcmp(driverName, "VBoxGuest") == 0 ||
                    strcmp(driverName, "VBoxMouse") == 0 ||
                    strcmp(driverName, "VBoxSF") == 0
                    ) {
                    return core::add(brands::VBOX);
                }

                if (
                    strcmp(driverName, "vmusbmouse") == 0 ||
                    strcmp(driverName, "vmmouse") == 0 ||
                    strcmp(driverName, "vmmemctl") == 0
                    ) {
                    return core::add(brands::VMWARE);
                }
            }
            else {
                debug("Failed to retrieve driver name");
                return false;
            }
        }
        return false;
#endif
    }


    /**
     * @brief Check for unknown IDT base address
     * @category Windows
     * @author Requiem (https://github.com/NotRequiem)
     */
    [[nodiscard]] static bool vm_sidt() {
#if (!WINDOWS || !x86) 
        return false;
#else
#pragma pack(push, 1)
        struct IDTR { uint16_t limit;  uint64_t base; };
#pragma pack(pop)
        IDTR idtr;
        __sidt(&idtr);
        u64 idt_base = idtr.base;

        constexpr u64 known_hyperv_exclusion = 0xfffff80000001000;

        if ((idt_base & 0xFFFF000000000000) == 0xFFFF000000000000 && idt_base != known_hyperv_exclusion) {
            return true;
        }

        return false;
#endif
    }


    /**
     * @brief Check for HDD serial number
     * @category Windows
     * @author Requiem (https://github.com/NotRequiem)
     */
    [[nodiscard]] static bool hdd_serial_number() {
#if (!WINDOWS) 
        return false;
#else
        if (!wmi::initialize()) {
            core_debug("Failed to initialize WMI in hdd_serial_number");
            return false;
        }

        const char* targetSerial = "VBbd5bbffd-59166c24";

        wmi_result results = wmi::execute(L"SELECT SerialNumber FROM Win32_DiskDrive", { L"SerialNumber" });

        for (const auto& res : results) {
            if (res.type == wmi::result_type::String) {
                if (_stricmp(res.strValue.c_str(), targetSerial) == 0) {
                    return core::add(brands::VBOX);
                }
            }
        }

        return false;
#endif
    };


    /**
     * @brief Check for physical connection ports
     * @category Windows
     * @author @unusual-aspect (https://github.com/unusual-aspect)
     */
    [[nodiscard]] static bool port_connectors() {
#if (!WINDOWS) 
        return false;
#else
        if (!wmi::initialize()) {
            core_debug("Failed to initialize WMI in port_connectors");
            return false;
        }

        wmi_result results = wmi::execute(L"SELECT * FROM Win32_PortConnector", { L"Caption" });

        return results.empty();
#endif
    };


    /**
     * @brief Check for VM keywords in HDD model
     * @category Windows
     */
    [[nodiscard]] static bool vm_hdd() {
#if (!WINDOWS) 
        return false;
#else
        if (!wmi::initialize()) {
            core_debug("Failed to initialize WMI in vm_hdd");
            return false;
        }

        wmi_result results = wmi::execute(L"SELECT Model FROM Win32_DiskDrive", { L"Model" });

        for (const auto& res : results) {
            if (res.type == wmi::result_type::String) {
                debug("QEMU_HDD: model = ", res.strValue);
                if (util::find(res.strValue, "QEMU")) {
                    return core::add(brands::QEMU);
                }

                if (util::find(res.strValue, "Virtual HD ATA Device")) {
                    return core::add(brands::HYPERV);
                }
            }
        }

        return false;
#endif
    };


    /**
     * @brief Check for Hyper-V string in ACPI data
     * @category Windows
     * @note idea by Requiem
     */
    [[nodiscard]] static bool acpi_detect() {
#if (!WINDOWS) 
        return false;
#else
        return (
            (util::AcpiData_string() == "VRTUAL MICROSFT") ||
            (util::AcpiData_string() == "VMWARE")
        );
#endif
    };


    /**
     * @brief Check for VM specific device names in GPUs
     * @category Windows
     * @author Requiem (https://github.com/NotRequiem)
     */
    [[nodiscard]] static bool vm_gpu() {
#if (!WINDOWS)
        return false;
#else
        // Define VM GPU names in TCHAR format
        constexpr std::array<const TCHAR*, 8> vm_gpu_names = {
            _T("VMware SVGA 3D"),
            _T("Microsoft Basic Render Driver"),
            _T("VirtualBox Graphics Adapter"),
            _T("Parallels Display Adapter (WDDM)"),
            _T("QXL GPU"),
            _T("VirGL 3D"),
            _T("Bochs Graphics Adapter"),
            _T("Hyper-V Video")
        };

        DISPLAY_DEVICE dd{};
        dd.cb = sizeof(DISPLAY_DEVICE);
        DWORD deviceNum = 0;

        while (EnumDisplayDevices(nullptr, deviceNum, &dd, 0)) {
            const std::basic_string<TCHAR> deviceString(dd.DeviceString);
            for (const auto& vm_gpu : vm_gpu_names) {
                if (deviceString == vm_gpu) {
                    return true;
                }
            }
            ++deviceNum;
        }
        return false;
#endif
    }


    /**
     * @brief Check for VMware-specific devices
     * @category Windows
     */
    [[nodiscard]] static bool vmware_devices() {
#if (!WINDOWS)
        return false;
#else
        HANDLE h1 = CreateFileA("\\\\.\\HGFS", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        bool result = false;

        if (h1 != INVALID_HANDLE_VALUE) {
            result = true;
        }

        CloseHandle(h1);

        if (result) {
            return core::add(brands::VMWARE);
        }

        return false;
#endif
    }    


    /**
     * @brief Check for VMware-specific memory trace in a specific process.
     * @category Windows
     * @author Requiem (https://github.com/NotRequiem)
     */
    [[nodiscard]] static bool vmware_memory() {
#if (!WINDOWS)
        return false;
#else
        const std::wstring searchString1 = L"_VMWARE_";
        const std::wstring searchString2 = L"VMware, Inc.";

        auto search_service_memory = [](const std::wstring& searchString, const std::string& serviceName) -> bool {
            const DWORD pid = util::FindProcessIdByServiceName(serviceName);
            if (pid == 0) return false; // Process missing; potentially tampered

            util::EnableDebugPrivilege();

            const HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (!hProcess) return false; // Not running as admin or insufficient permissions

            MEMORY_BASIC_INFORMATION mbi{};
            uintptr_t address = 0x1000;

            while (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == sizeof(mbi)) {
                uintptr_t regionBase = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                if (regionBase == 0 || address == 0) {
                    address += mbi.RegionSize;
                    continue;
                }

                if (
                    (mbi.State == MEM_COMMIT) &&
                    (mbi.Protect & (PAGE_READWRITE)) &&
                    !(mbi.Protect & PAGE_GUARD) &&
                    !(mbi.Protect & PAGE_NOACCESS)
                ) {
                    size_t regionSize = static_cast<size_t>(mbi.RegionSize);
                    std::vector<wchar_t> buffer(regionSize / sizeof(wchar_t));
                    SIZE_T bytesRead = 0;

                    if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(regionBase), buffer.data(), buffer.size() * sizeof(wchar_t), &bytesRead) && bytesRead > 0) {
                        if (util::findSubstring(buffer.data(), bytesRead / sizeof(wchar_t), searchString)) {
                            CloseHandle(hProcess);
                            return true;
                        }
                    }
                }

                address = regionBase + mbi.RegionSize;
            }

            CloseHandle(hProcess);
            return false;
        };

        if (search_service_memory(searchString1, "PlugPlay")) {
            return core::add(brands::VMWARE);
        }

        if (search_service_memory(searchString2, "Winmgmt")) {
            return core::add(brands::VMWARE);
        }

        if (search_service_memory(searchString2, "CDPSvc")) {
            return core::add(brands::VMWARE);
        }

        return false;
#endif
    }


    /**
     * @brief Check if the IDT and GDT limit addresses mismatch between different CPU cores. 
     * Despite the Windows kernel having different interrupt handlers registered for each CPU core, Windows typically uses identical virtual addresses for GDT and IDT across cores.
     * While the interrupt handlers (the actual ISR code) are typically the same across cores, each core may maintain its own IDT to handle specific local or processor-specific interrupts.
     * The virtual memory system allows mapping different physical memory locations to the same virtual address to minimize context switching overhead.
     * The CPU core's descriptor registers (GDTR and IDTR) are then used to point to the correct physical addresses of these tables.
     * @category Windows, x64
     * @author Requiem (https://github.com/NotRequiem)
     */
    [[nodiscard]] static bool idt_gdt_mismatch() {
#if (!WINDOWS)
        return false;
#else
        unsigned int num_threads = std::thread::hardware_concurrency();

        std::vector<std::thread> threads;
        std::vector<std::string> gdtResults(num_threads);
        std::vector<std::string> idtResults(num_threads);

        for (unsigned int i = 0; i < num_threads; ++i) {
            threads.emplace_back([i, &gdtResults, &idtResults]() {
                const HANDLE thread = GetCurrentThread();
                DWORD_PTR affinity_mask = 1ULL << i; // Bind thread to core i
                SetThreadAffinityMask(thread, affinity_mask);

#pragma pack(push, 1)
                struct DescriptorTablePointer {
                    uint16_t limit;
                    uint64_t base;   
                };
#pragma pack(pop)

                DescriptorTablePointer idtr = {};
                DescriptorTablePointer gdtr = {};

                __sidt(&idtr);
                _sgdt(&gdtr);  

                gdtResults[i] = std::to_string(gdtr.base);
                idtResults[i] = std::to_string(idtr.base);
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }
        for (unsigned int i = 1; i < num_threads; ++i) {
            if (gdtResults[i] != gdtResults[0]) {
                return true;
            }
        }
        for (unsigned int i = 1; i < num_threads; ++i) {
            if (idtResults[i] != idtResults[0]) {
                return true;
            }
        }

        return false;
#endif
    }


    /**
     * @brief Check for number of processors
     * @category Windows
     * @author idea from Al-Khaser project
     */
    [[nodiscard]] static bool processor_number()
    {
#if (!WINDOWS)
        return false;
#else
#if (x86_32)
        PULONG ulNumberProcessors = (PULONG)(__readfsdword(0x30) + 0x64);

#else
        PULONG ulNumberProcessors = (PULONG)(__readgsqword(0x60) + 0xB8);
#endif

        if (*ulNumberProcessors < 2)
            return true;
        else
            return false;
#endif
    }


    /**
     * @brief Check for number of cores
     * @category Windows
     * @author idea from Al-Khaser project
     */
    [[nodiscard]] static bool number_of_cores() {
#if (!WINDOWS)
        return false;
#else
        if (!wmi::initialize()) {
            core_debug("Failed to initialize WMI in number_of_cores");
            return false;
        }

        std::wstring query = L"SELECT NumberOfCores FROM Win32_Processor";
        std::vector<std::wstring> properties = { L"NumberOfCores" };

        wmi_result results = wmi::execute(query, properties);

        for (const auto& result : results) {
            if (result.type == wmi::result_type::Integer) {
                if (result.intValue < 2) {
                    return true; 
                }
            }
        }

        return false;
#endif
    }


    /**
     * @brief Check for device's model using WMI
     * @category Windows
     * @author idea from Al-Khaser project
     */
    [[nodiscard]] static bool wmi_model() {
#if (!WINDOWS)
        return false;
#else
        if (!wmi::initialize()) {
            core_debug("Failed to initialize WMI in number_of_cores");
            return false;
        }

        std::wstring query = L"SELECT Model FROM Win32_ComputerSystem";
        std::vector<std::wstring> properties = { L"Model" };
        wmi_result results = wmi::execute(query, properties);

        for (const auto& result : results) {
            if (result.type == wmi::result_type::String) {
                if (result.strValue == "VirtualBox" || result.strValue == "HVM domU" || result.strValue == "VMWare") {
                    return true;
                }
            }
        }
        return false;
#endif
    }


    /**
     * @brief Check for device's manufacturer using WMI
     * @category Windows
     * @author idea from Al-Khaser project
     */
    [[nodiscard]] static bool wmi_manufacturer() {
#if (!WINDOWS)
        return false;
#else
        if (!wmi::initialize()) {
            core_debug("Failed to initialize WMI in wmi_manufacturer");
            return false;
        }

        std::wstring query = L"SELECT Manufacturer FROM Win32_ComputerSystem";
        std::vector<std::wstring> properties = { L"Manufacturer" };
        wmi_result results = wmi::execute(query, properties);

        for (const auto& result : results) {
            if (result.type == wmi::result_type::String) {
                if (result.strValue == "VMWare" || result.strValue == "innotek GmbH" || result.strValue == "Xen" || result.strValue == "QEMU") {
                    return true;
                }
            }
        }
        return false;
#endif
    }


    /**
     * @brief Check for device's temperature
     * @category Windows
     * @author idea from Al-Khaser project
     */
    [[nodiscard]] static bool wmi_temperature() {
#if (!WINDOWS)
        return false;
#else
        if (!wmi::initialize()) {
            core_debug("Failed to initialize WMI in wmi_temperature");
            return false;
        }

        std::wstring query = L"SELECT * FROM MSAcpi_ThermalZoneTemperature";
        std::vector<std::wstring> properties = { L"CurrentTemperature" };

        std::vector<wmi::result> results = wmi::execute(query, properties);

        for (const auto& res : results) {
            if (res.type == wmi::result_type::Integer) {
                return true;
            }
        }

        return false;
#endif
    }


    /**
     * @brief Check for empty processor ids using wmi
     * @category Windows
     * @author idea from Al-Khaser project
     */
    [[nodiscard]] static bool processor_id() {
#if (!WINDOWS)
        return false;
#else
        if (!wmi::initialize()) {
            core_debug("Failed to initialize WMI in processor_id");
            return false;
        }

        std::wstring query = L"SELECT ProcessorId FROM Win32_Processor";
        std::vector<std::wstring> properties = { L"ProcessorId" };
        wmi_result results = wmi::execute(query, properties);

        for (const auto& result : results) {
            if (result.type == wmi::result_type::String) {
                if (result.strValue.empty()) {
                    return true;
                }
            }
        }
        return false;
#endif
    }


    /**
     * @brief Check for CPU Fans
     * @category Windows
     * @author idea from Al-Khaser project
     */
    [[nodiscard]] static bool cpu_fans() {
#if (!WINDOWS)
        return false;
#else
        if (!wmi::initialize()) {
            core_debug("Failed to initialize WMI in cpu_fans");
            return false;
        }

        std::wstring query = L"SELECT * FROM Win32_Fan";
        std::vector<std::wstring> properties = { };
        wmi_result results = wmi::execute(query, properties);

        return !results.empty();
#endif
    }


    /**
     * @brief Check RDTSC
     * @category Windows
     * @note This has been revised multiple times with previously removed techniques
     */
    [[nodiscard]] 
#if (LINUX)
    // this is added so that no sanitizers can potentially cause unwanted delays while measuring rdtsc in a debug compilation
    __attribute__((no_sanitize("address", "leak", "thread", "undefined")))
#endif

static bool rdtsc() {
#if (!LINUX && !WINDOWS)
        return false;
#else

        u64 start, end, total_cycles = 0;
        u32 eax = 0, ebx = 0, ecx = 0, edx = 0;
        i32 cpu_info[4];

        constexpr i32 iterations = 10000;
        constexpr u32 threshold = 25000;

        for (int i = 0; i < iterations; i++) {
            start = __rdtsc();
    #if (WINDOWS)
            __cpuid(cpu_info, 0);
    #elif (LINUX)
            __cpuid(0, eax, ebx, ecx, edx);
    #endif
            end = __rdtsc();

            total_cycles += (end - start);
        }

        UNUSED(eax);
        UNUSED(ebx);
        UNUSED(ecx);
        UNUSED(edx);
        UNUSED(cpu_info);

        double average_cycles = (double)total_cycles / iterations;

        return (average_cycles >= threshold);
#endif    
    }


    /*
     * @brief Detects VMwareHardenerLoader's technique to remove firmware signatures
     * @category Windows
     * @author MegaMax
     */
    [[nodiscard]] static bool vmware_hardener()
    {
#if (!WINDOWS)
        return false;
#else
        static const DWORD kProviders[] = { 'ACPI', 'RSMB', 'FIRM' };
        static const char* kPatchedStrings[] = { "VMware", "VMWARE", "Virtual" };

        for (DWORD provider : kProviders)
        {
            DWORD bufferSize = EnumSystemFirmwareTables(provider, NULL, 0);
            if (bufferSize == 0)
            {
                return false;
            }

            std::vector<char> tableNames(bufferSize);
            if (EnumSystemFirmwareTables(provider, tableNames.data(), (DWORD)tableNames.size()) == 0)
            {
                return false;
            }

            for (size_t i = 0; i < tableNames.size(); i += 4)
            {
                DWORD signature = *(DWORD*)&tableNames[i];

                DWORD requiredSize = GetSystemFirmwareTable(provider, signature, NULL, 0);
                if (requiredSize == 0)
                {
                    continue;
                }

                std::vector<BYTE> tableBuffer(requiredSize);
                if (GetSystemFirmwareTable(provider, signature, tableBuffer.data(), requiredSize) == 0)
                {
                    continue;
                }

                std::string tableData((char*)tableBuffer.data(), tableBuffer.size());
                for (const char* original : kPatchedStrings)
                {
                    size_t orig_len = strlen(original);
                    if (tableData.find(original) == std::string::npos)
                    {
                        std::string replaced(orig_len, '7');
                        if (tableData.find(replaced) != std::string::npos)
                        {
                            return core::add(brands::VMWARE, brands::VMWARE_HARD);
                        }
                    }
                }
            }
        }

        return false;
#endif
    }
 

	/**
	 * @brief Check for existence of qemu_fw_cfg directories within sys/module and /sys/firmware
	 * @category Linux
	 * @note 
	 */
	[[nodiscard]] static bool sys_qemu_dir() {
#if (!LINUX)
	    return false;
#else
	    const std::string module_path = "/sys/module/qemu_fw_cfg/";
	    const std::string firmware_path = "/sys/firmware/qemu_fw_cfg/";
	
    #if (CPP >= 17)
        namespace fs = std::filesystem;

	    return (
	        fs::is_directory(module_path) && 
	        fs::is_directory(firmware_path) &&
	        fs::exists(module_path) &&
	        fs::exists(firmware_path)
	    );
    #else
        auto is_directory(const std::string& path) -> bool {
            struct stat info;
            if (stat(path.c_str(), &info) != 0) {
                return false;
            }
            return (info.st_mode & S_IFDIR); // check if directory
        };

    	return (
	        is_directory(module_path) && 
	        is_directory(firmware_path) &&
	        util::exists(module_path) &&
	        util::exists(firmware_path)
	    );
    #endif
#endif
	}


	/**
	 * @brief Check for QEMU string instances with lshw command
	 * @category Linux
	 * @note 
	 */
	[[nodiscard]] static bool lshw_qemu() {
#if (!LINUX)
	    return false;
#else
	    if (!(
            (util::exists("/usr/bin/lshw")) || 
            (util::exists("/bin/lshw")) ||
            (util::exists("/usr/sbin/lshw"))
        )) {
	        debug("LSHW_QEMU: ", "binary doesn't exist");
	        return false;
	    }

	    const std::unique_ptr<std::string> result = util::sys_result("lshw 2>&1");
	
	    if (result == nullptr) {
	        debug("LSHW_QEMU: ", "invalid stdout output from lshw");
	        return false;
	    }
	
	    const std::string full_command = *result;
	
	    u8 score = 0;

        auto qemu_finder = [&](const char* str) -> void {
            if (util::find(full_command, str)) { 
                debug("LSHW_QEMU: found ", str);
                score++; 
            }
        };
	
	    qemu_finder("QEMU PCIe Root port");
	    qemu_finder("QEMU XHCI Host Controller");
	    qemu_finder("QEMU DVD-ROM");
	    qemu_finder("QEMU QEMU USB Tablet");
	
	    return (score >= 3);
#endif
	}

    // ADD NEW TECHNIQUE FUNCTION HERE




















    struct core {
        MSVC_DISABLE_WARNING(PADDING)
        struct technique {
            u8 points = 0;                // this is the certainty score between 0 and 100
            std::function<bool()> run;    // this is the technique function itself
            bool is_spoofable = false;    // this is to indicate that the technique can be very easily spoofed (not guaranteed)
        };

        struct custom_technique {
            u8 points;
            u16 id;
            std::function<bool()> run;
        };
        MSVC_ENABLE_WARNING(PADDING)

        // initial technique list, this is where all the techniques are stored
        static std::pair<enum_flags, technique> technique_list[];
    
        // the actual table, which is derived from the list above and will be 
        // used for most functionalities related to technique interactions
        static std::map<enum_flags, technique> technique_table;

        // specific to VM::add_custom(), where custom techniques will be stored here
        static std::vector<custom_technique> custom_table;
        
        // self-explanatory
        static bool cpuid_supported;

        // VM scoreboard table specifically for VM::brand()
        static std::map<const char*, brand_score_t> brand_scoreboard;

        // directly return when adding a brand to the scoreboard for a more succint expression
#if (WINDOWS)
        __declspec(noalias)
#elif (LINUX)
        [[gnu::const]]
#endif
        static inline bool add(const char* p_brand, const char* extra_brand = "") noexcept {
            core::brand_scoreboard.at(p_brand)++;
            if (std::strcmp(extra_brand, "") != 0) {
                core::brand_scoreboard.at(p_brand)++;
            }
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

        [[nodiscard]] static bool is_setting_flag_set(const flagset& flags) {
            for (std::size_t i = settings_begin; i < settings_end; i++) {
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

            if (!core::is_setting_flag_set(flags)) {
                throw std::invalid_argument("Invalid flag option for function parameter found, either leave it empty or add the VM::DEFAULT flag");
            }

            // at this stage, only setting flags are asserted to be set
            if (
                flags.test(NO_MEMO) ||
                flags.test(HIGH_THRESHOLD) ||
                flags.test(DYNAMIC) ||
                flags.test(NULL_ARG) ||
                flags.test(MULTIPLE)
            ) {
                flags |= DEFAULT;
            } else {
                throw std::invalid_argument("Invalid flag option found, aborting");
            }
        }

        // run every VM detection mechanism in the technique table
        static u16 run_all(const flagset& flags, const bool shortcut = false) {
            u16 points = 0;

            const bool memo_enabled = core::is_disabled(flags, NO_MEMO);

            u16 threshold_points = 150;
            
            // set it to 300 if high threshold is enabled
            if (core::is_enabled(flags, HIGH_THRESHOLD)) {
                threshold_points = high_threshold_score;
            }

            // loop through the technique table, where all the techniques are stored
            for (const auto& tmp : technique_table) {
                const enum_flags technique_macro = tmp.first;
                const technique technique_data = tmp.second;

                // check if the technique is disabled
                if (core::is_disabled(flags, technique_macro)) {
                    continue;
                }

                // check if it's spoofable, and whether it's enabled (NOTE: SPOOFABILITY IS DEPRECATED)
                //if (
                //    technique_data.is_spoofable && 
                //    core::is_disabled(flags, SPOOFABLE)
                //) {
                //    continue;
                //}

                // check if the technique is cached already
                if (memo_enabled && memo::is_cached(technique_macro)) {
                    const memo::data_t data = memo::cache_fetch(technique_macro);

                    if (data.result) {
                        points += data.points;
                    }

                    continue;
                }

                // run the technique
                const bool result = technique_data.run();

                // accumulate the points if technique detected a VM
                if (result) {
                    points += technique_data.points;

                    // this is specific to VM::detected_count() which returns 
                    // the number of techniques that returned a positive
                    detected_count_num++;
                }
                
                // for things like VM::detect() and VM::percentage(),
                // a score of 150+ is guaranteed to be a VM, so
                // there's no point in running the rest of the techniques
                if (shortcut && points >= threshold_points) {
                    return points;
                }

                // store the current technique result to the cache
                if (memo_enabled) {
                    memo::cache_store(technique_macro, result, technique_data.points);
                }
            }

            // for custom VM techniques, won't be used most of the time
            if (!custom_table.empty()) {
                for (const auto& technique : custom_table) {

                    // if cached, return that result
                    if (memo_enabled && memo::is_cached(technique.id)) {
                        const memo::data_t data = memo::cache_fetch(technique.id);

                        if (data.result) {
                            points += data.points;
                        }

                        continue;
                    }

                    // run the custom technique
                    const bool result = technique.run();

                    // accumulate a few important values
                    if (result) {
                        points += technique.points;
                        detected_count_num++;
                    }

                    // cache the result
                    if (memo_enabled) {
                        memo::cache_store(
                            technique.id,
                            result, 
                            technique.points
                        );
                    }
                }
            }

            return points;
        }


        /**
         * basically what this entire template fuckery does is manage the
         * variadic arguments being given through the arg_handler function,
         * which could either be a std::bitset<N>, a uint8_t, or a combination
         * of both of them. This will handle both argument types and implement
         * them depending on what their types are. If it's a std::bitset<N>,
         * do the |= operation on flag_collector. If it's a uint8_t, simply 
         * .set() that into the flag_collector. That's the gist of it.
         *
         * Also I won't even deny, the majority of this section was 90% generated
         * by chatgpt. Can't be arsed with this C++ templatisation shit.
         * Like is it really my fault that I have a hard time understanging C++'s 
         * god awful metaprogramming designs? And don't even get me started on SNIFAE. 
         * 
         * You don't need an IQ of 3 digits to realise how dogshit this language
         * is, when you end up in situations where there's a few correct solutions
         * to a problem, but with a billion ways you can do the same thing but in 
         * the "wrong" way. I genuinely can't wait for Carbon to come out.
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
            } else if (isType<enum_flags>(first)) {
                dispatch(first, uint8Handler);
            } else {
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
            } else if (isType<enum_flags>(first)) {
                dispatch(first, uint8Handler);
            } else {
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
        // fetch the flags, could be an enum value OR a std::bitset.
        // This will then generate a different std::bitset as the 
        // return value by enabling the bits based on the argument.
        template <typename... Args>
        static flagset arg_handler(Args&&... args) {
            if VMAWARE_CONSTEXPR (is_empty<Args...>()) {
                return DEFAULT;
            }

            flag_collector.reset();

            // set the bits in the flag, can take in 
            // either an enum value or a std::bitset
            handleArgs(std::forward<Args>(args)...);

            // handle edgecases
            core::flag_sanitizer(flag_collector);

            return flag_collector;
        }

        // same as above but for VM::disable which only accepts technique flags
        template <typename... Args>
        static flagset disabled_arg_handler(Args&&... args) {
            flag_collector.reset();

            if VMAWARE_CONSTEXPR (is_empty<Args...>()) {
                throw std::invalid_argument("VM::DISABLE() must contain a flag");
            }

            handle_disabled_args(std::forward<Args>(args)...);

            // check if a settings flag is set, which is not valid
            if (core::is_setting_flag_set(flag_collector)) {
                throw std::invalid_argument("VM::DISABLE() must not contain a settings flag, they are disabled by default anyway");
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
    static bool check(
        const enum_flags flag_bit, 
        const enum_flags memo_arg = NULL_ARG
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

        // check if the bit is a settings flag, which shouldn't be allowed
        if (
            (flag_bit == NO_MEMO) ||
            (flag_bit == HIGH_THRESHOLD) ||
            (flag_bit == DYNAMIC) ||
            (flag_bit == MULTIPLE)
        ) {
            throw_error("Flag argument must be a technique flag and not a settings flag");
        }

        if (
            (memo_arg != NO_MEMO) && 
            (memo_arg != NULL_ARG)
        ) {
            throw_error("Flag argument for memoization must be either VM::NO_MEMO or left empty");
        }

        const bool is_memoized = (memo_arg != NO_MEMO);

#if (CPP >= 23)
        [[assume(flag_bit < technique_end)]];
#endif

        // if the technique is already cached, return the cached value instead
        if (memo::is_cached(flag_bit) && is_memoized) {
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

        if (result) {
            detected_count_num++;
        }

#ifdef __VMAWARE_DEBUG__
        total_points += pair.points;
#endif

        // store the technique result in the cache table
        if (is_memoized) {
            memo::cache_store(flag_bit, result, pair.points);
        }

        return result;
    }


    /**
     * @brief Fetch the VM brand
     * @param any flag combination in VM structure or nothing (VM::MULTIPLE can be added)
     * @return std::string
     * @link https://github.com/kernelwernel/VMAware/blob/main/docs/documentation.md#vmbrand
     */
    template <typename ...Args>
    static std::string brand(Args ...args) {
        flagset flags = core::arg_handler(args...);

        // is the multiple setting flag enabled? (meaning multiple 
        // brand strings will be outputted if there's a conflict)
        const bool is_multiple = core::is_enabled(flags, MULTIPLE);

        // are all the techiques already run? if not, run them 
        // to fetch the necessary info to determine the brand
        if (!memo::all_present() || core::is_enabled(flags, NO_MEMO)) {
            core::run_all(flags);
        }

        // check if the result is already cached and return that instead
        if (core::is_disabled(flags, NO_MEMO)) {
            if (is_multiple) {
                if (memo::multi_brand::is_cached()) {
                    core_debug("VM::brand(): returned multi brand from cache");
                    return memo::multi_brand::fetch();
                }
            } else {
                if (memo::brand::is_cached()) {
                    core_debug("VM::brand(): returned brand from cache");
                    return memo::brand::fetch();
                }
            }
        }

        // goofy ass C++11 and C++14 linker error workaround, 
        // and yes, this does look stupid.
#if (CPP <= 14)
        constexpr const char* TMP_QEMU = "QEMU";
        constexpr const char* TMP_KVM = "KVM";
        constexpr const char* TMP_QEMU_KVM = "QEMU+KVM";
        constexpr const char* TMP_KVM_HYPERV = "KVM Hyper-V Enlightenment";
        constexpr const char* TMP_QEMU_KVM_HYPERV = "QEMU+KVM Hyper-V Enlightenment";

        constexpr const char* TMP_VMWARE = "VMware";
        constexpr const char* TMP_VMWARE_HARD = "VMware (with VmwareHardenedLoader)";
        constexpr const char* TMP_EXPRESS = "VMware Express";
        constexpr const char* TMP_ESX = "VMware ESX";
        constexpr const char* TMP_GSX = "VMware GSX";
        constexpr const char* TMP_WORKSTATION = "VMware Workstation";
        constexpr const char* TMP_FUSION = "VMware Fusion";

        constexpr const char* TMP_VPC = "Virtual PC";
        constexpr const char* TMP_HYPERV = "Microsoft Hyper-V";
        constexpr const char* TMP_HYPERV_VPC = "Microsoft Virtual PC/Hyper-V";
        constexpr const char* TMP_AZURE = "Microsoft Azure Hyper-V";
        constexpr const char* TMP_NANOVISOR = "Xbox NanoVisor (Hyper-V)";
        constexpr const char* TMP_HYPERV_ARTIFACT = "Hyper-V artifact (not an actual VM)";
#else
        constexpr const char* TMP_QEMU = brands::QEMU;
        constexpr const char* TMP_KVM = brands::KVM;
        constexpr const char* TMP_QEMU_KVM = brands::QEMU_KVM;
        constexpr const char* TMP_KVM_HYPERV = brands::KVM_HYPERV;
        constexpr const char* TMP_QEMU_KVM_HYPERV = brands::QEMU_KVM_HYPERV;

        constexpr const char* TMP_VMWARE = brands::VMWARE;
        constexpr const char* TMP_VMWARE_HARD = brands::VMWARE_HARD;
        constexpr const char* TMP_EXPRESS = brands::VMWARE_EXPRESS;
        constexpr const char* TMP_ESX = brands::VMWARE_ESX;
        constexpr const char* TMP_GSX = brands::VMWARE_GSX;
        constexpr const char* TMP_WORKSTATION = brands::VMWARE_WORKSTATION;
        constexpr const char* TMP_FUSION = brands::VMWARE_FUSION;

        constexpr const char* TMP_VPC = brands::VPC;
        constexpr const char* TMP_HYPERV = brands::HYPERV;
        constexpr const char* TMP_HYPERV_VPC = brands::HYPERV_VPC;
        constexpr const char* TMP_AZURE = brands::AZURE_HYPERV;
        constexpr const char* TMP_NANOVISOR = brands::NANOVISOR;
        constexpr const char* TMP_HYPERV_ARTIFACT = brands::HYPERV_ARTIFACT;
#endif

        // this is where all the RELEVANT brands are stored.
        // The ones with no points will be filtered out.
        std::map<const char*, brand_score_t> brands;

        // add the relevant brands with at least 1 point
        for (const auto &element : core::brand_scoreboard) {
            if (element.second > 0) {
                brands.insert(std::make_pair(element.first, element.second));
            }
        }

        // if all brands had a point of 0, return 
        // "Unknown" (no relevant brands were found)
        if (brands.empty()) {
            return "Unknown";
        }

        // if there's only a single brand, return it. 
        // This will skip the rest of the function
        // where it will process and merge certain
        // brands 
        if (brands.size() == 1) {
            return brands.begin()->first;
        }
        
        // remove Hyper-V artifacts if found with other 
        // brands, because that's not a VM. It's added 
        // only for the sake of information cuz of the 
        // fucky wucky Hyper-V problem (see Hyper-X)
        if (brands.size() > 1) {
            if (brands.find(TMP_HYPERV_ARTIFACT) != brands.end()) {
                brands.erase(TMP_HYPERV_ARTIFACT);
            }
        }

        // merge 2 brands, and make a single brand out of it.
        auto merger = [&](const char* a, const char* b, const char* result) -> void {
            if (
                (brands.count(a) > 0) &&
                (brands.count(b) > 0)
            ) {
                brands.erase(a);
                brands.erase(b);
                brands.emplace(std::make_pair(result, 2));
            }
        };

        // same as above, but for 3
        auto triple_merger = [&](const char* a, const char* b, const char* c, const char* result) -> void {
            if (
                (brands.count(a) > 0) &&
                (brands.count(b) > 0) &&
                (brands.count(c) > 0)
            ) {
                brands.erase(a);
                brands.erase(b);
                brands.erase(c);
                brands.emplace(std::make_pair(result, 2));
            }
        };


        // some edgecase handling for Hyper-V and VirtualPC since
        // they're very similar, and they're both from Microsoft (ew)
        if ((brands.count(TMP_HYPERV) > 0) && (brands.count(TMP_VPC) > 0)) {
            if (brands.count(TMP_HYPERV) == brands.count(TMP_VPC)) {
                merger(TMP_VPC, TMP_HYPERV, TMP_HYPERV_VPC);
            } else {
                brands.erase(TMP_VPC);
            }
        }
        

        // this is the section where brand post-processing will be done. 
        // The reason why this part is necessary is because it will
        // output a more accurate picture of the VM brand. For example, 
        // Azure's cloud is based on Hyper-V, but Hyper-V may have 
        // a higher score due to the prevalence of it in a practical 
        // setting, which will put Azure to the side. This is stupid 
        // because there should be an indication that Azure is involved
        // since it's a better idea to let the end-user know that the
        // brand is "Azure Hyper-V" instead of just "Hyper-V". So what
        // this section does is "merge" the brands together to form
        // a more accurate idea of the brand(s) involved.


        merger(TMP_AZURE, TMP_HYPERV,     TMP_AZURE);
        merger(TMP_AZURE, TMP_VPC,        TMP_AZURE);
        merger(TMP_AZURE, TMP_HYPERV_VPC, TMP_AZURE);

        merger(TMP_NANOVISOR, TMP_HYPERV,     TMP_NANOVISOR);
        merger(TMP_NANOVISOR, TMP_VPC,        TMP_NANOVISOR);
        merger(TMP_NANOVISOR, TMP_HYPERV_VPC, TMP_NANOVISOR);
        
        merger(TMP_QEMU,     TMP_KVM,        TMP_QEMU_KVM);
        merger(TMP_KVM,      TMP_HYPERV,     TMP_KVM_HYPERV);
        merger(TMP_QEMU,     TMP_HYPERV,     TMP_QEMU_KVM_HYPERV);
        merger(TMP_QEMU_KVM, TMP_HYPERV,     TMP_QEMU_KVM_HYPERV);
        merger(TMP_KVM,      TMP_KVM_HYPERV, TMP_KVM_HYPERV);
        merger(TMP_QEMU,     TMP_KVM_HYPERV, TMP_QEMU_KVM_HYPERV);
        merger(TMP_QEMU_KVM, TMP_KVM_HYPERV, TMP_QEMU_KVM_HYPERV);

        triple_merger(TMP_QEMU, TMP_KVM, TMP_KVM_HYPERV, TMP_QEMU_KVM_HYPERV);

        merger(TMP_VMWARE, TMP_FUSION,      TMP_FUSION);
        merger(TMP_VMWARE, TMP_EXPRESS,     TMP_EXPRESS);
        merger(TMP_VMWARE, TMP_ESX,         TMP_ESX);
        merger(TMP_VMWARE, TMP_GSX,         TMP_GSX);
        merger(TMP_VMWARE, TMP_WORKSTATION, TMP_WORKSTATION);

        merger(TMP_VMWARE_HARD, TMP_VMWARE,      TMP_VMWARE_HARD);
        merger(TMP_VMWARE_HARD, TMP_FUSION,      TMP_VMWARE_HARD);
        merger(TMP_VMWARE_HARD, TMP_EXPRESS,     TMP_VMWARE_HARD);
        merger(TMP_VMWARE_HARD, TMP_ESX,         TMP_VMWARE_HARD);
        merger(TMP_VMWARE_HARD, TMP_GSX,         TMP_VMWARE_HARD);
        merger(TMP_VMWARE_HARD, TMP_WORKSTATION, TMP_VMWARE_HARD);

        // the brand element, which stores the NAME (const char*) and the SCORE (u8)
        using brand_element_t = std::pair<const char*, brand_score_t>;

        // sort the "brands" map so that the brands with the
        // highest score appears first in descending order
        auto sorter = [&]() -> std::vector<brand_element_t> {
            std::vector<brand_element_t> vec(brands.begin(), brands.end());

            std::sort(vec.begin(), vec.end(), [](
                const brand_element_t &a,
                const brand_element_t &b
            ) {
                return a.second < b.second;
            });

            return vec;
        };

        std::vector<brand_element_t> vec = sorter();
        std::string ret_str = "Unknown";

        // if the multiple setting flag is NOT set, return the
        // brand with the highest score. Else, return a std::string
        // of the brand message (i.e. "VirtualBox or VMware").
        // See VM::MULTIPLE flag in docs for more information.
        if (!is_multiple) {
            ret_str = vec.front().first;
        } else {
            std::stringstream ss;
            std::size_t i = 1;

            ss << vec.front().first;
            for (; i < vec.size(); i++) {
                ss << " or ";
                ss << vec.at(i).first;
            }
            ret_str = ss.str();
        }

        // cache the result if memoization is enabled
        if (core::is_disabled(flags, NO_MEMO)) {
            if (is_multiple) {
                core_debug("VM::brand(): cached multiple brand string");
                memo::multi_brand::store(ret_str);
            } else {
                core_debug("VM::brand(): cached brand string");
                memo::brand::store(ret_str);
            }
        }

        // debug stuff to see the brand scoreboard, ignore this
#ifdef __VMAWARE_DEBUG__
        for (const auto& p : brands) {
            core_debug("scoreboard: ", (int)p.second, " : ", p.first);
        }
#endif

        return ret_str;
    }


    /**
     * @brief Detect if running inside a VM
     * @param any flag combination in VM structure or nothing
     * @return bool
     * @link https://github.com/kernelwernel/VMAware/blob/main/docs/documentation.md#vmdetect
     */
    template <typename ...Args>
    static bool detect(Args ...args) {
        // fetch all the flags in a std::bitset
        flagset flags = core::arg_handler(args...);

        // run all the techniques based on the 
        // flags above, and get a total score 
        const u16 points = core::run_all(flags, SHORTCUT);

#if (CPP >= 23)
        [[assume(points < maximum_points)]];
#endif

        u16 threshold = 150;

        // if high threshold is set, the points 
        // will be 300. If not, leave it as 150.
        if (core::is_enabled(flags, HIGH_THRESHOLD)) {
            threshold = high_threshold_score;
        }

        return (points >= threshold);
    }


    /**
     * @brief Get the percentage of how likely it's a VM
     * @param any flag combination in VM structure or nothing
     * @return std::uint8_t
     * @link https://github.com/kernelwernel/VMAware/blob/main/docs/documentation.md#vmpercentage
     */
    template <typename ...Args>
    static u8 percentage(Args ...args) {
        // fetch all the flags in a std::bitset
        const flagset flags = core::arg_handler(args...);

        // run all the techniques based on the 
        // flags above, and get a total score
        const u16 points = core::run_all(flags, SHORTCUT);

#if (CPP >= 23)
        [[assume(points < maximum_points)]];
#endif

        u8 percent = 0;
        u16 threshold = 150;

        // set to 300 if high threshold is enabled
        if (core::is_enabled(flags, HIGH_THRESHOLD)) {
            threshold = high_threshold_score;
        }

        // the percentage will be set to 99%, because a score 
        // of 100 is not entirely robust. 150 is more robust
        // in my opinion, which is why you need a score of
        // above 150 to get to 100% 
        if (points >= threshold) {
            percent = 100;
        } else if (points >= 100) {
            percent = 99;
        } else {
            percent = static_cast<u8>(points);
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
        // lambda to throw the error
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

        static u16 id = 0;
        id++;

        // generate the custom technique struct
        core::custom_technique query{
            percent,
            // this fucking sucks
            static_cast<u16>(static_cast<int>(base_technique_count) + static_cast<int>(id)),
            detection_func
        };

        technique_count++;

        // push it to the custome_table vector
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
        // basically core::arg_handler but in reverse,
        // it'll clear the bits of the provided flags
        flagset flags = core::disabled_arg_handler(args...);

        flags.flip();
        flags.set(NO_MEMO, 0);
        flags.set(HIGH_THRESHOLD, 0);
        flags.set(DYNAMIC, 0);
        flags.set(MULTIPLE, 0);

        return flags;
    }


    /**
     * @brief This will convert the technique flag into a string, which will correspond to the technique name
     * @param single technique flag in VM structure
     * @warning ⚠️ FOR DEVELOPMENT USAGE ONLY, NOT MEANT FOR PUBLIC USE FOR NOW ⚠️
     */
    [[nodiscard]] static std::string flag_to_string(const enum_flags flag) {
        switch (flag) {
            case VMID: return "VMID";
            case CPU_BRAND: return "CPU_BRAND";
            case HYPERVISOR_BIT: return "HYPERVISOR_BIT";
            case HYPERVISOR_STR: return "HYPERVISOR_STR";
            case RDTSC: return "RDTSC";
            case THREADCOUNT: return "THREADCOUNT";
            case MAC: return "MAC";
            case TEMPERATURE: return "TEMPERATURE";
            case SYSTEMD: return "SYSTEMD";
            case CVENDOR: return "CVENDOR";
            case CTYPE: return "CTYPE";
            case DOCKERENV: return "DOCKERENV";
            case DMIDECODE: return "DMIDECODE";
            case DMESG: return "DMESG";
            case HWMON: return "HWMON";
            case SIDT5: return "SIDT5";
            case VMWARE_REG: return "VMWARE_REG";
            case VBOX_REG: return "VBOX_REG";
            case USER: return "USER";
            case DLL: return "DLL";
            case REGISTRY: return "REGISTRY";
            case VM_FILES: return "VM_FILES";
            case HWMODEL: return "HWMODEL";
            case DISK_SIZE: return "DISK_SIZE";
            case VBOX_DEFAULT: return "VBOX_DEFAULT";
            case VBOX_NETWORK: return "VBOX_NETWORK";
            case VM_PROCESSES: return "VM_PROCESSES";
            case LINUX_USER_HOST: return "LINUX_USER_HOST";
            case GAMARUE: return "GAMARUE";
            case VMID_0X4: return "VMID_0X4";
            case PARALLELS_VM: return "PARALLELS_VM";
            case QEMU_BRAND: return "QEMU_BRAND";
            case BOCHS_CPU: return "BOCHS_CPU";
            case VPC_BOARD: return "VPC_BOARD";
            case HYPERV_WMI: return "HYPERV_WMI";
            case HYPERV_REG: return "HYPERV_REG";
            case BIOS_SERIAL: return "BIOS_SERIAL";
            case MSSMBIOS: return "MSSMBIOS";
            case MAC_MEMSIZE: return "MAC_MEMSIZE";
            case MAC_IOKIT: return "MAC_IOKIT";
            case IOREG_GREP: return "IOREG_GREP";
            case MAC_SIP: return "MAC_SIP";
            case HKLM_REGISTRIES: return "HKLM_REGISTRIES";
            case QEMU_GA: return "QEMU_GA";
            case VALID_MSR: return "VALID_MSR";
            case QEMU_PROC: return "QEMU_PROC";
            case VPC_PROC: return "VPC_PROC";
            case VPC_INVALID: return "VPC_INVALID";
            case SIDT: return "SIDT";
            case SGDT: return "SGDT";
            case SLDT: return "SLDT";
            case OFFSEC_SIDT: return "OFFSEC_SIDT";
            case OFFSEC_SGDT: return "OFFSEC_SGDT";
            case OFFSEC_SLDT: return "OFFSEC_SLDT";
            case HYPERV_BOARD: return "HYPERV_BOARD";
            case VM_FILES_EXTRA: return "VM_FILES_EXTRA";
            case VPC_SIDT: return "VPC_SIDT";
            case VMWARE_IOMEM: return "VMWARE_IOMEM";
            case VMWARE_IOPORTS: return "VMWARE_IOPORTS";
            case VMWARE_SCSI: return "VMWARE_SCSI";
            case VMWARE_DMESG: return "VMWARE_DMESG";
            case VMWARE_STR: return "VMWARE_STR";
            case VMWARE_BACKDOOR: return "VMWARE_BACKDOOR";
            case VMWARE_PORT_MEM: return "VMWARE_PORT_MEM";
            case SMSW: return "SMSW";
            case MUTEX: return "MUTEX";
            case UPTIME: return "UPTIME";
            case ODD_CPU_THREADS: return "ODD_CPU_THREADS";
            case INTEL_THREAD_MISMATCH: return "INTEL_THREAD_MISMATCH";
            case XEON_THREAD_MISMATCH: return "XEON_THREAD_MISMATCH";
            case NETTITUDE_VM_MEMORY: return "NETTITUDE_VM_MEMORY";
            case CPUID_BITSET: return "CPUID_BITSET";
            case CUCKOO_DIR: return "CUCKOO_DIR";
            case CUCKOO_PIPE: return "CUCKOO_PIPE";
            case HYPERV_HOSTNAME: return "HYPERV_HOSTNAME";
            case GENERAL_HOSTNAME: return "GENERAL_HOSTNAME";
            case SCREEN_RESOLUTION: return "SCREEN_RESOLUTION";
            case DEVICE_STRING: return "DEVICE_STRING";
            case BLUESTACKS_FOLDERS: return "BLUESTACKS_FOLDERS";
            case CPUID_SIGNATURE: return "CPUID_SIGNATURE";
            case HYPERV_BITMASK: return "HYPERV_BITMASK";
            case KVM_BITMASK: return "KVM_BITMASK";
            case KGT_SIGNATURE: return "KGT_SIGNATURE";
            case VMWARE_DMI: return "VMWARE_DMI";
            case HYPERV_EVENT_LOGS: return "HYPERV_EVENT_LOGS";
            case VMWARE_EVENT_LOGS: return "VMWARE_EVENT_LOGS";
            case QEMU_VIRTUAL_DMI: return "QEMU_VIRTUAL_DMI";
            case QEMU_USB: return "QEMU_USB";
            case HYPERVISOR_DIR: return "HYPERVISOR_DIR";
            case UML_CPU: return "UML_CPU";
            case KMSG: return "KMSG";
            case VM_PROCS: return "VM_PROCS";
            case VBOX_MODULE: return "VBOX_MODULE";
            case SYSINFO_PROC: return "SYSINFO_PROC";
            case DEVICE_TREE: return "DEVICE_TREE";
            case DMI_SCAN: return "DMI_SCAN";
            case SMBIOS_VM_BIT: return "SMBIOS_VM_BIT";
            case PODMAN_FILE: return "PODMAN_FILE";
            case WSL_PROC: return "WSL_PROC";
            case GPU_CHIPTYPE: return "GPU_CHIPTYPE";
            case DRIVER_NAMES: return "DRIVER_NAMES";
            case VM_SIDT: return "VM_SIDT";
            case HDD_SERIAL: return "HDD_SERIAL";
            case PORT_CONNECTORS: return "PORT_CONNECTORS";
            case VM_HDD: return "VM_HDD";
            case ACPI_DETECT: return "ACPI_DETECT";
            case GPU_NAME: return "GPU_NAME";
            case VMWARE_DEVICES: return "VMWARE_DEVICES";
            case VMWARE_MEMORY: return "VMWARE_MEMORY";
            case IDT_GDT_MISMATCH: return "CPU_CORES";
            case PROCESSOR_NUMBER: return "PROCESSOR_NUMBER";
            case NUMBER_OF_CORES: return "NUMBER_OF_CORES";
            case WMI_MODEL: return "WMI_MODEL";
            case WMI_MANUFACTURER: return "WMI_MANUFACTURER";
            case WMI_TEMPERATURE: return "WMI_TEMPERATURE";
            case PROCESSOR_ID: return "PROCESSOR_ID";
            case CPU_FANS: return "CPU_FANS";
            case POWER_CAPABILITIES: return "POWER_CAPABILITIES";
            case SETUPAPI_DISK: return "SETUPAPI_DISK";
            case VMWARE_HARDENER: return "VMWARE_HARDENER_LOADER";
            case WMI_QUERIES: return "WMI_QUERIES";
			case SYS_QEMU: return "SYS_QEMU";
			case LSHW_QEMU: return "LSHW_QEMU";
            // ADD NEW CASE HERE FOR NEW TECHNIQUE
            default: return "Unknown flag";
        }
    }


    /**
     * @brief Change the certainty score of a technique
     * @param technique flag, then the new percentage score to overwite
     * @return void
     * @warning ⚠️ FOR DEVELOPMENT USAGE ONLY, NOT MEANT FOR PUBLIC USE FOR NOW ⚠️
     */
    static void modify_score(
        const enum_flags flag,
        const u8 percent
        // clang doesn't support std::source_location for some reason
#if (CPP >= 20 && !CLANG)
        , const std::source_location& loc = std::source_location::current()
#endif
    ) {
        // lambda to throw the error
        auto throw_error = [&](const char* text) -> void {
            std::stringstream ss;
#if (CPP >= 20 && !CLANG)
            ss << ", error in " << loc.function_name() << " at " << loc.file_name() << ":" << loc.line() << ")";
#endif
            ss << ". Consult the documentation's parameters for VM::modify_score()";
            throw std::invalid_argument(std::string(text) + ss.str());
        };

        if (percent > 100) {
            throw_error("Percentage parameter must be between 0 and 100");
        }

#if (CPP >= 23)
        [[assume(percent <= 100)]];
#endif

        // check if the flag provided is a setting flag, which isn't valid.
        if (static_cast<u8>(flag) >= technique_end) {
            throw_error("The flag is not a technique flag");
        }

        using table_t =  std::map<enum_flags, core::technique>;

        auto modify = [](table_t &table, const enum_flags flag, const u8 percent) -> void {
            core::technique &tmp = table.at(flag);
            table[flag] = { percent, tmp.run, tmp.is_spoofable };
        };

        modify(core::technique_table, flag, percent);
    }


    /**
     * @brief Fetch the total number of detected techniques
     * @param any flag combination in VM structure or nothing
     * @return std::uint8_t
     */
    template <typename ...Args>
    static u8 detected_count(Args ...args) {
        flagset flags = core::arg_handler(args...);

        // run all the techniques, which will set the detected_count variable 
        core::run_all(flags);

        return detected_count_num;
    }


    /**
     * @brief Fetch the total number of detected techniques
     * @param any flag combination in VM structure or nothing
     * @return std::uint8_t
     */
    template <typename ...Args>
    static std::string type(Args ...args) {
        flagset flags = core::arg_handler(args...);

        const std::string brand_str = brand(flags);

        // if multiple brands were found, return unknown
        if (util::find(brand_str, " or ")) {
            return "Unknown";
        }

        const std::map<std::string, const char*> type_table {
            // type 1
            { brands::XEN, "Hypervisor (type 1)" },
            { brands::VMWARE_ESX, "Hypervisor (type 1)" },
            { brands::ACRN, "Hypervisor (type 1)" },
            { brands::QNX, "Hypervisor (type 1)" },
            { brands::HYPERV, "Hypervisor (type 1)" },
            { brands::AZURE_HYPERV, "Hypervisor (type 1)" },
            { brands::NANOVISOR, "Hypervisor (type 1)" },
            { brands::KVM, "Hypervisor (type 1)" },
            { brands::BHYVE, "Hypervisor (type 1)" },
            { brands::KVM_HYPERV, "Hypervisor (type 1)" },
            { brands::QEMU_KVM_HYPERV, "Hypervisor (type 1)" },
            { brands::QEMU_KVM, "Hypervisor (type 1)" },
            { brands::INTEL_HAXM, "Hypervisor (type 1)" },
            { brands::INTEL_KGT, "Hypervisor (type 1)" },
            { brands::SIMPLEVISOR, "Hypervisor (type 1)" },
            { brands::GCE, "Hypervisor (type 1)" },
            { brands::OPENSTACK, "Hypervisor (type 1)" },
            { brands::KUBEVIRT, "Hypervisor (type 1)" },
            { brands::POWERVM, "Hypervisor (type 1)" },
            { brands::AWS_NITRO, "Hypervisor (type 1)" },

            // type 2
            { brands::VBOX, "Hypervisor (type 2)" },
            { brands::VMWARE, "Hypervisor (type 2)" },
            { brands::VMWARE_EXPRESS, "Hypervisor (type 2)" },
            { brands::VMWARE_GSX, "Hypervisor (type 2)" },
            { brands::VMWARE_WORKSTATION, "Hypervisor (type 2)" },
            { brands::VMWARE_FUSION, "Hypervisor (type 2)" },
            { brands::PARALLELS, "Hypervisor (type 2)" },
            { brands::VPC, "Hypervisor (type 2)" },
            { brands::NVMM, "Hypervisor (type 2)" },
            { brands::BSD_VMM, "Hypervisor (type 2)" },

            // sandbox
            { brands::CUCKOO, "Sandbox" },
            { brands::SANDBOXIE, "Sandbox" },
            { brands::HYBRID, "Sandbox" },
            { brands::CWSANDBOX, "Sandbox" },
            { brands::JOEBOX, "Sandbox" },
            { brands::ANUBIS, "Sandbox" },
            { brands::COMODO, "Sandbox" },
            { brands::THREATEXPERT, "Sandbox" },

            // misc
            { brands::BOCHS, "Emulator" },
            { brands::BLUESTACKS, "Emulator" },
            { brands::MSXTA, "Emulator" },
            { brands::QEMU, "Emulator/Hypervisor (type 2)" },
            { brands::JAILHOUSE, "Partitioning Hypervisor" },
            { brands::UNISYS, "Partitioning Hypervisor" },
            { brands::DOCKER, "Container" },
            { brands::PODMAN, "Container" },
            { brands::OPENVZ, "Container" },
            { brands::HYPERV_VPC, "Hypervisor (either type 1 or 2)" },
            { brands::LMHS, "Hypervisor (unknown type)" },
            { brands::WINE, "Compatibility layer" },
            { brands::APPLE_VZ, "Unknown" },
            { brands::HYPERV_ARTIFACT, "Unknown" },
            { brands::UML, "Paravirtualised/Hypervisor (type 2)" },
            { brands::WSL, "Hybrid Hyper-V (type 1 and 2)" }, // debatable tbh
            { brands::APPLE_ROSETTA, "Binary Translation Layer/Emulator" }
        };

        auto it = type_table.find(brand_str.c_str());

        if (it != type_table.end()) {
            return it->second;
        }

        return "Unknown";
    }


    /**
     * @brief Fetch the conclusion message based on the brand and percentage
     * @param any flag combination in VM structure or nothing
     * @return std::string
     */
    template <typename ...Args>
    static std::string conclusion(Args ...args) {
        flagset flags = core::arg_handler(args...);

        const std::string brand_tmp = brand(flags);
        const u8 percent_tmp = percentage(flags);

        constexpr const char* baremetal = "Running on baremetal";
        constexpr const char* very_unlikely = "Very unlikely a VM";
        constexpr const char* unlikely = "Unlikely a VM";

        const std::string potentially = "Potentially";
        const std::string might = "Might be";
        const std::string likely = "Likely";
        const std::string very_likely = "Very likely";
        const std::string inside_vm = "Running inside";

        auto make_conclusion = [&](const std::string &category) -> std::string {
            std::string article = "";   

            if (brand_tmp == "Unknown") {
                article = " an ";
            } else {
                article = " a ";
            }

            return (brand_tmp == "Hyper-V artifact (not an actual VM)") ? (category + article + brand_tmp) : (category + article + brand_tmp + " VM");
        };

        if (core::is_enabled(flags, DYNAMIC)) {
            if      (percent_tmp == 0)   { return baremetal; } 
            else if (percent_tmp <= 20)  { return very_unlikely; } 
            else if (percent_tmp <= 35)  { return unlikely; } 
            else if (percent_tmp < 50)   { return make_conclusion(potentially); } 
            else if (percent_tmp <= 62)  { return make_conclusion(might); } 
            else if (percent_tmp <= 75)  { return make_conclusion(likely); } 
            else if (percent_tmp < 100)  { return make_conclusion(very_likely); } 
            else                         { return make_conclusion(inside_vm); }
        }

        if (percent_tmp == 100) {
            return make_conclusion(inside_vm);
        } else {
            return baremetal;
        }
    }

    #pragma pack(push, 1)
    struct vmaware {
        std::string brand;
        std::string type;
        std::string conclusion;
        bool is_vm;
        u8 percentage;
        u8 detected_count;
        u16 technique_count;

        template <typename ...Args>
        vmaware(Args ...args) {
            flagset flags = core::arg_handler(args...);

            brand = VM::brand(flags);
            type = VM::type(flags);
            conclusion = VM::conclusion(flags);
            is_vm = VM::detect(flags);
            percentage = VM::percentage(flags);
            detected_count = VM::detected_count(flags);
            technique_count = VM::technique_count;
        }
    };
    #pragma pack(pop)


    static u16 technique_count; // get total number of techniques
    static std::vector<u8> technique_vector;
#ifdef __VMAWARE_DEBUG__
    static u16 total_points;
#endif
};

MSVC_ENABLE_WARNING(ASSIGNMENT_OPERATOR NO_INLINE_FUNC SPECTRE)


// ============= EXTERNAL DEFINITIONS =============
// These are added here due to warnings related to C++17 inline variables for C++ standards that are under 17.
// It's easier to just group them together rather than having C++17<= preprocessors with inline stuff


// scoreboard list of brands, if a VM detection technique detects a brand, that will be incremented here as a single point.
std::map<const char*, VM::brand_score_t> VM::core::brand_scoreboard{
    { VM::brands::VBOX, 0 },
    { VM::brands::VMWARE, 0 },
    { VM::brands::VMWARE_EXPRESS, 0 },
    { VM::brands::VMWARE_ESX, 0 },
    { VM::brands::VMWARE_GSX, 0 },
    { VM::brands::VMWARE_WORKSTATION, 0 },
    { VM::brands::VMWARE_FUSION, 0 },
    { VM::brands::VMWARE_HARD, 0 },
    { VM::brands::BHYVE, 0 },
    { VM::brands::KVM, 0 },
    { VM::brands::QEMU, 0 },
    { VM::brands::QEMU_KVM, 0 },
    { VM::brands::KVM_HYPERV, 0 },
    { VM::brands::QEMU_KVM_HYPERV, 0 },
    { VM::brands::HYPERV, 0 },
    { VM::brands::HYPERV_VPC, 0 },
    { VM::brands::MSXTA, 0 },
    { VM::brands::PARALLELS, 0 },
    { VM::brands::XEN, 0 },
    { VM::brands::ACRN, 0 },
    { VM::brands::QNX, 0 },
    { VM::brands::HYBRID, 0 },
    { VM::brands::SANDBOXIE, 0 },
    { VM::brands::DOCKER, 0 },
    { VM::brands::WINE, 0 },
    { VM::brands::APPLE_ROSETTA, 0 },
    { VM::brands::VPC, 0 },
    { VM::brands::ANUBIS, 0 },
    { VM::brands::JOEBOX, 0 },
    { VM::brands::THREATEXPERT, 0 },
    { VM::brands::CWSANDBOX, 0 },
    { VM::brands::COMODO, 0 },
    { VM::brands::BOCHS, 0 },
    { VM::brands::NVMM, 0 },
    { VM::brands::BSD_VMM, 0 },
    { VM::brands::INTEL_HAXM, 0 },
    { VM::brands::UNISYS, 0 },
    { VM::brands::LMHS, 0 },
    { VM::brands::CUCKOO, 0 },
    { VM::brands::BLUESTACKS, 0 },
    { VM::brands::JAILHOUSE, 0 },
    { VM::brands::APPLE_VZ, 0 },
    { VM::brands::INTEL_KGT, 0 },
    { VM::brands::AZURE_HYPERV, 0 },
    { VM::brands::NANOVISOR, 0 },
    { VM::brands::SIMPLEVISOR, 0 },
    { VM::brands::HYPERV_ARTIFACT, 0 },
    { VM::brands::UML, 0 },
    { VM::brands::POWERVM, 0 },
    { VM::brands::GCE, 0 },
    { VM::brands::OPENSTACK, 0 },
    { VM::brands::KUBEVIRT, 0 },
    { VM::brands::AWS_NITRO, 0 },
    { VM::brands::PODMAN, 0 },
    { VM::brands::WSL, 0 },
    { VM::brands::OPENVZ, 0 },
    { VM::brands::BAREVISOR, 0 },
    { VM::brands::HYPERPLATFORM, 0 },
    { VM::brands::MINIVISOR, 0 },
    { VM::brands::NULL_BRAND, 0 }
};


// initial definitions for cache items because C++ forbids in-class initializations
std::map<VM::u16, VM::memo::data_t> VM::memo::cache_table;
VM::flagset VM::memo::cache_keys = 0;
std::string VM::memo::brand::brand_cache = "";
std::string VM::memo::multi_brand::brand_cache = "";
std::string VM::memo::cpu_brand::brand_cache = "";
VM::hyperx_state VM::memo::hyperx::state = VM::HYPERV_UNKNOWN_VM;
bool VM::memo::hyperx::cached = false;
#if (WINDOWS)
IWbemLocator* VM::wmi::pLoc = nullptr;
IWbemServices* VM::wmi::pSvc = nullptr;
bool VM::memo::wmi::cached = false;
bool VM::memo::wmi::status = false;
#endif

#ifdef __VMAWARE_DEBUG__
VM::u16 VM::total_points = 0;
#endif

// these are basically the base values for the core::arg_handler function.
// It's like a bucket that will collect all the bits enabled. If for example 
// VM::detect(VM::HIGH_THRESHOLD) is passed, the HIGH_THRESHOLD bit will be 
// collected in this flagset (std::bitset) variable, and eventually be the 
// return value for actual end-user functions like VM::detect() to rely 
// and work on.
VM::flagset VM::core::flag_collector;


VM::u8 VM::detected_count_num = 0;


// default flags 
VM::flagset VM::DEFAULT = []() noexcept -> flagset {
    flagset tmp;

    // set all bits to 1
    tmp.set();

    // disable all non-default techniques
    tmp.flip(VMWARE_DMESG);

    // disable all the settings flags
    tmp.flip(NO_MEMO);
    tmp.flip(HIGH_THRESHOLD);
    tmp.flip(DYNAMIC);
    tmp.flip(MULTIPLE);

    return tmp;
}();


// flag to enable every technique
VM::flagset VM::ALL = []() noexcept -> flagset {
    flagset tmp;

    // set all bits to 1
    tmp.set();

    // disable all the settings technique flags
    tmp.flip(NO_MEMO);
    tmp.flip(HIGH_THRESHOLD);
    tmp.flip(DYNAMIC);
    tmp.flip(MULTIPLE);

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


// this value is incremented each time VM::add_custom is called
VM::u16 VM::technique_count = base_technique_count;


// check if cpuid is supported
bool VM::core::cpuid_supported = []() -> bool {
#if (x86)
#if (WINDOWS)
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


// the 0~100 points are debatable, but I think it's fine how it is. Feel free to disagree.
std::pair<VM::enum_flags, VM::core::technique> VM::core::technique_list[] = {
    // FORMAT: { VM::<ID>, { certainty%, function pointer, is spoofable? } },
    { VM::VMID, { 100, VM::vmid, false } },
    { VM::CPU_BRAND, { 50, VM::cpu_brand, false } },
    { VM::HYPERVISOR_BIT, { 100, VM::hypervisor_bit , false}} , 
    { VM::HYPERVISOR_STR, { 75, VM::hypervisor_str, false } },
    { VM::RDTSC, { 40, VM::rdtsc, false } },
    { VM::THREADCOUNT, { 25, VM::thread_count, false } },
    { VM::MAC, { 20, VM::mac_address_check, true } },
    { VM::TEMPERATURE, { 15, VM::temperature, false } },
    { VM::SYSTEMD, { 35, VM::systemd_virt, true } },
    { VM::CVENDOR, { 65, VM::chassis_vendor, false } },
    { VM::CTYPE, { 20, VM::chassis_type, false } },
    { VM::DOCKERENV, { 30, VM::dockerenv, true } },
    { VM::DMIDECODE, { 55, VM::dmidecode, false } },
    { VM::DMESG, { 55, VM::dmesg, false } },
    { VM::HWMON, { 35, VM::hwmon, true } },
    { VM::SIDT5, { 45, VM::sidt5, false } },
    { VM::VMWARE_REG, { 50, VM::vmware_registry, true } },
    { VM::VBOX_REG, { 50, VM::vbox_registry, true } },
    { VM::USER, { 5, VM::user_check, true } },
    { VM::DLL, { 25, VM::DLL_check, true } },
    { VM::REGISTRY, { 50, VM::registry_key, true } },
    { VM::VM_FILES, { 25, VM::vm_files, true } },
    { VM::HWMODEL, { 35, VM::hwmodel, true } }, // TODO: update score
    { VM::DISK_SIZE, { 60, VM::disk_size, false } }, // TODO: update score
    { VM::VBOX_DEFAULT, { 25, VM::vbox_default_specs, false } },
    { VM::VBOX_NETWORK, { 100, VM::vbox_network_share, false } },  // used to be 70, debatable
    { VM::VM_PROCESSES, { 15, VM::vm_processes, true } }, 
    { VM::LINUX_USER_HOST, { 10, VM::linux_user_host, true } }, // TODO: update score
    { VM::GAMARUE, { 10, VM::gamarue, true } },
    { VM::VMID_0X4, { 100, VM::vmid_0x4, false } },
    { VM::PARALLELS_VM, { 50, VM::parallels, false } },
    { VM::QEMU_BRAND, { 100, VM::cpu_brand_qemu, false } },
    { VM::BOCHS_CPU, { 100, VM::bochs_cpu, false } },
    { VM::VPC_BOARD, { 25, VM::vpc_board, false } },
    { VM::BIOS_SERIAL, { 60, VM::bios_serial, false } }, // debatable
    { VM::MSSMBIOS, { 75, VM::mssmbios, false } },
    { VM::MAC_MEMSIZE, { 15, VM::hw_memsize, true } }, // TODO: update score
    { VM::MAC_IOKIT, { 40, VM::io_kit, true } }, // TODO: update score
    { VM::IOREG_GREP, { 30, VM::ioreg_grep, true } }, // TODO: update score
    { VM::MAC_SIP, { 40, VM::mac_sip, true } }, // TODO: update score
    { VM::HKLM_REGISTRIES, { 25, VM::hklm_registries, true } },
    { VM::QEMU_GA, { 10, VM::qemu_ga, true } }, // TODO: update score
    { VM::VALID_MSR, { 35, VM::valid_msr, false } },
    { VM::QEMU_PROC, { 50, VM::qemu_processes, true } }, // debatable
    { VM::VPC_PROC, { 50, VM::vpc_proc, true } }, // debatable 
    { VM::VPC_INVALID, { 75, VM::vpc_invalid, false } }, // TODO: update score
    { VM::SIDT, { 25, VM::sidt, false } },
    { VM::SGDT, { 30, VM::sgdt, false } }, // TODO: update score
    { VM::SLDT, { 15, VM::sldt, false } }, // TODO: update score
    { VM::OFFSEC_SIDT, { 60, VM::offsec_sidt, false } }, // TODO: update score
    { VM::OFFSEC_SGDT, { 60, VM::offsec_sgdt, false } }, // TODO: update score
    { VM::OFFSEC_SLDT, { 20, VM::offsec_sldt, false } }, // TODO: update score
    { VM::VPC_SIDT, { 15, VM::vpc_sidt, false } }, // debatable
    { VM::HYPERV_BOARD, { 100, VM::hyperv_board, false } },
    { VM::VM_FILES_EXTRA, { 30, VM::vm_files_extra, true } },
    { VM::VMWARE_IOMEM, { 65, VM::vmware_iomem, false } }, // debatable
    { VM::VMWARE_IOPORTS, { 70, VM::vmware_ioports, false } }, // debatable
    { VM::VMWARE_SCSI, { 40, VM::vmware_scsi, false } }, // debatable
    { VM::VMWARE_DMESG, { 65, VM::vmware_dmesg, false } }, // debatable
    { VM::VMWARE_STR, { 35, VM::vmware_str, false } }, // debatable
    { VM::VMWARE_BACKDOOR, { 100, VM::vmware_backdoor, false } }, // debatable
    { VM::VMWARE_PORT_MEM, { 85, VM::vmware_port_memory, false } }, // debatable
    { VM::SMSW, { 30, VM::smsw, false } }, // debatable
    { VM::MUTEX, { 85, VM::mutex, false } }, // could be 100, debatable
    { VM::UPTIME, { 5, VM::uptime, true } },
    { VM::ODD_CPU_THREADS, { 80, VM::odd_cpu_threads, false } },
    { VM::INTEL_THREAD_MISMATCH, { 60, VM::intel_thread_mismatch, false } },
    { VM::XEON_THREAD_MISMATCH, { 85, VM::xeon_thread_mismatch, false } }, // debatable
    { VM::NETTITUDE_VM_MEMORY, { 100, VM::nettitude_vm_memory, false } },
    { VM::CPUID_BITSET, { 25, VM::cpuid_bitset, false } }, // debatable
    { VM::CUCKOO_DIR, { 30, VM::cuckoo_dir, true } },
    { VM::CUCKOO_PIPE, { 30, VM::cuckoo_pipe, true } }, // debatable
    { VM::HYPERV_HOSTNAME, { 30, VM::hyperv_hostname, true } },
    { VM::GENERAL_HOSTNAME, { 10, VM::general_hostname, true } },
    { VM::SCREEN_RESOLUTION, { 20, VM::screen_resolution, false } },
    { VM::DEVICE_STRING, { 25, VM::device_string, false } },
    { VM::BLUESTACKS_FOLDERS, { 5, VM::bluestacks, true } }, // debatable
    { VM::CPUID_SIGNATURE, { 95, VM::cpuid_signature, false } }, // debatable
    { VM::HYPERV_BITMASK, { 20, VM::hyperv_bitmask, false } }, // debatable
    { VM::KVM_BITMASK, { 40, VM::kvm_bitmask, false } }, // debatable
    { VM::KGT_SIGNATURE, { 80, VM::intel_kgt_signature, false } }, // debatable
    { VM::VMWARE_DMI, { 40, VM::vmware_dmi, false } },
    { VM::HYPERV_EVENT_LOGS, { 50, VM::hyperv_event_logs, false } },
    { VM::VMWARE_EVENT_LOGS, { 25, VM::vmware_event_logs, false } },
    { VM::QEMU_VIRTUAL_DMI, { 40, VM::qemu_virtual_dmi, false } },
    { VM::QEMU_USB, { 20, VM::qemu_USB, false } }, // debatable
    { VM::HYPERVISOR_DIR, { 20, VM::hypervisor_dir, false } }, // debatable
    { VM::UML_CPU, { 80, VM::uml_cpu, false } }, // debatable
    { VM::KMSG, { 5, VM::kmsg, true } }, // debatable
    { VM::VM_PROCS, { 10, VM::vm_procs, true } }, // debatable
    { VM::VBOX_MODULE, { 15, VM::vbox_module, false } }, // debatable
    { VM::SYSINFO_PROC, { 15, VM::sysinfo_proc, false } }, // debatable
    { VM::DEVICE_TREE, { 20, VM::device_tree, false } }, // debatable
    { VM::DMI_SCAN, { 50, VM::dmi_scan, false } }, // debatable
    { VM::SMBIOS_VM_BIT, { 50, VM::smbios_vm_bit, false } }, // debatable
    { VM::PODMAN_FILE, { 5, VM::podman_file, true } }, // debatable
    { VM::WSL_PROC, { 30, VM::wsl_proc_subdir, false } }, // debatable
    { VM::GPU_CHIPTYPE, { 100, VM::gpu_chiptype, false } },
    { VM::DRIVER_NAMES, { 50, VM::driver_names, false } },
    { VM::VM_SIDT, { 100, VM::vm_sidt, false } },
    { VM::HDD_SERIAL, { 100, VM::hdd_serial_number, false } },
    { VM::PORT_CONNECTORS, { 50, VM::port_connectors, false } },
    { VM::VM_HDD, { 90, VM::vm_hdd, false } },
    { VM::ACPI_DETECT, { 85, VM::acpi_detect, false } },
    { VM::GPU_NAME, { 100, VM::vm_gpu, false } },
    { VM::VMWARE_DEVICES, { 45, VM::vmware_devices, true } }, 
    { VM::VMWARE_MEMORY, { 50, VM::vmware_memory, false } },
    { VM::IDT_GDT_MISMATCH, { 25, VM::idt_gdt_mismatch, false } },
    { VM::PROCESSOR_NUMBER, { 25, VM::processor_number, false } },
    { VM::NUMBER_OF_CORES, { 50, VM::number_of_cores, false } },
    { VM::WMI_MODEL, { 100, VM::wmi_model, false } },
    { VM::WMI_MANUFACTURER, { 100, VM::wmi_manufacturer, false } },
    { VM::WMI_TEMPERATURE, { 25, VM::wmi_temperature, false } },
    { VM::PROCESSOR_ID, { 25, VM::processor_id, false } },
    { VM::CPU_FANS, { 35, VM::cpu_fans, false } },
    { VM::VMWARE_HARDENER, { 60, VM::vmware_hardener, false } },
    { VM::SYS_QEMU, { 70, VM::sys_qemu_dir, false } },
    { VM::LSHW_QEMU, { 80, VM::lshw_qemu, false } },
    // ADD NEW TECHNIQUE STRUCTURE HERE
};


// this is initialised as empty, because this is where custom techniques can be added at runtime 
std::vector<VM::core::custom_technique> VM::core::custom_table = {

};

#define table_t std::map<VM::enum_flags, VM::core::technique>

// the reason why the map isn't directly initialized is due to potential SDK errors on windows combined with older C++ standards
table_t VM::core::technique_table = []() -> table_t {
    table_t table;
    for (const auto& technique : VM::core::technique_list) {
        table.insert(technique);
    }
    return table;
}();
