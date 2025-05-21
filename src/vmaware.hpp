/**
 * ██╗   ██╗███╗   ███╗ █████╗ ██╗    ██╗ █████╗ ██████╗ ███████╗
 * ██║   ██║████╗ ████║██╔══██╗██║    ██║██╔══██╗██╔══██╗██╔════╝
 * ██║   ██║██╔████╔██║███████║██║ █╗ ██║███████║██████╔╝█████╗
 * ╚██╗ ██╔╝██║╚██╔╝██║██╔══██║██║███╗██║██╔══██║██╔══██╗██╔══╝
 *  ╚████╔╝ ██║ ╚═╝ ██║██║  ██║╚███╔███╔╝██║  ██║██║  ██║███████╗
 *   ╚═══╝  ╚═╝     ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ 2.3.0 (May 2025)
 *
 *  C++ VM detection library
 *
 *  - Made by: kernelwernel (https://github.com/kernelwernel)
 *  - Co-developed by: Requiem (https://github.com/NotRequiem)
 *  - Contributed by:
 *      - Alex (https://github.com/greenozon)
 *      - Marek Knápek (https://github.com/MarekKnapek)
 *      - Vladyslav Miachkov (https://github.com/fameowner99)
 *      - Alan Tse (https://github.com/alandtse)
 *      - Georgii Gennadev (https://github.com/D00Movenok)
 *      - utoshu (https://github.com/utoshu)
 *      - Jyd (https://github.com/jyd519)
 *      - dmfrpro (https://github.com/dmfrpro)
 *      - Pierre-Étienne Messier (https://github.com/pemessier)
 *  - Repository: https://github.com/kernelwernel/VMAware
 *  - Docs: https://github.com/kernelwernel/VMAware/docs/documentation.md
 *  - Full credits: https://github.com/kernelwernel/VMAware#credits-and-contributors-%EF%B8%8F
 *  - License: MIT
 * 
 *                               MIT License
 *  
 *  Copyright (c) 2025 kernelwernel
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
 * ============================== SECTIONS ==================================
 * - enums for publicly accessible techniques  => line 557
 * - struct for internal cpu operations        => line 743
 * - struct for internal memoization           => line 1209
 * - struct for internal utility functions     => line 1337
 * - struct for internal core components       => line 10102
 * - start of VM detection technique list      => line 2450
 * - start of public VM detection functions    => line 10759
 * - start of externally defined variables     => line 11710
 *
 *
 * ============================== EXAMPLE ===================================
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
 * 
 *
 * ========================== CODE DOCUMENTATION =============================
 *
 * TL;DR if you have the patience of an ADHD kid, head over here:
 * https://deepwiki.com/kernelwernel/VMAware
 * 
 *
 * Welcome! This is just a preliminary text to lay the context of how it works, 
 * how it's structured, and guide anybody who's trying to understand the whole code. 
 * Reading over 12k+ lines of other people's C++ code is obviously not an easy task, 
 * and that's perfectly understandable. I'd struggle as well if I was in your position
 * while not even knowing where to start. So here's a more human-friendly explanation:
 * 
 * 
 * Firstly, the lib is completely static, meaning that there's no need for struct 
 * constructors to be initiated (unless you're using the VM::vmaware struct).
 * The main focus of the lib are the tables:
 *  - the TECHNIQUE table stores all the VM detection technique information in a std::map 
 * 
 *  - the BRAND table stores every VM brand as a std::map as well, but as a scoreboard. 
 *    This means that if a VM detection has detected a VM brand, that brand will have an
 *    incremented score. After every technique is run, the brand with the highest score
 *    is chosen as the officially detected brand. 
 * 
 * The techniques are all static functions, which all return a boolean. There are a few 
 * categories of techniques that target vastly different things such as OS queries, CPU
 * values, other hardware values, firmware data, and system files just to name a few. 
 * 
 * 
 * Secondly, there are multiple modules in the lib that are combined to integrate with
 * the functionalities needed:
 *    - core module:
 *        This contains many important components such as the aforementioned tables, 
 *        the standard structure for how VM techniques are organised, functionalities 
 *        to run all the techniques in the technique table, functionalities to run
 *        custom-made techniques by the user, and an argument handler based on the 
 *        arguments inputted by the user.
 *
 *    - cpu module:
 *        As the name suggests, this contains functionalities for the CPU. There are
 *        many techniques that utilise some kind of low-level CPU interaction, so 
 *        this module was added to further standardise it.
 * 
 *    - memo module:
 *        This contains functionalities for memoizing technique results (not to be
 *        confused with "memorization"). More specifically, this allows us to cache 
 *        a technique result in a table where each entry contains a technique and its
 *        result. This allows us to avoid re-running techniques which happens a lot
 *        internally. Some techniques are costlier than others in terms of 
 *        performance, so this is a crucial module that allows us to save a lot of
 *        time. Additionally, it contains other memoization caches for various other
 *        things for convenience purposes. 
 * 
 *    - util module:
 *        This contains many utility functionalities to be used by the techniques.
 *        Examples of functionalities include file I/O, registries, permission 
 *        checks, system commands, HDD sizes, RAM sizes, debugs, process checking, 
 *        OS queries, Hyper-X, and so on. (It should be mentioned that this is 
 *        probably the least enjoyable part of the lib to read, since it's really messy)
 * 
 * 
 * Thirdly, I'll explain in this section how all of these facets of the lib interact with 
 * each other. Let's take an example with VM::detect(), where it returns a boolean true or 
 * false if a VM has been detected or not. The chain of steps it takes goes like this:
 *    1. The function tries to handle the user arguments (if there's 
 *       any), and generates a std::bitset. This bitset has a length of 
 *       every VM detection technique + settings, where each bit 
 *       corresponds to whether this technique will be run or not, 
 *       and which settings were selected. 
 * 
 *    2. After the bitset has been generated, this information is then 
 *       passed to the core module of the lib. It analyses the bitset, 
 *       and runs every VM detection technique that has been selected, 
 *       while ignoring the ones that weren't selected (by default most 
 *       of them are already selected anyway). The function that does 
 *       this mechanism is core::run_all()
 * 
 *    3. While the core::run_all() function is being ran, it checks if 
 *       each technique has already been memoized or not. If it has, 
 *       retrieve the result from the cache and move to the next technique. 
 *       If it hasn't, run the technique and cache the result to the 
 *       cache table. 
 * 
 *    4. After every technique has been executed, this generates a 
 *       uint16_t score. Every technique has a score value between 0 to 
 *       100, and if they are detected then this score is accumulated to 
 *       a total score. If the total is above 150, that means it's a VM[1]. 
 * 
 * 
 * There are other functions such as VM::brand(), which returns a std::string of the most 
 * likely brand that your system is running on. It has a bit of a different mechanism:
 *    1. Same as step 1 in VM::detect()
 * 
 *    2. Check if the majority of techniques have been run already and stored
 *       in the cache. If not, invoke core::run_all(). The reason why this is
 *       important is because a lot of techniques increment a point for its 
 *       respected brand that was detected. For example, if the VM::QEMU_USB
 *       technique has detected a VM, it'll add a score to the QEMU brand in
 *       the scoreboard. If no technique has been run, then there's no way to
 *       populate the scoreboard with any points. After every VM detection 
 *       technique has been invoked/retrieved, the brand scoreboard is now
 *       ready to be analysed.
 * 
 *    3. Create a filter for the scoreboard, where every brand that has a score
 *       of 0 are erased for abstraction purposes. Now the scoreboard is only
 *       populated with relevant brands where they all have at least a single
 *       point. These are the contenders for which brand will be outputted.
 * 
 *    4. Merge certain brand combinations together. For example, Azure's cloud 
 *       is based on Hyper-V, but Hyper-V may have a higher score due to the 
 *       prevalence of it in a practical setting, which will put Azure to the 
 *       side. In reality, there should be an indication that Azure is involved
 *       since it's a better idea to let the user know that the brand is "Azure 
 *       Hyper-V" instead of just "Hyper-V". So what this step does is "merge" 
 *       the brands together to form a more accurate idea of the brand(s) involved.
 * 
 *    5. After all of this, the scoreboard is sorted in descending order, where
 *       the brands with the highest points are now selected as the official 
 *       output of the VM::brand() function.
 * 
 *    6. The result is then cached to the memo module, so if another function
 *       invokes VM:brand() again, "the result is retrieved from the cache 
 *       without needing to run all of the previous steps again.
 *      
 * (NOTE: it's a bit more complicated than this, but that's the gist of how this function works)
 * 
 * Most of the functions provided usually depend on the 2 techniques covered. 
 * And they serve as a functionality base for other components of the lib.
 *      
 *  
 *  [1]: If the user has provided a setting argument called VM::HIGH_THRESHOLD, 
 *       the threshold becomes 300 instead of 150.
 */

#pragma once

#if defined(_WIN32) || defined(_WIN64)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
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

#if defined(_MSVC_LANG)
#  define VMA_CPLUSPLUS _MSVC_LANG
#else
#  define VMA_CPLUSPLUS __cplusplus
#endif

#if VMA_CPLUSPLUS >= 202300L
#  define CPP 23
#  ifdef __VMAWARE_DEBUG__
#    pragma message("using C++23 or newer")
#  endif

#elif VMA_CPLUSPLUS >= 202002L
#  define CPP 20
#  ifdef __VMAWARE_DEBUG__
#    pragma message("using C++20")
#  endif

#elif VMA_CPLUSPLUS >= 201703L
#  define CPP 17
#  ifdef __VMAWARE_DEBUG__
#    pragma message("using C++17")
#  endif

#elif VMA_CPLUSPLUS >= 201402L
#  define CPP 14
#  ifdef __VMAWARE_DEBUG__
#    pragma message("using C++14")
#  endif

#elif VMA_CPLUSPLUS >= 201103L
#  define CPP 11
#  ifdef __VMAWARE_DEBUG__
#    pragma message("using C++11")
#  endif

#else
#  error "Unsupported C++ standard (pre-C++11 or unknown)."
#endif

#if (CPP < 11 && !WINDOWS)
    #error "VMAware only supports C++11 or above, set your compiler flag to '-std=c++20' for gcc/clang, or '/std:c++20' for MSVC"
#endif


#if defined(__x86_64__) || defined(_M_X64)
#define x86_64 1
#else
#define x86_64 0
#endif

#if defined(__i386__) || defined(_M_IX86)
#define x86_32 1
#else
#define x86_32 0
#endif

#if x86_32 || x86_64
#define x86 1
#else
#define x86 0
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
#include <locale>
#include <codecvt>
#endif

#include <functional>
#include <cstring>
#include <string>
#include <fstream>
#include <regex>
#include <thread>
#include <cstdint>
#include <map>
#include <unordered_set>
#include <array>
#include <algorithm>
#include <iostream>
#include <cassert>
#include <cmath>
#include <sstream>
#include <bitset>
#include <type_traits>
#include <atomic>
#include <condition_variable>
#include <mutex>

#if (WINDOWS)
#include <windows.h>
#include <intrin.h>
#include <tchar.h>
#include <winioctl.h>
#include <winternl.h>
#include <shlwapi.h>
#include <powerbase.h>
#include <setupapi.h>
#include <d3d9helper.h>
#include <tbs.h>
#include <initguid.h>
#include <devpkey.h>
#include <devguid.h>
#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10)
#include <wrl/client.h> // at least windows vista, but used on a function that requires at least windows 10
#endif

#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "powrprof.lib")
#pragma comment(lib, "tbs.lib")
#if (_WIN32_WINNT >= _WIN32_WINNT_WIN10)
#pragma comment(lib, "d3d9.lib")  
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
#include <csignal>      
#include <csetjmp>      
#include <pthread.h>     
#include <sched.h>      
#include <cerrno>   
#elif (APPLE)
#include <sys/types.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <chrono>
#endif

#ifdef _UNICODE
#define tregex std::wregex
#else
#define tregex std::regex
#endif

#ifdef __VMAWARE_DEBUG__
#define debug(...) VM::util::debug_msg(__VA_ARGS__)
#define core_debug(...) VM::util::core_debug_msg(__VA_ARGS__)
#else
#define debug(...)
#define core_debug(...)
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
namespace brands {
    static constexpr const char* NULL_BRAND = "Unknown";
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
    static constexpr const char* PARALLELS = "Parallels";
    static constexpr const char* XEN = "Xen HVM";
    static constexpr const char* ACRN = "ACRN";
    static constexpr const char* QNX = "QNX hypervisor";
    static constexpr const char* HYBRID = "Hybrid Analysis";
    static constexpr const char* SANDBOXIE = "Sandboxie";
    static constexpr const char* DOCKER = "Docker";
    static constexpr const char* WINE = "Wine";
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
    static constexpr const char* INTEL_TDX = "Intel TDX";
    static constexpr const char* LKVM = "LKVM";
    static constexpr const char* AMD_SEV = "AMD SEV";
    static constexpr const char* AMD_SEV_ES = "AMD SEV-ES";
    static constexpr const char* AMD_SEV_SNP = "AMD SEV-SNP";
    static constexpr const char* NEKO_PROJECT = "Neko Project II";
    static constexpr const char* NOIRVISOR = "NoirVisor";
    static constexpr const char* QIHOO = "Qihoo 360 Sandbox";
    static constexpr const char* NSJAIL = "nsjail";
    static constexpr const char* HYPERVISOR_PHANTOM = "Hypervisor-Phantom";
}



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
        TIMER,
        THREAD_COUNT,
        MAC,
        TEMPERATURE,
        SYSTEMD,
        CVENDOR,
        CTYPE,
        DOCKERENV,
        DMIDECODE,
        DMESG,
        HWMON,
        DLL,
        REGISTRY_KEYS,
        FILES,
        HWMODEL,
        DISK_SIZE,
        VBOX_DEFAULT,
        VBOX_NETWORK,
        WINE,
        POWER_CAPABILITIES,
        PROCESSES,
        LINUX_USER_HOST,
        GAMARUE,
        BOCHS_CPU,
        MAC_MEMSIZE,
        MAC_IOKIT,
        IOREG_GREP,
        MAC_SIP,
        REGISTRY_VALUES,
        VPC_INVALID,
        SIDT,
        SGDT,
        SLDT,
        VMWARE_IOMEM,
        VMWARE_IOPORTS,
        VMWARE_SCSI,
        VMWARE_DMESG,
        VMWARE_STR,
        VMWARE_BACKDOOR,
        SMSW,
        MUTEX,
        ODD_CPU_THREADS,
        INTEL_THREAD_MISMATCH,
        XEON_THREAD_MISMATCH,
        CUCKOO_DIR,
        CUCKOO_PIPE,
        HYPERV_HOSTNAME,
        GENERAL_HOSTNAME,
        DISPLAY,
        DEVICE_STRING,
        BLUESTACKS_FOLDERS,
        CPUID_SIGNATURE,
        KGT_SIGNATURE,
        QEMU_VIRTUAL_DMI,
        QEMU_USB,
        HYPERVISOR_DIR,
        UML_CPU,
        KMSG,
        VBOX_MODULE,
        SYSINFO_PROC,
        DMI_SCAN,
        SMBIOS_VM_BIT,
        PODMAN_FILE,
        WSL_PROC,
        DRIVERS,
        DISK_SERIAL,
        PORT_CONNECTORS,
        IVSHMEM,
        GPU_VM_STRINGS,
        GPU_CAPABILITIES,
        DEVICE_HANDLES,
        LOGICAL_PROCESSORS,
        PHYSICAL_PROCESSORS,
        QEMU_FW_CFG,
        LSHW_QEMU,
        VIRTUAL_PROCESSORS,
        HYPERV_QUERY,
        POOLS,
        AMD_SEV,
        AMD_THREAD_MISMATCH,
        VIRTUAL_REGISTRY,
        FIRMWARE,
        FILE_ACCESS_HISTORY,
        AUDIO,
        UNKNOWN_MANUFACTURER,
        NSJAIL_PID,
        TPM,
        PCI_VM_DEVICE_ID,
        QEMU_PASSTHROUGH,
        // ADD NEW TECHNIQUE ENUM NAME HERE

        // special flags, different to settings
        DEFAULT,
        ALL,
        NULL_ARG, // does nothing, just a placeholder flag mainly for the CLI

        // start of settings technique flags (THE ORDERING IS VERY SPECIFIC HERE AND MIGHT BREAK SOMETHING IF RE-ORDERED)
        NO_MEMO,
        HIGH_THRESHOLD,
        DYNAMIC,
        MULTIPLE
    };

private:
    static constexpr u8 enum_size = MULTIPLE; // get enum size through value of last element
    static constexpr u8 settings_count = MULTIPLE - NO_MEMO + 1; // get number of settings technique flags like VM::NO_MEMO for example
    static constexpr u8 INVALID = 255; // explicit invalid technique macro
    static constexpr u16 base_technique_count = NO_MEMO; // original technique count, constant on purpose (can also be used as a base count value if custom techniques are added)
    static constexpr u16 maximum_points = 5510; // theoretical total points if all VM detections returned true (which is practically impossible)
    static constexpr u16 high_threshold_score = 300; // new threshold score from 150 to 300 if VM::HIGH_THRESHOLD flag is enabled
    static constexpr bool SHORTCUT = true; // macro for whether VM::core::run_all() should take a shortcut by skipping the rest of the techniques if the threshold score is already met


    // intended for loop indexes
    static constexpr u8 enum_begin = 0;
    static constexpr u8 enum_end = enum_size + 1;
    static constexpr u8 technique_begin = enum_begin;
    static constexpr u8 technique_end = DEFAULT;
    static constexpr u8 settings_begin = DEFAULT;
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

private:
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
        HYPERV_ENLIGHTENMENT
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
            i32 x[4]{};
            __cpuidex((i32*)x, static_cast<int>(a_leaf), static_cast<int>(c_leaf));
            a = static_cast<u32>(x[0]);
            b = static_cast<u32>(x[1]);
            c = static_cast<u32>(x[2]);
            d = static_cast<u32>(x[3]);
#elif (LINUX || APPLE)
            __cpuid_count(a_leaf, c_leaf, a, b, c, d);
#endif
#else
            return;
#endif
        };

        // same as above but for array type parameters (MSVC specific)
        static void cpuid
        (
            i32 x[4],
            const u32 a_leaf,
            const u32 c_leaf = 0xFF
        ) {
#if (x86)
            // may be unmodified for older 32-bit processors, clearing just in case
            x[1] = 0;
            x[2] = 0;
#if (WINDOWS)
            __cpuidex((i32*)x, static_cast<int>(a_leaf), static_cast<int>(c_leaf));
#elif (LINUX || APPLE)
            __cpuid_count(a_leaf, c_leaf, x[0], x[1], x[2], x[3]);
#endif
#else
            return;
#endif
        };

        // check for maximum function leaf
        static bool is_leaf_supported(const u32 p_leaf) {
            u32 eax = 0, unused = 0;

            if (p_leaf < 0x40000000) {
                // Standard range: 0x00000000 - 0x3FFFFFFF
                cpu::cpuid(eax, unused, unused, unused, 0x00000000);
                debug("CPUID: max standard leaf = ", eax);
                return (p_leaf <= eax);
            }
            else if (p_leaf < 0x80000000) {
                // Hypervisor range: 0x40000000 - 0x7FFFFFFF
                cpu::cpuid(eax, unused, unused, unused, cpu::leaf::hypervisor);
                debug("CPUID: max hypervisor leaf = ", eax);
                return (p_leaf <= eax);
            }
            else if (p_leaf < 0xC0000000) {
                // Extended range: 0x80000000 - 0xBFFFFFFF
                cpu::cpuid(eax, unused, unused, unused, cpu::leaf::func_ext);
                debug("CPUID: max extended leaf = ", eax);
                return (p_leaf <= eax);
            }

            debug("CPUID: unsupported leaf range: ", p_leaf);
            return false;
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

        // get the CPU product
        [[nodiscard]] static std::string get_brand() {
            if (memo::cpu_brand::is_cached()) {
                return memo::cpu_brand::fetch();
            }

#if (!x86)
            return "Unknown";
#else
            if (!cpu::is_leaf_supported(cpu::leaf::brand3)) {
                return "Unknown";
            }

            constexpr std::array<u32, 3> ids {{
                cpu::leaf::brand1,
                cpu::leaf::brand2,
                cpu::leaf::brand3
            }};

            std::string b(48, '\0');

            union Regs {
                u32   i[4];
                char  c[16];
            } regs{};

            for (auto leaf_id : ids) {
                cpu::cpuid(regs.i[0], regs.i[1], regs.i[2], regs.i[3], leaf_id);
                b.append(regs.c, 16);
            }

            memo::cpu_brand::store(b);
            debug("CPU: ", b);
            return b;
#endif
        }

        // cpu manufacturer id
        [[nodiscard]] static std::string cpu_manufacturer(const u32 p_leaf) {
            auto cpuid_thingy = [](const u32 p_leaf, u32* regs, std::size_t start = 0, std::size_t end = 4) -> bool {
                u32 x[4]{};
                cpu::cpuid(x[0], x[1], x[2], x[3], p_leaf);

                for (; start < end; start++) {
                    *regs++ = x[start];
                }

                return true;
            };

            u32 sig_reg[3] = { 0 };

            // Start at index 1 to get EBX, ECX, EDX (x[1], x[2], x[3])
            if (!cpuid_thingy(p_leaf, sig_reg, 1, 4)) {
                return "";
            }

            if ((sig_reg[0] == 0) && (sig_reg[1] == 0) && (sig_reg[2] == 0)) {
                return "";
            }

            auto strconvert = [](u32 n) -> std::string {
                const char* bytes = reinterpret_cast<const char*>(&n);
                return std::string(bytes, 4);
            };

            std::stringstream ss;

            if (p_leaf >= 0x40000000) {
                // Hypervisor vendor string order: EBX, ECX, EDX
                ss << strconvert(sig_reg[0]) << strconvert(sig_reg[1]) << strconvert(sig_reg[2]);
            }
            else {
                // Standard vendor string (leaf 0x0) order: EBX, EDX, ECX
                ss << strconvert(sig_reg[0]) << strconvert(sig_reg[2]) << strconvert(sig_reg[1]);
            }

            return ss.str();
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

            model_struct result{ false, false, false, false, {} };

            if (cpu::is_intel()) {
                if (brand.find("i") != std::string::npos && brand.find("-") != std::string::npos &&
                    brand.find_first_of("0123456789") != std::string::npos) {
                    result.found = true;
                    result.is_i_series = true;
                    result.string = brand;
                    return result;
                }

                if (brand.find_first_of("DEW") != std::string::npos && brand.find("-") != std::string::npos &&
                    brand.find_first_of("0123456789") != std::string::npos) {
                    result.found = true;
                    result.is_xeon = true;
                    result.string = brand;
                    return result;
                }
            }
            else if (cpu::is_amd()) {
                if (brand.find("AMD Ryzen") != std::string::npos) {
                    result.found = true;
                    result.is_ryzen = true;
                    result.string = brand;
                    return result;
                }
            }

            return result;
        }


        [[nodiscard]] static bool vmid_template(const u32 p_leaf) {
            const std::string brand_str = cpu_manufacturer(p_leaf);

            if (brand_str == "Microsoft Hv") {
                if (util::hyper_x() == HYPERV_ARTIFACT_VM) {
                    return false;
                }
                return core::add(brands::HYPERV, brands::VPC);
            }

            if (util::find(brand_str, "KVM")) {
                return core::add(brands::KVM);
            }

            static const std::unordered_map<std::string, const char*> brand_map = {
                {"VMwareVMware", brands::VMWARE},
                {"VBoxVBoxVBox", brands::VBOX},
                {"TCGTCGTCGTCG", brands::QEMU},
                {"XenVMMXenVMM", brands::XEN},
                {"Linux KVM Hv", brands::KVM_HYPERV},
                {" prl hyperv ", brands::PARALLELS},
                {" lrpepyh  vr", brands::PARALLELS},
                {"bhyve bhyve ", brands::BHYVE},
                {"BHyVE BHyVE ", brands::BHYVE},
                {"ACRNACRNACRN", brands::ACRN},
                {" QNXQVMBSQG ", brands::QNX},
                {"___ NVMM ___", brands::NVMM},
                {"OpenBSDVMM58", brands::BSD_VMM},
                {"HAXMHAXMHAXM", brands::INTEL_HAXM},
                {"UnisysSpar64", brands::UNISYS},
                {"SRESRESRESRE", brands::LMHS},
                {"Jailhouse\0\0\0", brands::JAILHOUSE},
                {"EVMMEVMMEVMM", brands::INTEL_KGT},
                {"Barevisor!\0\0", brands::BAREVISOR},
                {"MiniVisor\0\0\0", brands::MINIVISOR},
                {"IntelTDX    ", brands::INTEL_TDX},
                {"LKVMLKVMLKVM", brands::LKVM},
                {"Neko Project", brands::NEKO_PROJECT},
                {"NoirVisor ZT", brands::NOIRVISOR}
            };

            const auto it = brand_map.find(brand_str);
            if (it != brand_map.end()) {
                return core::add(it->second);
            }

            if (util::find(brand_str, "QXNQSBMV")) {
                return core::add(brands::QNX);
            }

            if (util::find(brand_str, "Apple VZ")) {
                return core::add(brands::APPLE_VZ);
            }

            if (util::find(brand_str, "PpyH")) {
                return core::add(brands::HYPERPLATFORM);
            }

            return false;
        }
    };

    // memoization
    struct memo {
    private:
        using points_t = u8;

    public:
        struct data_t {
            bool result;
            points_t points;
        };

    private:
        static std::map<u16, data_t> cache_table;
        static flagset cache_keys;

    public:
        static void cache_store(const u16 technique_macro, const bool result, const points_t points) {
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
                    !cache_keys.test(VMWARE_DMESG) && 
                    !cache_keys.test(PORT_CONNECTORS) && 
                    !cache_keys.test(TEMPERATURE) && 
                    !cache_keys.test(LSHW_QEMU)
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
        struct module {
            static inline std::map<HMODULE, std::map<std::string, void*>> function_cache;

            static bool is_cached(const HMODULE& mod, const std::string& name) {
                auto mod_it = function_cache.find(mod);
                return mod_it != function_cache.end() && mod_it->second.find(name) != mod_it->second.end();
            }

            static void* fetch(const HMODULE& mod, const std::string& name) {
                return function_cache.at(mod).at(name);
            }

            static void store(const HMODULE& mod, const std::string& name, void* addr) {
                function_cache[mod][name] = addr;
            }

            static void store_bulk(const HMODULE& mod, const std::map<std::string, void*>& entries) {
                auto& inner = function_cache[mod];
                for (const auto& kv : entries) {
                    inner[kv.first] = kv.second;
                }
            }
        };
#endif
    };

    // miscellaneous functionalities
    struct util {
#if (LINUX)
        // fetch file data
        [[nodiscard]] static std::string read_file(const char* raw_path) {
            std::string path = "";
            const std::string raw_path_str = raw_path;

            // replace the "~" part with the home directory
            if (raw_path[0] == '~') {
                const char* home = std::getenv("HOME");
                if (home) {
                    path = std::string(home) + raw_path_str.substr(1);
                }
            } else {
                path = raw_path;
            }

            if (!exists(path.c_str())) {
                return "";
            }

            std::ifstream file{};
            std::string data{};
            std::string line{};

            file.open(path);

            if (file.is_open()) {
                while (std::getline(file, line)) {
                    data += line + "\n";
                }
            }

            file.close();
            return data;
        }
#endif

        // fetch the file but in binary form
        [[nodiscard]] static std::vector<u8> read_file_binary(const char* file_path) {
            std::ifstream file(file_path, std::ios::binary);

            if (!file) {
                return {};
            }

            std::vector<u8> buffer;
            std::istreambuf_iterator<char> it(file);
            std::istreambuf_iterator<char> end;

            while (it != end) {
                buffer.push_back(static_cast<u8>(*it));
                ++it;
            }

            file.close();

            return buffer;
        }


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

#if (LINUX)
        static bool is_directory(const char* path) {
            struct stat info;
            if (stat(path, &info) != 0) {
                return false;
            }
            return (info.st_mode & S_IFDIR); // check if directory
        };
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


        [[nodiscard]] static bool is_admin() noexcept {
#if (LINUX || APPLE)
            const uid_t uid = getuid();
            const uid_t euid = geteuid();

            return (
                (uid != euid) ||
                (euid == 0)
            );
#elif (WINDOWS)
            BOOL is_admin = 0;
            HANDLE hToken = nullptr;

            if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
                DWORD dwSize = 0;
                GetTokenInformation(hToken, TokenIntegrityLevel, nullptr, 0, &dwSize);

                if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                    auto pTIL = static_cast<PTOKEN_MANDATORY_LABEL>(malloc(dwSize));
                    if (pTIL != nullptr) {
                        if (GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwSize, &dwSize)) {
                            const DWORD subAuthCount = static_cast<DWORD>(
                                *GetSidSubAuthorityCount(pTIL->Label.Sid));
                            const DWORD dwIntegrityLevel = *GetSidSubAuthority(
                                pTIL->Label.Sid, subAuthCount - 1);

                            if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID) {
                                is_admin = 1;
                            }
                        }
                        free(pTIL);
                    }
                }
                CloseHandle(hToken);
            }

            return is_admin;
#endif
        }


        [[nodiscard]] static bool find(const std::string& base_str, const char* keyword) noexcept {
            return (base_str.find(keyword) != std::string::npos);
        };

#ifdef __VMAWARE_DEBUG__
#if (CPP < 17)
        static inline void print_to_stream(std::ostream&) noexcept {}

        template <typename T, typename... Args>
        static void print_to_stream(std::ostream& os, T&& first, Args&&... args) noexcept {
            os << std::forward<T>(first);
            using expander = int[];
            (void)expander {
                0, (void(os << std::forward<Args>(args)), 0)...
            };
        }
#endif

        static std::string narrow_wide(const wchar_t* wstr) {
            std::wstring ws(wstr);
            std::string result;
            result.reserve(ws.size());
            for (wchar_t wc : ws) {
                result.push_back((wc >= 0 && wc < 128)
                    ? static_cast<char>(wc)
                    : '?');
            }
            return result;
        }

        template <typename... Args>
        static inline void debug_msg(Args&&... message) noexcept {
#if (LINUX || APPLE)
            constexpr const char* black_bg = "\x1B[48;2;0;0;0m";
            constexpr const char* bold = "\033[1m";
            constexpr const char* blue = "\x1B[38;2;00;59;193m";
            constexpr const char* ansiexit = "\x1B[0m";

            std::cout.setf(std::ios::fixed, std::ios::floatfield);
            std::cout.setf(std::ios::showpoint);

            std::cout << black_bg
                << bold << "["
                << blue << "DEBUG"
                << ansiexit << bold << black_bg << "]"
                << ansiexit << " ";
#else
            std::cout << "[DEBUG] ";
#endif

            // helper that picks the right << or narrowing
            auto writeArg = [&](auto&& arg) {
                using T = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<T, const wchar_t*> ||
                    std::is_same_v<T, wchar_t*>)
                {
                    std::cout << narrow_wide(arg);
                }
                else if constexpr (std::is_convertible_v<T, std::wstring>)
                {
                    std::cout << narrow_wide(static_cast<const wchar_t*>(std::wstring(arg).c_str()));
                }
                else
                {
                    std::cout << std::forward<decltype(arg)>(arg);
                }
            };

            // fold‐expr over the pack
#if (CPP >= 17)
            (writeArg(std::forward<Args>(message)), ...);
#else
            print_to_stream(std::cout, std::forward<Args>(message)...);
#endif

            std::cout << std::dec << "\n";
        }


        template <typename... Args>
        static inline void core_debug_msg(Args&&... message) noexcept {
#if (LINUX || APPLE)
            constexpr const char* black_bg = "\x1B[48;2;0;0;0m";
            constexpr const char* bold = "\033[1m";
            constexpr const char* blue = "\x1B[38;2;255;180;5m";
            constexpr const char* ansiexit = "\x1B[0m";

            std::cout.setf(std::ios::fixed, std::ios::floatfield);
            std::cout.setf(std::ios::showpoint);

            std::cout << black_bg
                << bold << "["
                << blue << "CORE DEBUG"
                << ansiexit << bold << black_bg << "]"
                << ansiexit << " ";
#else
            std::cout << "[CORE DEBUG] ";
#endif

            auto writeArg = [&](auto&& arg) {
                using T = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<T, const wchar_t*> ||
                    std::is_same_v<T, wchar_t*>)
                {
                    std::cout << narrow_wide(arg);
                }
                else if constexpr (std::is_convertible_v<T, std::wstring>)
                {
                    std::cout << narrow_wide(static_cast<const wchar_t*>(std::wstring(arg).c_str()));
                }
                else
                {
                    std::cout << std::forward<decltype(arg)>(arg);
                }
            };

#if (CPP >= 17)
            (writeArg(std::forward<Args>(message)), ...);
#else
            print_to_stream(std::cout, std::forward<Args>(message)...);
#endif

            std::cout << std::dec << "\n";
        }
#endif

        [[nodiscard]] static std::unique_ptr<std::string> sys_result(const char* cmd) {
#if (CPP < 14)
            UNUSED(cmd);
            return nullptr;
#else
    #if (LINUX || APPLE)
                struct FileDeleter { void operator()(FILE* f) const noexcept { if (f) pclose(f); } };
                std::unique_ptr<FILE, FileDeleter> pipe(popen(cmd, "r"), FileDeleter());
                if (!pipe) {
                    return nullptr;
                }

                std::string result;
                char* line = nullptr;
                size_t len = 0;
                ssize_t nread;

                while ((nread = getline(&line, &len, pipe.get())) != -1) {
                    result.append(line, static_cast<size_t>(nread));
                }
                free(line);

                if (!result.empty() && result.back() == '\n') {
                    result.pop_back();
                }

                return util::make_unique<std::string>(std::move(result));
    #else
                UNUSED(cmd);
                return std::make_unique<std::string>();
    #endif
#endif
        }


        [[nodiscard]] static u16 get_disk_size() {
            u16 size = 0;
            constexpr u64 GB = 1024ull * 1024 * 1024;
            constexpr u64 U16_MAX = 65535;

#if (LINUX)
            struct statvfs stat;
            if (statvfs("/", &stat) != 0) {
                debug("util::get_disk_size: ", "failed to fetch disk size");
                return 0;
            }

            u64 total_bytes = static_cast<u64>(stat.f_blocks) * stat.f_frsize;
            u64 size_gb = total_bytes / GB;

            if (size_gb > U16_MAX) {
                size = static_cast<u16>(U16_MAX);
            }
            else {
                size = static_cast<u16>(size_gb);
            }

#elif (WINDOWS)
            ULARGE_INTEGER totalNumberOfBytes;
            if (GetDiskFreeSpaceExW(L"C:", nullptr, &totalNumberOfBytes, nullptr)) {
                const u64 size_gb = totalNumberOfBytes.QuadPart / GB;

                if (size_gb > U16_MAX) {
                    size = static_cast<u16>(U16_MAX);
                }
                else {
                    size = static_cast<u16>(size_gb);
                }
            }
            else {
                debug("util::get_disk_size: ", "failed to fetch size in GB");
            }
#endif

            constexpr u16 fallback_size = 81;
            return (size == 0) ? fallback_size : size;
        }


        [[nodiscard]] static u32 get_physical_ram_size() {
#if (LINUX)
            if (!util::is_admin()) {
                debug("get_physical_ram_size: ", "not root, returned 0");
                return 0;
            }

            auto result = util::sys_result("dmidecode --type 19 | grep 'Size' | grep '[[:digit:]]*'");
            if (!result) {
                debug("get_physical_ram_size: ", "invalid system result, returned 0");
                return 0;
            }

            bool is_mb = std::regex_search(*result, std::regex("MB"));
            bool is_gb = std::regex_search(*result, std::regex("GB"));
            if (!(is_mb || is_gb)) {
                debug("get_physical_ram_size: ", "unit not found, returned 0");
                return 0;
            }

            std::string number_str;
            for (char c : *result) {
                if (std::isdigit(c)) number_str += c;
                else if (!number_str.empty()) break;
            }

            if (number_str.empty()) {
                debug("get_physical_ram_size: ", "no digits found, returned 0");
                return 0;
            }

            u64 number = std::stoull(number_str);
            if (is_mb) number = static_cast<u64>(std::round(static_cast<double>(number) / 1024.0));

            return static_cast<u32>(std::min<u64>(number, std::numeric_limits<u32>::max()));
#elif (WINDOWS)
            ULONGLONG total_memory_kb = 0;
            if (GetPhysicallyInstalledSystemMemory(&total_memory_kb) == ERROR_INVALID_DATA)
                return 0;

            return static_cast<u32>(total_memory_kb / (static_cast<unsigned long long>(1024) * 1024));  // return in GB
#else
            return 0;
#endif
        }


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


        [[nodiscard]] static bool is_proc_running(const char* executable) {
#if (LINUX)
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
            UNUSED(executable);
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


        [[nodiscard]] static bool is_running_under_translator() {
#if (WINDOWS && _WIN32_WINNT >= _WIN32_WINNT_WIN10)
            USHORT procMachine = 0, nativeMachine = 0;
            if (IsWow64Process2(GetCurrentProcess(), &procMachine, &nativeMachine)) {
                if (nativeMachine == IMAGE_FILE_MACHINE_ARM64 &&
                    (procMachine == IMAGE_FILE_MACHINE_AMD64 ||
                        procMachine == IMAGE_FILE_MACHINE_I386))
                {
                    return true;
                }
            }           
#endif

            if (cpu::is_leaf_supported(cpu::leaf::hypervisor)) {
                const std::string vendor = cpu::cpu_manufacturer(cpu::leaf::hypervisor);
                if (vendor == "VirtualApple" ||   // Apple Rosetta
                    vendor == "PowerVM Lx86")     // IBM PowerVM Lx86
                {
                    return true;
                }
            }

            return false;
        }


        /**
         * @brief Check whether the system is running in a Hyper-V virtual machine or if the host system has Hyper-V enabled
         * @note Hyper-V's presence on a host system can set certain hypervisor-related CPU flags that may appear similar to those in a virtualized environment, which can make it challenging to differentiate between an actual Hyper-V virtual machine (VM) and a host system with Hyper-V enabled.
         *       This can lead to false conclusions, where the system might mistakenly be identified as running in a Hyper-V VM, when in reality, it's simply the host system with Hyper-V features active.
         *       This check aims to distinguish between these two cases by identifying specific CPU flags and hypervisor-related artifacts that are indicative of a Hyper-V VM rather than a host system with Hyper-V enabled.
         * @author Requiem (https://github.com/NotRequiem)
         * @returns hyperx_state enum indicating the detected state:
         *          - HYPERV_ARTIFACT_VM for host with Hyper-V enabled
         *          - HYPERV_REAL_VM for real Hyper-V VM
         *          - HYPERV_ENLIGHTENMENT for QEMU with Hyper-V enlightenments
         *          - HYPERV_UNKNOWN_VM for unknown/undetected state
         */
        [[nodiscard]] static hyperx_state hyper_x() {
#if (!WINDOWS)
            return HYPERV_UNKNOWN_VM;
#else
            if (memo::hyperx::is_cached()) {
                core_debug("HYPER_X: returned from cache");
                return memo::hyperx::fetch();
            }

            // check if hypervisor feature bit in CPUID eax bit 31 is enabled (always false for physical CPUs)
            auto is_hyperv_present = []() -> bool {
                u32 unused, ecx = 0;
                cpu::cpuid(unused, unused, ecx, unused, 1);

                return (ecx & (1 << 31));
            };

            // 0x40000003 on EBX indicates the flags that a parent partition specified to create a child partition (https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/datatypes/hv_partition_privilege_mask)
            auto is_root_partition = []() -> bool {
                u32 ebx, unused = 0;
                cpu::cpuid(unused, ebx, unused, unused, 0x40000003);
                const bool result = (ebx & 1);

#ifdef __VMAWARE_DEBUG__
                if (result) {
                    core_debug("HYPER_X: running under root partition");
                }
#endif
                return result;
            };

            /**
              * On Hyper-V virtual machines, the cpuid function reports an EAX value of 11
              * This value is tied to the Hyper-V partition model, where each virtual machine runs as a child partition
              * These child partitions have limited privileges and access to hypervisor resources, 
              * which is reflected in the maximum input value for hypervisor CPUID information as 11
              * Essentially, it indicates that the hypervisor is managing the VM and that the VM is not running directly on hardware but rather in a virtualized environment
            */
            auto eax = []() -> u32 {
                char out[sizeof(i32) * 4 + 1] = { 0 };
                cpu::cpuid((int*)out, cpu::leaf::hypervisor);

                const u32 eax = static_cast<u32>(out[0]);

                return eax;
            };

            hyperx_state state;

            if (!is_root_partition()) {
                if (eax() == 11 && is_hyperv_present()) {
                    // Windows machine running under Hyper-V type 2
                    core_debug("HYPER_X: added Hyper-V real VM");
                    core::add(brands::HYPERV);
                    state = HYPERV_REAL_VM;
                }
                else {
                    core_debug("HYPER_X: none found");
                    state = HYPERV_UNKNOWN_VM;
                }
            }
            else {
                // normally eax 12
                const std::string brand_str = cpu::cpu_manufacturer(0x40000001);

                if (util::find(brand_str, "KVM")) {
                    core_debug("HYPER_X: added Hyper-V Enlightenments");
                    core::add(brands::QEMU_KVM_HYPERV);
                    state = HYPERV_ENLIGHTENMENT;
                }
                else {
                    // Windows machine running under Hyper-V type 1
                    core_debug("HYPER_X: added Hyper-V artifact VM");
                    core::add(brands::HYPERV_ARTIFACT);
                    state = HYPERV_ARTIFACT_VM;
                }
            }

            memo::hyperx::store(state);
            core_debug("HYPER_X: cached");

            return state;
#endif
        }

#if (WINDOWS)
        [[nodiscard]] static bool is_wow64() {
            BOOL isWow64 = 0;
            BOOL pbool = IsWow64Process(GetCurrentProcess(), &isWow64);
            return (pbool && isWow64);
        }


        [[nodiscard]] static u8 get_windows_version() {
            struct VersionMapEntry {
                DWORD build;
                u8 major;
            };

            constexpr VersionMapEntry windowsVersions[] = {
                {6002, 6},
                {7601, 7},

                {9200, 8},
                {9600, 8},

                {10240, 10},
                {10586, 10},
                {14393, 10},
                {15063, 10},
                {16299, 10},
                {17134, 10},
                {17763, 10},
                {18362, 10},
                {18363, 10},
                {19041, 10},
                {19042, 10},
                {19043, 10},
                {19044, 10},
                {19045, 10},

                {22000, 11},
                {22621, 11},
                {22631, 11},
                {26100, 11}
            };

            const HMODULE ntdll = GetModuleHandle(_T("ntdll.dll"));
            if (!ntdll) {
                return 0;
            }

            typedef NTSTATUS(__stdcall* RtlGetVersionFunc)(PRTL_OSVERSIONINFOW);
#pragma warning (disable : 4191)
            RtlGetVersionFunc pRtlGetVersion = reinterpret_cast<RtlGetVersionFunc>(GetProcAddress(ntdll, "RtlGetVersion"));
#pragma warning (default : 4191)
            if (!pRtlGetVersion) {
                return 0;
            }

            RTL_OSVERSIONINFOW osvi{};
            osvi.dwOSVersionInfoSize = sizeof(osvi);
            if (pRtlGetVersion(&osvi) != 0) {
                return 0;
            }

            DWORD build = osvi.dwBuildNumber;

            int left = 0;
            int right = static_cast<int>(sizeof(windowsVersions) / sizeof(windowsVersions[0])) - 1;

            while (left <= right) {
                int mid = left + (right - left) / 2;
                if (windowsVersions[mid].build == build) {
                    return windowsVersions[mid].major;
                }
                else if (build < windowsVersions[mid].build) {
                    right = mid - 1;
                }
                else {
                    left = mid + 1;
                }
            }

            return 0;
        }


        // retrieves the addresses of specified functions from a loaded module using the export directory, manual implementation of GetProcAddress
        static void GetFunctionAddresses(const HMODULE hModule, const char* names[], void** functions, size_t count) {
            BYTE* base = reinterpret_cast<BYTE*>(hModule);
            const PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
            const PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dosHeader->e_lfanew);
            const auto& dd = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            const PIMAGE_EXPORT_DIRECTORY exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(base + dd.VirtualAddress);

            const DWORD* nameRvas = reinterpret_cast<DWORD*>(base + exportDir->AddressOfNames);
            const DWORD* funcRvas = reinterpret_cast<DWORD*>(base + exportDir->AddressOfFunctions);
            const WORD* ordinals = reinterpret_cast<WORD*>(base + exportDir->AddressOfNameOrdinals);
            const DWORD nameCount = exportDir->NumberOfNames;

            auto getName = [&](DWORD idx) -> const char* {
                return reinterpret_cast<char*>(base + nameRvas[idx]);
            };

            for (size_t i = 0; i < count; ++i) {
                std::string fname = names[i];
                if (memo::module::is_cached(hModule, fname)) {
                    functions[i] = memo::module::fetch(hModule, fname);
                    continue;
                }

                functions[i] = nullptr;
                DWORD lo = 0, hi = nameCount;
                while (lo < hi) {
                    DWORD mid = (lo + hi) / 2;
                    int cmp = strcmp(getName(mid), names[i]);
                    if (cmp < 0) {
                        lo = mid + 1;
                    }
                    else {
                        hi = mid;
                    }
                }

                if (lo < nameCount && strcmp(getName(lo), names[i]) == 0) {
                    DWORD rva = funcRvas[ordinals[lo]];
                    void* addr = base + rva;
                    functions[i] = addr;
                    memo::module::store(hModule, fname, addr);
                }
            }
        }
#endif
    };


private: // START OF PRIVATE VM DETECTION TECHNIQUE DEFINITIONS
    /**
     * @brief Check CPUID output of manufacturer ID for known VMs/hypervisors at leaf 0 and 0x40000000-0x40000100
     * @category x86
     * @implements VM::VMID
     */
    [[nodiscard]] static bool vmid() {
#if (!x86)
        return false;
#else
        return (
            cpu::vmid_template(0) ||
            cpu::vmid_template(cpu::leaf::hypervisor) || // 0x40000000
            cpu::vmid_template(cpu::leaf::hypervisor + 0x100) // 0x40000100
        );
#endif
    }


    /**
     * @brief Check if CPU brand model contains any VM-specific string snippets
     * @category x86
     * @implements VM::CPU_BRAND
     */
    [[nodiscard]] static bool cpu_brand() {
#if (!x86)
        return false;
#else
        const std::string& brand = cpu::get_brand();

        struct CStrView {
            const char* data;
            std::size_t size;
            constexpr CStrView(const char* d, std::size_t s) noexcept
                : data(d), size(s) {
            }
        };

        static constexpr std::array<CStrView, 10> checks{ {
            { "qemu",       4 },
            { "kvm",        3 },
            { "vbox",       4 },
            { "virtualbox", 10},
            { "monitor",    7 },
            { "bhyve",      5 },
            { "hypervisor", 10},
            { "hvisor",     6 },
            { "parallels",  9 },
            { "vmware",     6 }
        } };

        for (auto& v : checks) {
            if (brand.size() < v.size)
                continue;  // too short to match

            if (brand.find(v.data) != std::string::npos) {
                debug("CPU_BRAND: match = ", v.data);

                // For these, we only care that it's virtualized:
                if (v.size == 7  // "monitor"
                    || ((v.size == 6) && (v.data[0] == 'h'))  // "hvisor"
                    || ((v.size == 10) && (v.data[0] == 'h')) // "hypervisor" 
                ) {
                    return true;
                }

                switch (v.size) {
                case 4:  // "qemu" or "vbox"
                    return core::add(v.data[0] == 'q'
                        ? brands::QEMU
                        : brands::VBOX);
                case 3:  // "kvm"
                    return core::add(brands::KVM);
                case 5:  // "bhyve"
                    return core::add(brands::BHYVE);
                case 9:  // "parallels"
                    return core::add(brands::PARALLELS);
                case 10: // "virtualbox"
                    return core::add(brands::VBOX);
                case 6:  // "vmware"
                    return core::add(brands::VMWARE);
                default:
                    return false;
                }
            }
        }

        return false;
#endif
    }


    /**
     * @brief Check if hypervisor feature bit in CPUID eax bit 31 is enabled (always false for physical CPUs)
     * @category x86
     * @implements VM::HYPERVISOR_BIT
     */
    [[nodiscard]] static bool hypervisor_bit() {
#if (!x86)
        return false;
#else
        if (util::hyper_x() == HYPERV_ARTIFACT_VM) {
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
     * @implements VM::HYPERVISOR_STR
     */
    [[nodiscard]] static bool hypervisor_str() {
#if (!x86)
        return false;
#else
        if (util::hyper_x() == HYPERV_ARTIFACT_VM) {
            return false;
        }

        char out[sizeof(i32) * 4 + 1] = { 0 }; // e*x size + number of e*x registers + null terminator
        cpu::cpuid((int*)out, cpu::leaf::hypervisor);

        debug("HYPERVISOR_STR: \neax: ", static_cast<u32>(out[0]),
            "\nebx: ", static_cast<u32>(out[1]),
            "\necx: ", static_cast<u32>(out[2]),
            "\nedx: ", static_cast<u32>(out[3])
        );

        return (strlen(out + 4) >= 4);
#endif
    }


    /**
     * @brief Check if there are only 1 or 2 threads, which is a common pattern in VMs with default settings (nowadays physical CPUs should have at least 4 threads for modern CPUs
     * @category x86 (ARM might have very low thread counts, which is why it should be only for x86). Linux, Apple
     * @implements VM::THREAD_COUNT
     */
    [[nodiscard]] static bool thread_count() {
#if (x86 && (LINUX || APPLE))
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
     * @category Linux
     * @implements VM::MAC
     */
    [[nodiscard]] static bool mac_address_check() {
#if (!LINUX)
        return false;
#else
        // C-style array on purpose
        u8 mac[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        struct ifreq ifr;
        struct ifconf ifc;
        char buf[1024];
        i32 success = 0;

        i32 sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);

        if (sock == -1) {
            return false;
        }

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

    #ifdef __VMAWARE_DEBUG__
        {
            std::stringstream ss;
            ss << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<int>(mac[0]) << ":"
                << static_cast<int>(mac[1]) << ":"
                << static_cast<int>(mac[2]) << ":XX:XX:XX";
            debug("MAC: ", ss.str());
        }
    #endif

        if ((mac[0] | mac[1] | mac[2]) == 0) {
            return false;
        }

        const u32 prefix = (u32)mac[0]
            | ((u32)mac[1] << 8)
            | ((u32)mac[2] << 16);

        constexpr u32 VBOX = 0x270008;  // 08:00:27
        constexpr u32 VMW1 = 0x29000C;  // 00:0C:29
        constexpr u32 VMW2 = 0x141C00;  // 00:1C:14
        constexpr u32 VMW3 = 0x565000;  // 00:50:56
        constexpr u32 VMW4 = 0x690500;  // 00:05:69
        constexpr u32 XEN = 0xE31600;  // 00:16:E3
        constexpr u32 PAR = 0x421C00;  // 00:1C:42

        if (prefix == VBOX) {
            return core::add(brands::VBOX);
        }
        else if (prefix == VMW1 || prefix == VMW2
            || prefix == VMW3 || prefix == VMW4) {
            return core::add(brands::VMWARE);
        }
        else if (prefix == XEN) {
            return core::add(brands::XEN);
        }
        else if (prefix == PAR) {
            return core::add(brands::PARALLELS);
        }

        return false;
#endif
    }


    /**
     * @brief Check result from systemd-detect-virt tool
     * @category Linux
     * @implements VM::SYSTEMD
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
     * @implements VM::CVENDOR
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

        // TODO: More can definitely be added, I only tried QEMU and VBox so far
        if (util::find(vendor, "QEMU")) { return core::add(brands::QEMU); }
        if (util::find(vendor, "Oracle Corporation")) { return core::add(brands::VBOX); }

        debug("CVENDOR: vendor = ", vendor);

        return false;
#endif
    }


    /**
     * @brief Check if the chassis type is valid (it's very often invalid in VMs)
     * @category Linux
     * @implements VM::CTYPE
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
     * @implements VM::DOCKERENV
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
     * @implements VM::DMIDECODE
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
     * @implements VM::DMESG
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
     * @implements VM::HWMON
     */
    [[nodiscard]] static bool hwmon() {
#if (!LINUX)
        return false;
#else
        return (!util::exists("/sys/class/hwmon/"));
#endif
    }


    /**
     * @brief Check for VM-specific DLLs
     * @category Windows
     * @implements VM::DLL
     */
    [[nodiscard]] static bool dll() {
#if (!WINDOWS)
        return false;
#else
        static constexpr struct {
            const char* dll_name;  
            const char* brand;
        } dlls[] = {
            {"sbiedll.dll",   brands::SANDBOXIE},
            {"pstorec.dll",   brands::CWSANDBOX},
            {"vmcheck.dll",   brands::VPC},
            {"cmdvrt32.dll",  brands::COMODO},
            {"cmdvrt64.dll",  brands::COMODO},
            {"cuckoomon.dll", brands::CUCKOO},
            {"SxIn.dll",      brands::QIHOO},
            {"wpespy.dll",    brands::NULL_BRAND}
        };

        for (const auto& dll : dlls) {
            if (GetModuleHandleA(dll.dll_name) != nullptr) {
                debug("DLL: Found ", dll.dll_name, " (", dll.brand, ")");
                return core::add(dll.brand);
            }
        }

        return false;
#endif
    }


    /**
     * @brief Check for VM-specific registry values
     * @category Windows
     * @implements VM::REGISTRY_KEYS
     */
    [[nodiscard]] static bool registry_keys() {
#if (!WINDOWS)
        return false;
#else
        struct Entry { const char* brand; const char* regkey; };
        static constexpr Entry entries[] = {
            { nullptr, "HKLM\\Software\\Classes\\Folder\\shell\\sandbox" },

            { brands::PARALLELS, "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_1AB8*" },

            { brands::SANDBOXIE,  "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Sandboxie" },

            { brands::VBOX, "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_80EE*" },
            { brands::VBOX, "HKLM\\HARDWARE\\ACPI\\DSDT\\VBOX__" },
            { brands::VBOX, "HKLM\\HARDWARE\\ACPI\\FADT\\VBOX__" },
            { brands::VBOX, "HKLM\\HARDWARE\\ACPI\\RSDT\\VBOX__" },
            { brands::VBOX, "HKLM\\SOFTWARE\\Oracle\\VirtualBox Guest Additions" },
            { brands::VBOX, "HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxGuest" },
            { brands::VBOX, "HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxMouse" },
            { brands::VBOX, "HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxService" },
            { brands::VBOX, "HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxSF" },
            { brands::VBOX, "HKLM\\SYSTEM\\ControlSet001\\Services\\VBoxVideo" },

            { brands::VPC, "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_5333*" },
            { brands::VPC, "HKLM\\SYSTEM\\ControlSet001\\Services\\vpcbus" },
            { brands::VPC, "HKLM\\SYSTEM\\ControlSet001\\Services\\vpc-s3" },
            { brands::VPC, "HKLM\\SYSTEM\\ControlSet001\\Services\\vpcuhub" },
            { brands::VPC, "HKLM\\SYSTEM\\ControlSet001\\Services\\msvmmouf" },

            { brands::VMWARE, "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_15AD*" },
            { brands::VMWARE, "HKCU\\SOFTWARE\\VMware, Inc.\\VMware Tools" },
            { brands::VMWARE, "HKLM\\SOFTWARE\\VMware, Inc.\\VMware Tools" },
            { brands::VMWARE, "HKLM\\SYSTEM\\ControlSet001\\Services\\vmdebug" },
            { brands::VMWARE, "HKLM\\SYSTEM\\ControlSet001\\Services\\vmmouse" },
            { brands::VMWARE, "HKLM\\SYSTEM\\ControlSet001\\Services\\VMTools" },
            { brands::VMWARE, "HKLM\\SYSTEM\\ControlSet001\\Services\\VMMEMCTL" },
            { brands::VMWARE, "HKLM\\SYSTEM\\CurrentControlSet\\Services\\vmmouse" },
            { brands::VMWARE, "HKLM\\SYSTEM\\CurrentControlSet\\Services\\vmusbmouse" },
            { brands::VMWARE, "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\IDE\\CdRomNECVMWar_VMware_IDE_CD*" },
            { brands::VMWARE, "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\IDE\\CdRomNECVMWar_VMware_SATA_CD*" },
            { brands::VMWARE, "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\IDE\\DiskVMware_Virtual_IDE_Hard_Drive*" },
            { brands::VMWARE, "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\IDE\\DiskVMware_Virtual_SATA_Hard_Drive*" },
            { brands::VMWARE, "HKLM\\SYSTEM\\ControlSet001\\Enum\\ACPI\\VMW0003" },
            { brands::VMWARE, "HKLM\\SYSTEM\\CurrentControlSet\\Services\\vmmouse" },
            { brands::VMWARE, "HKLM\\SYSTEM\\CurrentControlSet\\Services\\vmusbmouse" },

            { brands::WINE,    "HKCU\\SOFTWARE\\Wine" },
            { brands::WINE,    "HKLM\\SOFTWARE\\Wine" },

            { brands::XEN, "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_5853*" },
            { brands::XEN, "HKLM\\HARDWARE\\ACPI\\DSDT\\xen" },
            { brands::XEN, "HKLM\\HARDWARE\\ACPI\\FADT\\xen" },
            { brands::XEN, "HKLM\\HARDWARE\\ACPI\\RSDT\\xen" },
            { brands::XEN, "HKLM\\SYSTEM\\ControlSet001\\Services\\xenevtchn" },
            { brands::XEN, "HKLM\\SYSTEM\\ControlSet001\\Services\\xennet" },
            { brands::XEN, "HKLM\\SYSTEM\\ControlSet001\\Services\\xennet6" },
            { brands::XEN, "HKLM\\SYSTEM\\ControlSet001\\Services\\xensvc" },
            { brands::XEN, "HKLM\\SYSTEM\\ControlSet001\\Services\\xenvdb" },

            { brands::KVM,  "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_1AF4*" },
            { brands::KVM,  "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\PCI\\VEN_1B36*" },
            { brands::KVM,  "HKLM\\SYSTEM\\ControlSet001\\Services\\vioscsi" },
            { brands::KVM,  "HKLM\\SYSTEM\\ControlSet001\\Services\\viostor" },
            { brands::KVM,  "HKLM\\SYSTEM\\ControlSet001\\Services\\VirtIO-FS Service" },
            { brands::KVM,  "HKLM\\SYSTEM\\ControlSet001\\Services\\VirtioSerial" },
            { brands::KVM,  "HKLM\\SYSTEM\\ControlSet001\\Services\\BALLOON" },
            { brands::KVM,  "HKLM\\SYSTEM\\ControlSet001\\Services\\BalloonService" },
            { brands::KVM,  "HKLM\\SYSTEM\\ControlSet001\\Services\\netkvm" },
        };

        u8 score = 0;
        const bool wow64 = util::is_wow64();
        const REGSAM sam = wow64 ? (KEY_READ | KEY_WOW64_64KEY) : KEY_READ;

        for (auto const& e : entries) {
            const char* full = e.regkey;
            HKEY hRoot = nullptr;

            if (full[0] == 'H' && full[1] == 'K' && full[2] == 'L' && full[3] == 'M' && full[4] == '\\') {
                hRoot = HKEY_LOCAL_MACHINE; full += 5;
            }
            else if (full[0] == 'H' && full[1] == 'K' && full[2] == 'C' && full[3] == 'U' && full[4] == '\\') {
                hRoot = HKEY_CURRENT_USER;  full += 5;
            }
            else continue;

            const char* sub = full;
            bool wildcard = strchr(sub, '*') || strchr(sub, '?');

            if (wildcard) {
                const char* slash = strrchr(sub, '\\');
                const char* parent = slash ? sub : "";
                const char* pattern = slash ? slash + 1 : sub;

                HKEY hParent;
                if (RegOpenKeyExA(hRoot, parent, 0, sam, &hParent) != 0L)
                    continue;

                DWORD idx = 0;
                char  name[MAX_PATH];
                DWORD nameLen = MAX_PATH;
                bool found = false;

                while (RegEnumKeyExA(hParent, idx, name, &nameLen,
                    nullptr, nullptr, nullptr, nullptr) == 0L)
                {
                    if (PathMatchSpecA(name, pattern)) {
                        found = true;
                        break;
                    }
                    idx++;
                    nameLen = MAX_PATH;
                }
                RegCloseKey(hParent);

                if (!found) continue;
            }
            else {
                HKEY hKey;
                if (RegOpenKeyExA(hRoot, sub, 0, sam, &hKey) != 0L)
                    continue;
                RegCloseKey(hKey);
            }

            score++;
            if (e.brand && e.brand[0]) {
                debug("REGISTRY_KEYS: ", "detected ", e.regkey, " for brand ", e.brand);
                core::add(e.brand);
            }
        }

        return score >= 1;
#endif
    }


    /**
     * @brief Find for VM specific files
     * @category Windows
     * @implements VM::FILES
     */
    [[nodiscard]] static bool files() {
#if !WINDOWS
        return false;
#else
        PVOID oldValue = nullptr;
        bool wow64RedirectDisabled = false;

        if (util::is_wow64()) {
            Wow64DisableWow64FsRedirection(&oldValue);
            wow64RedirectDisabled = true;
        }

        // system directory instead of the Windows directory
        char szSysDir[MAX_PATH] = { 0 };
        if (GetSystemDirectoryA(szSysDir, MAX_PATH) == 0) {
            if (wow64RedirectDisabled) {
                Wow64RevertWow64FsRedirection(&oldValue);
            }
            return false;
        }

        constexpr std::array<const char*, 12> vmwareFiles = { {
             "drivers\\Vmmouse.sys",
             "drivers\\Vmusbmouse.sys",
             "drivers\\vm3dgl.dll",
             "drivers\\vmdum.dll",
             "drivers\\VmGuestLibJava.dll",
             "drivers\\vm3dver.dll",
             "drivers\\vmtray.dll",
             "drivers\\VMToolsHook.dll",
             "drivers\\vmGuestLib.dll",
             "drivers\\vmhgfs.dll",
             "vm3dum64_loader.dll",
             "vm3dum64_10.dll"
        } };

        constexpr std::array<const char*, 17> vboxFiles = { {
             "drivers\\VBoxMouse.sys",
             "drivers\\VBoxGuest.sys",
             "drivers\\VBoxSF.sys",
             "drivers\\VBoxVideo.sys",
             "vboxoglpackspu.dll",
             "vboxoglpassthroughspu.dll",
             "vboxservice.exe",
             "vboxoglcrutil.dll",
             "vboxdisp.dll",
             "vboxhook.dll",
             "vboxmrxnp.dll",
             "vboxogl.dll",
             "vboxtray.exe",
             "VBoxControl.exe",
             "vboxoglerrorspu.dll",
             "vboxoglfeedbackspu.dll",
             "vboxoglarrayspu.dll"
        } };

        constexpr std::array<const char*, 10> kvmFiles = { {
            "drivers\\balloon.sys",
            "drivers\\netkvm.sys",
            "drivers\\pvpanic.sys",
            "drivers\\viofs.sys",
            "drivers\\viogpudo.sys",
            "drivers\\vioinput.sys",
            "drivers\\viorng.sys",
            "drivers\\vioscsi.sys",
            "drivers\\vioser.sys",
            "drivers\\viostor.sys"
        } };

        constexpr std::array<const char*, 7> parallelsFiles = { {
            "drivers\\prleth.sys",
            "drivers\\prlfs.sys",
            "drivers\\prlmouse.sys",
            "drivers\\prlvideo.sys",
            "drivers\\prltime.sys",
            "drivers\\prl_pv32.sys",
            "drivers\\prl_paravirt_32.sys"
        } };

        constexpr std::array<const char*, 2> vpcFiles = { {
            "drivers\\vmsrvc.sys",
            "drivers\\vpc-s3.sys"
        } };

        u8 vmware = 0, vbox = 0, kvm = 0, vpc = 0, parallels = 0;

        auto checkFiles = [&](const auto& files, u8& count) {
            for (const auto& relativePath : files) {
                char szPath[MAX_PATH] = { 0 };
                PathCombineA(szPath, szSysDir, relativePath);
                if (util::exists(szPath)) {
                    ++count;
                }
            }
        };

        checkFiles(vmwareFiles, vmware);
        checkFiles(vboxFiles, vbox);
        checkFiles(kvmFiles, kvm);
        checkFiles(parallelsFiles, parallels);
        checkFiles(vpcFiles, vpc);

        if (wow64RedirectDisabled) {
            Wow64RevertWow64FsRedirection(&oldValue);
        }

        if (util::exists("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\agent.pyw")) {
            debug("VM_FILES: Found startup agent (agent.pyw), indicating CUCKOO VM.");
            return core::add(brands::CUCKOO);
        }

        {
            char basePath[MAX_PATH];
            const char* programDir = nullptr;
            // if under WoW64, read ProgramW6432; otherwise read ProgramFiles
            if (util::is_wow64()) {
                DWORD len = GetEnvironmentVariableA(
                    /*lpName*/        "ProgramW6432",
                    /*lpBuffer*/      basePath,
                    /*nSize*/         MAX_PATH
                );
                if (len > 0 && len < MAX_PATH) {
                    programDir = basePath;
                }
            }
            else {
                DWORD len = GetEnvironmentVariableA(
                    /*lpName*/        "ProgramFiles",
                    /*lpBuffer*/      basePath,
                    /*nSize*/         MAX_PATH
                );
                if (len > 0 && len < MAX_PATH) {
                    programDir = basePath;
                }
            }
            if (programDir) {
                const char suffix[] = "\\Virtio-Win\\";
                size_t dirLen = strlen(programDir);
                size_t suffLen = sizeof(suffix) - 1;
                if (dirLen + suffLen < MAX_PATH) {
                    memcpy(basePath + dirLen, suffix, suffLen + 1);
                    if (util::exists(basePath)) {
                        debug("VM_FILES: Detected KVM directory at ", basePath);
                        return core::add(brands::KVM);
                    }
                }
            }
        }

        {
            char szProgramFile[MAX_PATH];
            char szPath[MAX_PATH] = { 0 };
            const char* szDirectories[] = {
                "qemu-ga",
                "SPICE Guest Tools",
            };
            int dirCount = sizeof(szDirectories) / sizeof(szDirectories[0]);

            for (int i = 0; i < dirCount; ++i) {
                // correct Program* variable based on WoW64
                if (util::is_wow64()) {
                    DWORD len = GetEnvironmentVariableA(
                        /*lpName*/   "ProgramW6432",
                        /*lpBuffer*/ szProgramFile,
                        /*nSize*/    MAX_PATH
                    );
                    if (len == 0 || len >= MAX_PATH) {
                        szProgramFile[0] = '\0';
                    }
                }
                else {
                    DWORD len = GetEnvironmentVariableA(
                        /*lpName*/   "ProgramFiles",
                        /*lpBuffer*/ szProgramFile,
                        /*nSize*/    MAX_PATH
                    );
                    if (len == 0 || len >= MAX_PATH) {
                        szProgramFile[0] = '\0';
                    }
                }

                if (szProgramFile[0] != '\0') {
                    // full path: szProgramFile + "\" + directory name
                    size_t baseLen = strlen(szProgramFile);
                    size_t dirLen = strlen(szDirectories[i]);
                    if (baseLen + 1 + dirLen < MAX_PATH) {
                        memcpy(szPath, szProgramFile, baseLen);
                        szPath[baseLen] = '\\';
                        memcpy(szPath + baseLen + 1, szDirectories[i], dirLen);
                        szPath[baseLen + 1 + dirLen] = '\0';

                        if (util::exists(szPath)) {
                            debug("VM_FILES: Detected QEMU directory at ", szPath);
                            return core::add(brands::QEMU);
                        }
                    }
                }
            }
        }

        if (vbox > vmware && vbox > kvm && vbox > vpc && vbox > parallels) {
            debug("VM_FILES: Detected VBox files with count ", vbox);
            return core::add(brands::VBOX);
        }
        if (vmware > vbox && vmware > kvm && vmware > vpc && vmware > parallels) {
            debug("VM_FILES: Detected VMware files with count ", vmware);
            return core::add(brands::VMWARE);
        }
        if (kvm > vbox && kvm > vmware && kvm > vpc && kvm > parallels) {
            debug("VM_FILES: Detected KVM files with count ", kvm);
            return core::add(brands::KVM);
        }
        if (vpc > vbox && vpc > vmware && vpc > kvm && vpc > parallels) {
            debug("VM_FILES: Detected VPC files with count ", vpc);
            return core::add(brands::VPC);
        }
        if (parallels > vbox && parallels > vmware && parallels > kvm && parallels > vpc) {
            debug("VM_FILES: Detected Parallels files with count ", parallels);
            return core::add(brands::PARALLELS);
        }

        return false;
#endif
    }


    /**
     * @brief Check if the sysctl for the hwmodel does not contain the "Mac" string
     * @author MacRansom ransomware
     * @category MacOS
     * @implements VM::HWMODEL
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
     * @implements VM::DISK_SIZE
     */
    [[nodiscard]] static bool disk_size() {
#if (!LINUX && !WINDOWS)
        return false;
#else
        const u16 size = util::get_disk_size();

        debug("DISK_SIZE: size = ", size);

        return (size <= 80);
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
     * @implements VM::VBOX_DEFAULT
     */
    [[nodiscard]] static bool vbox_default_specs() {
#if (APPLE)
        return false;
#else
        const u16 disk = util::get_disk_size(); 
        const u32 ram = util::get_physical_ram_size(); 

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

        return false;
    #elif (WINDOWS)
        const u8 version = util::get_windows_version();

        if (version < 10) {
            return false;
        }

        if (version == 10) {
            debug("VBOX_DEFAULT: Windows 10 detected");
            return ((50 == disk) && (2 == ram));
        }

        debug("VBOX_DEFAULT: Windows 11 detected");
        return ((80 == disk) && (4 == ram));
    #endif
#endif
    }


    /**
     * @brief Check for VirtualBox network provider string
     * @category Windows
     * @implements VM::VBOX_NETWORK
     */
    [[nodiscard]] static bool vbox_network_share() {
#if (!WINDOWS)
        return false;
#else
        static const bool isVBoxSF = []() -> bool {
            HKEY hKey = nullptr;

            constexpr LPCTSTR kVBoxSFKey = _T("SYSTEM\\CurrentControlSet\\Services\\VBoxSF");

            const LONG result = RegOpenKeyEx(
                HKEY_LOCAL_MACHINE,
                kVBoxSFKey,
                0,
                KEY_READ,
                &hKey
            );

            if (result == 0L) {
                RegCloseKey(hKey);
                return true;
            }
            return false;
            }();

        return isVBoxSF;
#endif
    }  


    /**
     * @brief Check if the function "wine_get_unix_file_name" is present and if the OS booted from a VHD container
     * @category Windows
     * @implements VM::WINE
     */
    [[nodiscard]] static bool wine() {
 #if (!WINDOWS)
      return false;
 #else     
    #if (_WIN32_WINNT < _WIN32_WINNT_WIN8)
            return false;
    #else
            BOOL isNativeVhdBoot = 0;

            __try {
                if (IsNativeVhdBoot(&isNativeVhdBoot)) {
                    return (isNativeVhdBoot == 1);
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                debug("WINE: SEH invoked");
                return true;
            }
    #endif

       const HMODULE k32 = GetModuleHandle(_T("kernel32.dll"));
       if (!k32) {
           return false;
       }

       const char* names[] = { "wine_get_unix_file_name" };
       void* functions[1] = { nullptr };

       util::GetFunctionAddresses(k32, names, functions, _countof(names));

       if (functions[0] != nullptr) {
           return core::add(brands::WINE);
       }

       return false;
#endif
    }


    /**
     * @brief Check what power states are enabled
     * @category Windows
     * @implements VM::POWER_CAPABILITIES
     */
    [[nodiscard]] static bool power_capabilities() {
#if (!WINDOWS)
        return false;
#else
        const HMODULE ntdll = GetModuleHandle(_T("ntdll.dll"));
        const char* names[] = { "NtPowerInformation" };
        void* funcs[1] = { nullptr };
        util::GetFunctionAddresses(ntdll, names, funcs, _countof(funcs));

        if (!funcs[0])
            return false;

        using NtPI_t = NTSTATUS(__stdcall*)(POWER_INFORMATION_LEVEL,
            PVOID, ULONG,
            PVOID, ULONG);
        auto NtPowerInformation = reinterpret_cast<NtPI_t>(funcs[0]);

        SYSTEM_POWER_CAPABILITIES caps = { 0 };
        NTSTATUS status = NtPowerInformation(
            SystemPowerCapabilities,
            nullptr, 0,
            &caps, sizeof(caps)
        );
        if (status != 0)
            return false;

        const bool no_sleep_states = !(caps.SystemS1 ||
            caps.SystemS2 ||
            caps.SystemS3 ||
            caps.SystemS4);
        if (no_sleep_states)
        {
            return (caps.ThermalControl == 0);
        }

        return false;
#endif
    }


    /**
     * @brief Check for any VM processes that are active
     * @category Windows
     * @implements VM::PROCESSES
     */
    [[nodiscard]] static bool processes() {
#if (WINDOWS)
        using QSI_t = NTSTATUS(__stdcall*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
        static QSI_t NtQSI = nullptr;
        
        if (!NtQSI) {
            const HMODULE ntdll = ::GetModuleHandle(_T("ntdll.dll"));
            if (!ntdll) return false;
            const char* fn = "NtQuerySystemInformation";
            void* addr = nullptr;
            util::GetFunctionAddresses(ntdll, &fn, &addr, 1);
            NtQSI = reinterpret_cast<QSI_t>(addr);
            if (!NtQSI) return false;
        }

        static PBYTE buf = nullptr;
        static ULONG bufSize = 0;
        ULONG needed = 0;

        NTSTATUS st = NtQSI(SystemProcessInformation, nullptr, 0, &needed);
        if (st != 0xC0000004 /*STATUS_INFO_LENGTH_MISMATCH*/)
            return false;

        if (needed + 1024 > bufSize) {
            if (buf) HeapFree(GetProcessHeap(), 0, buf);
            bufSize = needed + 1024;
            buf = static_cast<PBYTE>(HeapAlloc(GetProcessHeap(), 0, bufSize));
            if (!buf) return false;
        }

        st = NtQSI(SystemProcessInformation, buf, bufSize, &needed);
        if (st < 0)
            return false;

        struct ProcInfo {
            const WCHAR* name;
            USHORT        len;
            const char* brandName;
        } tbl[] = {
             { L"joeboxserver.exe",   18, brands::JOEBOX },
             { L"joeboxcontrol.exe",  17, brands::JOEBOX },
             { L"prl_cc.exe",          10, brands::PARALLELS },
             { L"prl_tools.exe",       12, brands::PARALLELS },
             { L"vboxservice.exe",     14, brands::VBOX },
             { L"vboxtray.exe",        11, brands::VBOX },
             { L"VBoxControl.exe",     14, brands::VBOX },
             { L"vmsrvc.exe",          10, brands::VPC },
             { L"vmusrvc.exe",         10, brands::VPC },
             { L"xenservice.exe",      13, brands::XEN },
             { L"xsvc_depriv.exe",     14, brands::XEN },
             { L"vm3dservice.exe",     14, brands::VMWARE },
             { L"VGAuthService.exe",   16, brands::VMWARE },
             { L"vmtoolsd.exe",        11, brands::VMWARE },
             { L"vdagent.exe",         10, brands::QEMU },
             { L"vdservice.exe",       11, brands::QEMU },
             { L"qemuwmi.exe",         10, brands::QEMU },
             { L"looking-glass-host.exe", 21, brands::HYPERVISOR_PHANTOM },
             { L"VDDSysTray.exe",      13, brands::HYPERVISOR_PHANTOM },
        };

        const PBYTE end = buf + bufSize;
        for (PBYTE p = buf; ; p += reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(p)->NextEntryOffset) {
            auto* info = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(p);

            if (info->ImageName.Buffer && info->ImageName.Length >= sizeof(WCHAR)) {
                USHORT wlen = info->ImageName.Length / sizeof(WCHAR);
                const WCHAR* w = info->ImageName.Buffer;

                for (auto& row : tbl) {
                    if (wlen == row.len
                        && memcmp(w, row.name, wlen * sizeof(WCHAR)) == 0)
                    {
                        debug("PROCESSES: Detected ", row.name);
                        return core::add(row.brandName);
                    }
                }
            }

            if (info->NextEntryOffset == 0)
                break;
            if (p + info->NextEntryOffset > end)
                break;
        }

#elif (LINUX)
        if (util::is_proc_running("qemu_ga")) {
            debug("PROCESSES: Detected QEMU guest agent process.");
            return core::add(brands::QEMU);
        }

        if (util::exists("/proc/xen")) {
            return core::add(brands::XEN);
        }

        if (util::exists("/proc/vz")) {
            return core::add(brands::OPENVZ);
        }
#endif
        return false;
    }


    /**
     * @brief Check for default VM username and hostname for linux
     * @category Linux
     * @implements VM::LINUX_USER_HOST
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

        if (!username || !hostname) {
            debug("VM::LINUX_USER_HOST: environment variables not found");
            return false;
        }

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
     * @implements VM::GAMARUE
     */
    [[nodiscard]] static bool gamarue() {
#if (!WINDOWS)
        return false;
#else
        HKEY hKey;
        char buffer[64] = { 0 };
        DWORD dwSize = sizeof(buffer);
        LONG lRes;

        lRes = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
            _T("Software\\Microsoft\\Windows\\CurrentVersion"),
            0,
            KEY_QUERY_VALUE,
            &hKey);

        if (lRes != 0L) return false;

        lRes = RegQueryValueEx(hKey, _T("ProductId"),
            nullptr, nullptr,
            reinterpret_cast<LPBYTE>(buffer), &dwSize);

        RegCloseKey(hKey);

        if (lRes != 0L) return false;

        struct TargetPattern {
            const char* product_id;
            const char* brand;
        };

        constexpr TargetPattern targets[] = {
            {"55274-640-2673064-23950", "JOEBOX"},
            {"76487-644-3177037-23510", "CWSANDBOX"},
            {"76487-337-8429955-22614", "ANUBIS"}
        };

        constexpr size_t target_len = 21;

        if (strlen(buffer) != target_len) return false;

        for (const auto& target : targets) {
            if (memcmp(buffer, target.product_id, target_len) == 0) {
                debug("GAMARUE: Detected ", target.product_id);
                return core::add(target.brand);
            }
        }

        return false;
#endif
    }


    /**
     * @brief Check for various Bochs-related emulation oversights through CPU checks
     * @category x86
     * @note Discovered by Peter Ferrie, Senior Principal Researcher, Symantec Advanced Threat Research peter_ferrie@symantec.com
     * @implements VM::BOCHS_CPU
     */
    [[nodiscard]] static bool bochs_cpu() {
#if (!x86)
        return false;
#else
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
     * @brief Check if memory is too low for MacOS system
     * @category MacOS
     * @link https://evasions.checkpoint.com/techniques/macos.html
     * @implements VM::MAC_MEMSIZE
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
     * @implements VM::MAC_IOKIT
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
     * @implements VM::IOREG_GREP
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
     * @implements VM::MAC_SIP
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
     * @implements VM::REGISTRY_VALUES
     */
    [[nodiscard]] static bool registry_values() {
#if (!WINDOWS)
        return false;
#else
        std::unordered_set<std::string> failedKeys;

        struct RegCheck {
            const char* brand;
            const char* subKey;
            const char* valueName;
            const char* compString;
        };
        static const std::vector<RegCheck> checks = {
            { brands::BOCHS,    "HARDWARE\\Description\\System",                                                      "SystemBiosVersion",       "BOCHS" },
            { brands::BOCHS,    "HARDWARE\\Description\\System",                                                      "VideoBiosVersion",        "BOCHS" },

            { brands::ANUBIS,   "SOFTWARE\\Microsoft\\Windows\\CurrentVersion",                                      "ProductID",               "76487-337-8429955-22614" },
            { brands::ANUBIS,   "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",                                 "ProductID",               "76487-337-8429955-22614" },

            { brands::CWSANDBOX,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion",                                      "ProductID",               "76487-644-3177037-23510" },
            { brands::CWSANDBOX,"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",                                 "ProductID",               "76487-644-3177037-23510" },

            { brands::JOEBOX,   "SOFTWARE\\Microsoft\\Windows\\CurrentVersion",                                      "ProductID",               "55274-640-2673064-23950" },
            { brands::JOEBOX,   "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",                                 "ProductID",               "55274-640-2673064-23950" },

            { brands::PARALLELS,"HARDWARE\\Description\\System",                                                      "SystemBiosVersion",       "PARALLELS" },
            { brands::PARALLELS,"HARDWARE\\Description\\System",                                                      "VideoBiosVersion",        "PARALLELS" },

            { brands::QEMU,     "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier",           "QEMU" },
            { brands::QEMU,     "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier",           "QEMU" },
            { brands::QEMU,     "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier",           "QEMU" },
            { brands::QEMU,     "HARDWARE\\Description\\System",                                                      "SystemBiosVersion",       "QEMU" },
            { brands::QEMU,     "HARDWARE\\Description\\System",                                                      "VideoBiosVersion",        "QEMU" },
            { brands::QEMU,     "HARDWARE\\Description\\System\\BIOS",                                            "SystemManufacturer",     "QEMU" },

            { brands::VBOX,     "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier",           "VBOX" },
            { brands::VBOX,     "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier",           "VBOX" },
            { brands::VBOX,     "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier",           "VBOX" },
            { brands::VBOX,     "HARDWARE\\Description\\System",                                                      "SystemBiosVersion",       "VBOX" },
            { brands::VBOX,     "HARDWARE\\DESCRIPTION\\System",                                                      "SystemBiosDate",          "06/23/99" },
            { brands::VBOX,     "HARDWARE\\Description\\System",                                                      "VideoBiosVersion",        "VIRTUALBOX" },
            { brands::VBOX,     "HARDWARE\\Description\\System\\BIOS",                                            "SystemProductName",      "VIRTUAL" },
            { brands::VBOX,     "SYSTEM\\ControlSet001\\Services\\Disk\\Enum",                                    "DeviceDesc",             "VBOX" },
            { brands::VBOX,     "SYSTEM\\ControlSet001\\Services\\Disk\\Enum",                                    "FriendlyName",           "VBOX" },
            { brands::VBOX,     "SYSTEM\\ControlSet002\\Services\\Disk\\Enum",                                    "DeviceDesc",             "VBOX" },
            { brands::VBOX,     "SYSTEM\\ControlSet002\\Services\\Disk\\Enum",                                    "FriendlyName",           "VBOX" },
            { brands::VBOX,     "SYSTEM\\ControlSet003\\Services\\Disk\\Enum",                                    "DeviceDesc",             "VBOX" },
            { brands::VBOX,     "SYSTEM\\ControlSet003\\Services\\Disk\\Enum",                                    "FriendlyName",           "VBOX" },
            { brands::VBOX,     "SYSTEM\\CurrentControlSet\\Control\\SystemInformation",                              "SystemProductName",      "VIRTUAL" },
            { brands::VBOX,     "SYSTEM\\CurrentControlSet\\Control\\SystemInformation",                              "SystemProductName",      "VIRTUALBOX" },

            { brands::VMWARE,   "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier",           "VMWARE" },
            { brands::VMWARE,   "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier",           "VMWARE" },
            { brands::VMWARE,   "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier",           "VMWARE" },
            { brands::VMWARE,   "HARDWARE\\Description\\System",                                                      "SystemBiosVersion",       "VMWARE" },
            { brands::VMWARE,   "HARDWARE\\Description\\System",                                                      "SystemBiosVersion",       "INTEL - 6040000" },
            { brands::VMWARE,   "HARDWARE\\Description\\System",                                                      "VideoBiosVersion",        "VMWARE" },
            { brands::VMWARE,   "HARDWARE\\Description\\System\\BIOS",                                            "SystemProductName",      "VMware" },
            { brands::VMWARE,   "HARDWARE\\Description\\System\\BIOS",                                            "SystemManufacturer",     "VMware, Inc." },
            { brands::VMWARE,   "SYSTEM\\ControlSet001\\Services\\Disk\\Enum",                                    "0",                       "VMware" },
            { brands::VMWARE,   "SYSTEM\\ControlSet001\\Services\\Disk\\Enum",                                    "1",                       "VMware" },
            { brands::VMWARE,   "SYSTEM\\ControlSet001\\Services\\Disk\\Enum",                                    "DeviceDesc",             "VMware" },
            { brands::VMWARE,   "SYSTEM\\ControlSet001\\Services\\Disk\\Enum",                                    "FriendlyName",           "VMware" },
            { brands::VMWARE,   "SYSTEM\\ControlSet002\\Services\\Disk\\Enum",                                    "DeviceDesc",             "VMware" },
            { brands::VMWARE,   "SYSTEM\\ControlSet002\\Services\\Disk\\Enum",                                    "FriendlyName",           "VMware" },
            { brands::VMWARE,   "SYSTEM\\ControlSet003\\Services\\Disk\\Enum",                                    "DeviceDesc",             "VMware" },
            { brands::VMWARE,   "SYSTEM\\ControlSet003\\Services\\Disk\\Enum",                                    "FriendlyName",           "VMware" },
            { brands::VMWARE,   "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",                        "DisplayName",            "vmware tools" },
            { brands::VMWARE,   "SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000", "CoInstallers32",        "*vmx*" },
            { brands::VMWARE,   "SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000", "DriverDesc",            "VMware*" },
            { brands::VMWARE,   "SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000", "InfSection",            "vmx*" },
            { brands::VMWARE,   "SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000", "ProviderName",          "VMware*" },
            { brands::VMWARE,   "SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\Settings", "Device Description",  "VMware*" },
            { brands::VMWARE,   "SYSTEM\\CurrentControlSet\\Control\\SystemInformation",                              "SystemProductName",      "VMWARE" },
            { brands::VMWARE,   "SYSTEM\\CurrentControlSet\\Control\\Video\\{GUID}\\Video",                        "Service",                "vm3dmp" },
            { brands::VMWARE,   "SYSTEM\\CurrentControlSet\\Control\\Video\\{GUID}\\Video",                        "Service",                "vmx_svga" },
            { brands::VMWARE,   "SYSTEM\\CurrentControlSet\\Control\\Video\\{GUID}\\0000",                       "Device Description",    "VMware SVGA*" },
            { brands::VMWARE,   "SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum",                                    "0",                       "VMWare" },
            { brands::VMWARE,   "HARDWARE\\ACPI\\DSDT\\PTLTD_\\CUSTOM__\\00000000",                           "00000000",               "VMWARE" },

            { brands::XEN,      "HARDWARE\\Description\\System\\BIOS",                                              "SystemProductName",      "Xen" },
        };

        std::unordered_map<std::string, std::vector<const RegCheck*>> grouped;
        grouped.reserve(checks.size());
        for (const auto& chk : checks) {
            grouped[chk.subKey].push_back(&chk);
        }

#if (CPP >= 17)
        for (auto& [subKey, entries] : grouped) {
#else
        for (auto it = grouped.begin(); it != grouped.end(); ++it) {
            const std::string& subKey = it->first;
            std::vector<const RegCheck*>& entries = it->second;
#endif
            if (failedKeys.count(subKey)) continue;

            HKEY hKey;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hKey) != 0L) {
                failedKeys.insert(subKey);
                continue;
            }

            for (auto* chk : entries) {
                DWORD dwType;
                char buffer[1024] = {};
                DWORD bufferSize = sizeof(buffer);

                if (RegQueryValueExA(hKey, chk->valueName, nullptr, &dwType,
                    reinterpret_cast<LPBYTE>(buffer), &bufferSize) == 0L) {
                    if (dwType == REG_SZ || dwType == REG_EXPAND_SZ || dwType == REG_MULTI_SZ) {
                        buffer[bufferSize ? bufferSize - 1 : 0] = '\0';
                        if (strstr(buffer, chk->compString) != nullptr) {
                            debug("REGISTRY_VALUES: Found ", chk->compString, " in ", subKey.c_str(), " for brand ", chk->brand);
                            RegCloseKey(hKey);
                            return core::add(chk->brand);
                        }
                    }
                }
            }

            RegCloseKey(hKey);
        }

        return false;
#endif
    }


    /**
     * @brief Check for official VPC method
     * @category Windows, x86_32
     * @implements VM::VPC_INVALID
     */
    [[nodiscard]] static bool vpc_invalid() {
#if (WINDOWS && x86_32 && !CLANG)
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
     * @brief Check for uncommon IDT virtual addresses
     * @author Matteo Malvica (Linux)
     * @link https://www.matteomalvica.com/blog/2018/12/05/detecting-vmware-on-64-bit-systems/ (Linux)
     * @note Idea to check VPC's range from Tom Liston and Ed Skoudis' paper "On the Cutting Edge: Thwarting Virtual Machine Detection" (Windows)
     * @note Paper situated at /papers/ThwartingVMDetection_Liston_Skoudis.pdf (Windows)
     * @category Windows, Linux
     * @implements VM::SIDT
     */
    [[nodiscard]] static bool sidt() {
#if (LINUX && (GCC || CLANG))
        u8 values[10] = { 0 };

        fflush(stdout);

#if (x86_64)
        // 64-bit Linux: IDT descriptor is 10 bytes (2-byte limit + 8-byte base)
        __asm__ __volatile__("sidt %0" : "=m"(values));

#ifdef __VMAWARE_DEBUG__
        debug("SIDT5: values = ");
        for (u8 i = 0; i < 10; ++i) {
            debug(std::hex, std::setw(2), std::setfill('0'), static_cast<unsigned>(values[i]));
            if (i < 9) debug(" ");
        }
#endif

        return (values[9] == 0x00);  // 10th byte in x64 mode

#elif (x86_32)
        // 32-bit Linux: IDT descriptor is 6 bytes (2-byte limit + 4-byte base)
        __asm__ __volatile__("sidt %0" : "=m"(values));

#ifdef __VMAWARE_DEBUG__
        debug("SIDT5: values = ");
        for (u8 i = 0; i < 6; ++i) {
            debug(std::hex, std::setw(2), std::setfill('0'), static_cast<unsigned>(values[i]));
            if (i < 5) debug(" ");
        }
#endif

        return (values[5] == 0x00);  // 6th byte in x86 mode

#else
        return false;
#endif
#elif (WINDOWS)
        SYSTEM_INFO si;
        GetNativeSystemInfo(&si);

        const DWORD_PTR origMask = SetThreadAffinityMask(GetCurrentThread(), 1);
        SetThreadAffinityMask(GetCurrentThread(), origMask);

        bool found = false;
        for (DWORD i = 0; i < si.dwNumberOfProcessors; ++i) {
            const DWORD_PTR mask = (DWORD_PTR)1 << i;
            if (SetThreadAffinityMask(GetCurrentThread(), mask) == 0)
                continue;

#if (x86_64)
            unsigned char m[10] = { 0 };
#else
            unsigned char m[6] = { 0 };
#endif
            u32 idt_base = 0;

            __try {
#if (CLANG || GCC)
                __asm__ volatile ("sidt %0" : "=m"(m));
#elif (MSVC && x86_32)
                __asm { sidt m }
#else  // MSVC x64
#pragma pack(push,1)
                struct { u16 limit; u64 base; } idtr = {};
#pragma pack(pop)
                __sidt(&idtr);
                memcpy(m, &idtr, sizeof(m));
#endif
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {} // CR4.UMIP

            idt_base = *reinterpret_cast<u32*>(&m[2]); // extract 32-bit base from bytes [2..5]
            if (m[5] > 0xD0) { // On x64, m[5] is the top byte of the 64-bit base; on x86 it's high byte of 32-bit base
                debug("0xD0 signature detected");
                found = true;
            }

            if ((idt_base >> 24) == 0xE8) {
                debug("VPC signature detected");
                SetThreadAffinityMask(GetCurrentThread(), origMask);
                return core::add(brands::VPC);
            }

            if (found)
                break;
        }

        SetThreadAffinityMask(GetCurrentThread(), origMask);
        return found;
#endif
    }


    /**
     * @brief Check for sgdt instruction method
     * @category Windows
     * @author Danny Quist (chamuco@gmail.com) (top-most byte signature)
     * @author Val Smith (mvalsmith@metasploit.com) (top-most byte signature)
     * @note code documentation paper in /papers/www.offensivecomputing.net_vm.pdf (top-most byte signature)
     * @implements VM::SGDT
     */
    [[nodiscard]] static bool sgdt() {
#if (WINDOWS)
        SYSTEM_INFO si;
        GetNativeSystemInfo(&si);
        const DWORD_PTR origMask = SetThreadAffinityMask(GetCurrentThread(), 1);
        SetThreadAffinityMask(GetCurrentThread(), origMask);

        bool found = false;
        for (DWORD i = 0; i < si.dwNumberOfProcessors; ++i) {
            const DWORD_PTR mask = (DWORD_PTR)1 << i;
            if (SetThreadAffinityMask(GetCurrentThread(), mask) == 0)
                continue;

#if (x86_64)
            unsigned char gdtr[10] = { 0 };
#else
            unsigned char gdtr[6] = { 0 };
#endif
            u32 gdt_base = 0;

            __try {
#if (CLANG || GCC)
                __asm__ volatile("sgdt %0" : "=m"(gdtr));
#elif (MSVC && x86_32)
                __asm { sgdt gdtr }
#else
#pragma pack(push,1)
                struct { u16 limit; u64 base; } _gdtr = {};
#pragma pack(pop)
                _sgdt(&_gdtr);
                memcpy(gdtr, &_gdtr, sizeof(gdtr));
#endif
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {} // CR4.UMIP

            // On x64, gdtr[5] is the top byte of the 64-bit base; on x86 it's high byte of 32-bit base
            if (gdtr[5] > 0xD0) {
                debug("SGDT: top-most byte signature detected");
                found = true;
            }

            // 0xFF signature in the high byte of the 32-bit base
            if ((gdt_base >> 24) == 0xFF) {
                debug("SGDT: 0xFF signature detected");
                found = true;
            }

            if (found)
                break;
        }

        SetThreadAffinityMask(GetCurrentThread(), origMask);
        return found;
#else
        return false;
#endif
    }


    /**
     * @brief Check for sldt instruction method
     * @category Windows, x86_32
     * @author Danny Quist (chamuco@gmail.com), ldtr_buf signature
     * @author Val Smith (mvalsmith@metasploit.com), ldtr_buf signature
     * @note code documentation paper in /papers/www.offensivecomputing.net_vm.pdf for ldtr_buf signature
     * @note code documentation paper in https://www.aldeid.com/wiki/X86-assembly/Instructions/sldt for ldt signature
     * @implements VM::SLDT
     */
    [[nodiscard]] static bool sldt() {
#if (WINDOWS && x86_32)
        SYSTEM_INFO si;
        GetNativeSystemInfo(&si);
        const DWORD_PTR origMask = SetThreadAffinityMask(GetCurrentThread(), 1);
        SetThreadAffinityMask(GetCurrentThread(), origMask);

        bool found = false;
        for (DWORD i = 0; i < si.dwNumberOfProcessors; ++i) {
            const DWORD_PTR mask = (DWORD_PTR)1 << i;
            if (SetThreadAffinityMask(GetCurrentThread(), mask) == 0)
                continue;

            unsigned char ldtr_buf[4] = { 0xEF, 0xBE, 0xAD, 0xDE };
            u32 ldt_val = 0;

            __try {
#if (CLANG || GCC)
                __asm__ volatile("sldt %0" : "=m"(*(u16*)ldtr_buf));
#else  // MSVC
                __asm {
                    sldt ax
                    mov  word ptr[ldtr_buf], ax
                }
#endif
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {} // CR4.UMIP

            memcpy(&ldt_val, ldtr_buf, sizeof(ldt_val));
            if (ldtr_buf[0] != 0x00 && ldtr_buf[1] != 0x00) {
                debug("SLDT: ldtr_buf signature detected");
                found = true;
            }
            if (ldt_val != 0xDEAD0000) {
                debug("SLDT: 0xDEAD0000 signature detected");
                found = true;
            }

            if (found)
                break;
        }

        SetThreadAffinityMask(GetCurrentThread(), origMask);
        return found;
#else
        return false;
#endif
    }


    /**
     * @brief Check for SMSW assembly instruction technique
     * @category Windows, x86_32
     * @author Danny Quist from Offensive Computing
     * @implements VM::SMSW
     */
    [[nodiscard]] static bool smsw() {
#if (!WINDOWS || !x86_64)
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
     * @brief Check for VMware string in /proc/iomem
     * @category Linux
     * @note idea from ScoopyNG by Tobias Klein
     * @implements VM::VMWARE_IOMEM
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
     * @implements VM::VMWARE_IOPORTS
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
     * @implements VM::VMWARE_SCSI
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
     * @implements VM::VMWARE_DMESG
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
     * @implements VM::VMWARE_STR
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
     * @category Windows, x86_32
     * @note Code from ScoopyNG by Tobias Klein
     * @note Technique founded by Ken Kato
     * @copyright BSD clause 2
     * @implements VM::VMWARE_BACKDOOR
     */
    [[nodiscard]] static bool vmware_backdoor() {
#if (WINDOWS && x86_32 && !CLANG)
        u32 a = 0;
        u32 b = 0;

        constexpr std::array<i16, 2> ioports = { { 'VX' , 'VY' } };
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

         return false;
#else
         return false;
#endif
    }


    /**
     * @brief Check for mutex strings of VM brands
     * @category Windows
     * @note from VMDE project
     * @author hfiref0x
     * @implements VM::MUTEX
     */
    [[nodiscard]] static bool mutex() {
#if (!WINDOWS)
        return false;
#else
        auto supMutexExist = [](const char* lpMutexName) -> bool {
            if (lpMutexName == NULL) {
                return false;
            }

            SetLastError(0);
            const HANDLE hObject = CreateMutexA(NULL, FALSE, lpMutexName);
            const DWORD dwError = GetLastError();

            if (hObject) {
                CloseHandle(hObject);
            }

            return (dwError == ERROR_ALREADY_EXISTS);
        };

        if (
            supMutexExist("Sandboxie_SingleInstanceMutex_Control") ||
            supMutexExist("SBIE_BOXED_ServiceInitComplete_Mutex1")
        ) {
            debug("MUTEX: Detected Sandboxie");
            return core::add(brands::SANDBOXIE);
        }

        if (supMutexExist("MicrosoftVirtualPC7UserServiceMakeSureWe'reTheOnlyOneMutex")) {
            debug("MUTEX: Detected VPC");
            return core::add(brands::VPC);
        }

        if (supMutexExist("Frz_State")) {
            debug("MUTEX: Detected DeepFreeze");
            return true;
        }

        return false;
#endif
    }


    /**
     * @brief Check for odd CPU threads, usually a sign of modification through VM setting because 99% of CPUs have even numbers of threads
     * @category x86
     * @implements VM::ODD_CPU_THREADS
     */
    [[nodiscard]] static bool odd_cpu_threads() {
#if (!x86)
        return false;
#else
        const u32 threads = std::thread::hardware_concurrency();

        auto steps = cpu::fetch_steppings();
        if (!(cpu::is_intel() || cpu::is_amd()))
            return false;
        if (cpu::is_celeron(steps))
            return false;

        auto make_id = [](u8 family, u8 extmodel, u8 model) -> u32 {
            return (static_cast<u32>(family) << 16) |
                (static_cast<u32>(extmodel) << 8) |
                static_cast<u32>(model);
            };

        static constexpr std::array<u32, 35> old_microarch_ids = { {
                // Family 4 (Intel 486): models 1,2,3,4,5,7,8,9
                make_id(0x4, 0x0, 0x1), make_id(0x4, 0x0, 0x2),
                make_id(0x4, 0x0, 0x3), make_id(0x4, 0x0, 0x4),
                make_id(0x4, 0x0, 0x5), make_id(0x4, 0x0, 0x7),
                make_id(0x4, 0x0, 0x8), make_id(0x4, 0x0, 0x9),

                // Family 5 (Pentium, P5): models 1,2,4,7,8
                make_id(0x5, 0x0, 0x1), make_id(0x5, 0x0, 0x2),
                make_id(0x5, 0x0, 0x4), make_id(0x5, 0x0, 0x7),
                make_id(0x5, 0x0, 0x8),

                // Family 6 (P6/Pentium Pro/Celeron/Pentium II–III): models 1,3,5,6,7,8,9,A,B,D,E,F
                make_id(0x6, 0x0, 0x1), make_id(0x6, 0x0, 0x3),
                make_id(0x6, 0x0, 0x5), make_id(0x6, 0x0, 0x6),
                make_id(0x6, 0x0, 0x7), make_id(0x6, 0x0, 0x8),
                make_id(0x6, 0x0, 0x9), make_id(0x6, 0x0, 0xA),
                make_id(0x6, 0x0, 0xB), make_id(0x6, 0x0, 0xD),
                make_id(0x6, 0x0, 0xE), make_id(0x6, 0x0, 0xF),

                // Family 6 (Yonah/early Core): models 1,2 (extmodel = 1)
                make_id(0x6, 0x1, 0x5), make_id(0x6, 0x1, 0x6),

                // Family F (Pentium 4): models 2,3,4,6,10
                make_id(0xF, 0x0, 0x2), make_id(0xF, 0x0, 0x3),
                make_id(0xF, 0x0, 0x4), make_id(0xF, 0x0, 0x6),
                make_id(0xF, 0x0, 0x10)
            } };

        const u32 curId = make_id(steps.family, steps.extmodel, steps.model);
        for (u32 oldId : old_microarch_ids) {
            if (curId == oldId)
                return false;
        }

        return (threads & 1u) != 0;
#endif
    }


    /**
     * @brief Check for Intel CPU thread count database if it matches the system's thread count
     * @category x86
     * @implements VM::INTEL_THREAD_MISMATCH
     */
    [[nodiscard]] static bool intel_thread_mismatch() {
#if (!x86)
        return false;
#else
        if (!cpu::is_intel()) {
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

        struct ThreadEntry {
            const char* model;
            unsigned    threads;
        };

        static const ThreadEntry thread_database[] = {
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
            { "i3-1210U", 8 },
            { "i3-1215U", 8 },
            { "i3-1215UE", 8 },
            { "i3-1215UL", 8 },
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
            { "i5-10210U", 8 },
            { "i5-10210Y", 8 },
            { "i5-10300H", 8 },
            { "i5-1030G4", 8 },
            { "i5-1030G7", 8 },
            { "i5-1030NG7", 8 },
            { "i5-10310U", 8 },
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
            { "i5-1230U", 12 },
            { "i5-1235U", 12 },
            { "i5-12400", 12 },
            { "i5-12400F", 12 },
            { "i5-12400T", 12 },
            { "i5-1240P", 16 },
            { "i5-1240U", 12 },
            { "i5-1245U", 12 },
            { "i5-12490F", 12 },
            { "i5-12500", 12 },
            { "i5-12500H", 16 },
            { "i5-12500HL", 16 },
            { "i5-12500T", 12 },
            { "i5-1250P", 16 },
            { "i5-1250PE", 16 },
            { "i5-12600", 12 },
            { "i5-12600H", 16 },
            { "i5-12600HE", 16 },
            { "i5-12600HL", 16 },
            { "i5-12600HX", 16 },
            { "i5-12600K", 16 },
            { "i5-12600KF", 16 },
            { "i5-12600T", 12 },
            { "i5-13400", 16 },
            { "i5-13400F", 16 },
            { "i5-13400T", 16 },
            { "i5-1340P", 16 },
            { "i5-1340PE", 16 },
            { "i5-13490F", 16 },
            { "i5-13500", 20 },
            { "i5-13500H", 16 },
            { "i5-13500T", 20 },
            { "i5-13505H", 16 },
            { "i5-1350P", 16 },
            { "i5-1350PE", 16 },
            { "i5-13600", 20 },
            { "i5-13600H", 16 },
            { "i5-13600HE", 16 },
            { "i5-13600K", 20 },
            { "i5-13600KF", 20 },
            { "i5-13600T", 20 },
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
            { "i7-10710U", 12 },
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
            { "i7-1250U", 12 },
            { "i7-1255U", 12 },
            { "i7-1260P", 16 },
            { "i7-1260U", 12 },
            { "i7-1265U", 12 },
            { "i7-12700", 20 },
            { "i7-12700F", 20 },
            { "i7-12700K", 20 },
            { "i7-12700KF", 20 },
            { "i7-12700T", 20 },
            { "i7-12700H", 20 },
            { "i7-1270P", 16 },
            { "i7-1270PE", 16 },
            { "i7-1360P", 16 },
            { "i7-13700", 24 },
            { "i7-13700F", 24 },
            { "i7-13700K", 24 },
            { "i7-13700KF", 24 },
            { "i7-13700T", 24 },
            { "i7-13790F", 24 },
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
            { "i9-12900", 24 },
            { "i9-12900F", 24 },
            { "i9-12900K", 24 },
            { "i9-12900KF", 24 },
            { "i9-12900KS", 24 },
            { "i9-12900T", 24 },
            { "i9-13900", 32 },
            { "i9-13900E", 32 },
            { "i9-13900F", 32 },
            { "i9-13900HX", 32 },
            { "i9-13900K", 32 },
            { "i9-13900KF", 32 },
            { "i9-13900KS", 32 },
            { "i9-13900T", 32 },
            { "i9-13900TE", 32 },
            { "i9-13950HX", 32 },
            { "i9-13980HX", 32 },
            { "i9-14900", 32 },
            { "i9-14900F", 32 },
            { "i9-14900HX", 32 },
            { "i9-14900K", 32 },
            { "i9-14900KF", 32 },
            { "i9-14900KS", 32 },
            { "i9-14900T", 32 },
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

        constexpr size_t thread_database_count = sizeof(thread_database) / sizeof(thread_database[0]);
        const std::string cpu_full_name = model.string;

        for (size_t i = 0; i < thread_database_count; ++i) {
            if (cpu_full_name.find(thread_database[i].model) != std::string::npos) {
                const unsigned expected = thread_database[i].threads;
                const unsigned actual = (unsigned)std::thread::hardware_concurrency();
                debug("INTEL_THREAD_MISMATCH: Expected threads -> ", expected);
                debug("INTEL_THREAD_MISMATCH: Current threads -> ", actual);
                return (actual != expected);
            }
        }

        return false;
#endif
    }


    /**
     * @brief Same as above, but for Xeon Intel CPUs
     * @category x86
     * @link https://en.wikipedia.org/wiki/List_of_Intel_Core_processors
     * @implements VM::XEON_THREAD_MISMATCH
     */
    [[nodiscard]] static bool xeon_thread_mismatch() {
#if (!x86)
        return false;
#else
        if (!cpu::is_intel()) {
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

        struct ThreadEntry {
            const char* model;
            unsigned    threads;
        };

        static const ThreadEntry thread_database[] = {
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

        constexpr size_t thread_database_count = sizeof(thread_database) / sizeof(thread_database[0]);
        const std::string cpu_full_name = model.string;

        for (size_t i = 0; i < thread_database_count; ++i) {
            if (cpu_full_name.find(thread_database[i].model) != std::string::npos) {
                const unsigned expected = thread_database[i].threads;
                const unsigned actual = (unsigned)std::thread::hardware_concurrency();
                debug("XEON_THREAD_MISMATCH:  Expected threads -> ", expected);
                debug("XEON_THREAD_MISMATCH:  Current threads -> ", actual);
                return (actual != expected);
            }
        }

        return false;
#endif
    }


    /**
     * @brief Check for AMD CPU thread count database if it matches the system's thread count
     * @link https://www.amd.com/en/products/specifications/processors.html
     * @category x86
     * @implements VM::AMD_THREAD_MISMATCH
     */
    [[nodiscard]] static bool amd_thread_mismatch() {
#if (!x86)
        return false;
#else
        if (!cpu::is_amd()) {
            return false;
        }

        std::string model = cpu::get_brand();

        for (char& c : model) {
            c = static_cast<char>(std::tolower(c));
        }

        debug("AMD_THREAD_MISMATCH: CPU model = ", model);

        // all of these have spaces at the end on purpose, because some of these could 
        // accidentally match different brands. Like for example: "a10-6700" could be 
        // detected when scanning the string in "a10-6700t", which are both different 
        // and obviously incorrect. So to fix this, spaces are added at the end.
        struct ThreadEntry {
            const char* model;
            unsigned    threads;
        };

        static const ThreadEntry thread_database[] = {
            { "3015ce ", 4 },
            { "3015e ", 4 },
            { "3020e ", 2 },
            { "860k ", 4 },
            { "870k ", 4 },
            { "a10 pro-7350b ", 4 },
            { "a10 pro-7800b ", 4 },
            { "a10 pro-7850b ", 4 },
            { "a10-6700 ", 4 },
            { "a10-6700t ", 4 },
            { "a10-6790b ", 4 },
            { "a10-6790k ", 4 },
            { "a10-6800b ", 4 },
            { "a10-6800k ", 4 },
            { "a10-7300 ", 4 },
            { "a10-7400p ", 4 },
            { "a10-7700k ", 4 },
            { "a10-7800 ", 4 },
            { "a10-7850k ", 4 },
            { "a10-7860k ", 4 },
            { "a10-7870k ", 4 },
            { "a10-8700b ", 4 },
            { "a10-8700p ", 4 },
            { "a10-8750b ", 4 },
            { "a10-8850b ", 4 },
            { "a12-8800b ", 4 },
            { "a4 micro-6400t ", 4 },
            { "a4 pro-3340b ", 4 },
            { "a4 pro-3350b ", 4 },
            { "a4 pro-7300b ", 2 },
            { "a4 pro-7350b ", 2 },
            { "a4-5000 ", 4 },
            { "a4-5100 ", 4 },
            { "a4-6210 ", 4 },
            { "a4-6300 ", 2 },
            { "a4-6320 ", 2 },
            { "a4-7210 ", 4 },
            { "a4-7300 ", 2 },
            { "a4-8350b ", 2 },
            { "a4-9120c ", 2 },
            { "a6 pro-7050b ", 2 },
            { "a6 pro-7400b ", 2 },
            { "a6-5200 ", 4 },
            { "a6-5200m ", 4 },
            { "a6-5350m ", 2 },
            { "a6-6310 ", 4 },
            { "a6-6400b ", 2 },
            { "a6-6400k ", 2 },
            { "a6-6420b ", 2 },
            { "a6-6420k ", 2 },
            { "a6-7000 ", 2 },
            { "a6-7310 ", 4 },
            { "a6-7400k ", 2 },
            { "a6-8500b ", 4 },
            { "a6-8500p ", 2 },
            { "a6-8550b ", 2 },
            { "a6-9220c ", 2 },
            { "a8 pro-7150b ", 4 },
            { "a8 pro-7600b ", 4 },
            { "a8-6410 ", 4 },
            { "a8-6500 ", 4 },
            { "a8-6500b ", 4 },
            { "a8-6500t ", 4 },
            { "a8-6600k ", 4 },
            { "a8-7100 ", 4 },
            { "a8-7200p ", 4 },
            { "a8-7410 ", 4 },
            { "a8-7600 ", 4 },
            { "a8-7650k ", 4 },
            { "a8-7670k ", 4 },
            { "a8-8600b ", 4 },
            { "a8-8600p ", 4 },
            { "a8-8650b ", 4 },
            { "ai 5 340 ", 12 },
            { "ai 5 pro 340 ", 12 },
            { "ai 7 350 ", 16 },
            { "ai 7 pro 350 ", 16 },
            { "ai 7 pro 360 ", 16 },
            { "ai 9 365 ", 20 },
            { "ai 9 hx 370 ", 24 },
            { "ai 9 hx 375 ", 24 },
            { "ai 9 hx pro 370 ", 24 },
            { "ai 9 hx pro 375 ", 24 },
            { "ai max 385 ", 16 },
            { "ai max 390 ", 24 },
            { "ai max pro 380 ", 12 },
            { "ai max pro 385 ", 16 },
            { "ai max pro 390 ", 24 },
            { "ai max+ 395 ", 32 },
            { "ai max+ pro 395 ", 32 },
            { "athlon  silver 3050c ", 2 }, // there's an extra space in the AMD specifications for some reason, which I assume it's a typo. I added the fixed and typo'd version just in case.
            { "athlon silver 3050c ", 2 },
            { "athlon 200ge ", 4 },
            { "athlon 220ge ", 4 },
            { "athlon 240ge ", 4 },
            { "athlon 255e ", 2 },
            { "athlon 3000g ", 4 },
            { "athlon 300ge ", 4 },
            { "athlon 300u ", 4 },
            { "athlon 320ge ", 4 },
            { "athlon 425e ", 3 },
            { "athlon 460 ", 3 },
            { "athlon 5150 ", 4 },
            { "athlon 5350 ", 4 },
            { "athlon 5370 ", 4 },
            { "athlon 620e ", 4 },
            { "athlon 631 ", 4 },
            { "athlon 638 ", 4 },
            { "athlon 641 ", 4 },
            { "athlon 740 ", 4 },
            { "athlon 750k ", 4 },
            { "athlon 760k ", 4 },
            { "athlon 860k ", 4 },
            { "athlon gold 3150c ", 4 },
            { "athlon gold 3150g ", 4 },
            { "athlon gold 3150ge ", 4 },
            { "athlon gold 3150u ", 4 },
            { "athlon gold 7220c ", 4 },
            { "athlon gold 7220u ", 4 },
            { "athlon gold pro 3150g ", 4 },
            { "athlon gold pro 3150ge ", 4 },
            { "athlon pro 200ge ", 4 },
            { "athlon pro 200u ", 4 },
            { "athlon pro 300ge ", 4 },
            { "athlon pro 300u ", 4 },
            { "athlon pro 3045b ", 2 },
            { "athlon pro 3145b ", 4 },
            { "athlon silver 3050e ", 4 },
            { "athlon silver 3050ge ", 4 },
            { "athlon silver 3050u ", 2 },
            { "athlon silver 7120c ", 2 },
            { "athlon silver 7120u ", 2 },
            { "athlon silver pro 3125ge ", 4 },
            { "athlon x4 940 ", 4 },
            { "athlon x4 950 ", 4 },
            { "athlon x4 970 ", 4 },
            { "b57 ", 2 },
            { "b59 ", 2 },
            { "b60 ", 2 },
            { "b75 ", 3 },
            { "b77 ", 3 },
            { "b97 ", 4 },
            { "b99 ", 4 },
            { "e1 micro-6200t ", 2 },
            { "e1-2100 ", 2 },
            { "e1-2200 ", 2 },
            { "e1-2500 ", 2 },
            { "e1-6010 ", 2 },
            { "e1-7010 ", 2 },
            { "e2-3000 ", 2 },
            { "e2-3800 ", 4 },
            { "e2-6110 ", 4 },
            { "e2-7110 ", 4 },
            { "fx 6100 ", 6 },
            { "fx-4100 ", 4 },
            { "fx-4130 ", 4 },
            { "fx-4170 ", 4 },
            { "fx-4300 ", 4 },
            { "fx-4320 ", 4 },
            { "fx-4350 ", 4 },
            { "fx-6200 ", 6 },
            { "fx-6300 ", 6 },
            { "fx-6350 ", 6 },
            { "fx-7500 ", 4 },
            { "fx-7600p ", 4 },
            { "fx-8120 ", 8 },
            { "fx-8150 ", 8 },
            { "fx-8300 ", 8 },
            { "fx-8310 ", 8 },
            { "fx-8320 ", 8 },
            { "fx-8320e ", 8 },
            { "fx-8350 ", 8 },
            { "fx-8370 ", 8 },
            { "fx-8370e ", 8 },
            { "fx-8800p ", 4 },
            { "fx-9370 ", 8 },
            { "fx-9590 ", 8 },
            { "micro-6700t ", 4 },
            { "n640 ", 2 },
            { "n660 ", 2 },
            { "n870 ", 3 },
            { "n960 ", 4 },
            { "n970 ", 4 },
            { "p650 ", 2 },
            { "p860 ", 3 },
            { "phenom ii 1075t ", 6 },
            { "phenom ii 555 ", 2 },
            { "phenom ii 565 ", 2 },
            { "phenom ii 570 ", 2 },
            { "phenom ii 840 ", 4 },
            { "phenom ii 850 ", 4 },
            { "phenom ii 960t ", 4 },
            { "phenom ii 965 ", 4 },
            { "phenom ii 975 ", 4 },
            { "phenom ii 980 ", 4 },
            { "ryzen 3 1200 ", 4 },
            { "ryzen 3 1300x ", 4 },
            { "ryzen 3 210 ", 8 },
            { "ryzen 3 2200g ", 4 },
            { "ryzen 3 2200ge ", 4 },
            { "ryzen 3 2200u ", 4 },
            { "ryzen 3 2300u ", 4 },
            { "ryzen 3 2300x ", 4 },
            { "ryzen 3 3100 ", 8 },
            { "ryzen 3 3200g ", 4 },
            { "ryzen 3 3200ge ", 4 },
            { "ryzen 3 3200u ", 4 },
            { "ryzen 3 3250c ", 4 },
            { "ryzen 3 3250u ", 4 },
            { "ryzen 3 3300u ", 4 },
            { "ryzen 3 3300x ", 8 },
            { "ryzen 3 3350u ", 4 },
            { "ryzen 3 4100 ", 8 },
            { "ryzen 3 4300g ", 8 },
            { "ryzen 3 4300ge ", 8 },
            { "ryzen 3 4300u ", 4 },
            { "ryzen 3 5125c ", 4 },
            { "ryzen 3 5300g ", 8 },
            { "ryzen 3 5300ge ", 8 },
            { "ryzen 3 5300u ", 8 },
            { "ryzen 3 5305g ", 8 },
            { "ryzen 3 5305ge ", 8 },
            { "ryzen 3 5400u ", 8 },
            { "ryzen 3 5425c ", 8 },
            { "ryzen 3 5425u ", 8 },
            { "ryzen 3 7320c ", 8 },
            { "ryzen 3 7320u ", 8 },
            { "ryzen 3 7330u ", 8 },
            { "ryzen 3 7335u ", 8 },
            { "ryzen 3 7440u ", 8 },
            { "ryzen 3 8300g ", 8 },
            { "ryzen 3 8300ge ", 8 },
            { "ryzen 3 8440u ", 8 },
            { "ryzen 3 pro 1200 ", 4 },
            { "ryzen 3 pro 1300 ", 4 },
            { "ryzen 3 pro 210 ", 8 },
            { "ryzen 3 pro 2200g ", 4 },
            { "ryzen 3 pro 2200ge ", 4 },
            { "ryzen 3 pro 2300u ", 4 },
            { "ryzen 3 pro 3200g ", 4 },
            { "ryzen 3 pro 3200ge ", 4 },
            { "ryzen 3 pro 3300u ", 4 },
            { "ryzen 3 pro 4350g ", 8 },
            { "ryzen 3 pro 4350ge ", 8 },
            { "ryzen 3 pro 4355g ", 8 },
            { "ryzen 3 pro 4355ge ", 8 },
            { "ryzen 3 pro 4450u ", 8 },
            { "ryzen 3 pro 5350g ", 8 },
            { "ryzen 3 pro 5350ge ", 8 },
            { "ryzen 3 pro 5355g ", 8 },
            { "ryzen 3 pro 5355ge ", 8 },
            { "ryzen 3 pro 5450u ", 8 },
            { "ryzen 3 pro 5475u ", 8 },
            { "ryzen 3 pro 7330u ", 8 },
            { "ryzen 3 pro 7335u ", 8 },
            { "ryzen 3 pro 8300g ", 8 },
            { "ryzen 3 pro 8300ge ", 8 },
            { "ryzen 5 1400 ", 8 },
            { "ryzen 5 1500x ", 8 },
            { "ryzen 5 1600 ", 12 },
            { "ryzen 5 1600 (af )", 12 },
            { "ryzen 5 1600x ", 12 },
            { "ryzen 5 220 ", 12 },
            { "ryzen 5 230 ", 12 },
            { "ryzen 5 240 ", 12 },
            { "ryzen 5 2400g ", 8 },
            { "ryzen 5 2400ge ", 8 },
            { "ryzen 5 2500u ", 8 },
            { "ryzen 5 2500x ", 8 },
            { "ryzen 5 2600 ", 12 },
            { "ryzen 5 2600e ", 12 },
            { "ryzen 5 2600h ", 8 },
            { "ryzen 5 2600x ", 12 },
            { "ryzen 5 3400g ", 8 },
            { "ryzen 5 3400ge ", 8 },
            { "ryzen 5 3450u ", 8 },
            { "ryzen 5 3500 ", 6 },
            { "ryzen 5 3500c ", 8 },
            { "ryzen 5 3500u ", 8 },
            { "ryzen 5 3550h ", 8 },
            { "ryzen 5 3580u ", 8 },
            { "ryzen 5 3600 ", 12 },
            { "ryzen 5 3600x ", 12 },
            { "ryzen 5 3600xt ", 12 },
            { "ryzen 5 4500 ", 12 },
            { "ryzen 5 4500u ", 6 },
            { "ryzen 5 4600g ", 12 },
            { "ryzen 5 4600ge ", 12 },
            { "ryzen 5 4600h ", 12 },
            { "ryzen 5 4600u ", 12 },
            { "ryzen 5 4680u ", 12 },
            { "ryzen 5 5500 ", 12 },
            { "ryzen 5 5500gt ", 12 },
            { "ryzen 5 5500h ", 8 },
            { "ryzen 5 5500u ", 12 },
            { "ryzen 5 5560u ", 12 },
            { "ryzen 5 5600 ", 12 },
            { "ryzen 5 5600g ", 12 },
            { "ryzen 5 5600ge ", 12 },
            { "ryzen 5 5600gt ", 12 },
            { "ryzen 5 5600h ", 12 },
            { "ryzen 5 5600hs ", 12 },
            { "ryzen 5 5600t ", 12 },
            { "ryzen 5 5600u ", 12 },
            { "ryzen 5 5600x ", 12 },
            { "ryzen 5 5600x3d ", 12 },
            { "ryzen 5 5600xt ", 12 },
            { "ryzen 5 5605g ", 12 },
            { "ryzen 5 5605ge ", 12 },
            { "ryzen 5 5625c ", 12 },
            { "ryzen 5 5625u ", 12 },
            { "ryzen 5 6600h ", 12 },
            { "ryzen 5 6600hs ", 12 },
            { "ryzen 5 6600u ", 12 },
            { "ryzen 5 7235hs ", 8 },
            { "ryzen 5 7400f ", 12 },
            { "ryzen 5 7430u ", 12 },
            { "ryzen 5 7500f ", 12 },
            { "ryzen 5 7520c ", 8 },
            { "ryzen 5 7520u ", 8 },
            { "ryzen 5 7530u ", 12 },
            { "ryzen 5 7535hs ", 12 },
            { "ryzen 5 7535u ", 12 },
            { "ryzen 5 7540u ", 12 },
            { "ryzen 5 7545u ", 12 },
            { "ryzen 5 7600 ", 12 },
            { "ryzen 5 7600x ", 12 },
            { "ryzen 5 7600x3d ", 12 },
            { "ryzen 5 7640hs ", 12 },
            { "ryzen 5 7640u ", 12 },
            { "ryzen 5 7645hx ", 12 },
            { "ryzen 5 8400f ", 12 },
            { "ryzen 5 8500g ", 12 },
            { "ryzen 5 8500ge ", 12 },
            { "ryzen 5 8540u ", 12 },
            { "ryzen 5 8600g ", 12 },
            { "ryzen 5 8640hs ", 12 },
            { "ryzen 5 8640u ", 12 },
            { "ryzen 5 8645hs ", 12 },
            { "ryzen 5 9600 ", 12 },
            { "ryzen 5 9600x ", 12 },
            { "ryzen 5 pro 1500 ", 8 },
            { "ryzen 5 pro 1600 ", 12 },
            { "ryzen 5 pro 220 ", 12 },
            { "ryzen 5 pro 230 ", 12 },
            { "ryzen 5 pro 2400g ", 8 },
            { "ryzen 5 pro 2400ge ", 8 },
            { "ryzen 5 pro 2500u ", 8 },
            { "ryzen 5 pro 2600 ", 12 },
            { "ryzen 5 pro 3350g ", 8 },
            { "ryzen 5 pro 3350ge ", 4 },
            { "ryzen 5 pro 3400g ", 8 },
            { "ryzen 5 pro 3400ge ", 8 },
            { "ryzen 5 pro 3500u ", 8 },
            { "ryzen 5 pro 3600 ", 12 },
            { "ryzen 5 pro 4650g ", 12 },
            { "ryzen 5 pro 4650ge ", 12 },
            { "ryzen 5 pro 4650u ", 12 },
            { "ryzen 5 pro 4655g ", 12 },
            { "ryzen 5 pro 4655ge ", 12 },
            { "ryzen 5 pro 5645 ", 12 },
            { "ryzen 5 pro 5650g ", 12 },
            { "ryzen 5 pro 5650ge ", 12 },
            { "ryzen 5 pro 5650u ", 12 },
            { "ryzen 5 pro 5655g ", 12 },
            { "ryzen 5 pro 5655ge ", 12 },
            { "ryzen 5 pro 5675u ", 12 },
            { "ryzen 5 pro 6650h ", 12 },
            { "ryzen 5 pro 6650hs ", 12 },
            { "ryzen 5 pro 6650u ", 12 },
            { "ryzen 5 pro 7530u ", 12 },
            { "ryzen 5 pro 7535u ", 12 },
            { "ryzen 5 pro 7540u ", 12 },
            { "ryzen 5 pro 7545u ", 12 },
            { "ryzen 5 pro 7640hs ", 12 },
            { "ryzen 5 pro 7640u ", 12 },
            { "ryzen 5 pro 7645 ", 12 },
            { "ryzen 5 pro 8500g ", 12 },
            { "ryzen 5 pro 8500ge ", 12 },
            { "ryzen 5 pro 8540u ", 12 },
            { "ryzen 5 pro 8600g ", 12 },
            { "ryzen 5 pro 8600ge ", 12 },
            { "ryzen 5 pro 8640hs ", 12 },
            { "ryzen 5 pro 8640u ", 12 },
            { "ryzen 5 pro 8645hs ", 12 },
            { "ryzen 7 1700 ", 16 },
            { "ryzen 7 1700x ", 16 },
            { "ryzen 7 1800x ", 16 },
            { "ryzen 7 250 ", 16 },
            { "ryzen 7 260 ", 16 },
            { "ryzen 7 2700 ", 16 },
            { "ryzen 7 2700e ", 16 },
            { "ryzen 7 2700u ", 8 },
            { "ryzen 7 2700x ", 16 },
            { "ryzen 7 2800h ", 8 },
            { "ryzen 7 3700c ", 8 },
            { "ryzen 7 3700u ", 8 },
            { "ryzen 7 3700x ", 16 },
            { "ryzen 7 3750h ", 8 },
            { "ryzen 7 3780u ", 8 },
            { "ryzen 7 3800x ", 16 },
            { "ryzen 7 3800xt ", 16 },
            { "ryzen 7 4700g ", 16 },
            { "ryzen 7 4700ge ", 16 },
            { "ryzen 7 4700u ", 8 },
            { "ryzen 7 4800h ", 16 },
            { "ryzen 7 4800hs ", 16 },
            { "ryzen 7 4800u ", 16 },
            { "ryzen 7 4980u ", 16 },
            { "ryzen 7 5700 ", 16 },
            { "ryzen 7 5700g ", 16 },
            { "ryzen 7 5700ge ", 16 },
            { "ryzen 7 5700u ", 16 },
            { "ryzen 7 5700x ", 16 },
            { "ryzen 7 5700x3d ", 16 },
            { "ryzen 7 5705g ", 16 },
            { "ryzen 7 5705ge ", 16 },
            { "ryzen 7 5800 ", 16 },
            { "ryzen 7 5800h ", 16 },
            { "ryzen 7 5800hs ", 16 },
            { "ryzen 7 5800u ", 16 },
            { "ryzen 7 5800x ", 16 },
            { "ryzen 7 5800x3d ", 16 },
            { "ryzen 7 5800xt ", 16 },
            { "ryzen 7 5825c ", 16 },
            { "ryzen 7 5825u ", 16 },
            { "ryzen 7 6800h ", 16 },
            { "ryzen 7 6800hs ", 16 },
            { "ryzen 7 6800u ", 16 },
            { "ryzen 7 7435hs ", 16 },
            { "ryzen 7 7700 ", 16 },
            { "ryzen 7 7700x ", 16 },
            { "ryzen 7 7730u ", 16 },
            { "ryzen 7 7735hs ", 16 },
            { "ryzen 7 7735u ", 16 },
            { "ryzen 7 7736u ", 16 },
            { "ryzen 7 7745hx ", 16 },
            { "ryzen 7 7800x3d ", 16 },
            { "ryzen 7 7840hs ", 16 },
            { "ryzen 7 7840hx ", 24 },
            { "ryzen 7 7840u ", 16 },
            { "ryzen 7 8700f ", 16 },
            { "ryzen 7 8700g ", 16 },
            { "ryzen 7 8840hs ", 16 },
            { "ryzen 7 8840u ", 16 },
            { "ryzen 7 8845hs ", 16 },
            { "ryzen 7 9700x ", 16 },
            { "ryzen 7 9800x3d ", 16 },
            { "ryzen 7 pro 1700 ", 16 },
            { "ryzen 7 pro 1700x ", 16 },
            { "ryzen 7 pro 250 ", 16 },
            { "ryzen 7 pro 2700 ", 16 },
            { "ryzen 7 pro 2700u ", 8 },
            { "ryzen 7 pro 2700x ", 16 },
            { "ryzen 7 pro 3700 ", 16 },
            { "ryzen 7 pro 3700u ", 8 },
            { "ryzen 7 pro 4750g ", 16 },
            { "ryzen 7 pro 4750ge ", 16 },
            { "ryzen 7 pro 4750u ", 16 },
            { "ryzen 7 pro 5750g ", 16 },
            { "ryzen 7 pro 5750ge ", 16 },
            { "ryzen 7 pro 5755g ", 16 },
            { "ryzen 7 pro 5755ge ", 16 },
            { "ryzen 7 pro 5845 ", 16 },
            { "ryzen 7 pro 5850u ", 16 },
            { "ryzen 7 pro 5875u ", 16 },
            { "ryzen 7 pro 6850h ", 16 },
            { "ryzen 7 pro 6850hs ", 16 },
            { "ryzen 7 pro 6850u ", 16 },
            { "ryzen 7 pro 6860z ", 16 },
            { "ryzen 7 pro 7730u ", 16 },
            { "ryzen 7 pro 7735u ", 16 },
            { "ryzen 7 pro 7745 ", 16 },
            { "ryzen 7 pro 7840hs ", 16 },
            { "ryzen 7 pro 7840u ", 16 },
            { "ryzen 7 pro 8700g ", 16 },
            { "ryzen 7 pro 8700ge ", 16 },
            { "ryzen 7 pro 8840hs ", 16 },
            { "ryzen 7 pro 8840u ", 16 },
            { "ryzen 7 pro 8845hs ", 16 },
            { "ryzen 9 270 ", 16 },
            { "ryzen 9 3900 processor ", 24 },
            { "ryzen 9 3900x ", 24 },
            { "ryzen 9 3900xt ", 24 },
            { "ryzen 9 3950x ", 32 },
            { "ryzen 9 4900h ", 16 },
            { "ryzen 9 4900hs ", 16 },
            { "ryzen 9 5900 ", 24 },
            { "ryzen 9 5900hs ", 16 },
            { "ryzen 9 5900hx ", 16 },
            { "ryzen 9 5900x ", 24 },
            { "ryzen 9 5900xt ", 32 },
            { "ryzen 9 5950x ", 32 },
            { "ryzen 9 5980hs ", 16 },
            { "ryzen 9 5980hx ", 16 },
            { "ryzen 9 6900hs ", 16 },
            { "ryzen 9 6900hx ", 16 },
            { "ryzen 9 6980hs ", 16 },
            { "ryzen 9 6980hx ", 16 },
            { "ryzen 9 7845hx ", 24 },
            { "ryzen 9 7900 ", 24 },
            { "ryzen 9 7900x ", 24 },
            { "ryzen 9 7900x3d ", 24 },
            { "ryzen 9 7940hs ", 16 },
            { "ryzen 9 7940hx ", 32 },
            { "ryzen 9 7945hx ", 32 },
            { "ryzen 9 7945hx3d ", 32 },
            { "ryzen 9 7950x ", 32 },
            { "ryzen 9 7950x3d ", 32 },
            { "ryzen 9 8945hs ", 16 },
            { "ryzen 9 9850hx ", 24 },
            { "ryzen 9 9900x ", 24 },
            { "ryzen 9 9900x3d ", 24 },
            { "ryzen 9 9950x ", 32 },
            { "ryzen 9 9950x3d ", 32 },
            { "ryzen 9 9955hx ", 32 },
            { "ryzen 9 9955hx3d ", 32 },
            { "ryzen 9 pro 3900 ", 24 },
            { "ryzen 9 pro 5945 ", 24 },
            { "ryzen 9 pro 6950h ", 16 },
            { "ryzen 9 pro 6950hs ", 16 },
            { "ryzen 9 pro 7940hs ", 16 },
            { "ryzen 9 pro 7945 ", 24 },
            { "ryzen 9 pro 8945hs ", 16 },
            { "ryzen threadripper 1900x ", 16 },
            { "ryzen threadripper 1920x ", 24 },
            { "ryzen threadripper 1950x ", 32 },
            { "ryzen threadripper 2920x ", 24 },
            { "ryzen threadripper 2950x ", 32 },
            { "ryzen threadripper 2970wx ", 48 },
            { "ryzen threadripper 2990wx ", 64 },
            { "ryzen threadripper 3960x ", 48 },
            { "ryzen threadripper 3970x ", 64 },
            { "ryzen threadripper 3990x ", 128 },
            { "ryzen threadripper 7960x ", 48 },
            { "ryzen threadripper 7970x ", 64 },
            { "ryzen threadripper 7980x ", 128 },
            { "ryzen threadripper pro 3945wx ", 24 },
            { "ryzen threadripper pro 3955wx ", 32 },
            { "ryzen threadripper pro 3975wx ", 64 },
            { "ryzen threadripper pro 3995wx ", 128 },
            { "ryzen threadripper pro 5945wx ", 24 },
            { "ryzen threadripper pro 5955wx ", 32 },
            { "ryzen threadripper pro 5965wx ", 48 },
            { "ryzen threadripper pro 5975wx ", 64 },
            { "ryzen threadripper pro 5995wx ", 128 },
            { "ryzen threadripper pro 7945wx ", 24 },
            { "ryzen threadripper pro 7955wx ", 32 },
            { "ryzen threadripper pro 7965wx ", 48 },
            { "ryzen threadripper pro 7975wx ", 64 },
            { "ryzen threadripper pro 7985wx ", 128 },
            { "ryzen threadripper pro 7995wx ", 192 },
            { "ryzen z1 extreme ", 16 },
            { "ryzen z1 ", 12 },
            { "sempron 2650 ", 2 },
            { "sempron 3850 ", 4 },
            { "x940 ", 4 },
            { "z2 extreme ", 16 },
            { "z2 go ", 8 }
        };

        constexpr size_t thread_database_count = sizeof(thread_database) / sizeof(thread_database[0]);
        const std::string cpu_full_name = model.c_str();

        for (size_t i = 0; i < thread_database_count; ++i) {
            if (cpu_full_name.find(thread_database[i].model) != std::string::npos) {
                const unsigned expected = thread_database[i].threads;
                const unsigned actual = (unsigned)std::thread::hardware_concurrency();
                debug("AMD_THREAD_MISMATCH Expected threads -> ", expected);
                debug("AMD_THREAD_MISMATCH Current threads -> ", actual);
                return (actual != expected);
            }
        }

        return false;
#endif
    }


    /**
     * @brief Check for cuckoo directory using crt and WIN API directory functions
     * @category Windows
     * @author 一半人生
     * @link https://unprotect.it/snippet/checking-specific-folder-name/196/
     * @implements VM::CUCKOO_DIR
     */
    [[nodiscard]] static bool cuckoo_dir() {
#if (!WINDOWS)
        return false;
#else
        const DWORD attrs = GetFileAttributes(_T("C:\\Cuckoo"));

        if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
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
     * @implements VM::CUCKOO_PIPE
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
     * @brief Check for default Azure hostname format (Azure uses Hyper-V as their base VM brand)
     * @category Windows, Linux
     * @implements VM::HYPERV_HOSTNAME
     */
    [[nodiscard]] static bool hyperv_hostname() {
#if (!(WINDOWS || LINUX))
        return false;
#else
        const std::string hostname = util::get_hostname();
        const size_t len = hostname.size();

        // most Hyper-V hostnames under Azure have the hostname format of fv-azXXX-XXX where the X is a digit
        if (len < 8)
            return false;

        if (!(hostname.rfind("fv-az", 0) == 0))
            return false;

        const size_t hyphen_pos = hostname.find('-', 5);
        if (hyphen_pos == std::string::npos ||
            hyphen_pos <= 5 ||
            hyphen_pos >= len - 1)
        {
            return false;
        }

        for (size_t i = 5; i < hyphen_pos; ++i) {
            if (!isdigit(static_cast<unsigned char>(hostname[i])))
                return false;
        }

        for (size_t i = hyphen_pos + 1; i < len; ++i) {
            if (!isdigit(static_cast<unsigned char>(hostname[i])))
                return false;
        }

        return core::add(brands::AZURE_HYPERV);
#endif
    }


    /**
     * @brief Check for commonly set hostnames by certain VM brands
     * @category Windows, Linux
     * @note Idea from Thomas Roccia (fr0gger)
     * @link https://unprotect.it/technique/detecting-hostname-username/
     * @implements VM::GENERAL_HOSTNAME
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
     * @brief Check for display configurations related to VMs
     * @category Windows
     * @note Idea of checking screen resolution from Thomas Roccia (fr0gger)
     * @link https://unprotect.it/technique/checking-screen-resolution/
     * @implements VM::DISPLAY
     */
    [[nodiscard]] static bool display() {
#if (!WINDOWS)
        return false;
#else
        const HDC hdc = GetDC(nullptr);
        const int bpp = GetDeviceCaps(hdc, BITSPIXEL) *
            GetDeviceCaps(hdc, PLANES);
        const int logpix = GetDeviceCaps(hdc, LOGPIXELSX);
        ReleaseDC(nullptr, hdc);

        // physical monitors are almost always 32bpp and 96–144 DPI
        if (bpp != 32 || logpix < 90 || logpix > 200)
            return true;

        UINT32 pathCount = 0, modeCount = 0;
        if (QueryDisplayConfig(QDC_ONLY_ACTIVE_PATHS,
            &pathCount, nullptr,
            &modeCount, nullptr,
            nullptr) != ERROR_SUCCESS)
            return false;

        if ((pathCount <= 1) || (pathCount != modeCount)) {
            debug("DISPLAY: Path count: ", pathCount);
            debug("DISPLAY: Mode count: ", modeCount);
            return true;
        }

        RECT desktop;
        const HWND hDesktop = GetDesktopWindow();
        if (!GetWindowRect(hDesktop, &desktop)) {
            return false;
        }

        const i16 horiz = static_cast<i16>(desktop.right);
        const i16 verti = static_cast<i16>(desktop.bottom);

        debug("DISPLAY: horizontal = ", horiz, ", vertical = ", verti);

        return (horiz == 1024 && verti == 768) ||
            (horiz == 800 && verti == 600) ||
            (horiz == 640 && verti == 480);
#endif
    }


    /**
     * @brief Check if bogus device string would be accepted
     * @category Windows
     * @author Huntress Research Team
     * @link https://unprotect.it/technique/buildcommdcbandtimeouta/
     * @implements VM::DEVICE_STRING
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
            return false;
        }
#endif
    }


    /**
     * @brief Check for the presence of BlueStacks-specific folders
     * @category ARM, Linux
     * @implements VM::BLUESTACKS_FOLDERS
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
     * @implements VM::CPUID_SIGNATURE
     */
    [[nodiscard]] static bool cpuid_signature() {
#if (!x86)
        return false;
#else
        u32 eax, unused = 0;
        cpu::cpuid(eax, unused, unused, unused, 0x40000001);
        UNUSED(unused);

        constexpr u32 nanovisor = 0x766E6258; // "Xbnv" 
        constexpr u32 simplevisor = 0x00766853; // " vhS"

        debug("CPUID_SIGNATURE: eax = ", eax);

        if (eax == nanovisor) 
            return core::add(brands::NANOVISOR);
        else if (eax == simplevisor)
            return core::add(brands::SIMPLEVISOR);

        return false;
#endif
    }


    /**
     * @brief Check for Intel KGT (Trusty branch) hypervisor signature in CPUID
     * @link https://github.com/intel/ikgt-core/blob/7dfd4d1614d788ec43b02602cce7a272ef8d5931/vmm/vmexit/vmexit_cpuid.c
     * @category x86
     * @implements VM::KGT_SIGNATURE
     */
    [[nodiscard]] static bool intel_kgt_signature() {
#if (!x86)
        return false;
#else
        u32 unused, ecx, edx = 0;
        cpu::cpuid(unused, unused, ecx, edx, 0x40000003);
     
        constexpr u32 ECX_SIG = 0x4D4D5645u; // 'EVMM' → 0x4D4D5645
        constexpr u32 EDX_SIG = 0x43544E49u;  // 'INTC' → 0x43544E49

        if (ecx == ECX_SIG && edx == EDX_SIG) {
            return core::add(brands::INTEL_KGT);
        }

        return false;
#endif
    }


    /**
     * @brief Check for presence of QEMU in the /sys/devices/virtual/dmi/id directory
     * @category Linux
     * @implements VM::QEMU_VIRTUAL_DMI
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

            if (
                util::find(sys_vendor_str, "QEMU") &&
                util::find(modalias_str, "QEMU")
            ) {
                return core::add(brands::QEMU);
            }
        }

        return false;
#endif
    } 


    /**
     * @brief Check for presence of QEMU in the /sys/kernel/debug/usb/devices directory
     * @category Linux
     * @implements VM::QEMU_USB
     */
    [[nodiscard]] static bool qemu_USB() {
#if (!LINUX)
        return false;
#else
        if (!util::is_admin()) {
            return false;
        }

        constexpr const char* usb_path = "/sys/kernel/debug/usb/devices";

        std::ifstream file(usb_path);
        if (!file) {
            return false;
        }

        std::string line;
        while (std::getline(file, line)) {
            if (line.find("QEMU") != std::string::npos) {
                return true;
            }
        }

        return false;
#endif
    }


    /**
     * @brief Check for presence of any files in /sys/hypervisor directory
     * @category Linux
     * @implements VM::HYPERVISOR_DIR
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
     * @implements VM::UML_CPU
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
     * @implements VM::KMSG
     */
    [[nodiscard]] static bool kmsg() {
#if (!LINUX)
        return false;
#else
        if (!util::is_admin()) {
            return false;
        }

        int fd = open("/dev/kmsg", O_RDONLY | O_NONBLOCK);
        if (fd < 0) {
            debug("KMSG: Failed to open /dev/kmsg");
            return false;
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
                    usleep(100000);
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
     * @brief Check for a VBox kernel module
     * @note idea from https://github.com/ShellCode33/VM-Detection/blob/master/vmdetect/linux.go
     * @category Linux
     * @implements VM::VBOX_MODULE
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
     * @implements VM::SYSINFO_PROC
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
     * @brief Check for string matches of VM brands in the linux DMI
     * @category Linux
     * @implements VM::DMI_SCAN
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
                    if (strcmp(vm_string.second, brands::AWS_NITRO) == 0) {
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
     * @implements VM::SMBIOS_VM_BIT
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
     * @implements VM::PODMAN_FILE
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
     * @implements VM::WSL_PROC
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
     * @brief Check for VM-specific names for drivers
     * @category Windows
     * @author Requiem (https://github.com/NotRequiem)
     * @implements VM::DRIVERS
     */
    [[nodiscard]] static bool drivers() {
#if (!WINDOWS)
        return false;
#else
        typedef struct _SYSTEM_MODULE_INFORMATION {
            PVOID  Reserved[2];
            PVOID  ImageBaseAddress;
            ULONG  ImageSize;
            ULONG  Flags;
            USHORT Index;
            USHORT NameLength;
            USHORT LoadCount;
            USHORT PathLength;
            CHAR   ImageName[256];
        } SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

        typedef struct _SYSTEM_MODULE_INFORMATION_EX {
            ULONG  NumberOfModules;
            SYSTEM_MODULE_INFORMATION Module[1];
        } SYSTEM_MODULE_INFORMATION_EX, * PSYSTEM_MODULE_INFORMATION_EX;

        typedef NTSTATUS(__stdcall* NtQuerySystemInformationFn)(
            ULONG SystemInformationClass,
            PVOID SystemInformation,
            ULONG SystemInformationLength,
            PULONG ReturnLength
            );

        typedef NTSTATUS(__stdcall* NtAllocateVirtualMemoryFn)(
            HANDLE ProcessHandle,
            PVOID* BaseAddress,
            ULONG_PTR ZeroBits,
            PSIZE_T RegionSize,
            ULONG AllocationType,
            ULONG Protect
            );

        typedef NTSTATUS(__stdcall* NtFreeVirtualMemoryFn)(
            HANDLE ProcessHandle,
            PVOID* BaseAddress,
            PSIZE_T RegionSize,
            ULONG FreeType
            );

        constexpr ULONG SystemModuleInformation = 11;
        const HMODULE hModule = GetModuleHandle(_T("ntdll.dll"));
        if (!hModule) return false;

        const char* functionNames[] = { "NtQuerySystemInformation", "NtAllocateVirtualMemory", "NtFreeVirtualMemory" };
        void* functionPointers[3] = { nullptr, nullptr, nullptr };

        util::GetFunctionAddresses(hModule, functionNames, functionPointers, 3);

        const auto ntQuerySystemInformation = reinterpret_cast<NtQuerySystemInformationFn>(functionPointers[0]);
        const auto ntAllocateVirtualMemory = reinterpret_cast<NtAllocateVirtualMemoryFn>(functionPointers[1]);
        const auto ntFreeVirtualMemory = reinterpret_cast<NtFreeVirtualMemoryFn>(functionPointers[2]);

        if (ntQuerySystemInformation == nullptr || ntAllocateVirtualMemory == nullptr || ntFreeVirtualMemory == nullptr)
            return false;
        
        ULONG ulSize = 0;
        NTSTATUS status = ntQuerySystemInformation(SystemModuleInformation, nullptr, 0, &ulSize);
        if (status != ((NTSTATUS)0xC0000004L)) return false;

        const HANDLE hProcess = GetCurrentProcess();
        PVOID allocatedMemory = nullptr;
        SIZE_T regionSize = ulSize;
        ntAllocateVirtualMemory(hProcess, &allocatedMemory, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        auto pSystemModuleInfoEx = reinterpret_cast<PSYSTEM_MODULE_INFORMATION_EX>(allocatedMemory);
        status = ntQuerySystemInformation(SystemModuleInformation, pSystemModuleInfoEx, ulSize, &ulSize);
        if (!(((NTSTATUS)(status)) >= 0)) {
            ntFreeVirtualMemory(hProcess, &allocatedMemory, &regionSize, MEM_RELEASE);
            return false;
        }

        for (ULONG i = 0; i < pSystemModuleInfoEx->NumberOfModules; ++i) {
            const char* driverPath = reinterpret_cast<const char*>(pSystemModuleInfoEx->Module[i].ImageName);
            if (
                strstr(driverPath, "VBoxGuest") ||
                strstr(driverPath, "VBoxMouse") ||
                strstr(driverPath, "VBoxSF")
                ) {
                debug("DRIVERS: Detected VBox driver: ", driverPath);
                ntFreeVirtualMemory(hProcess, &allocatedMemory, &regionSize, MEM_RELEASE);
                return core::add(brands::VBOX);
            }

            if (
                strstr(driverPath, "vmusbmouse") ||
                strstr(driverPath, "vmmouse") ||
                strstr(driverPath, "vmmemctl")
                ) {
                debug("DRIVERS: Detected VMware driver: ", driverPath);
                ntFreeVirtualMemory(hProcess, &allocatedMemory, &regionSize, MEM_RELEASE);
                return core::add(brands::VMWARE);
            }
        }

        ntFreeVirtualMemory(hProcess, &allocatedMemory, &regionSize, MEM_RELEASE);
        return false;
#endif
    }


    /**
     * @brief Check for serial numbers of virtual disks
     * @category Windows
     * @author Requiem (https://github.com/NotRequiem)
     * @note VMware can't be flagged without also flagging legitimate disks
     * @implements VM::DISK_SERIAL
     */
    [[nodiscard]] static bool disk_serial_number() {
#if (!WINDOWS)
        return false;
#else
        bool result = false;
        constexpr u8 MAX_PHYSICAL_DRIVES = 4;

        auto is_vbox_serial = [](const char* str, u8 len) -> bool {
            if (len != 19)
                return false;
            if ((str[0] != 'V' && str[0] != 'v') ||
                (str[1] != 'B' && str[1] != 'b'))
                return false;

            auto is_hex = [](char c) {
                return (c >= '0' && c <= '9') ||
                    (c >= 'A' && c <= 'F') ||
                    (c >= 'a' && c <= 'f');
            };

            static constexpr std::array<u8, 16> hex_positions = { {
                2, 3, 4, 5, 6, 7, 8, 9,
                11,12,13,14,15,16,17,18
            } };

            for (u8 idx : hex_positions) {
                if (!is_hex(str[idx]))
                    return false;
            }

            return str[10] == '-';
        };

        auto is_qemu_serial = [](const char* str, u8 len) -> bool {
            constexpr const char* prefix = "QM0000";
            constexpr size_t prefix_len = 6;
            if (len < prefix_len)
                return false;
            for (size_t i = 0; i < prefix_len; ++i) {
                if (str[i] != prefix[i])
                    return false;
            }
            return true;
        };

        for (u8 drive = 0; drive < MAX_PHYSICAL_DRIVES; drive++) {
            wchar_t path[32];
            swprintf_s(path, L"\\\\.\\PhysicalDrive%u", drive);

            const HANDLE hDevice = CreateFileW(path, 0,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                OPEN_EXISTING, 0, nullptr);

            if (hDevice == INVALID_HANDLE_VALUE) continue;

            STORAGE_PROPERTY_QUERY query{};
            query.PropertyId = StorageDeviceProperty;
            query.QueryType = PropertyStandardQuery;

            STORAGE_DESCRIPTOR_HEADER header{};
            DWORD bytesReturned = 0;

            if (!DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY,
                &query, sizeof(query), &header, sizeof(header),
                &bytesReturned, nullptr) || header.Size == 0) {
                CloseHandle(hDevice);
                continue;
            }

            BYTE stackBuf[512] = { 0 };
            BYTE* buffer = nullptr;

            if (header.Size <= sizeof(stackBuf)) {
                buffer = stackBuf;
            }
            else {
                buffer = static_cast<BYTE*>(LocalAlloc(LMEM_FIXED, header.Size));
                if (buffer == nullptr) {
                    CloseHandle(hDevice);
                    continue;
                }
            }

            if (!DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY,
                &query, sizeof(query), buffer, header.Size,
                &bytesReturned, nullptr)) {
                if (buffer != stackBuf) LocalFree(buffer);
                CloseHandle(hDevice);
                continue;
            }

            auto descriptor = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(buffer);
            const u32 serialOffset = descriptor->SerialNumberOffset;

            if (serialOffset > 0 && serialOffset < header.Size) {
                const char* serial =
                    reinterpret_cast<const char*>(buffer + serialOffset);

                const size_t maxAvail = header.Size - static_cast<size_t>(serialOffset);
                const size_t serialLen = strnlen(serial, maxAvail);

                constexpr size_t BUF_SZ = 256;
                char upperSerial[BUF_SZ] = { 0 };

                size_t copyLen = (serialLen < BUF_SZ - 1) ? serialLen : BUF_SZ - 1;

                for (size_t i = 0; i < copyLen; ++i) {
                    char c = serial[i];
                    upperSerial[i] = (c >= 'a' && c <= 'z') ? char(c - 32) : c;
                }
                upperSerial[copyLen] = '\0';

                if (is_qemu_serial(upperSerial, static_cast<u8>(copyLen))) {
                    debug("DISK_SERIAL: Detected QEMU");
                    result = core::add(brands::QEMU);
                    if (buffer != stackBuf) LocalFree(buffer);
                    CloseHandle(hDevice);
                    return result;
                }

                if (is_vbox_serial(upperSerial, static_cast<u8>(copyLen))) {
                    debug("DISK_SERIAL: Detected VBOX");
                    result = core::add(brands::VBOX);
                    if (buffer != stackBuf) LocalFree(buffer);
                    CloseHandle(hDevice);
                    return result;
                }
            }

            if (buffer != stackBuf) LocalFree(buffer);
            CloseHandle(hDevice);
        }

        return result;
#endif
    }


    /**
     * @brief Check for physical connection ports
     * @category Windows
     * @note original idea of using physical ports to detect VMs was suggested by @unusual-aspect (https://github.com/unusual-aspect)
     *       This technique is known to flag on devices like Surface Pro
     * @implements VM::PORT_CONNECTORS
     */
    [[nodiscard]] static bool port_connectors() {
#if (!WINDOWS)
        return false;
#else
        const GUID GUID_DEVCLASS_PORTCONNECTOR =
        { 0x4d36e978, 0xe325, 0x11ce, {0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18} };

        const HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_PORTCONNECTOR,
            nullptr, nullptr, DIGCF_PRESENT);
        if (hDevInfo == INVALID_HANDLE_VALUE) {
            return true;
        }

        SP_DEVINFO_DATA devInfoData = { sizeof(SP_DEVINFO_DATA) };
        // check first device only is sufficient to determine if ANY ports exist, physical machines typically have multiple
        const bool hasPorts = SetupDiEnumDeviceInfo(hDevInfo, 0, &devInfoData);

        SetupDiDestroyDeviceInfoList(hDevInfo);
        return !hasPorts;
#endif
    }


    /**
     * @brief Check for IVSHMEM device absense
     * @category Windows
     * @author dmfrpro (https://github.com/dmfrpro)
     * @implements VM::IVSHMEM
     */
    [[nodiscard]] static bool ivshmem() {
#if (!WINDOWS)
        return false;
#else
        constexpr GUID GUID_IVSHMEM_IFACE =
        { 0xdf576976, 0x569d, 0x4672, {0x95, 0xa0, 0xf5, 0x7e, 0x4e, 0xa0, 0xb2, 0x10} };

        const HDEVINFO hDevInfo = SetupDiGetClassDevs(
            &GUID_IVSHMEM_IFACE,
            nullptr,
            nullptr,
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE
        );
        if (hDevInfo == INVALID_HANDLE_VALUE) {
            return false;
        }

        SP_DEVICE_INTERFACE_DATA ifaceData = { 0 };
        ifaceData.cbSize = sizeof(ifaceData);
        const bool gotOne = SetupDiEnumDeviceInterfaces(
            hDevInfo,
            nullptr,
            &GUID_IVSHMEM_IFACE,
            0,
            &ifaceData
        );

        SetupDiDestroyDeviceInfoList(hDevInfo);

        if (gotOne) {
            core::add(brands::HYPERVISOR_PHANTOM);
            return true;
        }
        return false;
#endif
    }


    /**
     * @brief Check for specific GPU string signatures related to VMs
     * @category Windows
     * @author Requiem (https://github.com/NotRequiem)
     * @author dmfrpro (https://github.com/dmfrpro) (VDD detection)
     * @note utoshu did this with WMI in a removed technique (VM::GPU_CHIPTYPE)
     * @implements VM::GPU_VM_STRING
     */
    [[nodiscard]] static bool gpu_vm_strings() {
#if (!WINDOWS)
        return false;
#else

#if (CPP >= 17)
        struct VMGpuInfo {
            std::wstring_view name_substring;
            const char* brand;
        };

        static constexpr std::array<VMGpuInfo, 10> vm_gpu_names = { {
            { L"VMware SVGA 3D",                        brands::VMWARE     },
            { L"VirtualBox Graphics Adapter",           brands::VBOX       },
            { L"QXL GPU",                               brands::KVM        },
            { L"VirGL 3D",                              brands::QEMU       },
            { L"Microsoft Hyper-V Video",               brands::HYPERV     },
            { L"Parallels Display Adapter (WDDM)",      brands::PARALLELS  },
            { L"Bochs Graphics Adapter",                brands::BOCHS      },
            { L"IddSampleDriver Device",                brands::NULL_BRAND },
            { L"Remote Display Adapter",                brands::NULL_BRAND },
            { L"RDPDD Chained DD",                      brands::NULL_BRAND }
        } };
#else
        struct VMGpuInfo {
            const wchar_t* name_substring;
            const char* brand;
        };

        static const VMGpuInfo vm_gpu_names[10] = {
            { L"VMware SVGA 3D",                        brands::VMWARE     },
            { L"VirtualBox Graphics Adapter",           brands::VBOX       },
            { L"QXL GPU",                               brands::KVM        },
            { L"VirGL 3D",                              brands::QEMU       },
            { L"Microsoft Hyper-V Video",               brands::HYPERV     },
            { L"Parallels Display Adapter (WDDM)",      brands::PARALLELS  },
            { L"Bochs Graphics Adapter",                brands::BOCHS      },
            { L"IddSampleDriver Device",                brands::NULL_BRAND },
            { L"Remote Display Adapter",                brands::NULL_BRAND },
            { L"RDPDD Chained DD",                      brands::NULL_BRAND }
        };
#endif

        DISPLAY_DEVICEW dd{};
        dd.cb = sizeof(dd);

        for (DWORD deviceNum = 0;
            EnumDisplayDevicesW(nullptr, deviceNum, &dd, 0);
            ++deviceNum)
        {
#if (CPP >= 17)
            std::wstring_view devStr{ dd.DeviceString };
            for (auto const& info : vm_gpu_names) {
                if (devStr.find(info.name_substring) != std::wstring_view::npos) {
                    return core::add(info.brand);
                }
            }
#else
            for (int i = 0; i < 10; ++i) {
                if (wcsstr(dd.DeviceString, vm_gpu_names[i].name_substring) != nullptr) {
                    return core::add(vm_gpu_names[i].brand);
                }
            }
#endif
        }

        return false;
#endif
    }

    /**
     * @brief Check for GPU capabilities related to VMs
     * @category Windows
     * @author Requiem (https://github.com/NotRequiem)
     * @implements VM::GPU_CAPABILITIES
     */
    [[nodiscard]] static bool gpu_capabilities() {
#if (!WINDOWS)
        return false;
#else
        using Microsoft::WRL::ComPtr;

        ComPtr<IDirect3D9> d3d9{ Direct3DCreate9(D3D_SDK_VERSION) };
        if (!d3d9) {
            debug("GPU_CAPABILITIES: Direct3DCreate9 failed");
            return true;
        }

        D3DCAPS9 caps{};
        HRESULT hr = d3d9->GetDeviceCaps(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, &caps);
        if (FAILED(hr)) {
            debug("GPU_CAPABILITIES: GetDeviceCaps failed (HRESULT = 0x%08X)", static_cast<unsigned>(hr));
            return false;
        }

        // if the driver cannot adjust the display gamma ramp dynamically—but only in full‑screen mode—via the IDirect3DDevice9::SetGammaRamp API
        return (caps.Caps2 & D3DCAPS2_FULLSCREENGAMMA) == 0;
#endif
    }


    /**
     * @brief Check for vm-specific devices
     * @category Windows
     * @implements VM::DEVICE_HANDLES
     */
    [[nodiscard]] static bool device_handles() {
#if (!WINDOWS)
        return false;
#else
        const HANDLE handle1 = CreateFile(_T("\\\\.\\VBoxMiniRdrDN"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        const HANDLE handle2 = CreateFile(_T("\\\\.\\pipe\\VBoxMiniRdDN"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        const HANDLE handle3 = CreateFile(_T("\\\\.\\VBoxTrayIPC"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        const HANDLE handle4 = CreateFile(_T("\\\\.\\pipe\\VBoxTrayIPC"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        const HANDLE handle5 = CreateFile(_T("\\\\.\\HGFS"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        const HANDLE handle6 = CreateFile(_T("\\\\.\\pipe\\cuckoo"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        bool vbox = false;

        if (
            (handle1 != INVALID_HANDLE_VALUE) ||
            (handle2 != INVALID_HANDLE_VALUE) ||
            (handle3 != INVALID_HANDLE_VALUE) ||
            (handle4 != INVALID_HANDLE_VALUE)
           ) {
            vbox = true;
        }

        CloseHandle(handle1);
        CloseHandle(handle2);
        CloseHandle(handle3);
        CloseHandle(handle4);

        if (vbox) {
            debug("DEVICE_HANDLES: Detected VBox related device handles");
            return core::add(brands::VBOX);
        }

        if (handle5 != INVALID_HANDLE_VALUE) {
            CloseHandle(handle5);
            debug("DEVICE_HANDLES: Detected VMware related device (HGFS)");
            return core::add(brands::VMWARE);
        }
        if (handle6 != INVALID_HANDLE_VALUE) {
            CloseHandle(handle6);
            debug("DEVICE_HANDLES: Detected Cuckoo related device (pipe)");
            return core::add(brands::CUCKOO);
        }

        CloseHandle(handle5);
        CloseHandle(handle6);

        return false;
#endif
    }    


    /**
     * @brief Check for number of logical processors
     * @category Windows
     * @implements VM::LOGICAL_PROCESSORS
     */
    [[nodiscard]] static bool logical_processors()
    {
#if (!WINDOWS)
        return false;
#else
#if (x86_32)
        const PULONG ulNumberProcessors = reinterpret_cast<PULONG>(__readfsdword(0x30) + 0x64);

#else
        const PULONG ulNumberProcessors = reinterpret_cast<PULONG>(__readgsqword(0x60) + 0xB8);
#endif

        if (*ulNumberProcessors < 4)
            return true;
        else
            return false;
#endif
    }


    /**
     * @brief Check for number of physical cores
     * @category Windows
     * @implements VM::PHYSICAL_PROCESSORS
     */
    [[nodiscard]] static bool physical_processors() {
#if (!WINDOWS)
        return false;
#else
        DWORD size = 0;
        GetLogicalProcessorInformationEx(RelationProcessorCore, nullptr, &size);

        std::vector<BYTE> buffer(size);
        if (!GetLogicalProcessorInformationEx(RelationProcessorCore, reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(buffer.data()), &size)) {
            return false;
        }

        int physicalCoreCount = 0;
        auto* ptr = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(buffer.data());

        while (size > 0) {
            if (ptr->Relationship == RelationProcessorCore) {
                ++physicalCoreCount;
                if (physicalCoreCount > 1)
                    return false;
            }
            size -= ptr->Size;
            ptr = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(reinterpret_cast<BYTE*>(ptr) + ptr->Size);
        }

        return true;
#endif
    }


    /**
     * @brief Check for device's temperature
     * @category Windows, Linux
     * @implements VM::TEMPERATURE
     */
    [[nodiscard]] static bool temperature() {
#if (WINDOWS)
        static constexpr GUID GUID_DEVCLASS_THERMALZONE = {
            0x4AFA3D51, 0x74A7, 0x11d0,
            {0xBE, 0x5E, 0x00, 0xA0, 0xC9, 0x06, 0x28, 0x57}
        };

        const HDEVINFO hDevInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_THERMALZONE, nullptr, nullptr,
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
        if (hDevInfo == INVALID_HANDLE_VALUE) {
            return false;
        }

        SP_DEVICE_INTERFACE_DATA deviceInterfaceData = { 0 };
        deviceInterfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

        const bool hasThermal = SetupDiEnumDeviceInterfaces(hDevInfo, nullptr, &GUID_DEVCLASS_THERMALZONE, 0, &deviceInterfaceData);

        SetupDiDestroyDeviceInfoList(hDevInfo);

        return !hasThermal;
#elif (LINUX)
        return (!util::exists("/sys/class/thermal/thermal_zone0/"));
#else
        return false;
#endif
    }


    /**
     * @brief Check for timing anomalies in the system
     * @category x86
     * @author Requiem (https://github.com/NotRequiem)
     * @implements VM::TIMER
     */
#if (CLANG)
    #pragma clang optimize off
#elif (MSVC)
    #pragma optimize("", off)
#elif (GCC)
    #pragma GCC push_options
    #pragma GCC optimize("O0")
#endif
    [[nodiscard]]
#if (LINUX)
    __attribute__((no_sanitize("address", "leak", "thread", "undefined")))
#endif
    static bool timer() {
#if (ARM || !x86)
        return false;
#else
    if (util::hyper_x() == HYPERV_ARTIFACT_VM) {
       return false;
    }

    if (util::is_running_under_translator()) {
       debug("TIMER: Running inside a binary translation layer");
       return false;
    }

    // to minimize context switching/scheduling
    #if (WINDOWS)
        const HANDLE hThread = GetCurrentThread();
        const int oldPriority = GetThreadPriority(hThread);
        SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL);
    #else
        bool hasSchedPriority = (geteuid() == 0);
        int oldPolicy = SCHED_OTHER;
        sched_param oldParam{};

        if (hasSchedPriority) {
            oldPolicy = sched_getscheduler(0);
            sched_getparam(0, &oldParam);
            sched_param newParam{};
            newParam.sched_priority = sched_get_priority_max(SCHED_FIFO);

            if (sched_setscheduler(0, SCHED_FIFO, &newParam) == -1) {
                hasSchedPriority = false;  
            }
        }
    #endif
        auto restoreThreadPriority = [&]() {
    #if (WINDOWS)
            SetThreadPriority(hThread, oldPriority);
    #else
            sched_setscheduler(0, oldPolicy, &oldParam);
    #endif
        };

    #if (WINDOWS)
        DWORD_PTR procMask, sysMask;
        GetProcessAffinityMask(GetCurrentProcess(), &procMask, &sysMask);
    #elif (LINUX)
        cpu_set_t oldTscSet;
        CPU_ZERO(&oldTscSet);
        pthread_getaffinity_np(pthread_self(), sizeof(cpu_set_t), &oldTscSet);
    #endif

        // 1. TSC Synchronization Check Across Cores
        // Try reading the invariant TSC on two different cores to attempt to detect vCPU timers being shared
        constexpr u8  tscIterations = 10;
        constexpr u16 tscSyncDiffThreshold = 500;

        // Pre-flight checks for __rdtscp support & multi-core
        {
            unsigned aux = 0;

#if (WINDOWS)
            const bool haveRdtscp = [&]() noexcept -> bool {
                __try {
                    __rdtscp(&aux);
                    return true;
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    return false;
                }
                }();
            if (!haveRdtscp) {
                // __rdtscp should be supported nowadays
                restoreThreadPriority();
                debug("TIMER: RDTSCP instruction not supporteed");
                return true;
            }

            // Test for a second core
            DWORD_PTR testMask = DWORD_PTR(1) << 1;
            DWORD_PTR prev = SetThreadAffinityMask(hThread, testMask);
            if (prev == 0) {
                // single-core, cannot test, assume no VM
                SetThreadAffinityMask(hThread, prev);
                restoreThreadPriority();
                return false;
            }
            SetThreadAffinityMask(hThread, procMask);
#else
            // Test for __rdtscp support
            static sigjmp_buf jb;
            struct sigaction oldAct, newAct {};
            newAct.sa_flags = SA_SIGINFO;
            newAct.sa_sigaction = [](int, siginfo_t*, void*) { siglongjmp(jb, 1); };
            sigemptyset(&newAct.sa_mask);
            sigaction(SIGILL, &newAct, &oldAct);

            if (sigsetjmp(jb, 1) != 0) {
                // no __rdtscp support, assume VM
                sigaction(SIGILL, &oldAct, nullptr);
                restoreThreadPriority();
                return true;
            }
            __rdtscp(&aux);
            sigaction(SIGILL, &oldAct, nullptr);

            // Test for a second core
            cpu_set_t testSet{};
            CPU_ZERO(&testSet);
            CPU_SET(1, &testSet);
            int ret = pthread_setaffinity_np(pthread_self(), sizeof(testSet), &testSet);
            if (ret == EINVAL) {
                // single-core, cannot test, assume no VM
                restoreThreadPriority();
                return false;
            }
            else if (ret != 0) {
                // unexpected
                restoreThreadPriority();
                return true;
            }
            pthread_setaffinity_np(pthread_self(), sizeof(oldTscSet), &oldTscSet);
#endif
        }

        // Inline two-thread, per-core sampling
        std::atomic<bool> ready{ false };
        std::condition_variable cv;
        std::mutex cv_m;

        static u64    tscVals[2][tscIterations];
        static unsigned auxVals[2][tscIterations];

        auto worker = [&](int idx, int coreId) noexcept {
            // pin once
#if (WINDOWS)
            SetThreadAffinityMask(GetCurrentThread(), DWORD_PTR(1) << coreId);
#else
            cpu_set_t set{};
            CPU_ZERO(&set);
            CPU_SET(coreId, &set);
            pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
#endif

            // wait until both are ready
            {
                std::unique_lock<std::mutex> lk(cv_m);
                cv.wait(lk, [&] { return ready.load(); });
            }

            // reading loop
            for (int i = 0; i < tscIterations; ++i) {
                unsigned a = 0;
                u64      t = 0;

                // spin until on correct core
                do {
                    t = __rdtscp(&a);
                } while (a != (unsigned)coreId);

                tscVals[idx][i] = t;
                auxVals[idx][i] = a;
            }
            };

        std::thread t0(worker, 0, 0);
        std::thread t1(worker, 1, 1);

        {
            std::lock_guard<std::mutex> lk(cv_m);
            ready.store(true);
            cv.notify_all();
        }

        t0.join();
        t1.join();

#if (WINDOWS)
        SetThreadAffinityMask(hThread, procMask);
#else
        pthread_setaffinity_np(pthread_self(), sizeof(oldTscSet), &oldTscSet);
#endif

        // compare readings
        int tscIssueCount = 0;
        for (int i = 0; i < tscIterations; ++i) {
            u64 c0 = tscVals[0][i];
            u64 c1 = tscVals[1][i];
            u64 diff = (c1 > c0) ? (c1 - c0) : (c0 - c1);

#ifdef __VMAWARE_DEBUG__
            debug("TIMER: TSC sync check",
                " - Core0: ", c0,
                " Core1: ", c1,
                " Delta: ", diff,
                " (Threshold: <", tscSyncDiffThreshold, ')');
#endif

            // hypervisors often have near-zero skew
            if (diff < tscSyncDiffThreshold) {
                ++tscIssueCount;
            }
        }

        // if more than half the readings show tiny skew, it's a VM
        bool tscSyncDetected = (tscIssueCount >= tscIterations / 2);

        if (tscSyncDetected) {
            restoreThreadPriority();
            return true;
        }

    #if (WINDOWS)
        // 2. Ratio-based Timing Check on Single Core
        // measure trapping vs non-trapping instructions

        // warm-up to reduce noise
        for (int i = 0; i < 10; ++i) {
            unsigned aux;
        #if (MSVC)
            int cpuInfo[4]; __cpuid(cpuInfo, 0);
            __rdtsc(); 
            GetProcessHeap(); // purely user-mode function
            __rdtscp(&aux);
            #pragma warning (disable : 6387)
            CloseHandle((HANDLE)0); // NtClose syscall
            #pragma warning (default : 6387)
            __rdtscp(&aux);
        #elif (GCC) || (CLANG)
            unsigned low, high;
            __asm__ __volatile__(
                "cpuid\n\t"
                "rdtsc\n\t"
                : "=a"(low), "=d"(high)
                : "a"(0)
                : "ebx", "ecx"
            );
            GetProcessHeap();
            __asm__ __volatile__(
                "rdtscp\n\t"
                "cpuid"
                : "=a"(low), "=d"(high)
                :: "rbx", "rcx"
            );
            CloseHandle((HANDLE)0);
            __asm__ __volatile__(
                "rdtscp\n\t"
                "cpuid"
                : "=a"(low), "=d"(high)
                :: "rbx", "rcx"
            );
        #endif
        }

        // actual measurement
        constexpr u8  SAMPLE_COUNT = 100;
        constexpr u16 SCALE_FACTOR = 1000;
        constexpr u32 THRESHOLD_SCALED = 6 * SCALE_FACTOR;  // <6× ratio => VM
        u64 samples[SAMPLE_COUNT] = { 0 };

        for (int i = 0; i < SAMPLE_COUNT; ++i) {
            unsigned aux;
            u64 x0, x1, x2;
        #if (MSVC)
            int cpuInfo[4]; __cpuid(cpuInfo, 0);
            x0 = __rdtsc();
            GetProcessHeap();
            x1 = __rdtscp(&aux);
        #pragma warning (disable : 6387)
            CloseHandle((HANDLE)0);
        #pragma warning (default : 6387)
            x2 = __rdtscp(&aux);
        #else
            unsigned low, high;
            __asm__ __volatile__(
                "cpuid\n\t"
                "rdtsc\n\t"
                : "=a"(low), "=d"(high)
                : "a"(0)
                : "ebx", "ecx"
            );
            x0 = ((u64)high << 32) | low;

            GetProcessHeap();

            __asm__ __volatile__(
                "rdtscp\n\t"
                "cpuid"
                : "=a"(low), "=d"(high)
                :: "rbx", "rcx"
            );
            x1 = ((u64)high << 32) | low;

            CloseHandle((HANDLE)0);

            __asm__ __volatile__(
                "rdtscp\n\t"
                "cpuid"
                : "=a"(low), "=d"(high)
                :: "rbx", "rcx"
            );
            x2 = ((u64)high << 32) | low;
        #endif
            const u64 heapCost = x1 - x0;
            const u64 closeCost = x2 - x1;
            samples[i] = (heapCost > 0)
                ? ((closeCost * SCALE_FACTOR) / heapCost)
                : UINT64_MAX;
        }

        std::sort(std::begin(samples), std::end(samples));
        restoreThreadPriority();
        const u64 median = samples[SAMPLE_COUNT / 2];
        debug("TIMER: Ratio: ", median, " - Threshold: <", THRESHOLD_SCALED);

        if (median < THRESHOLD_SCALED) {
            return true;
        }

        // simple check to detect poorly coded RDTSC patches
        typedef struct _PROCESSOR_POWER_INFORMATION {
            ULONG Number;
            ULONG MaxMhz;
            ULONG CurrentMhz;
            ULONG MhzLimit;
            ULONG MaxIdleState;
            ULONG CurrentIdleState;
        } PROCESSOR_POWER_INFORMATION, * PPROCESSOR_POWER_INFORMATION;

        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        DWORD procCount = sysInfo.dwNumberOfProcessors;

        std::vector<PROCESSOR_POWER_INFORMATION> ppi(procCount);

        const NTSTATUS status = CallNtPowerInformation(
            ProcessorInformation,
            nullptr,
            0,
            ppi.data(),
            sizeof(PROCESSOR_POWER_INFORMATION) * procCount
        );

        if (status != 0)
            return false;       

        for (DWORD i = 0; i < procCount; ++i) {
            if (ppi[i].CurrentMhz < 1000) {
                return true;
            }
        }

    #endif
        return false;
#endif
    }
#if (CLANG)
    #pragma clang optimize off
#elif (MSVC)
    #pragma optimize("", off)
#elif (GCC)
    #pragma GCC pop_options
#endif


    /**
     * @brief Detect QEMU fw_cfg interface
     *
     * This first checks the Device Tree for a fw-cfg node or hypervisor tag,
     * then verifies the presence of the qemu_fw_cfg module and firmware directories in sysfs.
     *
     * @note Linux DT method: inspired by https://github.com/ShellCode33/VM-Detection
     * @note Linux sysfs method: looks for /sys/module/qemu_fw_cfg/ & /sys/firmware/qemu_fw_cfg/
     *
     * @category Linux
     * @implements VM::QEMU_FW_CFG
     */
    [[nodiscard]] static bool qemu_fw_cfg() {
#if (!LINUX)
        return false;
#else
        // 1) Device Tree-based detection
        if (util::exists("/proc/device-tree/fw-cfg")) {
            return core::add(brands::QEMU);
        }
        if (util::exists("/proc/device-tree/hypervisor/compatible")) {
            return core::add(brands::QEMU);
        }

        // 2) sysfs-based detection
        const char* module_path = "/sys/module/qemu_fw_cfg/";
        const char* firmware_path = "/sys/firmware/qemu_fw_cfg/";
        if (util::is_directory(module_path) && util::exists(module_path) &&
            util::is_directory(firmware_path) && util::exists(firmware_path)) {
            return core::add(brands::QEMU);
        }

        return false;
#endif
    }


	/**
	 * @brief Check for QEMU string instances with lshw command
	 * @category Linux
     * @implements VM::LSHW_QEMU
	 */
    [[nodiscard]] static bool lshw_qemu() {
#if !LINUX
        return false;
#else
        if (!(util::exists("/usr/bin/lshw") ||
            util::exists("/bin/lshw")    ||
            util::exists("/usr/sbin/lshw"))) {
            debug("LSHW_QEMU: ", "binary doesn't exist");
            return false;
        }

        FILE* pipe = popen("lshw 2>&1", "r");
        if (!pipe) {
            debug("LSHW_QEMU: ", "popen failed");
            return false;
        }

        static constexpr const char* patterns[] = {
            "QEMU PCIe Root port",
            "QEMU XHCI Host Controller",
            "QEMU DVD-ROM",
            "QEMU QEMU USB Tablet"
        };
        bool seen[sizeof(patterns)/sizeof(patterns[0])] = {false};
        int score = 0;

        size_t max_pat = 0;
        for (auto& p : patterns) max_pat = std::max(max_pat, strlen(p));
        std::string overlap;
        overlap.reserve(max_pat - 1);

        const size_t BUF_SIZE = 64 * 1024;
        std::vector<char> buf(BUF_SIZE);
        while (true) {
            size_t n = fread(buf.data(), 1, BUF_SIZE, pipe);
            if (n == 0) break;

            std::string chunk = overlap;
            chunk.append(buf.data(), n);

            if (chunk.size() >= max_pat - 1) {
                overlap = chunk.substr(chunk.size() - (max_pat - 1));
            } else {
                overlap = chunk;
            }

            #define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

            for (size_t i = 0; i < ARRAY_SIZE(patterns); ++i) {
                if (!seen[i] && chunk.find(patterns[i]) != std::string::npos) {
                    debug("LSHW_QEMU: found ", patterns[i]);
                    seen[i] = true;
                    ++score;
                    if (score >= 3) break;
                }
            }
            if (score >= 3) break;
        }

        pclose(pipe);
        return (score >= 3);
#endif
    }


    /**
     * @brief Check if the number of virtual and logical processors are reported correctly by the system
     * @category Windows
     * @author Requiem (https://github.com/NotRequiem)
     * @implements VM::VIRTUAL_PROCESSORS
     */
    [[nodiscard]] static bool virtual_processors() {
#if (!WINDOWS)
        return false;
#else   
        if (!cpu::is_leaf_supported(0x40000005)) {
            return false;
        }
        
        struct Registers {
            int eax = 0;
            int ebx = 0;
            int ecx = 0;
            int edx = 0;
        };
        struct ImplementationLimits {
            unsigned int MaxVirtualProcessors = 0;
            unsigned int MaxLogicalProcessors = 0;
        };

        Registers registers;
        __cpuid(&registers.eax, 0x40000005);

        ImplementationLimits implementationLimits;
        implementationLimits.MaxVirtualProcessors = static_cast<unsigned int>(registers.eax);
        implementationLimits.MaxLogicalProcessors = static_cast<unsigned int>(registers.ebx);

        debug("VIRTUAL_PROCESSORS: MaxVirtualProcessors: ", implementationLimits.MaxVirtualProcessors,
            ", MaxLogicalProcessors: ", implementationLimits.MaxLogicalProcessors);

        if (implementationLimits.MaxVirtualProcessors == 0xffffffff || implementationLimits.MaxLogicalProcessors == 0) {
            return true;
        }

        return false;
#endif
    }


    /**
     * @brief Check if a call to NtQuerySystemInformation with the 0x9f leaf fills a _SYSTEM_HYPERVISOR_DETAIL_INFORMATION structure
     * @category Windows
     * @implements VM::HYPERV_QUERY
     */
    [[nodiscard]] static bool hyperv_query() {
#if (!WINDOWS)
        return false;
#else 
        if (util::hyper_x() == HYPERV_ARTIFACT_VM) {
            return false;
        }

        typedef struct _HV_DETAILS {
            ULONG Data[4];
        } HV_DETAILS, * PHV_DETAILS;

        typedef struct _SYSTEM_HYPERVISOR_DETAIL_INFORMATION {
            HV_DETAILS HvVendorAndMaxFunction;
            HV_DETAILS HypervisorInterface;
            HV_DETAILS HypervisorVersion;
            HV_DETAILS HvFeatures;
            HV_DETAILS HwFeatures;
            HV_DETAILS EnlightenmentInfo;
            HV_DETAILS ImplementationLimits;
        } SYSTEM_HYPERVISOR_DETAIL_INFORMATION, * PSYSTEM_HYPERVISOR_DETAIL_INFORMATION;

        typedef NTSTATUS(__stdcall* FN_NtQuerySystemInformation)(
            SYSTEM_INFORMATION_CLASS SystemInformationClass,
            PVOID SystemInformation,
            ULONG SystemInformationLength,
            PULONG ReturnLength
            );

        const HMODULE hNtdll = GetModuleHandle(_T("ntdll.dll"));
        if (!hNtdll) {
            return false;
        }

        const char* functionNames[] = { "NtQuerySystemInformation" };
        void* functions[1] = { nullptr };

        util::GetFunctionAddresses(hNtdll, functionNames, functions, 1);

        FN_NtQuerySystemInformation pNtQuerySystemInformation = reinterpret_cast<FN_NtQuerySystemInformation>(functions[0]);
        if (pNtQuerySystemInformation) {
            SYSTEM_HYPERVISOR_DETAIL_INFORMATION hvInfo = { {} };
            const NTSTATUS status = pNtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(0x9F), &hvInfo, sizeof(hvInfo), nullptr);
            if (status != 0) {
                return false;
            }

            if (hvInfo.HvVendorAndMaxFunction.Data[0] != 0) {
                return true;
            }
        }

        return false;
#endif
    }


    /**
     * @brief Check for system pools allocated by hypervisors
     * @category Windows
     * @implements VM::POOLS
     */
    [[nodiscard]] static bool pools() {
#if (!WINDOWS)
        return false;
#else
#pragma warning (disable : 4459) 
        typedef enum _SYSTEM_INFORMATION_CLASS
        {
            SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
            SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
            SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
            SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
            SystemPathInformation, // not implemented
            SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
            SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
            SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
            SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
            SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
            SystemCallTimeInformation, // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
            SystemModuleInformation, // q: RTL_PROCESS_MODULES
            SystemLocksInformation, // q: RTL_PROCESS_LOCKS
            SystemStackTraceInformation, // q: RTL_PROCESS_BACKTRACES
            SystemPagedPoolInformation, // not implemented
            SystemNonPagedPoolInformation, // not implemented
            SystemHandleInformation, // q: SYSTEM_HANDLE_INFORMATION
            SystemObjectInformation, // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
            SystemPageFileInformation, // q: SYSTEM_PAGEFILE_INFORMATION
            SystemVdmInstemulInformation, // q
            SystemVdmBopInformation, // not implemented // 20
            SystemFileCacheInformation, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
            SystemPoolTagInformation, // q: SYSTEM_POOLTAG_INFORMATION
            SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION
            SystemDpcBehaviorInformation, // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
            SystemFullMemoryInformation, // not implemented
            SystemLoadGdiDriverInformation, // s (kernel-mode only)
            SystemUnloadGdiDriverInformation, // s (kernel-mode only)
            SystemTimeAdjustmentInformation, // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
            SystemSummaryMemoryInformation, // not implemented
            SystemMirrorMemoryInformation, // s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
            SystemPerformanceTraceInformation, // q; s: (type depends on EVENT_TRACE_INFORMATION_CLASS)
            SystemObsolete0, // not implemented
            SystemExceptionInformation, // q: SYSTEM_EXCEPTION_INFORMATION
            SystemCrashDumpStateInformation, // s (requires SeDebugPrivilege)
            SystemKernelDebuggerInformation, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
            SystemContextSwitchInformation, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
            SystemRegistryQuotaInformation, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
            SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
            SystemPrioritySeperation, // s (requires SeTcbPrivilege)
            SystemVerifierAddDriverInformation, // s (requires SeDebugPrivilege) // 40
            SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
            SystemProcessorIdleInformation, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION
            SystemLegacyDriverInformation, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
            SystemCurrentTimeZoneInformation, // q
            SystemLookasideInformation, // q: SYSTEM_LOOKASIDE_INFORMATION
            SystemTimeSlipNotification, // s (requires SeSystemtimePrivilege)
            SystemSessionCreate, // not implemented
            SystemSessionDetach, // not implemented
            SystemSessionInformation, // not implemented
            SystemRangeStartInformation, // q: SYSTEM_RANGE_START_INFORMATION // 50
            SystemVerifierInformation, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
            SystemVerifierThunkExtend, // s (kernel-mode only)
            SystemSessionProcessInformation, // q: SYSTEM_SESSION_PROCESS_INFORMATION
            SystemLoadGdiDriverInSystemSpace, // s (kernel-mode only) (same as SystemLoadGdiDriverInformation)
            SystemNumaProcessorMap, // q
            SystemPrefetcherInformation, // q: PREFETCHER_INFORMATION; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
            SystemExtendedProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
            SystemRecommendedSharedDataAlignment, // q
            SystemComPlusPackage, // q; s
            SystemNumaAvailableMemory, // 60
            SystemProcessorPowerInformation, // q: SYSTEM_PROCESSOR_POWER_INFORMATION
            SystemEmulationBasicInformation, // q
            SystemEmulationProcessorInformation,
            SystemExtendedHandleInformation, // q: SYSTEM_HANDLE_INFORMATION_EX
            SystemLostDelayedWriteInformation, // q: ULONG
            SystemBigPoolInformation, // q: SYSTEM_BIGPOOL_INFORMATION
            SystemSessionPoolTagInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
            SystemSessionMappedViewInformation, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
            SystemHotpatchInformation, // q; s
            SystemObjectSecurityMode, // q // 70
            SystemWatchdogTimerHandler, // s (kernel-mode only)
            SystemWatchdogTimerInformation, // q (kernel-mode only); s (kernel-mode only)
            SystemLogicalProcessorInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION
            SystemWow64SharedInformationObsolete, // not implemented
            SystemRegisterFirmwareTableInformationHandler, // s (kernel-mode only)
            SystemFirmwareTableInformation, // SYSTEM_FIRMWARE_TABLE_INFORMATION
            SystemModuleInformationEx, // q: RTL_PROCESS_MODULE_INFORMATION_EX
            SystemVerifierTriageInformation, // not implemented
            SystemSuperfetchInformation, // q; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
            SystemMemoryListInformation, // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
            SystemFileCacheInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
            SystemThreadPriorityClientIdInformation, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
            SystemProcessorIdleCycleTimeInformation, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[]
            SystemVerifierCancellationInformation, // not implemented // name:wow64:whNT32QuerySystemVerifierCancellationInformation
            SystemProcessorPowerInformationEx, // not implemented
            SystemRefTraceInformation, // q; s: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
            SystemSpecialPoolInformation, // q; s (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
            SystemProcessIdInformation, // q: SYSTEM_PROCESS_ID_INFORMATION
            SystemErrorPortInformation, // s (requires SeTcbPrivilege)
            SystemBootEnvironmentInformation, // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
            SystemHypervisorInformation, // q; s (kernel-mode only)
            SystemVerifierInformationEx, // q; s: SYSTEM_VERIFIER_INFORMATION_EX
            SystemTimeZoneInformation, // s (requires SeTimeZonePrivilege)
            SystemImageFileExecutionOptionsInformation, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
            SystemCoverageInformation, // q; s // name:wow64:whNT32QuerySystemCoverageInformation; ExpCovQueryInformation
            SystemPrefetchPatchInformation, // not implemented
            SystemVerifierFaultsInformation, // s (requires SeDebugPrivilege)
            SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
            SystemSystemDiskInformation, // q: SYSTEM_SYSTEM_DISK_INFORMATION
            SystemProcessorPerformanceDistribution, // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION // 100
            SystemNumaProximityNodeInformation, // q
            SystemDynamicTimeZoneInformation, // q; s (requires SeTimeZonePrivilege)
            SystemCodeIntegrityInformation, // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
            SystemProcessorMicrocodeUpdateInformation, // s
            SystemProcessorBrandString, // q // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
            SystemVirtualAddressInformation, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
            SystemLogicalProcessorAndGroupInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // since WIN7 // KeQueryLogicalProcessorRelationship
            SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[]
            SystemStoreInformation, // q; s // SmQueryStoreInformation
            SystemRegistryAppendString, // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
            SystemAitSamplingValue, // s: ULONG (requires SeProfileSingleProcessPrivilege)
            SystemVhdBootInformation, // q: SYSTEM_VHD_BOOT_INFORMATION
            SystemCpuQuotaInformation, // q; s // PsQueryCpuQuotaInformation
            SystemNativeBasicInformation, // not implemented
            SystemSpare1, // not implemented
            SystemLowPriorityIoInformation, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
            SystemTpmBootEntropyInformation, // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
            SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
            SystemPagedPoolInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
            SystemSystemPtesInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
            SystemNodeDistanceInformation, // q
            SystemAcpiAuditInformation, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
            SystemBasicPerformanceInformation, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
            SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
            SystemSessionBigPoolInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
            SystemBootGraphicsInformation, // q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
            SystemScrubPhysicalMemoryInformation, // q; s: MEMORY_SCRUB_INFORMATION
            SystemBadPageInformation,
            SystemProcessorProfileControlArea, // q; s: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
            SystemCombinePhysicalMemoryInformation, // s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
            SystemEntropyInterruptTimingCallback,
            SystemConsoleInformation, // q: SYSTEM_CONSOLE_INFORMATION
            SystemPlatformBinaryInformation, // q: SYSTEM_PLATFORM_BINARY_INFORMATION
            SystemThrottleNotificationInformation,
            SystemHypervisorProcessorCountInformation, // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
            SystemDeviceDataInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
            SystemDeviceDataEnumerationInformation,
            SystemMemoryTopologyInformation, // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
            SystemMemoryChannelInformation, // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
            SystemBootLogoInformation, // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
            SystemProcessorPerformanceInformationEx, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // since WINBLUE
            SystemSpare0,
            SystemSecureBootPolicyInformation, // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
            SystemPageFileInformationEx, // q: SYSTEM_PAGEFILE_INFORMATION_EX
            SystemSecureBootInformation, // q: SYSTEM_SECUREBOOT_INFORMATION
            SystemEntropyInterruptTimingRawInformation,
            SystemPortableWorkspaceEfiLauncherInformation, // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
            SystemFullProcessInformation, // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
            SystemKernelDebuggerInformationEx, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
            SystemBootMetadataInformation, // 150
            SystemSoftRebootInformation,
            SystemElamCertificateInformation, // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
            SystemOfflineDumpConfigInformation,
            SystemProcessorFeaturesInformation, // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
            SystemRegistryReconciliationInformation,
            SystemEdidInformation,
            SystemManufacturingInformation, // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
            SystemEnergyEstimationConfigInformation, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
            SystemHypervisorDetailInformation, // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
            SystemProcessorCycleStatsInformation, // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION // 160
            SystemVmGenerationCountInformation,
            SystemTrustedPlatformModuleInformation, // q: SYSTEM_TPM_INFORMATION
            SystemKernelDebuggerFlags,
            SystemCodeIntegrityPolicyInformation, // q: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
            SystemIsolatedUserModeInformation, // q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
            SystemHardwareSecurityTestInterfaceResultsInformation,
            SystemSingleModuleInformation, // q: SYSTEM_SINGLE_MODULE_INFORMATION
            SystemAllowedCpuSetsInformation,
            SystemDmaProtectionInformation, // q: SYSTEM_DMA_PROTECTION_INFORMATION
            SystemInterruptCpuSetsInformation, // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
            SystemSecureBootPolicyFullInformation, // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
            SystemCodeIntegrityPolicyFullInformation,
            SystemAffinitizedInterruptProcessorInformation,
            SystemRootSiloInformation, // q: SYSTEM_ROOT_SILO_INFORMATION
            SystemCpuSetInformation, // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
            SystemCpuSetTagInformation, // q: SYSTEM_CPU_SET_TAG_INFORMATION
            SystemWin32WerStartCallout,
            SystemSecureKernelProfileInformation, // q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
            SystemCodeIntegrityPlatformManifestInformation, // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // since REDSTONE
            SystemInterruptSteeringInformation, // 180
            SystemSupportedProcessorArchitectures,
            SystemMemoryUsageInformation, // q: SYSTEM_MEMORY_USAGE_INFORMATION
            SystemCodeIntegrityCertificateInformation, // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
            SystemPhysicalMemoryInformation, // q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
            SystemControlFlowTransition,
            SystemKernelDebuggingAllowed,
            SystemActivityModerationExeState, // SYSTEM_ACTIVITY_MODERATION_EXE_STATE
            SystemActivityModerationUserSettings, // SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
            SystemCodeIntegrityPoliciesFullInformation,
            SystemCodeIntegrityUnlockInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
            SystemIntegrityQuotaInformation,
            SystemFlushInformation, // q: SYSTEM_FLUSH_INFORMATION
            MaxSystemInfoClass
        } SYSTEM_INFORMATION_CLASS;
#pragma warning (default : 4459)
        typedef struct _SYSTEM_POOLTAG
        {
            union
            {
                UCHAR Tag[4];
                ULONG TagUlong;
            };
            ULONG PagedAllocs;
            ULONG PagedFrees;
            SIZE_T PagedUsed;
            ULONG NonPagedAllocs;
            ULONG NonPagedFrees;
            SIZE_T NonPagedUsed;
        } SYSTEM_POOLTAG, * PSYSTEM_POOLTAG;

        typedef struct _SYSTEM_POOLTAG_INFORMATION
        {
            ULONG Count;
            SYSTEM_POOLTAG TagInfo[1];
        } SYSTEM_POOLTAG_INFORMATION, * PSYSTEM_POOLTAG_INFORMATION;

        std::vector<BYTE> buffer_pool_info;
        ULONG ret_length = 0;
        NTSTATUS nt_status = ((NTSTATUS)0xC0000001L);

        const HMODULE ntdll = GetModuleHandle(_T("ntdll.dll"));
        if (!ntdll) return false;

        const char* funcNames[] = { "NtQuerySystemInformation" };
        void* funcPtrs[] = { nullptr };
        util::GetFunctionAddresses(ntdll, funcNames, funcPtrs, 1);

        typedef NTSTATUS(__stdcall* NtQuerySystemInformationFunc)(
            SYSTEM_INFORMATION_CLASS SystemInformationClass,
            PVOID SystemInformation,
            ULONG SystemInformationLength,
            PULONG ReturnLength
            );

        const NtQuerySystemInformationFunc NtQuerySystemInformation = reinterpret_cast<NtQuerySystemInformationFunc>(funcPtrs[0]);

        if (NtQuerySystemInformation)
            nt_status = NtQuerySystemInformation(SystemPoolTagInformation, nullptr, 0, &ret_length);

        while (nt_status == ((NTSTATUS)0xC0000004L)) {
            buffer_pool_info.resize(ret_length);
            nt_status = NtQuerySystemInformation(SystemPoolTagInformation, buffer_pool_info.data(), ret_length, &ret_length);
        }

        if (!(((NTSTATUS)(nt_status)) >= 0))
            return false;

        auto info = reinterpret_cast<PSYSTEM_POOLTAG_INFORMATION>(buffer_pool_info.data());
        if (!info || info->Count == 0)
            return false;

        u8 badCount = 0;
        const auto tagArray = info->TagInfo;

        for (ULONG i = 0; i < info->Count && badCount < 2; ++i) {
            DWORD tag = *reinterpret_cast<const DWORD*>(&tagArray[i].Tag);

            switch (tag) {
                case 0x44334D56: // VM3D
                case 0x706D6D76: // vmmp
                case 0x43475443: // CTGC - can be present on baremetal machines
                case 0x43434748: // HGCC
                case 0x4D4E4748: // HGNM
                case 0x4C424D56: // VMBL
                case 0x4D444256: // VBDM
                case 0x41474256: // VBGA
                    debug("POOLS: Detected bad pool tag: 0x",
                        std::hex, tag, std::dec);
                    ++badCount;
                    break;
                default:
                    break;
            }
        }

        return badCount >= 2;
#endif
    }


	/**
	 * @brief Check for AMD-SEV MSR running on the system
	 * @category x86, Linux, MacOS
	 * @note idea from virt-what
     * @implements VM::AMD_SEV
	 */
	[[nodiscard]] static bool amd_sev() {
#if (x86 && (LINUX || APPLE))
	    if (!cpu::is_amd()) {
	        return false;
	    }
	    
	    if (!util::is_admin()) {
	        return false;
	    }
	
	    constexpr u32 encrypted_memory_capability = 0x8000001f;
	    constexpr u32 msr_index = 0xc0010131;	  
        
	    if (!cpu::is_leaf_supported(encrypted_memory_capability)) {
	        return false;
	    }
	    
	    u32 eax, unused = 0;
	    cpu::cpuid(eax, unused, unused, unused, encrypted_memory_capability);
	      
	    if (!(eax & (1 << 1))) {
	        return false;
	    }       
	
	    u64 result = 0;
	  
        const std::string msr_device = "/dev/cpu/0/msr";
        std::ifstream msr_file(msr_device, std::ios::binary);

        if (!msr_file.is_open()) {
            debug("AMD_SEV: unable to open MSR file");
            return false;
        }

        msr_file.seekg(msr_index);
        msr_file.read(reinterpret_cast<char*>(&result), sizeof(result));

        if (!msr_file) {
            debug("AMD_SEV: unable to open MSR file");
            return false;
        }

        if (result & (static_cast<unsigned long long>(1) << 2)) { return core::add(brands::AMD_SEV_SNP); }
        else if (result & (static_cast<unsigned long long>(1) << 1)) { return core::add(brands::AMD_SEV_ES); }
	    else if (result & 1) { return core::add(brands::AMD_SEV); }
	
	    return false;
#else
        return false;
#endif
	}


    /**
     * @brief Check for particular object directory which is present in Sandboxie virtual environment but not in usual host systems
     * @category Windows
     * @note https://evasions.checkpoint.com/src/Evasions/techniques/global-os-objects.html
     * @implements VM::VIRTUAL_REGISTRY
     */
    [[nodiscard]] static bool virtual_registry() {
#if (!WINDOWS)
        return false;
#else
#pragma warning(disable : 4459)
        typedef struct _UNICODE_STRING {
            USHORT Length;
            USHORT MaximumLength;
            PWSTR  Buffer;
        } UNICODE_STRING, * PUNICODE_STRING;

        typedef struct _OBJECT_ATTRIBUTES {
            ULONG Length;
            HANDLE RootDirectory;
            PUNICODE_STRING ObjectName;
            ULONG Attributes;
            PVOID SecurityDescriptor;
            PVOID SecurityQualityOfService;
        } OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

        typedef enum _OBJECT_INFORMATION_CLASS {
            ObjectBasicInformation = 0,
            ObjectNameInformation = 1,
            ObjectTypeInformation = 2
        } OBJECT_INFORMATION_CLASS;

        typedef struct _OBJECT_NAME_INFORMATION {
            UNICODE_STRING Name;
        } OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;
#pragma warning(default : 4459)

        typedef NTSTATUS(__stdcall* PNtOpenKey)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
        typedef NTSTATUS(__stdcall* PNtQueryObject)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);

        const HMODULE hModule = GetModuleHandle(_T("ntdll.dll"));
        if (!hModule)
            return false;

        const char* functionNames[] = { "NtOpenKey", "NtQueryObject" };
        void* functionPointers[2] = { nullptr, nullptr };

        util::GetFunctionAddresses(hModule, functionNames, functionPointers, 2);

        const auto NtOpenKey = reinterpret_cast<PNtOpenKey>(functionPointers[0]);
        const auto NtQueryObject = reinterpret_cast<PNtQueryObject>(functionPointers[1]);
        if (!NtOpenKey || !NtQueryObject)
            return false;

        UNICODE_STRING keyPath{};
        keyPath.Buffer = const_cast<PWSTR>(L"\\REGISTRY\\USER");
        keyPath.Length = static_cast<USHORT>(wcslen(keyPath.Buffer) * sizeof(WCHAR));
        keyPath.MaximumLength = keyPath.Length + sizeof(WCHAR);

        OBJECT_ATTRIBUTES objAttr = {
            sizeof(OBJECT_ATTRIBUTES),
            nullptr,
            &keyPath,
            0x00000040L,  // OBJ_CASE_INSENSITIVE
            nullptr,
            nullptr
        };

        HANDLE hKey = nullptr;
        NTSTATUS status = NtOpenKey(&hKey, KEY_READ, &objAttr);
        if (!(((NTSTATUS)(status)) >= 0))
            return false;

        alignas(16) BYTE buffer[1024]{};
        ULONG returnedLength = 0;
        status = NtQueryObject(hKey, ObjectNameInformation, buffer, sizeof(buffer), &returnedLength);
        CloseHandle(hKey);
        if (!(((NTSTATUS)(status)) >= 0))
            return false;

        auto pObjectName = reinterpret_cast<POBJECT_NAME_INFORMATION>(buffer);

        UNICODE_STRING expectedName{};
        expectedName.Buffer = const_cast<PWSTR>(L"\\REGISTRY\\USER");
        expectedName.Length = static_cast<USHORT>(wcslen(expectedName.Buffer) * sizeof(WCHAR));
        expectedName.MaximumLength = expectedName.Length + sizeof(WCHAR);

        const bool mismatch = (pObjectName->Name.Length != expectedName.Length) ||
            (memcmp(pObjectName->Name.Buffer, expectedName.Buffer, expectedName.Length) != 0);

        return mismatch ? core::add(brands::SANDBOXIE) : false;
#endif
    }


    /**
     * @brief Check for VM signatures on all firmware tables
     * @category Windows
     * @credits Requiem, dmfrpro, MegaMax
     * @implements VM::FIRMWARE
     */
    [[nodiscard]] static bool firmware_scan() {
#if (WINDOWS)
#pragma warning(disable: 4459)
        typedef enum _SYSTEM_INFORMATION_CLASS {
            SystemFirmwareTableInformation = 76
        } SYSTEM_INFORMATION_CLASS;
        typedef enum _SYSTEM_FIRMWARE_TABLE_ACTION {
            SystemFirmwareTableEnumerate,
            SystemFirmwareTableGet,
            SystemFirmwareTableMax
        } SYSTEM_FIRMWARE_TABLE_ACTION;
        typedef struct _SYSTEM_FIRMWARE_TABLE_INFORMATION {
            ULONG ProviderSignature;
            SYSTEM_FIRMWARE_TABLE_ACTION Action;
            ULONG TableID;
            ULONG TableBufferLength;
            _Field_size_bytes_(TableBufferLength) UCHAR TableBuffer[1];
        } SYSTEM_FIRMWARE_TABLE_INFORMATION, * PSYSTEM_FIRMWARE_TABLE_INFORMATION;
#pragma warning(default: 4459)

        typedef NTSTATUS(__stdcall* PNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

#if defined(_MSC_VER)
#define BSWAP32(x) _byteswap_ulong(x)
#else
#define BSWAP32(x) __builtin_bswap32(x)
#endif

#if defined(_MSC_VER)
#define PREFETCH(addr) _mm_prefetch((const char*)(addr), _MM_HINT_T0)
#else
#define PREFETCH(addr) __builtin_prefetch(addr)
#endif

        constexpr ULONG STATUS_BUFFER_TOO_SMALL = 0xC0000023;
        constexpr DWORD ACPI_SIG = 'ACPI';
        constexpr DWORD ssdtSig = 'TDSS';
        constexpr DWORD facpSig = 'PCAF';
        constexpr DWORD dsdtSig = 'DSDT';
        constexpr DWORD FIRM_SIG = 'FIRM';
        constexpr DWORD RSMB_SIG = 'RSMB';

        PBYTE qsiBuf = nullptr;
        ULONG qsiSize = 0;

        auto clear = [&]() noexcept {
            free(qsiBuf);
            qsiBuf = nullptr;
            qsiSize = 0;
        };

        auto ensure = [&](ULONG need) noexcept -> bool {
            if (qsiSize < need) {
                PBYTE tmp = (PBYTE)realloc(qsiBuf, need);
                if (!tmp) return false;
                qsiBuf = tmp;
                qsiSize = need;
            }
            return true;
        };

        const HMODULE hNtdll = GetModuleHandle(_T("ntdll.dll"));
        if (!hNtdll) return false;

        const char* functionNames[] = { "NtQuerySystemInformation" };
        void* functionPointers[1] = { nullptr };

        util::GetFunctionAddresses(hNtdll, functionNames, functionPointers, 1);

        const auto ntqsi = reinterpret_cast<PNtQuerySystemInformation>(functionPointers[0]);
        if (!ntqsi) return false;

        constexpr std::array<const char*, 21> targets = { {
            "Parallels Software", "Parallels(R)",
            "innotek",            "Oracle",   "VirtualBox", "vbox", "VBOX",
            "VMware, Inc.",       "VMware",   "VMWARE",
            "QEMU",               "pc-q35",   "FWCF",       "BOCHS", "BXPC",
            "ovmf",               "edk ii unknown", "WAET", "S3 Corp.", "Virtual Machine", "VS2005R2"
        } };

        constexpr std::array<const char*, 21> brands_map = { {
            brands::PARALLELS, brands::PARALLELS,
            brands::VBOX,      brands::VBOX,      brands::VBOX,     brands::VBOX,     brands::VBOX,
            brands::VMWARE,    brands::VMWARE,    brands::VMWARE,
            brands::QEMU,      brands::QEMU,      brands::QEMU,     brands::BOCHS,    brands::BOCHS,
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr
        } };

        static_assert(targets.size() == brands_map.size(),
            "targets and brands_map must be the same length");

        auto query = [&](DWORD provider, DWORD tableID, PULONG outLen) noexcept -> PSYSTEM_FIRMWARE_TABLE_INFORMATION {
            const ULONG hdrSz = FIELD_OFFSET(SYSTEM_FIRMWARE_TABLE_INFORMATION, TableBuffer);
            if (!ensure(hdrSz)) { clear(); return nullptr; }

            auto hdr = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)qsiBuf;
            hdr->ProviderSignature = provider;
            hdr->Action = SystemFirmwareTableEnumerate;
            hdr->TableID = BSWAP32(tableID);
            hdr->TableBufferLength = 0;

            NTSTATUS st = ntqsi(SystemFirmwareTableInformation, hdr, hdrSz, outLen);
            if (static_cast<ULONG>(st) != STATUS_BUFFER_TOO_SMALL) { clear(); return nullptr; }

            const ULONG fullSz = *outLen;
            if (!ensure(fullSz)) { clear(); return nullptr; }

            hdr = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)qsiBuf;
            hdr->ProviderSignature = provider;
            hdr->Action = SystemFirmwareTableEnumerate;
            hdr->TableID = BSWAP32(tableID);
            hdr->TableBufferLength = fullSz - hdrSz;

            PREFETCH(hdr->TableBuffer);
            st = ntqsi(SystemFirmwareTableInformation, hdr, fullSz, outLen);
            if (!(((NTSTATUS)(st)) >= 0)) { clear(); return nullptr; }

            return hdr;
        };

        auto scan_table = [&](DWORD sig, DWORD id) noexcept -> bool {
            ULONG got = 0;
            auto info = query(sig, id, &got);
            if (!info) return false;

            const auto* buf = info->TableBuffer;
            const size_t len = info->TableBufferLength;

            constexpr char man_short[] = "Advanced Micro Devices";
            constexpr char man_full[] = "Advanced Micro Devices, Inc.";
            const size_t short_len = sizeof(man_short) - 1;
            const size_t full_len = sizeof(man_full) - 1;

            bool has_short = false, has_full = false;

            for (size_t i = 0; i + short_len <= len; ++i) {
                if (memcmp(buf + i, man_short, short_len) == 0) {
                    has_short = true;
                    break;
                }
            }
            for (size_t i = 0; i + full_len <= len; ++i) {
                if (memcmp(buf + i, man_full, full_len) == 0) {
                    has_full = true;
                    break;
                }
            }
            if (has_short && !has_full) {
                debug("FIRMWARE: Spoofed AMD manufacturer string detected");
                clear();
                return true;
            }

            for (size_t ti = 0; ti < targets.size(); ++ti) {
                const char* pat = targets[ti];
                const size_t plen = strlen(pat);
                if (plen > len) continue;

                for (size_t i = 0; i + plen <= len; ++i) {
                    if (buf[i] == static_cast<unsigned char>(pat[0])
                        && memcmp(buf + i, pat, plen) == 0)
                    {
                        clear();
                        const char* brand = brands_map[ti];
                        return (brand ? core::add(brand) : true);
                    }
                }
            }

            constexpr char marker[] = "777777";
            constexpr size_t mlen = sizeof(marker) - 1;
            if (len >= mlen) {
                for (size_t i = 0; i + mlen <= len; ++i) {
                    if (memcmp(buf + i, marker, mlen) == 0) {
                        clear();
                        return core::add(brands::VMWARE_HARD);
                    }
                }
            }

            clear();
            return false;
        };

        ULONG total = 0;
        auto list = query(ACPI_SIG, 0, &total);
        if (!list) return false;

        // ACPI table count
        const DWORD* tables = (DWORD*)list->TableBuffer;
        const ULONG cnt = list->TableBufferLength / sizeof(DWORD);
        if (cnt < 4) { clear(); return true; }

        // SSDT count
        int ssdt_ct = 0;
        for (ULONG i = 0; i < cnt; ++i) {
            if (tables[i] == ssdtSig && ++ssdt_ct == 2) break;
        }
        if (ssdt_ct < 2) { clear(); return true; }

        for (ULONG i = 0; i < cnt; ++i) {
            DWORD tbl = tables[i];
            // FADT PM type check
            if (tbl == facpSig) {
                ULONG fsz = 0;
                auto fadt = query(ACPI_SIG, tbl, &fsz);
                if (fadt && fsz > 45 && fadt->TableBuffer[45] == 0) {
                    debug("FIRMWARE: Invalid PM type detected");
                    clear();
                    return true;
                }
            }
            // ACPI scan
            if (scan_table(ACPI_SIG, tbl)) {
                clear();
                return true;
            }
        }

        // DSDT scan & OSI check
        clear();
        const ULONG dsdtSz = GetSystemFirmwareTable(ACPI_SIG, BSWAP32(dsdtSig), nullptr, 0);
        if (dsdtSz == 0) return false;

        BYTE* dsdt = (BYTE*)malloc(dsdtSz);
        if (!dsdt) return false;

        if (GetSystemFirmwareTable(ACPI_SIG, BSWAP32(dsdtSig), dsdt, dsdtSz) != dsdtSz) {
            free(dsdt);
            return false;
        }

        static const char* __restrict osi[] = {
            "Windows 95","Windows 98","Windows 2000","Windows XP","Windows 2012"
        };
        bool found = false;
        for (auto s : osi) {
            size_t L = strlen(s);
            for (ULONG j = 0; j + L <= dsdtSz; ++j) {
                if (dsdt[j] == (BYTE)s[0] && memcmp(dsdt + j, s, L) == 0) {
                    found = true;
                    break;
                }
            }
        }

        free(dsdt);
        if (!found) {
            debug("FIRMWARE: Invalid _OSI params found");
            return true;
        }

        // SMBIOS (RMSB) & FIRM scan
        const DWORD smbios[] = { FIRM_SIG, RSMB_SIG };
        for (DWORD provider : smbios) {
            ULONG totalOther = 0;
            auto listOther = query(provider, 0, &totalOther);
            if (!listOther)
                continue;

            const DWORD* tablesOther = reinterpret_cast<const DWORD*>(listOther->TableBuffer);
            const ULONG countOther = listOther->TableBufferLength / sizeof(DWORD);
            for (ULONG i = 0; i < countOther; ++i) {
                if (scan_table(provider, tablesOther[i])) {
                    clear();
                    return true;
                }

            }
            clear();
        }

        return false;
#elif (LINUX)
        // Author: dmfrpro
        if (!util::is_admin()) {
            return false;
        }

        DIR* dir = opendir("/sys/firmware/acpi/tables/");
        if (!dir) {
            debug("FIRMWARE: could not open ACPI tables directory");
            return false;
        }

        // Same targets as the Windows branch but without "WAET"
        constexpr const char* targets[] = {
            "Parallels Software International","Parallels(R)","innotek",
            "Oracle","VirtualBox","vbox","VBOX","VS2005R2",
            "VMware, Inc.","VMware","VMWARE",
            "S3 Corp.","Virtual Machine","QEMU","pc-q35","BOCHS","BXPC"
        };

        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            // Skip "." and ".."
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;

            char path[PATH_MAX];
            snprintf(path, sizeof(path), "/sys/firmware/acpi/tables/%s", entry->d_name);

            int fd = open(path, O_RDONLY);
            if (fd == -1) {
                debug("FIRMWARE: could not open ACPI table ", entry->d_name);
                continue;
            }

            struct stat statbuf;
            if (fstat(fd, &statbuf) != 0) {
                debug("FIRMWARE: skipped ", entry->d_name);
                close(fd);
                continue;
            }
            if (S_ISDIR(statbuf.st_mode)) {
                debug("FIRMWARE: skipped directory ", entry->d_name);
                close(fd);
                continue;
            }

            long file_size = statbuf.st_size;
            if (file_size <= 0) {
                debug("FIRMWARE: file empty or error ", entry->d_name);
                close(fd);
                continue;
            }

            char* buffer = static_cast<char*>(malloc(file_size));
            if (!buffer) {
                debug("FIRMWARE: failed to allocate memory for buffer");
                close(fd);
                continue;
            }
            close(fd);

            for (const char* target : targets) {
                size_t targetLen = strlen(target);
                if (targetLen == 0 || file_size < static_cast<long>(targetLen))
                    continue;
                for (long j = 0; j <= file_size - static_cast<long>(targetLen); ++j) {
                    if (memcmp(buffer + j, target, targetLen) == 0) {
                        const char* brand = nullptr;
                        if (strcmp(target, "Parallels Software International") == 0 ||
                            strcmp(target, "Parallels(R)") == 0) {
                            brand = brands::PARALLELS;
                        }
                        else if (strcmp(target, "innotek") == 0 ||
                            strcmp(target, "Oracle") == 0 ||
                            strcmp(target, "VirtualBox") == 0 ||
                            strcmp(target, "vbox") == 0 ||
                            strcmp(target, "VBOX") == 0) {
                            brand = brands::VBOX;
                        }
                        else if (strcmp(target, "VMware, Inc.") == 0 ||
                            strcmp(target, "VMware") == 0 ||
                            strcmp(target, "VMWARE") == 0) {
                            brand = brands::VMWARE;
                        }
                        else if (strcmp(target, "QEMU")) {
                            brand = brands::QEMU;
                        }
                        else if (strcmp(target, "BOCHS") == 0 ||
                            strcmp(target, "BXPC") == 0) {
                            brand = brands::BOCHS;
                        }
                        free(buffer);
                        closedir(dir);
                        if (brand)
                            return core::add(brand);
                        else
                            return true;
                    }
                }
            }
            free(buffer);
        }

        closedir(dir);
        return false;
#else
        return false;
#endif
    }


	/**
	 * @brief Check if the number of accessed files are too low for a human-managed environment
	 * @category Linux
	 * @note idea from https://unprotect.it/technique/xbel-recently-opened-files-check/
	 * @implements VM::FILE_ACCESS_HISTORY
     */
	[[nodiscard]] static bool file_access_history() {
#if (!LINUX)
	    return false;
#else 
	    const std::string xbel_file = util::read_file("~/.local/share/recently-used.xbel");
	    
        if (xbel_file.empty()) {
            debug("FILE_ACCESS_HISTORY: file content is empty");
            return false;
        }
    
        const std::string key = "href";
	
	    u32 count = 0;
	    std::size_t pos = 0;
	
	    while ((pos = xbel_file.find(key, pos)) != std::string::npos) {
	        count++;
	        pos += key.length();
	    }

	    return (count <= 10); 
#endif
	}


    /**
     * @brief Check if no waveform-audio output devices are present in the system
     * @category Windows
     * @implements VM::AUDIO
     */
    [[nodiscard]] static bool audio() {
#if (!WINDOWS)
        return false;
#else
        HKEY hKey = nullptr;
        const LONG err = RegOpenKeyEx(
            HKEY_LOCAL_MACHINE,
            TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\MMDevices\\Audio\\Render"),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &hKey
        );

        if (err != 0L) {
            return true;  
        }

        DWORD subKeyCount = 0;
        RegQueryInfoKey(
            hKey,
            nullptr,   
            nullptr,    
            nullptr,    
            &subKeyCount,  
            nullptr,    
            nullptr,   
            nullptr,    
            nullptr,    
            nullptr,   
            nullptr,    
            nullptr     
        );

        RegCloseKey(hKey);

        return subKeyCount == 0;
#endif
    }


    /**
     * @brief Check if the CPU manufacturer is not known
     * @category x86
     * @implements VM::UNKNOWN_MANUFACTURER
     */
    [[nodiscard]] static bool unknown_manufacturer() {
#if (!x86)
        return false;
#else
        constexpr std::array<const char*, 21> known_ids = { {
            "AuthenticAMD", "CentaurHauls", "CyrixInstead",
            "GenuineIntel", "GenuineIotel", "TransmetaCPU",
            "GenuineTMx86", "Geode by NSC", "NexGenDriven",
            "RiseRiseRise", "SiS SiS SiS ", "UMC UMC UMC ",
            "Vortex86 SoC", "  Shanghai  ", "HygonGenuine",
            "Genuine  RDC", "E2K MACHINE", "VIA VIA VIA ",
            "AMD ISBETTER", "GenuineAO486", "MiSTer AO486"
        } };

        const std::string cpuBrand = cpu::cpu_manufacturer(0);
        for (const char* id : known_ids) {
            if (memcmp(cpuBrand.data(), id, 12) == 0) {
                return false;
            }
        }

        debug("UNKNOWN_MANUFACTURER: CPU brand '", cpuBrand, "' did not match known vendor IDs.");
        return true; // no known manufacturer matched, likely a VM
#endif
    }


	/**
	 * @brief Check if process status matches with nsjail patterns with PID anomalies
	 * @category Linux
     * @implements VM::NSJAIL_PID
	 */
	[[nodiscard]] static bool nsjail_proc_id() {
#if (!LINUX)
        return false;
#else
	    std::ifstream status_file("/proc/self/status");
	    std::string line;
	    bool pid_match = false;
	    bool ppid_match = false;
	
	    while (std::getline(status_file, line)) {
	        if (line.find("Pid:") == 0) {
	            std::string num_str = "";
	            for (char ch : line) {
	                if (isdigit(ch)) {
	                    num_str += ch;
	                }
	            }
	
	            if (num_str.empty()) {
	                return false;
	            }
	
	            if (std::stoi(num_str) == 1) {
	                pid_match = true;
	            }
	        }
	
	        if (line.find("PPid:") == 0) {
	            std::string num_str = "";
	            for (char ch : line) {
	                if (isdigit(ch)) {
	                    num_str += ch;
	                }
	            }
	
	            if (num_str.empty()) {
	                return false;
	            }
	
	            if (std::stoi(num_str) == 0) {
	                ppid_match = true;
	            }
	        }
	    }
	
	    if (pid_match && ppid_match) {
            return core::add(brands::NSJAIL);
        }

        return false;
#endif
	}


    /**
     * @brief Check if the system has a physical TPM by matching the TPM manufacturer against known physical TPM chip vendors
     * @category Windows
     * @note CRB model will succeed, while TIS will fail
     * @author Requiem (https://github.com/NotRequiem)
     * @implements VM::TPM
     */
    [[nodiscard]] static bool tpm() {
#if (!WINDOWS)
        return false;
#else
        struct TbsContext {
            TBS_HCONTEXT hContext = 0;
            explicit TbsContext(const TBS_CONTEXT_PARAMS2& params) {
                Tbsi_Context_Create(reinterpret_cast<PCTBS_CONTEXT_PARAMS>(&params), &hContext);
            }
            ~TbsContext() {
                if (hContext) {
                    Tbsip_Context_Close(hContext);
                }
            }
            bool isValid() const { return hContext != 0; }
        };

        TBS_CONTEXT_PARAMS2 params{};
        params.version = TBS_CONTEXT_VERSION_TWO;
        params.includeTpm20 = 1;
        params.includeTpm12 = 1;

        TbsContext ctx(params);
        if (!ctx.isValid()) {
            return false;
        }

        // Prebuilt TPM2_GetCapability command for TPM_PT_MANUFACTURER
        static constexpr u8 cmd[] = {
            0x80,0x01,             // Tag: TPM_ST_NO_SESSIONS
            0x00,0x00,0x00,0x16,    // Command Size: 22
            0x00,0x00,0x01,0x7A,    // TPM2_GetCapability
            0x00,0x00,0x00,0x06,    // TPM_CAP_TPM_PROPERTIES
            0x00,0x00,0x01,0x05,    // TPM_PT_MANUFACTURER
            0x00,0x00,0x00,0x01     // Property Count: 1
        };

        u8 resp[1024] = {};
        u32 respSize = sizeof(resp);
        if (Tbsip_Submit_Command(ctx.hContext,
            TBS_COMMAND_LOCALITY_ZERO,
            TBS_COMMAND_PRIORITY_NORMAL,
            cmd,
            static_cast<u32>(sizeof(cmd)),
            resp,
            &respSize) != TBS_SUCCESS || respSize < 27) {
            return false;
        }

        const u32 manufacturerVal = (static_cast<u32>(resp[23]) << 24) |
            (static_cast<u32>(resp[24]) << 16) |
            (static_cast<u32>(resp[25]) << 8) |
            static_cast<u32>(resp[26]);
        debug("TPM: Manufacturer -> 0x", std::hex, manufacturerVal, std::dec);

        switch (manufacturerVal) {
            case 0x414D4400u: // "AMD\0"
            case 0x41544D4Cu: // "ATML"
            case 0x4252434Du: // "BRCM"
            case 0x49424D00u: // "IBM\0"
            case 0x49465800u: // "IFX\0"
            case 0x494E5443u: // "INTC"
            case 0x4E534D20u: // "NSM "
            case 0x4E544300u: // "NTC\0"
            case 0x51434F4Du: // "QCOM"
            case 0x534D5343u: // "SMSC"
            case 0x53544D20u: // "STM "
            case 0x54584E00u: // "TXN\0"
            case 0x524F4343u: // "ROCC"
            case 0x4C454E00u: // "LEN\0"
                return false;
            default:
                return true;
        }
#endif
    }


    /**
     * @brief Check for PCI vendor and device IDs that are VM-specific
     * @link https://www.pcilookup.com/?ven=&dev=&action=submit
     * @category Linux, Windows
     * @implements VM::PCI_VM_DEVICE_ID
     */
    [[nodiscard]] static bool pci_vm_device_id() {
#if (!WINDOWS && !LINUX)
        return false;
#else
        struct PCI_Device { u16 vendor_id; u32 device_id; };
        std::vector<PCI_Device> devices;

#if (LINUX)
        const std::string pci_path = "/sys/bus/pci/devices";
#if (CPP >= 17)
        for (const auto& entry : std::filesystem::directory_iterator(pci_path)) {
            std::ifstream vf(entry.path() / "vendor"), df(entry.path() / "device");
            if (!vf || !df) continue;
            u16 vid = 0; u32 did = 0;
            vf >> std::hex >> vid;
            df >> std::hex >> did;
            devices.push_back({ vid, did });
        }
#else
        DIR* dir = opendir(pci_path.c_str());
        if (!dir) return false;
        while (struct dirent* ent = readdir(dir)) {
            std::string name = ent->d_name;
            if (name == "." || name == "..") continue;
            std::string base = pci_path + "/" + name;
            std::ifstream vf(base + "/vendor"), df(base + "/device");
            if (!vf || !df) continue;
            u16 vid = 0; u32 did = 0;
            vf >> std::hex >> vid;
            df >> std::hex >> did;
            devices.push_back({ vid, did });
        }
        closedir(dir);
#endif

#elif (WINDOWS)
        HKEY hKey = nullptr;

        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
            TEXT("SYSTEM\\CurrentControlSet\\Enum\\PCI"),
            0, KEY_READ, &hKey) != 0L)
            return false;

        for (DWORD i = 0; ; ++i) {
            TCHAR instanceName[256];
            DWORD cbName = _countof(instanceName);
            if (RegEnumKeyEx(hKey, i, instanceName, &cbName,
                nullptr, nullptr, nullptr, nullptr) != 0L)
                break;

            HKEY hInstKey = nullptr;
            if (RegOpenKeyEx(hKey, instanceName, 0, KEY_READ, &hInstKey) != 0L)
                continue;

            DWORD type = 0, cbData = 0;
            if (RegQueryValueEx(hInstKey, TEXT("HardwareID"),
                nullptr, &type, nullptr, &cbData) == 0L
                && type == REG_MULTI_SZ && cbData > 0)
            {
                std::vector<TCHAR> buffer(cbData / sizeof(TCHAR));
                if (RegQueryValueEx(hInstKey, TEXT("HardwareID"),
                    nullptr, nullptr,
                    reinterpret_cast<BYTE*>(buffer.data()),
                    &cbData) == 0L)
                {
                    for (TCHAR* entry = buffer.data(); *entry; entry += lstrlen(entry) + 1)
                    {
                        TCHAR* pVen = StrStrI(entry, TEXT("VEN_"));
                        TCHAR* pDev = StrStrI(entry, TEXT("DEV_"));
                        if (!pVen || !pDev)
                            continue;

                        u16 vid = 0; u32 did = 0;
                        _stscanf_s(pVen + 4, TEXT("%4hx"), &vid);    
                        _stscanf_s(pDev + 4, TEXT("%8x"), &did);   

                        devices.push_back({ vid, did });
                        break; 
                    }
                }
            }

            RegCloseKey(hInstKey);
        }

        RegCloseKey(hKey);
#endif

        for (auto& d : devices) {
            const u64 id64 = (static_cast<u64>(d.vendor_id) << 32) | d.device_id;
            const u32 id32 = (static_cast<u32>(d.vendor_id) << 16) | static_cast<u32>(d.device_id);

            switch (id32) {
            // Red Hat + Virtio
            case 0x1af40022: case 0x1af41000: case 0x1af41001: case 0x1af41002:
            case 0x1af41003: case 0x1af41004: case 0x1af41005: case 0x1af41009:
            case 0x1af41041: case 0x1af41042: case 0x1af41043: case 0x1af41044:
            case 0x1af41045: case 0x1af41048: case 0x1af41049: case 0x1af41050:
            case 0x1af41052: case 0x1af41053: case 0x1af4105a: case 0x1af41100:
            case 0x1af41110: case 0x1af41b36:
                debug("PCI_VM_DEVICE_ID: Detected Red Hat + Virtio device -> ", id32);
                return true;

            // VMware
            case 0x15ad0405: case 0x15ad0710: case 0x15ad0720: case 0x15ad0740:
            case 0x15ad0770: case 0x15ad0774: case 0x15ad0778: case 0x15ad0779:
            case 0x15ad0790: case 0x15ad07a0: case 0x15ad07b0: case 0x15ad07c0:
            case 0x15ad07e0: case 0x15ad07f0: case 0x15ad0801: case 0x15ad0820:
            case 0x15ad1977: case 0xfffe0710:
            case 0x0e0f0001: case 0x0e0f0002: case 0x0e0f0003: case 0x0e0f0004:
            case 0x0e0f0005: case 0x0e0f0006: case 0x0e0f000a: case 0x0e0f8001:
            case 0x0e0f8002: case 0x0e0f8003: case 0x0e0ff80a:
                debug("PCI_VM_DEVICE_ID: Detected VMWARE device -> ", id32);
                return core::add(brands::VMWARE);

            // Red Hat + QEMU
            case 0x1b360001: case 0x1b360002: case 0x1b360003: case 0x1b360004:
            case 0x1b360005: case 0x1b360008: case 0x1b360009: case 0x1b36000b:
            case 0x1b36000c: case 0x1b36000d: case 0x1b360010: case 0x1b360011:
            case 0x1b360013: case 0x1b360100:
                debug("PCI_VM_DEVICE_ID: Detected Red Hat + QEMU device -> ", id32);
                return core::add(brands::QEMU);

            // QEMU
            case 0x06270001: case 0x1d1d1f1f: case 0x80865845: case 0x1d6b0200:
                debug("PCI_VM_DEVICE_ID: Detected QEMU device -> ", id32);
                return core::add(brands::QEMU);

            // vGPUs (NVIDIA + others)
            case 0x10de0fe7: case 0x10de0ff7: case 0x10de118d: case 0x10de11b0:
            case 0x1ec6020f:
                debug("PCI_VM_DEVICE_ID: Detected virtual gpu device -> ", id32);
                return true;

            // VirtualBox
            case 0x80ee0021: case 0x80ee0022: case 0x80eebeef: case 0x80eecafe:
                debug("PCI_VM_DEVICE_ID: Detected VirtualBox device -> ", id32);
                return core::add(brands::VBOX);

            // Hyper-V
            case 0x1f3f9002: case 0x1f3f9004: case 0x1f3f9009:
            case 0x808637d9: case 0x14145353:
                if (util::hyper_x() == HYPERV_ARTIFACT_VM) continue;
                debug("PCI_VM_DEVICE_ID: Detected Hyper-V device -> ", id32);
                return core::add(brands::HYPERV);

            // Parallels
            case 0x1ab84000: case 0x1ab84005: case 0x1ab84006:
                debug("PCI_VM_DEVICE_ID: Detected Parallels device -> ", id32);
                return core::add(brands::PARALLELS);

            // Xen
            case 0x5853c000: case 0xfffd0101: case 0x5853c147:
            case 0x5853c110: case 0x5853c200: case 0x58530001:
                debug("PCI_VM_DEVICE_ID: Detected Xen device -> ", id32);
                return core::add(brands::XEN);

            // Connectix
            case 0x29556e61:
                debug("PCI_VM_DEVICE_ID: Detected VirtualPC device -> ", id32);
                return core::add(brands::VPC);
            }

            // Devices with 32 bit device ids
            switch (id64) {
                case 0x0000000011061100ULL:
                case 0x000000001af41100ULL:
                case 0x000000001b361100ULL:
                case 0x0000000010ec1100ULL:
                case 0x0000000010331100ULL:
                case 0x0000000080861100ULL:
                case 0x0000000010131100ULL:
                case 0x00000000106b1100ULL:
                case 0x0000000010221100ULL:
                    debug("PCI_VM_DEVICE_ID: Detected QEMU device -> ", id64);
                    return core::add(brands::QEMU);

                case 0x0000000015ad0800ULL:  // Hypervisor ROM Interface
                    debug("PCI_VM_DEVICE_ID: Detected Hypervisor ROM interface -> ", id64);
                    return core::add(brands::VMWARE);
            }
        }

        return false;
#endif
    }
    

    /**
     * @brief Check for QEMU's hot-plug signature
     * @category Windows
     * @author Requiem (https://github.com/NotRequiem)
     * @implements VM::QEMU_PASSTHROUGH
     */
    [[nodiscard]] static bool qemu_passthrough()
    {
#if (!WINDOWS)
        return false;
#else
        auto __iswdigit = [](wchar_t c) constexpr noexcept {
            return (c >= L'0' && c <= L'9');
        };

        HDEVINFO hDevInfo = SetupDiGetClassDevsW(
            &GUID_DEVCLASS_DISPLAY,
            nullptr,
            nullptr,
            DIGCF_PRESENT);
        if (hDevInfo == INVALID_HANDLE_VALUE)
            return false;

        SP_DEVINFO_DATA devInfo = {};
        devInfo.cbSize = sizeof(devInfo);
        const DEVPROPKEY key = DEVPKEY_Device_LocationPaths;

        for (DWORD idx = 0; SetupDiEnumDeviceInfo(hDevInfo, idx, &devInfo); ++idx)
        {
            DEVPROPTYPE propType = 0;
            DWORD requiredSize = 0;

            SetupDiGetDevicePropertyW(
                hDevInfo, &devInfo, &key, &propType,
                nullptr, 0, &requiredSize, 0);
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || requiredSize == 0)
                continue;

            std::vector<BYTE> buffer(requiredSize);
            if (!SetupDiGetDevicePropertyW(
                hDevInfo, &devInfo, &key, &propType,
                buffer.data(), requiredSize, &requiredSize, 0))
                continue;

            const wchar_t* ptr = reinterpret_cast<const wchar_t*>(buffer.data());
            while (*ptr)
            {
                std::wstring_view path(ptr);

                if (path.substr(0, 17) != L"PCIROOT(0)#PCI(") {
                    ptr += path.size() + 1;
                    continue;
                }

                constexpr wchar_t kAcpiSlotPrefix[] = L"#ACPI(S";
                std::size_t pos = path.find(kAcpiSlotPrefix);
                while (pos != std::wstring_view::npos)
                {
                    // check for "#ACPI(Sxx_y)" pattern: two digits at +7/+8, '_' then ')'
                    if (pos + 10 < path.size() &&
                        __iswdigit(path[pos + 7]) &&
                        __iswdigit(path[pos + 8]) &&
                        path[pos + 9] == L'_' &&
                        path[pos + 10] == L')')
                    {
                        SetupDiDestroyDeviceInfoList(hDevInfo);
                        return true;
                    }
                    pos = path.find(kAcpiSlotPrefix, pos + 1);
                }

                ptr += path.size() + 1;
            }
        }

        SetupDiDestroyDeviceInfoList(hDevInfo);
        return false;
#endif
    }
    // ADD NEW TECHNIQUE FUNCTION HERE
    
    
    
    
    
    
    
    









    struct core {
        struct technique {
            u8 points = 0;                // this is the certainty score between 0 and 100
            std::function<bool()> run;    // this is the technique function itself
        
            technique() : points(0), run(nullptr) {}

            technique(u8 points, std::function<bool()> run) : points(points), run(run) {}
        };

        struct custom_technique {
            u8 points;
            u16 id;
            std::function<bool()> run;
        };

        // initial technique list, this is where all the techniques are stored
        static std::pair<enum_flags, technique> technique_list[];
    
        // the actual table, which is derived from the list above and will be 
        // used for most functionalities related to technique interactions
        static std::map<enum_flags, technique> technique_table;

        // specific to VM::add_custom(), where custom techniques will be stored here
        static std::vector<custom_technique> custom_table;
        
        // VM scoreboard table specifically for VM::brand()
        static std::map<const char*, brand_score_t> brand_scoreboard;

        // directly return when adding a brand to the scoreboard for a more succint expression
        static inline bool add(const char* p_brand, const char* extra_brand = "") noexcept {
            core::brand_scoreboard.at(p_brand)++;
            if (strcmp(extra_brand, "") != 0) {
                core::brand_scoreboard.at(p_brand)++;
            }
            return true;
        }

        // assert if the flag is enabled, far better expression than typing std::bitset member functions
        [[nodiscard]] static inline bool is_disabled(const flagset& flags, const u8 flag_bit) noexcept {
            return (!flags.test(flag_bit));
        }

        // same as above but for checking enabled flags
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
                generate_default(flags);
                return;
            }

            if (flags.test(DEFAULT)) {
                return;
            }
            
            if (flags.test(ALL)) {
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
                generate_default(flags);
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

                // both of these depend interchangeably, so both scores
                // are "merged" by making it 100 instead of 200 combined.
                // the GPU ones are that exception, and they will be run
                // in the post-processing stage within run_all();
                if (
                    (technique_macro == VM::GPU_CAPABILITIES) ||
                    (technique_macro == VM::GPU_VM_STRINGS)
                ) {
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

                // run the technique
                const bool result = technique_data.run();

                // accumulate the points if the technique detected a VM
                if (result) {
                    points += technique_data.points;

                    // this is specific to VM::detected_count() which 
                    // returns the number of techniques that found a VM.
                    detected_count_num++;
                }

                // store the current technique result to the cache
                if (memo_enabled) {
                    memo::cache_store(technique_macro, result, technique_data.points);
                }

                // for things like VM::detect() and VM::percentage(),
                // a score of 150+ is guaranteed to be a VM, so
                // there's no point in running the rest of the techniques
                // (unless the threshold is set to be higher, but it's the 
                // same story here nonetheless, except the threshold is 300)
                if (
                    (shortcut) && 
                    (points >= threshold_points)
                ) {
                    return points;
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


            // points post-processing stage
            const std::vector<enum_flags> post_processed_techniques = {
                GPU_CAPABILITIES,
                GPU_VM_STRINGS
            };

            auto merge_scores = [&](
                const enum_flags a, 
                const enum_flags b, 
                const u8 new_score
            ) {
                if (
                    core::is_disabled(flags, a) ||
                    core::is_disabled(flags, b)
                ) {
                    return;
                }

                const bool result_a = check(a);
                const bool result_b = check(b);

                if (result_a && result_b) {
                    points += new_score;
                    return;
                } else if ((result_a == false) && (result_b == false)) {
                    return;
                } else {
                    enum_flags tmp_flag;

                    if (result_a == true) {
                        tmp_flag = a;
                    } else {
                        tmp_flag = b;
                    }

                    const technique tmp = technique_table.at(tmp_flag);
                    points += tmp.points;
                }
            };

            merge_scores(GPU_CAPABILITIES, GPU_VM_STRINGS, 100); // instead of 200, it's 100 now

            return points;
        }















































        /**
         * basically what this entire recursive variadic template inheritance 
         * fuckery does is manage the variadic arguments being given through 
         * the arg_handler function, which could either be a std::bitset<N>, 
         * a uint8_t, or a combination of both of them. This will handle 
         * both argument types and implement them depending on what their 
         * types are. If it's a std::bitset<N>, do the |= operation on 
         * flag_collector. If it's a uint8_t, simply .set() that into the 
         * flag_collector. That's the gist of it.
         *
         * Also I won't even deny, the majority of this section was 90% generated
         * by chatgpt. Can't be arsed with this C++ variadic templatisation shit.
         * Like is it really my fault that I have a hard time understanging C++'s 
         * god awful metaprogramming designs? And don't even get me started on SNIFAE. 
         * 
         * You don't need an IQ of 3 digits to realise how dogshit this language
         * is, when you end up in situations where there's a few correct solutions
         * to a problem, but with a billion ways you can do the same thing but in 
         * the "wrong" way. I genuinely can't wait for Carbon to come out.
         */
    public:
        static flagset flag_collector;
        static flagset disabled_flag_collector;

        static void generate_default(flagset& flags) {
            // set all bits to 1
            flags.set();

            // disable all non-default techniques
            flags.flip(VMWARE_DMESG);
            flags.flip(PORT_CONNECTORS);
            flags.flip(TEMPERATURE);
            flags.flip(LSHW_QEMU);

            // disable all the settings flags
            flags.flip(NO_MEMO);
            flags.flip(HIGH_THRESHOLD);
            flags.flip(NULL_ARG);
            flags.flip(DYNAMIC);
            flags.flip(MULTIPLE);
            flags.flip(ALL);
        }

        static void generate_all(flagset& flags) {
            // set all bits to 1
            flags.set();

            // disable all the settings flags
            flags.flip(NO_MEMO);
            flags.flip(HIGH_THRESHOLD);
            flags.flip(NULL_ARG);
            flags.flip(DYNAMIC);
            flags.flip(MULTIPLE);
            flags.flip(DEFAULT);
        }

        static void generate_current_disabled_flags(flagset& flags) {
            const bool setting_no_memo = flags.test(NO_MEMO);
            const bool setting_high_threshold = flags.test(HIGH_THRESHOLD);
            const bool setting_dynamic = flags.test(DYNAMIC);
            const bool setting_multiple = flags.test(MULTIPLE);
            const bool setting_all = flags.test(ALL);
            const bool setting_default = flags.test(DEFAULT);

            if (disabled_flag_collector.count() == 0) {
                return;
            } else {
                flags &= disabled_flag_collector;
            }

            flags.set(NO_MEMO, setting_no_memo);
            flags.set(HIGH_THRESHOLD, setting_high_threshold);
            flags.set(DYNAMIC, setting_dynamic);
            flags.set(MULTIPLE, setting_multiple);
            flags.set(ALL, setting_all);
            flags.set(DEFAULT, setting_default);
        }

        static void disable_flagset_manager(const flagset& flags) {
            disabled_flag_collector = flags;
        }

        static void disable_flag_manager(const enum_flags flag) {
            disabled_flag_collector.set(flag, false);
        }

        static void flag_manager(const enum_flags flag) {
            if (
                (flag == INVALID) ||
                (flag > enum_size)
            ) {
                throw std::invalid_argument("Non-flag or invalid flag provided for VM::detect(), aborting");
            }

            if (flag == DEFAULT) {
                generate_default(flag_collector);
            } else if (flag == ALL) {
                generate_all(flag_collector);
            } else {
                flag_collector.set(flag);
            }
        }

        // Define a base class for different types
        struct TestHandler {
            virtual ~TestHandler() = default;

            virtual void handle(const flagset& flags) {
                disable_flagset_manager(flags);
            }

            virtual void handle(const enum_flags flag) {
                flag_manager(flag);
            }
        };

        // Define a base class for different types
        struct DisableTestHandler {
            virtual ~DisableTestHandler() = default;

            virtual void disable_handle(const enum_flags flag) {
                disable_flag_manager(flag);
            }
        };

        // Define derived classes for specific type implementations
        struct TestBitsetHandler : public TestHandler {
            using TestHandler::handle; 

            void handle(const flagset& flags) override {
                disable_flagset_manager(flags);
            }
        };

        struct TestUint8Handler : public TestHandler {
            using TestHandler::handle;  

            void handle(const enum_flags flag) override {
                flag_manager(flag);
            }
        };

        struct DisableTestUint8Handler : public DisableTestHandler {
            using DisableTestHandler::disable_handle;  

            void disable_handle(const enum_flags flag) override {
                disable_flag_manager(flag);
            }
        };

        // Define a function to dispatch handling based on type
        template <typename T>
        static void dispatch(const T& value, TestHandler& handler) {
            handler.handle(value);
        }

        // Define a function to dispatch handling based on type
        template <typename T>
        static void disable_dispatch(const T& value, DisableTestHandler& handler) {
            handler.disable_handle(value);
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
            DisableTestUint8Handler Disableuint8Handler;

            if (isType<flagset>(first)) {
                throw std::invalid_argument("Arguments must not contain VM::DEFAULT or VM::ALL, only technique flags are accepted (view the documentation for a full list)");
            } else if (isType<enum_flags>(first)) {
                disable_dispatch(first, Disableuint8Handler);
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
        static VMAWARE_CONSTEXPR flagset arg_handler(Args&&... args) {
            flag_collector.reset();
            generate_default(disabled_flag_collector);

            if VMAWARE_CONSTEXPR(is_empty<Args...>()) {
                generate_default(flag_collector);
                return flag_collector;
            }
            else {
                // set the bits in the flag, can take in either an enum value or a std::bitset
                handleArgs(std::forward<Args>(args)...);

                if (flag_collector.count() == 0) {
                    generate_default(flag_collector);
                }

                bool no_memo = flag_collector.test(NO_MEMO);
                bool high_threshold = flag_collector.test(HIGH_THRESHOLD);
                bool dynamic_flag = flag_collector.test(DYNAMIC);
                bool multiple = flag_collector.test(MULTIPLE);
                bool all_flag = flag_collector.test(ALL);
                bool default_flag = flag_collector.test(DEFAULT);

                flag_collector &= disabled_flag_collector;

                flag_collector.set(NO_MEMO, no_memo);
                flag_collector.set(HIGH_THRESHOLD, high_threshold);
                flag_collector.set(DYNAMIC, dynamic_flag);
                flag_collector.set(MULTIPLE, multiple);
                flag_collector.set(ALL, all_flag);
                flag_collector.set(DEFAULT, default_flag);

                // handle edgecases
                core::flag_sanitizer(flag_collector);
                return flag_collector;
            }
        }

        // same as above but for VM::disable which only accepts technique flags
        template <typename... Args>
        static void disabled_arg_handler(Args&&... args) {
            disabled_flag_collector.reset();

            generate_default(disabled_flag_collector);

            if VMAWARE_CONSTEXPR (is_empty<Args...>()) {
                throw std::invalid_argument("VM::DISABLE() must contain a flag");
            }

            handle_disabled_args(std::forward<Args>(args)...);

            // check if a settings flag is set, which is not valid
            if (core::is_setting_flag_set(disabled_flag_collector)) {
                throw std::invalid_argument("VM::DISABLE() must not contain a settings flag, they are disabled by default anyway");
            }

            return;
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

#if (MSVC)
    #define ASSUME(expr) __assume(expr)
#elif (CLANG)
    #define ASSUME(expr) __builtin_assume(expr)
#elif (GCC)
    // no __builtin_assume, but __builtin_unreachable gives same hint
    #define ASSUME(expr)               \
        do {                             \
          if (!(expr))                   \
            __builtin_unreachable();     \
        } while (0)
#else
    #define ASSUME(expr) ((void)0)
#endif

        ASSUME(flag_bit < technique_end);

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

        // used for later
        u16 score = 0;

        // are all the techiques already run? if not, run them 
        // to fetch the necessary info to determine the brand
        if (!memo::all_present() || core::is_enabled(flags, NO_MEMO)) {
            score = core::run_all(flags);
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

        // goofy ass C++11 and C++14 linker error workaround.
        // And yes, this does look stupid.
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

        // if all brands have a point of 0, return 
        // "Unknown" (no relevant brands were found)
        if (brands.empty()) {
            return brands::NULL_BRAND;
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
        auto merge = [&](const char* a, const char* b, const char* result) -> void {
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
        auto triple_merge = [&](const char* a, const char* b, const char* c, const char* result) -> void {
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
                merge(TMP_VPC, TMP_HYPERV, TMP_HYPERV_VPC);
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
        merge(TMP_AZURE, TMP_HYPERV,     TMP_AZURE);
        merge(TMP_AZURE, TMP_VPC,        TMP_AZURE);
        merge(TMP_AZURE, TMP_HYPERV_VPC, TMP_AZURE);

        merge(TMP_NANOVISOR, TMP_HYPERV,     TMP_NANOVISOR);
        merge(TMP_NANOVISOR, TMP_VPC,        TMP_NANOVISOR);
        merge(TMP_NANOVISOR, TMP_HYPERV_VPC, TMP_NANOVISOR);
        
        merge(TMP_QEMU,     TMP_KVM,        TMP_QEMU_KVM);
        merge(TMP_KVM,      TMP_HYPERV,     TMP_KVM_HYPERV);
        merge(TMP_QEMU,     TMP_HYPERV,     TMP_QEMU_KVM_HYPERV);
        merge(TMP_QEMU_KVM, TMP_HYPERV,     TMP_QEMU_KVM_HYPERV);
        merge(TMP_KVM,      TMP_KVM_HYPERV, TMP_KVM_HYPERV);
        merge(TMP_QEMU,     TMP_KVM_HYPERV, TMP_QEMU_KVM_HYPERV);
        merge(TMP_QEMU_KVM, TMP_KVM_HYPERV, TMP_QEMU_KVM_HYPERV);

        triple_merge(TMP_QEMU, TMP_KVM, TMP_KVM_HYPERV, TMP_QEMU_KVM_HYPERV);

        merge(TMP_VMWARE, TMP_FUSION,      TMP_FUSION);
        merge(TMP_VMWARE, TMP_EXPRESS,     TMP_EXPRESS);
        merge(TMP_VMWARE, TMP_ESX,         TMP_ESX);
        merge(TMP_VMWARE, TMP_GSX,         TMP_GSX);
        merge(TMP_VMWARE, TMP_WORKSTATION, TMP_WORKSTATION);

        merge(TMP_VMWARE_HARD, TMP_VMWARE,      TMP_VMWARE_HARD);
        merge(TMP_VMWARE_HARD, TMP_FUSION,      TMP_VMWARE_HARD);
        merge(TMP_VMWARE_HARD, TMP_EXPRESS,     TMP_VMWARE_HARD);
        merge(TMP_VMWARE_HARD, TMP_ESX,         TMP_VMWARE_HARD);
        merge(TMP_VMWARE_HARD, TMP_GSX,         TMP_VMWARE_HARD);
        merge(TMP_VMWARE_HARD, TMP_WORKSTATION, TMP_VMWARE_HARD);


        // this is added in case the lib detects a non-Hyper-X technique.
        // A Hyper-X affiliated technique should make the overall score
        // as 0, but this isn't the case if non-Hyper-X techniques were
        // found. There may be a conflict between an Unknown and Hyper-V
        // brand, which is exactly what this section is meant to handle.
        // It will remove the Hyper-V artifact brand string from the 
        // std::map to pave the way for other brands to take precedence.
        // One of the main reasons to do this is because it would look
        // incredibly awkward if the brand was "Hyper-V artifacts (not an
        // actual VM)", clearly stating that it's NOT a VM while the VM
        // confirmation is true and percentage is 100%, as if that makes
        // any sense whatsoever. That's what this part fixes.
        if (brands.count(TMP_HYPERV_ARTIFACT) > 0) {
            if (score > 0) {
                brands.erase(TMP_HYPERV_ARTIFACT);
            }
        }


        // the brand element, which stores the NAME (const char*) and the SCORE (u8)
        using brand_element_t = std::pair<const char*, brand_score_t>;

        // convert the std::map into a std::vector, easier to handle this way
        std::vector<brand_element_t> vec(brands.begin(), brands.end());

        // sort the relevant brands vector so that the brands with 
        // the highest score appears first in descending order
        std::sort(vec.begin(), vec.end(), [](
            const brand_element_t &a,
            const brand_element_t &b
        ) {
            return a.second > b.second;
        });

        std::string ret_str = brands::NULL_BRAND;




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

        ASSUME(points < maximum_points);

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

        ASSUME(points < maximum_points);

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
        const u8 percent,
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

        ASSUME(percent > 0 && percent <= 100);

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
        core::disabled_arg_handler(args...);

        return core::disabled_flag_collector;
    }


    /**
     * @brief This will convert the technique flag into a string, which will correspond to the technique name
     * @param single technique flag in VM structure
     */
    [[nodiscard]] static std::string flag_to_string(const enum_flags flag) {
        switch (flag) {
            case VMID: return "VMID";
            case CPU_BRAND: return "CPU_BRAND";
            case HYPERVISOR_BIT: return "HYPERVISOR_BIT";
            case HYPERVISOR_STR: return "HYPERVISOR_STR";
            case TIMER: return "TIMER";
            case THREAD_COUNT: return "THREAD_COUNT";
            case MAC: return "MAC";
            case TEMPERATURE: return "TEMPERATURE";
            case SYSTEMD: return "SYSTEMD";
            case CVENDOR: return "CVENDOR";
            case CTYPE: return "CTYPE";
            case DOCKERENV: return "DOCKERENV";
            case DMIDECODE: return "DMIDECODE";
            case DMESG: return "DMESG";
            case HWMON: return "HWMON";
            case DLL: return "DLL";
            case REGISTRY_KEYS: return "REGISTRY_KEYS";
            case FILES: return "VM_FILES";
            case HWMODEL: return "HWMODEL";
            case DISK_SIZE: return "DISK_SIZE";
            case VBOX_DEFAULT: return "VBOX_DEFAULT";
            case VBOX_NETWORK: return "VBOX_NETWORK";
            case WINE: return "WINE";
            case POWER_CAPABILITIES: return "POWER_CAPABILITIES";
            case PROCESSES: return "PROCESSES";
            case LINUX_USER_HOST: return "LINUX_USER_HOST";
            case GAMARUE: return "GAMARUE";
            case BOCHS_CPU: return "BOCHS_CPU";
            case MAC_MEMSIZE: return "MAC_MEMSIZE";
            case MAC_IOKIT: return "MAC_IOKIT";
            case IOREG_GREP: return "IOREG_GREP";
            case MAC_SIP: return "MAC_SIP";
            case REGISTRY_VALUES: return "REGISTRY_VALUES";
            case VPC_INVALID: return "VPC_INVALID";
            case SIDT: return "SIDT";
            case SGDT: return "SGDT";
            case SLDT: return "SLDT";
            case SMSW: return "SMSW";
            case VMWARE_IOMEM: return "VMWARE_IOMEM";
            case VMWARE_IOPORTS: return "VMWARE_IOPORTS";
            case VMWARE_SCSI: return "VMWARE_SCSI";
            case VMWARE_DMESG: return "VMWARE_DMESG";
            case VMWARE_STR: return "VMWARE_STR";
            case VMWARE_BACKDOOR: return "VMWARE_BACKDOOR";
            case MUTEX: return "MUTEX";
            case ODD_CPU_THREADS: return "ODD_CPU_THREADS";
            case INTEL_THREAD_MISMATCH: return "INTEL_THREAD_MISMATCH";
            case XEON_THREAD_MISMATCH: return "XEON_THREAD_MISMATCH";
            case AMD_THREAD_MISMATCH: return "AMD_THREAD_MISMATCH";
            case CUCKOO_DIR: return "CUCKOO_DIR";
            case CUCKOO_PIPE: return "CUCKOO_PIPE";
            case HYPERV_HOSTNAME: return "HYPERV_HOSTNAME";
            case GENERAL_HOSTNAME: return "GENERAL_HOSTNAME";
            case DISPLAY: return "DISPLAY";
            case DEVICE_STRING: return "DEVICE_STRING";
            case BLUESTACKS_FOLDERS: return "BLUESTACKS_FOLDERS";
            case CPUID_SIGNATURE: return "CPUID_SIGNATURE";
            case KGT_SIGNATURE: return "KGT_SIGNATURE";
            case QEMU_VIRTUAL_DMI: return "QEMU_VIRTUAL_DMI";
            case QEMU_USB: return "QEMU_USB";
            case HYPERVISOR_DIR: return "HYPERVISOR_DIR";
            case UML_CPU: return "UML_CPU";
            case KMSG: return "KMSG";
            case VBOX_MODULE: return "VBOX_MODULE";
            case SYSINFO_PROC: return "SYSINFO_PROC";
            case DMI_SCAN: return "DMI_SCAN";
            case SMBIOS_VM_BIT: return "SMBIOS_VM_BIT";
            case PODMAN_FILE: return "PODMAN_FILE";
            case WSL_PROC: return "WSL_PROC";
            case DRIVERS: return "DRIVERS";
            case DISK_SERIAL: return "DISK_SERIAL";
            case PORT_CONNECTORS: return "PORT_CONNECTORS";
            case IVSHMEM: return "IVSHMEM";
            case GPU_VM_STRINGS: return "GPU_STRINGS";
            case GPU_CAPABILITIES: return "GPU_CAPABILITIES";
            case DEVICE_HANDLES: return "DEVICE_HANDLES";
            case LOGICAL_PROCESSORS: return "LOGICAL_PROCESSORS";
            case PHYSICAL_PROCESSORS: return "PHYSICAL_PROCESSORS";
            case QEMU_FW_CFG: return "QEMU_FW_CFG";
            case LSHW_QEMU: return "LSHW_QEMU";
            case VIRTUAL_PROCESSORS: return "VIRTUAL_PROCESSORS";
            case HYPERV_QUERY: return "HYPERV_QUERY";
            case POOLS: return "POOLS";
            case AMD_SEV: return "AMD_SEV";
            case VIRTUAL_REGISTRY: return "VIRTUAL_REGISTRY";
            case FIRMWARE: return "FIRMWARE";
            case FILE_ACCESS_HISTORY: return "FILE_ACCESS_HISTORY";
            case AUDIO: return "AUDIO";
            case UNKNOWN_MANUFACTURER: return "UNKNOWN_MANUFACTURER";
            case NSJAIL_PID: return "NSJAIL_PID";
            case TPM: return "TPM";
            case PCI_VM_DEVICE_ID: return "PCI_VM_DEVICE_ID";
            case QEMU_PASSTHROUGH: return "QEMU_PASSTHROUGH";
            // ADD NEW CASE HERE FOR NEW TECHNIQUE
            default: return "Unknown flag";
        }
    }


    /**
     * @brief Fetch all the brands that were detected in a vector
     * @param any flag combination in VM structure or nothing
     * @return std::vector<VM::enum_flags>
     */
    template <typename ...Args>
    static std::vector<enum_flags> detected_enums(Args ...args) {
        const flagset flags = core::arg_handler(args...);

        std::vector<enum_flags> tmp{};

        // this will loop through all the enums in the technique_vector variable,
        // and then checks each of them and outputs the enum that was detected
        for (const auto technique_enum : technique_vector) {
            if (
                (flags.test(technique_enum)) &&
                (check(static_cast<enum_flags>(technique_enum)))
            ) {
                tmp.push_back(static_cast<enum_flags>(technique_enum));
            }
        }

        return tmp;
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

        ASSUME(percent <= 100);

        // check if the flag provided is a setting flag, which isn't valid.
        if (static_cast<u8>(flag) >= technique_end) {
            throw_error("The flag is not a technique flag");
        }

        using table_t =  std::map<enum_flags, core::technique>;

        auto modify = [](table_t &table, const enum_flags flag, const u8 percent) -> void {
            core::technique &tmp = table.at(flag);
            table[flag].points = percent;
            table[flag].run = tmp.run;
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
            { brands::HYPERV, "Hypervisor (type 2)" }, // to clarify you're running under a Hyper-V guest VM
            { brands::AZURE_HYPERV, "Hypervisor (type 1)" },
            { brands::NANOVISOR, "Hypervisor (type 1)" },
            { brands::KVM, "Hypervisor (type 1)" },
            { brands::KVM_HYPERV, "Hypervisor (type 1)" },
            { brands::QEMU_KVM_HYPERV, "Hypervisor (type 1)" },
            { brands::QEMU_KVM, "Hypervisor (type 1)" },
            { brands::INTEL_HAXM, "Hypervisor (type 1)" },
            { brands::INTEL_KGT, "Hypervisor (type 1)" },
            { brands::SIMPLEVISOR, "Hypervisor (type 1)" },
            { brands::OPENSTACK, "Hypervisor (type 1)" },
            { brands::KUBEVIRT, "Hypervisor (type 1)" },
            { brands::POWERVM, "Hypervisor (type 1)" },
            { brands::AWS_NITRO, "Hypervisor (type 1)" },
            { brands::LKVM, "Hypervisor (type 1)" },
            { brands::NOIRVISOR, "Hypervisor (type 1)" },
            { brands::WSL, "Hypervisor (Type 1)" }, // Type 1-derived lightweight VM system

            // type 2
            { brands::BHYVE, "Hypervisor (type 2)" },
            { brands::VBOX, "Hypervisor (type 2)" },
            { brands::VMWARE, "Hypervisor (type 2)" },
            { brands::VMWARE_EXPRESS, "Hypervisor (type 2)" },
            { brands::VMWARE_GSX, "Hypervisor (type 2)" },
            { brands::VMWARE_WORKSTATION, "Hypervisor (type 2)" },
            { brands::VMWARE_FUSION, "Hypervisor (type 2)" },
            { brands::VMWARE_HARD, "Hypervisor (type 2)" },
            { brands::PARALLELS, "Hypervisor (type 2)" },
            { brands::VPC, "Hypervisor (type 2)" },
            { brands::NVMM, "Hypervisor (type 2)" },
            { brands::BSD_VMM, "Hypervisor (type 2)" },
            { brands::HYPERV_VPC, "Hypervisor (type 2)" },

            // sandbox
            { brands::CUCKOO, "Sandbox" },
            { brands::SANDBOXIE, "Sandbox" },
            { brands::HYBRID, "Sandbox" },
            { brands::CWSANDBOX, "Sandbox" },
            { brands::JOEBOX, "Sandbox" },
            { brands::ANUBIS, "Sandbox" },
            { brands::COMODO, "Sandbox" },
            { brands::THREATEXPERT, "Sandbox" },
            { brands::QIHOO, "Sandbox" },
            { brands::HYPERVISOR_PHANTOM, "Sandbox" },

            // misc
            { brands::BOCHS, "Emulator" },
            { brands::BLUESTACKS, "Emulator" },
            { brands::NEKO_PROJECT, "Emulator" },
            { brands::QEMU, "Emulator/Hypervisor (type 2)" },
            { brands::JAILHOUSE, "Partitioning Hypervisor" },
            { brands::UNISYS, "Partitioning Hypervisor" },
            { brands::DOCKER, "Container" },
            { brands::PODMAN, "Container" },
            { brands::OPENVZ, "Container" },
            { brands::LMHS, "Hypervisor (unknown type)" },
            { brands::WINE, "Compatibility layer" },
            { brands::INTEL_TDX, "Trusted Domain" },
            { brands::APPLE_VZ, "Unknown" },
            { brands::UML, "Paravirtualised/Hypervisor (type 2)" },
            { brands::AMD_SEV, "VM encryptor" },
            { brands::AMD_SEV_ES, "VM encryptor" },
            { brands::AMD_SEV_SNP, "VM encryptor" },
            { brands::GCE, "Cloud VM service" },
            { brands::NSJAIL, "Process isolator" },
            { brands::HYPERV_ARTIFACT, "Unknown" }, // This refers to the type 1 hypervisor where Windows normally runs under, we put "Unknown" to clarify you're not running under a VM if this is detected
            { brands::NULL_BRAND, "Unknown" }
        };

        auto it = type_table.find(brand_str.c_str());

        if (it != type_table.end()) {
            return it->second;
        }

        debug("VM::type(): No known brand found, something went terribly wrong here...");

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

        std::string brand_tmp = brand(flags);
        const u8 percent_tmp = percentage(flags);

        constexpr const char* baremetal = "Running on baremetal";
        constexpr const char* very_unlikely = "Very unlikely a VM";
        constexpr const char* unlikely = "Unlikely a VM";

#if (CPP >= 17)
        constexpr std::string_view potentially = "Potentially";
        constexpr std::string_view might = "Might be";
        constexpr std::string_view likely = "Likely";
        constexpr std::string_view very_likely = "Very likely";
        constexpr std::string_view inside_vm = "Running inside";
#else
        const std::string potentially = "Potentially";
        const std::string might = "Might be";
        const std::string likely = "Likely";
        const std::string very_likely = "Very likely";
        const std::string inside_vm = "Running inside";
#endif

#if (CPP >= 17)
        auto make_conclusion = [&](const std::string_view category) -> std::string {
#else
        auto make_conclusion = [&](const std::string &category) -> std::string {
#endif
            // this basically just fixes the grammatical syntax
            // by either having "a" or "an" before the VM brand
            // name. Like it would look weird if the conclusion 
            // message was "an VirtualBox" or "a Anubis", so this
            // lambda fixes that issue.
            std::string article = "";

            if (
                (brand_tmp == brands::ACRN) ||
                (brand_tmp == brands::ANUBIS) ||
                (brand_tmp == brands::BSD_VMM) ||
                (brand_tmp == brands::INTEL_HAXM) ||
                (brand_tmp == brands::APPLE_VZ) ||
                (brand_tmp == brands::INTEL_KGT) ||
                (brand_tmp == brands::POWERVM) ||
                (brand_tmp == brands::OPENSTACK) ||
                (brand_tmp == brands::AWS_NITRO) ||
                (brand_tmp == brands::OPENVZ) ||
                (brand_tmp == brands::INTEL_TDX) ||
                (brand_tmp == brands::AMD_SEV) ||
                (brand_tmp == brands::AMD_SEV_ES) ||
                (brand_tmp == brands::AMD_SEV_SNP) ||
                (brand_tmp == brands::NSJAIL) ||
                (brand_tmp == brands::NULL_BRAND)
            ) {
                article = " an ";
            } else {
                article = " a ";
            }

            // this is basically just to remove the capital "U", 
            // since it doesn't make sense to see "an Unknown"
            if (brand_tmp == brands::NULL_BRAND) {
                brand_tmp = "unknown";
            }

            // Hyper-V artifacts are an exception due to how unique the circumstance is
            if (brand_tmp == brands::HYPERV_ARTIFACT) {
                return std::string(category) + article + brand_tmp;
            }
            else {
                return std::string(category) + article + brand_tmp + " VM";
            }
        };

        if (core::is_enabled(flags, DYNAMIC)) {
            if      (percent_tmp == 0)  { return baremetal; }
            else if (percent_tmp <= 20) { return very_unlikely; }
            else if (percent_tmp <= 35) { return unlikely; }
            else if (percent_tmp < 50)  { return make_conclusion(potentially); }
            else if (percent_tmp <= 62) { return make_conclusion(might); }
            else if (percent_tmp <= 75) { return make_conclusion(likely); }
            else if (percent_tmp < 100) { return make_conclusion(very_likely); }
            else                        { return make_conclusion(inside_vm); }
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
    static std::vector<enum_flags> technique_vector;
#ifdef __VMAWARE_DEBUG__
    static u16 total_points;
#endif
};

// ============= EXTERNAL DEFINITIONS =============
// These are added here due to warnings related to C++17 inline variables for C++ standards that are under 17.
// It's easier to just group them together rather than having C++17<= preprocessors with inline stuff


// scoreboard list of brands, if a VM detection technique detects a brand, that will be incremented here as a single point.
std::map<const char*, VM::brand_score_t> VM::core::brand_scoreboard{
    { brands::VBOX, 0 },
    { brands::VMWARE, 0 },
    { brands::VMWARE_EXPRESS, 0 },
    { brands::VMWARE_ESX, 0 },
    { brands::VMWARE_GSX, 0 },
    { brands::VMWARE_WORKSTATION, 0 },
    { brands::VMWARE_FUSION, 0 },
    { brands::VMWARE_HARD, 0 },
    { brands::BHYVE, 0 },
    { brands::KVM, 0 },
    { brands::QEMU, 0 },
    { brands::QEMU_KVM, 0 },
    { brands::KVM_HYPERV, 0 },
    { brands::QEMU_KVM_HYPERV, 0 },
    { brands::HYPERV, 0 },
    { brands::HYPERV_VPC, 0 },
    { brands::PARALLELS, 0 },
    { brands::XEN, 0 },
    { brands::ACRN, 0 },
    { brands::QNX, 0 },
    { brands::HYBRID, 0 },
    { brands::SANDBOXIE, 0 },
    { brands::DOCKER, 0 },
    { brands::WINE, 0 },
    { brands::VPC, 0 },
    { brands::ANUBIS, 0 },
    { brands::JOEBOX, 0 },
    { brands::THREATEXPERT, 0 },
    { brands::CWSANDBOX, 0 },
    { brands::COMODO, 0 },
    { brands::BOCHS, 0 },
    { brands::NVMM, 0 },
    { brands::BSD_VMM, 0 },
    { brands::INTEL_HAXM, 0 },
    { brands::UNISYS, 0 },
    { brands::LMHS, 0 },
    { brands::CUCKOO, 0 },
    { brands::BLUESTACKS, 0 },
    { brands::JAILHOUSE, 0 },
    { brands::APPLE_VZ, 0 },
    { brands::INTEL_KGT, 0 },
    { brands::AZURE_HYPERV, 0 },
    { brands::NANOVISOR, 0 },
    { brands::SIMPLEVISOR, 0 },
    { brands::HYPERV_ARTIFACT, 0 },
    { brands::UML, 0 },
    { brands::POWERVM, 0 },
    { brands::GCE, 0 },
    { brands::OPENSTACK, 0 },
    { brands::KUBEVIRT, 0 },
    { brands::AWS_NITRO, 0 },
    { brands::PODMAN, 0 },
    { brands::WSL, 0 },
    { brands::OPENVZ, 0 },
    { brands::BAREVISOR, 0 },
    { brands::HYPERPLATFORM, 0 },
    { brands::MINIVISOR, 0 },
    { brands::INTEL_TDX, 0 },
    { brands::LKVM, 0 },
    { brands::AMD_SEV, 0 },
    { brands::AMD_SEV_ES, 0 },
    { brands::AMD_SEV_SNP, 0 },
    { brands::NEKO_PROJECT, 0 },
    { brands::QIHOO, 0 },
    { brands::NOIRVISOR, 0 },
    { brands::NSJAIL, 0 },
    { brands::HYPERVISOR_PHANTOM, 0 },
    { brands::NULL_BRAND, 0 }
};


// initial definitions for cache items because C++ forbids in-class initializations
std::map<VM::u16, VM::memo::data_t> VM::memo::cache_table;
VM::flagset VM::memo::cache_keys = 0;
std::string VM::memo::brand::brand_cache = "";
std::string VM::memo::multi_brand::brand_cache = "";
std::string VM::memo::cpu_brand::brand_cache = "";
VM::hyperx_state VM::memo::hyperx::state = VM::HYPERV_UNKNOWN_VM;
bool VM::memo::hyperx::cached = false;

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
VM::flagset VM::core::disabled_flag_collector;


VM::u8 VM::detected_count_num = 0;


std::vector<VM::enum_flags> VM::technique_vector = []() -> std::vector<VM::enum_flags> {
    std::vector<VM::enum_flags> tmp{};

    // all the techniques have a macro value starting from 0 to ~90, hence why it's a classic loop
    for (u8 i = VM::technique_begin; i < VM::technique_end; i++) {
        tmp.push_back(static_cast<VM::enum_flags>(i));
    }

    return tmp;
}();


// this value is incremented each time VM::add_custom is called
VM::u16 VM::technique_count = base_technique_count;

// this is initialised as empty, because this is where custom techniques can be added at runtime 
std::vector<VM::core::custom_technique> VM::core::custom_table = {

};

#define table_t std::map<VM::enum_flags, VM::core::technique>

// the 0~100 points are debatable, but we think it's fine how it is. Feel free to disagree.
std::pair<VM::enum_flags, VM::core::technique> VM::core::technique_list[] = {
    // FORMAT: { VM::<ID>, { certainty%, function pointer } },
    // START OF TECHNIQUE TABLE
    std::make_pair(VM::FIRMWARE, VM::core::technique(100, VM::firmware_scan)),
    std::make_pair(VM::GPU_CAPABILITIES, VM::core::technique(100, VM::gpu_capabilities)),
    std::make_pair(VM::TIMER, VM::core::technique(45, VM::timer)),
    std::make_pair(VM::TPM, VM::core::technique(50, VM::tpm)),
    std::make_pair(VM::PCI_VM_DEVICE_ID, VM::core::technique(90, VM::pci_vm_device_id)),
    std::make_pair(VM::QEMU_PASSTHROUGH, VM::core::technique(90, VM::qemu_passthrough)),
    std::make_pair(VM::INTEL_THREAD_MISMATCH, VM::core::technique(95, VM::intel_thread_mismatch)),
    std::make_pair(VM::AMD_THREAD_MISMATCH, VM::core::technique(95, VM::amd_thread_mismatch)),
    std::make_pair(VM::XEON_THREAD_MISMATCH, VM::core::technique(95, VM::xeon_thread_mismatch)),
    std::make_pair(VM::DISK_SERIAL, VM::core::technique(100, VM::disk_serial_number)),
    std::make_pair(VM::IVSHMEM, VM::core::technique(100, VM::ivshmem)),
    std::make_pair(VM::GPU_VM_STRINGS, VM::core::technique(100, VM::gpu_vm_strings)),
    std::make_pair(VM::SIDT, VM::core::technique(45, VM::sidt)),
    std::make_pair(VM::SGDT, VM::core::technique(45, VM::sgdt)),
    std::make_pair(VM::SLDT, VM::core::technique(45, VM::sldt)),
    std::make_pair(VM::SMSW, VM::core::technique(45, VM::smsw)),
    std::make_pair(VM::DRIVERS, VM::core::technique(100, VM::drivers)),
    std::make_pair(VM::POOLS, VM::core::technique(80, VM::pools)),
    std::make_pair(VM::REGISTRY_VALUES, VM::core::technique(50, VM::registry_values)),
    std::make_pair(VM::REGISTRY_KEYS, VM::core::technique(50, VM::registry_keys)),
    std::make_pair(VM::VMID, VM::core::technique(100, VM::vmid)),
    std::make_pair(VM::CPU_BRAND, VM::core::technique(95, VM::cpu_brand)),
    std::make_pair(VM::HYPERVISOR_BIT, VM::core::technique(100, VM::hypervisor_bit)),
    std::make_pair(VM::HYPERVISOR_STR, VM::core::technique(75, VM::hypervisor_str)),
    std::make_pair(VM::CPUID_SIGNATURE, VM::core::technique(95, VM::cpuid_signature)),
    std::make_pair(VM::THREAD_COUNT, VM::core::technique(35, VM::thread_count)),
    std::make_pair(VM::LOGICAL_PROCESSORS, VM::core::technique(50, VM::logical_processors)),
    std::make_pair(VM::PHYSICAL_PROCESSORS, VM::core::technique(50, VM::physical_processors)),
    std::make_pair(VM::DEVICE_HANDLES, VM::core::technique(100, VM::device_handles)),
    std::make_pair(VM::VIRTUAL_PROCESSORS, VM::core::technique(100, VM::virtual_processors)),
    std::make_pair(VM::HYPERV_QUERY, VM::core::technique(100, VM::hyperv_query)),
    std::make_pair(VM::FILES, VM::core::technique(50, VM::files)),
    std::make_pair(VM::AUDIO, VM::core::technique(25, VM::audio)),
    std::make_pair(VM::DISPLAY, VM::core::technique(35, VM::display)),
    std::make_pair(VM::DLL, VM::core::technique(50, VM::dll)),
    std::make_pair(VM::DISK_SIZE, VM::core::technique(60, VM::disk_size)),
    std::make_pair(VM::VBOX_DEFAULT, VM::core::technique(25, VM::vbox_default_specs)),
    std::make_pair(VM::VBOX_NETWORK, VM::core::technique(100, VM::vbox_network_share)),
    std::make_pair(VM::VMWARE_BACKDOOR, VM::core::technique(100, VM::vmware_backdoor)),
    std::make_pair(VM::WINE, VM::core::technique(100, VM::wine)),
    std::make_pair(VM::POWER_CAPABILITIES, VM::core::technique(50, VM::power_capabilities)),
    std::make_pair(VM::PROCESSES, VM::core::technique(15, VM::processes)),
    std::make_pair(VM::VIRTUAL_REGISTRY, VM::core::technique(90, VM::virtual_registry)),
    std::make_pair(VM::MUTEX, VM::core::technique(100, VM::mutex)),
    std::make_pair(VM::DEVICE_STRING, VM::core::technique(25, VM::device_string)),
    std::make_pair(VM::VPC_INVALID, VM::core::technique(75, VM::vpc_invalid)),
    std::make_pair(VM::PORT_CONNECTORS, VM::core::technique(25, VM::port_connectors)),
    std::make_pair(VM::TEMPERATURE, VM::core::technique(15, VM::temperature)),
    std::make_pair(VM::QEMU_FW_CFG, VM::core::technique(70, VM::qemu_fw_cfg)),
    std::make_pair(VM::HWMODEL, VM::core::technique(100, VM::hwmodel)),
    std::make_pair(VM::SYSTEMD, VM::core::technique(35, VM::systemd_virt)),
    std::make_pair(VM::CVENDOR, VM::core::technique(65, VM::chassis_vendor)),
    std::make_pair(VM::CTYPE, VM::core::technique(20, VM::chassis_type)),
    std::make_pair(VM::DOCKERENV, VM::core::technique(30, VM::dockerenv)),
    std::make_pair(VM::DMIDECODE, VM::core::technique(55, VM::dmidecode)),
    std::make_pair(VM::DMESG, VM::core::technique(55, VM::dmesg)),
    std::make_pair(VM::HWMON, VM::core::technique(35, VM::hwmon)),
    std::make_pair(VM::LSHW_QEMU, VM::core::technique(80, VM::lshw_qemu)),
    std::make_pair(VM::LINUX_USER_HOST, VM::core::technique(10, VM::linux_user_host)),
    std::make_pair(VM::GAMARUE, VM::core::technique(10, VM::gamarue)),
    std::make_pair(VM::VMWARE_IOMEM, VM::core::technique(65, VM::vmware_iomem)),
    std::make_pair(VM::VMWARE_IOPORTS, VM::core::technique(70, VM::vmware_ioports)),
    std::make_pair(VM::VMWARE_SCSI, VM::core::technique(40, VM::vmware_scsi)),
    std::make_pair(VM::VMWARE_DMESG, VM::core::technique(65, VM::vmware_dmesg)),
    std::make_pair(VM::VMWARE_STR, VM::core::technique(35, VM::vmware_str)),
    std::make_pair(VM::ODD_CPU_THREADS, VM::core::technique(80, VM::odd_cpu_threads)),
    std::make_pair(VM::CUCKOO_DIR, VM::core::technique(30, VM::cuckoo_dir)),
    std::make_pair(VM::CUCKOO_PIPE, VM::core::technique(30, VM::cuckoo_pipe)),
    std::make_pair(VM::HYPERV_HOSTNAME, VM::core::technique(30, VM::hyperv_hostname)),
    std::make_pair(VM::GENERAL_HOSTNAME, VM::core::technique(10, VM::general_hostname)),
    std::make_pair(VM::KGT_SIGNATURE, VM::core::technique(80, VM::intel_kgt_signature)),
    std::make_pair(VM::QEMU_VIRTUAL_DMI, VM::core::technique(40, VM::qemu_virtual_dmi)),
    std::make_pair(VM::QEMU_USB, VM::core::technique(20, VM::qemu_USB)),
    std::make_pair(VM::HYPERVISOR_DIR, VM::core::technique(20, VM::hypervisor_dir)),
    std::make_pair(VM::UML_CPU, VM::core::technique(80, VM::uml_cpu)),
    std::make_pair(VM::KMSG, VM::core::technique(5, VM::kmsg)),
    std::make_pair(VM::VBOX_MODULE, VM::core::technique(15, VM::vbox_module)),
    std::make_pair(VM::SYSINFO_PROC, VM::core::technique(15, VM::sysinfo_proc)),
    std::make_pair(VM::DMI_SCAN, VM::core::technique(50, VM::dmi_scan)),
    std::make_pair(VM::SMBIOS_VM_BIT, VM::core::technique(50, VM::smbios_vm_bit)),
    std::make_pair(VM::PODMAN_FILE, VM::core::technique(5, VM::podman_file)),
    std::make_pair(VM::WSL_PROC, VM::core::technique(30, VM::wsl_proc_subdir)),
    std::make_pair(VM::AMD_SEV, VM::core::technique(50, VM::amd_sev)),
    std::make_pair(VM::FILE_ACCESS_HISTORY, VM::core::technique(15, VM::file_access_history)),
    std::make_pair(VM::UNKNOWN_MANUFACTURER, VM::core::technique(100, VM::unknown_manufacturer)),
    std::make_pair(VM::MAC, VM::core::technique(20, VM::mac_address_check)),
    std::make_pair(VM::NSJAIL_PID, VM::core::technique(75, VM::nsjail_proc_id)),
    std::make_pair(VM::MAC_MEMSIZE, VM::core::technique(15, VM::hw_memsize)),
    std::make_pair(VM::MAC_IOKIT, VM::core::technique(100, VM::io_kit)),
    std::make_pair(VM::IOREG_GREP, VM::core::technique(100, VM::ioreg_grep)),
    std::make_pair(VM::MAC_SIP, VM::core::technique(40, VM::mac_sip)),
    std::make_pair(VM::BOCHS_CPU, VM::core::technique(100, VM::bochs_cpu)),
    std::make_pair(VM::BLUESTACKS_FOLDERS, VM::core::technique(5, VM::bluestacks)),
    // ADD NEW TECHNIQUE STRUCTURE HERE
};


// the reason why the map isn't directly initialized is due to potential 
// SDK errors on windows combined with older C++ standards
table_t VM::core::technique_table = []() -> table_t {
    table_t table;
    for (const auto& technique : VM::core::technique_list) {
        table.insert(technique);
    }
    return table;
}();