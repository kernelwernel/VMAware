/**
 * ██╗   ██╗███╗   ███╗ █████╗ ██╗    ██╗ █████╗ ██████╗ ███████╗
 * ██║   ██║████╗ ████║██╔══██╗██║    ██║██╔══██╗██╔══██╗██╔════╝
 * ██║   ██║██╔████╔██║███████║██║ █╗ ██║███████║██████╔╝█████╗
 * ╚██╗ ██╔╝██║╚██╔╝██║██╔══██║██║███╗██║██╔══██║██╔══██╗██╔══╝
 *  ╚████╔╝ ██║ ╚═╝ ██║██║  ██║╚███╔███╔╝██║  ██║██║  ██║███████╗
 *   ╚═══╝  ╚═╝     ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ Experimental post-2.6.0 (February 2026)
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
 *      - Teselka (https://github.com/Teselka)
 *      - Kyun-J (https://github.com/Kyun-J)
 *      - luukjp (https://github.com/luukjp)
 *      - Lorenzo Rizzotti (https://github.com/Dreaming-Codes) 
 *      - virtfunc (https://github.com/virtfunc)
 *  - Repository: https://github.com/kernelwernel/VMAware
 *  - Docs: https://github.com/kernelwernel/VMAware/docs/documentation.md
 *  - Full credits: https://github.com/kernelwernel/VMAware#credits-and-contributors-%EF%B8%8F
 *  - License: MIT
 * 
 *                               MIT License
 *  
 *  Copyright (c) 2026 kernelwernel
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
 * - enums for publicly accessible techniques  => line 545
 * - struct for internal cpu operations        => line 717
 * - struct for internal memoization           => line 3041
 * - struct for internal utility functions     => line 3223
 * - struct for internal core components       => line 11338
 * - start of VM detection technique list      => line 4278
 * - start of public VM detection functions    => line 11716
 * - start of externally defined variables     => line 12736
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
 * TL;DR: if you have the patience of an ADHD kid, head over here:
 * https://deepwiki.com/kernelwernel/VMAware
 * 
 *
 * Welcome! This is just a preliminary text to lay the context of how it works, 
 * how it's structured, and to guide anybody who's trying to understand the whole code. 
 * Reading over 12k+ lines of other people's C++ code is obviously not an easy task, 
 * and that's perfectly understandable. We'd struggle as well if we were in your position
 * while not even knowing where to start. So here's a more human-friendly explanation:
 * 
 * 
 * Firstly, the lib is completely static, meaning that there's no need for struct 
 * constructors to be initialized (unless you're using the VM::vmaware struct).
 * The main focus of the lib are the tables:
 *  - the TECHNIQUE table stores all the VM detection technique information in a std::array 
 * 
 *  - the BRAND table stores every VM brand as a std::array as well, but as a scoreboard. 
 *    This means that if a VM detection technique has detected a VM brand, that brand will have an
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
 *        argument input by the user.
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
 *        things for convenience. 
 * 
 *    - util module:
 *        This contains many utility functionalities to be used by the techniques.
 *        Examples of functionalities include file I/O, registries, permission 
 *        checks, system commands, HDD sizes, RAM sizes, debugs, process checking, 
 *        OS queries, Hyper-X, and so on. (It should be mentioned that this is 
 *        probably the least enjoyable part of the lib to read, since it's really messy)
 * 
 * 
 * Thirdly, We'll explain in this section how all of these facets of the lib interact with 
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
 *       while ignoring the ones that weren't (by default most of them 
 *       are already selected anyway). The function that does this 
 *       mechanism is core::run_all()
 * 
 *    3. While the core::run_all() function is being run, it checks if 
 *       each technique has already been memoized or not. If it has, 
 *       retrieve the result from the cache and move to the next technique. 
 *       If it hasn't, run the technique and cache the result in the 
 *       cache table. 
 * 
 *    4. After every technique has been executed, this generates a 
 *       uint16_t score. Every technique has a score value between 0 to 
 *       100, and if a VM is detected then this score is accumulated to 
 *       a total. If the total is above 150, that means it's a VM[1]. 
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
 *       the scoreboard. If no technique were run, then there's no way to
 *       populate the scoreboard with any points. After every VM detection 
 *       technique has been invoked/retrieved, the brand scoreboard is now
 *       ready to be analysed.
 * 
 *    3. Create a filter for the scoreboard, where every brand that has a score
 *       of 0 are erased for abstraction purposes. Now the scoreboard is only
 *       populated with relevant brands where they all have at least a single
 *       point. These are the contenders for which brand will be outputted.
 *       Think of it as fetching candidates with potential while discarding
 *       those that don't.
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
 *    6. The result is then cached in the memo module, so if another function
 *       invokes VM::brand() again, the result is retrieved from the cache 
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

#ifndef VMAWARE_HEADER
#define VMAWARE_HEADER

#ifndef __VMAWARE_DEBUG__
    #if defined(_DEBUG)    /* MSVC Debug */       \
    || defined(DEBUG)     /* user or build-system */
        #define __VMAWARE_DEBUG__
    #endif
#endif

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
    #define VMA_CPLUSPLUS _MSVC_LANG
#else
    #define VMA_CPLUSPLUS __cplusplus
#endif

#if VMA_CPLUSPLUS >= 202302L
    #define VMA_CPP 23
#elif VMA_CPLUSPLUS >= 202002L
    #define VMA_CPP 20
#elif VMA_CPLUSPLUS >= 201703L
    #define VMA_CPP 17
#elif VMA_CPLUSPLUS >= 201402L
    #define VMA_CPP 14
#elif VMA_CPLUSPLUS >= 201103L
    #define VMA_CPP 11
#elif VMA_CPLUSPLUS >= 199711L
    #define VMA_CPP 98 /* C++98 or C++03 */
#else
    #error "Unsupported C++ standard (pre-C++98 or unknown)."
#endif
    
#if (VMA_CPP < 11 && !WINDOWS)
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
    
#if defined(__aarch64__) || defined(_M_ARM64) || defined(__ARM_LINUX_COMPILER__)
    #define ARM64 1
#else
    #define ARM64 0
#endif

#if (defined(__arm__) || defined(_M_ARM)) && !ARM64
    #define ARM32 1
#else
    #define ARM32 0
#endif
    
#if ARM32 || ARM64
    #define ARM 1
#else
    #define ARM 0
#endif

#if (!APPLE && (VMA_CPP >= 20) && (!CLANG || __clang_major__ >= 16))
    #define SOURCE_LOCATION_SUPPORTED 1
#else
    #define SOURCE_LOCATION_SUPPORTED 0
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

#if (VMA_CPP >= 23)
    #include <limits>
#endif
#if (VMA_CPP >= 20)
    #include <bit>
    #include <ranges>
    #if (SOURCE_LOCATION_SUPPORTED)
        #include <source_location>
    #endif
#endif
#if (VMA_CPP >= 17)
    #include <filesystem>
    #include <system_error>
#endif
#ifdef __VMAWARE_DEBUG__
    #include <iomanip>
    #include <ios>
    #include <locale>
    #include <codecvt>
#endif

#include <cstdio>
#include <functional>
#include <cstring>
#include <string>
#include <fstream>
#include <thread>
#include <cstdint>
#include <unordered_set>
#include <unordered_map>
#include <array>
#include <algorithm>
#include <iostream>
#include <cassert>
#include <cmath>
#include <sstream>
#include <bitset>
#include <type_traits>
#include <stdexcept>
#include <numeric>
#include <atomic>

#if (WINDOWS)
    #include <windows.h>
    #include <intrin.h>
    #include <winioctl.h>
    #include <winternl.h>
    #include <powerbase.h>
    #include <setupapi.h>
    #include <initguid.h>
    #include <devpkey.h>
    #include <devguid.h>
    #include <winevt.h>

    #pragma comment(lib, "setupapi.lib")
    #pragma comment(lib, "powrprof.lib")
    #pragma comment(lib, "wevtapi.lib")
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
    #if (x86)
        #include <cpuid.h>
        #include <x86intrin.h>
        #include <immintrin.h>
    #endif
    #include <sys/types.h>
    #include <sys/sysctl.h>
    #include <sys/user.h>
    #include <unistd.h>
    #include <time.h>
    #include <errno.h>
    #include <chrono>
#endif

#ifdef __VMAWARE_DEBUG__
    #define debug(...) VM::util::debug_msg(__VA_ARGS__)
#else
    #define debug(...)
#endif


/**
 * Official aliases for VM brands. This is added to avoid accidental typos
 * which could really mess up the result. Also, no errors/warnings are
 * issued if the string is invalid in case of a typo. For example:
 * scoreboard[VBOX]++;
 * is much better and safer against typos than:
 * scoreboard["VirtualBox"]++;
 * Hopefully this makes sense.
 *
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
    static constexpr const char* SIMPLEVISOR = "SimpleVisor";
    static constexpr const char* HYPERV_ARTIFACT = "Hyper-V artifact (host running Hyper-V)";
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
    static constexpr const char* DBVM = "DBVM";
    static constexpr const char* UTM = "UTM";
}

#if (VMA_CPP >= 17)
    #define VMAWARE_CONSTEXPR constexpr
#else
    #define VMAWARE_CONSTEXPR
#endif

#if (VMA_CPP >= 14)
    #define VMAWARE_CONSTEXPR_14 constexpr
#else
    #define VMAWARE_CONSTEXPR_14
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
        // Windows
        GPU_CAPABILITIES = 0,
        ACPI_SIGNATURE,
        POWER_CAPABILITIES,
        DISK_SERIAL,
        IVSHMEM,
        DRIVERS,
        DEVICE_HANDLES,
        VIRTUAL_PROCESSORS,
        HYPERVISOR_QUERY,
        AUDIO,
        DISPLAY,
        DLL,
        VMWARE_BACKDOOR,
        WINE,
        VIRTUAL_REGISTRY,
        MUTEX,
        DEVICE_STRING,
        VPC_INVALID,
        VMWARE_STR,
        GAMARUE,
        CUCKOO_DIR,
        CUCKOO_PIPE,
        BOOT_LOGO,
        TRAP,
        UD,
        BLOCKSTEP,
        DBVM,
        KERNEL_OBJECTS,
        NVRAM,
        SMBIOS_INTEGRITY,
        EDID,
        CPU_HEURISTIC,
        CLOCK,

        // Linux and Windows
        SYSTEM_REGISTERS,
        FIRMWARE,
        PCI_DEVICES,
        AZURE,
        
        // Linux
        SMBIOS_VM_BIT,
        KMSG,
        CVENDOR,
        QEMU_FW_CFG,
        SYSTEMD,
        CTYPE,
        DOCKERENV,
        DMIDECODE,
        DMESG,
        HWMON,
        LINUX_USER_HOST,
        VMWARE_IOMEM,
        VMWARE_IOPORTS,
        VMWARE_SCSI,
        VMWARE_DMESG,
        QEMU_VIRTUAL_DMI,
        QEMU_USB,
        HYPERVISOR_DIR,
        UML_CPU,
        VBOX_MODULE,
        SYSINFO_PROC,
        DMI_SCAN,
        PODMAN_FILE,
        WSL_PROC,
        FILE_ACCESS_HISTORY,
        MAC,
        NSJAIL_PID,
        BLUESTACKS_FOLDERS,
        AMD_SEV,
        TEMPERATURE,
        PROCESSES,

        // Linux and MacOS
        THREAD_COUNT,

        // MacOS
        MAC_MEMSIZE,
        MAC_IOKIT,
        MAC_SIP,
        IOREG_GREP,
        HWMODEL,
        MAC_SYS,

        // cross-platform
        HYPERVISOR_BIT,
        VMID,
        THREAD_MISMATCH,
        TIMER,
        CPU_BRAND,
        HYPERVISOR_STR,
        CPUID_SIGNATURE,
        BOCHS_CPU,
        KGT_SIGNATURE,
        // ADD NEW TECHNIQUE ENUM NAME HERE

        // special flags, different to settings
        DEFAULT,
        ALL,
        NULL_ARG, // does nothing, just a placeholder flag mainly for the CLI

        // start of settings technique flags (THE ORDERING IS VERY SPECIFIC HERE AND MIGHT BREAK SOMETHING IF RE-ORDERED)
        HIGH_THRESHOLD,
        DYNAMIC,
        MULTIPLE
    };

private:
    static constexpr u8 enum_size = MULTIPLE; // get enum size through value of last element
    static constexpr u8 settings_count = MULTIPLE - HIGH_THRESHOLD + 1; // get number of settings technique flags
    static constexpr u8 INVALID = 255; // explicit invalid technique macro
    static constexpr u16 base_technique_count = HIGH_THRESHOLD; // original technique count, constant on purpose (can also be used as a base count value if custom techniques are added)
    static constexpr u16 maximum_points = 5510; // theoretical total points if all VM detections returned true (which is practically impossible)
    static constexpr u16 threshold_score = 150; // standard threshold score
    static constexpr u16 high_threshold_score = 300; // new threshold score from 150 to 300 if VM::HIGH_THRESHOLD flag is enabled
    static constexpr bool SHORTCUT = true; // macro for whether VM::core::run_all() should take a shortcut by skipping the rest of the techniques if the threshold score is already met
       
    // intended for loop indexes
    static constexpr u8 enum_begin = 0;
    static constexpr u8 enum_end = enum_size + 1;
    static constexpr u8 technique_begin = enum_begin;
    static constexpr u8 technique_end = DEFAULT;
    static constexpr u8 settings_begin = DEFAULT;
    static constexpr u8 settings_end = enum_end;
    
public:
    // for platform compatibility ranges
    static constexpr u8 WINDOWS_START = VM::GPU_CAPABILITIES;
    static constexpr u8 WINDOWS_END = VM::AZURE;
    static constexpr u8 LINUX_START = VM::SYSTEM_REGISTERS;
    static constexpr u8 LINUX_END = VM::THREAD_COUNT;
    static constexpr u8 MACOS_START = VM::THREAD_COUNT;
    static constexpr u8 MACOS_END = VM::MAC_SYS;
    
    // this is specifically meant for VM::detected_count() to 
    // get the total number of techniques that detected a VM
    static u8 detected_count_num; 

    static std::vector<enum_flags> disabled_techniques;

private:

#if (WINDOWS)
    using brand_score_t = i32;
#else
    using brand_score_t = u8;
#endif

    // for the flag bitset structure
    using flagset = std::bitset<enum_size + 1>;

public:
    // constructor stuff
    VM() = delete;
    VM(const VM&) = delete;
    VM(VM&&) = delete;

private:
    // macro for bypassing unused parameter/variable warnings
    #define VMAWARE_UNUSED(x) ((void)(x))

    // specifically for util::hyper_x() and memo::hyperv
    enum hyperx_state : u8 {
        HYPERV_UNKNOWN = 0,
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

        #if (MSVC)
            #define CPUID_COUNT(leaf, subleaf, a_ptr, b_ptr, c_ptr, d_ptr) \
                    do { \
                        int __cpuid_regs[4]; \
                        __cpuidex(__cpuid_regs, static_cast<int>(leaf), static_cast<int>(subleaf)); \
                        *(a_ptr) = static_cast<unsigned int>(__cpuid_regs[0]); \
                        *(b_ptr) = static_cast<unsigned int>(__cpuid_regs[1]); \
                        *(c_ptr) = static_cast<unsigned int>(__cpuid_regs[2]); \
                        *(d_ptr) = static_cast<unsigned int>(__cpuid_regs[3]); \
                    } while (0)
        #else
            #define CPUID_COUNT(leaf, subleaf, a_ptr, b_ptr, c_ptr, d_ptr) \
                    do { \
                        __get_cpuid_count((unsigned)(leaf), (unsigned)(subleaf), (a_ptr), (b_ptr), (c_ptr), (d_ptr)); \
                    } while (0)
        #endif

        // cross-platform wrapper for linux and MSVC cpuid
        static void cpuid
        (
            u32& a, u32& b, u32& c, u32& d,
            const u32 a_leaf,
            const u32 c_leaf = 0xFF  // dummy value if not set manually
        ) {
        #if (x86)
            // may be unmodified for older 32-bit processors, clearing just in case
            a = 0;
            b = 0;
            c = 0;
            d = 0;

            unsigned int aa = 0u, bb = 0u, cc = 0u, dd = 0u;
            CPUID_COUNT(a_leaf, c_leaf, &aa, &bb, &cc, &dd);

            a = static_cast<u32>(aa);
            b = static_cast<u32>(bb);
            c = static_cast<u32>(cc);
            d = static_cast<u32>(dd);
        #endif
            return;
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
            x[0] = 0;
            x[1] = 0;
            x[2] = 0;
            x[3] = 0;

            unsigned int aa = 0u, bb = 0u, cc = 0u, dd = 0u;
            CPUID_COUNT(a_leaf, c_leaf, &aa, &bb, &cc, &dd);

            x[0] = static_cast<i32>(aa);
            x[1] = static_cast<i32>(bb);
            x[2] = static_cast<i32>(cc);
            x[3] = static_cast<i32>(dd);
        #endif
            return;
        };

        static bool is_leaf_supported(const u32 p_leaf) {
        #if (APPLE) 
            return false;
        #endif
            bool cached;

            if (memo::leaf_cache::fetch(p_leaf, cached)) {
                return cached;
            }

            u32 eax = 0, unused = 0;
            bool supported = false;

            if (p_leaf < 0x40000000) {
                // Standard range: 0x00000000 - 0x3FFFFFFF
                cpu::cpuid(eax, unused, unused, unused, 0x00000000);
                debug("CPUID: max standard leaf = ", eax);
                supported = (p_leaf <= eax);
            }
            else if (p_leaf < 0x80000000) {
                // Hypervisor range: 0x40000000 - 0x7FFFFFFF
                cpu::cpuid(eax, unused, unused, unused, cpu::leaf::hypervisor);
                debug("CPUID: max hypervisor leaf = ", eax);
                supported = (p_leaf <= eax);
            }
            else if (p_leaf < 0xC0000000) {
                // Extended range: 0x80000000 - 0xBFFFFFFF
                cpu::cpuid(eax, unused, unused, unused, cpu::leaf::func_ext);
                debug("CPUID: max extended leaf = ", eax);
                supported = (p_leaf <= eax);
            }
            else {
                supported = false;
            }

            memo::leaf_cache::store(p_leaf, supported);
            return supported;
        }

        [[nodiscard]] static bool is_amd() {
            constexpr u32 amd_ecx = 0x444d4163; // "cAMD"

            u32 unused, ecx = 0;
            cpuid(unused, unused, ecx, unused, 0);

            return (ecx == amd_ecx);
        }

        [[nodiscard]] static bool is_intel() {
            constexpr u32 intel_ecx1 = 0x6c65746e; // "ntel"
            constexpr u32 intel_ecx2 = 0x6c65746f; // "otel", this is because some Intel CPUs have a rare manufacturer string of "GenuineIotel"

            u32 unused, ecx = 0;
            cpuid(unused, unused, ecx, unused, 0);

            return ((ecx == intel_ecx1) || (ecx == intel_ecx2));
        }

        [[nodiscard]] static const char* get_brand() {
            if (memo::cpu_brand::is_cached()) {
                return memo::cpu_brand::fetch();
            }

        #if (!x86 || APPLE)
            return "Unknown";
        #else
            if (!cpu::is_leaf_supported(cpu::leaf::brand3)) {
                return "Unknown";
            }

            alignas(16) char buffer[49]{};
            u32* regs = reinterpret_cast<u32*>(buffer);

            // unrolled calls to fill buffer directly
            cpu::cpuid(regs[0], regs[1], regs[2], regs[3], cpu::leaf::brand1);
            cpu::cpuid(regs[4], regs[5], regs[6], regs[7], cpu::leaf::brand2);
            cpu::cpuid(regs[8], regs[9], regs[10], regs[11], cpu::leaf::brand3);

            buffer[48] = '\0';

            // do NOT touch trailing spaces for the AMD_THREAD_MISMATCH technique

            // left-trim only to handle stupid whitespaces before the brand string in ARM CPUs (Virtual CPUs)
            const char* start_ptr = buffer;
            while (*start_ptr && std::isspace(static_cast<u8>(*start_ptr))) {
                ++start_ptr;
            }

            memo::cpu_brand::store(start_ptr);
            debug("CPU: ", start_ptr);

            // Return pointer to the static cache, not the local stack buffer
            return memo::cpu_brand::fetch();
        #endif
        }


        [[nodiscard]] static std::string cpu_manufacturer(const u32 leaf_id) {
            alignas(16) char buffer[13]{};
            u32* regs = reinterpret_cast<u32*>(buffer);

            u32 eax, ebx, ecx, edx;
            cpu::cpuid(eax, ebx, ecx, edx, leaf_id);

            if (ebx == 0 && ecx == 0 && edx == 0) {
                return "";
            }

            if (leaf_id >= 0x40000000) {
                regs[0] = ebx;
                regs[1] = ecx;
                regs[2] = edx;
            }
            else {
                regs[0] = ebx;
                regs[1] = edx;
                regs[2] = ecx;
            }

            buffer[12] = '\0';
            return std::string(buffer);
        }

        struct stepping_struct {
            u8 model;
            u8 family;
            u8 extmodel;
        };

        static stepping_struct fetch_steppings() {
            struct stepping_struct steps {};

            u32 unused, eax = 0;
            cpu::cpuid(eax, unused, unused, unused, 1);
            VMAWARE_UNUSED(unused);

            steps.model = ((eax >> 4) & 0b1111);
            steps.family = ((eax >> 8) & 0b1111);
            steps.extmodel = ((eax >> 16) & 0b1111);

            return steps;
        }

        // check if the CPU is an intel celeron
        static bool is_celeron(const stepping_struct steps) {
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

        static bool is_amd_A_series() {
            if (!cpu::is_amd()) {
                return false;
            }

            const model_struct model = get_model();
            const char* s = model.string.c_str();

            for (; *s; ++s) {
                if ((*s | 0x20) != 'a') continue;

                // check for "MD A" (case-insensitive match for "AMD A")
                // We need 5 specific characters following the 'A': 'm', 'd', ' ', 'a', and a digit
                if (!s[1] || !s[2] || !s[3] || !s[4] || !s[5]) break;

                if ((s[1] | 0x20) == 'm' &&
                    (s[2] | 0x20) == 'd' &&
                    s[3] == ' ' &&
                    (s[4] | 0x20) == 'a') {

                    // we found "AMD A" so now verify pattern [0-9]+-[0-9]+
                    const char* num = s + 5;

                    // must have at least one digit immediately after "AMD A"
                    if (*num < '0' || *num > '9') continue;
                    do { num++; } while (*num >= '0' && *num <= '9');
                    if (*num != '-') continue;
                    num++;

                    // Must have at least one digit after the hyphen
                    if (*num >= '0' && *num <= '9') {
                        return true;
                    }
                }
            }

            return false;
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

            model_struct result { false, false, false, false, {} };

            if (cpu::is_intel()) {
                // Ultra
                if (brand.find("Ultra") != std::string::npos &&
                    brand.find_first_of("0123456789") != std::string::npos) {
                    result.found = true;
                    result.string = brand;
                    return result;
                }

                // i-series
                if (brand.find("i") != std::string::npos && brand.find("-") != std::string::npos &&
                    brand.find_first_of("0123456789") != std::string::npos) {
                    result.found = true;
                    result.is_i_series = true;
                    result.string = brand;
                    return result;
                }

                // Xeon
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
  
        // to search in our databases, we want to precompute hashes at compile time for C++11 and later
        // so we need to match the hardware _mm_crc32_u8, it is based on CRC32-C (Castagnoli) polynomial
        struct constexpr_hash {
            // it does 8 rounds of CRC32-C bit reflection recursively
            static constexpr u32 crc32_bits(u32 crc, int bits) {
                return (bits == 0) ? crc :
                    crc32_bits((crc >> 1) ^ ((crc & 1) ? 0x82F63B78u : 0), bits - 1);
            }

            // over string
            static constexpr u32 crc32_str(const char* s, u32 crc) {
                return (*s == '\0') ? crc :
                    crc32_str(s + 1, crc32_bits(crc ^ static_cast<u8>(*s), 8));
            }

            static constexpr u32 get(const char* s) {
                return crc32_str(s, 0);
            }
        };

        // this forces the compiler to calculate the hash when initializing the array while staying C++11 compatible
        struct cpu_entry {
            u32 hash;
            u32 threads;
            double base_clock;

            constexpr cpu_entry(const char* m, u32 t, double c)
                : hash(constexpr_hash::get(m)), threads(t), base_clock(c) {
            }
        };

        struct cpu_cache {
            u32 expected_threads;
            u32 base_clock_mhz;
            bool found;
            const char* debug_tag;
            std::string model_name;
        };

        enum class cpu_type {
            INTEL_I,
            INTEL_XEON,
            INTEL_ULTRA,
            AMD
        };

        static const cpu_cache& analyze_cpu() {
            static cpu_cache result = { 0, 0, false, "", "" };
            static bool initialized = false;

            if (initialized) return result;

            // to save a few cycles
            struct hasher {
                static u32 crc32_sw(u32 crc, char data) {
                    crc ^= static_cast<u8>(data);
                    for (int i = 0; i < 8; ++i)
                        crc = (crc >> 1) ^ ((crc & 1) ? 0x82F63B78u : 0);
                    return crc;
                }

                using hashfc = u32(*)(u32, char);

                static hashfc get() {
                    i32 regs[4];
                    cpu::cpuid(regs, 1);
                    const bool has_sse42 = (regs[2] & (1 << 20)) != 0;
                    return has_sse42 ? util::crc32 : crc32_sw;
                }
            };

            const cpu_entry* db = nullptr;
            size_t db_size = 0;
            size_t max_model_len = 32;
            cpu_type type;

            // Detection logic
            if (is_amd()) {
                type = cpu_type::AMD;
                result.model_name = get_brand();
                result.debug_tag = "AMD_THREAD_MISMATCH";
                get_amd_ryzen_db(db, db_size);
            }
            else if (is_intel()) {
                const model_struct model = get_model();
                if (!model.found) { initialized = true; return result; }

                result.model_name = model.string;

                if (result.model_name.find("Ultra") != std::string::npos) {
                    type = cpu_type::INTEL_ULTRA;
                    result.debug_tag = "ULTRA_THREAD_MISMATCH";
                    get_intel_ultra_db(db, db_size);
                }
                else if (model.is_i_series) {
                    type = cpu_type::INTEL_I;
                    result.debug_tag = "INTEL_THREAD_MISMATCH";
                    get_intel_core_db(db, db_size);
                }
                else if (model.is_xeon) {
                    type = cpu_type::INTEL_XEON;
                    result.debug_tag = "XEON_THREAD_MISMATCH";
                    get_intel_xeon_db(db, db_size);
                }
                else { 
                    initialized = true; 
                    return result; 
                }
                result.model_name = model.string;
            }
            else { 
                initialized = true; 
                return result; 
            }

            if (result.model_name.empty() || db == nullptr) { 
                initialized = true; 
                return result; 
            }

            const char* str = result.model_name.c_str();
            size_t best_len = 0;
            u32 z_series_threads = 0;
            double found_clock = 0.0;

            const auto hash_func = hasher::get();

            for (size_t i = 0; str[i] != '\0'; ) {
                char c = str[i];
                if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) {
                    i++;
                    continue;
                }

                u32 current_hash = 0;
                size_t current_len = 0;
                size_t j = i;

                while (true) {
                    char k = str[j];
                    const bool is_valid = (k >= '0' && k <= '9') ||
                        (k >= 'A' && k <= 'Z') ||
                        (k >= 'a' && k <= 'z') ||
                        (k == '-');
                    if (!is_valid) break;

                    if (current_len >= max_model_len) {
                        while (str[j] != '\0' && str[j] != ' ') j++;
                        break;
                    }

                    // convert to lowercase on-the-fly to match compile-time keys
                    if (type == cpu_type::AMD && (k >= 'A' && k <= 'Z')) k += 32;

                    current_hash = hash_func(current_hash, k);
                    current_len++;
                    j++;

                    const char next = str[j];
                    const bool next_is_alnum = (next >= '0' && next <= '9') ||
                        (next >= 'A' && next <= 'Z') ||
                        (next >= 'a' && next <= 'z');

                    if (!next_is_alnum) {
                        // Check specific Z1 Extreme token
                        if (type == cpu_type::AMD && current_hash == 0x3D09D5B4) { 
                            z_series_threads = 16; 
                        }

                        for (size_t idx = 0; idx < db_size; ++idx) {
                            if (db[idx].hash == current_hash) {
                                if (current_len > best_len) {
                                    best_len = current_len;
                                    result.expected_threads = db[idx].threads;
                                    found_clock = db[idx].base_clock;
                                    result.found = true;
                                }
                            }
                        }
                    }
                }
                i = j;
            }

            // Z1 Extreme fix
            if (type == cpu_type::AMD && z_series_threads != 0 && result.expected_threads == 12) {
                result.expected_threads = z_series_threads;
            }

            if (result.found) {
                result.base_clock_mhz = static_cast<u32>(found_clock * 1000.0);
            }

            initialized = true;
            return result;
        }

        // In C++11, you can define static const arrays inside a function
        // without specifying the size explicitly. The compiler deduces it
        // The data is stored in read-only data just like a global constexpr array
        // We can't also put it outside the VM struct because the compiler complains about "too many initializers"

        // we cannot use constexpr on a static array if we do not want to provide the size explicitly inside the class
        // we cant also use another source file or use the C++ 17 inline variable feature because we want to stay C++11 compatible
		// using other structs or std::array would not solve anything, so the ONLY solution to this c++ 11 limitation is to define the function that returns the array
		// just like we had before (intel_thread_mismatch, xeon_thread_mismatch, amd_thread_mismatch) but now inside the cpu struct
        inline static void get_intel_core_db(const cpu_entry*& out_ptr, size_t& out_size) {
            static const cpu_entry db[] = {
                // i3 series
                { "i3-1000G1", 4, 1.10 },
                { "i3-1000G4", 4, 1.10 },
                { "i3-1000NG4", 4, 1.10 },
                { "i3-1005G1", 4, 1.20 },
                { "i3-10100", 8, 3.60 },
                { "i3-10100E", 8, 3.20 },
                { "i3-10100F", 8, 3.60 },
                { "i3-10100T", 8, 3.00 },
                { "i3-10100TE", 8, 2.30 },
                { "i3-10100Y", 4, 1.30 },
                { "i3-10105", 8, 3.70 },
                { "i3-10105F", 8, 3.70 },
                { "i3-10105T", 8, 3.00 },
                { "i3-10110U", 4, 2.10 },
                { "i3-10110Y", 4, 1.00 },
                { "i3-10300", 8, 3.70 },
                { "i3-10300T", 8, 3.00 },
                { "i3-10305", 8, 3.80 },
                { "i3-10305T", 8, 3.00 },
                { "i3-10320", 8, 3.80 },
                { "i3-10325", 8, 3.90 },
                { "i3-11100B", 8, 3.60 },
                { "i3-11100HE", 8, 2.40 },
                { "i3-1110G4", 4, 2.50 },
                { "i3-1115G4E", 4, 3.00 },
                { "i3-1115GRE", 4, 3.00 },
                { "i3-1120G4", 8, 1.10 },
                { "i3-12100", 8, 3.30 },
                { "i3-12100F", 8, 3.30 },
                { "i3-12100T", 8, 2.20 },
                { "i3-1210U", 8, 1.00 },
                { "i3-1215U", 8, 1.20 },
                { "i3-1215UE", 8, 1.20 },
                { "i3-1215UL", 8, 1.20 },
                { "i3-12300", 8, 3.50 },
                { "i3-12300T", 8, 2.30 },
                { "i3-13100", 8, 3.40 },
                { "i3-13100F", 8, 3.40 },
                { "i3-13100T", 8, 2.50 },
                { "i3-1315U", 8, 1.20 },
                { "i3-1315UE", 8, 1.20 },
                { "i3-14100", 8, 3.50 },
                { "i3-14100F", 8, 3.50 },
                { "i3-14100T", 8, 2.70 },
                { "i3-2100", 4, 3.10 },
                { "i3-2100T", 4, 2.50 },
                { "i3-2102", 4, 3.10 },
                { "i3-2105", 4, 3.10 },
                { "i3-2120", 4, 3.30 },
                { "i3-2120T", 4, 2.60 },
                { "i3-2125", 4, 3.30 },
                { "i3-2130", 4, 3.40 },
                { "i3-2308M", 4, 2.10 },
                { "i3-2310E", 4, 2.10 },
                { "i3-2310M", 4, 2.10 },
                { "i3-2312M", 4, 2.10 },
                { "i3-2328M", 4, 2.20 },
                { "i3-2330E", 4, 2.20 },
                { "i3-2330M", 4, 2.20 },
                { "i3-2332M", 4, 2.20 },
                { "i3-2340UE", 4, 1.30 },
                { "i3-2348M", 4, 2.30 },
                { "i3-2350LM", 4, 1.30 },
                { "i3-2350M", 4, 2.30 },
                { "i3-2355M", 4, 1.40 },
                { "i3-2357M", 4, 1.30 },
                { "i3-2365M", 4, 1.40 },
                { "i3-2367M", 4, 1.40 },
                { "i3-2370LM", 4, 1.40 },
                { "i3-2370M", 4, 2.40 },
                { "i3-2375M", 4, 1.50 },
                { "i3-2377M", 4, 1.50 },
                { "i3-2390M", 4, 2.40 },
                { "i3-2393M", 4, 2.50 },
                { "i3-2394M", 4, 2.60 },
                { "i3-2395M", 4, 2.70 },
                { "i3-2397M", 4, 2.80 },
                { "i3-3110M", 4, 2.40 },
                { "i3-3115C", 4, 2.50 },
                { "i3-3120M", 4, 2.50 },
                { "i3-3120ME", 4, 2.40 },
                { "i3-3130M", 4, 2.60 },
                { "i3-3210", 4, 3.20 },
                { "i3-3217U", 4, 1.80 },
                { "i3-3217UE", 4, 1.60 },
                { "i3-3220", 4, 3.30 },
                { "i3-3220T", 4, 2.80 },
                { "i3-3225", 4, 3.30 },
                { "i3-3227U", 4, 1.90 },
                { "i3-3229Y", 4, 1.40 },
                { "i3-3240", 4, 3.40 },
                { "i3-3240T", 4, 2.90 },
                { "i3-3245", 4, 3.40 },
                { "i3-3250", 4, 3.50 },
                { "i3-3250T", 4, 3.00 },
                { "i3-330E", 4, 2.13 },
                { "i3-330M", 4, 2.13 },
                { "i3-330UM", 4, 1.20 },
                { "i3-350M", 4, 2.26 },
                { "i3-370M", 4, 2.40 },
                { "i3-380M", 4, 2.53 },
                { "i3-380UM", 4, 1.33 },
                { "i3-390M", 4, 2.66 },
                { "i3-4000M", 4, 2.40 },
                { "i3-4005U", 4, 1.70 },
                { "i3-4010M", 4, 1.70 },
                { "i3-4010U", 4, 1.70 },
                { "i3-4010Y", 4, 1.30 },
                { "i3-4012Y", 4, 1.50 },
                { "i3-4020Y", 4, 1.50 },
                { "i3-4025U", 4, 1.90 },
                { "i3-4030U", 4, 1.90 },
                { "i3-4030Y", 4, 1.60 },
                { "i3-4100E", 4, 2.40 },
                { "i3-4100M", 4, 2.50 },
                { "i3-4100U", 4, 1.80 },
                { "i3-4102E", 4, 1.60 },
                { "i3-4110E", 4, 2.60 },
                { "i3-4110M", 4, 2.60 },
                { "i3-4112E", 4, 1.80 },
                { "i3-4120U", 4, 2.00 },
                { "i3-4130", 4, 3.40 },
                { "i3-4130T", 4, 2.90 },
                { "i3-4150", 4, 3.50 },
                { "i3-4150T", 4, 3.00 },
                { "i3-4158U", 4, 2.00 },
                { "i3-4160", 4, 3.60 },
                { "i3-4160T", 4, 3.10 },
                { "i3-4170", 4, 3.70 },
                { "i3-4170T", 4, 3.20 },
                { "i3-4330", 4, 3.50 },
                { "i3-4330T", 4, 3.00 },
                { "i3-4330TE", 4, 2.40 },
                { "i3-4340", 4, 3.60 },
                { "i3-4340TE", 4, 2.60 },
                { "i3-4350", 4, 3.60 },
                { "i3-4350T", 4, 3.10 },
                { "i3-4360", 4, 3.70 },
                { "i3-4360T", 4, 3.20 },
                { "i3-4370", 4, 3.80 },
                { "i3-4370T", 4, 3.30 },
                { "i3-5005U", 4, 2.00 },
                { "i3-5010U", 4, 2.10 },
                { "i3-5015U", 4, 2.10 },
                { "i3-5020U", 4, 2.20 },
                { "i3-5157U", 4, 2.50 },
                { "i3-530", 4, 2.93 },
                { "i3-540", 4, 3.06 },
                { "i3-550", 4, 3.20 },
                { "i3-560", 4, 3.33 },
                { "i3-6006U", 4, 2.00 },
                { "i3-6098P", 4, 3.60 },
                { "i3-6100", 4, 3.70 },
                { "i3-6100E", 4, 2.70 },
                { "i3-6100H", 4, 2.70 },
                { "i3-6100T", 4, 3.20 },
                { "i3-6100TE", 4, 2.70 },
                { "i3-6100U", 4, 2.30 },
                { "i3-6102E", 4, 1.90 },
                { "i3-6120T", 4, 3.20 },
                { "i3-6157U", 4, 2.40 },
                { "i3-6167U", 4, 2.70 },
                { "i3-6300", 4, 3.80 },
                { "i3-6300T", 4, 3.30 },
                { "i3-6320", 4, 3.90 },
                { "i3-6320T", 4, 3.40 },
                { "i3-7007U", 4, 2.10 },
                { "i3-7020U", 4, 2.30 },
                { "i3-7100", 4, 3.90 },
                { "i3-7100E", 4, 2.90 },
                { "i3-7100H", 4, 3.00 },
                { "i3-7100T", 4, 3.40 },
                { "i3-7100U", 4, 2.40 },
                { "i3-7101E", 4, 3.90 },
                { "i3-7101TE", 4, 3.40 },
                { "i3-7102E", 4, 2.10 },
                { "i3-7110U", 4, 2.60 },
                { "i3-7120", 4, 4.00 },
                { "i3-7120T", 4, 3.50 },
                { "i3-7130U", 4, 2.70 },
                { "i3-7167U", 4, 2.80 },
                { "i3-7300", 4, 4.00 },
                { "i3-7300T", 4, 3.50 },
                { "i3-7310T", 4, 3.40 },
                { "i3-7310U", 4, 2.40 },
                { "i3-7320", 4, 4.10 },
                { "i3-7320T", 4, 3.50 },
                { "i3-7340", 4, 4.20 },
                { "i3-7350K", 4, 4.20 },
                { "i3-8000", 4, 3.60 },
                { "i3-8000T", 4, 3.10 },
                { "i3-8020", 4, 3.60 },
                { "i3-8020T", 4, 3.10 },
                { "i3-8100", 4, 3.60 },
                { "i3-8100B", 4, 3.60 },
                { "i3-8100F", 4, 3.60 },
                { "i3-8100H", 4, 3.00 },
                { "i3-8100T", 4, 3.10 },
                { "i3-8109U", 4, 3.00 },
                { "i3-8120", 4, 3.60 },
                { "i3-8120T", 4, 3.10 },
                { "i3-8121U", 4, 2.20 },
                { "i3-8130U", 4, 2.20 },
                { "i3-8140U", 4, 2.10 },
                { "i3-8145U", 4, 2.10 },
                { "i3-8145UE", 4, 2.20 },
                { "i3-8300", 4, 3.70 },
                { "i3-8300T", 4, 3.20 },
                { "i3-8320", 4, 3.70 },
                { "i3-8320T", 4, 3.20 },
                { "i3-8350K", 4, 4.00 },
                { "i3-9100", 4, 3.60 },
                { "i3-9100E", 4, 3.10 },
                { "i3-9100F", 4, 3.60 },
                { "i3-9100HL", 4, 1.60 },
                { "i3-9100T", 4, 3.10 },
                { "i3-9100TE", 4, 2.20 },
                { "i3-9300", 4, 3.70 },
                { "i3-9300T", 4, 3.20 },
                { "i3-9320", 4, 3.70 },
                { "i3-9350K", 4, 4.00 },
                { "i3-9350KF", 4, 4.00 },
                { "i3-N300", 8, 0.80 },
                { "i3-N305", 8, 1.80 },

                // i5 series
                { "i5-10200H", 8, 2.40 },
                { "i5-10210U", 8, 1.60 },
                { "i5-10210Y", 8, 1.00 },
                { "i5-10300H", 8, 2.50 },
                { "i5-1030G4", 8, 0.70 },
                { "i5-1030G7", 8, 0.80 },
                { "i5-1030NG7", 8, 1.10 },
                { "i5-10310U", 8, 1.70 },
                { "i5-10310Y", 8, 1.10 },
                { "i5-1035G1", 8, 1.00 },
                { "i5-1035G4", 8, 1.10 },
                { "i5-1035G7", 8, 1.20 },
                { "i5-1038NG7", 8, 2.00 },
                { "i5-10400", 12, 2.90 },
                { "i5-10400F", 12, 2.90 },
                { "i5-10400H", 8, 2.60 },
                { "i5-10400T", 12, 2.00 },
                { "i5-10500", 12, 3.10 },
                { "i5-10500E", 12, 3.10 },
                { "i5-10500H", 12, 2.50 },
                { "i5-10500T", 12, 2.30 },
                { "i5-10500TE", 12, 2.30 },
                { "i5-10505", 12, 3.20 },
                { "i5-10600", 12, 3.30 },
                { "i5-10600K", 12, 4.10 },
                { "i5-10600KF", 12, 4.10 },
                { "i5-10600T", 12, 2.40 },
                { "i5-1115G4", 4, 3.00 },
                { "i5-1125G4", 8, 2.00 },
                { "i5-11260H", 12, 2.60 },
                { "i5-11300H", 8, 3.10 },
                { "i5-1130G7", 8, 1.10 },
                { "i5-11320H", 8, 3.20 },
                { "i5-1135G7", 8, 2.40 },
                { "i5-11400", 12, 2.60 },
                { "i5-11400F", 12, 2.60 },
                { "i5-11400H", 12, 2.70 },
                { "i5-11400T", 12, 1.30 },
                { "i5-1140G7", 8, 1.10 },
                { "i5-1145G7", 8, 2.60 },
                { "i5-1145G7E", 8, 1.50 },
                { "i5-1145GRE", 8, 1.50 },
                { "i5-11500", 12, 2.70 },
                { "i5-11500B", 12, 3.30 },
                { "i5-11500H", 12, 2.90 },
                { "i5-11500HE", 12, 2.60 },
                { "i5-11500T", 12, 1.50 },
                { "i5-1155G7", 8, 2.50 },
                { "i5-11600", 12, 2.80 },
                { "i5-11600K", 12, 3.90 },
                { "i5-11600KF", 12, 3.90 },
                { "i5-11600T", 12, 1.70 },
                { "i5-1230U", 12, 1.00 },
                { "i5-1235U", 12, 1.30 },
                { "i5-12400", 12, 2.50 },
                { "i5-12400F", 12, 2.50 },
                { "i5-12400T", 12, 1.80 },
                { "i5-1240P", 16, 1.70 },
                { "i5-1240U", 12, 1.10 },
                { "i5-1245U", 12, 1.60 },
                { "i5-12490F", 12, 3.00 },
                { "i5-12500", 12, 3.00 },
                { "i5-12500H", 16, 2.50 },
                { "i5-12500HL", 16, 2.50 },
                { "i5-12500T", 12, 2.00 },
                { "i5-1250P", 16, 1.70 },
                { "i5-1250PE", 16, 1.70 },
                { "i5-12600", 12, 3.30 },
                { "i5-12600H", 16, 2.70 },
                { "i5-12600HE", 16, 2.50 },
                { "i5-12600HL", 16, 2.70 },
                { "i5-12600HX", 16, 2.50 },
                { "i5-12600K", 16, 3.70 },
                { "i5-12600KF", 16, 3.70 },
                { "i5-12600T", 12, 2.10 },
                { "i5-13400", 16, 2.50 },
                { "i5-13400F", 16, 2.50 },
                { "i5-13400T", 16, 1.30 },
                { "i5-1340P", 16, 1.90 },
                { "i5-1340PE", 16, 1.80 },
                { "i5-13490F", 16, 2.50 },
                { "i5-13500", 20, 2.50 },
                { "i5-13500H", 16, 2.60 },
                { "i5-13500T", 20, 1.60 },
                { "i5-13505H", 16, 2.60 },
                { "i5-1350P", 16, 1.90 },
                { "i5-1350PE", 16, 1.80 },
                { "i5-13600", 20, 2.70 },
                { "i5-13600H", 16, 2.80 },
                { "i5-13600HE", 16, 2.70 },
                { "i5-13600K", 20, 3.50 },
                { "i5-13600KF", 20, 3.50 },
                { "i5-13600T", 20, 1.80 },
                { "i5-2300", 4, 2.80 },
                { "i5-2310", 4, 2.90 },
                { "i5-2320", 4, 3.00 },
                { "i5-2380P", 4, 3.10 },
                { "i5-2390T", 4, 2.70 },
                { "i5-2400", 4, 3.10 },
                { "i5-2400S", 4, 2.50 },
                { "i5-2405S", 4, 2.50 },
                { "i5-2410M", 4, 2.30 },
                { "i5-2415M", 4, 2.30 },
                { "i5-2430M", 4, 2.40 },
                { "i5-2435M", 4, 2.40 },
                { "i5-2450M", 4, 2.50 },
                { "i5-2450P", 4, 3.20 },
                { "i5-2467M", 4, 1.60 },
                { "i5-2475M", 4, 2.40 },
                { "i5-2477M", 4, 1.80 },
                { "i5-2487M", 4, 1.90 },
                { "i5-2490M", 4, 2.50 },
                { "i5-2497M", 4, 2.30 },
                { "i5-2500", 4, 3.30 },
                { "i5-2500K", 4, 3.30 },
                { "i5-2500S", 4, 2.70 },
                { "i5-2500T", 4, 2.30 },
                { "i5-2510E", 4, 2.50 },
                { "i5-2515E", 4, 2.50 },
                { "i5-2520M", 4, 2.50 },
                { "i5-2537M", 4, 1.40 },
                { "i5-2540LM", 4, 2.60 },
                { "i5-2540M", 4, 2.60 },
                { "i5-2547M", 4, 1.60 },
                { "i5-2550K", 4, 3.40 },
                { "i5-2557M", 4, 1.70 },
                { "i5-2560LM", 4, 2.70 },
                { "i5-2560M", 4, 2.70 },
                { "i5-2580M", 4, 2.90 },
                { "i5-3210M", 4, 2.50 },
                { "i5-3230M", 4, 2.60 },
                { "i5-3317U", 4, 1.70 },
                { "i5-3320M", 4, 2.60 },
                { "i5-3330", 4, 3.00 },
                { "i5-3330S", 4, 2.70 },
                { "i5-3335S", 4, 2.70 },
                { "i5-3337U", 4, 1.80 },
                { "i5-3339Y", 4, 1.50 },
                { "i5-3340", 4, 3.10 },
                { "i5-3340M", 4, 2.70 },
                { "i5-3340S", 4, 2.80 },
                { "i5-3350P", 4, 3.10 },
                { "i5-3360M", 4, 2.80 },
                { "i5-3380M", 4, 2.90 },
                { "i5-3427U", 4, 1.80 },
                { "i5-3437U", 4, 1.90 },
                { "i5-3439Y", 4, 1.50 },
                { "i5-3450", 4, 3.10 },
                { "i5-3450S", 4, 2.80 },
                { "i5-3470", 4, 3.20 },
                { "i5-3470S", 4, 2.90 },
                { "i5-3470T", 4, 2.90 },
                { "i5-3475S", 4, 2.90 },
                { "i5-3550", 4, 3.30 },
                { "i5-3550S", 4, 3.00 },
                { "i5-3570", 4, 3.40 },
                { "i5-3570K", 4, 3.40 },
                { "i5-3570S", 4, 3.10 },
                { "i5-3570T", 4, 2.30 },
                { "i5-3610ME", 4, 2.70 },
                { "i5-4200H", 4, 2.80 },
                { "i5-4200M", 4, 2.50 },
                { "i5-4200U", 4, 1.60 },
                { "i5-4200Y", 4, 1.40 },
                { "i5-4202Y", 4, 1.60 },
                { "i5-4210H", 4, 2.90 },
                { "i5-4210M", 4, 2.60 },
                { "i5-4210U", 4, 1.70 },
                { "i5-4210Y", 4, 1.50 },
                { "i5-4220Y", 4, 1.60 },
                { "i5-4250U", 4, 1.30 },
                { "i5-4258U", 4, 2.40 },
                { "i5-4260U", 4, 1.40 },
                { "i5-4278U", 4, 2.60 },
                { "i5-4288U", 4, 2.60 },
                { "i5-4300M", 4, 2.60 },
                { "i5-4300U", 4, 1.90 },
                { "i5-4300Y", 4, 1.60 },
                { "i5-4302Y", 4, 1.60 },
                { "i5-4308U", 4, 2.80 },
                { "i5-430M", 4, 2.26 },
                { "i5-430UM", 4, 1.20 },
                { "i5-4310M", 4, 2.70 },
                { "i5-4310U", 4, 2.00 },
                { "i5-4330M", 4, 2.80 },
                { "i5-4340M", 4, 2.90 },
                { "i5-4350U", 4, 1.40 },
                { "i5-4360U", 4, 1.50 },
                { "i5-4400E", 4, 2.70 },
                { "i5-4402E", 4, 1.60 },
                { "i5-4402EC", 4, 2.50 },
                { "i5-4410E", 4, 2.90 },
                { "i5-4422E", 4, 1.80 },
                { "i5-4430", 4, 3.00 },
                { "i5-4430S", 4, 2.70 },
                { "i5-4440", 4, 3.10 },
                { "i5-4440S", 4, 2.80 },
                { "i5-4460", 4, 3.20 },
                { "i5-4460S", 4, 2.90 },
                { "i5-4460T", 4, 1.90 },
                { "i5-4470", 4, 3.40 },
                { "i5-450M", 4, 2.40 },
                { "i5-4570", 4, 3.20 },
                { "i5-4570R", 4, 2.70 },
                { "i5-4570S", 4, 2.90 },
                { "i5-4570T", 4, 2.90 },
                { "i5-4570TE", 4, 2.70 },
                { "i5-4590", 4, 3.30 },
                { "i5-4590S", 4, 3.00 },
                { "i5-4590T", 4, 2.00 },
                { "i5-460M", 4, 2.53 },
                { "i5-4670", 4, 3.40 },
                { "i5-4670K", 4, 3.40 },
                { "i5-4670R", 4, 3.00 },
                { "i5-4670S", 4, 3.10 },
                { "i5-4670T", 4, 2.30 },
                { "i5-4690", 4, 3.50 },
                { "i5-4690K", 4, 3.50 },
                { "i5-4690S", 4, 3.20 },
                { "i5-4690T", 4, 2.50 },
                { "i5-470UM", 4, 1.33 },
                { "i5-480M", 4, 2.66 },
                { "i5-5200U", 4, 2.20 },
                { "i5-520E", 4, 2.40 },
                { "i5-520M", 4, 2.40 },
                { "i5-520UM", 4, 1.06 },
                { "i5-5250U", 4, 1.60 },
                { "i5-5257U", 4, 2.70 },
                { "i5-5287U", 4, 2.90 },
                { "i5-5300U", 4, 2.30 },
                { "i5-5350H", 4, 3.00 },
                { "i5-5350U", 4, 1.80 },
                { "i5-540M", 4, 2.53 },
                { "i5-540UM", 4, 1.20 },
                { "i5-5575R", 4, 2.80 },
                { "i5-560M", 4, 2.66 },
                { "i5-560UM", 4, 1.33 },
                { "i5-5675C", 4, 3.10 },
                { "i5-5675R", 4, 3.10 },
                { "i5-580M", 4, 2.66 },
                { "i5-6198DU", 4, 2.30 },
                { "i5-6200U", 4, 2.30 },
                { "i5-6260U", 4, 1.80 },
                { "i5-6267U", 4, 2.90 },
                { "i5-6287U", 4, 3.10 },
                { "i5-6300HQ", 4, 2.30 },
                { "i5-6300U", 4, 2.40 },
                { "i5-6350HQ", 4, 2.30 },
                { "i5-6360U", 4, 2.00 },
                { "i5-6400", 4, 2.70 },
                { "i5-6400T", 4, 2.20 },
                { "i5-6402P", 4, 2.80 },
                { "i5-6440EQ", 4, 2.70 },
                { "i5-6440HQ", 4, 2.60 },
                { "i5-6442EQ", 4, 1.90 },
                { "i5-650", 4, 3.20 },
                { "i5-6500", 4, 3.20 },
                { "i5-6500T", 4, 2.50 },
                { "i5-6500TE", 4, 2.30 },
                { "i5-655K", 4, 3.20 },
                { "i5-6585R", 4, 2.80 },
                { "i5-660", 4, 3.33 },
                { "i5-6600", 4, 3.30 },
                { "i5-6600K", 4, 3.50 },
                { "i5-6600T", 4, 2.70 },
                { "i5-661", 4, 3.33 },
                { "i5-6685R", 4, 3.00 },
                { "i5-670", 4, 3.46 },
                { "i5-680", 4, 3.60 },
                { "i5-7200U", 4, 2.50 },
                { "i5-7210U", 4, 2.50 },
                { "i5-7260U", 4, 2.20 },
                { "i5-7267U", 4, 3.10 },
                { "i5-7287U", 4, 3.30 },
                { "i5-7300HQ", 4, 2.50 },
                { "i5-7300U", 4, 2.60 },
                { "i5-7360U", 4, 2.30 },
                { "i5-7400", 4, 3.00 },
                { "i5-7400T", 4, 2.40 },
                { "i5-7440EQ", 4, 2.90 },
                { "i5-7440HQ", 4, 2.80 },
                { "i5-7442EQ", 4, 2.10 },
                { "i5-750", 4, 2.66 },
                { "i5-7500", 4, 3.40 },
                { "i5-7500T", 4, 2.70 },
                { "i5-750S", 4, 2.40 },
                { "i5-760", 4, 2.80 },
                { "i5-7600", 4, 3.50 },
                { "i5-7600K", 4, 3.80 },
                { "i5-7600T", 4, 2.80 },
                { "i5-7640X", 4, 4.00 },
                { "i5-7Y54", 4, 1.20 },
                { "i5-7Y57", 4, 1.20 },
                { "i5-8200Y", 4, 1.30 },
                { "i5-8210Y", 4, 1.60 },
                { "i5-8250U", 8, 1.60 },
                { "i5-8257U", 8, 1.40 },
                { "i5-8259U", 8, 2.30 },
                { "i5-8260U", 8, 1.60 },
                { "i5-8265U", 8, 1.60 },
                { "i5-8269U", 8, 2.60 },
                { "i5-8279U", 8, 2.40 },
                { "i5-8300H", 8, 2.30 },
                { "i5-8305G", 8, 2.80 },
                { "i5-8310Y", 4, 1.60 },
                { "i5-8350U", 8, 1.70 },
                { "i5-8365U", 8, 1.60 },
                { "i5-8365UE", 8, 1.60 },
                { "i5-8400", 6, 2.80 },
                { "i5-8400B", 6, 2.80 },
                { "i5-8400H", 8, 2.50 },
                { "i5-8400T", 6, 1.70 },
                { "i5-8420", 6, 2.80 },
                { "i5-8420T", 6, 1.70 },
                { "i5-8500", 6, 3.00 },
                { "i5-8500B", 6, 3.00 },
                { "i5-8500T", 6, 2.10 },
                { "i5-8550", 6, 2.50 },
                { "i5-8600", 6, 3.10 },
                { "i5-8600K", 6, 3.60 },
                { "i5-8600T", 6, 2.30 },
                { "i5-8650", 6, 2.90 },
                { "i5-9300H", 8, 2.40 },
                { "i5-9300HF", 8, 2.40 },
                { "i5-9400", 6, 2.90 },
                { "i5-9400F", 6, 2.90 },
                { "i5-9400H", 8, 2.50 },
                { "i5-9400T", 6, 1.80 },
                { "i5-9500", 6, 3.00 },
                { "i5-9500E", 6, 3.00 },
                { "i5-9500F", 6, 3.00 },
                { "i5-9500T", 6, 2.20 },
                { "i5-9500TE", 6, 2.20 },
                { "i5-9600", 6, 3.10 },
                { "i5-9600K", 6, 3.70 },
                { "i5-9600KF", 6, 3.70 },
                { "i5-9600T", 6, 2.30 },
                { "i5-12450H", 12, 2.00 },
                { "i5-12450HX", 12, 2.40 },
                { "i5-12650H", 16, 2.30 },
                { "i5-13420H", 12, 2.10 },
                { "i5-13450HX", 16, 2.40 },
                { "i5-13500HX", 20, 2.50 },
                { "i5-13600HX", 20, 2.60 },
                { "i5-14400", 16, 2.50 },
                { "i5-14400F", 16, 2.50 },
                { "i5-14400T", 16, 1.50 },
                { "i5-14450HX", 16, 2.40 },
                { "i5-14490F", 16, 2.80 },
                { "i5-14500", 20, 2.60 },
                { "i5-14500GX", 20, 2.60 },
                { "i5-14500HX", 20, 2.60 },
                { "i5-14500T", 20, 1.70 },
                { "i5-14500TE", 20, 1.20 },
                { "i5-14600", 20, 2.70 },
                { "i5-14600K", 20, 3.50 },
                { "i5-14600KF", 20, 3.50 },
                { "i5-14600T", 20, 1.80 },

                // i7 series
                { "i7-10510U", 8, 1.80 },
                { "i7-10510Y", 8, 1.20 },
                { "i7-1060G7", 8, 1.00 },
                { "i7-10610U", 8, 1.80 },
                { "i7-1065G7", 8, 1.30 },
                { "i7-1068G7", 8, 2.30 },
                { "i7-1068NG7", 8, 2.30 },
                { "i7-10700", 16, 2.90 },
                { "i7-10700E", 16, 2.90 },
                { "i7-10700F", 16, 2.90 },
                { "i7-10700K", 16, 3.80 },
                { "i7-10700KF", 16, 3.80 },
                { "i7-10700T", 16, 2.00 },
                { "i7-10700TE", 16, 2.00 },
                { "i7-10710U", 12, 1.10 },
                { "i7-10750H", 12, 2.60 },
                { "i7-10810U", 12, 1.10 },
                { "i7-10850H", 12, 2.70 },
                { "i7-10870H", 16, 2.20 },
                { "i7-10875H", 16, 2.30 },
                { "i7-11370H", 8, 3.30 },
                { "i7-11375H", 8, 3.30 },
                { "i7-11390H", 8, 3.40 },
                { "i7-11600H", 12, 2.90 },
                { "i7-1160G7", 8, 1.20 },
                { "i7-1165G7", 8, 2.80 },
                { "i7-11700", 16, 2.50 },
                { "i7-11700B", 16, 3.20 },
                { "i7-11700F", 16, 2.50 },
                { "i7-11700K", 16, 3.60 },
                { "i7-11700KF", 16, 3.60 },
                { "i7-11700T", 16, 1.40 },
                { "i7-11800H", 16, 2.30 },
                { "i7-1180G7", 8, 1.30 },
                { "i7-11850H", 16, 2.50 },
                { "i7-11850HE", 16, 2.60 },
                { "i7-1185G7", 8, 3.00 },
                { "i7-1185G7E", 8, 1.80 },
                { "i7-1185GRE", 8, 1.80 },
                { "i7-1195G7", 8, 2.90 },
                { "i7-1250U", 12, 1.10 },
                { "i7-1255U", 12, 1.70 },
                { "i7-1260P", 16, 2.10 },
                { "i7-1260U", 12, 1.10 },
                { "i7-1265U", 12, 1.80 },
                { "i7-12700", 20, 2.10 },
                { "i7-12700F", 20, 2.10 },
                { "i7-12700K", 20, 3.60 },
                { "i7-12700KF", 20, 3.60 },
                { "i7-12700T", 20, 1.40 },
                { "i7-12700H", 20, 2.30 },
                { "i7-1270P", 16, 2.20 },
                { "i7-1270PE", 16, 2.20 },
                { "i7-1360P", 16, 2.20 },
                { "i7-13700", 24, 2.10 },
                { "i7-13700F", 24, 2.10 },
                { "i7-13700K", 24, 3.40 },
                { "i7-13700KF", 24, 3.40 },
                { "i7-13700T", 24, 1.40 },
                { "i7-13790F", 24, 2.10 },
                { "i7-2535QM", 8, 2.40 },
                { "i7-2570QM", 8, 2.70 },
                { "i7-2600", 8, 3.40 },
                { "i7-2600K", 8, 3.40 },
                { "i7-2600S", 8, 2.80 },
                { "i7-2610UE", 4, 1.50 },
                { "i7-2617M", 4, 1.50 },
                { "i7-2620M", 4, 2.70 },
                { "i7-2627M", 4, 1.50 },
                { "i7-2629M", 4, 2.10 },
                { "i7-2630QM", 8, 2.00 },
                { "i7-2635QM", 8, 2.00 },
                { "i7-2637M", 4, 1.70 },
                { "i7-2640M", 4, 2.80 },
                { "i7-2649M", 4, 2.30 },
                { "i7-2655LE", 4, 2.20 },
                { "i7-2655QM", 8, 2.40 },
                { "i7-2657M", 4, 1.60 },
                { "i7-2660M", 4, 2.20 },
                { "i7-2667M", 4, 1.80 },
                { "i7-2669M", 4, 2.10 },
                { "i7-2670QM", 8, 2.20 },
                { "i7-2675QM", 8, 2.20 },
                { "i7-2677M", 4, 1.80 },
                { "i7-2685QM", 8, 2.50 },
                { "i7-2689M", 4, 2.00 },
                { "i7-2700K", 8, 3.50 },
                { "i7-2710QE", 8, 2.10 },
                { "i7-2715QE", 8, 2.10 },
                { "i7-2720QM", 8, 2.20 },
                { "i7-2740QM", 8, 2.40 },
                { "i7-2760QM", 8, 2.40 },
                { "i7-2820QM", 8, 2.30 },
                { "i7-2840QM", 8, 2.40 },
                { "i7-2860QM", 8, 2.50 },
                { "i7-2920XM", 8, 2.50 },
                { "i7-2960XM", 8, 2.70 },
                { "i7-3517U", 4, 1.90 },
                { "i7-3517UE", 4, 1.70 },
                { "i7-3520M", 4, 2.90 },
                { "i7-3537U", 4, 2.00 },
                { "i7-3540M", 4, 3.00 },
                { "i7-3555LE", 4, 2.50 },
                { "i7-3610QE", 8, 2.30 },
                { "i7-3610QM", 8, 2.30 },
                { "i7-3612QE", 8, 2.10 },
                { "i7-3612QM", 8, 2.10 },
                { "i7-3615QE", 8, 2.30 },
                { "i7-3615QM", 8, 2.30 },
                { "i7-3630QM", 8, 2.40 },
                { "i7-3632QM", 8, 2.20 },
                { "i7-3635QM", 8, 2.40 },
                { "i7-3667U", 4, 2.00 },
                { "i7-3687U", 4, 2.10 },
                { "i7-3689Y", 4, 1.50 },
                { "i7-3720QM", 8, 2.60 },
                { "i7-3740QM", 8, 2.70 },
                { "i7-3770", 8, 3.40 },
                { "i7-3770K", 8, 3.50 },
                { "i7-3770S", 8, 3.10 },
                { "i7-3770T", 8, 2.50 },
                { "i7-3820", 8, 3.60 },
                { "i7-3820QM", 8, 2.70 },
                { "i7-3840QM", 8, 2.80 },
                { "i7-3920XM", 8, 2.90 },
                { "i7-3930K", 12, 3.20 },
                { "i7-3940XM", 8, 3.00 },
                { "i7-3960X", 12, 3.30 },
                { "i7-3970X", 12, 3.50 },
                { "i7-4500U", 4, 1.80 },
                { "i7-4510U", 4, 2.00 },
                { "i7-4550U", 4, 1.50 },
                { "i7-4558U", 4, 2.80 },
                { "i7-4578U", 4, 3.00 },
                { "i7-4600M", 4, 2.90 },
                { "i7-4600U", 4, 2.10 },
                { "i7-4610M", 4, 3.00 },
                { "i7-4610Y", 4, 1.70 },
                { "i7-4650U", 4, 1.70 },
                { "i7-4700EC", 8, 2.70 },
                { "i7-4700EQ", 8, 2.40 },
                { "i7-4700HQ", 8, 2.40 },
                { "i7-4700MQ", 8, 2.40 },
                { "i7-4701EQ", 8, 2.40 },
                { "i7-4702EC", 8, 2.00 },
                { "i7-4702HQ", 8, 2.20 },
                { "i7-4702MQ", 8, 2.20 },
                { "i7-4710HQ", 8, 2.50 },
                { "i7-4710MQ", 8, 2.50 },
                { "i7-4712HQ", 8, 2.30 },
                { "i7-4712MQ", 8, 2.30 },
                { "i7-4720HQ", 8, 2.60 },
                { "i7-4722HQ", 8, 2.40 },
                { "i7-4750HQ", 8, 2.00 },
                { "i7-4760HQ", 8, 2.10 },
                { "i7-4765T", 8, 2.00 },
                { "i7-4770", 8, 3.40 },
                { "i7-4770HQ", 8, 2.20 },
                { "i7-4770K", 8, 3.50 },
                { "i7-4770R", 8, 3.20 },
                { "i7-4770S", 8, 3.10 },
                { "i7-4770T", 8, 2.50 },
                { "i7-4770TE", 8, 2.30 },
                { "i7-4771", 8, 3.50 },
                { "i7-4785T", 8, 2.20 },
                { "i7-4790", 8, 3.60 },
                { "i7-4790K", 8, 4.00 },
                { "i7-4790S", 8, 3.20 },
                { "i7-4790T", 8, 2.70 },
                { "i7-4800MQ", 8, 2.70 },
                { "i7-4810MQ", 8, 2.80 },
                { "i7-4820K", 8, 3.70 },
                { "i7-4850EQ", 8, 1.60 },
                { "i7-4850HQ", 8, 2.30 },
                { "i7-4860EQ", 8, 1.80 },
                { "i7-4860HQ", 8, 2.40 },
                { "i7-4870HQ", 8, 2.50 },
                { "i7-4900MQ", 8, 2.80 },
                { "i7-4910MQ", 8, 2.90 },
                { "i7-4930K", 12, 3.40 },
                { "i7-4930MX", 8, 3.00 },
                { "i7-4940MX", 8, 3.10 },
                { "i7-4950HQ", 8, 2.40 },
                { "i7-4960HQ", 8, 2.60 },
                { "i7-4960X", 12, 3.60 },
                { "i7-4980HQ", 8, 2.80 },
                { "i7-5500U", 4, 2.40 },
                { "i7-5550U", 4, 2.00 },
                { "i7-5557U", 4, 3.10 },
                { "i7-5600U", 4, 2.60 },
                { "i7-5650U", 4, 2.20 },
                { "i7-5700EQ", 8, 2.60 },
                { "i7-5700HQ", 8, 2.70 },
                { "i7-5750HQ", 8, 2.50 },
                { "i7-5775C", 8, 3.30 },
                { "i7-5775R", 8, 3.30 },
                { "i7-5820K", 12, 3.30 },
                { "i7-5850EQ", 8, 2.70 },
                { "i7-5850HQ", 8, 2.70 },
                { "i7-5930K", 12, 3.50 },
                { "i7-5950HQ", 8, 2.90 },
                { "i7-5960X", 16, 3.00 },
                { "i7-610E", 4, 2.53 },
                { "i7-620LE", 4, 2.00 },
                { "i7-620LM", 4, 2.00 },
                { "i7-620M", 4, 2.66 },
                { "i7-620UE", 4, 1.06 },
                { "i7-620UM", 4, 1.20 },
                { "i7-640LM", 4, 2.13 },
                { "i7-640M", 4, 2.80 },
                { "i7-640UM", 4, 1.20 },
                { "i7-6498DU", 4, 2.50 },
                { "i7-6500U", 4, 2.50 },
                { "i7-6560U", 4, 2.20 },
                { "i7-6567U", 4, 3.30 },
                { "i7-6600U", 4, 2.60 },
                { "i7-660LM", 4, 2.26 },
                { "i7-660UE", 4, 1.33 },
                { "i7-660UM", 4, 1.33 },
                { "i7-6650U", 4, 2.20 },
                { "i7-6660U", 4, 2.40 },
                { "i7-6700", 8, 3.40 },
                { "i7-6700HQ", 8, 2.60 },
                { "i7-6700K", 8, 4.00 },
                { "i7-6700T", 8, 2.80 },
                { "i7-6700TE", 8, 2.40 },
                { "i7-6770HQ", 8, 2.60 },
                { "i7-6785R", 8, 3.30 },
                { "i7-6800K", 12, 3.40 },
                { "i7-680UM", 4, 1.46 },
                { "i7-6820EQ", 8, 2.80 },
                { "i7-6820HK", 8, 2.70 },
                { "i7-6820HQ", 8, 2.70 },
                { "i7-6822EQ", 8, 2.00 },
                { "i7-6850K", 12, 3.60 },
                { "i7-6870HQ", 8, 2.70 },
                { "i7-6900K", 16, 3.20 },
                { "i7-6920HQ", 8, 2.90 },
                { "i7-6950X", 20, 3.00 },
                { "i7-6970HQ", 8, 2.80 },
                { "i7-720QM", 8, 1.60 },
                { "i7-740QM", 8, 1.73 },
                { "i7-7500U", 4, 2.70 },
                { "i7-7510U", 4, 1.80 },
                { "i7-7560U", 4, 2.40 },
                { "i7-7567U", 4, 3.50 },
                { "i7-7600U", 4, 2.80 },
                { "i7-7660U", 4, 2.50 },
                { "i7-7700", 8, 3.60 },
                { "i7-7700HQ", 8, 2.80 },
                { "i7-7700K", 8, 4.20 },
                { "i7-7700T", 8, 2.90 },
                { "i7-7740X", 8, 4.30 },
                { "i7-7800X", 12, 3.50 },
                { "i7-7820EQ", 8, 3.00 },
                { "i7-7820HK", 8, 2.90 },
                { "i7-7820HQ", 8, 2.90 },
                { "i7-7820X", 16, 3.60 },
                { "i7-7920HQ", 8, 3.10 },
                { "i7-7Y75", 4, 1.30 },
                { "i7-8086K", 12, 4.00 },
                { "i7-820QM", 8, 1.73 },
                { "i7-840QM", 8, 1.86 },
                { "i7-8500Y", 4, 1.50 },
                { "i7-8550U", 8, 1.80 },
                { "i7-8557U", 8, 1.70 },
                { "i7-8559U", 8, 2.70 },
                { "i7-8565U", 8, 1.80 },
                { "i7-8569U", 8, 2.80 },
                { "i7-860", 8, 2.80 },
                { "i7-860S", 8, 2.53 },
                { "i7-8650U", 8, 1.90 },
                { "i7-8665U", 8, 1.90 },
                { "i7-8665UE", 8, 1.70 },
                { "i7-8670", 12, 2.90 },
                { "i7-8670T", 12, 2.20 },
                { "i7-870", 8, 2.93 },
                { "i7-8700", 12, 3.20 },
                { "i7-8700B", 12, 3.20 },
                { "i7-8700K", 12, 3.70 },
                { "i7-8700T", 12, 2.40 },
                { "i7-8705G", 8, 3.10 },
                { "i7-8706G", 8, 3.10 },
                { "i7-8709G", 8, 3.10 },
                { "i7-870S", 8, 2.66 },
                { "i7-8750H", 12, 2.20 },
                { "i7-875K", 8, 2.93 },
                { "i7-880", 8, 3.06 },
                { "i7-8809G", 8, 3.10 },
                { "i7-8850H", 12, 2.60 },
                { "i7-920", 8, 2.66 },
                { "i7-920XM", 8, 2.00 },
                { "i7-930", 8, 2.80 },
                { "i7-940", 8, 2.93 },
                { "i7-940XM", 8, 2.13 },
                { "i7-950", 8, 3.06 },
                { "i7-960", 8, 3.20 },
                { "i7-965", 8, 3.20 },
                { "i7-970", 12, 3.20 },
                { "i7-9700", 8, 3.00 },
                { "i7-9700E", 8, 2.60 },
                { "i7-9700F", 8, 3.00 },
                { "i7-9700K", 8, 3.60 },
                { "i7-9700KF", 8, 3.60 },
                { "i7-9700T", 8, 2.00 },
                { "i7-9700TE", 8, 1.80 },
                { "i7-975", 8, 3.33 },
                { "i7-9750H", 12, 2.60 },
                { "i7-9750HF", 12, 2.60 },
                { "i7-980", 12, 3.33 },
                { "i7-9800X", 16, 3.80 },
                { "i7-980X", 12, 3.33 },
                { "i7-9850H", 12, 2.60 },
                { "i7-9850HE", 12, 2.70 },
                { "i7-9850HL", 12, 1.90 },
                { "i7-990X", 12, 3.46 },
                { "i7-12650H", 16, 2.30 },
                { "i7-12800H", 20, 2.40 },
                { "i7-12800HE", 20, 2.40 },
                { "i7-12800HX", 24, 2.00 },
                { "i7-12850HX", 24, 2.10 },
                { "i7-13620H", 16, 2.40 },
                { "i7-13650HX", 20, 2.60 },
                { "i7-13700H", 20, 2.40 },
                { "i7-13700HX", 24, 2.10 },
                { "i7-13705H", 20, 2.40 },
                { "i7-13800H", 20, 2.50 },
                { "i7-13850HX", 28, 2.10 },
                { "i7-14650HX", 24, 2.20 },
                { "i7-14700", 28, 2.10 },
                { "i7-14700F", 28, 2.10 },
                { "i7-14700H", 28, 2.30 },
                { "i7-14700HX", 28, 2.10 },
                { "i7-14700K", 28, 3.40 },
                { "i7-14700KF", 28, 3.40 },
                { "i7-14700T", 28, 1.30 },
                { "i7-14790F", 24, 2.10 },
                { "i7-14950HX", 24, 2.20 },

                // i9 series
                { "i9-10850K", 20, 3.60 },
                { "i9-10885H", 16, 2.40 },
                { "i9-10900", 20, 2.80 },
                { "i9-10900E", 20, 2.80 },
                { "i9-10900F", 20, 2.80 },
                { "i9-10900K", 20, 3.70 },
                { "i9-10900KF", 20, 3.70 },
                { "i9-10900T", 20, 1.90 },
                { "i9-10900TE", 20, 1.80 },
                { "i9-10900X", 20, 3.70 },
                { "i9-10910", 20, 3.60 },
                { "i9-10920X", 24, 3.50 },
                { "i9-10940X", 28, 3.30 },
                { "i9-10980HK", 16, 2.40 },
                { "i9-10980XE", 36, 3.00 },
                { "i9-11900", 16, 2.50 },
                { "i9-11900F", 16, 2.50 },
                { "i9-11900H", 16, 2.50 },
                { "i9-11900K", 16, 3.50 },
                { "i9-11900KB", 16, 3.30 },
                { "i9-11900KF", 16, 3.50 },
                { "i9-11900T", 16, 1.50 },
                { "i9-11950H", 16, 2.60 },
                { "i9-11980HK", 16, 2.60 },
                { "i9-12900", 24, 2.40 },
                { "i9-12900F", 24, 2.40 },
                { "i9-12900H", 20, 2.50 },
                { "i9-12900K", 24, 3.20 },
                { "i9-12900KF", 24, 3.20 },
                { "i9-12900KS", 24, 3.40 },
                { "i9-12900T", 24, 1.40 },
                { "i9-13900", 32, 2.00 },
                { "i9-13900E", 32, 1.80 },
                { "i9-13900F", 32, 2.00 },
                { "i9-13900HX", 32, 2.20 },
                { "i9-13900K", 32, 3.00 },
                { "i9-13900KF", 32, 3.00 },
                { "i9-13900KS", 32, 3.20 },
                { "i9-13900T", 32, 1.10 },
                { "i9-13900TE", 32, 1.00 },
                { "i9-13950HX", 32, 2.20 },
                { "i9-13980HX", 32, 2.20 },
                { "i9-14900", 32, 2.00 },
                { "i9-14900F", 32, 2.00 },
                { "i9-14900HX", 32, 2.20 },
                { "i9-14900K", 32, 3.20 },
                { "i9-14900KF", 32, 3.20 },
                { "i9-14900KS", 32, 3.20 },
                { "i9-14900T", 32, 1.10 },
                { "i9-7900X", 20, 3.30 },
                { "i9-7920X", 24, 2.90 },
                { "i9-7940X", 28, 3.10 },
                { "i9-7960X", 32, 2.80 },
                { "i9-7980XE", 36, 2.60 },
                { "i9-8950HK", 12, 2.90 },
                { "i9-9820X", 20, 3.30 },
                { "i9-9880H", 16, 2.30 },
                { "i9-9900", 16, 3.10 },
                { "i9-9900K", 16, 3.60 },
                { "i9-9900KF", 16, 3.60 },
                { "i9-9900KS", 16, 4.00 },
                { "i9-9900T", 16, 2.10 },
                { "i9-9900X", 20, 3.50 },
                { "i9-9920X", 24, 3.50 },
                { "i9-9940X", 28, 3.30 },
                { "i9-9960X", 32, 3.10 },
                { "i9-9980HK", 16, 2.40 },
                { "i9-9980XE", 36, 3.00 },
                { "i9-9990XE", 28, 4.00 },
                { "i9-12900E", 24, 2.30 },
                { "i9-12900HK", 20, 2.50 },
                { "i9-12900HX", 24, 2.30 },
                { "i9-12900TE", 24, 1.10 },
                { "i9-12950HX", 24, 2.30 },
                { "i9-13900H", 20, 2.60 },
                { "i9-13900HK", 20, 2.60 },
                { "i9-13905H", 20, 2.60 },
                { "i9-14900H", 32, 2.20 },
                { "i9-14901KE", 16, 3.80 }
            };
            out_ptr = db;
            out_size = sizeof(db) / sizeof(cpu_entry);
        }

        inline static void get_intel_xeon_db(const cpu_entry*& out_ptr, size_t& out_size) {
            static const cpu_entry db[] = {
                { "D-1518", 8, 2.20 },
                { "D-1520", 8, 2.20 },
                { "D-1521", 8, 2.40 },
                { "D-1527", 8, 2.20 },
                { "D-1528", 12, 1.90 },
                { "D-1529", 8, 1.30 },
                { "D-1531", 12, 2.20 },
                { "D-1537", 16, 1.70 },
                { "D-1539", 16, 1.60 },
                { "D-1540", 16, 2.00 },
                { "D-1541", 16, 2.10 },
                { "D-1548", 16, 2.00 },
                { "D-1557", 24, 1.50 },
                { "D-1559", 24, 1.50 },
                { "D-1567", 24, 2.10 },
                { "D-1571", 32, 1.30 },
                { "D-1577", 32, 1.30 },
                { "D-1581", 32, 1.80 },
                { "D-1587", 32, 1.70 },
                { "D-1513N", 8, 1.60 },
                { "D-1523N", 8, 2.00 },
                { "D-1533N", 12, 2.10 },
                { "D-1543N", 16, 1.90 },
                { "D-1553N", 16, 2.30 },
                { "D-1602", 4, 2.50 },
                { "D-1612", 8, 1.50 },
                { "D-1622", 8, 2.60 },
                { "D-1627", 8, 2.90 },
                { "D-1632", 16, 1.50 },
                { "D-1637", 12, 2.90 },
                { "D-1623N", 8, 2.40 },
                { "D-1633N", 12, 2.50 },
                { "D-1649N", 16, 2.30 },
                { "D-1653N", 16, 2.80 },
                { "D-2141I", 16, 2.20 },
                { "D-2161I", 24, 2.20 },
                { "D-2191", 36, 1.60 },
                { "D-2123IT", 8, 2.20 },
                { "D-2142IT", 16, 1.90 },
                { "D-2143IT", 16, 2.20 },
                { "D-2163IT", 24, 2.10 },
                { "D-2173IT", 28, 1.70 },
                { "D-2183IT", 32, 2.20 },
                { "D-2145NT", 16, 1.90 },
                { "D-2146NT", 16, 2.30 },
                { "D-2166NT", 24, 2.00 },
                { "D-2177NT", 28, 1.90 },
                { "D-2187NT", 32, 2.00 },

                // Xeon E
                { "E-2104G", 4, 3.20 },
                { "E-2124", 4, 3.30 },
                { "E-2124G", 4, 3.40 },
                { "E-2126G", 6, 3.30 },
                { "E-2134", 8, 3.50 },
                { "E-2136", 12, 3.30 },
                { "E-2144G", 8, 3.60 },
                { "E-2146G", 12, 3.50 },
                { "E-2174G", 8, 3.80 },
                { "E-2176G", 12, 3.70 },
                { "E-2186G", 12, 3.80 },
                { "E-2176M", 12, 2.70 },
                { "E-2186M", 12, 2.90 },
                { "E-2224", 4, 3.40 },
                { "E-2224G", 4, 3.50 },
                { "E-2226G", 6, 3.40 },
                { "E-2234", 8, 3.60 },
                { "E-2236", 12, 3.40 },
                { "E-2244G", 8, 3.80 },
                { "E-2246G", 12, 3.60 },
                { "E-2274G", 8, 4.00 },
                { "E-2276G", 12, 3.80 },
                { "E-2278G", 16, 3.40 },
                { "E-2286G", 12, 4.00 },
                { "E-2288G", 16, 3.70 },
                { "E-2276M", 12, 2.80 },
                { "E-2286M", 16, 2.40 },

                // Xeon W
                { "W-2102", 4, 2.90 },
                { "W-2104", 4, 3.20 },
                { "W-2123", 8, 3.60 },
                { "W-2125", 8, 4.00 },
                { "W-2133", 12, 3.60 },
                { "W-2135", 12, 3.70 },
                { "W-2140B", 16, 3.20 },
                { "W-2145", 16, 3.70 },
                { "W-2150B", 20, 3.00 },
                { "W-2155", 20, 3.30 },
                { "W-2170B", 28, 2.50 },
                { "W-2175", 28, 2.50 },
                { "W-2191B", 36, 2.30 },
                { "W-2195", 36, 2.30 },
                { "W-3175X", 56, 3.10 },
                { "W-3223", 16, 3.50 },
                { "W-3225", 16, 3.70 },
                { "W-3235", 24, 3.30 },
                { "W-3245", 32, 3.20 },
                { "W-3245M", 32, 3.20 },
                { "W-3265", 48, 2.70 },
                { "W-3265M", 48, 2.70 },
                { "W-3275", 56, 2.50 },
                { "W-3275M", 56, 2.50 },
                { "w3-2423", 12, 2.10 },
                { "w3-2425", 12, 3.00 },
                { "w3-2435", 16, 3.10 },
                { "w5-2445", 20, 3.10 },
                { "w5-2455X", 24, 3.20 },
                { "w5-2465X", 32, 3.10 },
                { "w7-2475X", 40, 2.60 },
                { "w7-2495X", 48, 2.50 },
                { "w5-3425", 24, 3.20 },
                { "w5-3435X", 32, 3.10 },
                { "w7-3445", 40, 2.60 },
                { "w7-3455", 48, 2.50 },
                { "w7-3465X", 56, 2.50 },
                { "w9-3475X", 72, 2.20 },
                { "w9-3495X", 112, 1.90 },
                { "w3-2525", 16, 3.50 },
                { "w3-2535", 20, 3.50 },
                { "w5-2545", 24, 3.50 },
                { "w5-2555X", 28, 3.30 },
                { "w5-2565X", 36, 3.20 },
                { "w7-2575X", 44, 3.00 },
                { "w7-2595X", 52, 2.80 },
                { "w5-3525", 32, 3.20 },
                { "w5-3535X", 40, 3.20 },
                { "w7-3545", 48, 2.70 },
                { "w7-3555", 56, 2.70 },
                { "w7-3565X", 64, 2.60 },
                { "w9-3575X", 88, 2.20 },
                { "w9-3595X", 120, 2.00 }
            };
            out_ptr = db;
            out_size = sizeof(db) / sizeof(cpu_entry);
        }

        inline static void get_intel_ultra_db(const cpu_entry*& db, size_t& size) {
            static const cpu_entry intel_ultra[] = {
                // Series 2 (Arrow Lake - Desktop/Mobile) - No HT on P-Cores
                { "285K", 24, 3.70 },
                { "265K", 20, 3.90 },
                { "265KF", 20, 3.90 },
                { "245K", 14, 4.20 },
                { "245KF", 14, 4.20 },

                // Series 2 (Lunar Lake - Mobile)
                { "288V", 8, 3.30 },
                { "268V", 8, 3.30 },
                { "258V", 8, 2.20 },

                // Series 1 (Meteor Lake - Mobile) - P-Cores have HT
                // 6P + 8E + 2LP = 16 Cores. Threads = (6*2) + 8 + 2 = 22 Threads
                { "185H", 22, 2.30 },
                { "165H", 22, 1.40 },
                { "155H", 22, 1.40 },

                // 4P + 8E + 2LP = 14 Cores. Threads = (4*2) + 8 + 2 = 18 Threads
                { "135H", 18, 1.70 },
                { "125H", 18, 1.20 },

                // 2P + 8E + 2LP = 12 Cores. Threads = (2*2) + 8 + 2 = 14 Threads
                { "165U", 14, 1.70 },
                { "155U", 14, 1.70 },
                { "135U", 14, 1.60 },
                { "125U", 14, 1.30 },
            };
            db = intel_ultra;
            size = sizeof(intel_ultra) / sizeof(cpu_entry);
        }

        inline static void get_amd_ryzen_db(const cpu_entry*& out_ptr, size_t& out_size) {
            static const cpu_entry db[] = {
                // 3015/3020
                { "3015ce", 4, 1.20 },
                { "3015e", 4, 1.20 },
                { "3020e", 2, 1.20 },

                // Athlon/Ax suffixes
                { "860k", 4, 3.70 },
                { "870k", 4, 3.90 },
                { "pro-7350b", 4, 3.10 },
                { "pro-7800b", 4, 3.50 },
                { "pro-7850b", 4, 3.70 },
                { "a10-6700", 4, 3.70 },
                { "a10-6700t", 4, 2.50 },
                { "a10-6790b", 4, 4.00 },
                { "a10-6790k", 4, 4.00 },
                { "a10-6800b", 4, 4.10 },
                { "a10-6800k", 4, 4.10 },
                { "a10-7300", 4, 1.90 },
                { "a10-7400p", 4, 2.50 },
                { "a10-7700k", 4, 3.40 },
                { "a10-7800", 4, 3.50 },
                { "a10-7850k", 4, 3.70 },
                { "a10-7860k", 4, 3.60 },
                { "a10-7870k", 4, 3.90 },
                { "a10-8700b", 4, 1.80 },
                { "a10-8700p", 4, 1.80 },
                { "a10-8750b", 4, 3.60 },
                { "a10-8850b", 4, 3.90 },
                { "a12-8800b", 4, 2.10 },
                { "micro-6400t", 4, 1.00 },
                { "pro-3340b", 4, 2.20 },
                { "pro-3350b", 4, 2.20 },
                { "pro-7300b", 2, 1.90 },
                { "a4-5000", 4, 1.50 },
                { "a4-5100", 4, 1.55 },
                { "a4-6210", 4, 1.80 },
                { "a4-6300", 2, 3.70 },
                { "a4-6320", 2, 3.80 },
                { "a4-7210", 4, 1.80 },
                { "a4-7300", 2, 3.80 },
                { "a4-8350b", 2, 3.50 },
                { "a4-9120c", 2, 1.60 },
                { "pro-7050b", 2, 2.20 },
                { "pro-7400b", 2, 3.50 },
                { "a6-5200", 4, 2.00 },
                { "a6-5200m", 4, 2.00 },
                { "a6-5350m", 2, 2.90 },
                { "a6-6310", 4, 1.80 },
                { "a6-6400b", 2, 3.90 },
                { "a6-6400k", 2, 3.90 },
                { "a6-6420b", 2, 4.00 },
                { "a6-6420k", 2, 4.00 },
                { "a6-7000", 2, 2.20 },
                { "a6-7310", 4, 2.00 },
                { "a6-7400k", 2, 3.50 },
                { "a6-8500b", 2, 1.60 },
                { "a6-8500p", 2, 1.60 },
                { "a6-8550b", 2, 3.70 },
                { "a6-9220c", 2, 1.80 },
                { "pro-7150b", 4, 1.90 },
                { "pro-7600b", 4, 3.10 },
                { "a8-6410", 4, 2.00 },
                { "a8-6500", 4, 3.50 },
                { "a8-6500b", 4, 3.50 },
                { "a8-6500t", 4, 2.10 },
                { "a8-6600k", 4, 3.90 },
                { "a8-7100", 4, 1.80 },
                { "a8-7200p", 4, 2.40 },
                { "a8-7410", 4, 2.20 },
                { "a8-7600", 4, 3.10 },
                { "a8-7650k", 4, 3.30 },
                { "a8-7670k", 4, 3.60 },
                { "a8-8600b", 4, 1.60 },
                { "a8-8600p", 4, 1.60 },
                { "a8-8650b", 4, 3.20 },

                // AI Series (Strix Point)
                { "365", 20, 2.00 }, // Ryzen AI 7 365
                { "370", 24, 2.00 }, // Ryzen AI 9 HX 370
                { "375", 24, 2.00 }, // Ryzen AI 9 HX 375

                // Athlon
                { "3050c", 2, 2.30 },
                { "200ge", 4, 3.20 },
                { "220ge", 4, 3.40 },
                { "240ge", 4, 3.50 },
                { "255e", 2, 3.10 },
                { "3000g", 4, 3.50 },
                { "300ge", 4, 3.40 },
                { "300u", 4, 2.40 },
                { "320ge", 4, 3.50 },
                { "425e", 3, 2.70 },
                { "460", 3, 3.40 },
                { "5150", 4, 1.60 },
                { "5350", 4, 2.05 },
                { "5370", 4, 2.20 },
                { "620e", 4, 2.70 },
                { "631", 4, 2.60 },
                { "638", 4, 2.70 },
                { "641", 4, 2.80 },
                { "740", 4, 3.20 },
                { "750k", 4, 3.40 },
                { "760k", 4, 3.80 },
                { "3150c", 4, 2.40 },
                { "3150g", 4, 3.50 },
                { "3150ge", 4, 3.30 },
                { "3150u", 4, 2.40 },
                { "7220c", 4, 2.40 },
                { "7220u", 4, 2.40 },
                { "3045b", 2, 2.30 },
                { "3145b", 4, 2.40 },
                { "3050e", 4, 1.40 },
                { "3050ge", 4, 3.40 },
                { "3050u", 2, 2.30 },
                { "7120c", 2, 2.40 },
                { "7120u", 2, 2.40 },
                { "3125ge", 4, 3.40 },
                { "940", 4, 3.00 },
                { "950", 4, 3.50 },
                { "970", 4, 3.80 },

                // Business Class
                { "b57", 2, 3.20 },
                { "b59", 2, 3.40 },
                { "b60", 2, 3.50 },
                { "b75", 3, 3.00 },
                { "b77", 3, 3.20 },
                { "b97", 4, 3.20 },
                { "b99", 4, 3.30 },

                // E-Series
                { "micro-6200t", 2, 1.00 },
                { "e1-2100", 2, 1.00 },
                { "e1-2200", 2, 1.05 },
                { "e1-2500", 2, 1.40 },
                { "e1-6010", 2, 1.35 },
                { "e1-7010", 2, 1.50 },
                { "e2-3000", 2, 1.65 },
                { "e2-3800", 4, 1.30 },
                { "e2-6110", 4, 1.50 },
                { "e2-7110", 4, 1.80 },

                // FX
                { "fx-4100", 4, 3.60 },
                { "fx-4130", 4, 3.80 },
                { "fx-4170", 4, 4.20 },
                { "fx-4300", 4, 3.80 },
                { "fx-4320", 4, 4.00 },
                { "fx-4350", 4, 4.20 },
                { "fx-6200", 6, 3.80 },
                { "fx-6300", 6, 3.50 },
                { "fx-6350", 6, 3.90 },
                { "fx-7500", 4, 2.10 },
                { "fx-7600p", 4, 2.70 },
                { "fx-8120", 8, 3.10 },
                { "fx-8150", 8, 3.60 },
                { "fx-8300", 8, 3.30 },
                { "fx-8310", 8, 3.40 },
                { "fx-8320", 8, 3.50 },
                { "fx-8320e", 8, 3.20 },
                { "fx-8350", 8, 4.00 },
                { "fx-8370", 8, 4.00 },
                { "fx-8370e", 8, 3.30 },
                { "fx-8800p", 4, 2.10 },
                { "fx-9370", 8, 4.40 },
                { "fx-9590", 8, 4.70 },

                // Misc
                { "micro-6700t", 4, 1.20 },
                { "n640", 2, 2.90 },
                { "n660", 2, 3.00 },
                { "n870", 3, 2.30 },
                { "n960", 4, 1.80 },
                { "n970", 4, 2.20 },
                { "p650", 2, 2.60 },
                { "p860", 3, 2.00 },

                // Phenom II
                { "1075t", 6, 3.00 },
                { "555", 2, 3.20 },
                { "565", 2, 3.40 },
                { "570", 2, 3.50 },
                { "840", 4, 3.20 },
                { "850", 4, 3.30 },
                { "960t", 4, 3.00 },
                { "965", 4, 3.40 },
                { "975", 4, 3.60 },
                { "980", 4, 3.70 },

                // Ryzen Suffixes (3/5/7/9/Threadripper consolidated)
                { "1200", 4, 3.10 },
                { "1300x", 4, 3.50 },
                // "210" mapped to Ryzen 5 1400 (First Gen 4c/8t)
                { "210", 8, 3.20 },
                { "2200g", 4, 3.50 },
                { "2200ge", 4, 3.20 },
                { "2200u", 4, 2.50 },
                { "2300u", 4, 2.00 },
                { "2300x", 4, 3.50 },
                { "3100", 8, 3.60 },
                { "3200g", 4, 3.60 },
                { "3200ge", 4, 3.30 },
                { "3200u", 4, 2.60 },
                { "3250c", 4, 2.60 },
                { "3250u", 4, 2.60 },
                { "3300u", 4, 2.10 },
                { "3300x", 8, 3.80 },
                { "3350u", 4, 2.10 },
                { "4100", 8, 3.80 },
                { "4300g", 8, 3.80 },
                { "4300ge", 8, 3.50 },
                { "4300u", 4, 2.70 },
                { "5125c", 4, 3.00 },
                { "5300g", 8, 4.00 },
                { "5300ge", 8, 3.60 },
                { "5300u", 8, 2.60 },
                { "5305g", 8, 4.00 },
                { "5305ge", 8, 3.60 },
                { "5400u", 8, 2.60 },
                { "5425c", 8, 2.70 },
                { "5425u", 8, 2.70 },
                { "7320c", 8, 2.40 },
                { "7320u", 8, 2.40 },
                { "7330u", 8, 2.30 },
                { "7335u", 8, 3.00 },
                { "7440u", 8, 3.00 },
                { "8300g", 8, 3.40 },
                { "8300ge", 8, 3.40 },
                { "8440u", 8, 3.00 },
                { "1300", 4, 3.50 },
                { "4350g", 8, 3.80 },
                { "4350ge", 8, 3.50 },
                { "4355g", 8, 3.80 },
                { "4355ge", 8, 3.50 },
                { "4450u", 8, 2.50 },
                { "5350g", 8, 4.00 },
                { "5350ge", 8, 3.60 },
                { "5355g", 8, 4.00 },
                { "5355ge", 8, 3.60 },
                { "5450u", 8, 2.60 },
                { "5475u", 8, 2.70 },
                { "1400", 8, 3.20 },
                { "1500x", 8, 3.50 },
                { "1600", 12, 3.20 },
                { "1600x", 12, 3.60 },
                // "220" mapped to Ryzen 5 1600 (First Gen 6c/12t)
                { "220", 12, 3.20 },
                // "230" mapped to Ryzen 5 2600 (Second Gen 6c/12t)
                { "230", 12, 3.40 },
                // "240" mapped to Ryzen 5 3600 (Third Gen 6c/12t)
                { "240", 12, 3.60 },
                { "2400g", 8, 3.60 },
                { "2400ge", 8, 3.20 },
                { "2500u", 8, 2.00 },
                { "2500x", 8, 3.60 },
                { "2600", 12, 3.40 },
                { "2600e", 12, 3.10 },
                { "2600h", 8, 3.20 },
                { "2600x", 12, 3.60 },
                { "3400g", 8, 3.70 },
                { "3400ge", 8, 3.30 },
                { "3450u", 8, 2.10 },
                { "3500", 6, 3.60 },
                { "3500c", 8, 2.10 },
                { "3500u", 8, 2.10 },
                { "3550h", 8, 2.10 },
                { "3580u", 8, 2.10 },
                { "3600", 12, 3.60 },
                { "3600x", 12, 3.80 },
                { "3600xt", 12, 3.80 },
                { "4500", 12, 3.60 },
                { "4500u", 6, 2.30 },
                { "4600g", 12, 3.70 },
                { "4600ge", 12, 3.30 },
                { "4600h", 12, 3.00 },
                { "4600u", 12, 2.10 },
                { "4680u", 12, 2.10 },
                { "5500", 12, 3.60 },
                { "5500gt", 12, 3.60 },
                { "5500h", 8, 3.30 },
                { "5500u", 12, 2.10 },
                { "5560u", 12, 2.30 },
                { "5600", 12, 3.50 },
                { "5600g", 12, 3.90 },
                { "5600ge", 12, 3.40 },
                { "5600gt", 12, 3.60 },
                { "5600h", 12, 3.30 },
                { "5600hs", 12, 3.00 },
                { "5600t", 12, 3.50 },
                { "5600u", 12, 2.30 },
                { "5600x", 12, 3.70 },
                { "5600x3d", 12, 3.30 },
                { "5600xt", 12, 3.80 },
                { "5605g", 12, 3.90 },
                { "5605ge", 12, 3.40 },
                { "5625c", 12, 2.30 },
                { "5625u", 12, 2.30 },
                { "6600h", 12, 3.30 },
                { "6600hs", 12, 3.30 },
                { "6600u", 12, 2.90 },
                { "7235hs", 8, 3.20 },
                { "7400f", 12, 3.70 },
                { "7430u", 12, 2.30 },
                { "7500f", 12, 3.70 },
                { "7520c", 8, 2.80 },
                { "7520u", 8, 2.80 },
                { "7530u", 12, 2.00 },
                { "7535hs", 12, 3.30 },
                { "7535u", 12, 2.90 },
                { "7540u", 12, 3.20 },
                { "7545u", 12, 3.20 },
                { "7600", 12, 3.80 },
                { "7600x", 12, 4.70 },
                { "7600x3d", 12, 4.10 },
                { "7640hs", 12, 4.30 },
                { "7640u", 12, 3.50 },
                { "7645hx", 12, 4.00 },
                { "8400f", 12, 4.20 },
                { "8500g", 12, 4.10 }, // Zen 4 base
                { "8500ge", 12, 3.40 },
                { "8540u", 12, 3.20 },
                { "8600g", 12, 4.30 },
                { "8640hs", 12, 3.50 },
                { "8640u", 12, 3.50 },
                { "8645hs", 12, 4.30 },
                { "9600", 12, 3.90 },
                { "9600x", 12, 3.90 },
                { "1500", 8, 3.00 },
                { "3350g", 8, 3.60 },
                { "3350ge", 4, 3.30 },
                { "4650g", 12, 3.70 },
                { "4650ge", 12, 3.30 },
                { "4650u", 12, 2.10 },
                { "4655g", 12, 3.70 },
                { "4655ge", 12, 3.30 },
                { "5645", 12, 3.70 },
                { "5650g", 12, 3.90 },
                { "5650ge", 12, 3.40 },
                { "5650u", 12, 2.30 },
                { "5655g", 12, 3.90 },
                { "5655ge", 12, 3.40 },
                { "5675u", 12, 2.30 },
                { "6650h", 12, 3.30 },
                { "6650hs", 12, 3.30 },
                { "6650u", 12, 2.90 },
                { "1700", 16, 3.00 },
                { "1700x", 16, 3.40 },
                { "1800x", 16, 3.60 },
                // "250" mapped to Ryzen 7 1700 (First Gen 8c/16t)
                { "250", 16, 3.00 },
                // "260" mapped to Ryzen 7 2700 (Second Gen 8c/16t)
                { "260", 16, 3.20 },
                { "2700", 16, 3.20 },
                { "2700e", 16, 2.80 },
                { "2700u", 8, 2.20 },
                { "2700x", 16, 3.70 },
                { "2800h", 8, 3.30 },
                { "3700c", 8, 2.30 },
                { "3700u", 8, 2.30 },
                { "3700x", 16, 3.60 },
                { "3750h", 8, 2.30 },
                { "3780u", 8, 2.30 },
                { "3800x", 16, 3.90 },
                { "3800xt", 16, 3.90 },
                { "4700g", 16, 3.60 },
                { "4700ge", 16, 3.10 },
                { "4700u", 8, 2.00 },
                { "4800h", 16, 2.90 },
                { "4800hs", 16, 2.90 },
                { "4800u", 16, 1.80 },
                { "4980u", 16, 2.00 },
                { "5700", 16, 3.70 },
                { "5700g", 16, 3.80 },
                { "5700ge", 16, 3.20 },
                { "5700u", 16, 1.80 },
                { "5700x", 16, 3.40 },
                { "5700x3d", 16, 3.00 },
                { "5705g", 16, 3.80 },
                { "5705ge", 16, 3.20 },
                { "5800", 16, 3.40 },
                { "5800h", 16, 3.20 },
                { "5800hs", 16, 2.80 },
                { "5800u", 16, 1.90 },
                { "5800x", 16, 3.80 },
                { "5800x3d", 16, 3.40 },
                { "5800xt", 16, 3.80 },
                { "5825c", 16, 2.00 },
                { "5825u", 16, 2.00 },
                { "6800h", 16, 3.20 },
                { "6800hs", 16, 3.20 },
                { "6800u", 16, 2.70 },
                { "7435hs", 16, 3.10 },
                { "7700", 16, 3.80 },
                { "7700x", 16, 4.50 },
                { "7730u", 16, 2.00 },
                { "7735hs", 16, 3.20 },
                { "7735u", 16, 2.70 },
                { "7736u", 16, 2.70 },
                { "7745hx", 16, 3.60 },
                { "7800x3d", 16, 4.20 },
                { "7840hs", 16, 3.80 },
                { "7840hx", 24, 3.00 },
                { "7840u", 16, 3.30 },
                { "8700f", 16, 4.10 },
                { "8700g", 16, 4.20 },
                { "8840hs", 16, 3.30 },
                { "8840u", 16, 3.30 },
                { "8845hs", 16, 3.80 },
                { "9700x", 16, 3.80 },
                { "9800x3d", 16, 4.70 },
                { "4750g", 16, 3.60 },
                { "4750ge", 16, 3.10 },
                { "4750u", 16, 1.70 },
                { "5750g", 16, 3.80 },
                { "5750ge", 16, 3.20 },
                { "5755g", 16, 3.80 },
                { "5755ge", 16, 3.20 },
                { "5845", 16, 3.40 },
                { "5850u", 16, 1.90 },
                { "5875u", 16, 2.00 },
                { "6850h", 16, 3.20 },
                { "6850hs", 16, 3.20 },
                { "6850u", 16, 2.70 },
                { "6860z", 16, 2.70 },
                { "7745", 16, 3.60 },
                // "270" mapped to Ryzen 7 3700X (Third Gen 8c/16t)
                { "270", 16, 3.60 },
                { "3900", 24, 3.10 },
                { "3900x", 24, 3.80 },
                { "3900xt", 24, 3.80 },
                { "3950x", 32, 3.50 },
                { "4900h", 16, 3.30 },
                { "4900hs", 16, 3.00 },
                { "5900", 24, 3.00 },
                { "5900hs", 16, 3.00 },
                { "5900hx", 16, 3.30 },
                { "5900x", 24, 3.70 },
                { "5900xt", 32, 3.30 },
                { "5950x", 32, 3.40 },
                { "5980hs", 16, 3.00 },
                { "5980hx", 16, 3.30 },
                { "6900hs", 16, 3.30 },
                { "6900hx", 16, 3.30 },
                { "6980hs", 16, 3.30 },
                { "6980hx", 16, 3.30 },
                { "7845hx", 24, 3.00 },
                { "7900", 24, 3.70 },
                { "7900x", 24, 4.70 },
                { "7900x3d", 24, 4.40 },
                { "7940hs", 16, 4.00 },
                { "7940hx", 32, 2.40 },
                { "7945hx", 32, 2.50 },
                { "7945hx3d", 32, 2.30 },
                { "7950x", 32, 4.50 },
                { "7950x3d", 32, 4.20 },
                { "8945hs", 16, 4.00 },
                { "9850hx", 24, 2.40 },
                { "9900x", 24, 4.40 },
                { "9900x3d", 24, 4.40 },
                { "9950x", 32, 4.30 },
                { "9950x3d", 32, 4.30 },
                { "9955hx", 32, 2.40 },
                { "5945", 24, 4.10 },
                { "6950h", 16, 3.30 },
                { "6950hs", 16, 3.30 },
                { "7945", 24, 4.70 },
                { "1900x", 16, 3.80 },
                { "1920x", 24, 3.50 },
                { "1950x", 32, 3.40 },
                { "2920x", 24, 3.50 },
                { "2950x", 32, 3.50 },
                { "2970wx", 48, 3.00 },
                { "2990wx", 64, 3.00 },
                { "3960x", 48, 3.80 },
                { "3970x", 64, 3.70 },
                { "3990x", 128, 2.90 },
                { "7960x", 48, 4.20 },
                { "7970x", 64, 4.00 },
                { "7980x", 128, 3.20 },
                { "3945wx", 24, 4.00 },
                { "3955wx", 32, 3.90 },
                { "3975wx", 64, 3.50 },
                { "3995wx", 128, 2.70 },
                { "5945wx", 24, 4.10 },
                { "5955wx", 32, 4.00 },
                { "5965wx", 48, 3.80 },
                { "5975wx", 64, 3.60 },
                { "5995wx", 128, 2.70 },
                { "7945wx", 24, 4.70 },
                { "7955wx", 32, 4.50 },
                { "7965wx", 48, 4.20 },
                { "7975wx", 64, 4.00 },
                { "7985wx", 128, 3.20 },
                { "7995wx", 192, 2.50 },

                // Sempron
                { "2650", 2, 1.45 },
                { "3850", 4, 1.30 },

                // Z-Series
                { "z1", 12, 3.20 }
            };
            out_ptr = db;
            out_size = sizeof(db) / sizeof(cpu_entry);
        }
    };


    static void str_copy(char* dest, const char* src, size_t max_len) {
        size_t i = 0;
        while (src[i] != '\0' && i < max_len - 1) {
            dest[i] = src[i];
            i++;
        }
        dest[i] = '\0';
    }

    static void str_cat(char* dest, const char* src, size_t max_len) {
        size_t i = 0;
        while (dest[i] != '\0') i++;
        size_t j = 0;
        while (src[j] != '\0' && i < max_len - 1) {
            dest[i++] = src[j++];
        }
        dest[i] = '\0';
    }

    static bool str_eq(const char* a, const char* b) {
        if (a == b) return true;
        if (!a || !b) return false;
        while (*a && *b) {
            if (*a != *b) return false;
            a++; b++;
        }
        return *a == *b;
    }

    // memoization
    struct memo {
        struct data_t {
            bool result;
            u8 points;
            bool cached;
            const char* brand_name; 
        };
        struct cache_entry {
            bool result;
            u8 points;
            bool has_value;
            const char* brand_name; 
        };

        static std::array<cache_entry, enum_size + 1> cache_table;

        static void cache_store(u16 flag, bool result, u8 points, const char* brand = nullptr) {
            if (flag <= enum_size) {
                cache_table[flag] = { result, points, true, brand };
            }
        }

        static bool is_cached(u16 flag) {
            if (flag <= enum_size) {
                return cache_table[flag].has_value;
            }
            return false;
        }

        static data_t cache_fetch(u16 flag) {
            if (flag <= enum_size && cache_table[flag].has_value) {
                return { cache_table[flag].result, cache_table[flag].points, true, cache_table[flag].brand_name };
            }
            return { false, 0, false, nullptr };
        }

        static void uncache(u16 flag) {
            if (flag <= enum_size) {
                cache_table[flag].has_value = false;
                cache_table[flag].brand_name = nullptr;
            }
        }

        struct brand {
            static char brand_cache[512];
            static bool cached;

            static void store(const char* s) {
                str_copy(brand_cache, s, sizeof(brand_cache));
                cached = true;
            }

            static bool is_cached() { return cached; }
            static const char* fetch() { return brand_cache; }
        };

        struct multi_brand {
            static char brand_cache[1024];
            static bool cached;

            static void store(const char* s) {
                str_copy(brand_cache, s, sizeof(brand_cache));
                cached = true;
            }

            static bool is_cached() { return cached; }
            static const char* fetch() { return brand_cache; }
        };

        // helper specifically for conclusion strings
        struct conclusion {
            static char cache[512];
            static bool cached;
            static void store(const char* s) {
                str_copy(cache, s, sizeof(cache));
                cached = true;
            }
            static const char* fetch() { return cache; }
        };

        struct cpu_brand {
            static char brand_cache[128];
            static bool cached;
            static void store(const char* s) {
                str_copy(brand_cache, s, sizeof(brand_cache));
                cached = true;
            }
            static bool is_cached() { return cached; }
            static const char* fetch() { return brand_cache; }
        };

        struct threadcount {
            static u32 threadcount_cache;
            static u32 fetch() {
                if (threadcount_cache != 0) {
                    return threadcount_cache;
                }
                threadcount_cache = std::thread::hardware_concurrency();
                return threadcount_cache;
            }
        };

        struct hyperx {
            static hyperx_state state;
            static bool cached;
            static hyperx_state fetch() { return state; }
            static void store(const hyperx_state p_state) {
                state = p_state;
                cached = true;
            }
            static bool is_cached() { return cached; }
        };

        struct leaf_entry { 
            u32 leaf; 
            bool value;
            bool has_value; 
        };

        struct leaf_cache {
            static constexpr std::size_t CAPACITY = 128;
            static std::array<leaf_entry, CAPACITY> table;
            static std::size_t count;      
            static std::size_t next_index; 

            static bool fetch(u32 leaf, bool& out) {
                for (std::size_t i = 0; i < count; ++i) {
                    if (table[i].has_value && table[i].leaf == leaf) { out = table[i].value; return true; }
                }
                return false;
            }

            static void store(u32 leaf, bool val) {
                for (std::size_t i = 0; i < count; ++i) {
                    if (table[i].leaf == leaf) { table[i].value = val; table[i].has_value = true; return; }
                }
                if (count < CAPACITY) {
                    table[count++] = { leaf, val, true };
                    return;
                }
                // otherwise evict in round-robin fashion
                table[next_index] = { leaf, val, true };
                next_index = (next_index + 1) % CAPACITY;
            }
        };

        struct bios_info {
            static char manufacturer[256];
            static char model[128];
            static bool cached;

            static void store_manufacturer(const char* s) noexcept {
                if (!s) { manufacturer[0] = '\0'; return; }
                const size_t n = strlen(s);
                const size_t cap = sizeof(manufacturer) - 1;
                const size_t tocopy = (n > cap) ? cap : n;
                memcpy(manufacturer, s, tocopy);
                manufacturer[tocopy] = '\0';
                cached = true;
            }
            static void store_model(const char* s) noexcept {
                if (!s) { model[0] = '\0'; return; }
                const size_t n = strlen(s);
                const size_t cap = sizeof(model) - 1;
                const size_t tocopy = (n > cap) ? cap : n;
                memcpy(model, s, tocopy);
                model[tocopy] = '\0';
                cached = true;
            }

            static bool is_cached() noexcept { return cached; }
            static const char* fetch_manufacturer() noexcept { return manufacturer; }
            static const char* fetch_model() noexcept { return model; }
        };

        struct hardened {
            static bool result;
            static bool cached;
        };
    };

    // miscellaneous functionalities
    struct util {
        static bool is_unsupported(const VM::enum_flags flag) {
            // cross platform?
            if (
                (flag >= VM::HYPERVISOR_BIT) &&
                (flag <= VM::KGT_SIGNATURE)
            ) {
                return false;
            }

            #if (LINUX)
                return (!(
                    (flag >= LINUX_START) &&
                    (flag <= LINUX_END)
                ));
            #elif (WINDOWS)
                return (!(
                    (flag >= WINDOWS_START) &&
                    (flag <= WINDOWS_END)
                ));
            #elif (APPLE) 
                return (!(
                    (flag >= MACOS_START) &&
                    (flag <= MACOS_END)
                ));
            #else
                return false;
            #endif
        }

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

        [[nodiscard]] static bool exists(const char* path) {
        #if (VMA_CPP >= 17)
            return std::filesystem::exists(path);
        #elif (VMA_CPP >= 11)
            struct stat buffer;
            return (stat(path, &buffer) == 0);
        #endif
        }

        static bool is_directory(const char* path) {
            struct stat info;
            if (stat(path, &info) != 0) {
                return false;
            }
            return (info.st_mode & S_IFDIR); // check if directory
        };
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


        // wrapper for std::make_unique because it's not available for C++11
        template<typename T, typename... Args>
        [[nodiscard]] static std::unique_ptr<T> make_unique(Args&&... args) {
        #if (VMA_CPP < 14)
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
            bool is_admin = false;
            HANDLE hToken = nullptr;
            const HANDLE current_process = reinterpret_cast<HANDLE>(-1LL);
            if (OpenProcessToken(current_process, TOKEN_QUERY, &hToken)) {
                TOKEN_ELEVATION elevation{};
                DWORD dwSize;
                if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
                    if (elevation.TokenIsElevated)
                        is_admin = true;
                }
                CloseHandle(hToken);
            }
            return is_admin;
        #else
            return true;
        #endif
        }


        [[nodiscard]] static bool find(const std::string& base_str, const char* keyword) noexcept {
            return (base_str.find(keyword) != std::string::npos);
        };

        static std::string narrow_wide(const wchar_t* wstr) {
            if (!wstr) return std::string{};
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

        // choose correct << or narrow for each type
        static void write_arg_impl(std::ostream& os, const wchar_t* arg) {
            os << narrow_wide(arg);
        }
        static void write_arg_impl(std::ostream& os, wchar_t* arg) {
            os << narrow_wide(arg);
        }

        static void write_arg_impl(std::ostream& os, const std::wstring& ws) {
            os << narrow_wide(ws.c_str());
        }

        // everything else that is not std::string or wchar_t
        template <typename T>
        static typename std::enable_if<!std::is_convertible<T, std::wstring>::value
            && !std::is_same<typename std::decay<T>::type, wchar_t*>::value,
            void>::type
            write_arg_impl(std::ostream& os, T&& arg) {
            os << std::forward<T>(arg);
        }

        // variadic pack printer for C++11
        static inline void print_to_stream(std::ostream& /*unused*/) noexcept {}

        // forward the first, then expand the rest in an initializer list
        template <typename T, typename... Args>
        static void print_to_stream(std::ostream& os,
            T&& first,
            Args&&... args) noexcept
        {
            write_arg_impl(os, std::forward<T>(first));
            // trick to expand the pack
            using expander = int[];
            (void)expander {
                0, ((void)write_arg_impl(os, std::forward<Args>(args)), 0)...
            };
        }

        template <typename... Args>
        static inline void debug_msg(Args&&... message) noexcept {
            static std::unordered_set<std::string> printed_messages;

            std::stringstream ss;
            print_to_stream(ss, std::forward<Args>(message)...);
            std::string msg_content = ss.str();

            if (printed_messages.find(msg_content) == printed_messages.end()) {
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
                std::cout << msg_content;
                std::cout << std::dec << "\n";

                printed_messages.insert(std::move(msg_content));
            }
        }


        [[nodiscard]] static std::unique_ptr<std::string> sys_result(const char* cmd) {
        #if (VMA_CPP < 14)
            VMAWARE_UNUSED(cmd);
            return util::make_unique<std::string>();
        #else
            #if (LINUX || APPLE)
                struct file_deleter {
                    void operator()(FILE* f) const noexcept {
                        if (f) {
                            pclose(f);
                        };
                    }
                };

                std::unique_ptr<FILE, file_deleter> pipe(popen(cmd, "r"), file_deleter());
                if (!pipe) {
                    return util::make_unique<std::string>();
                }

                std::string result;
                char* line = nullptr;

                // to ensure line is freed even if string::append throws std::bad_alloc
                struct line_guard {
                    char*& ptr;
                    ~line_guard() { if (ptr) free(ptr); }
                } guard{ line };

                size_t len = 0;
                ssize_t nread;

                while ((nread = getline(&line, &len, pipe.get())) != -1) {
                    result.append(line, static_cast<size_t>(nread));
                }

                if (!result.empty() && result.back() == '\n') {
                    result.pop_back();
                }

                return util::make_unique<std::string>(std::move(result));
            #else
                VMAWARE_UNUSED(cmd);
                return std::make_unique<std::string>();
            #endif
        #endif
        }


        [[nodiscard]] static bool is_proc_running(const char* executable) {
        #if (LINUX)
            #if (VMA_CPP >= 17)
                for (const auto& entry : std::filesystem::directory_iterator("/proc")) {
                    if (!entry.is_directory()) {
                        continue;
                    }

                    const std::string filename = entry.path().filename().string();
            #else
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
                if (!std::all_of(filename.begin(), filename.end(), [](u8 c) { return std::isdigit(c); })) {
                    continue;
                }

                const std::string cmdline_file = "/proc/" + filename + "/cmdline";

                // read raw bytes (binary) to preserve embedded NULs
                std::ifstream ifs(cmdline_file, std::ios::in | std::ios::binary);
                if (!ifs.is_open()) {
                    continue;
                }

                // read entire file into vector<char>
                std::vector<char> buf((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
                ifs.close();

                if (buf.empty()) {
                    continue;
                }

                // cmdline is argv0\0argv1\0..., so argv0 is bytes up to first NUL
                const auto it_nul = std::find(buf.begin(), buf.end(), '\0');
                if (it_nul == buf.begin()) {
                    continue;
                }

                std::string argv0(buf.begin(), it_nul);
                if (argv0.empty()) {
                    continue;
                }

                // extract basename of argv0
                const std::size_t slash_index = argv0.find_last_of('/');
                std::string basename = (slash_index == std::string::npos) ? argv0 : argv0.substr(slash_index + 1);

                if (basename != executable) {
                    continue;
                }

                return true;
            }

            return false;
        #else
            VMAWARE_UNUSED(executable);
            return false;
        #endif
        }


        [[nodiscard]] static bool is_running_under_translator() {
        #if (WINDOWS && _WIN32_WINNT >= _WIN32_WINNT_WIN10)
            const HANDLE current_process = reinterpret_cast<HANDLE>(-1LL);
            USHORT procMachine = 0, nativeMachine = 0;
            const auto pIsWow64Process2 = &IsWow64Process2;

            if (pIsWow64Process2(current_process, &procMachine, &nativeMachine)) {
                if (nativeMachine == IMAGE_FILE_MACHINE_ARM64 &&
                    (procMachine == IMAGE_FILE_MACHINE_AMD64 || procMachine == IMAGE_FILE_MACHINE_I386)) {
                    debug("Translator detected x64/x86 process on ARM64");
                    return true;
                }
            }

            // only if we got MACHINE_UNKNOWN on process but native is ARM64
            if (nativeMachine == IMAGE_FILE_MACHINE_ARM64) {
                using get_process_information = BOOL(__stdcall*)(HANDLE, PROCESS_INFORMATION_CLASS, PVOID, DWORD);
                const HMODULE ntdll = util::get_ntdll();
                if (ntdll == nullptr) {
                    return false;
                }

                const char* names[] = { "GetProcessInformation" };
                void* funcs[1] = { nullptr };
                util::get_function_address(ntdll, names, funcs, 1);

                get_process_information get_proc_info = reinterpret_cast<get_process_information>(funcs[0]);
                if (get_proc_info) {
                    struct PROCESS_MACHINE_INFORMATION {
                        USHORT ProcessMachine;
                        USHORT Res0;
                        DWORD  MachineAttributes;
                    } pmInfo = {};
                    // ProcessMachineTypeInfo == 9 per MS Q&A
                    if (get_proc_info(current_process, (PROCESS_INFORMATION_CLASS)9, &pmInfo, sizeof(pmInfo))) {
                        if (pmInfo.ProcessMachine == IMAGE_FILE_MACHINE_AMD64 || pmInfo.ProcessMachine == IMAGE_FILE_MACHINE_I386) {
                            debug("Translator detected x64/x86 process on ARM64 by fallback");
                            return true;
                        }
                    }
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

        #if (WINDOWS)
            const std::string& brand = cpu::get_brand();
            if (brand.find("Virtual CPU") != std::string::npos) {
                return true;
            }
        #endif

            return false;
        }


        /**
         * @brief Check whether the system is running in a Hyper-V virtual machine or if the host system has Hyper-V enabled
         * @note Hyper-V's presence on a host system can set certain hypervisor-related CPU flags that may appear similar to those in a virtualized environment, which can make it challenging to differentiate between an actual Hyper-V virtual machine (VM) and a host system with Hyper-V enabled.
         *       This can lead to false conclusions, where the system might mistakenly be identified as running in a Hyper-V VM, when in reality, it's simply the host system with Hyper-V features active.
         *       This check aims to distinguish between these two cases by identifying specific CPU flags and hypervisor-related artifacts that are indicative of a Hyper-V VM rather than a host system with Hyper-V enabled.
         * @returns hyperx_state enum indicating the detected state:
         *          - HYPERV_ARTIFACT_VM for host with Hyper-V enabled
         *          - HYPERV_REAL_VM for real Hyper-V VM
         *          - HYPERV_ENLIGHTENMENT for QEMU with Hyper-V enlightenments
         *          - HYPERV_UNKNOWN for unknown/undetected state
         */
        [[nodiscard]] static hyperx_state hyper_x() {
        #if (!WINDOWS)
            return HYPERV_UNKNOWN;
        #else
            if (memo::hyperx::is_cached()) {
                debug("HYPER_X: returned from cache");
                return memo::hyperx::fetch();
            }

            // Check if hypervisor feature bit in CPUID Leaf 1, ECX bit 31 is enabled
            auto is_hyperv_present = []() noexcept -> bool {
                u32 unused, ecx = 0;
                cpu::cpuid(unused, unused, ecx, unused, 1);

                return (ecx >> 31) & 1;
            };

            // 0x40000003 on EBX indicates the flags that a parent partition specified to create a child partition (https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/datatypes/hv_partition_privilege_mask)
            // some CPU models like N-models (N4200, etc) expose 0x40000003 leaves without exposing the hypervisor bit
            auto is_root_partition = []() noexcept -> bool {
                u32 ebx, unused = 0;
                cpu::cpuid(unused, ebx, unused, unused, 0x40000003);

                return (ebx & 1);
            };

            /**
              * On Hyper-V virtual machines, the cpuid function reports an EAX value of 11
              * This value is tied to the Hyper-V partition model, where each virtual machine runs as a child partition
              * These child partitions have limited privileges and access to hypervisor resources, 
              * which is reflected in the maximum input value for hypervisor CPUID information as 11
              * Essentially, it indicates that the hypervisor is managing the VM and that the VM is not running directly on hardware but rather in a virtualized environment
            */
            auto eax = []() noexcept -> u32 {
                u32 eax_reg, unused = 0;
                cpu::cpuid(eax_reg, unused, unused, unused, cpu::leaf::hypervisor);

                // truncation is intentional
                return eax_reg & 0xFF;
            };

            hyperx_state state = HYPERV_UNKNOWN;

            if (!is_root_partition()) {
                if (eax() == 11 && is_hyperv_present()) {
                    // Windows machine running under Hyper-V type 2
                    debug("HYPER_X: Detected Hyper-V guest VM");
                    core::add(brands::HYPERV);
                    state = HYPERV_REAL_VM;
                }
                else {
                    debug("HYPER_X: Hyper-V is not active");
                    state = HYPERV_UNKNOWN;
                }
            }
            else {
                const std::string brand_str = cpu::cpu_manufacturer(0x40000100);
                
                if (util::find(brand_str, "KVM")) {
                    debug("HYPER_X: Detected Hyper-V enlightenments");
                    core::add(brands::QEMU_KVM_HYPERV);
                    state = HYPERV_ENLIGHTENMENT;
                }
                else {
                    // Windows machine running under Hyper-V type 1
                    debug("HYPER_X: Detected Hyper-V host machine");
                    core::add(brands::HYPERV_ARTIFACT);
                    state = HYPERV_ARTIFACT_VM;
                } 
            }

            memo::hyperx::store(state);

            return state;
        #endif
        }

        // For strings shorter than 16-32 bytes, the overhead of setting up the _mm_crc32_u64 (or 32) loop, then checking length, handling the tail bytes, and finally handling alignment, 
        // will always make it slower or equal to a simple unrolled u8 loop, and not every cpu model fits in u32/u64
        #if (x86 && (CLANG || GCC))
            __attribute__((__target__("crc32")))
        #endif
        static u32 crc32(u32 crc, char data) {
        #if (x86)
            return _mm_crc32_u8(crc, static_cast<u8>(data));
        #else
            // Fallback for non-x86: use software CRC32-C
            crc ^= static_cast<u8>(data);
            for (int i = 0; i < 8; ++i)
                crc = (crc >> 1) ^ ((crc & 1) ? 0x82F63B78u : 0);
            return crc;
        #endif
        }

        // to search in our databases, we want to precompute hashes at compile time for C++11 and later
        // so we need to match the hardware _mm_crc32_u8, it is based on CRC32-C (Castagnoli) polynomial
        struct constexpr_hash {
            // it does 8 rounds of CRC32-C bit reflection recursively
            static constexpr u32 crc32_bits(u32 crc, int bits) {
                return (bits == 0) ? crc :
                    crc32_bits((crc >> 1) ^ ((crc & 1) ? 0x82F63B78u : 0), bits - 1);
            }

            // over string
            static constexpr u32 crc32_str(const char* s, u32 crc) {
                return (*s == '\0') ? crc :
                    crc32_str(s + 1, crc32_bits(crc ^ static_cast<u8>(*s), 8));
            }

            static constexpr u32 get(const char* s) {
                return crc32_str(s, 0);
            }
        };

        // this forces the compiler to calculate the hash when initializing the array while staying C++11 compatible
        struct thread_entry {
            u32 hash;
            u32 threads;
            constexpr thread_entry(const char* m, u32 t) : hash(constexpr_hash::get(m)), threads(t) {}
        };

        enum class cpu_type {
            INTEL_I,
            INTEL_XEON,
            AMD
        };

        // 4 arguments to stay compliant with x64 __fastcall (just in case)
        [[nodiscard]] static bool verify_thread_count(const thread_entry* db, size_t db_size, size_t max_model_len, cpu_type type) {
            // to save a few cycles
            struct hasher {
                static u32 crc32_sw(u32 crc, char data) {
                    crc ^= static_cast<u8>(data);
                    for (int i = 0; i < 8; ++i)
                        crc = (crc >> 1) ^ ((crc & 1) ? 0x82F63B78u : 0);
                    return crc;
                }

                using hashfc = u32(*)(u32, char);

                static hashfc get() {
                    // yes, vmaware runs on dinosaur cpus without sse4.2 pretty often
                    i32 regs[4];
                    cpu::cpuid(regs, 1);
                    const bool has_sse42 = (regs[2] & (1 << 20)) != 0;

                    return has_sse42 ? util::crc32 : crc32_sw;
                }
            };

            std::string model_string;
            const char* debug_tag = "";

            if (type == cpu_type::AMD) {
                if (!cpu::is_amd()) {
                    return false;
                }
                model_string = cpu::get_brand();
                debug_tag = "AMD_THREAD_MISMATCH";
            }
            else {
                if (!cpu::is_intel()) {
                    return false;
                }

                const cpu::model_struct model = cpu::get_model();

                if (!model.found) {
                    return false;
                }

                if (type == cpu_type::INTEL_I) {
                    if (!model.is_i_series) {
                        return false;
                    }
                    debug_tag = "INTEL_THREAD_MISMATCH";
                }
                else {
                    if (!model.is_xeon) {
                        return false;
                    }
                    debug_tag = "XEON_THREAD_MISMATCH";
                }
                model_string = model.string;
            }

            if (model_string.empty()) return false;

            debug(debug_tag, ": CPU model = ", model_string);

            const char* str = model_string.c_str();
            u32 expected_threads = 0;
            bool found = false;
            size_t best_len = 0;

            // manual collision fix for Z1 Extreme (16) vs Z1 (12)
            // this is a special runtime check because "z1" is a substring of "z1 extreme" tokens
            // and both might be hashed. VMAware should prioritize 'extreme' if found
            u32 z_series_threads = 0;

            const auto hash_func = hasher::get();

            for (size_t i = 0; str[i] != '\0'; ) {
                char c = str[i];
                if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) {
                    i++;
                    continue;
                }

                u32 current_hash = 0;
                size_t current_len = 0;
                size_t j = i;

                while (true) {
                    char k = str[j];
                    const bool is_valid = (k >= '0' && k <= '9') ||
                        (k >= 'A' && k <= 'Z') ||
                        (k >= 'a' && k <= 'z') ||
                        (k == '-'); // models have hyphen
                    if (!is_valid) break;

                    if (current_len >= max_model_len) {
                        while (str[j] != '\0' && str[j] != ' ') j++; // fast forward to space/null
                        break;
                    }

                    /*
                       models are usually 8 or more bytes long, i.e. i9-10900K
                       so imagine we want to use u64, you hash the first 8 bytes i9-10900
                       but then you are left with K. You have to handle the tail
                       fetching 8 bytes would include the characters after the token, corrupting the hash
                       so a byte-by-byte loop is the most optimal choice here
                    */

                    // convert to lowercase on-the-fly to match compile-time keys
                    if (type == cpu_type::AMD && (k >= 'A' && k <= 'Z')) k += 32;

                    // since this technique is cross-platform, we cannot use a standard C++ try-catch block to catch a missing CPU instruction
                    // we could use preprocessor directives and add an exception handler (VEH/SEH or SIGHANDLER) but nah
                    current_hash = hash_func(current_hash, k);
                    current_len++;
                    j++;

                    // only verify match if the token has ended (next char is not alphanumeric)
                    const char next = str[j];
                    const bool next_is_alnum = (next >= '0' && next <= '9') ||
                        (next >= 'A' && next <= 'Z') ||
                        (next >= 'a' && next <= 'z');

                    if (!next_is_alnum) {
                        // Check specific Z1 Extreme token
                        // Hash for "extreme" (CRC32-C) is 0x3D09D5B4
                        if (type == cpu_type::AMD && current_hash == 0x3D09D5B4) { z_series_threads = 16; }

                        // since it's a contiguous block of integers in .rodata/.rdata, this is extremely fast
                        for (size_t idx = 0; idx < db_size; ++idx) {
                            if (db[idx].hash == current_hash) {
                                if (current_len > best_len) {
                                    best_len = current_len;
                                    expected_threads = db[idx].threads;
                                    found = true;
                                }
                                // since hashing implies uniqueness in this dataset, you might say we could break here,
                                // but we continue to ensure we find the longest substring match if overlaps exist,
                                // so like it finds both "i9-11900" and "i9-11900K" i.e.
                            }
                        }
                    }
                }
                i = j;
            }

            // Z1 Extreme fix
            if (type == cpu_type::AMD && z_series_threads != 0 && expected_threads == 12) {
                expected_threads = z_series_threads;
            }

            if (found) {
                const u32 actual = memo::threadcount::fetch();
                if (actual != expected_threads) {
                    debug(debug_tag, ": Expected threads -> ", expected_threads);
                    VMAWARE_UNUSED(debug_tag); // if compiled in release mode, silence the unused variable warning
                    return true;
                }
            }

            return false;
        }

    #if (WINDOWS)
        // retrieves the addresses of specified functions from a loaded module using the export directory, manual implementation of GetProcAddress
        static void get_function_address(const HMODULE hModule, const char* names[], void** functions, size_t count) {
            using func_map = std::unordered_map<std::string, void*>;
            static std::unordered_map<HMODULE, func_map> function_cache;

            for (size_t i = 0; i < count; ++i) functions[i] = nullptr;
            if (!hModule) return;

            BYTE* base = reinterpret_cast<BYTE*>(hModule);

            size_t module_size = 0;
            {
                MEMORY_BASIC_INFORMATION mbi = {};
                if (VirtualQuery(base, &mbi, sizeof(mbi))) {
                    module_size = static_cast<size_t>(mbi.RegionSize);
                }
                else {
                    return;
                }
            }

            auto valid_range = [&](size_t offset, size_t sz) noexcept -> bool {
                return (sz > 0) && (offset < module_size) && (sz <= module_size - offset);
            };

            auto cstr_from_rva = [&](DWORD rva) noexcept -> const char* {
                if (!valid_range(static_cast<size_t>(rva), 1)) return nullptr;

                const char* start = reinterpret_cast<const char*>(base + rva);
                const size_t remaining = module_size - static_cast<size_t>(rva);

                if (std::memchr(start, '\0', remaining)) {
                    return start;
                }

                return nullptr;
            };

            // Validate DOS header 
            if (!valid_range(0, sizeof(IMAGE_DOS_HEADER))) return;
            const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;

            // e_lfanew -> NT headers
            if (dosHeader->e_lfanew < 0) return;
            const size_t e_lfanew = static_cast<size_t>(dosHeader->e_lfanew);
            if (!valid_range(e_lfanew, sizeof(IMAGE_NT_HEADERS))) return;
            const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + e_lfanew);
            if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return;

            const size_t sizeOfImage = static_cast<size_t>(ntHeaders->OptionalHeader.SizeOfImage);
            if (sizeOfImage != 0 && sizeOfImage > module_size) {
                module_size = sizeOfImage;
            }

            // Check export data directory exists
            if (ntHeaders->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) {
                return; // no export directory
            }

            const auto& dd = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (dd.VirtualAddress == 0 || dd.Size == 0) {
                return; // no exports
            }

            // Validate export directory fits
            if (!valid_range(static_cast<size_t>(dd.VirtualAddress), sizeof(IMAGE_EXPORT_DIRECTORY))) {
                return;
            }

            const auto* exportDir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base + dd.VirtualAddress);

            const DWORD nameCount = exportDir->NumberOfNames;
            const DWORD funcCount = exportDir->NumberOfFunctions;

            constexpr DWORD MAX_NAMES = 1u << 20; // 1M names is absurd but protective
            if (nameCount == 0 || nameCount > MAX_NAMES) return;
            if (funcCount == 0 || funcCount > MAX_NAMES) return;

            const DWORD addr_names = exportDir->AddressOfNames;
            const DWORD addr_funcs = exportDir->AddressOfFunctions;
            const DWORD addr_ord = exportDir->AddressOfNameOrdinals;

            if (!valid_range(static_cast<size_t>(addr_names), static_cast<size_t>(nameCount) * sizeof(DWORD))) return;
            if (!valid_range(static_cast<size_t>(addr_funcs), static_cast<size_t>(funcCount) * sizeof(DWORD))) return;
            if (!valid_range(static_cast<size_t>(addr_ord), static_cast<size_t>(nameCount) * sizeof(WORD))) return;

            const DWORD* nameRvas = reinterpret_cast<const DWORD*>(base + addr_names);
            const DWORD* funcRvas = reinterpret_cast<const DWORD*>(base + addr_funcs);
            const WORD* ordinals = reinterpret_cast<const WORD*>(base + addr_ord);

            func_map& module_cache = function_cache[hModule];

            for (size_t i = 0; i < count; ++i) {
                const char* current_name = names[i];
                if (!current_name) continue;
                const std::string s_name(current_name);

                // check cache first
                const auto cache_it = module_cache.find(s_name);
                if (cache_it != module_cache.end()) {
                    functions[i] = cache_it->second;
                    continue;
                }

                // binary search over names (names array is typically sorted)
                DWORD lo = 0, hi = nameCount;
                while (lo < hi) {
                    const DWORD mid = lo + (hi - lo) / 2;
                    const DWORD midNameRva = nameRvas[mid];
                    const char* midName = cstr_from_rva(midNameRva);
                    if (!midName) { // corrupted string table or something
                        lo = hi;
                        break;
                    }

                    const int cmp = strcmp(current_name, midName);
                    if (cmp > 0) {
                        lo = mid + 1;
                    }
                    else {
                        hi = mid;
                    }
                }

                if (lo < nameCount) {
                    const char* candidateName = cstr_from_rva(nameRvas[lo]);
                    if (candidateName && strcmp(current_name, candidateName) == 0) {
                        const WORD nameOrdinal = ordinals[lo];
                        if (static_cast<DWORD>(nameOrdinal) >= funcCount) continue;
                        const DWORD funcRva = funcRvas[nameOrdinal];
                        if (!valid_range(static_cast<size_t>(funcRva), 1)) continue;
                        void* addr = reinterpret_cast<void*>(base + funcRva);
                        functions[i] = addr;
                        module_cache[s_name] = addr;
                        continue;
                    }
                }
            }
        }


        [[nodiscard]] static HMODULE get_ntdll() {
            static HMODULE cached_ntdll = nullptr;
            if (cached_ntdll != nullptr) {
                return cached_ntdll;
            }

        #ifndef _WINTERNL_
            typedef struct _UNICODE_STRING {
                USHORT Length;
                USHORT MaximumLength;
                PWSTR  Buffer;
            } UNICODE_STRING, * PUNICODE_STRING;

            typedef struct _PEB_LDR_DATA {
                BYTE Reserved1[8];
                PVOID Reserved2[3];
                LIST_ENTRY InMemoryOrderModuleList;
            } PEB_LDR_DATA, * PPEB_LDR_DATA;

            typedef struct _LDR_DATA_TABLE_ENTRY {
                PVOID Reserved1[2];
                LIST_ENTRY InMemoryOrderLinks;
                PVOID Reserved2[2];
                PVOID DllBase;
                PVOID Reserved3[2];
                UNICODE_STRING FullDllName;
                BYTE Reserved4[8];
                PVOID Reserved5[3];
            #pragma warning(push)
            #pragma warning(disable: 4201)
                union {
                    ULONG CheckSum;
                    PVOID Reserved6;
                } DUMMYUNIONNAME;
            #pragma warning(pop)
                ULONG TimeDateStamp;
            } LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

            typedef struct _PEB {
                BYTE Reserved1[2];
                BYTE BeingDebugged;
                BYTE Reserved2[1];
                PVOID Reserved3[2];
                PPEB_LDR_DATA Ldr;
            } PEB, * PPEB;
        #endif

            PPEB peb = nullptr;

        #if (x86_64)
            #if (MSVC && !CLANG)
                peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
            #else
                asm("movq %%gs:0x60, %0" : "=r"(peb));
            #endif
        #elif (x86_32)
            #if (MSVC&& !CLANG)
                peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
            #else
                asm("movl %%fs:0x30, %0" : "=r"(peb));
            #endif
        #endif

            if (!peb) { // not x86 or tampered with
                const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
                if (ntdll) cached_ntdll = ntdll;
                return ntdll;
            }

            PPEB_LDR_DATA ldr = peb->Ldr;
            if (!ldr) {
                const HMODULE h = GetModuleHandleW(L"ntdll.dll");
                if (h) cached_ntdll = h;
                return h;
            }

            #ifndef CONTAINING_RECORD
                #define CONTAINING_RECORD(address, type, field) ((type *)((char*)(address) - (size_t)(&((type *)0)->field)))
            #endif

            constexpr WCHAR target_name[] = L"ntdll.dll";
            constexpr size_t target_length = (std::size(target_name) - 1);

            LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
            // static analyzers don't know that InMemoryOrderModuleList is a circular list managed by the loader
            // so they conservatively assume head->Flink or some cur->Flink might be nullptr
            for (LIST_ENTRY* cur = head->Flink; cur != nullptr && cur != head; cur = cur->Flink) {
                auto* ent = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                if (!ent) continue;

                auto* fullname = &ent->FullDllName;
                if (!fullname->Buffer || fullname->Length == 0) continue;

                const auto total_chars = static_cast<USHORT>(fullname->Length / sizeof(WCHAR));

                size_t start = total_chars;
                while (start > 0) {
                    const WCHAR c = fullname->Buffer[start - 1];
                    if (c == L'\\' || c == L'/') break;
                    --start;
                }

                const size_t file_length = total_chars - start;
                if (file_length != target_length) continue;

                bool match = true;
                for (size_t i = 0; i < file_length; ++i) {
                    WCHAR a = fullname->Buffer[start + i];
                    WCHAR b = target_name[i];
                    if (a >= L'A' && a <= L'Z') a = static_cast<WCHAR>(a + 32);
                    if (b >= L'A' && b <= L'Z') b = static_cast<WCHAR>(b + 32);
                    if (a != b) { match = false; break; }
                }

                if (match) {
                    cached_ntdll = reinterpret_cast<HMODULE>(ent->DllBase);
                    return cached_ntdll;
                }
            }

            const HMODULE h = GetModuleHandleW(L"ntdll.dll");
            if (h) cached_ntdll = h;
            return h;
        } 


        static bool get_manufacturer_model(const char** out_manufacturer, const char** out_model) {
            if (out_manufacturer) *out_manufacturer = "";
            if (out_model) *out_model = "";

            if (memo::bios_info::is_cached()) {
                if (out_manufacturer) *out_manufacturer = memo::bios_info::fetch_manufacturer();
                if (out_model) *out_model = memo::bios_info::fetch_model();
                return memo::bios_info::fetch_manufacturer()[0] != '\0' || memo::bios_info::fetch_model()[0] != '\0';
            }

            WCHAR wbuf[256]{};
            DWORD cb = sizeof(wbuf);

            char man_tmp[sizeof(memo::bios_info::manufacturer)]{};
            char model_tmp[sizeof(memo::bios_info::model)]{};
            man_tmp[0] = '\0';
            model_tmp[0] = '\0';

            bool got_any = false;

            cb = sizeof(wbuf);
            if (RegGetValueW(HKEY_LOCAL_MACHINE,
                L"HARDWARE\\DESCRIPTION\\System\\BIOS",
                L"SystemManufacturer",
                RRF_RT_REG_SZ,
                nullptr,
                wbuf,
                &cb) == ERROR_SUCCESS && wbuf[0] != L'\0') {
                const int conv = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, man_tmp, static_cast<int>(sizeof(man_tmp)), nullptr, nullptr);
                if (conv > 0) {
                    man_tmp[sizeof(man_tmp) - 1] = '\0';
                    memo::bios_info::store_manufacturer(man_tmp);
                    got_any = true;
                }
            }

            cb = sizeof(wbuf);
            if (RegGetValueW(HKEY_LOCAL_MACHINE,
                L"HARDWARE\\DESCRIPTION\\System\\BIOS",
                L"SystemProductName",
                RRF_RT_REG_SZ,
                nullptr,
                wbuf,
                &cb) == ERROR_SUCCESS && wbuf[0] != L'\0') {
                const int conv = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, model_tmp, static_cast<int>(sizeof(model_tmp)), nullptr, nullptr);
                if (conv > 0) {
                    model_tmp[sizeof(model_tmp) - 1] = '\0';
                    memo::bios_info::store_model(model_tmp);
                    got_any = true;
                }
            }

            if (!memo::bios_info::is_cached()) {
                memo::bios_info::cached = true;
            }

            if (out_manufacturer) *out_manufacturer = memo::bios_info::fetch_manufacturer();
            if (out_model) *out_model = memo::bios_info::fetch_model();

            return got_any;
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

        struct cstrview {
            const char* data;
            std::size_t size;
            constexpr cstrview(const char* d, std::size_t s) noexcept
                : data(d), size(s) {
            }
        };

        static constexpr std::array<cstrview, 10> checks{ {
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

                // Otherwise map to our enums:
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
     * @brief Check if hypervisor feature bit in CPUID ECX bit 31 is enabled (always false for physical CPUs)
     * @category x86
     * @implements VM::HYPERVISOR_BIT
     */
    [[nodiscard]] static bool hypervisor_bit() {
    #if (!x86)
        return false;
    #else
        u32 eax = 0, ebx = 0, ecx = 0, edx = 0;
        cpu::cpuid(eax, ebx, ecx, edx, 1); 
        constexpr u32 HYPERVISOR_MASK = (1u << 31);

        if (ecx & HYPERVISOR_MASK) {
            if (util::hyper_x() == HYPERV_ARTIFACT_VM) {
                return false;
            }

            return true;
        }

        return false;
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
        cpu::cpuid(reinterpret_cast<int*>(out), cpu::leaf::hypervisor);

        debug("HYPERVISOR_STR: \neax: ", static_cast<u32>(out[0]),
            "\nebx: ", static_cast<u32>(out[1]),
            "\necx: ", static_cast<u32>(out[2]),
            "\nedx: ", static_cast<u32>(out[3])
        );

        return (std::strlen(out + 4) >= 4);
    #endif  
    }
    

    /**
     * @brief Check for various Bochs-related emulation oversights through CPU checks
     * @category x86
     * @author Discovered by Peter Ferrie, Senior Principal Researcher, Symantec Advanced Threat Research peter_ferrie@symantec.com
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

            auto is_k7 = [](const u32 eax) noexcept -> bool {
                if ((eax & 0x0FF00F00) != 0x00000600) {
                    return false;
                }

                const u32 model = (eax >> 4) & 0xF;

                return (model - 1) < 4;
            };

            auto is_k8 = [](const u32 eax) noexcept -> bool {
                if (((eax >> 8) & 0xF) != 0xF) {
                    return false;
                }

                const u32 extended_family = (eax >> 20) & 0xFF;

                return extended_family <= 1;
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
	 * @brief Check if the system's thread count matches the expected thread count for the detected CPU model
     * @category x86
     * @implements VM::THREAD_MISMATCH
     */
    [[nodiscard]] static bool thread_mismatch() {
    #if (!x86)
        return false;
    #else
        const auto& info = cpu::analyze_cpu();

        if (info.found) {
            debug(info.debug_tag, ": CPU model = ", info.model_name);

            const u32 actual = memo::threadcount::fetch();
            if (actual != info.expected_threads) {
                debug(info.debug_tag, ": Current threads -> ", actual);
                debug(info.debug_tag, ": Expected threads -> ", info.expected_threads);
                return true;
            }
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
        VMAWARE_UNUSED(unused);

        constexpr u32 simplevisor = 0x00766853; // " vhS"

        debug("CPUID_SIGNATURE: eax = ", eax);

        if (eax == simplevisor)
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

        constexpr u32 ECX_SIG = 0x4D4D5645u; // 'EVMM' -> 0x4D4D5645
        constexpr u32 EDX_SIG = 0x43544E49u;  // 'INTC' -> 0x43544E49

        if (ecx == ECX_SIG && edx == EDX_SIG) {
            return core::add(brands::INTEL_KGT);
        }

        return false;
    #endif
    }


    /**
     * @brief Check for timing anomalies in the system
     * @category x86
     * @implements VM::TIMER
     */
    [[nodiscard]] static bool timer() {
    #if (x86)
        #if (MSVC)
            #define COMPILER_BARRIER() _ReadWriteBarrier()
        #else
            #define COMPILER_BARRIER() asm volatile("" ::: "memory")
        #endif

        // ================ INITIALIZATION STUFF ================

        if (util::is_running_under_translator()) {
            debug("TIMER: Running inside a binary translation layer");
            return false;
        }
        // will be used in cpuid measurements
        u16 cycle_threshold = 800; // average latency of a VMX/SVM VMEXIT alone
        if (util::hyper_x() == HYPERV_ARTIFACT_VM) {
            cycle_threshold = 3250; // if we're running under Hyper-V, make VMAware detect nested virtualization
        }

        // check for RDTSCP support, we will use it later
        int regs[4] = { 0 };
        cpu::cpuid(regs, 0x80000001);
        const bool have_rdtscp = (regs[3] & (1u << 27)) != 0;
        if (!have_rdtscp) {
            debug("TIMER: RDTSCP instruction not supported"); // __rdtscp should be supported nowadays
            return true;
        }     

        constexpr u64 ITER_XOR = 100000000ULL;
        constexpr size_t CPUID_ITER = 100; // per leaf
        static constexpr unsigned int leaves[] = {
             0xB, 0xD, 0x4, 0x1, 0x7, 0xA, 0x12, 0x5, 0x40000000u, 0x80000008u, 0x0
        };
        constexpr size_t n_leaves = sizeof(leaves) / sizeof(leaves[0]);

        unsigned hw = std::thread::hardware_concurrency();
        if (hw == 0) hw = 1;

        std::atomic<int> ready_count(0);
        std::atomic<int> state(0); 

        std::atomic<u64> t1_start(0), t1_end(0);
        std::atomic<u64> t2_start(0), t2_end(0);
        std::atomic<u64> t2_accum(0);

        std::vector<u64> samples(100000, 0);

        auto rdtsc = []() noexcept -> u64 {
        #if (MSVC)
            return static_cast<u64>(__rdtsc());
        #else
            return static_cast<u64>(__rdtsc());
        #endif
        };

        struct affinity_cookie {
            bool valid{ false };
        #if (WINDOWS)
            HANDLE thread_handle{ nullptr };
            DWORD_PTR prev_mask{ 0 };
        #elif (LINUX)
            pthread_t thread{ 0 };
            cpu_set_t prev_mask{};
        #endif
        };

        auto set_affinity = [](std::thread& t, unsigned core) -> affinity_cookie {
            affinity_cookie cookie;
        #if (WINDOWS)
            HANDLE h = static_cast<HANDLE>(t.native_handle());
            DWORD_PTR mask = static_cast<DWORD_PTR>(1ULL) << core;
            DWORD_PTR prev = SetThreadAffinityMask(h, mask);
            if (prev != 0) {
                cookie.valid = true;
                cookie.thread_handle = h;
                cookie.prev_mask = prev;
            }
        #elif (LINUX)
            pthread_t ph = t.native_handle();
            cpu_set_t prev;
            if (pthread_getaffinity_np(ph, sizeof(prev), &prev) == 0) {
                cpu_set_t cp;
                CPU_ZERO(&cp);
                CPU_SET(core, &cp);
                (void)pthread_setaffinity_np(ph, sizeof(cp), &cp); 
                cookie.valid = true;
                cookie.thread = ph;
                cookie.prev_mask = prev; 
            }
        #else
            (void)t; (void)core;
        #endif
            return cookie;
        };

        auto restore_affinity = [](const affinity_cookie& cookie) {
            if (!cookie.valid) return;
        #if (WINDOWS)
            (void)SetThreadAffinityMask(cookie.thread_handle, cookie.prev_mask);
        #elif (LINUX)
            (void)pthread_setaffinity_np(cookie.thread, sizeof(cookie.prev_mask), &cookie.prev_mask);
        #else
            (void)cookie;
        #endif
        };

        thread_local u32 aux = 0;
        auto cpuid = [](unsigned int leaf) noexcept -> u64 {
        #if (MSVC)
            // make regs volatile so writes cannot be optimized out, if this isn't added and the code is compiled in release mode, cycles would be around 40 even under Hyper-V
            volatile int regs[4]{};

            // ensure the CPU pipeline is drained of previous loads before we start the clock
            _mm_lfence();

            // read start time
            const u64 t1 = __rdtsc();

            // prevent the compiler from moving the __cpuid call before the t1 read
            COMPILER_BARRIER();

            __cpuid((int*)regs, static_cast<int>(leaf)); // not using cpu::cpuid to get a chance of inlining

            COMPILER_BARRIER();

            // the idea is to let rdtscp internally wait until cpuid is executed rather than using another memory barrier
            const u64 t2 = __rdtscp(&aux);

            // ensure the read of t2 doesn't bleed into future instructions
            _mm_lfence();

            // Create a dependency on regs so the cast above isn't ignored
            (void)regs[0];

            return t2 - t1;
        #else
            // same logic of above
            unsigned int lo1, hi1, lo2, hi2;

            asm volatile("lfence" ::: "memory");
            asm volatile("rdtsc" : "=a"(lo1), "=d"(hi1) :: "memory");
            COMPILER_BARRIER();

            volatile unsigned int a, b, c, d;

            // this differs from the code above because a, b, c and d are effectively used
            // the compiler must honor the write to a volatile variable
            asm volatile("cpuid"
                : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                : "a"(leaf)
                : "memory");

            COMPILER_BARRIER();

            asm volatile("rdtscp" : "=a"(lo2), "=d"(hi2) :: "rcx", "memory");
            asm volatile("lfence" ::: "memory");

            const u64 t1 = (u64(hi1) << 32) | lo1;
            const u64 t2 = (u64(hi2) << 32) | lo2;

            return t2 - t1;
        #endif
        };

        auto calculate_latency = [&](const std::vector<u64>& samples_in) -> u64 {
            if (samples_in.empty()) return 0;
            const size_t N = samples_in.size();
            if (N == 1) return samples_in[0];

            // local sorted copy
            std::vector<u64> s = samples_in;
            std::sort(s.begin(), s.end()); // ascending

            // tiny-sample short-circuits
            if (N <= 4) return s.front();

            // median (and works for sorted input)
            auto median_of_sorted = [](const std::vector<u64>& v, size_t lo, size_t hi) -> u64 {
                // this is the median of v[lo..hi-1], requires 0 <= lo < hi
                const size_t len = hi - lo;
                if (len == 0) return 0;
                const size_t mid = lo + (len / 2);
                if (len & 1) return v[mid];
                return (v[mid - 1] + v[mid]) / 2;
            };

            // the robust center: median M and MAD -> approximate sigma
            const u64 M = median_of_sorted(s, 0, s.size());
            std::vector<u64> absdev;
            absdev.reserve(N);
            for (size_t i = 0; i < N; ++i) {
                const u64 d = (s[i] > M) ? (s[i] - M) : (M - s[i]);
                absdev.push_back(d);
            }
            std::sort(absdev.begin(), absdev.end());
            const u64 MAD = median_of_sorted(absdev, 0, absdev.size());
            // convert MAD to an approximate standard-deviation-like measure
            const long double kmad_to_sigma = 1.4826L; // consistent for normal approx
            const long double sigma = (MAD == 0) ? 1.0L : (static_cast<long double>(MAD) * kmad_to_sigma);

            // find the densest small-valued cluster by sliding a fixed-count window
            // this locates the most concentrated group of samples (likely it would be the true VMEXIT cluster)
            // const size_t frac_win = (N * 8 + 99) / 100; // ceil(N * 0.08)
            // const size_t win = std::min(N, std::max(MIN_WIN, frac_win));
            const size_t MIN_WIN = 10;
            const size_t win = std::min(
                N,
                std::max(
                    MIN_WIN,
                    static_cast<size_t>(std::ceil(static_cast<double>(N) * 0.08))
                )
            );
            size_t best_i = 0;
            u64 best_span = (s.back() - s.front()) + 1; // large initial
            for (size_t i = 0; i + win <= N; ++i) {
                const u64 span = s[i + win - 1] - s[i];
                if (span < best_span) {
                    best_span = span;
                    best_i = i;
                }
            }

            // expand the initial window greedily while staying "tight"
            // allow expansion while adding samples does not more than multiply the span by EXPAND_FACTOR
            constexpr long double EXPAND_FACTOR = 1.5L;
            size_t cluster_lo = best_i;
            size_t cluster_hi = best_i + win; // exclusive
            // expand left
            while (cluster_lo > 0) {
                const u64 new_span = s[cluster_hi - 1] - s[cluster_lo - 1];
                if (static_cast<long double>(new_span) <= EXPAND_FACTOR * static_cast<long double>(best_span) ||
                    (s[cluster_hi - 1] <= (s[cluster_lo - 1] + static_cast<u64>(std::ceil(3.0L * sigma))))) {
                    --cluster_lo;
                    best_span = std::min(best_span, new_span);
                }
                else break;
            }
            // expand right
            while (cluster_hi < N) {
                const u64 new_span = s[cluster_hi] - s[cluster_lo];
                if (static_cast<long double>(new_span) <= EXPAND_FACTOR * static_cast<long double>(best_span) ||
                    (s[cluster_hi] <= (s[cluster_lo] + static_cast<u64>(std::ceil(3.0L * sigma))))) {
                    ++cluster_hi;
                    best_span = std::min(best_span, new_span);
                }
                else break;
            }

            const size_t cluster_size = (cluster_hi > cluster_lo) ? (cluster_hi - cluster_lo) : 0;

            // cluster must be reasonably dense and cover a non-negligible portion of samples, so this is pure sanity checks
            const double fraction_in_cluster = static_cast<double>(cluster_size) / static_cast<double>(N);
            const size_t MIN_CLUSTER = std::min(static_cast<size_t>(std::max<int>(5, static_cast<int>(N / 50))), N); // at least 2% or 5 elements
            if (cluster_size < MIN_CLUSTER || fraction_in_cluster < 0.02) {
                // low-percentile (10th) trimmed median
                const size_t fallback_count = std::max<size_t>(1, static_cast<size_t>(std::floor(static_cast<double>(N) * 0.10)));
                // median of lowest fallback_count elements (if fallback_count==1 that's smallest)
                if (fallback_count == 1) return s.front();
                const size_t mid = fallback_count / 2;
                if (fallback_count & 1) return s[mid];
                return (s[mid - 1] + s[mid]) / 2;
            }

            // now we try to get a robust estimate inside the cluster, trimmed mean (10% trim) centered on cluster
            const size_t trim_count = static_cast<size_t>(std::floor(static_cast<double>(cluster_size) * 0.10));
            const size_t lo = cluster_lo + trim_count;
            const size_t hi = cluster_hi - trim_count; // exclusive
            if (hi <= lo) {
                // degenerate -> median of cluster
                return median_of_sorted(s, cluster_lo, cluster_hi);
            }

            // sum with long double to avoid overflow and better rounding
            long double sum = 0.0L;
            for (size_t i = lo; i < hi; ++i) sum += static_cast<long double>(s[i]);
            const long double avg = sum / static_cast<long double>(hi - lo);
            u64 result = static_cast<u64>(std::llround(avg));

            // final sanity adjustments:
            // if the computed result is suspiciously far from the global median (e.g., > +6*sigma)
            // clamp toward the median to avoid choosing a high noisy cluster by mistake
            const long double diff_from_med = static_cast<long double>(result) - static_cast<long double>(M);
            if (diff_from_med > 0 && diff_from_med > (6.0L * sigma)) {
                // clamp to median + 4*sigma (conservative)
                result = static_cast<u64>(std::llround(static_cast<long double>(M) + 4.0L * sigma));
            }

            // also, if result is zero (shouldn't be) or extremely small, return a smallest observed sample
            if (result == 0) result = s.front();

            return result;
        };

        // to touch pages and exercise cpuid paths
        for (int w = 0; w < 128; ++w) {
            volatile u64 tmp = cpuid(leaves[w % n_leaves]);
            VMAWARE_UNUSED(tmp);
        }

        // if hypervisor downscales TSC globally, this will catch it
        const u64 calib_start = rdtsc();
        {
            volatile u64 x = 0xDEADBEEFCAFEBABEULL;
            for (u64 i = 0; i < ITER_XOR; ++i) {
                x ^= i;
                x = (x << 1) ^ (x >> 3);
            }
            VMAWARE_UNUSED(x);
        }
        const u64 calib_end = rdtsc();
        const u64 calib_delta = (calib_end > calib_start) ? (calib_end - calib_start) : 0;

        ready_count.store(0, std::memory_order_release);
        state.store(0, std::memory_order_release);

        // Thread 1: start near same cycle, do XOR work, set end
        std::thread th1([&]() {
            ready_count.fetch_add(1, std::memory_order_acq_rel);
            while (ready_count.load(std::memory_order_acquire) < 2)
                _mm_pause();

            const u64 s = rdtsc();
            t1_start.store(s, std::memory_order_release);
            state.store(1, std::memory_order_release);

            volatile u64 x = 0xDEADBEEFCAFEBABEULL;
            for (u64 i = 0; i < ITER_XOR; ++i) {
                x ^= i;
                x = (x << 1) ^ (x >> 3);
            }
            VMAWARE_UNUSED(x);

            const u64 e = rdtsc();
            t1_end.store(e, std::memory_order_release);
            state.store(2, std::memory_order_release);
        });

        // Thread 2: rdtsc and cpuid spammer, forces hypervisor to downscale TSC if patch is present; if interception disabled, caught by cpuid latency 
        std::thread th2([&]() {
            ready_count.fetch_add(1, std::memory_order_acq_rel);
            while (ready_count.load(std::memory_order_acquire) < 2) 
                _mm_pause();

            u64 last = rdtsc();
            t2_start.store(last, std::memory_order_release);

            // local accumulator (fast) and local index into samples
            u64 acc = 0;
            size_t idx = 0;

            // for each leaf do CPUID_ITER samples, then repeat
            while (state.load(std::memory_order_acquire) != 2) {
                for (size_t li = 0; li < n_leaves; ++li) {
                    const unsigned int leaf = leaves[li];

                    for (unsigned i = 0; i < CPUID_ITER; ++i) {
                        // read rdtsc and accumulate delta
                        const u64 now = rdtsc();
                        acc += (now >= last) ? (now - last) : (u64)((u64)0 - last + now);
                        last = now;

                        // store latency if buffer has space
                        if (idx < samples.size()) samples[idx] = cpuid(leaf);
                        ++idx;

                        // if thread1 finished
                        if (state.load(std::memory_order_acquire) == 2) break;
                    }

                    if (state.load(std::memory_order_acquire) == 2) break;
                }
            }

            // final rdtsc after detecting finish
            const u64 final_now = rdtsc();
            acc += (final_now >= last) ? (final_now - last) : (u64)((u64)0 - last + final_now);
            last = final_now;

            // publish results
            t2_end.store(final_now, std::memory_order_release);
            t2_accum.store(acc, std::memory_order_release);
        });

        // try to pin to different cores
        affinity_cookie cookie1{};
        affinity_cookie cookie2{};
        if (hw >= 2) { 
            if (hw >= 2) {
                cookie1 = set_affinity(th1, 0);
                cookie2 = set_affinity(th2, 1);
            }
        }

        th1.join();
        th2.join();

        restore_affinity(cookie1);
        restore_affinity(cookie2);

        // collect results
        const u64 a = t1_start.load(std::memory_order_acquire);
        const u64 b = t1_end.load(std::memory_order_acquire);
        #ifdef __VMAWARE_DEBUG__
            const u64 c = t2_start.load(std::memory_order_acquire);
            const u64 d = t2_end.load(std::memory_order_acquire);
        #endif
        const u64 acc = t2_accum.load(std::memory_order_acquire);

        const u64 t1_delta = (b > a) ? (b - a) : 0;
        const u64 t2_delta = acc;

        std::vector<u64> used;
        for (size_t i = 0; i < samples.size(); ++i)
            if (samples[i] != 0)
                used.push_back(samples[i]);
        const u64 cpuid_latency = calculate_latency(used);

        debug("TIMER: calibration cycles: start=", calib_start, " delta=", calib_delta);
        debug("TIMER: thread1 cycles: start=", a, " delta=", t1_delta);
        debug("TIMER: thread2 cycles: start=", c, " delta=", t2_delta);
        debug("TIMER: vmexit latency: ", cpuid_latency);

        if (cpuid_latency >= cycle_threshold) {
            return true;
        }
        else if (cpuid_latency <= 25) {
            // cpuid is fully serializing, no CPU have this low average cycles in real-world scenarios
            // however, in patches, zero or even negative deltas can be seen oftenly
            return true;
        }

        if (t1_delta == 0 || calib_delta == 0) {
            return true;
        }

        const double ratio = double(t2_delta) / double(t1_delta);
        const double calibration_ratio = static_cast<double>(t1_delta) / static_cast<double>(calib_delta);

        // if thread 1 was faster than thread 2, hypervisor downscaled TSC per-vCPU in either cpuid or rdtsc
        if (ratio < 0.95 || ratio > 1.05) {
            return true;
        }
        // if calibration was much faster than thread 1, hypervisor downscaled TSC globally while thread 2 was spamming
        if (calibration_ratio < 0.95) {
            return true;
        }

        #if (WINDOWS)
            typedef struct _PROCESSOR_POWER_INFORMATION {
                u32 Number;
                u32 MaxMhz;
                u32 CurrentMhz;
                u32 MhzLimit;
                u32 MaxIdleState;
                u32 CurrentIdleState;
            } PROCESSOR_POWER_INFORMATION, * PPROCESSOR_POWER_INFORMATION;

            enum POWER_INFORMATION_LEVEL_MIN {
                ProcessorInformation = 11
            };

            const HMODULE hPowr = LoadLibraryA("powrprof.dll");
            if (!hPowr) return 0;

            const char* names[] = { "CallNtPowerInformation" };
            void* funcs[1] = { nullptr };
            util::get_function_address(hPowr, names, funcs, 1);
            if (!funcs[0]) return 0;

            using CallNtPowerInformation_t = NTSTATUS(__stdcall*)(int, PVOID, ULONG, PVOID, ULONG);
            CallNtPowerInformation_t CallNtPowerInformation =
                reinterpret_cast<CallNtPowerInformation_t>(funcs[0]);

            SYSTEM_INFO si;
            GetSystemInfo(&si);
            const DWORD procCount = si.dwNumberOfProcessors;
            if (procCount == 0) return 0;

            const SIZE_T bufSize = static_cast<SIZE_T>(procCount) * sizeof(PROCESSOR_POWER_INFORMATION);
            void* raw = _malloca(bufSize);
            if (!raw) return 0;
            memset(raw, 0, bufSize);

            NTSTATUS status = CallNtPowerInformation(
                ProcessorInformation,
                nullptr, 0,
                raw, static_cast<ULONG>(bufSize)
            );

            unsigned speed = 0;
            if ((LONG)status >= 0) {
                PROCESSOR_POWER_INFORMATION* info = reinterpret_cast<PROCESSOR_POWER_INFORMATION*>(raw);
                speed = static_cast<unsigned>(info[0].CurrentMhz);
            }

            _freea(raw);

            if (speed < 800) {
                debug("TIMER: VMAware detected an hypervisor offsetting TSC: ", speed);
                return true;
            }
        #endif
    #endif
        return false;
    }

#if (LINUX)
    /**
     * @brief Check result from systemd-detect-virt tool
     * @category Linux
     * @implements VM::SYSTEMD
     */
    [[nodiscard]] static bool systemd_virt() {
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
    }


    /**
     * @brief Check if the chassis vendor is a VM vendor
     * @category Linux
     * @implements VM::CVENDOR
     */
    [[nodiscard]] static bool chassis_vendor() {
        const char* vendor_file = "/sys/devices/virtual/dmi/id/chassis_vendor";

        if (!util::exists(vendor_file)) {
            debug("CVENDOR: ", "file doesn't exist");
            return false;
        }

        const std::string vendor = util::read_file(vendor_file);

        // TODO: More can definitely be added, only QEMU and VBox were tested so far
        if (util::find(vendor, "QEMU")) { return core::add(brands::QEMU); }
        if (util::find(vendor, "Oracle Corporation")) { return core::add(brands::VBOX); }

        debug("CVENDOR: vendor = ", vendor);

        return false;
    }


    /**
     * @brief Check if the chassis type is valid (it's very often invalid in VMs)
     * @category Linux
     * @implements VM::CTYPE
     */
    [[nodiscard]] static bool chassis_type() {
        const char* chassis = "/sys/devices/virtual/dmi/id/chassis_type";

        if (util::exists(chassis)) {
            return (stoi(util::read_file(chassis)) == 1);
        } else {
            debug("CTYPE: ", "file doesn't exist");
        }

        return false;
    }


    /**
     * @brief Check if /.dockerenv or /.dockerinit file is present
     * @category Linux
     * @implements VM::DOCKERENV
     */
    [[nodiscard]] static bool dockerenv() {
        if (util::exists("/.dockerenv") || util::exists("/.dockerinit")) {
            return core::add(brands::DOCKER);
        }

        return false;
    }


    /**
     * @brief Check if dmidecode output matches a VM brand
     * @category Linux
     * @warning Permissions required
     * @implements VM::DMIDECODE
     */
    [[nodiscard]] static bool dmidecode() {
        if (!util::is_admin()) {
            debug("DMIDECODE: ", "precondition return called (root = ", util::is_admin(), ")");
            return false;
        }

        if (!(util::exists("/bin/dmidecode") || util::exists("/usr/bin/dmidecode"))) {
            debug("DMIDECODE: ", "binary doesn't exist");
            return false;
        }

        const std::unique_ptr<std::string> result = util::sys_result("dmidecode -t system | grep 'Manufacturer|Product' | grep -c \"QEMU|VirtualBox|KVM\"");

        if (!result || result->empty()) {
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
    }


    /**
     * @brief Check if mac address starts with certain VM designated values
     * @category Linux
     * @implements VM::MAC
     */
    [[nodiscard]] static bool mac_address_check() {
        struct fdguard {
            int fd;
            explicit fdguard(int fd = -1) : fd(fd) {}
            ~fdguard() { if (fd != -1) ::close(fd); }
            int get() const { return fd; }
            int release() { int tmp = fd; fd = -1; return tmp; }
        };

        u8 mac[6] = { 0 };
        struct ifreq ifr;
        struct ifconf ifc;
        char buf[1024];
        int success = 0;

        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (sock == -1) {
            return false;
        }
        fdguard sockGuard(sock); // will close on function exit

        ifc.ifc_len = sizeof(buf);
        ifc.ifc_buf = buf;

        if (ioctl(sockGuard.get(), SIOCGIFCONF, &ifc) == -1) {
            return false;
        }

        struct ifreq* it = ifc.ifc_req;
        const struct ifreq* end = it + (ifc.ifc_len / sizeof(struct ifreq));

        for (; it != end; ++it) {
            std::size_t name_len = std::min<std::size_t>(sizeof(ifr.ifr_name) - 1, strlen(it->ifr_name));
            std::memcpy(ifr.ifr_name, it->ifr_name, name_len);
            ifr.ifr_name[name_len] = '\0';

            if (ioctl(sockGuard.get(), SIOCGIFFLAGS, &ifr) != 0) {
                return false;
            }

            if (!(ifr.ifr_flags & IFF_LOOPBACK)) {
                if (ioctl(sockGuard.get(), SIOCGIFHWADDR, &ifr) == 0) {
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
        constexpr u32 XEN = 0xE31600;   // 00:16:E3
        constexpr u32 PAR = 0x421C00;   // 00:1C:42

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
    }


    /**
     * @brief Check if dmesg output matches a VM brand
     * @category Linux
     * @warning Permissions required
     * @implements VM::DMESG
     */
    [[nodiscard]] static bool dmesg() {
    #if (VMA_CPP <= 11)
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

        if (!result || result->empty()) {
            return false;
        }
        else if (*result == "KVM") {
            return core::add(brands::KVM);
        }
        else if (*result == "QEMU") {
            return core::add(brands::QEMU);
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


    /**
     * @brief Check if /sys/class/hwmon/ directory is present. If not, likely a VM
     * @category Linux
     * @implements VM::HWMON
     */
    [[nodiscard]] static bool hwmon() {
        return (!util::exists("/sys/class/hwmon/"));
    }


    /**
     * @brief Check for default VM username and hostname for linux
     * @category Linux
     * @implements VM::LINUX_USER_HOST
     */
    [[nodiscard]] static bool linux_user_host() {
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
    }


    /**
     * @brief Check for VMware string in /proc/iomem
     * @category Linux
     * @author idea from ScoopyNG by Tobias Klein
     * @implements VM::VMWARE_IOMEM
     */
    [[nodiscard]] static bool vmware_iomem() {
        const std::string iomem_file = util::read_file("/proc/iomem");

        if (util::find(iomem_file, "VMware")) {
            return core::add(brands::VMWARE);
        }

        return false;
    }


    /**
     * @brief Check for the presence of BlueStacks-specific folders
     * @category ARM, Linux
     * @implements VM::BLUESTACKS_FOLDERS
     */
    [[nodiscard]] static bool bluestacks() {
    #if (!ARM)
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
	 * @brief Check for AMD-SEV MSR running on the system
	 * @category x86, Linux, MacOS
	 * @author idea from virt-what
     * @warning Permissions required
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

        if (result & (static_cast<u64>(1) << 2)) { return core::add(brands::AMD_SEV_SNP); }
        else if (result & (static_cast<u64>(1) << 1)) { return core::add(brands::AMD_SEV_ES); }
        else if (result & 1) { return core::add(brands::AMD_SEV); }

        return false;
    #else
        return false;
    #endif
    }


    /**
     * @brief Check for presence of QEMU in the /sys/devices/virtual/dmi/id directory
     * @category Linux
     * @implements VM::QEMU_VIRTUAL_DMI
     */
    [[nodiscard]] static bool qemu_virtual_dmi() {
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
    }


    /**
     * @brief Check for presence of QEMU in the /sys/kernel/debug/usb/devices directory
     * @category Linux
     * @warning Permissions required
     * @implements VM::QEMU_USB
     */
    [[nodiscard]] static bool qemu_USB() {
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
    }


    /**
     * @brief Check for presence of any files in /sys/hypervisor directory
     * @category Linux
     * @implements VM::HYPERVISOR_DIR
     */
    [[nodiscard]] static bool hypervisor_dir() {
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
    } 


    /**
     * @brief Check for the "UML" string in the CPU brand
     * @author idea from https://github.com/ShellCode33/VM-Detection/blob/master/vmdetect/linux.go
     * @category Linux
     * @implements VM::UML_CPU
     */
    [[nodiscard]] static bool uml_cpu() {
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
    } 


    /**
     * @brief Check for any indications of hypervisors in the kernel message logs
     * @author idea from https://github.com/ShellCode33/VM-Detection/blob/master/vmdetect/linux.go
     * @category Linux
     * @warning Permissions required
     * @implements VM::KMSG
     */
    [[nodiscard]] static bool kmsg() {
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
    } 


    /**
     * @brief Check for a VBox kernel module
     * @author idea from https://github.com/ShellCode33/VM-Detection/blob/master/vmdetect/linux.go
     * @category Linux
     * @implements VM::VBOX_MODULE
     */
    [[nodiscard]] static bool vbox_module() {
        const char* file = "/proc/modules";

        if (!util::exists(file)) {
            return false;
        }

        const std::string content = util::read_file(file);

        if (util::find(content, "vboxguest")) {
            return core::add(brands::VBOX);
        }

        return false;
    }


    /**
     * @brief Check for VMware string in /proc/scsi/scsi
     * @category Linux
     * @author idea from ScoopyNG by Tobias Klein
     * @implements VM::VMWARE_SCSI
     */
    [[nodiscard]] static bool vmware_scsi() {
        const std::string scsi_file = util::read_file("/proc/scsi/scsi");

        if (util::find(scsi_file, "VMware")) {
            return core::add(brands::VMWARE);
        }

        return false;
    }

        
    /**
     * @brief Check for VMware-specific device name in dmesg output
     * @category Linux
     * @author idea from ScoopyNG by Tobias Klein
     * @note Disabled by default
     * @warning Permissions required
     * @implements VM::VMWARE_DMESG
     */
    [[nodiscard]] static bool vmware_dmesg() {
        if (!util::is_admin()) {
            return false;
        }

        if (!util::exists("/usr/bin/dmesg")) {
            return false;
        }

        auto dmesg_output = util::sys_result("dmesg");
        const std::string dmesg_o = *dmesg_output;

        if (dmesg_o.empty()) {
            return false;
        }

        if (util::find(dmesg_o, "BusLogic BT-958")) {
            return core::add(brands::VMWARE);
        }

        if (util::find(dmesg_o, "pcnet32")) {
            return core::add(brands::VMWARE);
        }

        return false;
    }


    /**
     * @brief Check for potential VM info in /proc/sysinfo
     * @author idea from https://github.com/ShellCode33/VM-Detection/blob/master/vmdetect/linux.go
     * @category Linux
     * @implements VM::SYSINFO_PROC
     */
    [[nodiscard]] static bool sysinfo_proc() {
        const char* file = "/proc/sysinfo";

        if (!util::exists(file)) {
            return false;
        }

        const std::string content = util::read_file(file);

        if (util::find(content, "VM00")) {
            return true;
        }

        return false;
    } 


    /**
     * @brief Check for string matches of VM brands in the linux DMI
     * @category Linux
     * @implements VM::DMI_SCAN
     */
    [[nodiscard]] static bool dmi_scan() {
        /*
        cat: /sys/class/dmi/id/board_serial: Permission denied
        cat: /sys/class/dmi/id/chassis_serial: Permission denied
        cat: /sys/class/dmi/id/product_serial: Permission denied
        cat: /sys/class/dmi/id/product_uuid: Permission denied
        */

        constexpr std::array<const char*, 7> dmi_array{
            "/sys/class/dmi/id/bios_vendor",
            "/sys/class/dmi/id/board_name",
            "/sys/class/dmi/id/board_vendor",
            "/sys/class/dmi/id/chassis_asset_tag",
            "/sys/class/dmi/id/product_family",
            "/sys/class/dmi/id/product_sku",
            "/sys/class/dmi/id/sys_vendor"
        };

        constexpr std::array<std::pair<const char*, const char*>, 15> vm_table{ {
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
        } };


        for (const auto file : dmi_array) {
            if (!util::exists(file)) {
                continue;
            }

            std::string content = util::read_file(file);
            if (content.empty()) {
                continue;
            }
            char* data = &content[0];
            const size_t len = content.size();
            for (size_t i = 0; i < len; ++i) {
                if (data[i] >= 'A' && data[i] <= 'Z') {
                    data[i] |= 0x20;
                }
            }

            for (const auto& vm_string : vm_table) {
                if (content.find(vm_string.first) != std::string::npos) {

                    debug("DMI_SCAN: content = ", content);

                    if (strcmp(vm_string.second, brands::AWS_NITRO) == 0) {
                        if (smbios_vm_bit()) {
                            return core::add(brands::AWS_NITRO);
                        }
                    }
                    else {
                        return core::add(vm_string.second);
                    }
                }
            }
        }

        return false;
    }


    /**
     * @brief Check for the VM bit in the SMBIOS data
     * @author idea from https://github.com/systemd/systemd/blob/main/src/basic/virt.c
     * @category Linux
     * @warning Permissions required
     * @implements VM::SMBIOS_VM_BIT
     */
    [[nodiscard]] static bool smbios_vm_bit() {
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
    } 


    /**
     * @brief Check for podman file in /run/
     * @author idea from https://github.com/systemd/systemd/blob/main/src/basic/virt.c
     * @category Linux
     * @implements VM::PODMAN_FILE
     */
    [[nodiscard]] static bool podman_file() {
        if (util::exists("/run/.containerenv")) {
            return core::add(brands::PODMAN);
        }

        return false;
    }


    /**
     * @brief Check for VMware string in /proc/ioports
     * @category Linux
     * @author idea from ScoopyNG by Tobias Klein
     * @implements VM::VMWARE_IOPORTS
     */
    [[nodiscard]] static bool vmware_ioports() {
        const std::string ioports_file = util::read_file("/proc/ioports");
    
        if (util::find(ioports_file, "VMware")) {
            return core::add(brands::VMWARE);
        }
    
        return false;
    }


    /**
     * @brief Check for WSL or microsoft indications in /proc/ subdirectories
     * @author idea from https://github.com/systemd/systemd/blob/main/src/basic/virt.c
     * @category Linux
     * @implements VM::WSL_PROC
     */
    [[nodiscard]] static bool wsl_proc_subdir() {
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
                (util::find(version_content, "WSL") || util::find(version_content, "Microsoft"))
            ) {
                return core::add(brands::WSL);
            }
        }

        return false;
    }


    /**
     * @brief Detect QEMU fw_cfg interface. This first checks the Device Tree for a fw-cfg node or hypervisor tag, then verifies the presence of the qemu_fw_cfg module and firmware directories in sysfs.
     * @category Linux
     * @implements VM::QEMU_FW_CFG
     */
     [[nodiscard]] static bool qemu_fw_cfg() {
        // Linux DT method: inspired by https://github.com/ShellCode33/VM-Detection
        // Linux sysfs method: looks for /sys/module/qemu_fw_cfg/ & /sys/firmware/qemu_fw_cfg/

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
    }


    /**
     * @brief Check if the number of accessed files are too low for a human-managed environment
     * @category Linux
     * @author idea from https://unprotect.it/technique/xbel-recently-opened-files-check/
     * @implements VM::FILE_ACCESS_HISTORY
     */
    [[nodiscard]] static bool file_access_history() {
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
    }


    /**
     * @brief Check if process status matches with nsjail patterns with PID anomalies
     * @category Linux
     * @implements VM::NSJAIL_PID
     */
    [[nodiscard]] static bool nsjail_proc_id() {
        std::ifstream status_file("/proc/self/status");
        if (!status_file.is_open()) {
            return false;
        }

        std::string line;
        bool pid_match = false;
        bool ppid_match = false;

        auto parse_number = [&](const std::string& prefix) -> int {
            if (line.compare(0, prefix.size(), prefix) != 0) {
                return -1;
            }
            int num = 0;
            for (size_t i = prefix.size(); i < line.size(); ++i) {
                u8 ch = static_cast<u8>(line[i]);
                if (std::isdigit(ch)) {
                    num = num * 10 + (ch - '0');
                }
                else if (num > 0) {
                    break;
                }
            }
            return num;
        };

        while (std::getline(status_file, line)) {
            int pid = parse_number("Pid:");
            if (pid == 1) {
                pid_match = true;
            }

            int ppid = parse_number("PPid:");
            if (ppid == 0) {
                ppid_match = true;
            }

            if (pid_match && ppid_match) {
                return core::add(brands::NSJAIL);
            }
        }

        return false;
    }


    /**
     * @brief Check for device's temperature
     * @category Linux
     * @implements VM::TEMPERATURE
     */
    [[nodiscard]] static bool temperature() {
        if (util::exists("/sys/class/thermal/cooling_device0")) return false;
        return (!util::exists("/sys/class/thermal/thermal_zone0/"));
    }


    /**
     * @brief Check for any VM processes that are active
     * @category Linux
     * @implements VM::PROCESSES
     */
    [[nodiscard]] static bool processes() {
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

        return false;
    }
#endif

#if (LINUX || WINDOWS)
    /**
     * @brief Check for Task Segment and Descriptor Table instructions (SGDT, SLDT, SMSW, SIDT)
     * @category Windows, Linux, x86, x86_32
     * @implements VM::DESCRIPTOR_TABLES
     * 
     * --- SGDT ---
     * @note code documentation paper in /papers/www.offensivecomputing.net_vm.pdf (top-most byte signature)
     *
     * --- SLDT ---
     * @author Danny Quist (chamuco@gmail.com), ldtr_buf signature
     * @author Val Smith (mvalsmith@metasploit.com), ldtr_buf signature
     * @author code documentation paper in /papers/www.offensivecomputing.net_vm.pdf for ldtr_buf signature and in https://www.aldeid.com/wiki/X86-assembly/Instructions/sldt for ldt signature
     *
     * --- SMSW ---
     * @author Danny Quist from Offensive Computing
     *
     * --- SIDT ---
     * @author Matteo Malvica
     * @author Idea to check VPC's range from Tom Liston and Ed Skoudis' paper "On the Cutting Edge: Thwarting Virtual Machine Detection" (Windows)
     * @link https://www.matteomalvica.com/blog/2018/12/05/detecting-vmware-on-64-bit-systems/ (Linux)
     * 
     */
    [[nodiscard]] static bool system_registers() {
        // Even though SMSW queries a status register (CR0), it is historically grouped with descriptor table checks in virtualization detection 
        // (often called "Red Pill" techniques)
        bool found = false;

        // Linux Implementation (SIDT only)
    #if (LINUX && (GCC || CLANG) && x86)
        u8 values[10] = { 0 };

        fflush(stdout);

        #if (x86_64)
            // 64-bit Linux: IDT descriptor is 10 bytes (2-byte limit + 8-byte base)
            __asm__ __volatile__("sidt %0" : "=m"(values));

        #ifdef __VMAWARE_DEBUG__
            debug("SIDT: values = ");
            for (u8 i = 0; i < 10; ++i) {
                debug(std::hex, std::setw(2), std::setfill('0'), static_cast<u32>(values[i]));
                if (i < 9) debug(" ");
            }
        #endif

            if (values[9] == 0x00) found = true; // 10th byte in x64 mode
        #elif (x86_32)
            // 32-bit Linux: IDT descriptor is 6 bytes (2-byte limit + 4-byte base)
            __asm__ __volatile__("sidt %0" : "=m"(values));

        #ifdef __VMAWARE_DEBUG__
            debug("SIDT: values = ");
            for (u8 i = 0; i < 6; ++i) {
                debug(std::hex, std::setw(2), std::setfill('0'), static_cast<u32>(values[i]));
                if (i < 5) debug(" ");
            }
        #endif

            if (values[5] == 0x00) found = true; // 6th byte in x86 mode
        #endif

        // Windows Implementation (SGDT, SLDT, SIDT, SMSW)
    #elif (WINDOWS && x86)
        SYSTEM_INFO si;
        GetNativeSystemInfo(&si);
        DWORD_PTR original_mask = 0;
        const HANDLE current_thread = reinterpret_cast<HANDLE>(-2LL);

        // Iterating processors for SGDT, SLDT, and SIDT
        for (DWORD i = 0; i < si.dwNumberOfProcessors; ++i) {
            const DWORD_PTR mask = (DWORD_PTR)1 << i;
            const DWORD_PTR previous_mask = SetThreadAffinityMask(current_thread, mask);

            if (previous_mask == 0) {
                continue;
            }

            if (original_mask == 0) {
                original_mask = previous_mask;
            }

            // Technique 1: SGDT (x86 & x64)
            {
            #if (x86_64)
                u8 gdtr[10] = { 0 };
            #else
                u8 gdtr[6] = { 0 };
            #endif

                __try {
                #if (CLANG || GCC)
                    __asm__ volatile("sgdt %0" : "=m"(gdtr));
                #elif (MSVC && x86_32)
                    __asm { sgdt gdtr }
                #else
                    #pragma pack(push,1)
                    struct {
                        u16 limit;
                        u64 base;
                    } _gdtr = {};
                    #pragma pack(pop)
                    _sgdt(&_gdtr);
                    memcpy(gdtr, &_gdtr, sizeof(_gdtr));
                #endif
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {} // CR4.UMIP

                ULONG_PTR gdt_base = 0;
                memcpy(&gdt_base, &gdtr[2], sizeof(gdt_base));

                if ((gdt_base >> 24) == 0xFF) {
                    debug("SGDT: 0xFF signature detected on core %u", i);
                    found = true;
                }
            }

            // Technique 2: SLDT (x86_32 only)
            #if (x86_32)
                if (!found) {
                    u8 ldtr_buf[4] = { 0xEF, 0xBE, 0xAD, 0xDE };
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
                }
            #endif

                // Technique 3: SIDT (x86 & x64)
                if (!found) {
                #if (x86_64)
                    u8 idtr_buffer[10] = { 0 };
                #else
                    u8 idtr_buffer[6] = { 0 };
                #endif

                    __try {
                    #if (CLANG || GCC)
                        __asm__ volatile("sidt %0" : "=m"(idtr_buffer));
                    #elif (MSVC) && (x86_32)
                        __asm { sidt idtr_buffer }
                    #elif (MSVC) && (x86_64)
                        #pragma pack(push, 1)
                        struct {
                            USHORT Limit;
                            ULONG_PTR Base;
                        } idtr;
                        #pragma pack(pop)
                        __sidt(&idtr);
                        memcpy(idtr_buffer, &idtr, sizeof(idtr));
                    #endif
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {} // CR4.UMIP

                    ULONG_PTR idt_base = 0;
                    memcpy(&idt_base, &idtr_buffer[2], sizeof(idt_base));

                    // Check for the 0xE8 signature (VPC/Hyper-V) in the high byte
                    if ((idt_base >> 24) == 0xE8) {
                        debug("SIDT: VPC/Hyper-V signature detected on core %u", i);
                        found = true;
                    }
                }

            if (found) break;
        }

        if (original_mask != 0) {
            SetThreadAffinityMask(current_thread, original_mask);
        }

        // Technique 4: SMSW (x86_32 only), no affinity pinning needed
        #if (x86_32)
            if (!found) {
                u32 reax = 0;
                __asm
                {
                    mov eax, 0xCCCCCCCC;
                    smsw eax;
                    mov DWORD PTR[reax], eax;
                }

                if ((((reax >> 24) & 0xFF) == 0xCC) && (((reax >> 16) & 0xFF) == 0xCC)) {
                    debug("SMSW: Signature detected");
                    found = true;
                }
            }
        #endif

    #endif

        return found;
    }


    /**
     * @brief Check for default Azure hostname format (Azure uses Hyper-V as their base VM brand)
     * @category Windows, Linux
     * @implements VM::AZURE
     */
    [[nodiscard]] static bool azure() {
        std::string hostname;

    #if (WINDOWS)
        char buf[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD len = sizeof(buf);

        if (GetComputerNameA(buf, &len)) {
            hostname.assign(buf, len);
        }
        else {
            return false;
        }
    #elif (LINUX)
        char buf[HOST_NAME_MAX];

        if (gethostname(buf, sizeof(buf)) == 0) {
            hostname = buf;
        }
        else {
            return false;
        }
    #endif

        const char* prefix = "runnervm";
        const std::size_t prefix_len = std::strlen(prefix);
        const std::size_t extra_chars = 5;
        const std::size_t expected_len = prefix_len + extra_chars;

        if (hostname.size() != expected_len) {
            return false;
        }

        if (hostname.compare(0, prefix_len, prefix) != 0) {
            return false;
        }

        for (std::size_t i = prefix_len; i < hostname.size(); ++i) {
            if (!std::isalnum(static_cast<unsigned char>(hostname[i]))) {
                return false;
            }
        }

        return core::add(brands::AZURE_HYPERV);
    }
    template <typename T, size_t N>
    constexpr bool check_no_nulls(const std::array<T, N>& arr, size_t i = 0) {
        return (i == N)
            ? true
            : (arr[i] != nullptr && check_no_nulls(arr, i + 1));
    }


    /**
     * @brief Check for VM signatures on all firmware tables
     * @category Windows, Linux
     * @authors Requiem, dmfrpro, MegaMax
     * @warning Permissions required
     * @implements VM::FIRMWARE
     */
    [[nodiscard]] static bool firmware() {
    #if (WINDOWS)
        struct acpi_header {
            char signature[4];
            u32 length;
            u8 revision;
        };

        struct fadt_table {
            u32 signature;
            u32 length;
            u8 revision;
            u8 checksum;
            char oem_id[6];
            char oem_table_id[8];
            u32 oem_revision;
            char asl_compiler_id[4];
            u32 asl_compiler_revision;

            u32 firmware_ctrl;
            u32 dsdt;
            u8 reserved1;
            u8 preferred_pm_profile;
            u16 sci_interrupt;
            u32 smi_command_port;
            u8 acpi_enable;
            u8 acpi_disable;
            u8 s4_bios_req;
            u8 reserved2;
            u32 pstate_control;
            u32 pm1a_event_block;
            u32 pm1b_event_block;
            u32 pm1a_control_block;
            u32 pm1b_control_block;
            u32 pm2_control_block;
            u32 pm_timer_block;
            u32 gpe0_block;
            u32 gpe1_block;
            u8 pm1_event_length;
            u8 pm1_control_length;
            u8 pm2_control_length;
            u8 pm_timer_length;

            u16 p_lvl2_lat;
            u16 p_lvl3_lat;
        };

        // "WAET" is also present as a string inside the WAET table, so there's no need to check for its table signature
        constexpr std::array<const char*, 22> targets = { {
            "Parallels Software", "Parallels(R)",
            "innotek",            "Oracle",   "VirtualBox", "vbox", "VBOX",
            "VMware, Inc.",       "VMware",   "VMWARE",     "VMW0003",
            "QEMU",               "pc-q35",   "Q35 +",      "FWCF",     "BOCHS",
            "ovmf",               "edk ii unknown", "WAET", "S3 Corp.", "VS2005R2",
            "Xen"
        } };

        constexpr std::array<const char*, 22> brands_map = { {
            brands::PARALLELS, brands::PARALLELS,
            brands::VBOX,      brands::VBOX,      brands::VBOX,     brands::VBOX,     brands::VBOX,
            brands::VMWARE,    brands::VMWARE,    brands::VMWARE,   brands::VMWARE,
            brands::QEMU,      brands::QEMU,      brands::QEMU,     brands::QEMU,     brands::BOCHS,
            nullptr, nullptr, nullptr, nullptr, nullptr,
            brands::XEN
        } };

        // inside struct to not have to move out of function, constexpr this way because of c++ 11 compatibility
        struct array_validator {
            static constexpr bool verify_no_nulls(const std::array<const char*, 22>& arr, size_t i) {
                return (i == arr.size())
                    ? true
                    : (arr[i] != nullptr && verify_no_nulls(arr, i + 1));
            }
        };

        // ensure sizes match
        static_assert(targets.size() == brands_map.size(),
            "FIRMWARE: 'targets' and 'brands_map' must have the same size.");

        // detects if you increased size but forgot strings
        static_assert(array_validator::verify_no_nulls(targets, 0),
            "FIRMWARE: 'targets' array contains NULLs. Array size declared is larger than the number of strings provided.");

        auto scan_buffer = [&](const u8* buffer, const size_t buffer_len) noexcept -> bool {
            // faster than std::search because of a manual byte-by-byte loop, could be optimized further with Boyer-Moore-Horspool for large tables like DSDT
            auto find_pattern = [&](const char* pattern, size_t pattern_len) noexcept -> bool {
                if (pattern_len == 0 || pattern_len > buffer_len) return false;
                const u8 first_byte = static_cast<u8>(pattern[0]);
                const u8* base_ptr = buffer;
                const u8* search_ptr = base_ptr;
                size_t remaining_bytes = buffer_len;

                while (remaining_bytes >= pattern_len) {
                    const void* match = memchr(search_ptr, first_byte, remaining_bytes);
                    if (!match) return false;
                    const u8* match_ptr = static_cast<const u8*>(match);
                    const size_t index = static_cast<size_t>(match_ptr - base_ptr);
                    // ensure pattern fits
                    if (index + pattern_len > buffer_len) return false;
                    if (memcmp(match_ptr, pattern, pattern_len) == 0) return true;
                    // advance one past this found first-byte and continue
                    search_ptr = match_ptr + 1;
                    remaining_bytes = buffer_len - static_cast<size_t>(search_ptr - base_ptr);
                }
                return false;
            };

            // 1) VM-specific firmware signatures. It is important that vm-specific checks run first because of the hardened detection logic
            for (size_t i = 0; i < targets.size(); ++i) {
                const char* pattern = targets[i];
                const size_t pattern_len = strlen(pattern);
                if (pattern_len > buffer_len) continue;

                if (find_pattern(pattern, pattern_len)) {
                    // special handling for Xen: must not have PXEN to prevent false flagging some baremetal systems
                    if (strcmp(pattern, "Xen") == 0) {
                        constexpr char pxen[] = "PXEN";
                        constexpr size_t pxen_len = sizeof(pxen) - 1;
                        const bool has_pxen = find_pattern(pxen, pxen_len);
                        if (!has_pxen)
                            return core::add(brands::XEN);
                        else
                            continue;
                    }

                    // special handling for BOCHS: if BXPC is detected, check if "BOCHS" is present too
                    if (strcmp(pattern, "BXPC") == 0) {
                        constexpr char bochs[] = "BOCHS";
                        constexpr size_t bochs_len = sizeof(bochs) - 1;
                        const bool has_bochs = find_pattern(bochs, bochs_len);
                        if (!has_bochs)
                            return core::add(brands::BOCHS);
                        else
                            continue;
                    }

                    debug("FIRMWARE: Detected ", pattern);
                    const char* detected_brand = brands_map[i];
                    return (detected_brand ? core::add(detected_brand) : true);
                }
            }

            // 2) known patches used by popular hardeners 
            {
                constexpr char marker[] = "777777";

                if (buffer_len >= 36) {
                    // OEMID (6)
                    char oem_id[7] = { 0 };
                    memcpy(oem_id, buffer + 10, 6);
                    // OEM Table ID (8)
                    char oem_table_id[9] = { 0 };
                    memcpy(oem_table_id, buffer + 16, 8);

                    // Creator / ASL Compiler ID (4) won't contain 6-char marker because its length is 4
                    if (strstr(oem_id, marker) != nullptr) {
                        debug("FIRMWARE: VMWareHardenedLoader found in OEMID -> '", oem_id, "'");
                        return core::add(brands::VMWARE_HARD);
                    }
                    if (strstr(oem_table_id, marker) != nullptr) {
                        debug("FIRMWARE: VMWareHardenedLoader found in OEM Table ID -> '", oem_table_id, "'");
                        return core::add(brands::VMWARE_HARD);
                    }
                }
            }

            if (!buffer || buffer_len < sizeof(acpi_header)) {
                return false;
            }

            acpi_header header;
            memcpy(&header, buffer, sizeof(header));

            // 3) FADT specific checks
            if (memcmp(header.signature, "FACP", 4) == 0) {
                if (header.length > buffer_len) {
                    debug("FIRMWARE: declared header length larger than fetched length (declared ", header.length, ", fetched ", buffer_len, ")");
                    return true;
                }
                if (buffer_len < sizeof(fadt_table)) {
                    debug("FIRMWARE: FACP buffer too small (len ", buffer_len, ")");
                    return true;
                }

                fadt_table fadt;
                memcpy(&fadt, buffer, sizeof(fadt_table));

                if (fadt.p_lvl2_lat == 0x0FFF || fadt.p_lvl3_lat == 0x0FFF) { // A value > 100 indicates the system does not support a C2/C3 state
                    debug("FIRMWARE: C2 and C3 latencies indicate VM");
                    return true;
                }

                if (buffer_len >= 276) {
                    u64 hypervisor_vid = 0;
                    memcpy(&hypervisor_vid, buffer + 268, 8);

                    if (hypervisor_vid != 0) {
                        debug("FIRMWARE: FACP 'Hypervisor Vendor Identity' field is occupied");
                        return true;
                    }
                }
            }

            return false;
        };

        // to minimize heap allocations
        std::vector<u8> work_buffer;
        work_buffer.reserve(65536);

        // Enumerate ACPI tables
        constexpr DWORD acpi_signature = 'ACPI';
        const DWORD acpi_enum_size = EnumSystemFirmwareTables(acpi_signature, nullptr, 0);
        if (acpi_enum_size == 0) 
            return false;
        if (acpi_enum_size % sizeof(DWORD) != 0) 
            return false;
       
        const size_t table_count = acpi_enum_size / sizeof(DWORD);
        std::vector<DWORD> tables(table_count);
        if (EnumSystemFirmwareTables(acpi_signature, tables.data(), acpi_enum_size) != acpi_enum_size)
            return false;

        // DSDT special fetch
        {
            constexpr DWORD dsdt_sig = 'DSDT';
            constexpr DWORD dsdt_swapped =
                ((dsdt_sig >> 24) & 0x000000FFu)
                | ((dsdt_sig >> 8) & 0x0000FF00u)
                | ((dsdt_sig << 8) & 0x00FF0000u)
                | ((dsdt_sig << 24) & 0xFF000000u);

            const UINT sz = GetSystemFirmwareTable(acpi_signature, dsdt_swapped, nullptr, 0);
            if (sz > 0) {
                if (sz > work_buffer.capacity()) work_buffer.reserve(sz);
                work_buffer.resize(sz);
                if (GetSystemFirmwareTable(acpi_signature, dsdt_swapped, work_buffer.data(), sz) == sz) {
                    if (scan_buffer(work_buffer.data(), work_buffer.size())) {
                        return true;
                    }
                }
            }
        }

        // helper to fetch one table into a malloc'd buffer
        auto fetch_and_scan = [&](DWORD provider, DWORD table_id) noexcept -> bool {
            const DWORD sz = GetSystemFirmwareTable(provider, table_id, nullptr, 0);
            if (sz == 0) return false;

            if (sz > work_buffer.capacity()) work_buffer.reserve(sz);
            work_buffer.resize(sz);

            if (GetSystemFirmwareTable(provider, table_id, work_buffer.data(), sz) != sz) {
                return false;
            }

            return scan_buffer(work_buffer.data(), sz);
        };

        // Scan every ACPI table, dont make explicit whitelisting/blacklisting because of possible bypasses
        for (const auto table_id : tables) {
            if (fetch_and_scan(acpi_signature, table_id)) {
                return true;
            }
        }

        // Scan SMBIOS (RSMB) / FIRM tables
        constexpr DWORD smb_providers[] = { 'FIRM', 'RSMB' };

        for (DWORD prov : smb_providers) {
            const UINT e = EnumSystemFirmwareTables(prov, nullptr, 0);
            if (!e) continue;

            // even if alignment is supported on x86 its good to check if size is a multiple of DWORD
            if (e % sizeof(DWORD) != 0) continue;

            const size_t cnt = e / sizeof(DWORD);
            std::vector<DWORD> provider_tables(cnt);

            if (EnumSystemFirmwareTables(prov, provider_tables.data(), e) != e) continue;

            for (const auto table_id : provider_tables) {
                if (fetch_and_scan(prov, table_id)) {
                    return true;
                }
            }
        }

        return false;
    #elif (LINUX)
        // Author: dmfrpro
        DIR* raw_dir = opendir("/sys/firmware/acpi/tables/");
        if (!raw_dir) {
            debug("FIRMWARE: could not open ACPI tables directory");
            return false;
        }

        struct dir_closer {
            DIR* d;
            explicit dir_closer(DIR* dir) : d(dir) {}
            ~dir_closer() { if (d) closedir(d); }
        } dir(raw_dir);

        constexpr const char* targets[] = {
            "Parallels Software", "Parallels(R)",
            "innotek",            "Oracle",   "VirtualBox", "vbox", "VBOX",
            "VMware, Inc.",       "VMware",   "VMWARE",     "VMW0003",
            "QEMU",               "pc-q35",   "Q35 +",      "FWCF",     "BOCHS",
            "ovmf",               "edk ii unknown", "S3 Corp.", "Virtual Machine", "VS2005R2",
            "Xen"
        };

        struct dirent* entry;
        constexpr long MAX_TABLE_SIZE = 8 * 1024 * 1024;

        while ((entry = readdir(raw_dir)) != nullptr) {
            // Skip "." and ".."
            if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0)
                continue;

            char path[PATH_MAX];
            snprintf(path, sizeof(path),
                "/sys/firmware/acpi/tables/%s",
                entry->d_name);

            int fd = open(path, O_RDONLY);
            if (fd == -1) {
                debug("FIRMWARE: could not open ACPI table ", entry->d_name);
                continue;
            }

            struct fd_closer {
                int fd;
                explicit fd_closer(int f) : fd(f) {}
                ~fd_closer() { if (fd != -1) close(fd); }
            } fdguard(fd);

            struct stat statbuf;
            if (fstat(fd, &statbuf) != 0 || S_ISDIR(statbuf.st_mode)) {
                debug("FIRMWARE: skipped ", entry->d_name);
                continue;
            }
            long file_size = statbuf.st_size;
            if (file_size <= 0) {
                debug("FIRMWARE: file empty or error ", entry->d_name);
                continue;
            }

            if (file_size > MAX_TABLE_SIZE) {
                debug("FIRMWARE: table too large, skipping ", entry->d_name);
                continue;
            }

            const size_t file_size_u = static_cast<size_t>(file_size);

            std::vector<u8> buffer;
            try {
                buffer.resize(file_size_u);
            }
            catch (...) {
                debug("FIRMWARE: failed to allocate memory for buffer");
                continue;
            }

            size_t total = 0;
            while (total < file_size_u) {
                ssize_t n = read(fdguard.fd, buffer.data() + total, file_size_u - total);
                if (n <= 0) break; // error or EOF
                total += static_cast<size_t>(n);
            }
            if (total != file_size_u) {
                debug("FIRMWARE: could not read full table ", entry->d_name);
                continue;
            }

            for (const char* target : targets) {
                size_t target_length = strlen(target);
                if (target_length > file_size_u)
                    continue;
                for (size_t j = 0; j <= file_size_u - target_length; ++j) {
                    if (memcmp(buffer.data() + j, target, target_length) == 0) {
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
                        else if (strcmp(target, "QEMU") == 0) {
                            brand = brands::QEMU;
                        }
                        else if (strcmp(target, "BOCHS") == 0 ||
                            strcmp(target, "BXPC") == 0) {
                            brand = brands::BOCHS;
                        }

                        if (brand)
                            return core::add(brand);
                        else
                            return true;
                    }
                }
            }
        }

        return false;
    #endif
    }


    /**
     * @brief Check for PCI vendor and device IDs that are VM-specific
     * @link https://www.pcilookup.com/?ven=&dev=&action=submit
     * @category Linux, Windows
     * @implements VM::PCI_DEVICES
     */
    [[nodiscard]] static bool pci_devices() {
        struct pci_device { u16 vendor_id; u32 device_id; };
        std::vector<pci_device> devices;

        #if (LINUX)
         const std::string pci_path = "/sys/bus/pci/devices";
         #if (VMA_CPP >= 17)
            // std::filesystem throws exceptions when directories don't exist (SIGSEGV)
            std::error_code ec;
            auto dir_iter = std::filesystem::directory_iterator(pci_path, ec);

            if (!ec) {
                for (const auto& entry : dir_iter) {
                    std::ifstream vf(entry.path() / "vendor"), df(entry.path() / "device");
                    if (!vf || !df) continue;
                    u16 vid = 0; u32 did = 0;
                    vf >> std::hex >> vid;
                    df >> std::hex >> did;
                    devices.push_back({ vid, did });
                }
            }
         #else
            DIR* dir = opendir(pci_path.c_str());
            if (dir) {
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
            }
        #endif
        #elif (WINDOWS)
        static constexpr const wchar_t* kroots[] = {
            L"SYSTEM\\CurrentControlSet\\Enum\\PCI",
            L"SYSTEM\\CurrentControlSet\\Enum\\USB",
            L"SYSTEM\\CurrentControlSet\\Enum\\HDAUDIO"
        };

        enum root_type { RT_PCI, RT_USB, RT_HDAUDIO };
        constexpr DWORD MAX_MULTI_SZ = 64 * 1024;

        auto hex_val = [](wchar_t c) noexcept -> int {
            if (c >= L'0' && c <= L'9') return c - L'0';

            const wchar_t lower = static_cast<wchar_t>((static_cast<int>(c) | 0x20));
            if (lower >= L'a' && lower <= L'f') return lower - L'a' + 10;

            return -1;
        };

        auto parse_hex = [&](const wchar_t* ptr, size_t maxDigits, size_t stopLen, unsigned long& out, size_t& consumed) noexcept -> bool {
            out = 0;
            consumed = 0;

            const size_t limit = (stopLen < maxDigits) ? stopLen : maxDigits;

            for (; consumed < limit; ++consumed) {
                const int v = hex_val(ptr[consumed]);
                if (v < 0) break;

                // caller must ensure maxDigits doesn't exceed 8, because on Windows unsigned long is 32-bit
                out = (out << 4) | static_cast<unsigned long>(v);
            }

            return consumed > 0;
        };

        std::unordered_set<unsigned long long> seen;

        auto add_device = [&](u16 vid, u32 did) noexcept {
            const unsigned long long key = (static_cast<unsigned long long>(vid) << 32) | static_cast<unsigned long long>(did);
            if (seen.insert(key).second) {
                devices.push_back({ vid, did });
            }
        };

        auto scan_text_ids = [&](const wchar_t* text) noexcept {
            if (!text) return;

            // USB: VID_ and then PID_
            const wchar_t* p = text;
            while ((p = wcsstr(p, L"VID_"))) {
                const wchar_t* v = p;
                p += 4;
                const wchar_t* d = wcsstr(v + 4, L"PID_");
                if (d && (d - v) < 64) {
                    unsigned long parsed_v = 0, parsed_d = 0;
                    size_t c_v = 0, c_d = 0;
                    if (parse_hex(v + 4, 4, SIZE_MAX, parsed_v, c_v) &&
                        parse_hex(d + 4, 8, SIZE_MAX, parsed_d, c_d)) {
                        add_device(static_cast<u16>(parsed_v & 0xFFFFu), static_cast<u32>(parsed_d));
                    }
                }
            }

            // PCI or HDAUDIO = VEN_ and then DEV_ after it
            p = text;
            while ((p = wcsstr(p, L"VEN_"))) {
                const wchar_t* v = p;
                p += 4;
                const wchar_t* d = wcsstr(v + 4, L"DEV_");
                if (d && (d - v) < 64) {
                    unsigned long parsed_v = 0;
                    size_t c_v = 0;
                    if (parse_hex(v + 4, 4, SIZE_MAX, parsed_v, c_v)) {
                        const wchar_t* dev_start = const_cast<wchar_t*>(d + 4);
                        const wchar_t* amp_after_dev = wcschr(dev_start, L'&');
                        const size_t dev_len = amp_after_dev ? static_cast<size_t>(amp_after_dev - dev_start) : wcslen(dev_start);

                        // for HDAUDIO expect 4 digits and for PCI allow up to 8
                        if (dev_len > 0 && dev_len <= 8) {
                            unsigned long parsed_d = 0;
                            size_t c_d = 0;
                            // parse exactly devLen digits (fail if any char is non-hex)
                            if (parse_hex(dev_start, 8, dev_len, parsed_d, c_d) && c_d == dev_len) {
                                add_device(static_cast<u16>(parsed_v & 0xFFFFu), static_cast<u32>(parsed_d));
                            }
                        }
                    }
                }
            }
        };

        // process the hardware ID on an instance key
        auto process_hardware_id_reg = [&](HKEY h_inst) noexcept {
            // most HardwareIDs fit within 512 bytes
            static thread_local std::vector<wchar_t> buf;
            if (buf.empty()) buf.resize(512);

            DWORD type = 0;
            DWORD cb_data = static_cast<DWORD>(buf.size() * sizeof(wchar_t));

            LONG rv = RegGetValueW(
                h_inst,
                nullptr,
                L"HardwareID",
                RRF_RT_REG_MULTI_SZ,
                &type,
                buf.data(),
                &cb_data
            );

            if (rv == ERROR_MORE_DATA) {
                if (cb_data > MAX_MULTI_SZ) {
                    return;
                }

                // allocate a buffer large enough to hold the entire MULTI_SZ
                // (+1 for safety null terminator logic below)
                buf.resize((cb_data / sizeof(wchar_t)) + 2);

                rv = RegGetValueW(
                    h_inst,
                    nullptr,
                    L"HardwareID",
                    RRF_RT_REG_MULTI_SZ,
                    &type,
                    buf.data(),
                    &cb_data
                );
            }

            if (rv != ERROR_SUCCESS || type != REG_MULTI_SZ || cb_data <= sizeof(wchar_t)) {
                return;
            }

            // guarantee terminating NUL
            // RegGetValueW with RRF_RT_REG_MULTI_SZ usually handles this but for safety
            const size_t wchar_count = cb_data / sizeof(wchar_t);
            if (wchar_count < buf.size()) buf[wchar_count] = L'\0';
            else buf.back() = L'\0';

            for (wchar_t* p = buf.data(); *p; p += wcslen(p) + 1) {
                scan_text_ids(p);
            }
        };

        // all instance subkeys under a given device key
        auto enum_instances = [&](HKEY h_dev) noexcept {
            wchar_t inst_name[256];

            for (DWORD j = 0;; ++j) {
                // reset size for each iteration as RegEnumKeyExW modifies it
                DWORD cb_inst = _countof(inst_name);

                const LONG st2 = RegEnumKeyExW(
                    h_dev,
                    j,
                    inst_name,
                    &cb_inst,
                    nullptr,
                    nullptr,
                    nullptr,
                    nullptr
                );
                if (st2 == ERROR_NO_MORE_ITEMS) break;
                if (st2 != ERROR_SUCCESS) continue;

                HKEY h_inst = nullptr;
                if (RegOpenKeyExW(h_dev, inst_name, 0, KEY_READ, &h_inst) != ERROR_SUCCESS) continue;

                process_hardware_id_reg(h_inst);
                RegCloseKey(h_inst);
            }
        };

        // all device subkeys under a given root key
        auto enum_devices = [&](HKEY h_root) noexcept {
            wchar_t device_name[256];

            for (DWORD i = 0;; ++i) {
                DWORD cb_name = _countof(device_name);

                const LONG status = RegEnumKeyExW(
                    h_root,
                    i,
                    device_name,
                    &cb_name,
                    nullptr,
                    nullptr,
                    nullptr,
                    nullptr
                );
                if (status == ERROR_NO_MORE_ITEMS) break;
                if (status != ERROR_SUCCESS) continue;

                HKEY h_dev = nullptr;
                if (RegOpenKeyExW(h_root, device_name, 0, KEY_READ, &h_dev) != ERROR_SUCCESS) continue;

                enum_instances(h_dev);
                RegCloseKey(h_dev);
            }
        };

        // for each rootPath we open the root key once
        for (size_t root_idx = 0; root_idx < _countof(kroots); ++root_idx) {
            const wchar_t* root_path = kroots[root_idx];
            HKEY root = nullptr;
            if (RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                root_path,
                0,
                KEY_READ,
                &root
            ) != ERROR_SUCCESS) {
                continue;
            }

            enum_devices(root);
            RegCloseKey(root);
        }
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
                    debug("PCI_DEVICES: Detected Red Hat + Virtio device -> ", std::hex, id32);
                    return true;

                // VMware
                case 0x15ad0710: case 0x15ad0720: case 0x15ad0770: case 0x15ad0774: 
                case 0x15ad0778: case 0x15ad0779: case 0x15ad0790: case 0x15ad07a0: 
                case 0x15ad07b0: case 0x15ad07c0: case 0x15ad07e0: case 0x15ad07f0: 
                case 0x15ad0801: case 0x15ad0820: case 0x15ad1977: case 0xfffe0710: 
                case 0x0e0f0001: case 0x0e0f0002: case 0x0e0f0003: case 0x0e0f0004: 
                case 0x0e0f0005: case 0x0e0f0006: case 0x0e0f000a: case 0x0e0f8001: 
                case 0x0e0f8002: case 0x0e0f8003: case 0x0e0ff80a:
                    debug("PCI_DEVICES: Detected VMWARE device -> ", std::hex, id32);
                    return core::add(brands::VMWARE);

                // Red Hat + QEMU
                case 0x1b360001: case 0x1b360002: case 0x1b360003: case 0x1b360004:
                case 0x1b360005: case 0x1b360008: case 0x1b360009: case 0x1b36000b:
                case 0x1b36000c: case 0x1b36000d: case 0x1b360010: case 0x1b360011:
                case 0x1b360013: case 0x1b360100:
                    debug("PCI_DEVICES: Detected Red Hat + QEMU device -> ", std::hex, id32);
                    return core::add(brands::QEMU);

                // QEMU
                case 0x06270001: case 0x1d1d1f1f: case 0x80865845: case 0x1d6b0200:
                    debug("PCI_DEVICES: Detected QEMU device -> ", std::hex, id32);
                    return core::add(brands::QEMU);

                // vGPUs (NVIDIA + others)
                case 0x10de0fe7: case 0x10de0ff7: case 0x10de118d: case 0x10de11b0:
                case 0x1ec6020f:
                    debug("PCI_DEVICES: Detected virtual gpu device -> ", std::hex, id32);
                    return true;

                // VirtualBox
                case 0x80ee0021: case 0x80ee0022: case 0x80eebeef: case 0x80eecafe:
                    debug("PCI_DEVICES: Detected VirtualBox device -> ", std::hex, id32);
                    return core::add(brands::VBOX);

                // Parallels
                case 0x1ab84000: case 0x1ab84005: case 0x1ab84006:
                    debug("PCI_DEVICES: Detected Parallels device -> ", std::hex, id32);
                    return core::add(brands::PARALLELS);

                // Xen
                case 0x5853c000: case 0xfffd0101: case 0x5853c147:
                case 0x5853c110: case 0x5853c200: case 0x58530001:
                    debug("PCI_DEVICES: Detected Xen device -> ", std::hex, id32);
                    return core::add(brands::XEN);

                // Connectix (VirtualPC)
                case 0x29556e61:
                    debug("PCI_DEVICES: Detected VirtualPC device -> ", std::hex, id32);
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
                    debug("PCI_DEVICES: Detected QEMU device -> ", std::hex, id64);
                    return core::add(brands::QEMU);
    
                case 0x0000000015ad0800ULL:  // Hypervisor ROM Interface
                    debug("PCI_DEVICES: Detected Hypervisor ROM interface -> ", std::hex, id64);
                    return core::add(brands::VMWARE);
            }
        }
        
        return false;
    }
#endif

#if (LINUX || APPLE)
    /**
     * @brief Check if there are only 1 or 2 threads, which is a common pattern in VMs with default settings, nowadays physical CPUs should have at least 4 threads for modern CPUs
     * @category x86 (ARM might have very low thread counts, which is why it should be only for x86)
     * @implements VM::THREAD_COUNT
     */
    [[nodiscard]] static bool thread_count() {
    #if (x86 && !APPLE)
        debug("THREADCOUNT: ", "threads = ", memo::threadcount::fetch());

        struct cpu::stepping_struct steps = cpu::fetch_steppings();

        if (cpu::is_celeron(steps)) {
            return false;
        }

        return (memo::threadcount::fetch() <= 2);
    #else 
        return false;
    #endif
    }
#endif

#if (APPLE) 
    /**
     * @brief Check if the sysctl for the hwmodel does not contain the "Mac" string
     * @author MacRansom ransomware
     * @category MacOS
     * @implements VM::HWMODEL
     */
    [[nodiscard]] static bool hwmodel() {
        
        //hw.model strings are short (like for example MacBookPro16,1), 128 bytes is plenty
        char buffer[128] = { 0 };
        size_t size = sizeof(buffer);

        // sysctlbyname queries the kernel directly, bypassing the overhead of 
        // fork(), exec(), and pipe() found in util::sys_result (popen)
        if (sysctlbyname("hw.model", buffer, &size, nullptr, 0) != 0) {
            debug("HWMODEL: ", "failed to read hw.model");
            return false;
        }

        // sysctlbyname returns the raw value (usually without a trailing newline),
        // so no trimming is required
        debug("HWMODEL: ", "output = ", buffer);

        if (strstr(buffer, "Mac") != nullptr) {
            return false;
        }

        if (strstr(buffer, "VMware") != nullptr) {
            return core::add(brands::VMWARE);
        }

        // assumed true since it doesn't contain "Mac" string
        return true;
    }


    /**
     * @brief Check if memory is too low for MacOS system
     * @category MacOS
     * @link https://evasions.checkpoint.com/src/MacOS/macos.html
     * @implements VM::MAC_MEMSIZE
     */
    [[nodiscard]] static bool hw_memsize() {
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
    }


    /**
     * @brief Check MacOS' IO kit registry for VM-specific strings
     * @category MacOS
     * @link https://evasions.checkpoint.com/src/MacOS/macos.html
     * @implements VM::MAC_IOKIT
     */
    [[nodiscard]] static bool io_kit() {
        // board_ptr and manufacturer_ptr empty
        std::unique_ptr<std::string> platform_ptr = util::sys_result("ioreg -rd1 -c IOPlatformExpertDevice");
        std::unique_ptr<std::string> board_ptr = util::sys_result("ioreg -rd1 -c board-id");
        std::unique_ptr<std::string> manufacturer_ptr = util::sys_result("ioreg -rd1 -c manufacturer");
        std::unique_ptr<std::string> keyboard_ptr = util::sys_result("ioreg -lw0 -p IODeviceTree");

        const std::string platform = *platform_ptr;
        const std::string board = *board_ptr;
        const std::string manufacturer = *manufacturer_ptr;
        const std::string keyboard = *keyboard_ptr;

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

        auto check_keyboard = [&]() -> bool {
            debug("IO_KIT: ", "keyboard = ", keyboard);

            if (keyboard.empty()) {
                return false;
            }

            if (util::find(keyboard, "Virtual Machine")) {
                return true;
            }

            return false;
        };

        return (
            check_platform() ||
            check_board() ||
            check_manufacturer() ||
            check_keyboard()
       );
    }


    /**
     * @brief Check for VM-strings in ioreg commands for MacOS
     * @category MacOS
     * @link https://evasions.checkpoint.com/src/MacOS/macos.html
     * @implements VM::IOREG_GREP
     */
    [[nodiscard]] static bool ioreg_grep() {
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
    }


    /**
     * @brief Check for the status of System Integrity Protection and hv_mm_present
     * @category MacOS
     * @link https://evasions.checkpoint.com/src/MacOS/macos.html
     * @implements VM::MAC_SIP
     */
    [[nodiscard]] static bool mac_sip() {
        int hv_present = 0;
        std::size_t size = sizeof(hv_present);
        if (sysctlbyname("kern.hv_vmm_present",
            &hv_present,
            &size,
            nullptr,
            0) != 0) {
            return false;
        }

        if (hv_present != 0) {
            return true;
        }

        std::unique_ptr<std::string> result = util::sys_result("csrutil status");

        if (!result) {
            return false;
        }

        std::string tmp = *result;

        auto pos = tmp.find('\n');

        if (pos != std::string::npos) {
            tmp.resize(pos);
        }

        debug("MAC_SIP: ", "result = ", tmp);

        if (util::find(tmp, "unknown")) {
            return false;
        }

        return (util::find(tmp, "disabled"));
    }


    /**
     * @brief Check for VM-strings in system profiler commands for MacOS
     * @category MacOS
     * @implements VM::MAC_SYS
     */
    [[nodiscard]] static bool mac_sys() {
        const char* keyword = "virtual machine";

        if (std::unique_ptr<std::string> profiler_res_ptr = util::sys_result("system_profiler SPHardwareDataType")) {
            std::string& output = *profiler_res_ptr;

            std::transform(output.begin(), output.end(), output.begin(),
                [](u8 c) { return std::tolower(c); });

            if (util::find(output, keyword)) {
                return true;
            }
        }

        return false;
    }
#endif


#if (WINDOWS)
    /**
     * @brief Check for VM-specific DLLs
     * @category Windows
     * @implements VM::DLL
     */
    [[nodiscard]] static bool dll() {
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

        for (const auto& x : dlls) {
            if (GetModuleHandleA(x.dll_name) != nullptr) {
                debug("DLL: Found ", x.dll_name, " (", x.brand, ")");
                return core::add(x.brand);
            }
        }

        return false;
    }

             
    /**
     * @brief Check if the function "wine_get_unix_file_name" is present and if the OS booted from a VHD container
     * @category Windows
     * @implements VM::WINE
     */
    [[nodiscard]] static bool wine() {
        #if (_WIN32_WINNT < _WIN32_WINNT_WIN8)
            return false;
        #else
            __try {
                BOOL isNativeVhdBoot = 0;
                // we dont call NtQuerySystemInformation with SystemPrefetchPathInformation | SystemHandleInformation
                // the point is to check if this kernel32.dll function throws an exception
                IsNativeVhdBoot(&isNativeVhdBoot);
                VMAWARE_UNUSED(isNativeVhdBoot);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                debug("WINE: SEH invoked");
                return true;
            }
        #endif

        const HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
        const HMODULE ntdll = util::get_ntdll();
        if (!kernel32 || !ntdll) {
            return false;
        }

        const char* kernel32_names[] = { "wine_get_unix_file_name" };
        void* kernel32_functions[ARRAYSIZE(kernel32_names)] = {};
        util::get_function_address(kernel32, kernel32_names, kernel32_functions, _countof(kernel32_names));

        if (kernel32_functions[0] != nullptr) {
            return core::add(brands::WINE);
        }

        const char* ntdll_names[] = { "NtAllocateVirtualMemory", "NtFreeVirtualMemory", "NtProtectVirtualMemory" };
        void* ntdll_functions[ARRAYSIZE(ntdll_names)] = {};
        util::get_function_address(ntdll, ntdll_names, ntdll_functions, _countof(ntdll_names));

        // https://www.unknowncheats.me/forum/anti-cheat-bypass/729130-article-wine-detection.html
        const UINT old_mode = SetErrorMode(SEM_NOALIGNMENTFAULTEXCEPT);

        static constexpr unsigned char movaps_stub[] = {
            0x0F, 0x28, 0x01, // movaps xmm0, XMMWORD PTR [rcx]   (Windows x64: arg in RCX)
            0xC3              // ret
        };

        typedef void (*movaps_fn)(void*);

        using NtAllocateVirtualMemoryFn = NTSTATUS(__stdcall*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
        using NtFreeVirtualMemoryFn = NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG);
        using NtProtectVirtualMemoryFn = NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

        const auto nt_allocate_virtual_memory = reinterpret_cast<NtAllocateVirtualMemoryFn>(ntdll_functions[0]);
        const auto nt_free_virtual_memory = reinterpret_cast<NtFreeVirtualMemoryFn>(ntdll_functions[1]);
        const auto nt_protect_virtual_memory = reinterpret_cast<NtProtectVirtualMemoryFn>(ntdll_functions[2]);

        if (nt_allocate_virtual_memory == nullptr || nt_free_virtual_memory == nullptr || nt_protect_virtual_memory == nullptr) {
            SetErrorMode(old_mode);
            return false;
        }

        PVOID exec_mem = NULL;
        const HANDLE current_process = reinterpret_cast<HANDLE>(-1);
        SIZE_T region_size = sizeof movaps_stub;
        NTSTATUS st = nt_allocate_virtual_memory(current_process, &exec_mem, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(st) || exec_mem == NULL) {
            SetErrorMode(old_mode);
            return false;
        }

        memcpy(exec_mem, movaps_stub, sizeof movaps_stub);
     
        PVOID tmp_base = exec_mem;
        SIZE_T tmp_sz = region_size;
        ULONG old_protection = 0;
        st = nt_protect_virtual_memory(current_process, &tmp_base, &tmp_sz, PAGE_EXECUTE_READ, &old_protection);
        if (!NT_SUCCESS(st)) {
            PVOID free_base = exec_mem;
            SIZE_T free_size = 0;
            nt_free_virtual_memory(current_process, &free_base, &free_size, MEM_RELEASE);
            SetErrorMode(old_mode);
            return false;
        }
        
        __declspec(align(16)) unsigned char buffer[32] = { 0 };
        void* misaligned = buffer + 1;

        __try {
            ((movaps_fn)exec_mem)(misaligned);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            PVOID free_base = exec_mem;
            SIZE_T free_size = 0;
            nt_free_virtual_memory(current_process, &free_base, &free_size, MEM_RELEASE);

            SetErrorMode(old_mode);
            return core::add(brands::WINE);
        }
      
        PVOID free_base = exec_mem;
        SIZE_T free_size = 0;
        nt_free_virtual_memory(current_process, &free_base, &free_size, MEM_RELEASE);

        SetErrorMode(old_mode);
        return false;
    }
                
                
    /**
     * @brief Check what power states are enabled
     * @category Windows
     * @implements VM::POWER_CAPABILITIES
     */
    [[nodiscard]] static bool power_capabilities() {
        const HMODULE ntdll = util::get_ntdll();

        const char* names[] = { "NtPowerInformation" }; // Win8
        void* funcs[ARRAYSIZE(names)] = {};
        util::get_function_address(ntdll, names, funcs, ARRAYSIZE(names));

        if (!funcs[0]) return false;

        using NtPI_t = NTSTATUS(__stdcall*)(POWER_INFORMATION_LEVEL,
            PVOID, ULONG,
            PVOID, ULONG);
        const auto nt_power_information = reinterpret_cast<NtPI_t>(funcs[0]);

        SYSTEM_POWER_CAPABILITIES caps = { 0 };
        const NTSTATUS status = nt_power_information(
            SystemPowerCapabilities,
            nullptr, 0,
            &caps, sizeof(caps)
        );
        if (status != 0) return false;

        const bool s0_supported = caps.AoAc;
        const bool s1_supported = caps.SystemS1;
        const bool s2_supported = caps.SystemS2;
        const bool s3_supported = caps.SystemS3;
        const bool s4_supported = caps.SystemS4;
        const bool hiber_file_present = caps.HiberFilePresent;

        const bool is_physical_pattern = (s0_supported || s3_supported) &&
            (s4_supported || hiber_file_present);

        if (is_physical_pattern) {
            return false;
        }

        const bool is_vm_pattern = !(s0_supported || s3_supported || s4_supported || hiber_file_present) &&
            (s1_supported || s2_supported);

        if (is_vm_pattern) {
            debug("POWER_CAPABILITIES: Detected !(S0||S3||S4||HiberFilePresent) + S1|S2 pattern");
            return true;
        }

        // could check for HKLM\\SYSTEM\\CurrentControlSet\\Control\\Power\\PlatformAoAcOverride
        const bool no_sleep_states = !s0_supported && !s1_supported && !s2_supported && !s3_supported;
        if (no_sleep_states) {
            debug("POWER_CAPABILITIES: Detected !(S0||S1||S2||S3) pattern"); // can sometimes false flag baremetal devices
            return true;
        }

        return (caps.ThermalControl == 0);
    }


    /**
     * @brief Check for Gamarue ransomware technique which compares VM-specific Window product IDs
     * @category Windows
     * @implements VM::GAMARUE
     */
    [[nodiscard]] static bool gamarue() {
        const HMODULE ntdll = util::get_ntdll();
        if (!ntdll) return false;

        const char* names[] = { "NtOpenKey", "NtQueryValueKey", "RtlInitUnicodeString", "NtClose" };
        void* funcs[ARRAYSIZE(names)] = {};
        util::get_function_address(ntdll, names, funcs, ARRAYSIZE(names));

        const auto nt_open_key = reinterpret_cast<NTSTATUS(__stdcall*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)>(funcs[0]);
        const auto nt_query_value_key = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, PUNICODE_STRING, ULONG, PVOID, ULONG, PULONG)>(funcs[1]);
        const auto rtl_init_unicode_string = reinterpret_cast<void(__stdcall*)(PUNICODE_STRING, PCWSTR)>(funcs[2]);
        const auto nt_close = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE)>(funcs[3]);

        if (!nt_open_key || !nt_query_value_key || !rtl_init_unicode_string || !nt_close) 
            return false;

        // We use native unicode strings and object attributes to interface directly with the kernel
        UNICODE_STRING key_name;
        rtl_init_unicode_string(&key_name, L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion");

        OBJECT_ATTRIBUTES object_attributes;
        ZeroMemory(&object_attributes, sizeof(object_attributes));
        object_attributes.Length = sizeof(object_attributes);
        object_attributes.ObjectName = &key_name;
        object_attributes.Attributes = OBJ_CASE_INSENSITIVE;

        // Open the registry key with minimal permissions (query only)
        HANDLE key = nullptr;
        constexpr ACCESS_MASK KEY_QUERY_ONLY = 0x0001; // KEY_QUERY_VALUE
        NTSTATUS st = nt_open_key(&key, KEY_QUERY_ONLY, &object_attributes);
        if (!NT_SUCCESS(st) || !key) {
            return false;
        }

        // We specifically want the "ProductId". Automated malware analysis sandboxes often
        // neglect to randomize this value, thats why we flag it
        UNICODE_STRING value_name;
        rtl_init_unicode_string(&value_name, L"ProductId");

        // Buffer for KEY_VALUE_PARTIAL_INFORMATION
        BYTE buffer[128]{};
        ULONG result_length = 0;
        constexpr ULONG key_value_partial_information = 2;

        st = nt_query_value_key(key, &value_name, key_value_partial_information, buffer, sizeof(buffer), &result_length);

        nt_close(key);

        if (!NT_SUCCESS(st)) {
            return false;
        }

        // raw structure returned by the native API to manually parse the binary data
        struct KEY_VALUE_PARTIAL_INFORMATION_LOCAL {
            ULONG TitleIndex;
            ULONG Type;
            ULONG DataLength;
            BYTE Data[1];
        };

        if (result_length < offsetof(KEY_VALUE_PARTIAL_INFORMATION_LOCAL, Data) + 1) {
            return false;
        }

        // Safely extract the ProductId string from the raw byte buffer, ensuring we don't 
        // buffer overflow if the registry returns garbage data
        const auto* kv = reinterpret_cast<KEY_VALUE_PARTIAL_INFORMATION_LOCAL*>(buffer);
        const ULONG data_length = kv->DataLength;
        if (data_length == 0 || data_length >= sizeof(buffer)) return false;

        char product_id[64] = { 0 };
        const size_t copyLen = (data_length < (sizeof(product_id) - 1)) ? data_length : (sizeof(product_id) - 1);
        memcpy(product_id, kv->Data, copyLen);
        product_id[copyLen] = '\0';

        // A list of known "dirty" Product IDs associated with public malware analysis sandboxes
        struct target_pattern {
            const char* product_id;
            const char* brand;
        };

        constexpr target_pattern targets[] = {
            {"55274-640-2673064-23950", brands::JOEBOX},   
            {"76487-644-3177037-23510", brands::CWSANDBOX}, 
            {"76487-337-8429955-22614", brands::ANUBIS}     
        };

        constexpr size_t target_length = 21;

        if (strlen(product_id) != target_length) return false;

        // compare the current system's ProductId against the blacklist
        // if a match is found, we identify the specific sandbox environment and flag it
        for (const auto& target : targets) {
            if (memcmp(product_id, target.product_id, target_length) == 0) {
                debug("GAMARUE: Detected ", target.product_id);
                return core::add(target.brand);
            }
        }

        return false;
    }
 

    /**
     * @brief Check for official VPC method
     * @category Windows, x86_32
     * @implements VM::VPC_INVALID
     */
    [[nodiscard]] static bool vpc_invalid() {
        bool rc = false;
    #if (x86_32 && !CLANG)

        auto is_inside_vpc = [](PEXCEPTION_POINTERS ep) noexcept -> DWORD {
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
        __except (is_inside_vpc(GetExceptionInformation())) {
            rc = false;
        }
    #endif
        return rc;
    }


    /**
     * @brief Check str assembly instruction method for VMware
     * @author Alfredo Omella's (S21sec) STR technique, paper describing this technique is located in /papers/
     * @category Windows, x86_32
     * @implements VM::VMWARE_STR
     */
    [[nodiscard]] static bool vmware_str() {
    #if (x86_32)
        u16 tr = 0;
        __asm {
            str ax
            mov tr, ax
        }
        if ((tr & 0xFF) == 0x00 && ((tr >> 8) & 0xFF) == 0x40) {
            return core::add(brands::VMWARE);
        }

        return false;
    #else
        return false;
    #endif
    }


    /**
     * @brief Check for official VMware io port backdoor technique
     * @category Windows, x86_32
     * @author Code from ScoopyNG by Tobias Klein, technique founded by Ken Kato
     * @copyright BSD clause 2
     * @implements VM::VMWARE_BACKDOOR
     */
    [[nodiscard]] static bool vmware_backdoor() {
        bool is_vm = false;
    #if (x86_32 && !CLANG)
        u32 a = 0;
        u32 b = 0;

        constexpr std::array<i16, 2> ioports = { { 'VX' , 'VY' } };
        i16 ioport;

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
        return is_vm;
    }


    /**
     * @brief Check for mutex strings of VM brands
     * @category Windows
     * @author from VMDE project
     * @author hfiref0x
     * @implements VM::MUTEX
     */
    [[nodiscard]] static bool mutex() {
        const HMODULE ntdll = util::get_ntdll();
        if (!ntdll) return false;

        using RtlInitUnicodeString_t = void(__stdcall*)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
        using NtClose_t = NTSTATUS(__stdcall*)(HANDLE Handle);
        using NtOpenMutant_t = NTSTATUS(__stdcall*)(PHANDLE MutantHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);

        const char* names[] = { "NtOpenMutant", "RtlInitUnicodeString", "NtClose" };
        void* funcs[ARRAYSIZE(names)] = {};
        util::get_function_address(ntdll, names, funcs, ARRAYSIZE(names));

        const auto nt_open_mutant = reinterpret_cast<NtOpenMutant_t>(funcs[0]);
        const auto rtl_init_unicode_string = reinterpret_cast<RtlInitUnicodeString_t>(funcs[1]);
        const auto nt_close = reinterpret_cast<NtClose_t>(funcs[2]);

        if (!nt_open_mutant || !rtl_init_unicode_string || !nt_close) {
            return false;
        }

        auto try_mutex_name = [&](const wchar_t* base_name) noexcept -> bool {
            constexpr wchar_t prefix[] = L"\\BaseNamedObjects\\";
            constexpr size_t prefix_len = (sizeof(prefix) / sizeof(wchar_t)) - 1;

            wchar_t full_path[260];

            // memcpy as it is faster than wcscpy/wcscat
            memcpy(full_path, prefix, sizeof(prefix)); 

            const size_t name_len = wcslen(base_name);
            if (prefix_len + name_len < 260) {
                memcpy(full_path + prefix_len, base_name, (name_len + 1) * sizeof(wchar_t));
            }
            else {
                // should not happen for standard VM artifacts
                full_path[0] = L'\0';
            }

            const wchar_t* attempts[] = { full_path, base_name };

            for (const wchar_t* path : attempts) {
                if (*path == L'\0') continue;

                UNICODE_STRING u_name;
                rtl_init_unicode_string(&u_name, path);

                OBJECT_ATTRIBUTES obj_attr;
                memset(&obj_attr, 0, sizeof(obj_attr));
                obj_attr.Length = sizeof(obj_attr);
                obj_attr.ObjectName = &u_name;
                obj_attr.Attributes = OBJ_CASE_INSENSITIVE;

                HANDLE h_mutant = nullptr;
                const NTSTATUS st = nt_open_mutant(&h_mutant, MUTANT_QUERY_STATE, &obj_attr);

                if (NT_SUCCESS(st)) {
                    if (h_mutant) nt_close(h_mutant);
                    return true;
                }
            }

            return false;
        };

        if (try_mutex_name(L"Sandboxie_SingleInstanceMutex_Control") ||
            try_mutex_name(L"SBIE_BOXED_ServiceInitComplete_Mutex1")) {
            debug("MUTEX: Detected Sandboxie");
            return core::add(brands::SANDBOXIE);
        }

        if (try_mutex_name(L"MicrosoftVirtualPC7UserServiceMakeSureWe'reTheOnlyOneMutex")) {
            debug("MUTEX: Detected VPC");
            return core::add(brands::VPC);
        }

        return false;
    }


    /**
     * @brief Check for cuckoo directory using crt and WIN API directory functions
     * @category Windows
     * @author 一半人生
     * @link https://unprotect.it/snippet/checking-specific-folder-name/196/
     * @implements VM::CUCKOO_DIR
     */
    [[nodiscard]] static bool cuckoo_dir() {
        using NtOpenFile_t = NTSTATUS(__stdcall*)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
            POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
            ULONG ShareAccess, ULONG OpenOptions);
        using RtlInitUnicodeString_t = void(__stdcall*)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
        using NtClose_t = NTSTATUS(__stdcall*)(HANDLE Handle);

        const HMODULE ntdll = util::get_ntdll();
        if (!ntdll) return false;

        const char* names[] = { "NtOpenFile", "RtlInitUnicodeString", "NtClose" };
        void* funcs[ARRAYSIZE(names)] = {};
        util::get_function_address(ntdll, names, funcs, ARRAYSIZE(names));

        const auto nt_open_file = reinterpret_cast<NtOpenFile_t>(funcs[0]);
        const auto rtl_init_unicode_string = reinterpret_cast<RtlInitUnicodeString_t>(funcs[1]);
        const auto nt_close = reinterpret_cast<NtClose_t>(funcs[2]);

        if (!nt_open_file || !rtl_init_unicode_string || !nt_close) {
            return false;
        }

        const wchar_t* native_path = L"\\??\\C:\\Cuckoo";
        UNICODE_STRING path;
        rtl_init_unicode_string(&path, native_path);

        OBJECT_ATTRIBUTES object_attributes;
        ZeroMemory(&object_attributes, sizeof(object_attributes));
        object_attributes.Length = sizeof(object_attributes);
        object_attributes.ObjectName = &path;
        object_attributes.Attributes = OBJ_CASE_INSENSITIVE;

        IO_STATUS_BLOCK iosb;
        HANDLE hFile = nullptr;

        constexpr ACCESS_MASK desired_access = FILE_READ_ATTRIBUTES; 
        constexpr ULONG share_access = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
        constexpr ULONG open_options = FILE_OPEN | FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE;

        const NTSTATUS st = nt_open_file(&hFile, desired_access, &object_attributes, &iosb, share_access, open_options);
        if (NT_SUCCESS(st)) {
            if (hFile) nt_close(hFile);
            return core::add(brands::CUCKOO);
        }

        return false;
    }
                
                
    /**
     * @brief Check for Cuckoo specific piping mechanism
     * @category Windows
     * @author Thomas Roccia (fr0gger)
     * @link https://unprotect.it/snippet/checking-specific-folder-name/196/
     * @implements VM::CUCKOO_PIPE
     */
    [[nodiscard]] static bool cuckoo_pipe() {
        using NtOpenFile_t = NTSTATUS(__stdcall*)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
            POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
            ULONG ShareAccess, ULONG OpenOptions);
        using RtlInitUnicodeString_t = void(__stdcall*)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
        using NtClose_t = NTSTATUS(__stdcall*)(HANDLE Handle);

        const HMODULE ntdll = util::get_ntdll();
        if (!ntdll) return false;

        const char* names[] = { "NtOpenFile", "RtlInitUnicodeString", "NtClose" };
        void* funcs[ARRAYSIZE(names)] = {};
        util::get_function_address(ntdll, names, funcs, ARRAYSIZE(names));

        const auto nt_open_file = reinterpret_cast<NtOpenFile_t>(funcs[0]);
        const auto rtl_init_unicode_string = reinterpret_cast<RtlInitUnicodeString_t>(funcs[1]);
        const auto nt_close = reinterpret_cast<NtClose_t>(funcs[2]);

        if (!nt_open_file || !rtl_init_unicode_string || !nt_close) {
            return false;
        }

        const wchar_t* pipe_path = L"\\??\\pipe\\cuckoo";
        UNICODE_STRING pipe;
        rtl_init_unicode_string(&pipe, pipe_path);

        OBJECT_ATTRIBUTES object_attributes;
        ZeroMemory(&object_attributes, sizeof(object_attributes));
        object_attributes.Length = sizeof(object_attributes);
        object_attributes.ObjectName = &pipe;
        object_attributes.Attributes = OBJ_CASE_INSENSITIVE;

        IO_STATUS_BLOCK iosb;
        HANDLE h_pipe = nullptr;

        constexpr ACCESS_MASK desired_access = FILE_READ_DATA | FILE_READ_ATTRIBUTES;
        constexpr ULONG share_access = 0;
        constexpr ULONG open_options = FILE_OPEN | FILE_SYNCHRONOUS_IO_NONALERT;

        const NTSTATUS st = nt_open_file(&h_pipe, desired_access, &object_attributes, &iosb, share_access, open_options);
        if (NT_SUCCESS(st)) {
            if (h_pipe) nt_close(h_pipe);
            return core::add(brands::CUCKOO);
        }

        return false;
    }


    /**
     * @brief Check for display configurations commonly found in VMs
     * @category Windows
     * @author Idea of screen resolution from Thomas Roccia (fr0gger)
     * @link https://unprotect.it/technique/checking-screen-resolution/
     * @implements VM::DISPLAY
     */
    [[nodiscard]] static bool display() {
        const HDC hdc = GetDC(nullptr);
        const int bpp = GetDeviceCaps(hdc, BITSPIXEL) *
            GetDeviceCaps(hdc, PLANES);
        const int logpix = GetDeviceCaps(hdc, LOGPIXELSX);
        ReleaseDC(nullptr, hdc);

        // physical monitors are almost always 32bpp and 96–144 DPI
        if (bpp != 32 || logpix < 90 || logpix > 200)
            return true;

        UINT32 path_count = 0, mode_count = 0;
        if (QueryDisplayConfig(QDC_ONLY_ACTIVE_PATHS, // win7 and later
            &path_count, nullptr,
            &mode_count, nullptr,
            nullptr) != ERROR_SUCCESS)
            return false;

        if ((path_count <= 1) || (path_count != mode_count)) {
            debug("DISPLAY: Path count: ", path_count);
            debug("DISPLAY: Mode count: ", mode_count);
            return true;
        }

        return false;
    }


    /**
     * @brief Check if bogus device string would be accepted
     * @category Windows
     * @author Huntress Research Team
     * @link https://unprotect.it/technique/buildcommdcbandtimeouta/
     * @implements VM::DEVICE_STRING
     */
    [[nodiscard]] static bool device_string() {
        DCB dcb = { 0 };
        COMMTIMEOUTS timeouts = { 0 };

        if (BuildCommDCBAndTimeoutsA("jhl46745fghb", &dcb, &timeouts)) {
            return true;
        } else {
            return false;
        }
    }


    /**
     * @brief Check for VM-specific names for drivers
     * @category Windows
     * @implements VM::DRIVERS
     */
    [[nodiscard]] static bool drivers() {
        struct _SYSTEM_MODULE_INFORMATION {
            PVOID  Reserved[2];
            PVOID  ImageBaseAddress;
            ULONG  ImageSize;
            ULONG  Flags;
            USHORT Index;
            USHORT NameLength;
            USHORT LoadCount;
            USHORT PathLength;
            CHAR   ImageName[256];
        };

        struct _SYSTEM_MODULE_INFORMATION_EX {
            ULONG  NumberOfModules;
            _SYSTEM_MODULE_INFORMATION Module[1];
        };

        using SYSTEM_MODULE_INFORMATION = _SYSTEM_MODULE_INFORMATION;
        using PSYSTEM_MODULE_INFORMATION = _SYSTEM_MODULE_INFORMATION*;
        using SYSTEM_MODULE_INFORMATION_EX = _SYSTEM_MODULE_INFORMATION_EX;
        using PSYSTEM_MODULE_INFORMATION_EX = _SYSTEM_MODULE_INFORMATION_EX*;

        using NtQuerySystemInformationFn = NTSTATUS(__stdcall*)(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
        using NtAllocateVirtualMemoryFn = NTSTATUS(__stdcall*)(
            HANDLE ProcessHandle,
            PVOID* BaseAddress,
            ULONG_PTR ZeroBits,
            PSIZE_T RegionSize,
            ULONG AllocationType,
            ULONG Protect
        );
        using NtFreeVirtualMemoryFn = NTSTATUS(__stdcall*)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);

        constexpr ULONG system_module_information = 11;
        const HMODULE ntdll = util::get_ntdll();
        if (!ntdll) return false;

        const char* names[] = { "NtQuerySystemInformation", "NtAllocateVirtualMemory", "NtFreeVirtualMemory" };
        void* funcs[ARRAYSIZE(names)] = {};
        util::get_function_address(ntdll, names, funcs, ARRAYSIZE(names));

        const auto nt_query_system_information = reinterpret_cast<NtQuerySystemInformationFn>(funcs[0]);
        const auto nt_allocate_virtual_memory = reinterpret_cast<NtAllocateVirtualMemoryFn>(funcs[1]);
        const auto nt_free_virtual_memory = reinterpret_cast<NtFreeVirtualMemoryFn>(funcs[2]);

        if (nt_query_system_information == nullptr || nt_allocate_virtual_memory == nullptr || nt_free_virtual_memory == nullptr)
            return false;
        
        ULONG ul_size = 0;
        NTSTATUS status = nt_query_system_information(system_module_information, nullptr, 0, &ul_size);
        if (status != ((NTSTATUS)0xC0000004L)) return false;

        const HANDLE current_process = reinterpret_cast<HANDLE>(-1LL);
        PVOID allocated_memory = nullptr;
        SIZE_T region_size = ul_size;
        nt_allocate_virtual_memory(current_process, &allocated_memory, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        const auto system_module_info_ex = reinterpret_cast<PSYSTEM_MODULE_INFORMATION_EX>(allocated_memory);
        status = nt_query_system_information(system_module_information, system_module_info_ex, ul_size, &ul_size);
        if (!(((NTSTATUS)(status)) >= 0)) {
            nt_free_virtual_memory(current_process, &allocated_memory, &region_size, MEM_RELEASE);
            return false;
        }

        for (ULONG i = 0; i < system_module_info_ex->NumberOfModules; ++i) {
            const char* driverPath = reinterpret_cast<const char*>(system_module_info_ex->Module[i].ImageName);
            if (
                strstr(driverPath, "VBoxGuest") || // only installed after vbox guest additions
                strstr(driverPath, "VBoxMouse") ||
                strstr(driverPath, "VBoxSF")
            ) {
                debug("DRIVERS: Detected VBox driver: ", driverPath);
                nt_free_virtual_memory(current_process, &allocated_memory, &region_size, MEM_RELEASE);
                return core::add(brands::VBOX);
            }

            if (
                strstr(driverPath, "vmusbmouse") ||
                strstr(driverPath, "vmmouse") ||
                strstr(driverPath, "vmmemctl")
            ) {
                debug("DRIVERS: Detected VMware driver: ", driverPath);
                nt_free_virtual_memory(current_process, &allocated_memory, &region_size, MEM_RELEASE);
                return core::add(brands::VMWARE);
            }
        }

        nt_free_virtual_memory(current_process, &allocated_memory, &region_size, MEM_RELEASE);
        return false;
    }


    /**
     * @brief Check for serial numbers of virtual disks
     * @category Windows
     * @implements VM::DISK_SERIAL
     */
    [[nodiscard]] static bool disk_serial_number() {
        using NtOpenFile_t = NTSTATUS(__stdcall*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
        using NtDeviceIoControlFile_t = NTSTATUS(__stdcall*)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, ULONG, PVOID, ULONG, PVOID, ULONG);
        using NtAllocateVirtualMemory_t = NTSTATUS(__stdcall*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
        using NtFreeVirtualMemory_t = NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG);
        using NtClose_t = NTSTATUS(__stdcall*)(HANDLE);
        using RtlInitUnicodeString_t = void(__stdcall*)(PUNICODE_STRING, PCWSTR);

        bool result = false;
        constexpr u8 MAX_PHYSICAL_DRIVES = 4;
        constexpr SIZE_T MAX_DESCRIPTOR_SIZE = 64 * 1024;
        u8 successful_opens = 0;

        // Helper to detect QEMU instances based on default hard drive serial patterns
        // QEMU drives often start with "QM000" followed by digits
        auto is_qemu_serial = [](const char* str) noexcept -> bool {
            if ((str[0] & 0xDF) != 'Q') return false;
            if ((str[1] & 0xDF) != 'M') return false;

            // we check byte-by-byte to be safe regarding alignment,
            // though a 32-bit integer check (0x30303030) could be used if alignment is guaranteed
            // we also essentially check for null termination safety here because '\0' != '0'
            return str[2] == '0' && str[3] == '0' && str[4] == '0' && str[5] == '0';
        };

        // Helper to detect VirtualBox instances
        // VirtualBox uses a specific serial format "VB" followed by hex segments
        auto is_vbox_serial = [](const char* str, size_t len) noexcept -> bool {
            // format: VB12345678-12345678 (19 chars)
            if (len != 19) return false;

            if ((str[0] & 0xDF) != 'V' || (str[1] & 0xDF) != 'B') {
                return false;
            }
            if (str[10] != '-') return false;

            auto is_hex = [](char c) noexcept -> bool {
                const char lower = c | 0x20;
                return (c >= '0' && c <= '9') 
                    || (lower >= 'a' && lower <= 'f');
            };

            for (size_t i = 2; i < 10; ++i) {
                if (!is_hex(str[i])) return false;
            }

            for (size_t i = 11; i < 19; ++i) {
                if (!is_hex(str[i])) return false;
            }

            return true;
        };

        auto strnlen = [](const char* s, size_t max) noexcept -> size_t {
            const void* p = memchr(s, 0, max);
            if (!p) return max;
            return static_cast<size_t>(static_cast<const char*>(p) - s);
        };

        const HMODULE ntdll = util::get_ntdll();
        if (!ntdll) return result;

        const char* names[] = {
            "RtlInitUnicodeString",
            "NtOpenFile",
            "NtDeviceIoControlFile",
            "NtAllocateVirtualMemory",
            "NtFreeVirtualMemory",
            "NtFlushInstructionCache",
            "NtClose"
        };
        void* funcs[ARRAYSIZE(names)] = {};
        util::get_function_address(ntdll, names, funcs, ARRAYSIZE(names));

        const auto rtl_init_unicode_string = reinterpret_cast<RtlInitUnicodeString_t>(funcs[0]);
        const auto nt_open_file = reinterpret_cast<NtOpenFile_t>(funcs[1]);
        const auto nt_device_io_control_file = reinterpret_cast<NtDeviceIoControlFile_t>(funcs[2]);
        const auto nt_allocate_virtual_memory = reinterpret_cast<NtAllocateVirtualMemory_t>(funcs[3]);
        const auto nt_free_virtual_memory = reinterpret_cast<NtFreeVirtualMemory_t>(funcs[4]);
        const auto nt_close = reinterpret_cast<NtClose_t>(funcs[6]);

        if (!rtl_init_unicode_string || !nt_open_file || !nt_device_io_control_file ||
            !nt_allocate_virtual_memory || !nt_free_virtual_memory || !nt_close) {
            return result;
        }

        // Iterate through the first few physical drives (PhysicalDrive0 to PhysicalDrive3)
        // Most systems boot from 0, and VMs rarely emulate more than 1 or 2 drives by default
        for (u8 drive = 0; drive < MAX_PHYSICAL_DRIVES; ++drive) {
            wchar_t path[32];
            swprintf_s(path, L"\\??\\PhysicalDrive%u", drive);

            UNICODE_STRING unicode_path;
            rtl_init_unicode_string(&unicode_path, path);

            OBJECT_ATTRIBUTES object_attributes;
            RtlZeroMemory(&object_attributes, sizeof(object_attributes));
            object_attributes.Length = sizeof(object_attributes);
            object_attributes.ObjectName = &unicode_path;
            object_attributes.Attributes = OBJ_CASE_INSENSITIVE;
            object_attributes.RootDirectory = nullptr;

            IO_STATUS_BLOCK iosb;
            HANDLE device = nullptr;

            constexpr ACCESS_MASK desired_access = SYNCHRONIZE | FILE_READ_ATTRIBUTES;
            constexpr ULONG share_access = FILE_SHARE_READ | FILE_SHARE_WRITE;
            constexpr ULONG open_options = FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT;

            // Attempt to open the physical drive directly using Native API
            NTSTATUS st = nt_open_file(&device, desired_access, &object_attributes, &iosb, share_access, open_options);
            if (!NT_SUCCESS(st) || device == nullptr) {
                continue;
            }
            ++successful_opens;

            // stack buffer attempt
            // We first try to read the storage properties into a small stack buffer to avoid heap
            BYTE stackBuf[512] = { 0 };
            const STORAGE_DEVICE_DESCRIPTOR* descriptor = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(stackBuf);

            STORAGE_PROPERTY_QUERY query{};
            query.PropertyId = StorageDeviceProperty;
            query.QueryType = PropertyStandardQuery;

            const ULONG ioctl = IOCTL_STORAGE_QUERY_PROPERTY;

            st = nt_device_io_control_file(device, nullptr, nullptr, nullptr, &iosb,
                ioctl,
                &query, sizeof(query),
                stackBuf, sizeof(stackBuf));

            BYTE* allocated_buffer = nullptr;
            SIZE_T allocated_size = 0;
            const HANDLE current_process = reinterpret_cast<HANDLE>(-1LL);

            // If the stack buffer was too small (NtDeviceIoControlFile failed), we fall back 
            // to allocating memory dynamically using NtAllocateVirtualMemory
            if (!NT_SUCCESS(st)) {
                DWORD reported_size = 0;
                if (descriptor && descriptor->Size > 0) {
                    reported_size = descriptor->Size;
                }

                // This branch just ensures the requested size is reasonable before allocating
                if (reported_size > 0 && reported_size < static_cast<DWORD>(MAX_DESCRIPTOR_SIZE) && reported_size >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
                    allocated_size = static_cast<SIZE_T>(reported_size);
                    PVOID allocation_base = nullptr;
                    SIZE_T region_size = allocated_size;
                    st = nt_allocate_virtual_memory(current_process, &allocation_base, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                    if (!NT_SUCCESS(st) || allocation_base == nullptr) {
                        nt_close(device);
                        continue;
                    }
                    allocated_buffer = reinterpret_cast<BYTE*>(allocation_base);

                    // Retry the query with the larger allocated buffer
                    st = nt_device_io_control_file(device, nullptr, nullptr, nullptr, &iosb,
                        ioctl,
                        &query, sizeof(query),
                        allocated_buffer, static_cast<ULONG>(allocated_size));
                    if (!NT_SUCCESS(st)) {
                        PVOID free_base = reinterpret_cast<PVOID>(allocated_buffer);
                        SIZE_T free_size = allocated_size;
                        nt_free_virtual_memory(current_process, &free_base, &free_size, MEM_RELEASE);
                        nt_close(device);
                        continue;
                    }
                    descriptor = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(allocated_buffer);
                }
                else {
                    nt_close(device);
                    continue;
                }
            }

            // This part is just to validate the structure size returned by the driver to prevent out-of-bounds reads
            {
                const DWORD reported_size = descriptor->Size;
                if (reported_size < sizeof(STORAGE_DEVICE_DESCRIPTOR) || static_cast<SIZE_T>(reported_size) > MAX_DESCRIPTOR_SIZE) {
                    if (allocated_buffer) {
                        PVOID free_base = reinterpret_cast<PVOID>(allocated_buffer);
                        SIZE_T free_size = allocated_size;
                        nt_free_virtual_memory(current_process, &free_base, &free_size, MEM_RELEASE);
                        allocated_buffer = nullptr;
                    }
                    nt_close(device);
                    continue;
                }
            }

            // Serial number string within the descriptor structure
            const u32 serial_offset = descriptor->SerialNumberOffset;
            if (serial_offset > 0 && serial_offset < descriptor->Size) {
                const char* serial = reinterpret_cast<const char*>(descriptor) + serial_offset;
                const size_t max_avail = static_cast<size_t>(descriptor->Size) - static_cast<size_t>(serial_offset);
                const size_t serialLen = strnlen(serial, max_avail);

                debug("DISK_SERIAL: ", serial);

                // Check the retrieved serial number against known VM artifacts
                if (is_qemu_serial(serial) || is_vbox_serial(serial, serialLen)) {
                    if (allocated_buffer) {
                        PVOID free_base = reinterpret_cast<PVOID>(allocated_buffer);
                        SIZE_T free_size = allocated_size;
                        nt_free_virtual_memory(current_process, &free_base, &free_size, MEM_RELEASE);
                        allocated_buffer = nullptr;
                    }
                    nt_close(device);
                    return true;
                }
            }

            // Cleanup for the current iteration if no VM was detected on this drive
            if (allocated_buffer) {
                PVOID free_base = reinterpret_cast<PVOID>(allocated_buffer);
                SIZE_T free_size = allocated_size;
                nt_free_virtual_memory(current_process, &free_base, &free_size, MEM_RELEASE);
                allocated_buffer = nullptr;
            }
            nt_close(device);
        }

		// If we couldn't open any physical drives (not even read permissions) it's weird so we flag it.
        if (successful_opens == 0) {
            debug("DISK_SERIAL: No physical drives detected");
            return true;
        }

        return result;
    }


    /**
     * @brief Check for IVSHMEM device presence
     * @category Windows
     * @author dmfrpro (https://github.com/dmfrpro)
     * @implements VM::IVSHMEM
     */
    [[nodiscard]] static bool ivshmem() {
        typedef struct _KEY_FULL_INFORMATION {
            LARGE_INTEGER LastWriteTime;
            ULONG         TitleIndex;
            ULONG         ClassOffset;
            ULONG         ClassLength;
            ULONG         SubKeys;
            ULONG         MaxNameLen;
            ULONG         MaxClassLen;
            ULONG         Values;
            ULONG         MaxValueNameLen;
            ULONG         MaxValueDataLen;
            WCHAR         Class[1];
        } KEY_FULL_INFORMATION, * PKEY_FULL_INFORMATION;

        typedef enum _KEY_INFORMATION_CLASS {
            KeyBasicInformation,
            KeyNodeInformation,
            KeyFullInformation,
            KeyNameInformation,
            KeyCachedInformation,
            KeyFlagsInformation,
            KeyVirtualizationInformation,
            KeyHandleTagsInformation,
            KeyTrustInformation,
            KeyLayerInformation,
            MaxKeyInfoClass
        } KEY_INFORMATION_CLASS;

        const HMODULE ntdll = util::get_ntdll();
        if (!ntdll) return false;

        const char* names[] = { "RtlInitUnicodeString", "NtOpenKey", "NtQueryKey", "NtClose" };
        void* funcs[ARRAYSIZE(names)] = {};
        util::get_function_address(ntdll, names, funcs, ARRAYSIZE(names));

        const auto rtl_init_unicode_string = reinterpret_cast<void(__stdcall*)(PUNICODE_STRING, PCWSTR)>(funcs[0]);
        const auto nt_open_key = reinterpret_cast<NTSTATUS(__stdcall*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)>(funcs[1]);
        const auto nt_query_key = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG)>(funcs[2]);
        const auto nt_close = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE)>(funcs[3]);

        if (!rtl_init_unicode_string || !nt_open_key || !nt_query_key || !nt_close) {
            return false;
        }

        // Targeted GUID for IVSHMEM (Inter-VM Shared Memory).
        // This device is typically used in KVM/QEMU environments (like Looking Glass) to pass memory between host and guest
        constexpr GUID GUID_IVSHMEM_IFACE =
        { 0xdf576976, 0x569d, 0x4672, { 0x95, 0xa0, 0xf5, 0x7e, 0x4e, 0xa0, 0xb2, 0x10 } };

        // Construct the registry path for the DeviceClasses key
        // We access the "DeviceClasses" registry hive directly to find hardware interfaces
        wchar_t interface_class_path[256];
        swprintf_s(
            interface_class_path,
            ARRAYSIZE(interface_class_path),
            L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\DeviceClasses\\{%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}",
            GUID_IVSHMEM_IFACE.Data1, GUID_IVSHMEM_IFACE.Data2, GUID_IVSHMEM_IFACE.Data3,
            GUID_IVSHMEM_IFACE.Data4[0], GUID_IVSHMEM_IFACE.Data4[1], GUID_IVSHMEM_IFACE.Data4[2],
            GUID_IVSHMEM_IFACE.Data4[3], GUID_IVSHMEM_IFACE.Data4[4], GUID_IVSHMEM_IFACE.Data4[5],
            GUID_IVSHMEM_IFACE.Data4[6], GUID_IVSHMEM_IFACE.Data4[7]
        );

        UNICODE_STRING unicode_path;
        rtl_init_unicode_string(&unicode_path, interface_class_path);

        OBJECT_ATTRIBUTES object_attributes;
        RtlZeroMemory(&object_attributes, sizeof(object_attributes));
        object_attributes.Length = sizeof(object_attributes);
        object_attributes.ObjectName = &unicode_path;
        object_attributes.Attributes = OBJ_CASE_INSENSITIVE;

        HANDLE key = nullptr;
        NTSTATUS st = nt_open_key(&key, KEY_READ, &object_attributes);
        if (!NT_SUCCESS(st) || key == nullptr) {
            return false;
        }

        // We query the "Full Information" of the key to get the count of subkeys
        // The existence of the class key alone isn't enough cuz Windows might register the class but have no devices
        // If SubKeys > 0, it means actual device instances (for ex. PCI devices) are registered under this interface
        BYTE info_buffer[512] = {};
        ULONG returned_len = 0;
        st = nt_query_key(key, KeyFullInformation, info_buffer, sizeof(info_buffer), &returned_len);

        DWORD number_of_subkeys = 0;
        if (NT_SUCCESS(st) && returned_len >= sizeof(KEY_FULL_INFORMATION)) {
            auto* kfi = reinterpret_cast<KEY_FULL_INFORMATION*>(info_buffer);
            number_of_subkeys = static_cast<DWORD>(kfi->SubKeys);
        }
        else {
            nt_close(key);
            return false;
        }

        nt_close(key);

        return number_of_subkeys > 0;
    }


    /**
     * @brief Check for GPU capabilities related to VMs
     * @category Windows
     * @implements VM::GPU_CAPABILITIES
     */
    [[nodiscard]] static bool gpu_capabilities() {
        /*
            Microsoft::WRL::ComPtr<IDirect3D9> d3d9 {
                Direct3DCreate9(D3D_SDK_VERSION)
            };

            if (!d3d9) {
                debug("GPU_CAPABILITIES: Direct3DCreate9 failed");
                return true;
            }

            D3DCAPS9 caps;
            if (FAILED(d3d9->GetDeviceCaps(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, &caps))) {
                debug("GPU_CAPABILITIES: GetDeviceCaps failed");
                return false;
            }

            // if the driver cannot adjust the display gamma ramp dynamically but only in full-screen mode—via the IDirect3DDevice9::SetGammaRamp API
            return !(caps.Caps2 & D3DCAPS2_FULLSCREENGAMMA);
        */

        const HDC hdc = GetDC(nullptr);
        if (!hdc) {
            return true;
        }

        const int color_caps = GetDeviceCaps(hdc, COLORMGMTCAPS);
        ReleaseDC(nullptr, hdc);

        return !(color_caps & CM_GAMMA_RAMP) || color_caps == 0;
    }


    /**
     * @brief Check for vm-specific devices
     * @category Windows
     * @implements VM::DEVICE_HANDLES
     */
    [[nodiscard]] static bool device_handles() {
        const HMODULE ntdll = util::get_ntdll();
        if (!ntdll) return false;

        const char* names[] = { "RtlInitUnicodeString", "NtOpenFile", "NtClose" };
        void* funcs[ARRAYSIZE(names)] = {};
        util::get_function_address(ntdll, names, funcs, ARRAYSIZE(names));

        const auto rtl_init_unicode_string = reinterpret_cast<void(__stdcall*)(PUNICODE_STRING, PCWSTR)>(funcs[0]);
        const auto nt_open_file = reinterpret_cast<NTSTATUS(__stdcall*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG)>(funcs[1]);
        const auto nt_close = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE)>(funcs[2]);

        if (!rtl_init_unicode_string || !nt_open_file || !nt_close) {
            return false;
        }

        auto try_open_mutex = [&](const wchar_t* native_path) noexcept -> HANDLE {
            UNICODE_STRING u_path{};
            u_path.Buffer = const_cast<wchar_t*>(native_path);

            const size_t len_bytes = wcslen(native_path) * sizeof(wchar_t);
            u_path.Length = static_cast<USHORT>(len_bytes);
            u_path.MaximumLength = static_cast<USHORT>(len_bytes + sizeof(wchar_t));

            OBJECT_ATTRIBUTES obj_attr = {
                sizeof(OBJECT_ATTRIBUTES),
                nullptr,
                &u_path,
                OBJ_CASE_INSENSITIVE,
                nullptr,
                nullptr
            };

            IO_STATUS_BLOCK iosb;
            HANDLE h_file = nullptr;

            constexpr ACCESS_MASK desired_access = FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
            constexpr ULONG share_access = FILE_SHARE_READ;
            constexpr ULONG open_options = FILE_OPEN | FILE_SYNCHRONOUS_IO_NONALERT;

            const NTSTATUS st = nt_open_file(&h_file, desired_access, &obj_attr, &iosb, share_access, open_options);

            if (NT_SUCCESS(st)) {
                return h_file;
            }
            return INVALID_HANDLE_VALUE;
        };

        // \\.\Name -> \??\Name, \\.\pipe\name -> \??\pipe\name
        constexpr const wchar_t* paths[] = {
            L"\\??\\VBoxMiniRdrDN",    // \\.\VBoxMiniRdrDN
            L"\\??\\pipe\\VBoxMiniRdDN",// \\.\pipe\VBoxMiniRdDN
            L"\\??\\VBoxTrayIPC",      // \\.\VBoxTrayIPC
            L"\\??\\pipe\\VBoxTrayIPC",// \\.\pipe\VBoxTrayIPC
            L"\\??\\HGFS",             // \\.\HGFS (VMware)
            L"\\??\\pipe\\cuckoo"      // \\.\pipe\cuckoo (Cuckoo)
        };

        HANDLE handles[ARRAYSIZE(paths)]{};
        for (size_t i = 0; i < ARRAYSIZE(paths); ++i) {
            handles[i] = try_open_mutex(paths[i]);
        }

        bool vbox = false;
        if (handles[0] != INVALID_HANDLE_VALUE ||
            handles[1] != INVALID_HANDLE_VALUE ||
            handles[2] != INVALID_HANDLE_VALUE ||
            handles[3] != INVALID_HANDLE_VALUE) {
            vbox = true;
        }

        for (size_t i = 0; i < 4; ++i) {
            if (handles[i] != INVALID_HANDLE_VALUE) {
                nt_close(handles[i]);
            }
        }

        if (vbox) {
            debug("DEVICE_HANDLES: Detected VBox related device handles");
            return core::add(brands::VBOX);
        }

        if (handles[4] != INVALID_HANDLE_VALUE) {
            nt_close(handles[4]);
            debug("DEVICE_HANDLES: Detected VMware related device (HGFS)");
            return core::add(brands::VMWARE);
        }

        if (handles[5] != INVALID_HANDLE_VALUE) {
            nt_close(handles[5]);
            debug("DEVICE_HANDLES: Detected Cuckoo related device (pipe)");
            return core::add(brands::CUCKOO);
        }

        return false;
    }


    /**
     * @brief Check if the number of virtual and logical processors are reported correctly by the system
     * @category Windows, x86
     * @implements VM::VIRTUAL_PROCESSORS
     */
    [[nodiscard]] static bool virtual_processors() {
    #if (x86)
        int regs[4];
        __cpuid(regs, 0x40000000);

        const u32 max_leaf = static_cast<u32>(regs[0]);
        if (max_leaf < 0x40000005) {
            return false;
        }

        __cpuid(regs, 0x40000005);
        const u32 max_virtual_processors = static_cast<u32>(regs[0]);
        const u32 max_logical_processors = static_cast<u32>(regs[1]);

        debug("VIRTUAL_PROCESSORS: MaxVirtualProcessors -> ", max_virtual_processors,
            ", MaxLogicalProcessors -> ", max_logical_processors);

        if (max_virtual_processors == 0xFFFFFFFF || max_logical_processors == 0) {
            return true;
        }
    #endif
        return false;
    }


    /**
     * @brief Check if a call to NtQuerySystemInformation with the 0x9f leaf fills a _SYSTEM_HYPERVISOR_DETAIL_INFORMATION structure
     * @category Windows, x86_64
     * @implements VM::HYPERVISOR_QUERY
     */
    [[nodiscard]] static bool hypervisor_query() {
    #if (x86_32)
        return false;
    #else
        if (util::hyper_x() == HYPERV_ARTIFACT_VM) {
            return false;
        }

        struct HV_DETAILS {
            ULONG Data[4];
        };
        struct SYSTEM_HYPERVISOR_DETAIL_INFORMATION {
            HV_DETAILS HvVendorAndMaxFunction;
            HV_DETAILS HypervisorInterface;
            HV_DETAILS HypervisorVersion;
            HV_DETAILS HvFeatures;
            HV_DETAILS HwFeatures;
            HV_DETAILS EnlightenmentInfo;
            HV_DETAILS ImplementationLimits;
        };

        using PHV_DETAILS = HV_DETAILS*;
        using PSYSTEM_HYPERVISOR_DETAIL_INFORMATION = SYSTEM_HYPERVISOR_DETAIL_INFORMATION*;

        using FN_NtQuerySystemInformation = NTSTATUS(__stdcall*)(
            SYSTEM_INFORMATION_CLASS SystemInformationClass,
            PVOID SystemInformation,
            ULONG SystemInformationLength,
            PULONG ReturnLength
        );

        const HMODULE ntdll = util::get_ntdll();
        if (!ntdll) return false;        

        const char* names[] = { "NtQuerySystemInformation" };
        void* funcs[ARRAYSIZE(names)] = {};
        util::get_function_address(ntdll, names, funcs, ARRAYSIZE(names));

        const FN_NtQuerySystemInformation nt_query_system_information = reinterpret_cast<FN_NtQuerySystemInformation>(funcs[0]);
        if (nt_query_system_information) {
            SYSTEM_HYPERVISOR_DETAIL_INFORMATION hypervisor_information = { {} };

            // Request class 0x9F (SystemHypervisorDetailInformation)
            // This asks the OS kernel to fill the structure with information about the 
            // hypervisor layer it is running on top of
            const NTSTATUS status = nt_query_system_information(static_cast<SYSTEM_INFORMATION_CLASS>(0x9F), &hypervisor_information, sizeof(hypervisor_information), nullptr);

            if (status != 0) {
                return false;
            }

            // If Data[0] is non-zero, it means the kernel has successfully communicated 
            // with a hypervisor and retrieved a vendor signature like "Micr" for Microsoft
            if (hypervisor_information.HvVendorAndMaxFunction.Data[0] != 0) {
                return true;
            }
        }
    #endif
        return false;
    }

    
    /**
     * @brief Check for particular object directory which is present in Sandboxie virtual environment but not in usual host systems
     * @category Windows
     * @link https://evasions.checkpoint.com/src/Evasions/techniques/global-os-objects.html
     * @implements VM::VIRTUAL_REGISTRY
     */
    [[nodiscard]] static bool virtual_registry() {
        struct UNICODE_STRING {
            USHORT Length;
            USHORT MaximumLength;
            PWSTR  Buffer;
        };
        struct OBJECT_ATTRIBUTES {
            ULONG Length;
            HANDLE RootDirectory;
            UNICODE_STRING* ObjectName;
            ULONG Attributes;
            PVOID SecurityDescriptor;
            PVOID SecurityQualityOfService;
        };
        enum OBJECT_INFORMATION_CLASS {
            ObjectBasicInformation = 0,
            ObjectNameInformation = 1,
            ObjectTypeInformation = 2
        };
        struct OBJECT_NAME_INFORMATION {
            UNICODE_STRING Name;
        };

        using POBJECT_NAME_INFORMATION = OBJECT_NAME_INFORMATION*;
        using PNtOpenKey = NTSTATUS(__stdcall*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES );
        using PNtQueryObject = NTSTATUS(__stdcall*)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    
        const HMODULE ntdll = util::get_ntdll();
        if (!ntdll) return false;
    
        const char* names[] = { "NtOpenKey", "NtQueryObject", "NtClose" };
        void* funcs[ARRAYSIZE(names)] = {};
        util::get_function_address(ntdll, names, funcs, ARRAYSIZE(names));
    
        const auto nt_open_key = reinterpret_cast<PNtOpenKey>(funcs[0]);
        const auto nt_query_object = reinterpret_cast<PNtQueryObject>(funcs[1]);
        const auto nt_close = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE)>(funcs[2]);

        if (!nt_open_key || !nt_query_object || !nt_close)
            return false;
    
        // Prepare to open the root USER registry hive
        UNICODE_STRING key_path{};
        key_path.Buffer = const_cast<PWSTR>(L"\\REGISTRY\\USER");
        key_path.Length = static_cast<USHORT>(wcslen(key_path.Buffer) * sizeof(WCHAR));
        key_path.MaximumLength = key_path.Length + sizeof(WCHAR);

        OBJECT_ATTRIBUTES object_attributes = {
            sizeof(OBJECT_ATTRIBUTES),
            nullptr,
            &key_path,
            0x00000040L,  // OBJ_CASE_INSENSITIVE
            nullptr,
            nullptr
        };

        // Attempt to open the key. If we are sandboxed, this open call often succeeds,
        // but the underlying handle will point to a virtualized container, not the real OS path
        HANDLE key = nullptr;
        NTSTATUS status = nt_open_key(&key, KEY_READ, reinterpret_cast<POBJECT_ATTRIBUTES>(&object_attributes));
        if (!(((NTSTATUS)(status)) >= 0))
            return false;

        // Ask the kernel: "What is the actual name of the object this handle points to?"
        // Sandboxie implements file system and registry virtualization by redirecting access
        // While the API pretends we opened "\REGISTRY\USER", the handle might actually point to 
        // something like "\Device\HarddiskVolume2\Sandbox\User\DefaultBox\RegHive"
        alignas(16) BYTE buffer[1024]{};
        ULONG returned_length = 0;
        status = nt_query_object(key, ObjectNameInformation, buffer, sizeof(buffer), &returned_length);
        nt_close(key);
        if (!(((NTSTATUS)(status)) >= 0))
            return false;

        const auto object_name = reinterpret_cast<POBJECT_NAME_INFORMATION>(buffer);

        UNICODE_STRING expected_name{};
        expected_name.Buffer = const_cast<PWSTR>(L"\\REGISTRY\\USER");
        expected_name.Length = static_cast<USHORT>(wcslen(expected_name.Buffer) * sizeof(WCHAR));

        // Compare the requested name vs the actual kernel object name
        // If they don't match, we have been redirected, confirming the presence of Sandboxie
        const bool mismatch = (object_name->Name.Length != expected_name.Length) ||
            (memcmp(object_name->Name.Buffer, expected_name.Buffer, expected_name.Length) != 0);

        return mismatch ? core::add(brands::SANDBOXIE) : false;
    }
    
    
    /**
     * @brief Check if no waveform-audio output devices are present in the system
     * @category Windows
     * @implements VM::AUDIO
     */
    [[nodiscard]] static bool audio() {
        struct KEY_FULL_INFORMATION {
            LARGE_INTEGER LastWriteTime;
            ULONG         TitleIndex;
            ULONG         ClassOffset;
            ULONG         ClassLength;
            ULONG         SubKeys;
            ULONG         MaxNameLen;
            ULONG         MaxClassLen;
            ULONG         Values;             
            ULONG         MaxValueNameLen;
            ULONG         MaxValueDataLen;
            WCHAR         Class[1];
        };
        using PKEY_FULL_INFORMATION = KEY_FULL_INFORMATION*;

        enum KEY_INFORMATION_CLASS {
            KeyBasicInformation,
            KeyNodeInformation,
            KeyFullInformation,
            KeyNameInformation,
            KeyCachedInformation,
            KeyFlagsInformation,
            KeyVirtualizationInformation,
            KeyHandleTagsInformation,
            KeyTrustInformation,
            KeyLayerInformation,
            MaxKeyInfoClass
        };

        const HMODULE ntdll = util::get_ntdll();
        if (!ntdll) return false;

        const char* names[] = { "RtlInitUnicodeString", "NtOpenKey", "NtQueryKey", "NtClose" };
        void* funcs[ARRAYSIZE(names)] = {};
        util::get_function_address(ntdll, names, funcs, ARRAYSIZE(names));

        const auto rtl_init_unicode_string = reinterpret_cast<void(__stdcall*)(PUNICODE_STRING, PCWSTR)>(funcs[0]);
        const auto nt_open_key = reinterpret_cast<NTSTATUS(__stdcall*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)>(funcs[1]);
        const auto nt_query_key = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG)>(funcs[2]);
        const auto nt_close = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE)>(funcs[3]);

        if (!rtl_init_unicode_string || !nt_open_key || !nt_query_key || !nt_close) {
            return false;
        }

        // We are checking for the presence of Audio Render devices
        // Most legitimate user PCs have speakers or headphones (audio endpoints)
        // Automated sandboxes and headless servers often have no audio devices configured
        // We target the MMDevices\Audio\Render key where these endpoints are registered
        const wchar_t* native_path = L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\MMDevices\\Audio\\Render";

        UNICODE_STRING unicode_path;
        rtl_init_unicode_string(&unicode_path, native_path);

        OBJECT_ATTRIBUTES object_attributes;
        RtlZeroMemory(&object_attributes, sizeof(object_attributes));
        object_attributes.Length = sizeof(object_attributes);
        object_attributes.ObjectName = &unicode_path;
        object_attributes.Attributes = OBJ_CASE_INSENSITIVE;

        HANDLE key = nullptr;
        const ACCESS_MASK desired_access = KEY_READ;

        NTSTATUS st = nt_open_key(&key, desired_access, &object_attributes);
        if (!NT_SUCCESS(st) || key == nullptr) {
            return false;
        }

        constexpr KEY_INFORMATION_CLASS InfoClass = KeyFullInformation;
        std::vector<BYTE> info_buffer(512);
        ULONG returned_len = 0;

        // Query the key information. If the buffer is too small (STATUS_BUFFER_TOO_SMALL),
        // resize it to the exact length required by the kernel and try again
        st = nt_query_key(key, InfoClass, info_buffer.data(), static_cast<ULONG>(info_buffer.size()), &returned_len);

        if (!NT_SUCCESS(st) && returned_len > info_buffer.size()) {
            info_buffer.resize(returned_len);
            st = nt_query_key(key, InfoClass, info_buffer.data(), static_cast<ULONG>(info_buffer.size()), &returned_len);
        }

        bool has_values = false;
        if (NT_SUCCESS(st) && returned_len >= sizeof(KEY_FULL_INFORMATION)) {
            const auto* kfi = reinterpret_cast<PKEY_FULL_INFORMATION>(info_buffer.data());

            // Check if the registry key has any values associated with it
            // If 'Values' is 0, the audio system is likely uninitialized or barren,
            // which strongly suggests a virtualized/sandbox environment
            const DWORD value_count = static_cast<DWORD>(kfi->Values); // values, not subkeys
            has_values = (value_count > 0);
        }
        else {
            nt_close(key);
            return false;
        }

        nt_close(key);

        return has_values;
    }
    
    
    /**
     * @brief Check for VM-specific ACPI device signatures
     * @category Windows
     * @implements VM::ACPI_SIGNATURE
     */
    [[nodiscard]] static bool acpi_signature() {
        auto is_hex = [](wchar_t c) noexcept -> bool {
            return (c >= L'0' && c <= L'9') || (c >= L'A' && c <= L'F');
        };

        // enumerate all DISPLAY devices
        const HDEVINFO handle_dev_info = SetupDiGetClassDevsW(&GUID_DEVCLASS_DISPLAY, nullptr, nullptr, DIGCF_PRESENT);
        if (handle_dev_info == INVALID_HANDLE_VALUE) {
            debug("ACPI_SIGNATURE: No display device detected");
            return true;
        }

        SP_DEVINFO_DATA dev_info;
        ZeroMemory(&dev_info, sizeof(dev_info));
        dev_info.cbSize = sizeof(dev_info);
        const DEVPROPKEY key = DEVPKEY_Device_LocationPaths;

        // baremetal tokens (case-sensitive to preserve handling against edge-cases)
        static constexpr const wchar_t* excluded_tokens[] = {
            L"GFX",
            L"IGD", L"IGFX", L"IGPU",
            L"VGA", L"VIDEO", L"DISPLAY", L"GPU",
            L"PCIROOT", L"PNP0A03", L"PNP0A08",
            L"PCH", L"PXS", L"PEG", L"PEGP"
        };

        auto has_excluded_token = [&](const wchar_t* s) noexcept -> bool {
            if (!s || !*s) return false;
            for (const wchar_t* tok : excluded_tokens) {
                if (wcsstr(s, tok) != nullptr) return true;
            }
            return false;
        };

        for (DWORD idx = 0; SetupDiEnumDeviceInfo(handle_dev_info, idx, &dev_info); ++idx) {
            DEVPROPTYPE prop_type = 0;
            DWORD required_size = 0;

            // query required size (bytes)
            SetupDiGetDevicePropertyW(handle_dev_info, &dev_info, &key, &prop_type, nullptr, 0, &required_size, 0);
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || required_size == 0) {
                if (GetLastError() == ERROR_NOT_FOUND) {
                    debug("ACPI_SIGNATURE: No dedicated display/GPU detected");
                    SetupDiDestroyDeviceInfoList(handle_dev_info);
                    return false;
                }
                else {
                    continue;
                }
            }

            // fetch buffer (multi-sz)
            std::vector<BYTE> buffer(required_size);
            if (!SetupDiGetDevicePropertyW(handle_dev_info, &dev_info, &key, &prop_type,
                buffer.data(), required_size, &required_size, 0))
            {
                continue;
            }

            const wchar_t* ptr = reinterpret_cast<const wchar_t*>(buffer.data());
            // number of wchar_t slots in buffer
            const size_t total_wchars = required_size / sizeof(wchar_t);
            const wchar_t* buf_end = ptr + (total_wchars ? total_wchars : 0);

        #ifdef __VMAWARE_DEBUG__
            for (const wchar_t* p = ptr; p < buf_end && *p; p += (wcslen(p) + 1)) {
                debug("ACPI_SIGNATURE: ", p);
            }
        #endif

            static const wchar_t acpi_prefix[] = L"#ACPI(S";
            static const wchar_t acpi_paren[] = L"ACPI(";

            // First pass: QEMU-style "#ACPI(Sxx...)" and generic "ACPI(Sxx)"
            for (const wchar_t* p = ptr; p < buf_end && *p; p += (wcslen(p) + 1)) {
                if (has_excluded_token(p)) {
                    debug("ACPI_SIGNATURE: Valid signature -> ", p);
                    continue;
                }

                // search for "#ACPI(S"
                const wchar_t* search = p;
                while (true) {
                    const wchar_t* found = wcsstr(search, acpi_prefix);
                    if (!found) break;

                    // after "#ACPI(S" we expect two hex chars
                    const wchar_t* hexpos = found + wcslen(acpi_prefix); // first hex char
                    if (hexpos && hexpos[0] && hexpos[1]) {
                        wchar_t b = hexpos[0];
                        wchar_t s = hexpos[1];
                        if (is_hex(b) && is_hex(s)) {
                            const wchar_t after = hexpos[2]; // may be '_' or ')'
                            if (after == L'_' || after == L')') {
                                SetupDiDestroyDeviceInfoList(handle_dev_info);
                                return core::add(brands::QEMU);
                            }
                        }
                    }
                    search = found + 1;
                }

                // search for "ACPI(" then check for "S" + two hex digits
                search = p;
                while (true) {
                    const wchar_t* found = wcsstr(search, acpi_paren);
                    if (!found) break;
                    const wchar_t* start = found + wcslen(acpi_paren); // char after '('
                    if (start && start[0] && start[1] && start[2]) {
                        if (start[0] == L'S' && is_hex(start[1]) && is_hex(start[2])) {
                            SetupDiDestroyDeviceInfoList(handle_dev_info);
                            return core::add(brands::QEMU);
                        }
                    }
                    search = found + 1;
                }
            }

            // Important to run Hyper-V checks later because of is_hardened() logic
            static constexpr const wchar_t* vm_signatures[] = {
                L"#ACPI(VMOD)", L"#ACPI(VMBS)", L"#VMBUS(", L"#VPCI("
            };

            for (const wchar_t* p = ptr; p < buf_end && *p; p += (wcslen(p) + 1)) {
                if (has_excluded_token(p)) continue;

                for (const wchar_t* sig : vm_signatures) {
                    if (wcsstr(p, sig) != nullptr) {
                        SetupDiDestroyDeviceInfoList(handle_dev_info);
                        return core::add(brands::HYPERV);
                    }
                }
            }
        }

        SetupDiDestroyDeviceInfoList(handle_dev_info);
        return false;
    }


    /**
     * @brief Check if after raising two traps at the same RIP, a hypervisor interferes with the instruction pointer delivery
     * @category Windows, x86_64
     * @implements VM::TRAP
     */
    [[nodiscard]] static bool trap() {
        bool hypervisor_caught = false;
    #if (x86_64)
        // when a single - step(TF) and hardware breakpoint(DR0) collide, Intel CPUs set both DR6.BS and DR6.B0 to report both events, which help make this detection trick
        // AMD CPUs prioritize the breakpoint, setting only its corresponding bit in DR6 and clearing the single-step bit, which is why this technique is not compatible with AMD
        if (!cpu::is_intel()) {
            return false;
        }

        // mobile SKUs can "false flag" this check
        const char* brand = cpu::get_brand();
        for (const char* c = brand; *c; ++c) {
            if (*c == 'U') {
                if (c > brand && (c[-1] >= '0' && c[-1] <= '9')) {
                    if (c[1] == ' ' || c[1] == '\0') {
                        return false;
                    }
                }
            }
        }

        // We must preserve RBX because CPUID clobbers it, and RBX is a non-volatile 
        // register in x64. If we don't restore it, the calling function (VM::check) crashes
        // we use MOV R8, RBX instead of PUSH RBX. Pushing to the stack without 
        // unwind metadata breaks SEH in x64 (OS cannot find the handler), causing a crash
        constexpr u8 trampoline[] = {
            0x49, 0x89, 0xD8,                     // mov r8, rbx      (save rbx to volatile register r8)
            0x9C,                                 // pushfq
            0x81, 0x04, 0x24,                     // OR DWORD PTR [RSP], 0x10100 (Set TF)
            0x00, 0x01, 0x01, 0x00,
            0x9D,                                 // popfq
            0x0F, 0xA2,                           // cpuid 
            0x4C, 0x89, 0xC3,                     // mov rbx, r8      (restore rbx from r8) - trap happens here
            0xC3                                  // ret
        };
        SIZE_T trampoline_size = sizeof(trampoline);

        const HMODULE ntdll = util::get_ntdll();
        if (!ntdll) return false;

        const char* names[] = {
            "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory",
            "NtFreeVirtualMemory",
            "NtFlushInstructionCache",
            "NtClose",
            "NtGetContextThread",
            "NtSetContextThread"
        };
        void* funcs[ARRAYSIZE(names)] = {};
        util::get_function_address(ntdll, names, funcs, ARRAYSIZE(names));

        using NtAllocateVirtualMemory_t = NTSTATUS(__stdcall*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
        using NtProtectVirtualMemory_t = NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
        using NtFreeVirtualMemory_t = NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG);
        using NtFlushInstructionCache_t = NTSTATUS(__stdcall*)(HANDLE, PVOID, SIZE_T);
        using NtClose_t = NTSTATUS(__stdcall*)(HANDLE);
        using NtGetContextThread_t = NTSTATUS(__stdcall*)(HANDLE, PCONTEXT);
        using NtSetContextThread_t = NTSTATUS(__stdcall*)(HANDLE, PCONTEXT);

        // volatile ensures these are loaded from stack after SEH unwind when compiled with aggresive optimizations
        NtAllocateVirtualMemory_t volatile nt_allocate_virtual_memory = reinterpret_cast<NtAllocateVirtualMemory_t>(funcs[0]);
        NtProtectVirtualMemory_t volatile nt_protect_virtual_memory = reinterpret_cast<NtProtectVirtualMemory_t>(funcs[1]);
        NtFreeVirtualMemory_t volatile nt_free_virtual_memory = reinterpret_cast<NtFreeVirtualMemory_t>(funcs[2]);
        NtFlushInstructionCache_t volatile nt_flush_instruction_cache = reinterpret_cast<NtFlushInstructionCache_t>(funcs[3]);
        NtClose_t volatile nt_close = reinterpret_cast<NtClose_t>(funcs[4]);
        NtGetContextThread_t volatile nt_get_context_thread = reinterpret_cast<NtGetContextThread_t>(funcs[5]);
        NtSetContextThread_t volatile nt_set_context_thread = reinterpret_cast<NtSetContextThread_t>(funcs[6]);

        if (!nt_allocate_virtual_memory || !nt_protect_virtual_memory || !nt_flush_instruction_cache ||
            !nt_free_virtual_memory || !nt_get_context_thread || !nt_set_context_thread || !nt_close) {
            return false;
        }

        PVOID exec_mem = nullptr;
        SIZE_T region_size = trampoline_size;
        const HANDLE current_process = reinterpret_cast<HANDLE>(-1LL);
        NTSTATUS st = nt_allocate_virtual_memory(current_process, &exec_mem, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(st) || !exec_mem) {
            return false;
        }
        memcpy(exec_mem, trampoline, trampoline_size);

        {
            PVOID tmp_base = exec_mem;
            SIZE_T tmp_sz = trampoline_size;
            ULONG oldProt = 0;
            st = nt_protect_virtual_memory(current_process, &tmp_base, &tmp_sz, PAGE_EXECUTE_READ, &oldProt);
            if (!NT_SUCCESS(st)) {
                PVOID free_base = exec_mem;
                SIZE_T free_size = trampoline_size;
                nt_free_virtual_memory(current_process, &free_base, &free_size, MEM_RELEASE);
                return false;
            }
        }

        nt_flush_instruction_cache(current_process, exec_mem, trampoline_size);

        u8 hitCount = 0;

        CONTEXT original_context{};
        original_context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        const HANDLE current_thread = reinterpret_cast<HANDLE>(-2LL);

        if (!NT_SUCCESS(nt_get_context_thread(current_thread, &original_context))) {
            PVOID free_base = exec_mem;
            SIZE_T free_size = trampoline_size;
            nt_free_virtual_memory(current_process, &free_base, &free_size, MEM_RELEASE);
            return false;
        }

        // Set DR0 to trampoline + 14 (Instruction: mov rbx, r8)
        // Offset calculation: mov_r8_rbx(3) + pushfq(1) + or(7) + popfq(1) + cpuid(2) = 14
        // This is where single step traps after CPUID, and where we want the collision
        const uintptr_t expected_trap_address = reinterpret_cast<uintptr_t>(exec_mem) + 14;

        // set Dr0 to trampoline+offset
        CONTEXT debug_context = original_context;
        debug_context.Dr0 = expected_trap_address; // single step breakpoint address
        debug_context.Dr7 = 1; // enable Local Breakpoint 0

        if (!NT_SUCCESS(nt_set_context_thread(current_thread, &debug_context))) {
            nt_set_context_thread(current_thread, &original_context);
            PVOID free_base = exec_mem;
            SIZE_T free_size = trampoline_size;
            nt_free_virtual_memory(current_process, &free_base, &free_size, MEM_RELEASE);
            return false;
        }

        // Context structure to pass data to the static SEH handler
        struct trap_context {
            uintptr_t expectedTrapAddr;
            u8* hitCount;
            bool* hypervisor_caught;
        };

        // Static class for SEH filtering to avoid Release mode Lambda corruption
        struct SEH_Trap {
            static LONG Vet(u32 code, EXCEPTION_POINTERS* info, trap_context* ctx) noexcept {
                // Lambda returns LONG to support EXCEPTION_CONTINUE_EXECUTION
                if (code != static_cast<DWORD>(0x80000004L)) {
                    return EXCEPTION_CONTINUE_SEARCH;
                }

                // Verify exception happened at our calculated offset
                if (reinterpret_cast<uintptr_t>(info->ExceptionRecord->ExceptionAddress) != ctx->expectedTrapAddr) {
                    info->ContextRecord->EFlags &= ~0x100; // Clear TF
                    info->ContextRecord->Dr7 &= ~1;        // Clear DR0 Enable
                    *ctx->hypervisor_caught = true;
                    return EXCEPTION_CONTINUE_EXECUTION;
                }

                (*ctx->hitCount)++;

                // check if Trap Flag and DR0 contributed
                constexpr u64 required_bits = (1ULL << 14) | 1ULL; // BS | B0
                const u64 status = info->ContextRecord->Dr6;

                if ((status & required_bits) != required_bits) {
                    if (util::hyper_x() != HYPERV_ARTIFACT_VM) // detects type 1 Hyper-V too, which we consider legitimate
                        *ctx->hypervisor_caught = true;
                }

                // Clear Trap Flag to stop single stepping
                info->ContextRecord->EFlags &= ~0x100;

                // Clear DR7 Local Enable 0 to disable the hardware breakpoint
                // If we don't do this, the next instruction will trigger the breakpoint again immediately
                info->ContextRecord->Dr7 &= ~1;

                // executes mov rbx, r8 (restore), and returns
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        };

        trap_context ctx = { expected_trap_address, &hitCount, &hypervisor_caught };

        __try {
            reinterpret_cast<void(*)()>(exec_mem)();
        }
        __except (SEH_Trap::Vet(_exception_code(), reinterpret_cast<EXCEPTION_POINTERS*>(_exception_info()), &ctx)) {
            // This block is effectively unreachable because vetExceptions returns CONTINUE_EXECUTION or CONTINUE_SEARCH
        }

        // If the hypervisor swallowed the exception entirely, hitCount will be 0
        if (hitCount != 1) {
            hypervisor_caught = true;
        }

        nt_set_context_thread(current_thread, &original_context);

        PVOID free_base = exec_mem;
        SIZE_T free_size = trampoline_size;
        nt_free_virtual_memory(current_process, &free_base, &free_size, MEM_RELEASE);
    #endif
        return hypervisor_caught;
    }


    /**
     * @brief Check if after executing an undefined instruction, a hypervisor misinterpret it as a system call
     * @category Windows
     * @implements VM::UD
     */
    [[nodiscard]] static bool ud() {
    #if (x86)
        // ud2; ret
        constexpr u8 ud_opcodes[] = { 0x0F, 0x0B, 0xC3 };
    #elif (ARM32)
        // udf #0; bx lr
        // (Little-endian for 0xE7F000F0 and 0xE12FFF1E)
        constexpr u8 ud_opcodes[] = { 0xF0, 0x00, 0xF0, 0xE7, 0x1E, 0xFF, 0x2F, 0xE1 };
    #elif (ARM64)
        // hlt #0; ret
        // (Little-endian for 0xD4400000 and 0xD65F03C0)
        constexpr u8 ud_opcodes[] = { 0x00, 0x00, 0x40, 0xD4, 0xC0, 0x03, 0x5F, 0xD6 };
    #else
        // architecture not supported by this check
        return false;
    #endif
        
        bool saw_ud = false;
        const HMODULE ntdll = util::get_ntdll();
        if (!ntdll) return false;

        const char* names[] = { "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtFlushInstructionCache", "NtFreeVirtualMemory" };
        void* funcs[ARRAYSIZE(names)] = {};
        util::get_function_address(ntdll, names, funcs, ARRAYSIZE(names));

        const auto nt_allocate_virtual_memory = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG)>(funcs[0]);
        const auto nt_protect_virtual_memory = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG)>(funcs[1]);
        const auto nt_flush_instruction_cache = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, PVOID, SIZE_T)>(funcs[2]);
        const auto nt_free_virtual_memory = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG)>(funcs[3]);

        if (!nt_allocate_virtual_memory || !nt_protect_virtual_memory || !nt_flush_instruction_cache || !nt_free_virtual_memory) {
            return false;
        }

        const HANDLE current_process = reinterpret_cast<HANDLE>(-1LL);
        PVOID base = nullptr;
        SIZE_T region_size = sizeof(ud_opcodes);
        NTSTATUS st = nt_allocate_virtual_memory(current_process, &base, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(st) || !base) {
            return false;
        }

        memcpy(base, ud_opcodes, sizeof(ud_opcodes));

        ULONG old_protection = 0;
        st = nt_protect_virtual_memory(current_process, &base, &region_size, PAGE_EXECUTE_READ, &old_protection);
        if (!NT_SUCCESS(st)) {
            nt_free_virtual_memory(current_process, &base, &region_size, MEM_RELEASE);
            return false;
        }

        nt_flush_instruction_cache(current_process, base, region_size);

        __try {
            reinterpret_cast<void(*)()>(base)();
        }
        __except (GetExceptionCode() == EXCEPTION_ILLEGAL_INSTRUCTION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
            saw_ud = true;
        }

        nt_free_virtual_memory(current_process, &base, &region_size, MEM_RELEASE);

        return !saw_ud;
    }


    /**
     * @brief Check if a hypervisor does not properly restore the interruptibility state after a VM-exit in compatibility mode
     * @category Windows
     * @implements VM::BLOCKSTEP
     */
    [[nodiscard]] static bool blockstep() {  
    #if (x86_32 && MSVC && !CLANG)
        volatile int saw_single_step = 0;

        __try
        {
            __asm
            {
                // set TF in EFLAGS
                pushfd
                or dword ptr[esp], 0x100
                popfd

                // execute MOV SS,AX (reload SS with itself) to force the interruptible state block
                mov ax, ss
                mov ss, ax // this blocks any debug exception for exactly one instruction

                // because TF was set, CPUID would normally cause a #DB on the next instruction.
                xor eax, eax
                cpuid

                // one extra instruction: on bare metal, TF's single-step now fires here
                nop

                pushfd
                and dword ptr[esp], 0xFFFFFEFF
                popfd
            }
        }
        __except (GetExceptionCode() == EXCEPTION_SINGLE_STEP
            ? EXCEPTION_EXECUTE_HANDLER
            : EXCEPTION_CONTINUE_SEARCH)
        {
            saw_single_step = 1;
        }
        return (saw_single_step == 0) ? true : false;
    #else
        return false;
    #endif
    }


    /**
     * @brief Check if Dark Byte's VM is present
     * @category Windows
     * @implements VM::DBVM
     */
    [[nodiscard]] static bool dbvm() {
    #if (!x86_64)
        return false;
    #else
        constexpr u64 PW1 = 0x0000000076543210ULL;
        constexpr u64 PW3 = 0x0000000090909090ULL;
        constexpr u32 PW2 = 0xFEDCBA98U;

        struct vmcall_info {
            u32 structsize;
            u32 level2pass;
            u32 command;
        };

        vmcall_info vmcall_info = {};
        u64 vmcall_result = 0;

        constexpr u8 intel_template[44] = {
            0x48,0xBA,0,0,0,0,0,0,0,0,                     // mov rdx, imm64   ; PW1
            0x48,0xB9,0,0,0,0,0,0,0,0,                     // mov rcx, imm64   ; PW3
            0x48,0xB8,0,0,0,0,0,0,0,0,                     // mov rax, imm64   ; &vmcallInfo
            0x0F,0x01,0xC1,                                // vmcall
            0x48,0xA3,0,0,0,0,0,0,0,0,                     // mov [imm64], rax ; &vmcallResult
            0xC3                                           // ret
        };

        constexpr u8 amd_template[44] = {
            0x48,0xBA,0,0,0,0,0,0,0,0,                     // mov rdx, imm64   ; PW1
            0x48,0xB9,0,0,0,0,0,0,0,0,                     // mov rcx, imm64   ; PW3
            0x48,0xB8,0,0,0,0,0,0,0,0,                     // mov rax, imm64   ; &vmcallInfo
            0x0F,0x01,0xD9,                                // vmmcall (AMD)
            0x48,0xA3,0,0,0,0,0,0,0,0,                     // mov [imm64], rax ; &vmcallResult
            0xC3                                           // ret
        };

        const SIZE_T stub_size = sizeof(intel_template);
        const bool is_amd = cpu::is_amd();

        const HANDLE current_process = reinterpret_cast<HANDLE>(-1LL);
        const HMODULE ntdll = util::get_ntdll();
        if (!ntdll) return false;

        const char* names[] = { "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtFlushInstructionCache", "NtFreeVirtualMemory" };
        void* funcs[ARRAYSIZE(names)] = {};
        util::get_function_address(ntdll, names, funcs, ARRAYSIZE(names));

        const auto nt_allocate_virtual_memory = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG)>(funcs[0]);
        const auto nt_protect_virtual_memory = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG)>(funcs[1]);
        const auto nt_flush_instruction_cache = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, PVOID, SIZE_T)>(funcs[2]);
        const auto nt_free_virtual_memory = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG)>(funcs[3]);

        if (!nt_allocate_virtual_memory || !nt_protect_virtual_memory || !nt_flush_instruction_cache || !nt_free_virtual_memory) {
            return false;
        }

        PVOID stub = nullptr;
        SIZE_T region_size = stub_size;
        NTSTATUS st = nt_allocate_virtual_memory(current_process, &stub, 0, &region_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(st) || !stub) return false;

        if (is_amd) {
            memcpy(stub, amd_template, stub_size);
        }
        else {
            memcpy(stub, intel_template, stub_size);
        }

        // rdx imm64
        // rcx imm64
        // rax imm64
        // mov [imm64], rax immediate
        *reinterpret_cast<u64*>(reinterpret_cast<u8*>(stub) + 2) = PW1;
        *reinterpret_cast<u64*>(reinterpret_cast<u8*>(stub) + 12) = PW3;
        *reinterpret_cast<u64*>(reinterpret_cast<u8*>(stub) + 22) = reinterpret_cast<u64>(static_cast<void*>(&vmcall_info));
        *reinterpret_cast<u64*>(reinterpret_cast<u8*>(stub) + 35) = reinterpret_cast<u64>(static_cast<void*>(&vmcall_result));

        ULONG old_protection = 0;
        st = nt_protect_virtual_memory(current_process, &stub, &region_size, PAGE_EXECUTE_READ, &old_protection);
        if (!NT_SUCCESS(st)) {
            nt_free_virtual_memory(current_process, &stub, &region_size, MEM_RELEASE);
            return false;
        }

        nt_flush_instruction_cache(current_process, stub, region_size);

        auto tryPass = [&]() noexcept -> bool {
            // store forwarding in modern CPUs
            vmcall_info.structsize = static_cast<u32>(sizeof(vmcall_info));
            vmcall_info.level2pass = PW2;
            vmcall_info.command = 0;
            vmcall_result = 0;

            __try {
                reinterpret_cast<void(*)()>(stub)();
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { // EXCEPTION_ILLEGAL_INSTRUCTION normally, EXCEPTION_ACCESS_VIOLATION_READ on edge-cases
                vmcall_result = 0;
            }

            return (((vmcall_result >> 24) & 0xFF) == 0xCE); // the VM returns status in bits 24–31; Cheat Engine uses 0xCE here
        };

        const bool found = tryPass();

        nt_free_virtual_memory(current_process, &stub, &region_size, MEM_RELEASE);

        if (found) return core::add(brands::DBVM);

        return false;
    #endif
    }


    /**
     * @brief Check boot logo for known VM images
     * @category Windows, x86_64
     * @author Teselka (https://github.com/Teselka)
     * @implements VM::BOOT_LOGO
     */
    [[nodiscard]] static bool boot_logo()
    #if (x86 && (CLANG || GCC))
        __attribute__((__target__("crc32")))
    #endif
    {
    #if (x86_64)
        const HMODULE ntdll = util::get_ntdll();
        if (!ntdll)
            return false;

        const char* function_names[] = { "NtQuerySystemInformation" };
        void* functions[1] = { nullptr };
        util::get_function_address(ntdll, function_names, functions, 1);

        using NtQuerySysInfo_t = NTSTATUS(__stdcall*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
        NtQuerySysInfo_t nt_query = reinterpret_cast<NtQuerySysInfo_t>(functions[0]);
        if (!nt_query)
            return false;

        // determine required buffer size
        const SYSTEM_INFORMATION_CLASS sys_boot_info = static_cast<SYSTEM_INFORMATION_CLASS>(140);
        ULONG needed = 0;
        NTSTATUS st = nt_query(sys_boot_info, nullptr, 0, &needed);
        if (st != static_cast<NTSTATUS>(0xC0000023) && st != static_cast<NTSTATUS>(0x80000005) && st != static_cast<NTSTATUS>(0xC0000004))
            return false;

        std::vector<u8> buffer(needed);

        // fetch the boot-logo data
        st = nt_query(sys_boot_info, buffer.data(), needed, &needed);
        if (!NT_SUCCESS(st))
            return false;

        // parse header to locate the bitmap
        struct boot_logo_info { ULONG flags, bitmap_offset; };
        const auto* info = reinterpret_cast<boot_logo_info*>(buffer.data());
        const u8* bmp = buffer.data() + info->bitmap_offset;
        const size_t size = static_cast<size_t>(needed) - info->bitmap_offset;

        // struct + function to isolate SEH from the stack frame containing std::vector and use __target__
        struct crc {
            #if (GCC || CLANG)
                __attribute__((__target__("sse4.2")))
            #endif
                static u32 compute(const u8* data, size_t len) {
                // 8 byte chunks
                u64 crcReg = 0xFFFFFFFFull;
                const size_t qwords = len >> 3;
                const auto* ptr = reinterpret_cast<const u64*>(data);

                size_t i = 0;

                __try {
                    // Unrolled loop
                    for (; i + 3 < qwords; i += 4) {
                        crcReg = _mm_crc32_u64(crcReg, ptr[i]);
                        crcReg = _mm_crc32_u64(crcReg, ptr[i + 1]);
                        crcReg = _mm_crc32_u64(crcReg, ptr[i + 2]);
                        crcReg = _mm_crc32_u64(crcReg, ptr[i + 3]);
                    }

                    for (; i < qwords; ++i) {
                        crcReg = _mm_crc32_u64(crcReg, ptr[i]);
                    }

                    u32 crc = static_cast<u32>(crcReg);
                    const auto* tail = reinterpret_cast<const u8*>(ptr + qwords);

                    for (size_t j = 0, r = len & 7; j < r; ++j) {
                        crc = _mm_crc32_u8(crc, tail[j]);
                    }
                    crc ^= 0xFFFFFFFFu;
                    return crc;
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    return 0;
                }
            }
        };

        const u32 hash = crc::compute(bmp, size);

        debug("BOOT_LOGO: size=", needed, ", flags=", info->flags, ", offset=", info->bitmap_offset, ", crc=0x", std::hex, hash);

        switch (hash) {
            case 0x110350C5: return core::add(brands::QEMU); // TianoCore EDK2
            case 0x87c39681: return core::add(brands::HYPERV);
            case 0xf6829262: return core::add(brands::VBOX);
            default:         return false;
        }
    #else
        return false;
    #endif
    }


    /**
     * @brief Check for any signs of VMs in Windows kernel object entities 
     * @category Windows
     * @implements VM::KERNEL_OBJECTS
     */
    [[nodiscard]] static bool kernel_objects() {
        struct OBJECT_DIRECTORY_INFORMATION {
            UNICODE_STRING Name;
            UNICODE_STRING TypeName;
        };

        using POBJECT_DIRECTORY_INFORMATION = OBJECT_DIRECTORY_INFORMATION*;
        constexpr auto DIRECTORY_QUERY = 0x0001;
        constexpr NTSTATUS STATUS_NO_MORE_ENTRIES = 0x8000001A;

        HANDLE dir = nullptr;
        OBJECT_ATTRIBUTES object_attributes{};
        UNICODE_STRING dir_name{};
        NTSTATUS status;

        const HMODULE ntdll = util::get_ntdll();
        if (!ntdll) return false;

        const char* names[] = { "NtOpenDirectoryObject", "NtQueryDirectoryObject", "NtClose" };
        void* funcs[ARRAYSIZE(names)] = {};
        util::get_function_address(ntdll, names, funcs, ARRAYSIZE(names));

        const auto nt_open_directory_object = reinterpret_cast<NTSTATUS(__stdcall*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)>(funcs[0]);
        const auto nt_query_directory_object = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG)>(funcs[1]);
        const auto nt_close = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE)>(funcs[2]);

        if (!nt_open_directory_object || !nt_query_directory_object || !nt_close) return false;

        // Prepare to open the root "\Device" directory in the Object Manager namespace
        // This is different from the file system and we are looking for kernel objects created by drivers
        const wchar_t* device_dir_path = L"\\Device";
        dir_name.Buffer = (PWSTR)device_dir_path;
        dir_name.Length = (USHORT)(wcslen(device_dir_path) * sizeof(wchar_t));
        dir_name.MaximumLength = dir_name.Length + sizeof(wchar_t);

        InitializeObjectAttributes(&object_attributes, &dir_name, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        // Open the directory object so we can enumerate its contents
        status = nt_open_directory_object(&dir, DIRECTORY_QUERY, &object_attributes);

        if (!NT_SUCCESS(status)) {
            return false;
        }

        // Set up a buffer for querying directory entries
        // We process entries one by one using a context index
        std::vector<BYTE> buffer(4096);
        constexpr size_t MAX_DIR_BUFFER = 64 * 1024;
        ULONG context = 0;
        ULONG returned_length = 0;

        while (true) {
            // Query the next single object in the directory
            // 'ReturnSingleEntry' is TRUE to simplify buffer parsing logic
            status = nt_query_directory_object(
                dir,
                buffer.data(),
                static_cast<ULONG>(buffer.size()),
                TRUE,
                FALSE,
                &context,
                &returned_length
            );

            // Stop if we have iterated through all objects
            if (status == STATUS_NO_MORE_ENTRIES) {
                break;
            }

            // Handle buffer sizing. If the buffer is too small, the kernel tells us how much it needs
            // We resize and retry, but impose a sanity cap to prevent memory issues
            if (!NT_SUCCESS(status)) {
                if (returned_length > buffer.size()) {
                    size_t new_size = static_cast<size_t>(returned_length);
                    if (new_size > MAX_DIR_BUFFER) new_size = MAX_DIR_BUFFER;
                    if (new_size <= buffer.size()) {
                        nt_close(dir);
                        return false;
                    }
                    try {
                        buffer.resize(new_size);
                    }
                    catch (...) {
                        nt_close(dir);
                        return false;
                    }
                    continue;
                }
                nt_close(dir);
                return false;
            }

            // Validate the returned data length to ensure we don't read out of bounds
            const size_t used_len = (returned_length == 0) ? buffer.size() : static_cast<size_t>(returned_length);
            if (used_len < sizeof(OBJECT_DIRECTORY_INFORMATION) || used_len > buffer.size()) {
                nt_close(dir);
                return false;
            }

            const POBJECT_DIRECTORY_INFORMATION object_directory_information = reinterpret_cast<POBJECT_DIRECTORY_INFORMATION>(buffer.data());

            // memory boundaries just for safe pointer arithmetic
            const uintptr_t buf_base = reinterpret_cast<uintptr_t>(buffer.data());
            const uintptr_t buf_end = buf_base + used_len;

            std::wstring object_name;
            bool found_name = false;

            // Extract the name using the explicit Name pointer in the structure
            // We strictly validate that the pointer falls within our allocated buffer to prevent crashes
            const size_t nameBytes = static_cast<size_t>(object_directory_information->Name.Length);
            const uintptr_t name_ptr = reinterpret_cast<uintptr_t>(object_directory_information->Name.Buffer);

            if (nameBytes > 0 && (nameBytes % sizeof(wchar_t) == 0)) {
                const uintptr_t min_valid_ptr = buf_base + sizeof(OBJECT_DIRECTORY_INFORMATION);
                if (name_ptr >= min_valid_ptr && (name_ptr + nameBytes) <= buf_end && (name_ptr % sizeof(wchar_t) == 0)) {
                    const wchar_t* wname = reinterpret_cast<const wchar_t*>(name_ptr);
                    const size_t wlen = nameBytes / sizeof(wchar_t);
                    bool found_term = false;
                    // scan for null terminator just in case
                    for (size_t i = 0; i < wlen; ++i) {
                        if (wname[i] == L'\0') { 
                            object_name.assign(wname, i); 
                            found_term = true;
                            break; 
                        }
                    }
                    if (!found_term) {
                        object_name.assign(wname, wlen);
                    }
                    found_name = true;
                }
            }

            // If the explicit pointer was invalid, assume the string data immediately follows the structure
            if (!found_name) {
                const uintptr_t altStart = buf_base + sizeof(OBJECT_DIRECTORY_INFORMATION);
                if (altStart >= buf_end) {
                    nt_close(dir);
                    return false;
                }
                const size_t maxBytes = buf_end - altStart;
                if (maxBytes < sizeof(wchar_t)) {
                    nt_close(dir);
                    return false;
                }
                const wchar_t* alt_ptr = reinterpret_cast<const wchar_t*>(buffer.data() + (altStart - buf_base));
                const size_t max_chars = maxBytes / sizeof(wchar_t);

                size_t realChars = 0;
                for (; realChars < max_chars; ++realChars) {
                    if (alt_ptr[realChars] == L'\0') break;
                }
                if (realChars == max_chars) {
                    nt_close(dir);
                    return false;
                }
                object_name.assign(alt_ptr, realChars);
                found_name = true;
            }

            if (!found_name) {
                nt_close(dir);
                return false;
            }

            // "VmGenerationCounter" and "VmGid" are created by the Hyper-V VM Bus provider
            if (object_name == L"VmGenerationCounter") {
                nt_close(dir);
                debug("KERNEL_OBJECTS: Detected VmGenerationCounter");
                return core::add(brands::HYPERV);
            }
            if (object_name == L"VmGid") {
                nt_close(dir);
                debug("KERNEL_OBJECTS: Detected VmGid");
                return core::add(brands::HYPERV);
            }
        }

        nt_close(dir);
        return false;
    }


    /**
     * @brief Check for known NVRAM signatures that are present on virtual firmware
     * @category Windows
     * @warning Permissions required
     * @implements VM::NVRAM
     */
    static bool nvram() {
        struct VARIABLE_NAME { ULONG NextEntryOffset; GUID VendorGuid; WCHAR Name[1]; };
        using variable_name_ptr = VARIABLE_NAME*;
        using nt_enumerate_system_environment_values_ex_t = NTSTATUS(__stdcall*)(ULONG, PVOID, PULONG);
        using nt_query_system_environment_value_ex_t = NTSTATUS(__stdcall*)(PUNICODE_STRING VariableName, LPGUID VendorGuid, PVOID Value, PULONG ValueLength, PULONG Attributes);
        using nt_allocate_virtual_memory_t = NTSTATUS(__stdcall*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
        using nt_free_virtual_memory_t = NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG);

        // Secure Boot stuff
        bool found_dbx_default = false;
        bool found_kek_default = false;
        bool found_pk_default = false;

        /*
            MemoryOverwriteRequestControlLock is part of a state machine defined in the TCG Platform Reset Attack Mitigation Specification
            the SMM driver expects to initialize and manage this variable itself during the DXE phase of booting
            Secure Boot, TPM and SMM must be enabled to set it
        */
        bool found_morcl = false;
        bool detection_result = false;

        // Handles and Buffers
        HANDLE token_handle = nullptr;
        PVOID enum_base_buffer = nullptr;
        BYTE* pk_default_buf = nullptr;
        BYTE* pk_buf = nullptr;
        BYTE* kek_default_buf = nullptr;
        BYTE* kek_buf = nullptr;
        bool privileges_enabled = false;
        LUID luid_struct{};

        // Function Pointers
        nt_enumerate_system_environment_values_ex_t nt_enumerate_values = nullptr;
        nt_allocate_virtual_memory_t nt_allocate_memory = nullptr;
        nt_free_virtual_memory_t nt_free_memory = nullptr;
        nt_query_system_environment_value_ex_t nt_query_value = nullptr;

        const HANDLE current_process_handle = reinterpret_cast<HANDLE>(-1LL);

        const char* manufacturer_str = "";
        const char* model_str = "";
        util::get_manufacturer_model(&manufacturer_str, &model_str);

        // -------------------------------------------------------------------------
        // Helper Lambdas
        // -------------------------------------------------------------------------

        auto buffer_contains_ascii_ci = [](const BYTE* data, size_t len, const char* pat) noexcept -> bool {
            if (!data || len == 0 || !pat) return false;
            const size_t plen = strlen(pat); if (len < plen) return false;
            const BYTE p0 = static_cast<BYTE>((pat[0] >= 'A' && pat[0] <= 'Z') ? (pat[0] + 32) : pat[0]);
            const BYTE* end = data + (len - plen);
            for (const BYTE* p = data; p <= end; ++p) {
                BYTE c0 = *p; c0 = static_cast<BYTE>((c0 >= 'A' && c0 <= 'Z') ? (c0 + 32) : c0);
                if (c0 != p0) continue;
                bool ok = true;
                for (size_t j = 1; j < plen; ++j) {
                    BYTE dj = p[j]; dj = static_cast<BYTE>((dj >= 'A' && dj <= 'Z') ? (dj + 32) : dj);
                    BYTE pj = static_cast<BYTE>((pat[j] >= 'A' && pat[j] <= 'Z') ? (pat[j] + 32) : pat[j]);
                    if (dj != pj) { ok = false; break; }
                }
                if (ok) return true;
            }
            return false;
        };

        auto buffer_contains_utf16le_ci = [](const WCHAR* data, size_t wlen, const wchar_t* pat) noexcept -> bool {
            if (!data || wlen == 0 || !pat) return false;
            const size_t plen = wcslen(pat); if (wlen < plen) return false;
            const WCHAR p0 = static_cast<WCHAR>((pat[0] >= L'A' && pat[0] <= L'Z') ? (pat[0] + 32) : pat[0]);
            const WCHAR* end = data + (wlen - plen);
            for (const WCHAR* p = data; p <= end; ++p) {
                WCHAR c0 = *p; c0 = static_cast<WCHAR>((c0 >= L'A' && c0 <= L'Z') ? (c0 + 32) : c0);
                if (c0 != p0) continue;
                bool ok = true;
                for (size_t j = 1; j < plen; ++j) {
                    WCHAR dj = p[j]; dj = static_cast<WCHAR>((dj >= L'A' && dj <= L'Z') ? (dj + 32) : dj);
                    WCHAR pj = static_cast<WCHAR>((pat[j] >= L'A' && pat[j] <= L'Z') ? (pat[j] + 32) : pat[j]);
                    if (dj != pj) { ok = false; break; }
                }
                if (ok) return true;
            }
            return false;
        };

        // -------------------------------------------------------------------------
        // Main Logic Block
        // -------------------------------------------------------------------------

        do {
            if (!util::is_admin()) break;

            if (!OpenProcessToken(current_process_handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle)) break;

            if (!LookupPrivilegeValue(nullptr, SE_SYSTEM_ENVIRONMENT_NAME, &luid_struct)) break;

            TOKEN_PRIVILEGES tp_enable{};
            tp_enable.PrivilegeCount = 1;
            tp_enable.Privileges[0].Luid = luid_struct;
            tp_enable.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(token_handle, FALSE, &tp_enable, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);
            if (GetLastError() != ERROR_SUCCESS) break;
            privileges_enabled = true;

            const HMODULE ntdll_module = util::get_ntdll();
            if (!ntdll_module) break;

            const char* func_names[] = { "NtEnumerateSystemEnvironmentValuesEx", "NtAllocateVirtualMemory", "NtFreeVirtualMemory", "NtQuerySystemEnvironmentValueEx" };
            void* resolved_funcs[sizeof(func_names) / sizeof(func_names[0])] = {};
            util::get_function_address(ntdll_module, func_names, resolved_funcs, sizeof(func_names) / sizeof(func_names[0]));

            nt_enumerate_values = reinterpret_cast<nt_enumerate_system_environment_values_ex_t>(resolved_funcs[0]);
            nt_allocate_memory = reinterpret_cast<nt_allocate_virtual_memory_t>(resolved_funcs[1]);
            nt_free_memory = reinterpret_cast<nt_free_virtual_memory_t>(resolved_funcs[2]);
            nt_query_value = reinterpret_cast<nt_query_system_environment_value_ex_t>(resolved_funcs[3]);

            if (!nt_enumerate_values || !nt_allocate_memory || !nt_free_memory || !nt_query_value) break;

            bool has_function = false;
            bool call_success = false;
            SIZE_T enum_alloc_size = 0;
            ULONG buffer_required_length = 0;

            // ask for size
            if (nt_enumerate_values) {
                has_function = true;
                nt_enumerate_values(static_cast<ULONG>(1), nullptr, &buffer_required_length);

                if (buffer_required_length != 0) {
                    enum_alloc_size = static_cast<SIZE_T>(buffer_required_length);
                    NTSTATUS alloc_status = nt_allocate_memory(current_process_handle, &enum_base_buffer, 0, &enum_alloc_size, static_cast<ULONG>(MEM_COMMIT | MEM_RESERVE), static_cast<ULONG>(PAGE_READWRITE));

                    if (alloc_status == 0 && enum_base_buffer) {
                        alloc_status = nt_enumerate_values(static_cast<ULONG>(1), enum_base_buffer, &buffer_required_length);
                        if (alloc_status == 0) {
                            call_success = true;
                        }
                        else {
                            SIZE_T zero_size = 0;
                            nt_free_memory(current_process_handle, &enum_base_buffer, &zero_size, 0x8000);
                            enum_base_buffer = nullptr;
                            enum_alloc_size = 0;
                        }
                    }
                }
            }

            if (!has_function) {
                debug("NVRAM: NtEnumerateSystemEnvironmentValuesEx could not be resolved");
                detection_result = false;
                break;
            }
            if (!call_success) {
                debug("NVRAM: System is not UEFI");
                detection_result = false;
                break;
            }

            // ---------------------------------------------------------------------
            // Constants & Data
            // ---------------------------------------------------------------------
            constexpr const char* vendor_list_ascii[] = { "msi","asrock","asus","asustek","gigabyte","giga-byte","micro-star","microstar" };
            constexpr const wchar_t* vendor_list_wide[] = { L"msi",L"asrock",L"asus",L"asustek",L"gigabyte",L"giga-byte",L"micro-star",L"microstar" };
            constexpr const char redhat_sig_ascii[] = "red hat";
            constexpr const wchar_t redhat_sig_wide[] = L"red hat";

            SIZE_T pk_default_len = 0;
            SIZE_T pk_len = 0;
            SIZE_T kek_default_len = 0;
            SIZE_T kek_len = 0;

            const GUID EFI_GLOBAL_VARIABLE = { 0x8BE4DF61, 0x93CA, 0x11D2, {0xAA,0x0D,0x00,0xE0,0x98,0x03,0x2B,0x8C} };

            // Helper to read 1-byte UEFI variables like SecureBoot or SetupMode
            auto read_uint8_var = [&](const std::wstring& name, const GUID& g, u8& out) noexcept -> bool {
                if (!nt_query_value || !nt_allocate_memory || !nt_free_memory) return false;
                UNICODE_STRING uni_str{};
                uni_str.Buffer = const_cast<PWSTR>(name.c_str());
                uni_str.Length = static_cast<USHORT>(name.length() * sizeof(wchar_t));
                uni_str.MaximumLength = uni_str.Length + sizeof(wchar_t);

                ULONG required_size = 0;
                NTSTATUS status = nt_query_value(&uni_str, const_cast<LPGUID>(&g), nullptr, &required_size, nullptr);
                if (required_size == 0) return false;

                PVOID allocation_base = nullptr;
                SIZE_T alloc_size = required_size;
                if (alloc_size < 0x1000) alloc_size = 0x1000;

                status = nt_allocate_memory(current_process_handle, &allocation_base, 0, &alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (status != 0 || !allocation_base) { return false; }

                status = nt_query_value(&uni_str, const_cast<LPGUID>(&g), allocation_base, &required_size, nullptr);
                if (status == 0 && required_size >= 1) {
                    out = *reinterpret_cast<u8*>(allocation_base);
                    SIZE_T z = 0;
                    nt_free_memory(current_process_handle, &allocation_base, &z, 0x8000);
                    return true;
                }

                SIZE_T zero_s = 0;
                nt_free_memory(current_process_handle, &allocation_base, &zero_s, 0x8000);
                return false;
            };

            bool have_secureboot = false;
            u8 secureboot_val = 0;
            if (read_uint8_var(L"SecureBoot", EFI_GLOBAL_VARIABLE, secureboot_val)) {
                have_secureboot = true;
                debug("NVRAM: SecureBoot variable detected");
            }

            bool have_setupmode = false;
            u8 setupmode_val = 0;
            if (read_uint8_var(L"SetupMode", EFI_GLOBAL_VARIABLE, setupmode_val)) {
                have_setupmode = true;
                debug("NVRAM: SetupMode variable detected");
            }

            // Determine whether it's safe to run Secure Boot dependent checks
            const bool sb_active = (have_secureboot && (secureboot_val == 1) && have_setupmode && (setupmode_val == 0));
            if (!sb_active) {
                debug("NVRAM: Secure Boot not confirmed active, disabling MOCRL and raw buffer mismatch checks...");
            }

            auto read_variable_to_buffer = [&](const std::wstring& name, GUID& guid, BYTE*& out_buf, SIZE_T& out_len) noexcept -> bool {
                UNICODE_STRING uni_str{};
                uni_str.Buffer = const_cast<PWSTR>(name.c_str());
                uni_str.Length = static_cast<USHORT>(name.length() * sizeof(wchar_t));
                uni_str.MaximumLength = uni_str.Length + sizeof(wchar_t);

                ULONG required_size = 0;
                NTSTATUS status = nt_query_value(&uni_str, &guid, nullptr, &required_size, nullptr);

                if (required_size == 0) return false;

                PVOID allocation_base = nullptr;
                SIZE_T alloc_size = required_size;
                if (alloc_size < 0x1000) alloc_size = 0x1000;

                status = nt_allocate_memory(current_process_handle, &allocation_base, 0, &alloc_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (status != 0 || !allocation_base) { 
                    out_buf = nullptr;
                    out_len = 0; 
                    return false; 
                }

                status = nt_query_value(&uni_str, &guid, allocation_base, &required_size, nullptr);
                if (status == 0) {
                    out_buf = reinterpret_cast<BYTE*>(allocation_base);
                    out_len = required_size;
                    return true;
                }

                SIZE_T zero_s = 0;
                nt_free_memory(current_process_handle, &allocation_base, &zero_s, 0x8000);
                out_buf = nullptr;
                out_len = 0;
                return false;
            };

            variable_name_ptr current_var = reinterpret_cast<variable_name_ptr>(enum_base_buffer);
            const size_t buffer_total_size = static_cast<size_t>(buffer_required_length);
            constexpr size_t MAX_NAME_BYTE_LIMIT = 4096;

            bool should_break_loop = false;

            // ---------------------------------------------------------------------
            // Iteration Loop
            // ---------------------------------------------------------------------
            while (true) {
                const uintptr_t base_address = reinterpret_cast<uintptr_t>(enum_base_buffer);
                const uintptr_t current_address = reinterpret_cast<uintptr_t>(current_var);

                if (current_address < base_address) break;

                const size_t current_offset = static_cast<size_t>(current_address - base_address);
                if (current_offset >= buffer_total_size) break;

                const size_t name_struct_offset = offsetof(VARIABLE_NAME, Name);
                if (buffer_total_size - current_offset < name_struct_offset) break;

                size_t name_max_bytes = 0;
                if (current_var->NextEntryOffset != 0) {
                    const SIZE_T next_entry = static_cast<SIZE_T>(current_var->NextEntryOffset);
                    if (next_entry <= name_struct_offset) { 
                        detection_result = false; 
                        should_break_loop = true; 
                        break;
                    }
                    if (next_entry > buffer_total_size - current_offset) break;
                    name_max_bytes = next_entry - name_struct_offset;
                }
                else {
                    if (current_offset + name_struct_offset >= buffer_total_size) {
                        detection_result = false; 
                        should_break_loop = true;
                        break; 
                    }
                    name_max_bytes = buffer_total_size - (current_offset + name_struct_offset);
                }

                if (name_max_bytes > MAX_NAME_BYTE_LIMIT) name_max_bytes = MAX_NAME_BYTE_LIMIT;

                std::wstring var_name_view;
                if (name_max_bytes >= sizeof(WCHAR)) {
                    const WCHAR* name_ptr = reinterpret_cast<const WCHAR*>(reinterpret_cast<const BYTE*>(current_var) + name_struct_offset);
                    const size_t max_chars = name_max_bytes / sizeof(WCHAR);
                    size_t real_chars = 0;
                    while (real_chars < max_chars && name_ptr[real_chars] != L'\0') 
                        ++real_chars;
                    if (real_chars == max_chars) { 
                        detection_result = false; 
                        should_break_loop = true;
                        break; 
                    }
                    var_name_view = std::wstring(name_ptr, real_chars);
                }

                // Presence checks
                if (!var_name_view.empty() && var_name_view.rfind(L"VMM", 0) == 0) {
                    debug("NVRAM: Detected hypervisor signature");
                    detection_result = true;
                    should_break_loop = true;
                    break;
                }
                else if (var_name_view == L"KEKDefault") found_kek_default = true;
                else if (var_name_view == L"PKDefault") found_pk_default = true;
                else if (var_name_view == L"dbxDefault") found_dbx_default = true;
                else if (var_name_view == L"MemoryOverwriteRequestControlLock") found_morcl = true;

                // Read specific variables (later checks that act on them will only be performed if Secure Boot was explicitly confirmed active)
                if (var_name_view == L"PKDefault") (void)read_variable_to_buffer(std::wstring(var_name_view), current_var->VendorGuid, pk_default_buf, pk_default_len);
                else if (var_name_view == L"PK") (void)read_variable_to_buffer(std::wstring(var_name_view), current_var->VendorGuid, pk_buf, pk_len);
                else if (var_name_view == L"KEKDefault") (void)read_variable_to_buffer(std::wstring(var_name_view), current_var->VendorGuid, kek_default_buf, kek_default_len);
                else if (var_name_view == L"KEK") (void)read_variable_to_buffer(std::wstring(var_name_view), current_var->VendorGuid, kek_buf, kek_len);

                if (current_var->NextEntryOffset == 0) break;
                const SIZE_T next_entry_off = static_cast<SIZE_T>(current_var->NextEntryOffset);
                if (next_entry_off == 0) break;
                const size_t next_var_offset = current_offset + next_entry_off;
                if (next_var_offset <= current_offset || next_var_offset > buffer_total_size) break;
                current_var = reinterpret_cast<variable_name_ptr>(reinterpret_cast<PBYTE>(enum_base_buffer) + next_var_offset);
            }

            if (should_break_loop) break;

            // free enumeration buffer
            { 
                SIZE_T z = 0; 
                nt_free_memory(current_process_handle, &enum_base_buffer, &z, 0x8000); 
                enum_base_buffer = nullptr; 
                enum_alloc_size = 0; 
            }

            // ---------------------------------------------------------------------
            // EFI variable analysis
            // ---------------------------------------------------------------------
            if (sb_active) {
                if (!found_morcl) {
                    debug("NVRAM: Missing MemoryOverwriteRequestControlLock"); detection_result = true;
                    break;
                }
            }
            if (!found_dbx_default) {
                debug("NVRAM: Missing dbxDefault"); detection_result = true;
                break;
            }
            if (!found_kek_default) {
                debug("NVRAM: Missing KEKDefault"); detection_result = true;
                break;
            }
            if (!found_pk_default) {
                debug("NVRAM: Missing PKDefault"); detection_result = true;
                break;
            }

            // check for official red hat certs (QEMU/OVMF)
            bool found_redhat = false;
            if (pk_default_buf && pk_default_len) {
                if ((pk_default_len >= 2) && ((pk_default_len % 2) == 0)) {
                    const WCHAR* wptr = reinterpret_cast<const WCHAR*>(pk_default_buf);
                    const size_t wlen = pk_default_len / sizeof(WCHAR);
                    if (buffer_contains_utf16le_ci(wptr, wlen, redhat_sig_wide))
                        found_redhat = true;
                }
                if (!found_redhat)
                    if (buffer_contains_ascii_ci(pk_default_buf, pk_default_len, redhat_sig_ascii))
                        found_redhat = true;
            }
            if (found_redhat) {
                debug("NVRAM: QEMU/OVMF detected");
                detection_result = core::add(brands::QEMU);
                break;
            }

            // vendor string checks and PK/KEK mismatch checks
            auto buffer_has_any_vendor = [&](BYTE* buf, SIZE_T len) noexcept -> bool {
                if (!buf || len == 0) return false;
                if ((len >= 2) && ((len % 2) == 0)) {
                    const WCHAR* wptr = reinterpret_cast<const WCHAR*>(buf); const size_t wlen = len / sizeof(WCHAR);
                    for (const wchar_t* p : vendor_list_wide)
                        if (buffer_contains_utf16le_ci(wptr, wlen, p))
                            return true;
                }
                for (const char* p : vendor_list_ascii)
                    if (buffer_contains_ascii_ci(buf, len, p))
                        return true;
                return false;
            };
            auto buffer_has_specific_vendor = [&](BYTE* buf, SIZE_T len, const char* a, const wchar_t* w) noexcept -> bool {
                if (!buf || len == 0) return false;
                if ((len >= 2) && ((len % 2) == 0) && w) {
                    const WCHAR* wp = reinterpret_cast<const WCHAR*>(buf);
                    if (buffer_contains_utf16le_ci(wp, len / sizeof(WCHAR), w))
                        return true;
                }
                if (a)
                    if (buffer_contains_ascii_ci(buf, len, a))
                        return true;
                return false;
            };

            if (sb_active) {
                const bool pk_def_has_vendor = buffer_has_any_vendor(pk_default_buf, pk_default_len);
                const bool kek_def_has_vendor = buffer_has_any_vendor(kek_default_buf, kek_default_len);

                if (pk_def_has_vendor || kek_def_has_vendor) {
                    bool vendor_mismatch = false;
                    for (size_t i = 0; i < sizeof(vendor_list_ascii) / sizeof(*vendor_list_ascii); ++i) {
                        const char* vendor_asc = vendor_list_ascii[i];
                        const wchar_t* vendor_w = vendor_list_wide[i];

                        const bool in_pk_def = buffer_has_specific_vendor(pk_default_buf, pk_default_len, vendor_asc, vendor_w);
                        const bool in_kek_def = buffer_has_specific_vendor(kek_default_buf, kek_default_len, vendor_asc, vendor_w);

                        if (!in_pk_def && !in_kek_def) continue;

                        const bool in_pk_active = buffer_has_specific_vendor(pk_buf, pk_len, vendor_asc, vendor_w);
                        const bool in_kek_active = buffer_has_specific_vendor(kek_buf, kek_len, vendor_asc, vendor_w);

                        // If the Default contains the vendor but the active variable is missing entirely
                        if (in_pk_def && pk_len == 0) {
                            std::string msg = "NVRAM: PKDefault contains vendor '";
                            msg += vendor_asc;
                            msg += "' but active PK variable is missing";
                            debug(msg.c_str());
                            detection_result = true;
                            vendor_mismatch = true;
                            break;
                        }
                        if (in_kek_def && kek_len == 0) {
                            std::string msg = "NVRAM: KEKDefault contains vendor '";
                            msg += vendor_asc;
                            msg += "' but active KEK variable is missing";
                            debug(msg.c_str());
                            detection_result = true;
                            vendor_mismatch = true;
                            break;
                        }

                        // If the active variable exists but does not contain the same vendor string
                        if (in_pk_def && pk_len != 0 && !in_pk_active) {
                            std::string msg = "NVRAM: Vendor string '";
                            msg += vendor_asc;
                            msg += "' found in PKDefault but missing from active PK";
                            debug(msg.c_str());
                            detection_result = true;
                            vendor_mismatch = true;
                            break;
                        }
                        if (in_kek_def && kek_len != 0 && !in_kek_active) {
                            std::string msg = "NVRAM: Vendor string '";
                            msg += vendor_asc;
                            msg += "' found in KEKDefault but missing from active KEK";
                            debug(msg.c_str());
                            detection_result = true;
                            vendor_mismatch = true;
                            break;
                        }
                    }
                    if (vendor_mismatch) break;
                }

                if (pk_default_buf && pk_buf && (pk_default_len != pk_len || memcmp(pk_default_buf, pk_buf, static_cast<size_t>(pk_default_len < pk_len ? pk_default_len : pk_len)) != 0)) {
                    debug("NVRAM: PK vs PKDefault raw mismatch detected");
                    detection_result = true;
                    break;
                }
                if (kek_default_buf && kek_buf && (kek_default_len != kek_len || memcmp(kek_default_buf, kek_buf, static_cast<size_t>(kek_default_len < kek_len ? kek_default_len : kek_len)) != 0)) {
                    debug("NVRAM: KEK vs KEKDefault raw mismatch detected");
                    detection_result = true;
                    break;
                }
            }

            detection_result = false;

        } while (false);

        // cleanup
        auto cleanup = [&](auto& ptr) {
            if (ptr) {
                PVOID base = ptr;
                SIZE_T size = 0;
                nt_free_memory(current_process_handle, &base, &size, 0x8000);
                ptr = nullptr;
            }
        };

        cleanup(pk_buf);
        cleanup(kek_buf);
        cleanup(pk_default_buf);
        cleanup(kek_default_buf);
        cleanup(enum_base_buffer);

        if (privileges_enabled && token_handle) {
            TOKEN_PRIVILEGES tp_disable{};
            tp_disable.PrivilegeCount = 1;
            tp_disable.Privileges[0].Luid = luid_struct;
            tp_disable.Privileges[0].Attributes = 0;
            AdjustTokenPrivileges(token_handle, FALSE, &tp_disable, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);
        }
        if (token_handle) {
            CloseHandle(token_handle);
            token_handle = nullptr;
        }

        return detection_result;
    }


    /**
	 * @brief Check if SMBIOS is malformed/corrupted in a way that is typical for VMs
     * @category Windows
     * @implements VM::SMBIOS_INTEGRITY
     */
    [[nodiscard]] static bool smbios_integrity() {
        ULONGLONG total_memory_in_kilobytes;
        return !GetPhysicallyInstalledSystemMemory(&total_memory_in_kilobytes);
    }


    /**
     * @brief Check for non-standard EDID configurations
     * @category Windows
     * @implements VM::EDID
     */
    [[nodiscard]] static bool edid() {
        auto decode_manufacturer = [](const BYTE* edid, char out[4]) noexcept {
            const u16 word = static_cast<u16>((edid[8] << 8) | edid[9]);

            // 5 bits per character. 0x01='A', 0x1A='Z'
            const u8 c1 = static_cast<u8>((word >> 10) & 0x1F);
            const u8 c2 = static_cast<u8>((word >> 5) & 0x1F);
            const u8 c3 = static_cast<u8>(word & 0x1F);

            // '?' is fallback for valid EDID range 1-26
            out[0] = (c1 >= 1 && c1 <= 26) ? static_cast<char>('A' + c1 - 1) : '?';
            out[1] = (c2 >= 1 && c2 <= 26) ? static_cast<char>('A' + c2 - 1) : '?';
            out[2] = (c3 >= 1 && c3 <= 26) ? static_cast<char>('A' + c3 - 1) : '?';
            out[3] = '\0';
        };

        auto is_three_upper_alpha = [](const char m[4]) noexcept -> bool {
            return (m[0] >= 'A' && m[0] <= 'Z') &&
                (m[1] >= 'A' && m[1] <= 'Z') &&
                (m[2] >= 'A' && m[2] <= 'Z');
        };

        auto edid_checksum_valid = [](const BYTE* edid, size_t len) noexcept -> bool {
            if (len < 128) return false;

            u8 sum = 0;
            const BYTE* end = edid + 128;

            while (edid < end) {
                sum += *edid++;
            }

            return sum == 0;
        };

        auto extract_monitor_name = [](const BYTE* edid, size_t len, char out[32]) noexcept -> bool {
            out[0] = '\0';
            if (len < 128) return false;

            // Standard EDID 1.3/1.4 Descriptor offsets
            const BYTE* block = edid + 54;
            const BYTE* end = edid + 126; // block area

            const BYTE* best_block = nullptr;

            for (; block <= end - 18; block += 18) {
                // bytes 0-2 must be 0 to indicate a Display Descriptor
                if (block[0] != 0 || block[1] != 0 || block[2] != 0) continue;

                const u8 tag = block[3];

                // 0xFC = Monitor Name
                if (tag == 0xFC) {
                    best_block = block;
                    break;
                }

                // 0xFF = Monitor Serial (this is only a fallback)
                if (tag == 0xFF && !best_block) {
                    best_block = block;
                }
            }

            if (best_block) {
                int outi = 0;
                for (int j = 5; j < 18 && outi < 31; ++j) {
                    const char c = static_cast<char>(best_block[j]);
                    // Terminate on newline (0x0A) or carriage return (0x0D) or null
                    if (c == 0x0A || c == 0x0D || c == '\0') break;
                    out[outi++] = c;
                }

                // right-trim spaces
                while (outi > 0 && (out[outi - 1] == ' ' || out[outi - 1] == '\t')) {
                    --outi;
                }

                out[outi] = '\0';
                return outi > 0;
            }

            return false;
        };

        // Helper lambda to retrieve device properties from the registry
        auto get_device_property = [](HDEVINFO dev_info, SP_DEVINFO_DATA& dev_data, DWORD prop_id,
            char* out_buf, DWORD out_buf_size) noexcept -> bool {
                DWORD needed = 0;

                // Try to get the property with the provided buffer
                if (SetupDiGetDeviceRegistryPropertyA(dev_info, &dev_data, prop_id, nullptr,
                    reinterpret_cast<PBYTE>(out_buf), out_buf_size, &needed)) {
                    if (out_buf_size > 0) out_buf[out_buf_size - 1] = '\0';
                    return true;
                }

                const DWORD err = GetLastError();

                // If the buffer was too small, allocate exactly what is needed and try again
                // This ensures we don't fail just because a property string is unusually long
                if (err == ERROR_INSUFFICIENT_BUFFER && needed > 0 && needed < 65536) {

                    void* h = malloc(static_cast<size_t>(needed) + 1);
                    if (!h) return false;

                    if (SetupDiGetDeviceRegistryPropertyA(dev_info, &dev_data, prop_id, nullptr,
                        reinterpret_cast<PBYTE>(h), needed, &needed)) {

                        const DWORD to_copy = (needed < out_buf_size - 1) ? needed : (out_buf_size - 1);

                        if (out_buf_size > 0) {
                            memcpy(out_buf, h, to_copy);
                            out_buf[to_copy] = '\0';
                        }

                        free(h);
                        return true;
                    }
                    free(h);
                }

                if (out_buf_size > 0) out_buf[0] = '\0';
                return false;
        };

        // Initiate a query for all "Monitor" class devices present in the system.
        // We target monitors because VMs often emulate generic displays (e.g., "Generic Non-PnP Monitor")
        // or specific virtual hardware signatures in their EDID data.
        const HDEVINFO dev_info = SetupDiGetClassDevs(&GUID_DEVCLASS_MONITOR, nullptr, nullptr, DIGCF_PRESENT);
        if (dev_info == INVALID_HANDLE_VALUE) return false;

        SP_DEVINFO_DATA dev_data{};
        dev_data.cbSize = sizeof(dev_data);

        const int threshold = 3;

        // Iterate through every enumerated monitor to inspect its hardware details
        for (DWORD index = 0; SetupDiEnumDeviceInfo(dev_info, index, &dev_data); ++index) {
            // Open the "Hardware" registry key for the specific device instance
            // This is where the driver stores low-level configuration, including the EDID
            const HKEY handle_dev_key = SetupDiOpenDevRegKey(dev_info, &dev_data, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ);
            if (handle_dev_key == INVALID_HANDLE_VALUE) {
                dev_data = {};
                dev_data.cbSize = sizeof(dev_data);
                continue;
            }

            // Prepare to read the EDID (Extended Display Identification Data)
            // EDID is a standard data structure containing the display's manufacturer ID, 
            // serial number, and capabilities
            BYTE edid_stack[256];
            DWORD buffer_size = static_cast<DWORD>(sizeof(edid_stack));
            const LONG rc = RegQueryValueExA(handle_dev_key, "EDID", nullptr, nullptr, edid_stack, &buffer_size);
            RegCloseKey(handle_dev_key);

            BYTE* edid = nullptr;
            bool used_heap = false;
            BYTE* heap_buf = nullptr;

            // standard EDID is 128 bytes so it should fit in stack
            if (rc == ERROR_SUCCESS && buffer_size >= 128) {
                edid = edid_stack;
            }
            // If for some reason the EDID contains extension blocks (making it larger than our stack buffer)
            // allocate a heap buffer dynamically to capture the full data
            else if (rc == ERROR_MORE_DATA) {
                if (buffer_size > 0 && buffer_size < 65536) {
                    heap_buf = static_cast<BYTE*>(LocalAlloc(LMEM_FIXED, buffer_size));
                    if (heap_buf) {
                        DWORD extra_buffer_size = buffer_size;
                        // Re-open the key to read the full data into the new buffer
                        const HKEY extra_dev_key = SetupDiOpenDevRegKey(dev_info, &dev_data, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ);
                        if (extra_dev_key != INVALID_HANDLE_VALUE) {
                            if (RegQueryValueExA(extra_dev_key, "EDID", nullptr, nullptr, heap_buf, &extra_buffer_size) == ERROR_SUCCESS && extra_buffer_size >= 128) {
                                edid = heap_buf;
                                used_heap = true;
                                buffer_size = extra_buffer_size;
                            }
                            RegCloseKey(extra_dev_key);
                        }
                        if (!edid) {
                            LocalFree(heap_buf);
                            heap_buf = nullptr;
                        }
                    }
                }
            }

            if (!edid) {
                dev_data = {};
                dev_data.cbSize = sizeof(dev_data);
                continue;
            }

            // header check
            if (!(edid[0] == 0x00 && edid[1] == 0xFF && edid[2] == 0xFF && edid[3] == 0xFF
                && edid[4] == 0xFF && edid[5] == 0xFF && edid[6] == 0xFF && edid[7] == 0x00)) {
                if (used_heap) LocalFree(heap_buf);
                dev_data = {};
                dev_data.cbSize = sizeof(dev_data);
                continue;
            }

            const bool checksum_ok = edid_checksum_valid(edid, buffer_size);

            char manu[4];
            decode_manufacturer(edid, manu);
            const bool manu_ok = is_three_upper_alpha(manu);

            const u16 product = static_cast<u16>(edid[10] | (edid[11] << 8)); // because its little-endian
            const u32 serial = static_cast<u32>(edid[12] | (edid[13] << 8) | (edid[14] << 16) | (edid[15] << 24));

            char monname[32];
            const bool has_name = extract_monitor_name(edid, buffer_size, monname);

            char prop_buf[512];
            const bool have_friendly = get_device_property(dev_info, dev_data, SPDRP_FRIENDLYNAME, prop_buf, sizeof(prop_buf)); // friendly_name is often empty, like in Digital-Flachbildschirm monitors
            const bool have_dev_desc = get_device_property(dev_info, dev_data, SPDRP_DEVICEDESC, prop_buf, sizeof(prop_buf));

            int score = 0;

            if (!checksum_ok) score += 1;
            if (!manu_ok) score += 1;

            if (product == 0 && serial == 0) {
                score += 1;
            }
            else if (product == 0 || serial == 0) {
                if (score > 0) score += 1;
            }

            if (!has_name && score > 0) score += 1;

            if (!have_friendly && !have_dev_desc) score += 1;

            if (used_heap) LocalFree(heap_buf);

            if (score >= threshold) {
                SetupDiDestroyDeviceInfoList(dev_info);
                return true;
            }

            dev_data = {};
            dev_data.cbSize = sizeof(dev_data);
        }

        SetupDiDestroyDeviceInfoList(dev_info);
        return false;
    }


    /**
     * @brief Check whether the CPU is genuine and its reported instruction capabilities are not masked
     * @category Windows
     * @implements VM::CPU_HEURISTIC
     */
    [[nodiscard]] static bool cpu_heuristic() {
        bool spoofed = false;
    #if (x86)
        if (util::is_running_under_translator()) {
            debug("CPU_HEURISTIC: Running inside a binary translation layer");
            return false;
        }

        // 1) Check for commonly disabled instructions on patches and VMs    
        u32 a = 0, b = 0, c = 0, d = 0;
        cpu::cpuid(a, b, c, d, 1u);

        constexpr u32 AES_NI_BIT = 1u << 25;
        const bool aes_support = (c & AES_NI_BIT) != 0;

        alignas(16) unsigned char plaintext[16] = {
            0x00,0x11,0x22,0x33, 0x44,0x55,0x66,0x77,
            0x88,0x99,0xAA,0xBB, 0xCC,0xDD,0xEE,0xFF
        };
        alignas(16) unsigned char key[16] = {
            0x0F,0x0E,0x0D,0x0C, 0x0B,0x0A,0x09,0x08,
            0x07,0x06,0x05,0x04, 0x03,0x02,0x01,0x00
        };
        alignas(16) unsigned char out[16] = { 0 };

        // need to do a lambda wrapper to isolate SEH from the parent function's stack unwinding
        // target aes is required for clang/gcc while in MSVC not, and this target can only be applied to functions, meaning we need a struct
        struct aes_executor {
                #if (CLANG || GCC)
                    __attribute__((__target__("aes")))
                #endif
                static bool check_aes_integrity(const unsigned char* pt, const unsigned char* k, unsigned char* o, bool support) {
                __try {
                    __m128i block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(pt));
                    __m128i key_vec = _mm_loadu_si128(reinterpret_cast<const __m128i*>(k));

                    __m128i tmp = _mm_xor_si128(block, key_vec);
                    tmp = _mm_aesenc_si128(tmp, key_vec);

                    _mm_storeu_si128(reinterpret_cast<__m128i*>(o), tmp);

                    if (!support) {
                        debug("CPU_HEURISTIC: Hypervisor detected hiding AES capabilities");
                        return true;
                    }
                }
                __except (GetExceptionCode() == EXCEPTION_ILLEGAL_INSTRUCTION
                    ? EXCEPTION_EXECUTE_HANDLER
                    : EXCEPTION_CONTINUE_SEARCH) {
                    if (support) {
                        debug("CPU_HEURISTIC: Hypervisor reports AES, but it is not handled correctly");
                        return true;
                    }
                }
                return false;
            }
        };

        if (aes_executor::check_aes_integrity(plaintext, key, out, aes_support)) return true;

        const bool avx_support = ((c >> 28) & 1u) != 0;
        const bool xsave_support = ((c >> 26) & 1u) != 0;

        if (avx_support && !xsave_support) {
            debug("CPU_HEURISTIC: YMM state not correct for a baremetal machine");
            return true;
        }

        const bool rdrand_support = ((c >> 30) & 1u) != 0;

        auto check_rdrand_integrity = [&]() -> bool {
            __try {
                unsigned int v = 0;
            #if (MSVC && !CLANG)
                if (_rdrand32_step(&v) && !rdrand_support) {
                    debug("CPU_HEURISTIC: Hypervisor detected hiding RDRAND capabilities");
                    return true;
                }
            #else 
                unsigned char ok = 0;
                asm volatile("rdrand %0\n\tsetc %1" : "=r"(v), "=qm"(ok) : : "cc");
                if (ok && !rdrand_support) {
                    debug("CPU_HEURISTIC: Hypervisor detected hiding RDRAND capabilities");
                    return true;
                }
            #endif      
            }
            __except (GetExceptionCode() == EXCEPTION_ILLEGAL_INSTRUCTION
                ? EXCEPTION_EXECUTE_HANDLER
                : EXCEPTION_CONTINUE_SEARCH) {
                if (rdrand_support) {
                    debug("CPU_HEURISTIC: Hypervisor reports RDRAND, but it is not handled correctly");
                    return true;
                }
            }
            return false;
        };

        if (check_rdrand_integrity()) return true;

        // 2. Test if the CPU vendor is spoofed (for example, a CPU reports being AMD in CPUID, but it is Intel)
        /*
            For this task, we want a instruction that:
            1. It is vendor-only, meaning that other CPU vendors never implemented the same instruction on their microcode
                -> Note: Even if an instruction is vendor-only, it may be treated as a NOP by other CPU vendors, we don't want this
            2. Is compatible enough, meaning both old and new CPUs of this vendor have it
            3. Is enabled by default, without needing BIOS/OS changes
            4. Never switches to kernel-mode, so that is harder to intercept
            5. Is not deprecated today
            6. Its side-effects can be measured from CPL3 (user-mode)

            On Intel, most options are unreliable:
            SGX are deprecated and disabled by default, MPX is deprecated and treated as NOP even in AMD CPUs, AVX-512 is not found in all processors (and AMD integrated part of this set), etc
            On AMD, 3dNow! could be an option, but since its being deprecated, CLZERO fits this criteria better

            So for example, if the CPU reports being Intel, and succesfully runs CLZERO without a NOP, then it's not an Intel CPU.
        */

        // AMD stub template (mov rax, imm64 + clzero + ret)
        // 8-byte immediate at runtime at offsets [2..9]
        u8 amd_bytes[] = {
            0x48, 0xB8,                 // mov rax, imm64
            0x00, 0x00, 0x00, 0x00,     // imm64 low bytes (placeholder)
            0x00, 0x00, 0x00, 0x00,     // imm64 high bytes (placeholder)
            0x0F, 0x01, 0xFC,           // clzero
            0xC3                        // ret
        };
        constexpr SIZE_T amd_stub_size = sizeof(amd_bytes); // 14

        const u8* bytes = nullptr;
        SIZE_T codeSize = 0;

        LPVOID amd_target_mem = nullptr;
        LPVOID exec_mem = nullptr;
        PVOID free_base = nullptr;
        SIZE_T free_size = 0;

        const bool claimed_amd = cpu::is_amd();
        const bool claimed_intel = cpu::is_intel();

        if (!claimed_amd && !claimed_intel) {
            debug("CPU_HEURISTIC: x86 CPU vendor was not recognized as either Intel or AMD");
            return false; // Zhaoxin? VIA/Centaur?
        }

        bool proceed = true;
        bool exception = false;

        // A case where this check could false flag is when analyzing the AMD PRO A8-9600B CPU
        // is based on the "Bristol Ridge" platform, which uses the Excavator microarchitecture (the 4th and final generation of the Bulldozer family)
        // Excavator CPUs do not possess the CLZERO instruction
        if (claimed_amd) {
            cpu::model_struct model = cpu::get_model();
            if (!model.is_ryzen) {
                debug("CPU_HEURISTIC: CPU is AMD but not Ryzen (Pre-Zen). Skipping CLZERO check");
                proceed = false;
            }
        }

        if (claimed_intel || !claimed_amd) exception = true; // should generate an exception rather than be treated as a NOP, but we will check its side effects anyways

        // one cache line = 64 bytes
        const SIZE_T target_size = 64;

        const HMODULE ntdll = util::get_ntdll();
        if (!ntdll) return false;

        const char* names[] = { "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtFlushInstructionCache", "NtFreeVirtualMemory" };
        void* funcs[ARRAYSIZE(names)] = {};
        util::get_function_address(ntdll, names, funcs, ARRAYSIZE(names));

        using NtAllocateVirtualMemory_t = NTSTATUS(__stdcall*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
        using NtProtectVirtualMemory_t = NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
        using NtFreeVirtualMemory_t = NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG);
        using NtFlushInstructionCache_t = NTSTATUS(__stdcall*)(HANDLE, PVOID, SIZE_T);
        const auto nt_allocate_virtual_memory = reinterpret_cast<NtAllocateVirtualMemory_t>(funcs[0]);
        const auto nt_protect_virtual_memory = reinterpret_cast<NtProtectVirtualMemory_t>(funcs[1]);
        const auto nt_flush_instruction_cache = reinterpret_cast<NtFlushInstructionCache_t>(funcs[2]);
        const auto nt_free_virtual_memory = reinterpret_cast<NtFreeVirtualMemory_t>(funcs[3]);

        if (!nt_allocate_virtual_memory || !nt_protect_virtual_memory || !nt_flush_instruction_cache || !nt_free_virtual_memory) {
            return false;
        }

        const HANDLE current_process = reinterpret_cast<HANDLE>(-1LL);

        {
            PVOID base = nullptr;
            SIZE_T sz = target_size;
            NTSTATUS st2 = nt_allocate_virtual_memory(current_process, &base, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!NT_SUCCESS(st2) || base == nullptr) {
                proceed = false;
            }
            else {
                amd_target_mem = base;
                // fill target with a recognizable non-zero pattern so we can detect CLZERO's effect (in case some obscure Intel CPU treat our instruction as a NOP)
                memset(amd_target_mem, 0xA5, target_size);

                const std::uintptr_t paddr = reinterpret_cast<std::uintptr_t>(amd_target_mem); // to avoid sign-extension, 32-bit compatible
                const u64 addr = static_cast<u64>(paddr);
                for (u8 i = 0; i < 8; ++i) {
                    amd_bytes[2 + i] = static_cast<u8>((addr >> (i * 8)) & 0xFF);
                }
                bytes = amd_bytes;
                codeSize = amd_stub_size;
            }
        }

        if (proceed) {
            PVOID base = nullptr;
            SIZE_T sz = codeSize;
            NTSTATUS st2 = nt_allocate_virtual_memory(current_process, &base, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (NT_SUCCESS(st2) && base != nullptr) {
                exec_mem = base;
                memcpy(exec_mem, bytes, codeSize);

                // change to RX
                ULONG oldProt = 0;
                PVOID tmp_base = exec_mem;
                SIZE_T tmp_sz = codeSize;
                st2 = nt_protect_virtual_memory(current_process, &tmp_base, &tmp_sz, PAGE_EXECUTE_READ, &oldProt);
                if (NT_SUCCESS(st2)) {
                    nt_flush_instruction_cache(current_process, exec_mem, codeSize);

                    using code_func = void(*)();
                    using runner_func = u8(*)(code_func);
                    runner_func runner = +[](code_func func) -> u8 {
                        __try {
                            func();
                            return 0;
                        }
                        __except (GetExceptionCode() == EXCEPTION_ILLEGAL_INSTRUCTION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
                            return 1;
                        }
                    };

                    const u8 runner_rc = runner(reinterpret_cast<code_func>(exec_mem));

                    // check if the target buffer was written to zero by CLZERO
                    bool memory_all_zero = false;
                    if (amd_target_mem) {
                        volatile u8* p = reinterpret_cast<volatile u8*>(amd_target_mem);
                        memory_all_zero = true;
                        for (SIZE_T i = 0; i < target_size; ++i) {
                            if (p[i] != 0) { memory_all_zero = false; break; }
                        }
                    }

                    if (runner_rc == 0 && exception) {
                        // only treat as spoofed if the CLZERO execution actually zeroed the target memory
                        if (memory_all_zero) {
                            debug("CPU_HEURISTIC: CPU reports being Intel, but VMAware detected a hypervisor running an AMD CPU in the host"); // or another CPU vendor
                            spoofed = true;
                        }
                        else {
                            debug("CPU_HEURISTIC: CLZERO returned without exception but target memory was NOT zeroed (NOP/emulated)");
                        }
                    }
                    else if (runner_rc == 1 && !exception) {
                        debug("CPU_HEURISTIC: CPU reports being AMD, but VMAware detected a hypervisor running an Intel CPU in the host"); // or another CPU vendor
                        spoofed = true;
                    }
                    else if (runner_rc == 0 && !exception) {
                        if (!memory_all_zero) {
                            debug("CPU_HEURISTIC: CPU reports being AMD, CLZERO executed but did NOT zero the target memory");
                            spoofed = true;
                        }
                    }
                }
            }
        }

        if (exec_mem) {
            free_base = exec_mem; free_size = codeSize;
            nt_free_virtual_memory(current_process, &free_base, &free_size, MEM_RELEASE);
            exec_mem = nullptr;
        }
        if (amd_target_mem) {
            free_base = amd_target_mem; free_size = target_size;
            nt_free_virtual_memory(current_process, &free_base, &free_size, MEM_RELEASE);
            amd_target_mem = nullptr;
        }

        if (spoofed) return spoofed;

        // ok so if the CPU is intel, the motherboard should be intel aswell (and same with AMD)
        // this doesnt happen in most public hardened configs out there so lets abuse it
        constexpr unsigned int VID_INTEL = 0x8086;
        constexpr unsigned int VID_AMD_ATI = 0x1002;
        constexpr unsigned int VID_AMD_MICRO = 0x1022;

        enum class MBVendor { Unknown = 0, Intel = 1, AMD = 2 };

        auto detect_motherboard = []() noexcept -> MBVendor {
            static constexpr const wchar_t* TOKENS[] = {
                L"host bridge", L"northbridge", L"southbridge", L"pci bridge", L"chipset", L"pch", L"fch",
                L"platform controller", L"lpc", L"sata controller", L"ahci", L"ide controller", L"usb controller",
                L"xhci", L"usb3", L"usb 3.0", L"usb 3", L"pcie root", L"pci express", L" sata", nullptr
            };

            auto contains_token = [](const wchar_t* haystack) noexcept -> bool {
                if (!haystack) return false;
                for (const wchar_t* const* t = TOKENS; *t; ++t) {
                    const wchar_t* needle = *t;
                    const wchar_t* h = haystack;

                    // naive scan is faster than BM/KMP for very short needles/haystacks
                    while (*h) {
                        const wchar_t* h_iter = h;
                        const wchar_t* n_iter = needle;

                        while (*n_iter) {
                            wchar_t hc = *h_iter;
                            if (hc >= L'A' && hc <= L'Z') hc += 32;

                            if (hc != *n_iter) break;
                            h_iter++;
                            n_iter++;
                        }

                        if (!*n_iter) return true; 
                        h++;
                    }
                }
                return false;
            };

            auto find_vendor_hex = [](const wchar_t* wptr) noexcept -> u32 {
                if (!wptr) return 0;
                const wchar_t* p = wptr;
                while (*p) {
                    // Check for "VEN_" (case-insensitive)
                    if (((p[0] | 0x20) == L'v') &&
                        ((p[1] | 0x20) == L'e') &&
                        ((p[2] | 0x20) == L'n') &&
                        (p[3] == L'_')) {

                        const wchar_t* q = p + 4;
                        u32 val = 0;
                        int got = 0;
                        while (got < 4 && *q) {
                            const wchar_t c = *q;
                            u32 nib = 0;
                            if (c >= L'0' && c <= L'9') 
                                nib = static_cast<u32>(c - L'0');
                            else if ((c | 0x20) >= L'a' && (c | 0x20) <= L'f') 
                                nib = static_cast<u32>((c | 0x20) - L'a' + 10);
                            else
                                break;

                            val = (val << 4) | nib;
                            ++got; ++q;
                        }
                        if (got == 4) return val;
                    }
                    ++p;
                }
                return 0;
            };

            // setupapi stuff
            int intel_hits = 0;
            int amd_hits = 0;

            wchar_t stack_buf[1024]{};
            std::vector<BYTE> heap_buf; // fallback for rare huge strings

            auto scan_devices = [&](const GUID* classGuid, DWORD flags) noexcept {
                HDEVINFO handle_dev_info = SetupDiGetClassDevsW(classGuid, nullptr, nullptr, flags);
                if (handle_dev_info == INVALID_HANDLE_VALUE) return;

                SP_DEVINFO_DATA dev_info_data{};
                dev_info_data.cbSize = sizeof(SP_DEVINFO_DATA);

                for (DWORD i = 0; SetupDiEnumDeviceInfo(handle_dev_info, i, &dev_info_data); ++i) {

                    const wchar_t* w_desc = nullptr;
                    DWORD req_size = 0;
                    DWORD prop_type = 0;

                    if (SetupDiGetDeviceRegistryPropertyW(handle_dev_info, &dev_info_data, SPDRP_DEVICEDESC, &prop_type, reinterpret_cast<PBYTE>(stack_buf), sizeof(stack_buf), &req_size)) {
                        w_desc = stack_buf;
                    }
                    else if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                        if (heap_buf.size() < req_size) heap_buf.resize(req_size);
                        if (SetupDiGetDeviceRegistryPropertyW(handle_dev_info, &dev_info_data, SPDRP_DEVICEDESC, &prop_type, heap_buf.data(), req_size, nullptr)) {
                            w_desc = reinterpret_cast<const wchar_t*>(heap_buf.data());
                        }
                    }

                    // check if the description contains any interesting stuff
                    if (w_desc && contains_token(w_desc)) {

                        // if interesting get hwid to get vendor
                        const wchar_t* w_hardware_id = nullptr;

                        if (SetupDiGetDeviceRegistryPropertyW(handle_dev_info, &dev_info_data, SPDRP_HARDWAREID, &prop_type, reinterpret_cast<PBYTE>(stack_buf), sizeof(stack_buf), &req_size)) {
                            w_hardware_id = stack_buf;
                        }
                        else if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                            if (heap_buf.size() < req_size) heap_buf.resize(req_size);
                            if (SetupDiGetDeviceRegistryPropertyW(handle_dev_info, &dev_info_data, SPDRP_HARDWAREID, &prop_type, heap_buf.data(), req_size, nullptr)) {
                                w_hardware_id = reinterpret_cast<const wchar_t*>(heap_buf.data());
                            }
                        }

                        if (w_hardware_id) {
                            const u32 vid = find_vendor_hex(w_hardware_id);
                            if (vid == VID_INTEL) intel_hits++;
                            else if (vid == VID_AMD_ATI || vid == VID_AMD_MICRO) amd_hits++;
                        }
                    }
                }
                SetupDiDestroyDeviceInfoList(handle_dev_info);
            };

            // GUID_DEVCLASS_SYSTEM covers Host Bridges, LPC, PCI bridges Chipset/CPU etc
            // GUID_DEVCLASS_USB covers USB controller stuff
            // GUID_DEVCLASS_HDC covers SATA/IDE
            const GUID* interesting_classes[] = {
                &GUID_DEVCLASS_SYSTEM,
                &GUID_DEVCLASS_USB,
                &GUID_DEVCLASS_HDC
            };

            for (const GUID* guid : interesting_classes) {
                scan_devices(guid, DIGCF_PRESENT);
            }

            // if no stuff then mybe query all devices in the system?
            if (intel_hits == 0 && amd_hits == 0) {
                scan_devices(nullptr, DIGCF_ALLCLASSES | DIGCF_PRESENT);
            }

            if (intel_hits > amd_hits) return MBVendor::Intel;
            if (amd_hits > intel_hits) return MBVendor::AMD;
            return MBVendor::Unknown;
        };

        const MBVendor vendor = detect_motherboard();

        switch (vendor) {
        case MBVendor::Intel:
            if (claimed_amd && !claimed_intel) {
                debug("CPU_HEURISTIC: CPU reports AMD but chipset looks Intel");
                spoofed = true;
            }
            break;
        case MBVendor::AMD:
            if (claimed_intel && !claimed_amd) {
                debug("CPU_HEURISTIC: CPU reports Intel but chipset looks AMD");
                spoofed = true;
            }
            break;
        case MBVendor::Unknown:
            debug("CPU_HEURISTIC: Could not determine chipset vendor");
            break;
        }
    #endif
        return spoofed;
    }


    /**
     * @brief Check the presence of system timers
     * @category x86, Windows
     * @implements VM::CLOCK
     */
    [[nodiscard]] static bool clock() {
    #if (ARM)
		return false; // ARM systems do not have the classic x86 timers
    #endif
		if (util::is_running_under_translator()) {
            debug("CLOCK: Running inside an ARM CPU");
            return false;
        }

        // Surface Pro models typically do not have PIT
        {
            const char* manufacturer = nullptr;
            const char* model = nullptr;
            if (util::get_manufacturer_model(&manufacturer, &model)) {
                auto ci_contains = [](const char* hay, const char* needle) noexcept -> bool {
                    if (!hay || !needle || !*hay || !*needle) return false;
                    const unsigned char* h = reinterpret_cast<const unsigned char*>(hay);
                    const unsigned char* n = reinterpret_cast<const unsigned char*>(needle);
                    const size_t nlen = strlen(reinterpret_cast<const char*>(n));
                    for (; *h; ++h) {
                        size_t i = 0;
                        for (;; ++i) {
                            unsigned char hc = h[i];
                            unsigned char nc = n[i];
                            if (!nc) return false; // matched whole needle
                            if (!hc) break; // hay ended
                            // ascii lowercase
                            if (hc >= 'A' && hc <= 'Z') hc += 32;
                            if (nc >= 'A' && nc <= 'Z') nc += 32;
                            if (hc != nc) break;
                        }
                        if (i == nlen) return false;
                    }
                    return false;
                };

                const bool model_has_surface = ci_contains(model, "surface");
                const bool model_has_pro = ci_contains(model, "pro");
                const bool man_is_microsoft = ci_contains(manufacturer, "microsoft");

                if (model_has_surface && (model_has_pro || man_is_microsoft)) {
                    return false;
                }
            }
        }

        // The RTC (ACPI/CMOS RTC) timer can't be always detected via SetupAPI, it needs AML decode of the DSDT firmware table
        // The HPET (PNP0103) timer presence check was removed, more info at: https://github.com/kernelwernel/VMAware/pull/616
        // Here, we check for the PIT/AT timer (PC-class System Timer)
        constexpr wchar_t pattern[] = L"pnp0100"; 
        constexpr size_t patLen = (sizeof(pattern) / sizeof(wchar_t)) - 1;

        auto wcsstr_ci_ascii = [&](const wchar_t* hay) noexcept -> const wchar_t* {
            if (!hay) return nullptr;

            for (; *hay; ++hay) {
                wchar_t h = *hay;
                if (h >= L'A' && h <= L'Z') h += 32;

                if (h != pattern[0]) continue;

                size_t i = 1;
                for (; i < patLen; ++i) {
                    wchar_t next_h = hay[i];

                    if (next_h == L'\0') return nullptr;

                    if (next_h >= L'A' && next_h <= L'Z') next_h += 32;

                    if (next_h != pattern[i]) break;
                }

                if (i == patLen) return hay; 
            }
            return nullptr;
        };

        const HDEVINFO devs = SetupDiGetClassDevsW(nullptr, nullptr, nullptr, DIGCF_PRESENT | DIGCF_ALLCLASSES);
        if (devs == INVALID_HANDLE_VALUE) return false;

        SP_DEVINFO_DATA dev_info{};
        dev_info.cbSize = sizeof(SP_DEVINFO_DATA);

        DWORD buf_bytes = 4096;
        BYTE* buffer = static_cast<BYTE*>(malloc(buf_bytes));
        if (!buffer) {
            SetupDiDestroyDeviceInfoList(devs);
            return false;
        }

        bool found = false;
        for (DWORD idx = 0; SetupDiEnumDeviceInfo(devs, idx, &dev_info); ++idx) {
            DWORD property_type = 0;
            if (!SetupDiGetDeviceRegistryPropertyW(devs, &dev_info, SPDRP_HARDWAREID,
                &property_type, buffer, buf_bytes, nullptr))
            {
                const DWORD err = GetLastError();
                if (err == ERROR_INSUFFICIENT_BUFFER) {
                    DWORD required = 0;
                    SetupDiGetDeviceRegistryPropertyW(devs, &dev_info, SPDRP_HARDWAREID,
                        &property_type, nullptr, 0, &required);
                    if (required > buf_bytes) {
                        BYTE* new_buffer = static_cast<BYTE*>(realloc(buffer, required));
                        if (!new_buffer) { 
                            found = false; 
                            break; 
                        } 
                        buffer = new_buffer;
                        buf_bytes = required;
                    }
                    if (!SetupDiGetDeviceRegistryPropertyW(devs, &dev_info, SPDRP_HARDWAREID,
                        &property_type, buffer, buf_bytes, nullptr)) {
                        continue;
                    }
                }
                else {
                    continue;
                }
            }

            if (property_type != REG_MULTI_SZ) continue;

            wchar_t* cur = reinterpret_cast<wchar_t*>(buffer);
            while (*cur) {
                if (wcsstr_ci_ascii(cur)) {
                    found = true;
                    break;
                }
                cur += wcslen(cur) + 1;
            }
            if (found) break;
        }

		free(buffer);
		SetupDiDestroyDeviceInfoList(devs);
		
		return !found;
    }
    // ADD NEW TECHNIQUE FUNCTION HERE
#endif
 

    /* ============================================================================================== *
     *                                                                                                *                                                                                               *
     *                                        CORE SECTION                                            *
     *                                                                                                *
     * ============================================================================================== */
public:
    struct core {
        struct technique {
            u8 points = 0;                // this is the certainty score between 0 and 100
            bool(*run)();                 // this is the technique function itself

            constexpr technique() : points(0), run(nullptr) {}
            constexpr technique(u8 points, bool(*run)()) : points(points), run(run) {}
        };

        struct custom_technique {
            u8 points;
            u16 id;
            bool(*run)();
        };

        // entry for the initialization list
        struct technique_entry {
            enum_flags id;
            technique tech;
        };

        // entry for brand scoreboard
        struct brand_entry {
            const char* name;
            brand_score_t score;
        };

        // the actual table, which is derived from the list above and will be 
        // used for most functionalities related to technique interactions
        static std::array<technique, enum_size + 1> technique_table;

        // specific to VM::add_custom(), where custom techniques will be stored here
        static constexpr size_t MAX_CUSTOM_TECHNIQUES = 256;
        static std::vector<VM::core::custom_technique> custom_table; // users should not have a limit of how many functions they should add, this is the only exception of a heap-allocated object in our core
        static size_t custom_table_size;

        // VM scoreboard table specifically for VM::brand()
        static constexpr size_t MAX_BRANDS = 128;
        static std::array<brand_entry, MAX_BRANDS> brand_scoreboard;
        static size_t brand_count;

        // Temporary storage to capture which brand was detected by the currently running technique
        static const char* last_detected_brand;
        static u8 last_detected_score;

        // 1. one brand, custom score
        static inline bool add(const char* p_brand, u8 score) noexcept {
            return add_score(p_brand, "", score);
        }

        // 2. one brand, default score
        static inline bool add(const char* p_brand) noexcept {
            return add_score(p_brand, "", 0);
        }

        // 3. two brands, default score
        static inline bool add(const char* p_brand, const char* extra_brand) noexcept {
            return add_score(p_brand, extra_brand, 0);
        }

        static inline bool add_score(const char* p_brand, const char* extra_brand, u8 score) noexcept {
            last_detected_brand = p_brand;
            last_detected_score = score; // Store for the engine to read

            for (size_t i = 0; i < brand_count; ++i) {
                // pointer comparison is sufficient as we use the static constants from brands:: namespace
                if (brand_scoreboard[i].name == p_brand) {
                    brand_scoreboard[i].score++;
                    break;
                }
            }

            if (extra_brand && extra_brand[0] != '\0') {
                for (size_t i = 0; i < brand_count; ++i) {
                    if (brand_scoreboard[i].name == extra_brand) {
                        brand_scoreboard[i].score++;
                        break;
                    }
                }
            }
            return true;
        }

        // assert if the flag is enabled, far better expression than typing std::bitset member functions
        [[nodiscard]] static inline bool is_disabled(const flagset& flags, const u8 flag_bit) noexcept {
            if (flag_bit >= flags.size()) return true;
            return !flags.test(flag_bit);
        }

        // same as above but for checking enabled flags
        [[nodiscard]] static inline bool is_enabled(const flagset& flags, const u8 flag_bit) noexcept {
            if (flag_bit >= flags.size()) return false;
            return flags.test(flag_bit);
        }

        [[nodiscard]] static bool are_techniques_empty(const flagset& flags) {
            for (std::size_t i = technique_begin; i < technique_end; i++) {
                if (flags.test(i)) {
                    return false;
                }
            }

            return true;
        }

        [[nodiscard]] static bool is_setting_flag_set(const flagset& flags) {
            for (std::size_t i = settings_begin; i < settings_end; i++) {
                if (flags.test(i)) {
                    return true;
                }
            }

            return false;
        }

        // run every VM detection mechanism in the technique table
        static u16 run_all(const flagset& flags, const bool shortcut = false) {
            u16 points = 0;

            u16 threshold_points = threshold_score;

            // set it to 300 if high threshold is enabled
            if (core::is_enabled(flags, HIGH_THRESHOLD)) {
                threshold_points = high_threshold_score;
            }

            for (size_t i = technique_begin; i < technique_end; ++i) {
                const enum_flags technique_macro = static_cast<enum_flags>(i);
                const technique& technique_data = technique_table[i];

                // skip empty entries
                if (!technique_data.run) continue;

                // check if the technique is disabled
                if (core::is_disabled(flags, technique_macro)) {
                    continue;
                }

                // check if the technique is cached already
                if (memo::is_cached(technique_macro)) {
                    const memo::data_t data = memo::cache_fetch(technique_macro);

                    if (data.result) {
                        points += data.points;
                    }

                    continue;
                }

                // reset the last detected brand before running
                last_detected_brand = nullptr;
                last_detected_score = 0;

                // run the technique
                const bool result = technique_data.run();

                if (result) {
                    // determine which points to use: Override or Default
                    const u8 points_to_add = (last_detected_score > 0) ? last_detected_score : technique_data.points;

                    points += points_to_add;
                    // this is specific to VM::detected_count() which 
                    // returns the number of techniques that found a VM.
                    detected_count_num++;

                    // retrieve the brand that was set during execution (if any)
                    const char* detected_brand = (last_detected_brand) ? last_detected_brand : brands::NULL_BRAND;
                    // store the current technique result to the cache
                    memo::cache_store(technique_macro, result, points_to_add, detected_brand);
                }
                else {
                    memo::cache_store(technique_macro, false, 0, brands::NULL_BRAND);
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
            if (!core::custom_table.empty()) {
                for (const auto& technique : core::custom_table) {

                    // if cached, return that result
                    if (memo::is_cached(technique.id)) {
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
                    memo::cache_store(
                        technique.id,
                        result,
                        technique.points
                    );
                }
            }

            return points;
        }


        /* ============================================================================================== *
         *                                                                                                *
         *                                     ARGUMENT HANDLER SECTION                                   *
         *                                                                                                *
         * ============================================================================================== */

         /**
          * basically what this entire section does is handle the arguments in a way
          * where it can coordinate between enabled and disabled flags. The flags in
          * the argument handling strategy are std::bitset variables (right below 
          * this comment), and it's used as a semi-global variable so that each 
          * component can share this variable together. The core of this section is
          * the arg_handler and disabled_arg_handler functions. They both take a 
          * variadic argument of enum_flags. The former decides which bits should be 
          * enabled, while the latter will toggle those bits (if there's any) after 
          * the arg_handler processing is done.
          */
    
    // this is public but only for advanced use cases. It's intentionally undocumented.
    public: 
        static flagset flag_collector;
        static flagset disabled_flag_collector;
    
        static void generate_default(flagset& flags) {
            // set all bits to 1
            flags.set();

            // disable all non-default techniques
            for (const auto id : disabled_techniques) {
                flags.flip(id);
            }

            // disable all the settings flags except for VM::DEFAULT
            flags.flip(HIGH_THRESHOLD);
            flags.flip(NULL_ARG);
            flags.flip(DYNAMIC);
            flags.flip(MULTIPLE);
            flags.flip(ALL);
        }

        // this overload is mainly for default argument purposes
        static flagset generate_default() {
            flagset flags;
            generate_default(flags);
            return flags;
        }

        static void generate_all(flagset& flags) {
            generate_default(flags);

            for (const enum_flags technique : disabled_techniques) {
                flags.set((enum_flags)technique, true);
            }
        }

        static void reset_disabled_flagset() {
            disabled_flag_collector.reset();
            for (const auto technique : disabled_techniques) {
                disabled_flag_collector.set(static_cast<u32>(technique), true);
            }
        }

        // base handle implementation
        static inline bool all_enum_flags() {
            return true;
        }

        template <typename T, typename... Rest>
        static bool all_enum_flags(T&& /*first*/, Rest&&... rest) {
            using Decayed = typename std::decay<T>::type;

            if (!std::is_same<Decayed, enum_flags>::value) {
                return false;
            }

            return all_enum_flags(std::forward<Rest>(rest)...);
        }

        template <typename... Args>
        static bool is_type_valid(Args&&... args) {
            return all_enum_flags(std::forward<Args>(args)...);
        }

        template <typename... Args>
        static constexpr bool is_empty() {
            return (sizeof...(Args) == 0);
        }

        // this will generate a std::bitset based on the arguments provided
        template <typename... Args>
        static VMAWARE_CONSTEXPR flagset arg_handler(Args&&... args) {
            if (is_type_valid(args...) == false) {
                throw std::invalid_argument("argument handler only accepts enum_flags variables");
            }

            // reset all relevant flags
            flag_collector.reset();

            if VMAWARE_CONSTEXPR(is_empty<Args...>()) {
                generate_default(flag_collector);
                return flag_collector;
            }

            // C++ trick to loop over the variadic arguments one by one
            int dummy[] = {
                (flag_collector.set(static_cast<u32>(args), true), 0)...
            };
            VMAWARE_UNUSED(dummy);

            if (flag_collector.test(DEFAULT)) {
                generate_default(flag_collector);
            }

            if (are_techniques_empty(flag_collector)) {
                flag_collector |= generate_default();
            }

            if (flag_collector.test(ALL)) {
                generate_all(flag_collector);
            }

            // if flag is disabled, remove it from the flag_collector
            for (u8 i = 0; i < enum_size + 1; i++) {
                if (disabled_flag_collector.test(i)) {
                    flag_collector.set(i, false);
                }
            }

            return flag_collector;
        }

        // same as above but for VM::disable which only accepts technique flags
        template <typename... Args>
        static void disabled_arg_handler(Args&&... args) {
            if (is_type_valid(args...) == false) {
                throw std::invalid_argument("disabled argument handler only accepts enum_flags variables");
            }

            if VMAWARE_CONSTEXPR(is_empty<Args...>()) {
                throw std::invalid_argument("VM::DISABLE() must contain a flag");
            }

            // C++ trick to loop over the variadic arguments one by one
            int dummy[] = { 
                (disabled_flag_collector.set(args, true), 0)...
            };
            VMAWARE_UNUSED(dummy);

            // check if a settings flag is set, which is not valid
            if (core::is_setting_flag_set(disabled_flag_collector)) {
                throw std::invalid_argument("VM::DISABLE() must not contain a settings flag, they are disabled by default anyway");
            }
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
        const enum_flags flag_bit
    #if (SOURCE_LOCATION_SUPPORTED)
        , [[maybe_unused]] const std::source_location& loc = std::source_location::current()
    #endif
    ) {
        if (util::is_unsupported(flag_bit)) {
            memo::cache_store(flag_bit, false, 0, brands::NULL_BRAND);
            return false;
        }

        auto throw_error = [&](const char* text) -> void {
            std::stringstream ss;
        #if (VMA_CPP >= 20 && !CLANG)
            ss << ", error in " << loc.function_name() << " at " << loc.file_name() << ":" << loc.line() << ")";
        #endif
            ss << ". Consult the documentation's flag handler for VM::check()";
            throw std::invalid_argument(std::string(text) + ss.str());
        };

        if (flag_bit > enum_size) {
            throw_error("Flag argument must be a valid");
        }

        // check if the bit is a settings flag, which shouldn't be allowed
        if (
            (flag_bit == HIGH_THRESHOLD) ||
            (flag_bit == DYNAMIC) ||
            (flag_bit == MULTIPLE)
        ) {
            throw_error("Flag argument must be a technique flag and not a settings flag");
        }

        #if (VMA_CPP >= 23)
            [[assume(flag_bit < technique_end)]];
        #endif

        // if the technique is already cached, return the cached value instead
        if (memo::is_cached(flag_bit)) {
            const memo::data_t data = memo::cache_fetch(flag_bit);
            return data.result;
        }

        if (flag_bit < technique_end) {
            const core::technique& pair = core::technique_table[flag_bit];

            if (auto run_fn = pair.run) {
                core::last_detected_brand = nullptr;
                core::last_detected_score = 0;

                const bool result = run_fn();

                const u8 points_to_add = (core::last_detected_score > 0) ? core::last_detected_score : pair.points;
                const char* detected_brand = (core::last_detected_brand) ? core::last_detected_brand : brands::NULL_BRAND;

                if (result) {
                    detected_count_num++;
                }

                memo::cache_store(flag_bit, result, result ? points_to_add : 0, detected_brand);
                return result;
            }
            else {
                throw_error("Flag is not known or not implemented");
            }
        }

        return false;
    }


    /**
     * @brief Fetch the VM brand
     * @param any flag combination in VM structure or nothing (VM::MULTIPLE can be added)
     * @return const char*
     * @link https://github.com/kernelwernel/VMAware/blob/main/docs/documentation.md#vmbrand
     */
    template <typename ...Args>
    static std::string brand(Args ...args) {
        const flagset flags = core::arg_handler(args...);
        return brand(flags);
    }

    static std::string brand(const flagset& flags = core::generate_default()) {
        // is the multiple setting flag enabled?
        const bool is_multiple = core::is_enabled(flags, MULTIPLE);

        // check if the result is already cached and return that instead
        if (is_multiple) {
            if (memo::multi_brand::is_cached()) {
                debug("VM::brand(): returned multi brand from cache");
                return memo::multi_brand::fetch();
            }
        }
        else {
            if (memo::brand::is_cached()) {
                debug("VM::brand(): returned brand from cache");
                return memo::brand::fetch();
            }
        }

        // run all the techniques
        const u16 score = core::run_all(flags);

    #if (VMA_CPP <= 14)
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
        constexpr const char* TMP_HYPERV_ARTIFACT = "Hyper-V artifact (host running Hyper-V)";
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
        constexpr const char* TMP_HYPERV_ARTIFACT = brands::HYPERV_ARTIFACT;
    #endif

        using brand_element_t = std::pair<const char*, brand_score_t>;
        std::array<brand_element_t, core::MAX_BRANDS> active_brands;
        size_t active_count = 0;

        for (size_t i = 0; i < core::brand_count; ++i) {
            if (core::brand_scoreboard[i].score > 0) {
                active_brands[active_count++] = std::make_pair(core::brand_scoreboard[i].name, core::brand_scoreboard[i].score);
            }
        }

        // if all brands have a point of 0, return "Unknown"
        if (active_count == 0) {
            return brands::NULL_BRAND;
        }

        // if there's only a single brand, return it immediately
        // We skip this early return if the single brand is HYPERV_ARTIFACT,
        // so that the removal logic at the end of the function can process it
        if (active_count == 1 && active_brands[0].first != TMP_HYPERV_ARTIFACT) {
            return active_brands[0].first;
        }

        // helper lambdas for array manipulation
        auto find_index = [&](const char* name) noexcept -> int {
            for (size_t i = 0; i < active_count; ++i) {
                // pointer comparison is sufficient for static brands
                if (active_brands[i].first == name) return static_cast<int>(i);
            }
            return -1;
        };

        auto remove_at = [&](int index) noexcept {
            if (index >= 0 && index < static_cast<int>(active_count)) {
                if (index != static_cast<int>(active_count - 1)) {
                    active_brands[static_cast<size_t>(index)] = active_brands[active_count - 1];
                }
                active_count--;
            }
        };

        // remove Hyper-V artifacts if found with other brands
        if (active_count > 1) {
            const int idx = find_index(TMP_HYPERV_ARTIFACT);
            if (idx != -1) {
                remove_at(idx);
            }
        }

        // merge 2 brands
        auto merge = [&](const char* a, const char* b, const char* result) noexcept -> void {
            int idx_a = find_index(a);
            if (idx_a == -1) return;

            int idx_b = find_index(b);
            if (idx_b == -1) return;

            remove_at(idx_a);
            idx_b = find_index(b); // re-find
            remove_at(idx_b);

            active_brands[active_count++] = std::make_pair(result, 2);
        };

        // same as above, but for 3
        auto triple_merge = [&](const char* a, const char* b, const char* c, const char* result) noexcept -> void {
            int idx_a = find_index(a);
            if (idx_a == -1) return;
            int idx_b = find_index(b);
            if (idx_b == -1) return;
            int idx_c = find_index(c);
            if (idx_c == -1) return;

            remove_at(idx_a);
            remove_at(find_index(b));
            remove_at(find_index(c));

            active_brands[active_count++] = std::make_pair(result, 2);
        };

        // some edgecase handling for Hyper-V and VirtualPC
        int idx_hv = find_index(TMP_HYPERV);
        int idx_vpc = find_index(TMP_VPC);

        if (idx_hv != -1 && idx_vpc != -1) {
            // existence is confirmed by index != -1
            merge(TMP_VPC, TMP_HYPERV, TMP_HYPERV_VPC);
        }
        else if (idx_hv != -1 && idx_vpc == -1) {
            // logic handled by merge check essentially
        }

        // Brand post-processing / merging
        merge(TMP_AZURE, TMP_HYPERV, TMP_AZURE);
        merge(TMP_AZURE, TMP_VPC, TMP_AZURE);
        merge(TMP_AZURE, TMP_HYPERV_VPC, TMP_AZURE);

        merge(TMP_QEMU, TMP_KVM, TMP_QEMU_KVM);
        merge(TMP_KVM, TMP_HYPERV, TMP_KVM_HYPERV);
        merge(TMP_QEMU, TMP_HYPERV, TMP_QEMU_KVM_HYPERV);
        merge(TMP_QEMU_KVM, TMP_HYPERV, TMP_QEMU_KVM_HYPERV);
        merge(TMP_KVM, TMP_KVM_HYPERV, TMP_KVM_HYPERV);
        merge(TMP_QEMU, TMP_KVM_HYPERV, TMP_QEMU_KVM_HYPERV);
        merge(TMP_QEMU_KVM, TMP_KVM_HYPERV, TMP_QEMU_KVM_HYPERV);

        triple_merge(TMP_QEMU, TMP_KVM, TMP_KVM_HYPERV, TMP_QEMU_KVM_HYPERV);

        merge(TMP_VMWARE, TMP_FUSION, TMP_FUSION);
        merge(TMP_VMWARE, TMP_EXPRESS, TMP_EXPRESS);
        merge(TMP_VMWARE, TMP_ESX, TMP_ESX);
        merge(TMP_VMWARE, TMP_GSX, TMP_GSX);
        merge(TMP_VMWARE, TMP_WORKSTATION, TMP_WORKSTATION);

        merge(TMP_VMWARE_HARD, TMP_VMWARE, TMP_VMWARE_HARD);
        merge(TMP_VMWARE_HARD, TMP_FUSION, TMP_VMWARE_HARD);
        merge(TMP_VMWARE_HARD, TMP_EXPRESS, TMP_VMWARE_HARD);
        merge(TMP_VMWARE_HARD, TMP_ESX, TMP_VMWARE_HARD);
        merge(TMP_VMWARE_HARD, TMP_GSX, TMP_VMWARE_HARD);
        merge(TMP_VMWARE_HARD, TMP_WORKSTATION, TMP_VMWARE_HARD);

        // determine threshold (150 or 300)
        u16 confirmed_vm_threshold = threshold_score;
        if (core::is_enabled(flags, HIGH_THRESHOLD)) {
            confirmed_vm_threshold = high_threshold_score;
        }

        // check if Hyper-V artifact is present
        const int idx_art = find_index(TMP_HYPERV_ARTIFACT);
        if (idx_art != -1) {
            // If score confirms it is a VM, remove the "Artifact" label (because we're in a VM, not in a host machine)
            // so it falls back to "Unknown" if no other brands exist
            if (score >= confirmed_vm_threshold) {
                remove_at(idx_art);
            }
        }

        if (active_count > 1) {
            std::sort(active_brands.begin(), active_brands.begin() + static_cast<std::ptrdiff_t>(active_count), [](
                const brand_element_t& a,
                const brand_element_t& b
                ) {
                return a.second > b.second;
            });
        }

    #ifdef __VMAWARE_DEBUG__
        for (size_t i = 0; i < active_count; ++i) {
            debug("scoreboard: ", (int)active_brands[i].second, " : ", active_brands[i].first);
        }
    #endif

        if (active_count > 0) {
            if (!is_multiple) {
                memo::brand::store(active_brands[0].first);
                debug("VM::brand(): cached brand string");
                return memo::brand::fetch();
            }
            else {
                char* buffer = memo::multi_brand::brand_cache;
                buffer[0] = '\0';
                const size_t buf_size = sizeof(memo::multi_brand::brand_cache);

                str_copy(buffer, active_brands[0].first, buf_size);
                for (size_t i = 1; i < active_count; i++) {
                    str_cat(buffer, " or ", buf_size);
                    str_cat(buffer, active_brands[i].first, buf_size);
                }

                memo::multi_brand::cached = true;
                debug("VM::brand(): cached multiple brand string");
                return memo::multi_brand::fetch();
            }
        }

        return brands::NULL_BRAND;
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
        const flagset flags = core::arg_handler(args...);
        return detect(flags);
    }

    static bool detect(const flagset &flags = core::generate_default()) {
        // run all the techniques based on the 
        // flags above, and get a total score 
        const u16 points = core::run_all(flags, SHORTCUT);

    #if (VMA_CPP >= 23)
        [[assume(points < maximum_points)]];
    #endif

        u16 threshold = threshold_score;

        // if high threshold is set, the bar
        // will be 300. If not, leave it as 150
        if (core::is_enabled(flags, HIGH_THRESHOLD)) {
            threshold = high_threshold_score;
        }

        if (points >= threshold) {
            return true;
        }

        // this is added as a last ditch attempt to detect a VM, 
        // because if there are indications of hardening then logically 
        // it should in fact be a VM.
        return (is_hardened());
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
        return percentage(flags);
    }


    static u8 percentage(const flagset &flags = core::generate_default()) {
        // run all the techniques based on the 
        // flags above, and get a total score
        const u16 points = core::run_all(flags, SHORTCUT);

    #if (VMA_CPP >= 23)
        [[assume(points < maximum_points)]];
    #endif

        u8 percent = 0;
        u16 threshold = threshold_score;

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
            percent = static_cast<u8>(std::min<u16>(points, 99));
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
        bool(*detection_func)()
        #if (SOURCE_LOCATION_SUPPORTED)
        , const std::source_location& loc = std::source_location::current()
        #endif
    ) {
        // lambda to throw the error
        auto throw_error = [&](const char* text) -> void {
            std::stringstream ss;
    #if (VMA_CPP >= 20 && !CLANG)
            ss << ", error in " << loc.function_name() << " at " << loc.file_name() << ":" << loc.line() << ")";
    #endif
            ss << ". Consult the documentation's parameters for VM::add_custom()";
            throw std::invalid_argument(std::string(text) + ss.str());
        };

        if (percent > 100) {
            throw_error("Percentage parameter must be between 0 and 100");
        }

    #if (VMA_CPP >= 23)
        [[assume(percent > 0 && percent <= 100)]];
    #endif

        size_t current_index = core::custom_table.size();

        core::custom_technique query{
            percent,
            static_cast<u16>(static_cast<int>(base_technique_count) + static_cast<int>(current_index) + 1),
            detection_func
        };

        technique_count++;

        core::custom_table.push_back(query);
    }


    /**
     * @brief disable the provided technique flags so they are not counted to the overall result
     * @param technique flag(s) only
     * @link https://github.com/kernelwernel/VMAware/blob/main/docs/documentation.md#vmdetect
     * @return flagset
     */
    template <typename ...Args>
    static enum_flags DISABLE(Args ...args) {
        // basically core::arg_handler but in reverse,
        // it'll clear the bits of the provided flags
        core::disabled_arg_handler(args...);
        return VM::NULL_ARG;
    }

    /**
     * @brief This will convert the technique flag into a string, which will correspond to the technique name
     * @param single technique flag in VM structure
     */
    [[nodiscard]] static std::string flag_to_string(const enum_flags flag) {
        switch (flag) {
            // START OF TECHNIQUE LIST
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
            case HWMODEL: return "HWMODEL";
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
            case VPC_INVALID: return "VPC_INVALID";
            case SYSTEM_REGISTERS: return "TASK_SEGMENT";
            case VMWARE_IOMEM: return "VMWARE_IOMEM";
            case VMWARE_IOPORTS: return "VMWARE_IOPORTS";
            case VMWARE_SCSI: return "VMWARE_SCSI";
            case VMWARE_DMESG: return "VMWARE_DMESG";
            case VMWARE_STR: return "VMWARE_STR";
            case VMWARE_BACKDOOR: return "VMWARE_BACKDOOR";
            case MUTEX: return "MUTEX";
            case THREAD_MISMATCH: return "THREAD_MISMATCH";
            case CUCKOO_DIR: return "CUCKOO_DIR";
            case CUCKOO_PIPE: return "CUCKOO_PIPE";
            case AZURE: return "AZURE";
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
            case IVSHMEM: return "IVSHMEM";
            case GPU_CAPABILITIES: return "GPU_CAPABILITIES";
            case DEVICE_HANDLES: return "DEVICE_HANDLES";
            case QEMU_FW_CFG: return "QEMU_FW_CFG";
            case VIRTUAL_PROCESSORS: return "VIRTUAL_PROCESSORS";
            case HYPERVISOR_QUERY: return "HYPERVISOR_QUERY";
            case AMD_SEV: return "AMD_SEV";
            case VIRTUAL_REGISTRY: return "VIRTUAL_REGISTRY";
            case FIRMWARE: return "FIRMWARE";
            case FILE_ACCESS_HISTORY: return "FILE_ACCESS_HISTORY";
            case AUDIO: return "AUDIO";
            case NSJAIL_PID: return "NSJAIL_PID";
            case PCI_DEVICES: return "PCI_DEVICES";
            case ACPI_SIGNATURE: return "ACPI_SIGNATURE";
            case TRAP: return "TRAP";
            case UD: return "UNDEFINED_INSTRUCTION";
            case BLOCKSTEP: return "BLOCKSTEP";
            case DBVM: return "DBVM";
            case BOOT_LOGO: return "BOOT_LOGO";
            case MAC_SYS: return "MAC_SYS";
            case KERNEL_OBJECTS: return "KERNEL_OBJECTS";
            case NVRAM: return "NVRAM";
            case SMBIOS_INTEGRITY: return "SMBIOS_INTEGRITY";
            case EDID: return "EDID";
            case CPU_HEURISTIC: return "CPU_HEURISTIC";
            case CLOCK: return "CLOCK";
            // END OF TECHNIQUE LIST
            case DEFAULT: return "DEFAULT"; 
            case ALL: return "ALL"; 
            case NULL_ARG: return "NULL_ARG"; 
            case HIGH_THRESHOLD: return "HIGH_THRESHOLD"; 
            case DYNAMIC: return "DYNAMIC"; 
            case MULTIPLE: return "MULTIPLE"; 
            default: return "Unknown flag";
        }
    }


    /**
     * @brief Fetch all the brands that were detected in a vector
     * @param any flag combination in VM structure or nothing
     * @return VM::enum_vector
     */
    template <typename ...Args>
    static std::vector<enum_flags> detected_enums(Args ...args) {
        const flagset flags = core::arg_handler(args...);
        return detected_enums(flags);
    }


    static std::vector<enum_flags> detected_enums(const flagset &flags = core::generate_default()) {
        std::vector<enum_flags> tmp;

        // this will loop through all the enums in the technique_vector variable,
        // and then checks each of them and outputs the enum that was detected
        for (u8 i = technique_begin; i < technique_end; ++i) {
            const enum_flags technique_enum = static_cast<enum_flags>(i);

            if (
                (flags.test(technique_enum)) &&
                (check(technique_enum))
            ) {
                tmp.push_back(technique_enum);
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
    #if (SOURCE_LOCATION_SUPPORTED)
        , const std::source_location& loc = std::source_location::current()
    #endif
    ) {
        // lambda to throw the error
        auto throw_error = [&](const char* text) -> void {
            std::stringstream ss;
    #if (VMA_CPP >= 20 && !CLANG)
            ss << ", error in " << loc.function_name() << " at " << loc.file_name() << ":" << loc.line() << ")";
    #endif
            ss << ". Consult the documentation's parameters for VM::modify_score()";
            throw std::invalid_argument(std::string(text) + ss.str());
        };

        if (percent > 100) {
            throw_error("Percentage parameter must be between 0 and 100");
        }

    #if (VMA_CPP >= 23)
        [[assume(percent <= 100)]];
    #endif  

        // check if the flag provided is a setting flag, which isn't valid
        if (static_cast<u8>(flag) >= technique_end) {
            throw_error("The flag is not a technique flag");
        }

        core::technique_table[flag].points = percent;
    }

    /**
     * @brief Fetch the total number of detected techniques
     * @param any flag combination in VM structure or nothing
     * @return std::uint8_t
     */
    template <typename ...Args>
    static u8 detected_count(Args ...args) {
        const flagset flags = core::arg_handler(args...);
        return detected_count(flags);
    }


    static u8 detected_count(const flagset &flags = core::generate_default()) {
        // run all the techniques, which will set the detected_count variable 
        core::run_all(flags);

        return detected_count_num;
    }


    /**
     * @brief Fetch the total number of detected techniques
     * @param any flag combination in VM structure or nothing
     * @return const char*
     */
    template <typename ...Args>
    static std::string type(Args ...args) {
        const flagset flags = core::arg_handler(args...);
        return type(flags);
    }


    static std::string type(const flagset &flags = core::generate_default()) {
        const std::string brand_str = brand(flags);

        // if multiple brands were found, return unknown
        if (util::find(brand_str, " or ")) {
            return "Unknown";
        }

        struct map_entry {
            const char* name;
            const char* type;
        };

        // Static table for O(1) scanning
        static constexpr map_entry type_table[] = {
            // type 1
            { brands::XEN, "Hypervisor (type 1)" },
            { brands::VMWARE_ESX, "Hypervisor (type 1)" },
            { brands::ACRN, "Hypervisor (type 1)" },
            { brands::QNX, "Hypervisor (type 1)" },
            { brands::HYPERV, "Hypervisor (type 2)" }, // to clarify you're running under a Hyper-V guest VM
            { brands::AZURE_HYPERV, "Hypervisor (type 1)" },
            { brands::KVM, "Hypervisor (type 1)" },
            { brands::KVM_HYPERV, "Hypervisor (type 1)" },
            { brands::QEMU_KVM_HYPERV, "Hypervisor (type 1)" },
            { brands::QEMU_KVM, "Hypervisor (type 1)" },
            { brands::INTEL_KGT, "Hypervisor (type 1)" },
            { brands::SIMPLEVISOR, "Hypervisor (type 1)" },
            { brands::OPENSTACK, "Hypervisor (type 1)" },
            { brands::KUBEVIRT, "Hypervisor (type 1)" },
            { brands::POWERVM, "Hypervisor (type 1)" },
            { brands::AWS_NITRO, "Hypervisor (type 1)" },
            { brands::LKVM, "Hypervisor (type 1)" },
            { brands::NOIRVISOR, "Hypervisor (type 1)" },
            { brands::WSL, "Hypervisor (Type 1)" }, // Type 1-derived lightweight VM system
            { brands::DBVM, "Hypervisor (Type 1)" }, 

            // type 2
            { brands::BHYVE, "Hypervisor (type 2)" },
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
            { brands::HYPERV_VPC, "Hypervisor (type 2)" },
            { brands::VMWARE_HARD, "Hypervisor (type 2)" },
            { brands::UTM, "Hypervisor (type 2)" },
            { brands::INTEL_HAXM, "Hosted hypervisor / accelerator (type 2)" },

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

        for (const auto& entry : type_table) {
            // pointer comparison first , because is the fastest/O(1) relative to string length
            if (brand_str == entry.name) {
                return entry.type;
            }
        }

        // theres a chance of brand() returning a cache pointer but same content
        for (const auto& entry : type_table) {
            if (brand_str == entry.name) {
                return entry.type;
            }
        }

        debug("VM::type(): No known brand found, something went terribly wrong here...");

        return "Unknown";
    }


    /**
      * @brief Fetch the conclusion message based on the brand and percentage
      * @param any flag combination in VM structure or nothing
      * @return const char*
      */
    template <typename ...Args>
    static std::string conclusion(Args ...args) {
        const flagset flags = core::arg_handler(args...);
        return conclusion(flags);
    }


    static std::string conclusion(const flagset &flags = core::generate_default()) {
        std::string brand_tmp = brand(flags);
        const u8 percent_tmp = percentage(flags);
        const bool has_hardener = is_hardened();

        constexpr const char* very_unlikely = "Very unlikely";
        constexpr const char* unlikely = "Unlikely";
        constexpr const char* potentially = "Potentially";
        constexpr const char* might = "Might be";
        constexpr const char* likely = "Likely";
        constexpr const char* very_likely = "Very likely";
        constexpr const char* inside_vm = "Running inside";

        auto make_conclusion = [&](const char* category) -> std::string {
            if (memo::conclusion::cached) {
                return memo::conclusion::fetch();
            }

            const char* hardener = "";
            
            if (has_hardener) {
                hardener = "hardened ";
            }
            
            const char* addition = " a ";

            // this basically just fixes the grammatical syntax
            // by either having "a" or "an" before the VM brand
            // name. It would look weird if the conclusion 
            // message was "an VirtualBox" or "a Anubis", so this
            // condition fixes that issue.
            if (
                !has_hardener && (
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
                )
            ) {
                addition = " an ";
            }

            // this is basically just to remove the capital "U", 
            // since it doesn't make sense to see "an Unknown"
            if (brand_tmp == brands::NULL_BRAND) {
                brand_tmp = "unknown";
            }

            // Hyper-V artifacts are an exception due to how unique the circumstance is
            const std::string result = 
                std::string(category) + 
                addition + 
                hardener + 
                brand_tmp + 
                (brand_tmp == brands::HYPERV_ARTIFACT ? "" : " VM");

            memo::conclusion::store(result.c_str());

            return result;
        };

        if (has_hardener) {
            return make_conclusion(inside_vm);
        }

        if (core::is_enabled(flags, DYNAMIC)) {
            if (percent_tmp == 0) { return "Running on baremetal"; }
            else if (percent_tmp <= 20) { return make_conclusion(very_unlikely); }
            else if (percent_tmp <= 35) { return make_conclusion(unlikely); }
            else if (percent_tmp < 50) { return make_conclusion(potentially); }
            else if (percent_tmp <= 62) { return make_conclusion(might); }
            else if (percent_tmp <= 75) { return make_conclusion(likely); }
            else if (percent_tmp < 100) { return make_conclusion(very_likely); }
        }

        if (percent_tmp == 100) {
            return make_conclusion(inside_vm);
        }

        return "Running on baremetal";
    }


    /**
     * @brief Returns whether it suspects the environment has anti-VM hardening
     * @return bool
     */
    static bool is_hardened() {
        if (memo::hardened::cached) {
            return memo::hardened::result;
        }

        auto hardened_logic = []() -> bool {
            // Helper to get the specific brand associated with a technique using the cache.
            auto detected_brand = [](const enum_flags flag) -> const char* {
                if (!check(flag)) {
                    return brands::NULL_BRAND;
                }
                if (memo::cache_table[flag].has_value) {
                    const char* b = memo::cache_table[flag].brand_name;
                    return (b != nullptr) ? b : brands::NULL_BRAND;
                }
                return brands::NULL_BRAND;
            };

            const bool hv_present = (check(VM::HYPERVISOR_BIT) || check(VM::HYPERVISOR_STR));

            // rule 1: if VM::FIRMWARE is detected, so should VM::HYPERVISOR_BIT or VM::HYPERVISOR_STR
            const char* firmware_brand = detected_brand(VM::FIRMWARE);
            if (firmware_brand != brands::NULL_BRAND && !hv_present) {
                return true;
            }

        #if (LINUX)
            // rule 2: if VM::FIRMWARE is detected, so should VM::CVENDOR (QEMU or VBOX)
            if (firmware_brand == brands::QEMU || firmware_brand == brands::VBOX) {
                const char* cvendor_brand = detected_brand(VM::CVENDOR);
                if (firmware_brand != cvendor_brand) {
                    return true;
                }
            }
        #endif

        #if (WINDOWS)        
            // rule 3: if VM::ACPI_SIGNATURE (QEMU) is detected, so should VM::FIRMWARE (QEMU)
            const char* acpi_brand = detected_brand(VM::ACPI_SIGNATURE);
            if (acpi_brand == brands::QEMU && firmware_brand != brands::QEMU) {
                return true;
            }

            // rule 4: if VM::TRAP or VM::NVRAM is detected, so should VM::HYPERVISOR_BIT or VM::HYPERVISOR_STR
            if ((check(VM::TRAP) || check(VM::NVRAM)) && !hv_present) {
                return true;
            }
        #endif

            return false;
        };

        const bool result = hardened_logic();

        memo::hardened::result = result;
        memo::hardened::cached = true;

        return result;
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
        std::vector<enum_flags> detected_techniques;
        std::vector<std::string> detected_technique_strings;
        std::vector<enum_flags> disabled_techniques;

        template <typename ...Args>
        vmaware(Args&& ...args) {
            const flagset flags = core::arg_handler(args...);
            initialise(flags);
        }

        vmaware(const flagset &flags) {
            initialise(flags);
        }

        // having this design avoids some niche errors
        void initialise(const flagset &flags) {
            brand = VM::brand(flags);
            type = VM::type(flags);
            conclusion = VM::conclusion(flags);
            is_vm = VM::detect(flags);
            percentage = VM::percentage(flags);
            detected_count = VM::detected_count(flags);
            technique_count = VM::technique_count;
            detected_techniques = VM::detected_enums(flags);
            detected_technique_strings = [&]() -> std::vector<std::string> {
                std::vector<std::string> tmp{};

                for (const auto technique : detected_techniques) {
                    tmp.push_back(VM::flag_to_string(technique));
                }

                return tmp;
            }();
            disabled_techniques = VM::disabled_techniques;
        }

    };
    #pragma pack(pop)


    static u16 technique_count; // get total number of techniques
#ifdef __VMAWARE_DEBUG__
    static u16 total_points;
#endif
};

// ============= EXTERNAL DEFINITIONS =============
// These are added here due to warnings related to C++17 inline variables for C++ standards that are under 17
// It's easier to just group them together rather than having C++17<= preprocessors with inline stuff
char VM::memo::conclusion::cache[512] = { 0 };
bool VM::memo::conclusion::cached = false;

// scoreboard list of brands, if a VM detection technique detects a brand, that will be incremented here as a single point
std::array<VM::core::brand_entry, VM::core::MAX_BRANDS> VM::core::brand_scoreboard = []() {
    std::array<VM::core::brand_entry, VM::core::MAX_BRANDS> arr{};
    size_t i = 0;

    auto insert = [&](const char* n) noexcept {
        if (i < VM::core::MAX_BRANDS) {
            arr[i] = { n, 0 };
            i++;
        }
    };

    insert(brands::VBOX);
    insert(brands::VMWARE);
    insert(brands::VMWARE_EXPRESS);
    insert(brands::VMWARE_ESX);
    insert(brands::VMWARE_GSX);
    insert(brands::VMWARE_WORKSTATION);
    insert(brands::VMWARE_FUSION);
    insert(brands::VMWARE_HARD);
    insert(brands::BHYVE);
    insert(brands::KVM);
    insert(brands::QEMU);
    insert(brands::QEMU_KVM);
    insert(brands::KVM_HYPERV);
    insert(brands::QEMU_KVM_HYPERV);
    insert(brands::HYPERV);
    insert(brands::HYPERV_VPC);
    insert(brands::PARALLELS);
    insert(brands::XEN);
    insert(brands::ACRN);
    insert(brands::QNX);
    insert(brands::HYBRID);
    insert(brands::SANDBOXIE);
    insert(brands::DOCKER);
    insert(brands::WINE);
    insert(brands::VPC);
    insert(brands::ANUBIS);
    insert(brands::JOEBOX);
    insert(brands::THREATEXPERT);
    insert(brands::CWSANDBOX);
    insert(brands::COMODO);
    insert(brands::BOCHS);
    insert(brands::NVMM);
    insert(brands::BSD_VMM);
    insert(brands::INTEL_HAXM);
    insert(brands::UNISYS);
    insert(brands::LMHS);
    insert(brands::CUCKOO);
    insert(brands::BLUESTACKS);
    insert(brands::JAILHOUSE);
    insert(brands::APPLE_VZ);
    insert(brands::INTEL_KGT);
    insert(brands::AZURE_HYPERV);
    insert(brands::SIMPLEVISOR);
    insert(brands::HYPERV_ARTIFACT);
    insert(brands::UML);
    insert(brands::POWERVM);
    insert(brands::GCE);
    insert(brands::OPENSTACK);
    insert(brands::KUBEVIRT);
    insert(brands::AWS_NITRO);
    insert(brands::PODMAN);
    insert(brands::WSL);
    insert(brands::OPENVZ);
    insert(brands::BAREVISOR);
    insert(brands::HYPERPLATFORM);
    insert(brands::MINIVISOR);
    insert(brands::INTEL_TDX);
    insert(brands::LKVM);
    insert(brands::AMD_SEV);
    insert(brands::AMD_SEV_ES);
    insert(brands::AMD_SEV_SNP);
    insert(brands::NEKO_PROJECT);
    insert(brands::QIHOO);
    insert(brands::NOIRVISOR);
    insert(brands::NSJAIL);
    insert(brands::DBVM);
    insert(brands::UTM);
    insert(brands::NULL_BRAND);

    return arr;
}();

// Dynamically count the brands initialized above
size_t VM::core::brand_count = []() -> size_t {
    size_t c = 0;
    for (const auto& b : VM::core::brand_scoreboard) {
        if (b.name != nullptr) c++;
    }
    return c;
}();

// initial definitions for cache items because C++ forbids in-class initializations
std::array<VM::memo::cache_entry, VM::enum_size + 1> VM::memo::cache_table{};
char VM::memo::brand::brand_cache[512] = { 0 };
char VM::memo::multi_brand::brand_cache[1024] = { 0 };
char VM::memo::cpu_brand::brand_cache[128] = { 0 };
char VM::memo::bios_info::manufacturer[256] = { 0 };
char VM::memo::bios_info::model[128] = { 0 };
bool VM::memo::brand::cached = false;
bool VM::memo::multi_brand::cached = false;
bool VM::memo::cpu_brand::cached = false;
bool VM::memo::bios_info::cached = false;
bool VM::memo::hyperx::cached = false;
bool VM::memo::hardened::result = false;
bool VM::memo::hardened::cached = false;
VM::u32 VM::memo::threadcount::threadcount_cache = 0;
VM::hyperx_state VM::memo::hyperx::state = VM::HYPERV_UNKNOWN;
std::array<VM::memo::leaf_entry, VM::memo::leaf_cache::CAPACITY> VM::memo::leaf_cache::table{};
std::size_t VM::memo::leaf_cache::count = 0;
std::size_t VM::memo::leaf_cache::next_index = 0;
const char* VM::core::last_detected_brand = nullptr;
VM::u8 VM::core::last_detected_score = 0;

#ifdef __VMAWARE_DEBUG__
VM::u16 VM::total_points = 0;
#endif

// these are basically the base values for the core::arg_handler function.
// It's like a bucket that will collect all the bits enabled. If for example 
// VM::detect(VM::HIGH_THRESHOLD) is passed, the HIGH_THRESHOLD bit will be 
// collected to this flagset (std::bitset) variable, and eventually be provided
// as the return value for actual end-user functions like VM::detect() to operate on.
VM::flagset VM::core::flag_collector;
VM::flagset VM::core::disabled_flag_collector;


VM::u8 VM::detected_count_num = 0;

std::vector<VM::enum_flags> VM::disabled_techniques = []() {
    std::vector<VM::enum_flags> c;
    c.push_back(VM::VMWARE_DMESG);
    return c;
}();

// this value is incremented each time VM::add_custom is called
VM::u16 VM::technique_count = base_technique_count;

// this is initialised as empty, because this is where custom techniques can be added at runtime 
std::vector<VM::core::custom_technique> VM::core::custom_table = {

}; 
size_t VM::core::custom_table_size = 0;

// the 0~100 points are debatable, but we think it's fine how it is. Feel free to disagree
std::array<VM::core::technique, VM::enum_size + 1> VM::core::technique_table = []() {
    std::array<VM::core::technique, VM::enum_size + 1> table{};
    // FORMAT: { VM::<ID>, { certainty%, function pointer } },
    const VM::core::technique_entry entries[] = {
        // START OF TECHNIQUE TABLE
        #if (WINDOWS)
            {VM::TRAP, {100, VM::trap}},
            {VM::ACPI_SIGNATURE, {100, VM::acpi_signature}},
            {VM::NVRAM, {100, VM::nvram}},
            {VM::CLOCK, {90, VM::clock}},
            {VM::POWER_CAPABILITIES, {45, VM::power_capabilities}},
            {VM::CPU_HEURISTIC, {90, VM::cpu_heuristic}},
            {VM::EDID, {100, VM::edid}},
            {VM::BOOT_LOGO, {100, VM::boot_logo}},
            {VM::GPU_CAPABILITIES, {45, VM::gpu_capabilities}},
            {VM::SMBIOS_INTEGRITY, {50, VM::smbios_integrity}},
            {VM::DISK_SERIAL, {100, VM::disk_serial_number}},
            {VM::IVSHMEM, {100, VM::ivshmem}},
            {VM::DRIVERS, {100, VM::drivers}},
            {VM::DEVICE_HANDLES, {100, VM::device_handles}},
            {VM::VIRTUAL_PROCESSORS, {100, VM::virtual_processors}},
            {VM::KERNEL_OBJECTS, {100, VM::kernel_objects}},
            {VM::HYPERVISOR_QUERY, {100, VM::hypervisor_query}},
            {VM::AUDIO, {25, VM::audio}},
            {VM::DISPLAY, {25, VM::display}},
            {VM::WINE, {100, VM::wine}},
            {VM::DLL, {50, VM::dll}},
            {VM::DBVM, {150, VM::dbvm}},
            {VM::UD, {100, VM::ud}},
            {VM::BLOCKSTEP, {100, VM::blockstep}},
            {VM::VMWARE_BACKDOOR, {100, VM::vmware_backdoor}},
            {VM::VIRTUAL_REGISTRY, {90, VM::virtual_registry}},
            {VM::MUTEX, {100, VM::mutex}},
            {VM::DEVICE_STRING, {25, VM::device_string}},
            {VM::VPC_INVALID, {75, VM::vpc_invalid}},
            {VM::VMWARE_STR, {35, VM::vmware_str}},
            {VM::GAMARUE, {10, VM::gamarue}},
            {VM::CUCKOO_DIR, {30, VM::cuckoo_dir}},
            {VM::CUCKOO_PIPE, {30, VM::cuckoo_pipe}},
        #endif

        #if (LINUX || WINDOWS)
            {VM::FIRMWARE, {100, VM::firmware}},
            {VM::PCI_DEVICES, {95, VM::pci_devices}},
            {VM::SYSTEM_REGISTERS, {50, VM::system_registers}},
            {VM::AZURE, {30, VM::azure}},
        #endif

        #if (LINUX)
            {VM::SMBIOS_VM_BIT, {50, VM::smbios_vm_bit}},
            {VM::KMSG, {5, VM::kmsg}},
            {VM::CVENDOR, {65, VM::chassis_vendor}},
            {VM::QEMU_FW_CFG, {70, VM::qemu_fw_cfg}},
            {VM::SYSTEMD, {35, VM::systemd_virt}},
            {VM::CTYPE, {20, VM::chassis_type}},
            {VM::DOCKERENV, {30, VM::dockerenv}},
            {VM::DMIDECODE, {55, VM::dmidecode}},
            {VM::DMESG, {55, VM::dmesg}},
            {VM::HWMON, {35, VM::hwmon}},
            {VM::LINUX_USER_HOST, {10, VM::linux_user_host}},
            {VM::VMWARE_IOMEM, {65, VM::vmware_iomem}},
            {VM::VMWARE_IOPORTS, {70, VM::vmware_ioports}},
            {VM::VMWARE_SCSI, {40, VM::vmware_scsi}},
            {VM::VMWARE_DMESG, {65, VM::vmware_dmesg}},
            {VM::QEMU_VIRTUAL_DMI, {40, VM::qemu_virtual_dmi}},
            {VM::QEMU_USB, {20, VM::qemu_USB}},
            {VM::HYPERVISOR_DIR, {20, VM::hypervisor_dir}},
            {VM::UML_CPU, {80, VM::uml_cpu}},
            {VM::VBOX_MODULE, {15, VM::vbox_module}},
            {VM::SYSINFO_PROC, {15, VM::sysinfo_proc}},
            {VM::DMI_SCAN, {50, VM::dmi_scan}},
            {VM::PODMAN_FILE, {5, VM::podman_file}},
            {VM::WSL_PROC, {30, VM::wsl_proc_subdir}},
            {VM::FILE_ACCESS_HISTORY, {15, VM::file_access_history}},
            {VM::MAC, {20, VM::mac_address_check}},
            {VM::NSJAIL_PID, {75, VM::nsjail_proc_id}},
            {VM::BLUESTACKS_FOLDERS, {5, VM::bluestacks}},
            {VM::AMD_SEV, {50, VM::amd_sev}},
            {VM::TEMPERATURE, {80, VM::temperature}},
            {VM::PROCESSES, {40, VM::processes}},
        #endif    

        #if (LINUX || APPLE)
            {VM::THREAD_COUNT, {35, VM::thread_count}},
        #endif

        #if (APPLE)
            {VM::MAC_MEMSIZE, {15, VM::hw_memsize}},
            {VM::MAC_IOKIT, {100, VM::io_kit}},
            {VM::MAC_SIP, {100, VM::mac_sip}},
            {VM::IOREG_GREP, {100, VM::ioreg_grep}},
            {VM::HWMODEL, {100, VM::hwmodel}},
            {VM::MAC_SYS, {100, VM::mac_sys}},
        #endif

        {VM::TIMER, {150, VM::timer}},
        {VM::THREAD_MISMATCH, {50, VM::thread_mismatch}},
        {VM::VMID, {100, VM::vmid}},
        {VM::CPU_BRAND, {95, VM::cpu_brand}},
        {VM::CPUID_SIGNATURE, {95, VM::cpuid_signature}},
        {VM::HYPERVISOR_STR, {100, VM::hypervisor_str}},
        {VM::HYPERVISOR_BIT, {100, VM::hypervisor_bit}},
        {VM::BOCHS_CPU, {100, VM::bochs_cpu}},
        {VM::KGT_SIGNATURE, {80, VM::intel_kgt_signature}}
        // END OF TECHNIQUE TABLE
    };

    // fill the table based on ID
    for (const auto& entry : entries) {
        if (entry.id < table.size()) {
            table[entry.id] = entry.tech;
        }
    }
    return table;
}();

#endif // include guard end
