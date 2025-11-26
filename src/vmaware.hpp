/**
 * ██╗   ██╗███╗   ███╗ █████╗ ██╗    ██╗ █████╗ ██████╗ ███████╗
 * ██║   ██║████╗ ████║██╔══██╗██║    ██║██╔══██╗██╔══██╗██╔════╝
 * ██║   ██║██╔████╔██║███████║██║ █╗ ██║███████║██████╔╝█████╗
 * ╚██╗ ██╔╝██║╚██╔╝██║██╔══██║██║███╗██║██╔══██║██╔══██╗██╔══╝
 *  ╚████╔╝ ██║ ╚═╝ ██║██║  ██║╚███╔███╔╝██║  ██║██║  ██║███████╗
 *   ╚═══╝  ╚═╝     ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ Experimental post-2.5.0 (November 2025)
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
 * - enums for publicly accessible techniques  => line 534
 * - struct for internal cpu operations        => line 717
 * - struct for internal memoization           => line 1150
 * - struct for internal utility functions     => line 1280
 * - struct for internal core components       => line 10141
 * - start of VM detection technique list      => line 2077
 * - start of public VM detection functions    => line 10634
 * - start of externally defined variables     => line 11615
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
 * and that's perfectly understandable. I'd struggle as well if I were in your position
 * while not even knowing where to start. So here's a more human-friendly explanation:
 * 
 * 
 * Firstly, the lib is completely static, meaning that there's no need for struct 
 * constructors to be initialized (unless you're using the VM::vmaware struct).
 * The main focus of the lib are the tables:
 *  - the TECHNIQUE table stores all the VM detection technique information in a std::map 
 * 
 *  - the BRAND table stores every VM brand as a std::map as well, but as a scoreboard. 
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
     || defined(DEBUG)     /* user or build-system */ \
     || !defined(NDEBUG)   /* assert-enabled (standard) */
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
    #include <source_location>
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
#include <regex>
#include <thread>
#include <cstdint>
#include <map>
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
#include <numeric>

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
    #pragma comment(lib, "Mincore.lib")
    #pragma comment(lib,"wevtapi.lib")
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

#ifdef _UNICODE
    #define tregex std::wregex
#else
    #define tregex std::regex
#endif

#ifdef __VMAWARE_DEBUG__
    #define debug(...) VM::util::debug_msg(__VA_ARGS__)
#else
    #define debug(...)
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
    static constexpr const char* DBVM = "DBVM";
    static constexpr const char* UTM = "UTM";
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
        // Windows
        GPU_CAPABILITIES = 0,
        ACPI_SIGNATURE,
        POWER_CAPABILITIES,
        DISK_SERIAL,
        IVSHMEM,
        SGDT,
        SLDT,
        SMSW,
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
        OBJECTS,
        NVRAM,
        SMBIOS_INTEGRITY,
        EDID,
        CPU_HEURISTIC,
        CLOCK,
        LBR,

        // Linux and Windows
        SIDT,
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
        INTEL_THREAD_MISMATCH,
        AMD_THREAD_MISMATCH,
        XEON_THREAD_MISMATCH,
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
    static constexpr u8 LINUX_START = VM::SIDT;
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
    // this will allow the enum to be used in the public interface as "VM::TECHNIQUE"
    enum enum_flags tmp_ignore_this = HIGH_THRESHOLD;

    // constructor stuff ignore this
    VM() = delete;
    VM(const VM&) = delete;
    VM(VM&&) = delete;

private:
    // macro for bypassing unused parameter/variable warnings
    #define UNUSED(x) ((void)(x))

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

        // cross-platform wrapper function for linux and MSVC cpuid
        static void cpuid
        (
            u32& a, u32& b, u32& c, u32& d,
            const u32 a_leaf,
            const u32 c_leaf = 0xFF  // dummy value if not set manually
        ) {
        #if (x86 && !APPLE)
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
            #elif (LINUX)
                __cpuid_count(a_leaf, c_leaf, a, b, c, d);
            #endif
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
        #if (x86 && !APPLE)
            // may be unmodified for older 32-bit processors, clearing just in case
            x[1] = 0;
            x[2] = 0;
            #if (WINDOWS)
                __cpuidex((i32*)x, static_cast<int>(a_leaf), static_cast<int>(c_leaf));
            #elif (LINUX)
                __cpuid_count(a_leaf, c_leaf, x[0], x[1], x[2], x[3]);
            #endif
        #endif
            return;
        };

        static bool is_leaf_supported(const u32 p_leaf) {
        #if (APPLE) 
            return false;
        #endif
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

        [[nodiscard]] static std::string get_brand() {
            if (memo::cpu_brand::is_cached()) {
                return memo::cpu_brand::fetch();
            }

        #if (!x86 || APPLE)
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

            std::string b;
            b.reserve(48); // expected brand length

            union Regs {
                u32   i[4];
                char  c[16];
            } regs{};

            for (auto leaf_id : ids) {
                cpu::cpuid(regs.i[0], regs.i[1], regs.i[2], regs.i[3], leaf_id);
                b.append(regs.c, 16);
            }

            // do NOT touch trailing spaces for the AMD_THREAD_MISMATCH technique
            const size_t nul = b.find('\0');
            if (nul != std::string::npos) b.resize(nul);

            // left-trim only to handle stupid whitespaces before the brand string in ARM CPUs (Virtual CPUs)
            size_t start = 0;
            while (start < b.size() && std::isspace(static_cast<u8>(b[start]))) ++start;
            if (start) b.erase(0, start);

            memo::cpu_brand::store(b);
            debug("CPU: ", b);
            return b;
        #endif
        }

#if (WINDOWS)
        static u32 get_cpu_base_speed() {
            u32 a = 0, b = 0, c = 0, d = 0;

            if (cpu::is_leaf_supported(0x16u)) {
                cpu::cpuid(a, b, c, d, 0x16u);
                const u32 proc_base_mhz = a & 0xFFFFu;
                if (proc_base_mhz != 0) {
                    return proc_base_mhz;
                }
            }

            if (cpu::is_leaf_supported(0x15u)) {
                cpu::cpuid(a, b, c, d, 0x15u);
                const u32 denom = a;  
                const u32 numer = b;   
                const u32 core_crystal_hz = c; 
                if (denom != 0 && numer != 0 && core_crystal_hz != 0) {
                    const u64 tsc_hz = (u64)core_crystal_hz * (u64)numer / (u64)denom;
                    const u32 mhz = static_cast<u32>((tsc_hz + 500000ULL) / 1000000ULL);
                    if (mhz != 0) return mhz;
                }
            }

            // exposed by PPM/PEP framework and ACPI (likely _PSS, _CST and _PCT)
            const EVT_HANDLE hQuery = EvtQuery(nullptr, L"System",LR"(*[System[Provider[@Name='Microsoft-Windows-Kernel-Processor-Power'] and EventID=55]])", EvtQueryReverseDirection);
            if (!hQuery) return 0;
            LPCWSTR props[] = { L"Event/EventData/Data[@Name='Number']", L"Event/EventData/Data[@Name='NominalFrequency']" };
            const EVT_HANDLE hCtx = EvtCreateRenderContext(2, props, EvtRenderContextValues);
            if (!hCtx) { EvtClose(hQuery); return 0; }

            auto to_u64 = [](EVT_VARIANT& v)->uint64_t {
                switch (v.Type) {
                case EvtVarTypeUInt32:  return v.UInt32Val;
                case EvtVarTypeUInt64:  return v.UInt64Val;
                case EvtVarTypeInt32:   return (uint64_t)v.Int32Val;
                case EvtVarTypeInt64:   return (uint64_t)v.Int64Val;
                case EvtVarTypeUInt16:  return v.UInt16Val;
                case EvtVarTypeSByte:   return (uint8_t)v.SByteVal;
                case EvtVarTypeByte:    return v.ByteVal;
                case EvtVarTypeBoolean: return v.BooleanVal ? 1ull : 0ull;
                case EvtVarTypeDouble:  return (uint64_t)v.DoubleVal;
                case EvtVarTypeAnsiString:
                    if (v.AnsiStringVal) try { return std::stoull(std::string(v.AnsiStringVal)); }
                    catch (...) { return 0; }
                    return 0;
                case EvtVarTypeString:
                    if (v.StringVal) try { return std::stoull(std::wstring(v.StringVal)); }
                    catch (...) { return 0; }
                    return 0;
                default:
                    return 0;
                }
            };

            const DWORD BATCH = 16;
            std::vector<EVT_HANDLE> events(BATCH);
            while (true) {
                DWORD returned = 0;
                if (!EvtNext(hQuery, BATCH, events.data(), INFINITE, 0, &returned)) {
                    if (GetLastError() == ERROR_NO_MORE_ITEMS) break;
                    break;
                }
                for (DWORD i = 0; i < returned; ++i) {
                    EVT_HANDLE hEv = events[i];
                    DWORD needed = 0, propCount = 0;
                    EvtRender(hCtx, hEv, EvtRenderEventValues, 0, nullptr, &needed, &propCount);
                    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || needed == 0) { EvtClose(hEv); continue; }
                    std::vector<BYTE> buf(needed);
                    if (!EvtRender(hCtx, hEv, EvtRenderEventValues, needed, buf.data(), &needed, &propCount)) { EvtClose(hEv); continue; }
                    EvtClose(hEv);
                    if (propCount < 2) continue;
                    EVT_VARIANT* v = reinterpret_cast<EVT_VARIANT*>(buf.data());
                    uint64_t num = to_u64(v[0]);
                    if (num != 0) continue; // only processor Number == 0 because thats where we will pin our thread on VM::TIMER and other functions
                    uint64_t nominal = to_u64(v[1]);
                    if (nominal != 0) { EvtClose(hCtx); EvtClose(hQuery); return static_cast<uint32_t>(nominal); }
                }
            }
            EvtClose(hCtx);
            EvtClose(hQuery);

            return 0;
        }
#endif

        static std::string cpu_manufacturer(const u32 p_leaf) {
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

        static stepping_struct fetch_steppings() {
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

            std::regex amd_a_series("AMD A[0-9]+-[0-9]+", std::regex_constants::icase);
            return std::regex_search(model.string, amd_a_series);
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

        static void uncache(const u16 technique_macro) {
            cache_table.erase(technique_macro);
            cache_keys.set(technique_macro, false);
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

        struct brand {
            static std::string brand_cache;

            static const std::string& fetch() {
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

            static const std::string& fetch() {
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

            static const std::string& fetch() {
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

#if (LINUX)
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
            const HANDLE hCurrentProcess = reinterpret_cast<HANDLE>(-1LL);
            if (OpenProcessToken(hCurrentProcess, TOKEN_QUERY, &hToken)) {
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
            UNUSED(cmd);
            return util::make_unique<std::string>();
        #else
            #if (LINUX || APPLE)
                struct FileDeleter {
                    void operator()(FILE* f) const noexcept {
                        if (f) {
                            pclose(f);
                        };
                    }
                };

                std::unique_ptr<FILE, FileDeleter> pipe(popen(cmd, "r"), FileDeleter());
                if (!pipe) {
                    return util::make_unique<std::string>();
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
            const HANDLE hCurrentProcess = reinterpret_cast<HANDLE>(-1LL);
            USHORT procMachine = 0, nativeMachine = 0;
            const auto pIsWow64Process2 = &IsWow64Process2;

            if (pIsWow64Process2(hCurrentProcess, &procMachine, &nativeMachine)) {
                if (nativeMachine == IMAGE_FILE_MACHINE_ARM64 &&
                    (procMachine == IMAGE_FILE_MACHINE_AMD64 || procMachine == IMAGE_FILE_MACHINE_I386)) {
                    debug("Translator detected x64/x86 process on ARM64");
                    return true;
                }
            }

            // only if we got MACHINE_UNKNOWN on process but native is ARM64
            if (nativeMachine == IMAGE_FILE_MACHINE_ARM64) {
                using PGetProcessInformation = BOOL(__stdcall*)(HANDLE, PROCESS_INFORMATION_CLASS, PVOID, DWORD);
                const HMODULE ntdll = util::get_ntdll();
                if (ntdll == nullptr) {
                    return false;
                }

                const char* names[] = { "GetProcessInformation" };
                void* funcs[1] = { nullptr };
                util::get_function_address(ntdll, names, funcs, 1);

                PGetProcessInformation pGetProcInfo = reinterpret_cast<PGetProcessInformation>(funcs[0]);
                if (pGetProcInfo) {
                    struct PROCESS_MACHINE_INFORMATION {
                        USHORT ProcessMachine;
                        USHORT Res0;
                        DWORD  MachineAttributes;
                    } pmInfo = {};
                    // ProcessMachineTypeInfo == 9 per MS Q&A
                    if (pGetProcInfo(hCurrentProcess, (PROCESS_INFORMATION_CLASS)9, &pmInfo, sizeof(pmInfo))) {
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

            // check if hypervisor feature bit in CPUID eax bit 31 is enabled (always false for physical CPUs)
            auto is_hyperv_present = []() -> bool {
                u32 unused, ecx = 0;
                cpu::cpuid(unused, unused, ecx, unused, 1);

                const u32 mask = (1u << 31);
                return (ecx & mask);
            };

            // 0x40000003 on EBX indicates the flags that a parent partition specified to create a child partition (https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/tlfs/datatypes/hv_partition_privilege_mask)
            auto is_root_partition = []() -> bool {
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
            auto eax = []() -> u32 {
                char out[sizeof(i32) * 4 + 1] = { 0 };
                cpu::cpuid(reinterpret_cast<int*>(out), cpu::leaf::hypervisor);

                const u32 eax = static_cast<u32>(out[0]);

                return eax;
            };

            hyperx_state state;

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
                // normally eax 12
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

#if (WINDOWS)
        // retrieves the addresses of specified functions from a loaded module using the export directory, manual implementation of GetProcAddress
        static void get_function_address(const HMODULE hModule, const char* names[], void** functions, size_t count) {
            using FuncMap = std::unordered_map<std::string, void*>;
            static std::unordered_map<HMODULE, FuncMap> function_cache;

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

            auto valid_range = [&](size_t offset, size_t sz) -> bool {
                if (sz == 0) return false;
                if (module_size == 0) return false;
                if (offset >= module_size) return false;
                if (sz > module_size) return false;
                if (offset > module_size - sz) return false;
                return true;
            };

            auto safe_cstr_from_rva = [&](DWORD rva) -> const char* {
                if (!valid_range(static_cast<size_t>(rva), 1)) return nullptr;
                const char* p = reinterpret_cast<const char*>(base + rva);
                const size_t remaining = module_size - static_cast<size_t>(rva);
                for (size_t i = 0; i < remaining; ++i) {
                    if (p[i] == '\0') return p;
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

            FuncMap& module_cache = function_cache[hModule];

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
                    const char* midName = safe_cstr_from_rva(midNameRva);
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
                    const char* candidateName = safe_cstr_from_rva(nameRvas[lo]);
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
            static HMODULE cachedNtdll = nullptr;
            if (cachedNtdll != nullptr) {
                return cachedNtdll;
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
                const HMODULE h = GetModuleHandleW(L"ntdll.dll");
                if (h) cachedNtdll = h;
                return h;
            }

            PPEB_LDR_DATA ldr = peb->Ldr;
            if (!ldr) {
                const HMODULE h = GetModuleHandleW(L"ntdll.dll");
                if (h) cachedNtdll = h;
                return h;
            }

            #ifndef CONTAINING_RECORD
                #define CONTAINING_RECORD(address, type, field) ((type *)((char*)(address) - (size_t)(&((type *)0)->field)))
            #endif

            constexpr const WCHAR targetName[] = L"ntdll.dll";
            constexpr size_t targetLen = (std::size(targetName) - 1);

            LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
            for (LIST_ENTRY* cur = head->Flink; cur != head; cur = cur->Flink) {
                auto* ent = CONTAINING_RECORD(cur, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
                if (!ent) continue;

                auto* fullname = &ent->FullDllName;
                if (!fullname->Buffer || fullname->Length == 0) continue;

                const auto totalChars = static_cast<USHORT>(fullname->Length / sizeof(WCHAR));

                size_t start = totalChars;
                while (start > 0) {
                    const WCHAR c = fullname->Buffer[start - 1];
                    if (c == L'\\' || c == L'/') break;
                    --start;
                }

                const size_t fileLen = totalChars - start;
                if (fileLen != targetLen) continue;

                bool match = true;
                for (size_t i = 0; i < fileLen; ++i) {
                    WCHAR a = fullname->Buffer[start + i];
                    WCHAR b = targetName[i];
                    if (a >= L'A' && a <= L'Z') a = static_cast<WCHAR>(a + 32);
                    if (b >= L'A' && b <= L'Z') b = static_cast<WCHAR>(b + 32);
                    if (a != b) { match = false; break; }
                }

                if (match) {
                    cachedNtdll = reinterpret_cast<HMODULE>(ent->DllBase);
                    return cachedNtdll;
                }
            }

            const HMODULE h = GetModuleHandleW(L"ntdll.dll");
            if (h) cachedNtdll = h;
            return h;
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
     * @brief Check if hypervisor feature bit in CPUID eax bit 31 is enabled (always false for physical CPUs)
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

        const auto hx = util::hyper_x();
        if (hx != HYPERV_UNKNOWN) {
            debug("HYPERVISOR_BIT: Running under nested virtualization");
            return true; // hypervisor bit is not set but Hyper-V was detected through root partition checks
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
        }
        else if (amd) {
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
     * @brief Check for Intel I-series CPU thread count database if it matches the system's thread count
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

        // we want to precompute hashes at compile time for C++11 and later, so we need to match the hardware _mm_crc32_u8
        // it is based on CRC32-C (Castagnoli) polynomial
        struct ConstexprHash {
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
        struct Entry {
            u32 hash;
            u32 threads;
            constexpr Entry(const char* m, u32 t) : hash(ConstexprHash::get(m)), threads(t) {}
        };

        // umap is not an option because it cannot be constexpr
        // constexpr is respected here even in c++ 11 and static solves stack overflow
        // c arrays have less construction overhead than std::array
        static constexpr Entry thread_database[] = {
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
            { "i7-4610M", 4 },
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
            { "i9-10900F", 20 },
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
            { "i9-12900H", 20 },
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

        // to save a few cycles
        static constexpr size_t MAX_INTEL_MODEL_LEN = 16;

        struct hasher {
            static u32 crc32_sw(u32 crc, char data) {
                crc ^= static_cast<u8>(data);
                for (int i = 0; i < 8; ++i)
                    crc = (crc >> 1) ^ ((crc & 1) ? 0x82F63B78u : 0);
                return crc;
            }

            #if (CLANG || GCC)
                __attribute__((__target__("crc32")))
            #endif
            static u32 crc32_hw(u32 crc, char data) {
                return _mm_crc32_u8(crc, static_cast<u8>(data));
            }

            using hashfc = u32(*)(u32, char);

            static hashfc get() {
                // yes, vmaware runs on dinosaur cpus without sse4.2 pretty often
                i32 regs[4];
                cpu::cpuid(regs, 1);
                const bool has_sse42 = (regs[2] & (1 << 20)) != 0;

                return has_sse42 ? crc32_hw : crc32_sw;
            }
        };

        const char* str = model.string.c_str();
        u32 expected_threads = 0;
        bool found = false;
        size_t best_len = 0;

        const auto hash_func = hasher::get();

        for (size_t i = 0; str[i] != '\0'; ) {
            const char c = str[i];
            if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) {
                i++;
                continue;
            }

            u32 current_hash = 0;
            size_t current_len = 0;
            size_t j = i;

            while (true) {
                const char k = str[j];
                const bool is_valid = (k >= '0' && k <= '9') ||
                    (k >= 'A' && k <= 'Z') ||
                    (k >= 'a' && k <= 'z') ||
                    (k == '-'); // models have hyphen
                if (!is_valid) break;

                if (current_len >= MAX_INTEL_MODEL_LEN) {
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
                    // since it's a contiguous block of integers in .rodata/.rdata, this is extremely fast
                    for (const auto& entry : thread_database) {
                        if (entry.hash == current_hash) {
                            if (current_len > best_len) {
                                best_len = current_len;
                                expected_threads = entry.threads;
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

        if (found) {
            const u32 actual = memo::threadcount::fetch();
            return actual != expected_threads;
        }

        return false;
    #endif
    }
                
                
    /**
     * @brief Check for Intel Xeon CPU thread count database if it matches the system's thread count
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

        // we want to precompute hashes at compile time for C++11 and later, so we need to match the hardware _mm_crc32_u8
        // it is based on CRC32-C (Castagnoli) polynomial
        struct ConstexprHash {
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
        struct Entry {
            u32 hash;
            u32 threads;
            constexpr Entry(const char* m, u32 t) : hash(ConstexprHash::get(m)), threads(t) {}
        };

        // umap is not an option because it cannot be constexpr
        // constexpr is respected here even in c++ 11 and static solves stack overflow
        // c arrays have less construction overhead than std::array
        static constexpr Entry thread_database[] = {
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
            { "W-3275M", 56 },
            { "w3-2423", 12 },
            { "w3-2425", 12 },
            { "w3-2435", 16 },
            { "w5-2445", 20 },
            { "w5-2455X", 24 },
            { "w5-2465X", 32 },
            { "w7-2475X", 40 },
            { "w7-2495X", 48 },
            { "w5-3425", 24 },
            { "w5-3435X", 32 },
            { "w7-3445", 40 },
            { "w7-3455", 48 },
            { "w7-3465X", 56 },
            { "w9-3475X", 72 },
            { "w9-3495X", 112 },
            { "w3-2525", 16 },
            { "w3-2535", 20 },
            { "w5-2545", 24 },
            { "w5-2555X", 28 },
            { "w5-2565X", 36 },
            { "w7-2575X", 44 },
            { "w7-2595X", 52 },
            { "w5-3525", 32 },
            { "w5-3535X", 40 },
            { "w7-3545", 48 },
            { "w7-3555", 56 },
            { "w7-3565X", 64 },
            { "w9-3575X", 88 },
            { "w9-3595X", 120 }
        };

        // to save a few cycles
        static constexpr size_t MAX_XEON_MODEL_LEN = 16;

        struct hasher {
            static u32 crc32_sw(u32 crc, char data) {
                crc ^= static_cast<u8>(data);
                for (int i = 0; i < 8; ++i)
                    crc = (crc >> 1) ^ ((crc & 1) ? 0x82F63B78u : 0);
                return crc;
            }

            #if (CLANG || GCC)
                __attribute__((__target__("crc32")))
            #endif
            static u32 crc32_hw(u32 crc, char data) {
                return _mm_crc32_u8(crc, static_cast<u8>(data));
            }

            using hashfc = u32(*)(u32, char);

            static hashfc get() {
                // yes, vmaware runs on dinosaur cpus without sse4.2 pretty often
                i32 regs[4];
                cpu::cpuid(regs, 1);
                const bool has_sse42 = (regs[2] & (1 << 20)) != 0;

                return has_sse42 ? crc32_hw : crc32_sw;
            }
        };

        const std::string& cpu_full_name = model.string;
        if (cpu_full_name.empty()) return false;

        const char* str = cpu_full_name.c_str();
        u32 expected_threads = 0;
        bool found = false;
        size_t best_len = 0;

        const auto hash_func = hasher::get();

        for (size_t i = 0; str[i] != '\0'; ) {
            const char c = str[i];
            if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) {
                i++;
                continue;
            }

            u32 current_hash = 0;
            size_t current_len = 0;
            size_t j = i;

            while (true) {
                const char k = str[j];
                const bool is_valid = (k >= '0' && k <= '9') ||
                    (k >= 'A' && k <= 'Z') ||
                    (k >= 'a' && k <= 'z') ||
                    (k == '-');
                if (!is_valid) break;

                if (current_len >= MAX_XEON_MODEL_LEN) {
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
                    // since it's a contiguous block of integers in .rodata/.rdata, this is extremely fast
                    for (const auto& entry : thread_database) {
                        if (entry.hash == current_hash) {
                            if (current_len > best_len) {
                                best_len = current_len;
                                expected_threads = entry.threads;
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

        if (found) {
            const u32 actual = memo::threadcount::fetch();
            debug("XEON_THREAD_MISMATCH: Expected threads -> ", expected_threads);
            return actual != expected_threads;
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

        std::string model_str = cpu::get_brand();

        static constexpr size_t MAX_AMD_TOKEN_LEN = 24; // "threadripper" is long

        struct ConstexprHash {
            static constexpr u32 crc32_bits(u32 crc, int bits) {
                return (bits == 0) ? crc :
                    crc32_bits((crc >> 1) ^ ((crc & 1) ? 0x82F63B78u : 0), bits - 1);
            }
            static constexpr u32 crc32_str(const char* s, u32 crc) {
                return (*s == '\0') ? crc :
                    crc32_str(s + 1, crc32_bits(crc ^ static_cast<u8>(*s), 8));
            }
            static constexpr u32 get(const char* s) {
                return crc32_str(s, 0);
            }
        };

        struct Entry {
            u32 hash;
            u32 threads;
            constexpr Entry(const char* m, u32 t) : hash(ConstexprHash::get(m)), threads(t) {}
        };

        // Database is reduced to identifying suffixes (last token of the original strings)
        // for example handles "ryzen 5 3600" by matching "3600", which is unique in context
        static constexpr Entry db_entries[] = {
            // 3015/3020
            { "3015ce", 4 },
            { "3015e", 4 },
            { "3020e", 2 },

            // Athlon/Ax suffixes
            { "860k", 4 },
            { "870k", 4 },
            { "pro-7350b", 4 },
            { "pro-7800b", 4 },
            { "pro-7850b", 4 },
            { "a10-6700", 4 },
            { "a10-6700t", 4 },
            { "a10-6790b", 4 },
            { "a10-6790k", 4 },
            { "a10-6800b", 4 },
            { "a10-6800k", 4 },
            { "a10-7300", 4 },
            { "a10-7400p", 4 },
            { "a10-7700k", 4 },
            { "a10-7800", 4 },
            { "a10-7850k", 4 },
            { "a10-7860k", 4 },
            { "a10-7870k", 4 },
            { "a10-8700b", 4 },
            { "a10-8700p", 4 },
            { "a10-8750b", 4 },
            { "a10-8850b", 4 },
            { "a12-8800b", 4 },
            { "micro-6400t", 4 },
            { "pro-3340b", 4 },
            { "pro-3350b", 4 },
            { "pro-7300b", 2 },
            { "a4-5000", 4 },
            { "a4-5100", 4 },
            { "a4-6210", 4 },
            { "a4-6300", 2 },
            { "a4-6320", 2 },
            { "a4-7210", 4 },
            { "a4-7300", 2 },
            { "a4-8350b", 2 },
            { "a4-9120c", 2 },
            { "pro-7050b", 2 },
            { "pro-7400b", 2 },
            { "a6-5200", 4 },
            { "a6-5200m", 4 },
            { "a6-5350m", 2 },
            { "a6-6310", 4 },
            { "a6-6400b", 2 },
            { "a6-6400k", 2 },
            { "a6-6420b", 2 },
            { "a6-6420k", 2 },
            { "a6-7000", 2 },
            { "a6-7310", 4 },
            { "a6-7400k", 2 },
            { "a6-8500b", 4 },
            { "a6-8500p", 2 },
            { "a6-8550b", 2 },
            { "a6-9220c", 2 },
            { "pro-7150b", 4 },
            { "pro-7600b", 4 },
            { "a8-6410", 4 },
            { "a8-6500", 4 },
            { "a8-6500b", 4 },
            { "a8-6500t", 4 },
            { "a8-6600k", 4 },
            { "a8-7100", 4 },
            { "a8-7200p", 4 },
            { "a8-7410", 4 },
            { "a8-7600", 4 },
            { "a8-7650k", 4 },
            { "a8-7670k", 4 },
            { "a8-8600b", 4 },
            { "a8-8600p", 4 },
            { "a8-8650b", 4 },

            // AI Series (Suffixes)
            { "340", 12 },
            { "350", 16 },
            { "360", 16 },
            { "365", 20 },
            { "370", 24 },
            { "375", 24 },
            { "380", 12 },
            { "385", 16 },
            { "390", 24 },
            { "395", 32 },

            // Athlon
            { "3050c", 2 },
            { "200ge", 4 },
            { "220ge", 4 },
            { "240ge", 4 },
            { "255e", 2 },
            { "3000g", 4 },
            { "300ge", 4 },
            { "300u", 4 },
            { "320ge", 4 },
            { "425e", 3 },
            { "460", 3 },
            { "5150", 4 },
            { "5350", 4 },
            { "5370", 4 },
            { "620e", 4 },
            { "631", 4 },
            { "638", 4 },
            { "641", 4 },
            { "740", 4 },
            { "750k", 4 },
            { "760k", 4 },
            { "3150c", 4 },
            { "3150g", 4 },
            { "3150ge", 4 },
            { "3150u", 4 },
            { "7220c", 4 },
            { "7220u", 4 },
            { "3045b", 2 },
            { "3145b", 4 },
            { "3050e", 4 },
            { "3050ge", 4 },
            { "3050u", 2 },
            { "7120c", 2 },
            { "7120u", 2 },
            { "3125ge", 4 },
            { "940", 4 },
            { "950", 4 },
            { "970", 4 },

            // Business Class
            { "b57", 2 },
            { "b59", 2 },
            { "b60", 2 },
            { "b75", 3 },
            { "b77", 3 },
            { "b97", 4 },
            { "b99", 4 },

            // E-Series
            { "micro-6200t", 2 },
            { "e1-2100", 2 },
            { "e1-2200", 2 },
            { "e1-2500", 2 },
            { "e1-6010", 2 },
            { "e1-7010", 2 },
            { "e2-3000", 2 },
            { "e2-3800", 4 },
            { "e2-6110", 4 },
            { "e2-7110", 4 },

            // FX
            { "fx-4100", 4 },
            { "fx-4130", 4 },
            { "fx-4170", 4 },
            { "fx-4300", 4 },
            { "fx-4320", 4 },
            { "fx-4350", 4 },
            { "fx-6200", 6 },
            { "fx-6300", 6 },
            { "fx-6350", 6 },
            { "fx-7500", 4 },
            { "fx-7600p", 4 },
            { "fx-8120", 8 },
            { "fx-8150", 8 },
            { "fx-8300", 8 },
            { "fx-8310", 8 },
            { "fx-8320", 8 },
            { "fx-8320e", 8 },
            { "fx-8350", 8 },
            { "fx-8370", 8 },
            { "fx-8370e", 8 },
            { "fx-8800p", 4 },
            { "fx-9370", 8 },
            { "fx-9590", 8 },

            // Misc
            { "micro-6700t", 4 },
            { "n640", 2 },
            { "n660", 2 },
            { "n870", 3 },
            { "n960", 4 },
            { "n970", 4 },
            { "p650", 2 },
            { "p860", 3 },

            // Phenom II
            { "1075t", 6 },
            { "555", 2 },
            { "565", 2 },
            { "570", 2 },
            { "840", 4 },
            { "850", 4 },
            { "960t", 4 },
            { "965", 4 },
            { "975", 4 },
            { "980", 4 },

            // Ryzen Suffixes (3/5/7/9/Threadripper consolidated)
            { "1200", 4 },
            { "1300x", 4 },
            { "210", 8 },
            { "2200g", 4 },
            { "2200ge", 4 },
            { "2200u", 4 },
            { "2300u", 4 },
            { "2300x", 4 },
            { "3100", 8 },
            { "3200g", 4 },
            { "3200ge", 4 },
            { "3200u", 4 },
            { "3250c", 4 },
            { "3250u", 4 },
            { "3300u", 4 },
            { "3300x", 8 },
            { "3350u", 4 },
            { "4100", 8 },
            { "4300g", 8 },
            { "4300ge", 8 },
            { "4300u", 4 },
            { "5125c", 4 },
            { "5300g", 8 },
            { "5300ge", 8 },
            { "5300u", 8 },
            { "5305g", 8 },
            { "5305ge", 8 },
            { "5400u", 8 },
            { "5425c", 8 },
            { "5425u", 8 },
            { "7320c", 8 },
            { "7320u", 8 },
            { "7330u", 8 },
            { "7335u", 8 },
            { "7440u", 8 },
            { "8300g", 8 },
            { "8300ge", 8 },
            { "8440u", 8 },
            { "1300", 4 },
            { "4350g", 8 },
            { "4350ge", 8 },
            { "4355g", 8 },
            { "4355ge", 8 },
            { "4450u", 8 },
            { "5350g", 8 },
            { "5350ge", 8 },
            { "5355g", 8 },
            { "5355ge", 8 },
            { "5450u", 8 },
            { "5475u", 8 },
            { "1400", 8 },
            { "1500x", 8 },
            { "1600", 12 },
            { "1600x", 12 },
            { "220", 12 },
            { "230", 12 },
            { "240", 12 },
            { "2400g", 8 },
            { "2400ge", 8 },
            { "2500u", 8 },
            { "2500x", 8 },
            { "2600", 12 },
            { "2600e", 12 },
            { "2600h", 8 },
            { "2600x", 12 },
            { "3400g", 8 },
            { "3400ge", 8 },
            { "3450u", 8 },
            { "3500", 6 },
            { "3500c", 8 },
            { "3500u", 8 },
            { "3550h", 8 },
            { "3580u", 8 },
            { "3600", 12 },
            { "3600x", 12 },
            { "3600xt", 12 },
            { "4500", 12 },
            { "4500u", 6 },
            { "4600g", 12 },
            { "4600ge", 12 },
            { "4600h", 12 },
            { "4600u", 12 },
            { "4680u", 12 },
            { "5500", 12 },
            { "5500gt", 12 },
            { "5500h", 8 },
            { "5500u", 12 },
            { "5560u", 12 },
            { "5600", 12 },
            { "5600g", 12 },
            { "5600ge", 12 },
            { "5600gt", 12 },
            { "5600h", 12 },
            { "5600hs", 12 },
            { "5600t", 12 },
            { "5600u", 12 },
            { "5600x", 12 },
            { "5600x3d", 12 },
            { "5600xt", 12 },
            { "5605g", 12 },
            { "5605ge", 12 },
            { "5625c", 12 },
            { "5625u", 12 },
            { "6600h", 12 },
            { "6600hs", 12 },
            { "6600u", 12 },
            { "7235hs", 8 },
            { "7400f", 12 },
            { "7430u", 12 },
            { "7500f", 12 },
            { "7520c", 8 },
            { "7520u", 8 },
            { "7530u", 12 },
            { "7535hs", 12 },
            { "7535u", 12 },
            { "7540u", 12 },
            { "7545u", 12 },
            { "7600", 12 },
            { "7600x", 12 },
            { "7600x3d", 12 },
            { "7640hs", 12 },
            { "7640u", 12 },
            { "7645hx", 12 },
            { "8400f", 12 },
            { "8500g", 12 },
            { "8500ge", 12 },
            { "8540u", 12 },
            { "8600g", 12 },
            { "8640hs", 12 },
            { "8640u", 12 },
            { "8645hs", 12 },
            { "9600", 12 },
            { "9600x", 12 },
            { "1500", 8 },
            { "3350g", 8 },
            { "3350ge", 4 },
            { "4650g", 12 },
            { "4650ge", 12 },
            { "4650u", 12 },
            { "4655g", 12 },
            { "4655ge", 12 },
            { "5645", 12 },
            { "5650g", 12 },
            { "5650ge", 12 },
            { "5650u", 12 },
            { "5655g", 12 },
            { "5655ge", 12 },
            { "5675u", 12 },
            { "6650h", 12 },
            { "6650hs", 12 },
            { "6650u", 12 },
            { "1700", 16 },
            { "1700x", 16 },
            { "1800x", 16 },
            { "250", 16 },
            { "260", 16 },
            { "2700", 16 },
            { "2700e", 16 },
            { "2700u", 8 },
            { "2700x", 16 },
            { "2800h", 8 },
            { "3700c", 8 },
            { "3700u", 8 },
            { "3700x", 16 },
            { "3750h", 8 },
            { "3780u", 8 },
            { "3800x", 16 },
            { "3800xt", 16 },
            { "4700g", 16 },
            { "4700ge", 16 },
            { "4700u", 8 },
            { "4800h", 16 },
            { "4800hs", 16 },
            { "4800u", 16 },
            { "4980u", 16 },
            { "5700", 16 },
            { "5700g", 16 },
            { "5700ge", 16 },
            { "5700u", 16 },
            { "5700x", 16 },
            { "5700x3d", 16 },
            { "5705g", 16 },
            { "5705ge", 16 },
            { "5800", 16 },
            { "5800h", 16 },
            { "5800hs", 16 },
            { "5800u", 16 },
            { "5800x", 16 },
            { "5800x3d", 16 },
            { "5800xt", 16 },
            { "5825c", 16 },
            { "5825u", 16 },
            { "6800h", 16 },
            { "6800hs", 16 },
            { "6800u", 16 },
            { "7435hs", 16 },
            { "7700", 16 },
            { "7700x", 16 },
            { "7730u", 16 },
            { "7735hs", 16 },
            { "7735u", 16 },
            { "7736u", 16 },
            { "7745hx", 16 },
            { "7800x3d", 16 },
            { "7840hs", 16 },
            { "7840hx", 24 },
            { "7840u", 16 },
            { "8700f", 16 },
            { "8700g", 16 },
            { "8840hs", 16 },
            { "8840u", 16 },
            { "8845hs", 16 },
            { "9700x", 16 },
            { "9800x3d", 16 },
            { "4750g", 16 },
            { "4750ge", 16 },
            { "4750u", 16 },
            { "5750g", 16 },
            { "5750ge", 16 },
            { "5755g", 16 },
            { "5755ge", 16 },
            { "5845", 16 },
            { "5850u", 16 },
            { "5875u", 16 },
            { "6850h", 16 },
            { "6850hs", 16 },
            { "6850u", 16 },
            { "6860z", 16 },
            { "7745", 16 },
            { "270", 16 },
            { "3900", 24 },
            { "3900x", 24 },
            { "3900xt", 24 },
            { "3950x", 32 },
            { "4900h", 16 },
            { "4900hs", 16 },
            { "5900", 24 },
            { "5900hs", 16 },
            { "5900hx", 16 },
            { "5900x", 24 },
            { "5900xt", 32 },
            { "5950x", 32 },
            { "5980hs", 16 },
            { "5980hx", 16 },
            { "6900hs", 16 },
            { "6900hx", 16 },
            { "6980hs", 16 },
            { "6980hx", 16 },
            { "7845hx", 24 },
            { "7900", 24 },
            { "7900x", 24 },
            { "7900x3d", 24 },
            { "7940hs", 16 },
            { "7940hx", 32 },
            { "7945hx", 32 },
            { "7945hx3d", 32 },
            { "7950x", 32 },
            { "7950x3d", 32 },
            { "8945hs", 16 },
            { "9850hx", 24 },
            { "9900x", 24 },
            { "9900x3d", 24 },
            { "9950x", 32 },
            { "9950x3d", 32 },
            { "9955hx", 32 },
            { "9955hx3d", 32 },
            { "5945", 24 },
            { "6950h", 16 },
            { "6950hs", 16 },
            { "7945", 24 },
            { "1900x", 16 },
            { "1920x", 24 },
            { "1950x", 32 },
            { "2920x", 24 },
            { "2950x", 32 },
            { "2970wx", 48 },
            { "2990wx", 64 },
            { "3960x", 48 },
            { "3970x", 64 },
            { "3990x", 128 },
            { "7960x", 48 },
            { "7970x", 64 },
            { "7980x", 128 },
            { "3945wx", 24 },
            { "3955wx", 32 },
            { "3975wx", 64 },
            { "3995wx", 128 },
            { "5945wx", 24 },
            { "5955wx", 32 },
            { "5965wx", 48 },
            { "5975wx", 64 },
            { "5995wx", 128 },
            { "7945wx", 24 },
            { "7955wx", 32 },
            { "7965wx", 48 },
            { "7975wx", 64 },
            { "7985wx", 128 },
            { "7995wx", 192 },
            { "9945wx", 24 },
            { "9955wx", 32 },
            { "9975wx", 64 },
            { "9985wx", 128 },
            { "9995wx", 192 },

            // Sempron
            { "2650", 2 },
            { "3850", 4 },

            // Z-Series
            { "z1", 12 },
            { "z2", 16 }
        };

        struct hasher {
            static u32 crc32_sw(u32 crc, char data) {
                crc ^= static_cast<u8>(data);
                for (int i = 0; i < 8; ++i)
                    crc = (crc >> 1) ^ ((crc & 1) ? 0x82F63B78u : 0);
                return crc;
            }

            #if (CLANG || GCC)
                __attribute__((__target__("crc32")))
            #endif
            static u32 crc32_hw(u32 crc, char data) {
                return _mm_crc32_u8(crc, static_cast<u8>(data));
            }

            using hashfc = u32(*)(u32, char);

            static hashfc get() {
                i32 regs[4];
                cpu::cpuid(regs, 1);
                const bool has_sse42 = (regs[2] & (1 << 20)) != 0;
                return has_sse42 ? crc32_hw : crc32_sw;
            }
        };

        debug("AMD_THREAD_MISMATCH: CPU model = ", model_str);

        const char* str = model_str.c_str();
        u32 expected_threads = 0;
        bool found = false;
        size_t best_len = 0;

        const auto hash_func = hasher::get();

        // manual collision fix for Z1 Extreme (16) vs Z1 (12)
        // this is a special runtime check because "z1" is a substring of "z1 extreme" tokens
        // and both might be hashed. VMAware should prioritize 'extreme' if found
        u32 z_series_threads = 0;

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

                if (current_len >= MAX_AMD_TOKEN_LEN) {
                    while (str[j] != '\0' && str[j] != ' ') j++;
                    break;
                }

                // convert to lowercase on-the-fly to match compile-time keys
                if (k >= 'A' && k <= 'Z') k += 32;

                current_hash = hash_func(current_hash, k);
                current_len++;
                j++;

                // boundary check
                const char next = str[j];
                const bool next_is_alnum = (next >= '0' && next <= '9') ||
                    (next >= 'A' && next <= 'Z') ||
                    (next >= 'a' && next <= 'z');

                if (!next_is_alnum) {
                    // Check specific Z1 Extreme token
                    // Hash for "extreme" (CRC32-C) is 0x3D09D5B4
                    if (current_hash == 0x3D09D5B4) { z_series_threads = 16; }

                    for (const auto& entry : db_entries) {
                        if (entry.hash == current_hash) {
                            if (current_len > best_len) {
                                best_len = current_len;
                                expected_threads = entry.threads;
                                found = true;
                            }
                        }
                    }
                }
            }
            i = j;
        }

        // Z1 Extreme fix
        if (z_series_threads != 0 && expected_threads == 12) {
            expected_threads = z_series_threads;
        }

        if (found) {
            const u32 actual = memo::threadcount::fetch();
            return actual != expected_threads;
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
        if (util::is_running_under_translator()) {
            debug("TIMER: Running inside a binary translation layer");
            return false;
        }
        u16 cycleThreshold = 1200;
        if (util::hyper_x() == HYPERV_ARTIFACT_VM) {
            cycleThreshold = 15000; // if we're running under Hyper-V, attempt to detect nested virtualization only
        }

    #if (WINDOWS)
        const HMODULE ntdll = util::get_ntdll();
        if (!ntdll) {
            return false;
        }

        const char* names[] = { "NtQueryInformationThread", "NtSetInformationThread" };
        void* funcs[ARRAYSIZE(names)] = {};
        util::get_function_address(ntdll, names, funcs, ARRAYSIZE(names));

        using NtQueryInformationThread_t = NTSTATUS(__stdcall*)(HANDLE, int, PVOID, ULONG, PULONG);
        using NtSetInformationThread_t = NTSTATUS(__stdcall*)(HANDLE, int, PVOID, ULONG);

        const auto pNtQueryInformationThread = reinterpret_cast<NtQueryInformationThread_t>(funcs[0]);
        const auto pNtSetInformationThread = reinterpret_cast<NtSetInformationThread_t>(funcs[1]);
        if (!pNtQueryInformationThread || !pNtSetInformationThread) {
            return false;
        }

        constexpr int ThreadBasicInformation = 0;
        constexpr int ThreadAffinityMask = 4;

        struct CLIENT_ID {
            ULONG_PTR UniqueProcess;
            ULONG_PTR UniqueThread;
        };
        struct THREAD_BASIC_INFORMATION {
            NTSTATUS ExitStatus;
            PVOID    TebBaseAddress;
            CLIENT_ID ClientId;
            ULONG_PTR AffinityMask;
            LONG     Priority;
            LONG     BasePriority;
        } tbi;
        const HANDLE hCurrentThread = reinterpret_cast<HANDLE>(-2LL);

        // current affinity
        memset(&tbi, 0, sizeof(tbi));
        NTSTATUS status = pNtQueryInformationThread(
            hCurrentThread,
            ThreadBasicInformation,
            &tbi,
            sizeof(tbi),
            nullptr
        );

        if (status < 0) {
            return false;
        }

        const ULONG_PTR originalAffinity = tbi.AffinityMask;

        // new affinity
        const DWORD_PTR wantedMask = static_cast<DWORD_PTR>(1);
        status = pNtSetInformationThread(
            hCurrentThread,
            ThreadAffinityMask,
            reinterpret_cast<PVOID>(const_cast<DWORD_PTR*>(&wantedMask)),
            static_cast<ULONG>(sizeof(wantedMask))
        );

        DWORD_PTR prevMask = 0;
        if (status >= 0) {
            prevMask = originalAffinity; // emulate SetThreadAffinityMask return
        }
        else {
            prevMask = 0;
        }

        // setting a higher priority for the current thread actually makes the timings drift more when comparing rdtsc against NOP/XOR loops
    #endif 

        // Case A - Hypervisor without RDTSC patch
        thread_local u32 aux = 0;
        // Check for RDTSCP support
        {
        #if (x86_64 && WINDOWS)
            const bool haveRdtscp = [&]() noexcept -> bool {
                __try {
                    __rdtscp(&aux);
                    return true;
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    return false;
                }
            }();
        #else
            UNUSED(aux);
            int regs[4] = { 0 };
            cpu::cpuid(regs, 0x80000001);
            const bool haveRdtscp = (regs[3] & (1u << 27)) != 0;
        #endif
            if (!haveRdtscp) {
                debug("TIMER: RDTSCP instruction not supported"); // __rdtscp should be supported nowadays
                return true;
            }
        }
        auto cpuid = [&]() -> u64 {
            const u64 t1 = __rdtsc();

            u32 a, b, c, d;
            cpu::cpuid(a, b, c, d, 0); // sometimes not intercepted in some hvs under compat mode

            const u64 t2 = __rdtscp(&aux);

            return t2 - t1;
        };

        constexpr u16 N = 1000;

        auto sample_avg = [&]() -> u64 {
            u64 sum = 0;
            for (u16 i = 0; i < N; ++i) {
                sum += cpuid();
            }
            return (sum + N / 2) / N;
        };

        u64 avg = sample_avg();
        debug("TIMER: Average latency -> ", avg, " cycles");
        if (avg <= 20) {
            return true;
        }
        else if (avg >= cycleThreshold) {
            avg = sample_avg();
            debug("TIMER: 2nd pass average -> ", avg, " cycles");
            if (avg >= cycleThreshold) {
                avg = sample_avg();
                debug("TIMER: 3rd pass average -> ", avg, " cycles");
                if (avg >= cycleThreshold) return true; // some CPUs like Intel's Emerald Rapids have much more cycles when executing CPUID than average, we should accept a high threshold
            }
        }

        #if (WINDOWS)
            // Case B - Hypervisor with RDTSC patch + useplatformclock=true
            LARGE_INTEGER freq;
            if (!QueryPerformanceFrequency(&freq)) // NtPowerInformation and NtQueryPerformanceCounter are avoided as some hypervisors downscale tsc only if we triggered a context switch from userspace
                return false;

            // calculates the invariant TSC base rate (on modern CPUs), not the dynamic core frequency, similar to what CallNtPowerInformation would give you
            LARGE_INTEGER t1q, t2q;
            const u64 t1 = __rdtsc();
            QueryPerformanceCounter(&t1q); // uses RDTSCP under the hood unless platformclock (a bcdedit setting) is set, which then would use HPET or ACPI PM via NtQueryPerformanceCounter
            SleepEx(50, 0);
            QueryPerformanceCounter(&t2q);
            const u64 t2 = __rdtscp(&aux);

            // this thread is pinned to the first CPU core due to the previous SetThreadAffinityMask call, meaning this calculation and cpu::get_cpu_base_speed() will report the same speed 
            const double elapsedSec = double(t2q.QuadPart - t1q.QuadPart) / double(freq.QuadPart); // the performance counter frequency is always 10MHz when running under Hyper-V
            const double tscHz = double(t2 - t1) / elapsedSec;
            const double tscMHz = tscHz / 1e6;

            debug("TIMER: Current CPU base speed -> ", tscMHz, " MHz");

            if (tscMHz < 800.0 || tscMHz >= 7000) { // i9-14900KS has 6.2 GHz; 9 9950X3D has 5.7 GHz
                debug("TIMER: TSC is spoofed");
                return true;
            }

            const u32 baseMHz = cpu::get_cpu_base_speed(); // wont work reliably on AMD, but its more reliable than fetching from SMBIOS

            if (baseMHz == 0) {
                debug("TIMER: Processor's true base speed not available for this CPU");
            }
            else if (baseMHz < 800.0) {
                debug("TIMER: CPUID seems to be intercepted by an hypervisor");
                return true;
            }
            else {
                debug("TIMER: Processor's true base speed -> ", static_cast<double>(baseMHz), " MHz");
                // this -650 delta accounts for older CPUs, it's better to use this rather than calling CPUID to know if the CPU supports invariant TSC, as it can be spoofed
                if (tscMHz <= static_cast<double>(baseMHz) - 650.0) {
                    return true;
                }
            }
        
            // Case C - Hypervisor with RDTSC patch + useplatformclock = false
            const ULONG64 count_first = 20000000ULL;
            const ULONG64 count_second = 200000000ULL;
            static thread_local volatile u64 g_sink = 0; // so that it doesnt need to be captured by the lambda

            auto rd_lambda = []() -> u64 {
                u64 v = __rdtsc();
                g_sink ^= v;
                return v;
            };

            auto xor_lambda = []() -> u64 {
                volatile u64 a = 0xDEADBEEFDEADBEEFull; // can be replaced by NOPs
                volatile u64 b = 0x1234567890ABCDEFull;
                u64 v = a ^ b;
                g_sink ^= v;
                return v;
            };

            using fn_t = u64 (*)();

            // make the pointer volatile so the compiler treats the call as opaque/indirect
            volatile fn_t rd_ptr = +rd_lambda;    // +lambda forces conversion to function ptr, so it won't be inlined, we need this to prevent some optimizatons by the compiler
            volatile fn_t xor_ptr = +xor_lambda;

            // first measurement
            ULONG64 beforeqit = 0;
            QueryInterruptTime(&beforeqit); // the kernel routine that backs up this api runs at CLOCK_LEVEL(13), only preempted by IPI, POWER_LEVEL and NMIs
            const ULONG64 beforetsc = __rdtsc();

            volatile u64 dummy = 0;
            for (ULONG64 x = 0; x < count_first; ++x) {
                dummy = rd_ptr(); // this loop will be intercepted by a RDTSC trap, downscaling our TSC
            }

            ULONG64 afterqit = 0;
            QueryInterruptTime(&afterqit);
            const ULONG64 aftertsc = __rdtsc();

            const ULONG64 dtsc1 = aftertsc - beforetsc;
            const ULONG64 dtq1 = afterqit - beforeqit;
            const ULONG64 firstRatio = (dtq1 != 0) ? (dtsc1 / dtq1) : 0ULL;

            // second measurement
            ULONG64 beforeqit2 = 0;
            QueryInterruptTime(&beforeqit2);
            const ULONG64 beforetsc2 = __rdtsc();

            for (ULONG64 x = 0; x < count_second; ++x) {
                dummy = xor_ptr(); // this loop won't be intercepted, it never switches to kernel-mode
            }
            UNUSED(dummy);

            ULONG64 afterqit2 = 0;
            QueryInterruptTime(&afterqit2);
            const ULONG64 aftertsc2 = __rdtsc();

            const ULONG64 dtsc2 = aftertsc2 - beforetsc2;
            const ULONG64 dtq2 = afterqit2 - beforeqit2;
            const ULONG64 secondRatio = (dtq2 != 0) ? (dtsc2 / dtq2) : 0ULL;

            /* Branchless absolute difference is like:
               mask = -(uint64_t)(firstRatio < secondRatio) -> 0 or 0xFFFFFFFFFFFFFFFF
               diff  = firstRatio - secondRatio
               abs   = (diff ^ mask) - mask
            */
            const ULONG64 diffMask = (ULONG64)0 - (ULONG64)(firstRatio < secondRatio);  // all-ones if first<second, else 0
            const ULONG64 diff = firstRatio - secondRatio;                              // unsigned subtraction
            const ULONG64 difference = (diff ^ diffMask) - diffMask;                    // absolute difference, unsigned

            debug("TIMER: RDTSC -> ", firstRatio, ", QIT -> ", secondRatio, ", Ratio: ", difference);

            if (prevMask != 0) {
                pNtSetInformationThread(
                    hCurrentThread,
                    ThreadAffinityMask,
                    reinterpret_cast<PVOID>(const_cast<ULONG_PTR*>(&originalAffinity)),
                    static_cast<ULONG>(sizeof(originalAffinity))
                );
            }             

            if (difference >= 100) {
                debug("TIMER: An hypervisor has been detected intercepting RDTSC");
                return true; // both ratios will always differ if a RDTSC trap is present, since the hypervisor can't account for the XOR/NOP loop
            }
            // TLB flushes or side channel cache attacks are not even tried due to how ineffective they are against stealthy hypervisors
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

        // TODO: More can definitely be added, I only tried QEMU and VBox so far
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
        struct FDGuard {
            int fd;
            explicit FDGuard(int fd = -1) : fd(fd) {}
            ~FDGuard() { if (fd != -1) ::close(fd); }
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
        FDGuard sockGuard(sock); // will close on function exit

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
     * @category Windows
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
     * @brief Check for uncommon IDT virtual addresses
     * @author Matteo Malvica
     * @author Idea to check VPC's range from Tom Liston and Ed Skoudis' paper "On the Cutting Edge: Thwarting Virtual Machine Detection" (Windows)
     * @link https://www.matteomalvica.com/blog/2018/12/05/detecting-vmware-on-64-bit-systems/ (Linux)
     * @category Windows, Linux, x86
     * @implements VM::SIDT
     */
    [[nodiscard]] static bool sidt() {
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
                return (values[9] == 0x00);  // 10th byte in x64 mode
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
                return (values[5] == 0x00);  // 6th byte in x86 mode
        #else
                return false;
        #endif
    #elif (WINDOWS && x86)
        SYSTEM_INFO si;
        GetNativeSystemInfo(&si);
        DWORD_PTR originalMask = 0;
        const HANDLE hCurrentThread = reinterpret_cast<HANDLE>(-2LL);

        for (DWORD i = 0; i < si.dwNumberOfProcessors; ++i) {
            const DWORD_PTR mask = (DWORD_PTR)1 << i;
            const DWORD_PTR previousMask = SetThreadAffinityMask(hCurrentThread, mask);

            if (previousMask == 0) {
                continue;
            }

            if (originalMask == 0) {
                originalMask = previousMask;
            }

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
                struct { USHORT Limit; ULONG_PTR Base; } idtr;
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

                if (originalMask != 0) {
                    SetThreadAffinityMask(hCurrentThread, originalMask);
                }
                return core::add(brands::VPC);
            }
        }

        if (originalMask != 0) {
            SetThreadAffinityMask(hCurrentThread, originalMask);
        }

        return false;
    #else
        return false;
    #endif
    }


    /**
     * @brief Check for default Azure hostname format (Azure uses Hyper-V as their base VM brand)
     * @category Windows, Linux
     * @implements VM::HYPERV_HOSTNAME
     */
    static bool hyperv_hostname() {
        const std::string hostname = util::get_hostname();

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
            unsigned char c = static_cast<unsigned char>(hostname[i]);
            if (!std::isalnum(c)) {
                return false;
            }
        }

        return core::add(brands::AZURE_HYPERV);
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
        typedef struct {
            char Signature[4];
            u32 Length;
            u8 Revision;
            // others not needed
        } ACPI_HEADER;

        typedef struct _FADT {
            UINT32  Signature;
            UINT32  Length;
            UINT8   Revision;
            UINT8   Checksum;
            CHAR    OemId[6];
            CHAR    OemTableId[8];
            UINT32  OemRevision;
            CHAR    AslCompilerId[4];
            UINT32  AslCompilerRevision;

            UINT32  FirmwareCtrl;
            UINT32  Dsdt;
            UINT8   Reserved1;
            UINT8   PreferredPmProfile;
            UINT16  SciInterrupt;
            UINT32  SmiCommandPort;
            UINT8   AcpiEnable;
            UINT8   AcpiDisable;
            UINT8   S4BiosReq;
            UINT8   Reserved2;
            UINT32  PstateControl;
            UINT32  Pm1aEventBlock;
            UINT32  Pm1bEventBlock;
            UINT32  Pm1aControlBlock;
            UINT32  Pm1bControlBlock;
            UINT32  Pm2ControlBlock;
            UINT32  PmTimerBlock;
            UINT32  Gpe0Block;
            UINT32  Gpe1Block;
            UINT8   Pm1EventLength;
            UINT8   Pm1ControlLength;
            UINT8   Pm2ControlLength;
            UINT8   PmTimerLength;

            UINT16  P_Lvl2_Lat;
            UINT16  P_Lvl3_Lat;
        } FADT, * PFADT;

        // "WAET" is also present as a string inside the WAET table, so there's no need to check for its table signature
        constexpr std::array<const char*, 24> targets = { {
            "Parallels Software", "Parallels(R)",
            "innotek",            "Oracle",   "VirtualBox", "vbox", "VBOX",
            "VMware, Inc.",       "VMware",   "VMWARE",     "VMW0003",
            "QEMU",               "pc-q35",   "Q35 +",      "FWCF",     "BOCHS", "BXPC",
            "ovmf",               "edk ii unknown", "WAET", "S3 Corp.", "Virtual Machine", "VS2005R2",
            "Xen"
        } };

        constexpr std::array<const char*, 24> brands_map = { {
            brands::PARALLELS, brands::PARALLELS,
            brands::VBOX,      brands::VBOX,      brands::VBOX,     brands::VBOX,     brands::VBOX,
            brands::VMWARE,    brands::VMWARE,    brands::VMWARE,   brands::VMWARE,
            brands::QEMU,      brands::QEMU,      brands::QEMU,     brands::QEMU,     brands::BOCHS,    brands::BOCHS,
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
            brands::XEN // this last one is just a marker, not really used
        } };

        static_assert(targets.size() == brands_map.size(), "targets and brands_map must be the same length");

        auto scan_table = [&](const BYTE* buf, const size_t len) noexcept -> bool {
            // faster than std::search because of a manual byte-by-byte loop, could be optimized further with Boyer-Moore-Horspool implementations for large firmware tables like DSDT
            auto find_pattern = [&](const char* pat, size_t patlen) noexcept -> bool {
                if (patlen == 0 || patlen > len) return false;
                const u8 first = static_cast<u8>(pat[0]);
                const u8* base = reinterpret_cast<const u8*>(buf);
                const u8* search_ptr = base;
                size_t remaining = len;

                while (remaining >= patlen) {
                    const void* m = memchr(search_ptr, first, remaining);
                    if (!m) return false;
                    const u8* mptr = static_cast<const u8*>(m);
                    const size_t idx = static_cast<size_t>(mptr - base);
                    // ensure pattern fits
                    if (idx + patlen > len) return false;
                    if (memcmp(mptr, pat, patlen) == 0) return true;
                    // advance one past this found first-byte and continue
                    search_ptr = mptr + 1;
                    remaining = len - static_cast<size_t>(search_ptr - base);
                }
                return false;
            };

            // 1) VM-specific firmware signatures. It is important that vm-specific checks run first because of the hardened detection logic
            for (size_t ti = 0; ti < targets.size(); ++ti) {
                const char* pat = targets[ti];
                const size_t plen = strlen(pat);
                if (plen > len) continue;

                if (find_pattern(pat, plen)) {
                    // special handling for Xen: must not have PXEN to prevent false flagging some baremetal systems
                    if (strcmp(pat, "Xen") == 0) {
                        constexpr char pxen[] = "PXEN";
                        constexpr size_t pxen_len = sizeof(pxen) - 1;
                        const bool has_pxen = find_pattern(pxen, pxen_len);
                        if (!has_pxen)
                            return core::add(brands::XEN);
                        else
                            continue;
                    }

                    debug("FIRMWARE: Detected ", pat);
                    const char* brand = brands_map[ti];
                    return (brand ? core::add(brand) : true);
                }
            }

            // 2) known patches used by popular hardeners 
            {
                constexpr char marker[] = "777777";

                if (len >= 36) {
                    // OEMID (6)
                    char oemid[7] = { 0 };
                    memcpy(oemid, buf + 10, 6);
                    // OEM Table ID (8)
                    char oemtableid[9] = { 0 };
                    memcpy(oemtableid, buf + 16, 8);

                    // Creator / ASL Compiler ID (4) won't contain 6-char marker because its length is 4
                    if (strstr(oemid, marker) != nullptr) {
                        debug("FIRMWARE: VMWareHardenedLoader found in OEMID -> '", oemid, "'");
                        return core::add(brands::VMWARE_HARD);
                    }
                    if (strstr(oemtableid, marker) != nullptr) {
                        debug("FIRMWARE: VMWareHardenedLoader found in OEM Table ID -> '", oemtableid, "'");
                        return core::add(brands::VMWARE_HARD);
                    }
                }
            }

            if (!buf || len < sizeof(ACPI_HEADER)) {
                return false;
            }

            ACPI_HEADER hdr;
            memcpy(&hdr, buf, sizeof(hdr));

            // 3) FADT specific checks
            if (memcmp(hdr.Signature, "FACP", 4) == 0) {
                if (hdr.Length > len) {
                    debug("FIRMWARE: declared header length larger than fetched length (declared ", hdr.Length, ", fetched ", len, ")");
                    return true;
                }
                if (len < sizeof(FADT)) {
                    debug("FIRMWARE: FACP buffer too small (len ", len, ")");
                    return true;
                }

                FADT fadt;
                memcpy(&fadt, buf, sizeof(FADT));

                if (fadt.P_Lvl2_Lat == 0x0FFF || fadt.P_Lvl3_Lat == 0x0FFF) { // A value > 100 indicates the system does not support a C2/C3 state
                    debug("FIRMWARE: C2 and C3 latencies indicate VM");
                    return true;
                }
            }

            return false;
        };

        // Enumerate ACPI tables
        constexpr DWORD ACPI_SIG = 'ACPI';
        const DWORD enumSize = EnumSystemFirmwareTables(ACPI_SIG, nullptr, 0);
        if (enumSize == 0) return false;
        if (enumSize % sizeof(DWORD) != 0) return false;

        std::vector<BYTE> tableIDs(enumSize);
        if (EnumSystemFirmwareTables(ACPI_SIG, tableIDs.data(), enumSize) != enumSize)
            return false;

        const DWORD count = enumSize / sizeof(DWORD);
        std::vector<DWORD> tables(count);
        bool found_hpet = false;
        for (DWORD i = 0; i < count; ++i) {
            DWORD entry;
            memcpy(&entry, tableIDs.data() + i * sizeof(DWORD), sizeof(entry));
            tables[i] = entry;
            constexpr DWORD HPET_SIG = 'TEPH';
            if (tables[i] == HPET_SIG) {
                found_hpet = true;
            }
        }

        // DSDT special fetch
        {
            constexpr DWORD DSDT_SIG = 'DSDT';
            constexpr DWORD DSDT_SWAPPED =
                ((DSDT_SIG >> 24) & 0x000000FFu)
                | ((DSDT_SIG >> 8) & 0x0000FF00u)
                | ((DSDT_SIG << 8) & 0x00FF0000u)
                | ((DSDT_SIG << 24) & 0xFF000000u);

            const UINT sz = GetSystemFirmwareTable(ACPI_SIG, DSDT_SWAPPED, nullptr, 0);
            if (sz > 0) {
                std::vector<BYTE> dsdtBuf;
                dsdtBuf.resize(sz);
                if (GetSystemFirmwareTable(ACPI_SIG, DSDT_SWAPPED, dsdtBuf.data(), sz) == sz) {
                    if (scan_table(dsdtBuf.data(), dsdtBuf.size())) {
                        return true;
                    }
                }
            }
        }

        // helper to fetch one table into a malloc'd buffer
        auto fetch = [&](DWORD provider, DWORD tableID, BYTE*& outBuf, size_t& outLen) -> bool {
            const UINT sz = GetSystemFirmwareTable(provider, tableID, nullptr, 0);
            if (sz == 0) return false;
            outBuf = reinterpret_cast<BYTE*>(malloc(sz));
            if (!outBuf) return false;
            if (GetSystemFirmwareTable(provider, tableID, outBuf, sz) != sz) {
                free(outBuf);
                return false;
            }
            outLen = sz;
            return true;
        };

        // Scan every ACPI table, dont make explicit whitelisting/blacklisting because of possible bypasses
        for (auto tbl : tables) {
            BYTE* buf = nullptr; size_t len = 0;
            if (fetch(ACPI_SIG, tbl, buf, len)) {
                if (scan_table(buf, len)) {
                    free(buf);
                    return true;
                }
                free(buf);
            }
        }

        // Scan SMBIOS (RSMB) / FIRM tables
        constexpr DWORD smbProviders[] = { 'FIRM', 'RSMB' };

        for (DWORD prov : smbProviders) {
            const UINT e = EnumSystemFirmwareTables(prov, nullptr, 0);
            if (!e) continue;

            std::vector<BYTE> bufIDs(e);

            if (EnumSystemFirmwareTables(prov, bufIDs.data(), e) != e) continue;

            // even if alignment is supported on x86 its good to check if size is a multiple of DWORD
            if (e % sizeof(DWORD) != 0) continue;

            const DWORD cnt = e / sizeof(DWORD);
            // auto otherIDs = reinterpret_cast<DWORD*>(bufIDs.data());
            char provStr[5] = { 0 }; memcpy(provStr, &prov, 4);

            for (DWORD i = 0; i < cnt; ++i) {
                DWORD tblID;
                memcpy(&tblID, bufIDs.data() + i * sizeof(DWORD), sizeof(DWORD));
                UINT sz = GetSystemFirmwareTable(prov, tblID, nullptr, 0);
                if (!sz) continue;
                BYTE* buf = reinterpret_cast<BYTE*>(malloc(sz));
                if (!buf) continue;
                if (GetSystemFirmwareTable(prov, tblID, buf, sz) != sz) {
                    free(buf); continue;
                }

                if (scan_table(buf, sz)) {
                    free(buf);
                    return true;
                }

                free(buf);
            }
        }

        // Checks for non existent tables must run at the end because of is_hardened() logic
        if (!found_hpet && !util::is_running_under_translator()) {
            debug("FIRMWARE: HPET table not found");
            return true;
        }

        return false;
    #elif (LINUX)
        // Author: dmfrpro
        DIR* raw_dir = opendir("/sys/firmware/acpi/tables/");
        if (!raw_dir) {
            debug("FIRMWARE: could not open ACPI tables directory");
            return false;
        }

        struct DirCloser {
            DIR* d;
            explicit DirCloser(DIR* dir) : d(dir) {}
            ~DirCloser() { if (d) closedir(d); }
        } dir(raw_dir);

        constexpr const char* targets[] = {
            "Parallels Software", "Parallels(R)",
            "innotek",            "Oracle",   "VirtualBox", "vbox", "VBOX",
            "VMware, Inc.",       "VMware",   "VMWARE",     "VMW0003",
            "QEMU",               "pc-q35",   "Q35 +",      "FWCF",     "BOCHS", "BXPC",
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

            struct FDCloser {
                int fd;
                explicit FDCloser(int f) : fd(f) {}
                ~FDCloser() { if (fd != -1) close(fd); }
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
                size_t targetLen = strlen(target);
                if (targetLen > file_size_u)
                    continue;
                for (size_t j = 0; j <= file_size_u - targetLen; ++j) {
                    if (memcmp(buffer.data() + j, target, targetLen) == 0) {
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
        struct PCI_Device { u16 vendor_id; u32 device_id; };
        std::vector<PCI_Device> devices;

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
        static constexpr const wchar_t* kRoots[] = {
            L"SYSTEM\\CurrentControlSet\\Enum\\PCI",
            L"SYSTEM\\CurrentControlSet\\Enum\\USB",
            L"SYSTEM\\CurrentControlSet\\Enum\\HDAUDIO"
        };

        enum RootType { RT_PCI, RT_USB, RT_HDAUDIO };
        constexpr DWORD MAX_MULTI_SZ = 64 * 1024;

        auto hexVal = [](wchar_t c) -> int {
            if (c >= L'0' && c <= L'9') return c - L'0';
            c = towupper(c);
            if (c >= L'A' && c <= L'F') return 10 + (c - L'A');
            return -1;
        };

        // parse up to maxDigits from ptr; stop also if stopLen supplied (SIZE_MAX = no limit)
        auto parseHexInplace = [&](const wchar_t* ptr, size_t maxDigits, size_t stopLen, unsigned long& out, size_t& consumed) -> bool {
            out = 0;
            consumed = 0;
            while (consumed < maxDigits && (stopLen == SIZE_MAX || consumed < stopLen)) {
                int v = hexVal(ptr[consumed]);
                if (v < 0) break;
                out = (out << 4) | static_cast<unsigned long>(v);
                ++consumed;
            }
            return consumed > 0;
        };

        std::unordered_set<unsigned long long> seen;

        // Lambda #1: Process the hardware ID on an instance key,
        // extract every (VID, DID) pair, and push into devices
        auto processHardwareID = [&](HKEY hInst, RootType rootType) {
            DWORD type = 0, cbData = 0;
            LONG rv = RegGetValueW(
                hInst,
                nullptr,
                L"HardwareID",
                RRF_RT_REG_MULTI_SZ,
                &type,
                nullptr,
                &cbData
            );
            if (rv != ERROR_SUCCESS || type != REG_MULTI_SZ || cbData <= sizeof(wchar_t)) {
                return;
            }

            if (cbData > MAX_MULTI_SZ) {
                debug("PCI_DEVICES: HardwareID size too large: ", cbData);
                return;
            }

            // allocate a buffer large enough to hold the entire MULTI_SZ
            std::vector<wchar_t> buf((cbData / sizeof(wchar_t)) + 1);
            buf.back() = L'\0';
            rv = RegGetValueW(
                hInst,
                nullptr,
                L"HardwareID",
                RRF_RT_REG_MULTI_SZ,
                nullptr,
                buf.data(),
                &cbData
            );
            if (rv != ERROR_SUCCESS) {
                return;
            }

            // guarantee terminating NUL
            size_t wcharCount = cbData / sizeof(wchar_t);
            if (wcharCount < buf.size()) buf[wcharCount] = L'\0';
            else buf.back() = L'\0';

            for (wchar_t* p = buf.data(); *p; p += wcslen(p) + 1) {
                wchar_t* s = p;
                wchar_t* v = nullptr;
                wchar_t* d = nullptr;
                u16 vid = 0;
                u32 did = 0;
                bool ok = false;

                if (rootType == RT_USB) {
                    // USB: VID_ and then PID_
                    v = wcsstr(s, L"VID_");
                    if (v) d = wcsstr(v + 4, L"PID_");
                    if (v && d) {
                        unsigned long parsedV = 0, parsedD = 0;
                        size_t cV = 0, cD = 0;
                        // VID_ usually 4 hex digits, PID_ usually 4
                        if (parseHexInplace(v + 4, 4, SIZE_MAX, parsedV, cV) &&
                            parseHexInplace(d + 4, 8, SIZE_MAX, parsedD, cD)) {
                            vid = static_cast<u16>(parsedV & 0xFFFFu);
                            did = static_cast<u32>(parsedD);
                            ok = true;
                        }
                    }
                }
                else {
                    // PCI or HDAUDIO = VEN_ and then DEV_ after it
                    v = wcsstr(s, L"VEN_");
                    if (v) d = wcsstr(v + 4, L"DEV_");
                    if (v && d) {
                        unsigned long parsedV = 0;
                        size_t cV = 0;
                        if (!parseHexInplace(v + 4, 4, SIZE_MAX, parsedV, cV)) {
                            continue; 
                        }
                        vid = static_cast<u16>(parsedV & 0xFFFFu);

                        wchar_t* devStart = d + 4;
                        wchar_t* ampAfterDev = wcschr(devStart, L'&');
                        size_t devLen = ampAfterDev ? static_cast<size_t>(ampAfterDev - devStart) : wcslen(devStart);

                        // For HDAUDIO expect 4 digits and for PCI allow up to 8
                        size_t maxDigits = (rootType == RT_HDAUDIO) ? 4 : 8;
                        if (devLen == 0 || devLen > maxDigits) {
                            // If the token is longer than maxDigits, we cap parsing to maxDigits but
                            // require that the parsed digit count equals devLen
                            if (devLen > maxDigits) continue;
                        }

                        unsigned long parsedD = 0;
                        size_t cD = 0;
                        // parse exactly devLen digits (fail if any char is non-hex)
                        if (!parseHexInplace(devStart, maxDigits, devLen, parsedD, cD)) {
                            continue;
                        }
                        // require we consumed all characters in device token (like std::stoul on the substring)
                        if (cD != devLen) continue;

                        // overflow checks
                        if (rootType == RT_HDAUDIO) {
                            if (parsedD > 0xFFFF) continue;
                            did = static_cast<u32>(parsedD & 0xFFFFu);
                        }
                        else {
                            // PCI device id may be up to 32-bit
                            did = static_cast<u32>(parsedD);
                        }
                        ok = true;
                    }
                }

                if (ok) {
                    unsigned long long key = (static_cast<unsigned long long>(vid) << 32) | static_cast<unsigned long long>(did);
                    if (seen.insert(key).second) {
                        devices.push_back({ vid, did });
                    }
                }
            }
        };

        // Lambda #2: all instance subkeys under a given device key,
        // and for each instance, open it and call processHardwareID()
        auto enumInstances = [&](HKEY hDev, RootType rootType) {
            for (DWORD j = 0;; ++j) {
                wchar_t instName[256]{};
                DWORD   cbInst = _countof(instName);
                LONG    st2 = RegEnumKeyExW(
                    hDev,
                    j,
                    instName,
                    &cbInst,
                    nullptr,
                    nullptr,
                    nullptr,
                    nullptr
                );
                if (st2 == ERROR_NO_MORE_ITEMS) break;
                if (st2 != ERROR_SUCCESS) continue;

                HKEY hInst = nullptr;
                if (RegOpenKeyExW(hDev, instName, 0, KEY_READ, &hInst) != ERROR_SUCCESS) continue;

                processHardwareID(hInst, rootType);
                RegCloseKey(hInst);
            }
        };

        // Lambda #3: all device subkeys under a given root key,
        // open each device key, and call enumInstances()
        auto enumDevices = [&](HKEY hRoot, RootType rootType) {
            for (DWORD i = 0;; ++i) {
                wchar_t deviceName[256];
                DWORD   cbName = _countof(deviceName);
                LONG    status = RegEnumKeyExW(
                    hRoot,
                    i,
                    deviceName,
                    &cbName,
                    nullptr,
                    nullptr,
                    nullptr,
                    nullptr
                );
                if (status == ERROR_NO_MORE_ITEMS) break;
                if (status != ERROR_SUCCESS) continue;

                HKEY hDev = nullptr;
                if (RegOpenKeyExW(hRoot, deviceName, 0, KEY_READ, &hDev) != ERROR_SUCCESS) continue;

                enumInstances(hDev, rootType);
                RegCloseKey(hDev);
            }
        };

        // for each rootPath we open the root key once, compute its RootType, then call enumDevices()
        for (size_t rootIdx = 0; rootIdx < _countof(kRoots); ++rootIdx) {
            const wchar_t* rootPath = kRoots[rootIdx];
            HKEY hRoot = nullptr;
            if (RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                rootPath,
                0,
                KEY_READ,
                &hRoot
            ) != ERROR_SUCCESS) {
                continue;
            }

            RootType rootType;
            if (wcscmp(rootPath, L"SYSTEM\\CurrentControlSet\\Enum\\USB") == 0) {
                rootType = RT_USB;
            }
            else if (wcscmp(rootPath, L"SYSTEM\\CurrentControlSet\\Enum\\HDAUDIO") == 0) {
                rootType = RT_HDAUDIO;
            }
            else {
                rootType = RT_PCI;
            }

            enumDevices(hRoot, rootType);
            RegCloseKey(hRoot);
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

                // VMware, 0x15ad0405 (Virtual Machine Communication Interface) and 0x15ad0740 false flag
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
        const auto result = util::sys_result("sysctl -n hw.model");

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

        if (hv_present != 0) return true;

        std::unique_ptr<std::string> result = util::sys_result("csrutil status");
        const std::string tmp = *result;

        debug("MAC_SIP: ", "result = ", tmp);

        return (util::find(tmp, "disabled") || (!util::find(tmp, "enabled")));
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
                UNUSED(isNativeVhdBoot);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                debug("WINE: SEH invoked");
                return true;
            }
        #endif

        const HMODULE k32 = GetModuleHandleA("kernel32.dll");
        if (!k32) {
            return false;
        }

        const char* names[] = { "wine_get_unix_file_name" };
        void* functions[1] = { nullptr };
        util::get_function_address(k32, names, functions, _countof(names));

        if (functions[0] != nullptr) {
            return core::add(brands::WINE);
        }

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
        const auto NtPowerInformation = reinterpret_cast<NtPI_t>(funcs[0]);

        SYSTEM_POWER_CAPABILITIES caps = { 0 };
        const NTSTATUS status = NtPowerInformation(
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
        const bool hiberFilePresent = caps.HiberFilePresent;

        const bool is_physical_pattern = (s0_supported || s3_supported) &&
            (s4_supported || hiberFilePresent);

        if (is_physical_pattern) {
            return false;
        }

        const bool is_vm_pattern = !(s0_supported || s3_supported || s4_supported || hiberFilePresent) &&
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

        const auto pNtOpenKey = reinterpret_cast<NTSTATUS(__stdcall*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)>(funcs[0]);
        const auto pNtQueryValueKey = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, PUNICODE_STRING, ULONG, PVOID, ULONG, PULONG)>(funcs[1]);
        const auto pRtlInitUnicodeString = reinterpret_cast<void (__stdcall*)(PUNICODE_STRING, PCWSTR)>(funcs[2]);
        const auto pNtClose = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE)>(funcs[3]);

        if (!pNtOpenKey || !pNtQueryValueKey || !pRtlInitUnicodeString || !pNtClose) return false;

        UNICODE_STRING uKeyName;
        pRtlInitUnicodeString(&uKeyName, L"\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion");

        OBJECT_ATTRIBUTES objAttr;
        ZeroMemory(&objAttr, sizeof(objAttr));
        objAttr.Length = sizeof(objAttr);
        objAttr.ObjectName = &uKeyName;
        objAttr.Attributes = OBJ_CASE_INSENSITIVE;

        HANDLE hKey = nullptr;
        constexpr ACCESS_MASK KEY_QUERY_ONLY = 0x0001; // KEY_QUERY_VALUE
        NTSTATUS st = pNtOpenKey(&hKey, KEY_QUERY_ONLY, &objAttr);
        if (!NT_SUCCESS(st) || !hKey) {
            return false;
        }

        UNICODE_STRING uValueName;
        pRtlInitUnicodeString(&uValueName, L"ProductId");

        // Buffer for KEY_VALUE_PARTIAL_INFORMATION
        BYTE buffer[128]{};
        ULONG resultLength = 0;
        constexpr ULONG KeyValuePartialInformation = 2;

        st = pNtQueryValueKey(hKey, &uValueName, KeyValuePartialInformation, buffer, sizeof(buffer), &resultLength);

        pNtClose(hKey);

        if (!NT_SUCCESS(st)) {
            return false;
        }

        struct KEY_VALUE_PARTIAL_INFORMATION_LOCAL {
            ULONG TitleIndex;
            ULONG Type;
            ULONG DataLength;
            BYTE Data[1];
        };

        if (resultLength < offsetof(KEY_VALUE_PARTIAL_INFORMATION_LOCAL, Data) + 1) {
            return false;
        }

        const auto* kv = reinterpret_cast<KEY_VALUE_PARTIAL_INFORMATION_LOCAL*>(buffer);
        const ULONG dataLen = kv->DataLength;
        if (dataLen == 0 || dataLen >= sizeof(buffer)) return false;

        char productId[64] = { 0 };
        const size_t copyLen = (dataLen < (sizeof(productId) - 1)) ? dataLen : (sizeof(productId) - 1);
        memcpy(productId, kv->Data, copyLen);
        productId[copyLen] = '\0';

        struct TargetPattern {
            const char* product_id;
            const char* brand;
        };

        constexpr TargetPattern targets[] = {
            {"55274-640-2673064-23950", brands::JOEBOX},
            {"76487-644-3177037-23510", brands::CWSANDBOX},
            {"76487-337-8429955-22614", brands::ANUBIS}
        };

        constexpr size_t target_len = 21;

        if (strlen(productId) != target_len) return false;

        for (const auto& target : targets) {
            if (memcmp(productId, target.product_id, target_len) == 0) {
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
    #endif
        return rc;
    }


    /**
     * @brief Check for sgdt instruction method
     * @category Windows, x86
     * @note code documentation paper in /papers/www.offensivecomputing.net_vm.pdf (top-most byte signature)
     * @implements VM::SGDT
     */
    [[nodiscard]] static bool sgdt() {
        bool found = false;
    #if (x86)
        SYSTEM_INFO si;
        GetNativeSystemInfo(&si);
        DWORD_PTR originalMask = 0;
        const HANDLE hCurrentThread = reinterpret_cast<HANDLE>(-2LL);

        for (DWORD i = 0; i < si.dwNumberOfProcessors; ++i) {
            const DWORD_PTR mask = (DWORD_PTR)1 << i;
            const DWORD_PTR previousMask = SetThreadAffinityMask(hCurrentThread, mask);

            if (previousMask == 0) {
                continue;
            }

            if (originalMask == 0) {
                originalMask = previousMask;
            }

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
                struct { u16 limit; u64 base; } _gdtr = {};
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

            if (found) break;
        }

        if (originalMask != 0) {
            SetThreadAffinityMask(hCurrentThread, originalMask);
        }
    #endif
        return found;
    }


    /**
     * @brief Check for sldt instruction method
     * @category Windows, x86_32
     * @author Danny Quist (chamuco@gmail.com), ldtr_buf signature
     * @author Val Smith (mvalsmith@metasploit.com), ldtr_buf signature
     * @author code documentation paper in /papers/www.offensivecomputing.net_vm.pdf for ldtr_buf signature and in https://www.aldeid.com/wiki/X86-assembly/Instructions/sldt for ldt signature
     * @implements VM::SLDT
     */
    [[nodiscard]] static bool sldt() {
        bool found = false;
    #if (x86_32)
        SYSTEM_INFO si;
        GetNativeSystemInfo(&si);
        const HANDLE hCurrentThread = reinterpret_cast<HANDLE>(-2LL);
        const DWORD_PTR origMask = SetThreadAffinityMask(hCurrentThread, 1);
        SetThreadAffinityMask(hCurrentThread, origMask);

        for (DWORD i = 0; i < si.dwNumberOfProcessors; ++i) {
            const DWORD_PTR mask = (DWORD_PTR)1 << i;
            if (SetThreadAffinityMask(hCurrentThread, mask) == 0)
                continue;

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

            if (found)
                break;
        }

        SetThreadAffinityMask(hCurrentThread, origMask);
    #endif
        return found;
    }


    /**
     * @brief Check for SMSW assembly instruction technique
     * @category Windows, x86_32
     * @author Danny Quist from Offensive Computing
     * @implements VM::SMSW
     */
    [[nodiscard]] static bool smsw() {
    #if (x86_32)
        u32 reax = 0;

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

        const auto pNtOpenMutant = reinterpret_cast<NtOpenMutant_t>(funcs[0]);
        const auto pRtlInitUnicodeString = reinterpret_cast<RtlInitUnicodeString_t>(funcs[1]);
        const auto pNtClose = reinterpret_cast<NtClose_t>(funcs[2]);

        if (!pNtOpenMutant || !pRtlInitUnicodeString || !pNtClose) {
            return false;
        }

        auto try_mutex_name = [&](const wchar_t* baseName) -> bool {
            std::wstring full = L"\\BaseNamedObjects\\";
            full += baseName;

            UNICODE_STRING uName;
            pRtlInitUnicodeString(&uName, full.c_str());

            OBJECT_ATTRIBUTES objAttr;
            ZeroMemory(&objAttr, sizeof(objAttr));
            objAttr.Length = sizeof(objAttr);
            objAttr.ObjectName = &uName;
            objAttr.Attributes = OBJ_CASE_INSENSITIVE;

            HANDLE hMutant = nullptr;
            NTSTATUS st = pNtOpenMutant(&hMutant, MUTANT_QUERY_STATE, &objAttr);
            if (NT_SUCCESS(st)) {
                if (hMutant) pNtClose(hMutant);
                return true;
            }

            // some contexts expose it without the prefix
            pRtlInitUnicodeString(&uName, baseName);
            ZeroMemory(&objAttr, sizeof(objAttr));
            objAttr.Length = sizeof(objAttr);
            objAttr.ObjectName = &uName;
            objAttr.Attributes = OBJ_CASE_INSENSITIVE;

            hMutant = nullptr;
            st = pNtOpenMutant(&hMutant, MUTANT_QUERY_STATE, &objAttr);
            if (NT_SUCCESS(st)) {
                if (hMutant) pNtClose(hMutant);
                return true;
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

        const auto pNtOpenFile = reinterpret_cast<NtOpenFile_t>(funcs[0]);
        const auto pRtlInitUnicodeString = reinterpret_cast<RtlInitUnicodeString_t>(funcs[1]);
        const auto pNtClose = reinterpret_cast<NtClose_t>(funcs[2]);

        if (!pNtOpenFile || !pRtlInitUnicodeString || !pNtClose) {
            return false;
        }

        const wchar_t* nativePath = L"\\??\\C:\\Cuckoo";
        UNICODE_STRING uPath;
        pRtlInitUnicodeString(&uPath, nativePath);

        OBJECT_ATTRIBUTES objAttr;
        ZeroMemory(&objAttr, sizeof(objAttr));
        objAttr.Length = sizeof(objAttr);
        objAttr.ObjectName = &uPath;
        objAttr.Attributes = OBJ_CASE_INSENSITIVE;

        IO_STATUS_BLOCK iosb;
        HANDLE hFile = nullptr;

        constexpr ACCESS_MASK desiredAccess = FILE_READ_ATTRIBUTES; 
        constexpr ULONG shareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
        constexpr ULONG openOptions = FILE_OPEN | FILE_SYNCHRONOUS_IO_NONALERT | FILE_DIRECTORY_FILE;

        const NTSTATUS st = pNtOpenFile(&hFile, desiredAccess, &objAttr, &iosb, shareAccess, openOptions);
        if (NT_SUCCESS(st)) {
            if (hFile) pNtClose(hFile);
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

        const auto pNtOpenFile = reinterpret_cast<NtOpenFile_t>(funcs[0]);
        const auto pRtlInitUnicodeString = reinterpret_cast<RtlInitUnicodeString_t>(funcs[1]);
        const auto pNtClose = reinterpret_cast<NtClose_t>(funcs[2]);

        if (!pNtOpenFile || !pRtlInitUnicodeString || !pNtClose) {
            return false;
        }

        const wchar_t* pipePath = L"\\??\\pipe\\cuckoo";
        UNICODE_STRING uPipe;
        pRtlInitUnicodeString(&uPipe, pipePath);

        OBJECT_ATTRIBUTES objAttr;
        ZeroMemory(&objAttr, sizeof(objAttr));
        objAttr.Length = sizeof(objAttr);
        objAttr.ObjectName = &uPipe;
        objAttr.Attributes = OBJ_CASE_INSENSITIVE;

        IO_STATUS_BLOCK iosb;
        HANDLE hPipe = nullptr;

        constexpr ACCESS_MASK desiredAccess = FILE_READ_DATA | FILE_READ_ATTRIBUTES;
        constexpr ULONG shareAccess = 0;
        constexpr ULONG openOptions = FILE_OPEN | FILE_SYNCHRONOUS_IO_NONALERT;

        const NTSTATUS st = pNtOpenFile(&hPipe, desiredAccess, &objAttr, &iosb, shareAccess, openOptions);
        if (NT_SUCCESS(st)) {
            if (hPipe) pNtClose(hPipe);
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

        UINT32 pathCount = 0, modeCount = 0;
        if (QueryDisplayConfig(QDC_ONLY_ACTIVE_PATHS, // win7 and later
            &pathCount, nullptr,
            &modeCount, nullptr,
            nullptr) != ERROR_SUCCESS)
            return false;

        if ((pathCount <= 1) || (pathCount != modeCount)) {
            debug("DISPLAY: Path count: ", pathCount);
            debug("DISPLAY: Mode count: ", modeCount);
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

        constexpr ULONG SystemModuleInformation = 11;
        const HMODULE ntdll = util::get_ntdll();
        if (!ntdll) return false;

        const char* names[] = { "NtQuerySystemInformation", "NtAllocateVirtualMemory", "NtFreeVirtualMemory" };
        void* funcs[ARRAYSIZE(names)] = {};
        util::get_function_address(ntdll, names, funcs, ARRAYSIZE(names));

        const auto ntQuerySystemInformation = reinterpret_cast<NtQuerySystemInformationFn>(funcs[0]);
        const auto ntAllocateVirtualMemory = reinterpret_cast<NtAllocateVirtualMemoryFn>(funcs[1]);
        const auto ntFreeVirtualMemory = reinterpret_cast<NtFreeVirtualMemoryFn>(funcs[2]);

        if (ntQuerySystemInformation == nullptr || ntAllocateVirtualMemory == nullptr || ntFreeVirtualMemory == nullptr)
            return false;
        
        ULONG ulSize = 0;
        NTSTATUS status = ntQuerySystemInformation(SystemModuleInformation, nullptr, 0, &ulSize);
        if (status != ((NTSTATUS)0xC0000004L)) return false;

        const HANDLE hCurrentProcess = reinterpret_cast<HANDLE>(-1LL);
        PVOID allocatedMemory = nullptr;
        SIZE_T regionSize = ulSize;
        ntAllocateVirtualMemory(hCurrentProcess, &allocatedMemory, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

        const auto pSystemModuleInfoEx = reinterpret_cast<PSYSTEM_MODULE_INFORMATION_EX>(allocatedMemory);
        status = ntQuerySystemInformation(SystemModuleInformation, pSystemModuleInfoEx, ulSize, &ulSize);
        if (!(((NTSTATUS)(status)) >= 0)) {
            ntFreeVirtualMemory(hCurrentProcess, &allocatedMemory, &regionSize, MEM_RELEASE);
            return false;
        }

        for (ULONG i = 0; i < pSystemModuleInfoEx->NumberOfModules; ++i) {
            const char* driverPath = reinterpret_cast<const char*>(pSystemModuleInfoEx->Module[i].ImageName);
            if (
                strstr(driverPath, "VBoxGuest") || // only installed after vbox guest additions
                strstr(driverPath, "VBoxMouse") ||
                strstr(driverPath, "VBoxSF")
            ) {
                debug("DRIVERS: Detected VBox driver: ", driverPath);
                ntFreeVirtualMemory(hCurrentProcess, &allocatedMemory, &regionSize, MEM_RELEASE);
                return core::add(brands::VBOX);
            }

            if (
                strstr(driverPath, "vmusbmouse") ||
                strstr(driverPath, "vmmouse") ||
                strstr(driverPath, "vmmemctl")
            ) {
                debug("DRIVERS: Detected VMware driver: ", driverPath);
                ntFreeVirtualMemory(hCurrentProcess, &allocatedMemory, &regionSize, MEM_RELEASE);
                return core::add(brands::VMWARE);
            }
        }

        ntFreeVirtualMemory(hCurrentProcess, &allocatedMemory, &regionSize, MEM_RELEASE);
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
        u8 successfulOpens = 0;

        auto is_qemu_serial = [](const char* str) -> bool {
            return _strnicmp(str, "QM0000", 6) == 0;
        };

        auto is_vbox_serial = [](const char* str, size_t len) -> bool {
            if (len != 19) {
                return false;
            }

            auto toupper_char = [](char c) -> char {
                return (c >= 'a' && c <= 'z') ? static_cast<char>(c - 'a' + 'A') : c;
            };

            if (toupper_char(str[0]) != 'V' || toupper_char(str[1]) != 'B' || str[10] != '-') {
                return false;
            }

            auto is_hex = [&](char c) {
                char upper_c = toupper_char(c);
                return (upper_c >= '0' && upper_c <= '9') || (upper_c >= 'A' && upper_c <= 'F');
            };

            static constexpr std::array<u8, 16> hex_positions = { {
                2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17, 18
            } };

            for (u8 idx : hex_positions) {
                if (!is_hex(str[idx])) {
                    return false;
                }
            }
            return true;
        };

        auto __strnlen = [](const char* s, size_t max) -> size_t {
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

        const auto pRtlInitUnicodeString = reinterpret_cast<RtlInitUnicodeString_t>(funcs[0]);
        const auto pNtOpenFile = reinterpret_cast<NtOpenFile_t>(funcs[1]);
        const auto pNtDeviceIoControlFile = reinterpret_cast<NtDeviceIoControlFile_t>(funcs[2]);
        const auto pNtAllocateVirtualMemory = reinterpret_cast<NtAllocateVirtualMemory_t>(funcs[3]);
        const auto pNtFreeVirtualMemory = reinterpret_cast<NtFreeVirtualMemory_t>(funcs[4]);
        const auto pNtClose = reinterpret_cast<NtClose_t>(funcs[6]);

        if (!pRtlInitUnicodeString || !pNtOpenFile || !pNtDeviceIoControlFile ||
            !pNtAllocateVirtualMemory || !pNtFreeVirtualMemory || !pNtClose) {
            return result;
        }

        for (u8 drive = 0; drive < MAX_PHYSICAL_DRIVES; ++drive) {
            wchar_t path[32];
            swprintf_s(path, L"\\??\\PhysicalDrive%u", drive);

            UNICODE_STRING uPath;
            pRtlInitUnicodeString(&uPath, path);

            OBJECT_ATTRIBUTES objAttr;
            RtlZeroMemory(&objAttr, sizeof(objAttr));
            objAttr.Length = sizeof(objAttr);
            objAttr.ObjectName = &uPath;
            objAttr.Attributes = OBJ_CASE_INSENSITIVE;
            objAttr.RootDirectory = nullptr;

            IO_STATUS_BLOCK iosb;
            HANDLE hDevice = nullptr;

            constexpr ACCESS_MASK desiredAccess = SYNCHRONIZE | FILE_READ_ATTRIBUTES;
            constexpr ULONG shareAccess = FILE_SHARE_READ | FILE_SHARE_WRITE;
            constexpr ULONG openOptions = FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT;

            NTSTATUS st = pNtOpenFile(&hDevice, desiredAccess, &objAttr, &iosb, shareAccess, openOptions);
            if (!NT_SUCCESS(st) || hDevice == nullptr) {
                continue;
            }
            ++successfulOpens;

            // stack buffer attempt
            BYTE stackBuf[512] = { 0 };
            const STORAGE_DEVICE_DESCRIPTOR* descriptor = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(stackBuf);

            STORAGE_PROPERTY_QUERY query{};
            query.PropertyId = StorageDeviceProperty;
            query.QueryType = PropertyStandardQuery;

            const ULONG ioctl = IOCTL_STORAGE_QUERY_PROPERTY;

            st = pNtDeviceIoControlFile(hDevice, nullptr, nullptr, nullptr, &iosb,
                ioctl,
                &query, sizeof(query),
                stackBuf, sizeof(stackBuf));

            BYTE* allocatedBuffer = nullptr;
            SIZE_T allocatedSize = 0;
            const HANDLE hCurrentProcess = reinterpret_cast<HANDLE>(-1LL);

            if (!NT_SUCCESS(st)) {
                DWORD reportedSize = 0;
                if (descriptor && descriptor->Size > 0) {
                    reportedSize = descriptor->Size;
                }

                if (reportedSize > 0 && reportedSize < static_cast<DWORD>(MAX_DESCRIPTOR_SIZE) && reportedSize >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
                    allocatedSize = static_cast<SIZE_T>(reportedSize);
                    PVOID allocBase = nullptr;
                    SIZE_T regionSize = allocatedSize;
                    st = pNtAllocateVirtualMemory(hCurrentProcess, &allocBase, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                    if (!NT_SUCCESS(st) || allocBase == nullptr) {
                        pNtClose(hDevice);
                        continue;
                    }
                    allocatedBuffer = reinterpret_cast<BYTE*>(allocBase);
                    st = pNtDeviceIoControlFile(hDevice, nullptr, nullptr, nullptr, &iosb,
                        ioctl,
                        &query, sizeof(query),
                        allocatedBuffer, static_cast<ULONG>(allocatedSize));
                    if (!NT_SUCCESS(st)) {
                        PVOID freeBase = reinterpret_cast<PVOID>(allocatedBuffer);
                        SIZE_T freeSize = allocatedSize;
                        pNtFreeVirtualMemory(hCurrentProcess, &freeBase, &freeSize, MEM_RELEASE);
                        pNtClose(hDevice);
                        continue;
                    }
                    descriptor = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(allocatedBuffer);
                }
                else {
                    pNtClose(hDevice);
                    continue;
                }
            }

            {
                const DWORD reportedSize = descriptor->Size;
                if (reportedSize < sizeof(STORAGE_DEVICE_DESCRIPTOR) || static_cast<SIZE_T>(reportedSize) > MAX_DESCRIPTOR_SIZE) {
                    if (allocatedBuffer) {
                        PVOID freeBase = reinterpret_cast<PVOID>(allocatedBuffer);
                        SIZE_T freeSize = allocatedSize;
                        pNtFreeVirtualMemory(hCurrentProcess, &freeBase, &freeSize, MEM_RELEASE);
                        allocatedBuffer = nullptr;
                    }
                    pNtClose(hDevice);
                    continue;
                }
            }

            const u32 serialOffset = descriptor->SerialNumberOffset;
            if (serialOffset > 0 && serialOffset < descriptor->Size) {
                const char* serial = reinterpret_cast<const char*>(descriptor) + serialOffset;
                const size_t maxAvail = static_cast<size_t>(descriptor->Size) - static_cast<size_t>(serialOffset);
                const size_t serialLen = __strnlen(serial, maxAvail);

                debug("DISK_SERIAL: ", serial);

                if (is_qemu_serial(serial) || is_vbox_serial(serial, serialLen)) {
                    if (allocatedBuffer) {
                        PVOID freeBase = reinterpret_cast<PVOID>(allocatedBuffer);
                        SIZE_T freeSize = allocatedSize;
                        pNtFreeVirtualMemory(hCurrentProcess, &freeBase, &freeSize, MEM_RELEASE);
                        allocatedBuffer = nullptr;
                    }
                    pNtClose(hDevice);
                    return true;
                }
            }

            if (allocatedBuffer) {
                PVOID freeBase = reinterpret_cast<PVOID>(allocatedBuffer);
                SIZE_T freeSize = allocatedSize;
                pNtFreeVirtualMemory(hCurrentProcess, &freeBase, &freeSize, MEM_RELEASE);
                allocatedBuffer = nullptr;
            }
            pNtClose(hDevice);
        }

        if (successfulOpens == 0) {
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

        const auto pRtlInitUnicodeString = reinterpret_cast<void(__stdcall*)(PUNICODE_STRING, PCWSTR)>(funcs[0]);
        const auto pNtOpenKey = reinterpret_cast<NTSTATUS(__stdcall*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)>(funcs[1]);
        const auto pNtQueryKey = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG)>(funcs[2]);
        const auto pNtClose = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE)>(funcs[3]);

        if (!pRtlInitUnicodeString || !pNtOpenKey || !pNtQueryKey || !pNtClose) {
            return false;
        }

        constexpr GUID GUID_IVSHMEM_IFACE =
        { 0xdf576976, 0x569d, 0x4672, { 0x95, 0xa0, 0xf5, 0x7e, 0x4e, 0xa0, 0xb2, 0x10 } };

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

        UNICODE_STRING uPath;
        pRtlInitUnicodeString(&uPath, interface_class_path);

        OBJECT_ATTRIBUTES objAttr;
        RtlZeroMemory(&objAttr, sizeof(objAttr));
        objAttr.Length = sizeof(objAttr);
        objAttr.ObjectName = &uPath;
        objAttr.Attributes = OBJ_CASE_INSENSITIVE;

        HANDLE hKey = nullptr;
        NTSTATUS st = pNtOpenKey(&hKey, KEY_READ, &objAttr);
        if (!NT_SUCCESS(st) || hKey == nullptr) {
            return false;
        }

        BYTE infoBuf[512] = {};
        ULONG returnedLen = 0;
        st = pNtQueryKey(hKey, KeyFullInformation, infoBuf, sizeof(infoBuf), &returnedLen);

        DWORD number_of_subkeys = 0;
        if (NT_SUCCESS(st) && returnedLen >= sizeof(KEY_FULL_INFORMATION)) {
            auto* kfi = reinterpret_cast<KEY_FULL_INFORMATION*>(infoBuf);
            number_of_subkeys = static_cast<DWORD>(kfi->SubKeys);
        }
        else {
            pNtClose(hKey);
            return false;
        }

        pNtClose(hKey);

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

        const int colorMgmtCaps = GetDeviceCaps(hdc, COLORMGMTCAPS);
        ReleaseDC(nullptr, hdc);

        return !(colorMgmtCaps & CM_GAMMA_RAMP) || colorMgmtCaps == 0;
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

        const auto pRtlInitUnicodeString = reinterpret_cast<void(__stdcall*)(PUNICODE_STRING, PCWSTR)>(funcs[0]);
        const auto pNtOpenFile = reinterpret_cast<NTSTATUS(__stdcall*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG)>(funcs[1]);
        const auto pNtClose = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE)>(funcs[2]);

        if (!pRtlInitUnicodeString || !pNtOpenFile || !pNtClose) {
            return false;
        }

        auto try_open_native = [&](const wchar_t* nativePath) -> HANDLE {
            UNICODE_STRING uPath;
            pRtlInitUnicodeString(&uPath, nativePath);

            OBJECT_ATTRIBUTES objAttr;
            RtlZeroMemory(&objAttr, sizeof(objAttr));
            objAttr.Length = sizeof(objAttr);
            objAttr.ObjectName = &uPath;
            objAttr.Attributes = OBJ_CASE_INSENSITIVE;

            IO_STATUS_BLOCK iosb;
            HANDLE hFile = nullptr;

            // minimal read access to emulate CreateFile(...GENERIC_READ...)
            constexpr ACCESS_MASK desiredAccess = FILE_READ_DATA | FILE_READ_ATTRIBUTES;
            constexpr ULONG shareAccess = FILE_SHARE_READ;
            constexpr ULONG openOptions = FILE_OPEN | FILE_SYNCHRONOUS_IO_NONALERT;

            const NTSTATUS st = pNtOpenFile(&hFile, desiredAccess, &objAttr, &iosb, shareAccess, openOptions);
            if (NT_SUCCESS(st) && hFile) {
                return hFile;
            }
            return INVALID_HANDLE_VALUE;
        };

        // \\.\Name -> \??\Name, \\.\pipe\name -> \??\pipe\name
        const wchar_t* paths[] = {
            L"\\??\\VBoxMiniRdrDN",    // \\.\VBoxMiniRdrDN
            L"\\??\\pipe\\VBoxMiniRdDN",// \\.\pipe\VBoxMiniRdDN
            L"\\??\\VBoxTrayIPC",      // \\.\VBoxTrayIPC
            L"\\??\\pipe\\VBoxTrayIPC",// \\.\pipe\VBoxTrayIPC
            L"\\??\\HGFS",             // \\.\HGFS (VMware)
            L"\\??\\pipe\\cuckoo"      // \\.\pipe\cuckoo (Cuckoo)
        };

        HANDLE handles[ARRAYSIZE(paths)]{};
        for (size_t i = 0; i < ARRAYSIZE(paths); ++i) {
            handles[i] = try_open_native(paths[i]);
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
                pNtClose(handles[i]);
            }
        }

        if (vbox) {
            debug("DEVICE_HANDLES: Detected VBox related device handles");
            return core::add(brands::VBOX);
        }

        if (handles[4] != INVALID_HANDLE_VALUE) {
            pNtClose(handles[4]);
            debug("DEVICE_HANDLES: Detected VMware related device (HGFS)");
            return core::add(brands::VMWARE);
        }

        if (handles[5] != INVALID_HANDLE_VALUE) {
            pNtClose(handles[5]);
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

        const FN_NtQuerySystemInformation pNtQuerySystemInformation = reinterpret_cast<FN_NtQuerySystemInformation>(funcs[0]);
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
    
        const auto NtOpenKey = reinterpret_cast<PNtOpenKey>(funcs[0]);
        const auto NtQueryObject = reinterpret_cast<PNtQueryObject>(funcs[1]);
        const auto pNtClose = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE)>(funcs[2]);

        if (!NtOpenKey || !NtQueryObject || !pNtClose)
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
        NTSTATUS status = NtOpenKey(&hKey, KEY_READ, reinterpret_cast<POBJECT_ATTRIBUTES>(&objAttr));
        if (!(((NTSTATUS)(status)) >= 0))
            return false;
    
        alignas(16) BYTE buffer[1024]{};
        ULONG returnedLength = 0;
        status = NtQueryObject(hKey, ObjectNameInformation, buffer, sizeof(buffer), &returnedLength);
        pNtClose(hKey);
        if (!(((NTSTATUS)(status)) >= 0))
            return false;
    
        const auto pObjectName = reinterpret_cast<POBJECT_NAME_INFORMATION>(buffer);
    
        UNICODE_STRING expectedName{};
        expectedName.Buffer = const_cast<PWSTR>(L"\\REGISTRY\\USER");
        expectedName.Length = static_cast<USHORT>(wcslen(expectedName.Buffer) * sizeof(WCHAR));
    
        const bool mismatch = (pObjectName->Name.Length != expectedName.Length) ||
            (memcmp(pObjectName->Name.Buffer, expectedName.Buffer, expectedName.Length) != 0);
    
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

        const auto pRtlInitUnicodeString = reinterpret_cast<void(__stdcall*)(PUNICODE_STRING, PCWSTR)>(funcs[0]);
        const auto pNtOpenKey = reinterpret_cast<NTSTATUS(__stdcall*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)>(funcs[1]);
        const auto pNtQueryKey = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, KEY_INFORMATION_CLASS, PVOID, ULONG, PULONG)>(funcs[2]);
        const auto pNtClose = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE)>(funcs[3]);

        if (!pRtlInitUnicodeString || !pNtOpenKey || !pNtQueryKey || !pNtClose) {
            return false;
        }

        const wchar_t* nativePath = L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\MMDevices\\Audio\\Render";

        UNICODE_STRING uPath;
        pRtlInitUnicodeString(&uPath, nativePath);

        OBJECT_ATTRIBUTES objAttr;
        RtlZeroMemory(&objAttr, sizeof(objAttr));
        objAttr.Length = sizeof(objAttr);
        objAttr.ObjectName = &uPath;
        objAttr.Attributes = OBJ_CASE_INSENSITIVE;

        HANDLE hKey = nullptr;
        const ACCESS_MASK desiredAccess = KEY_READ;

        NTSTATUS st = pNtOpenKey(&hKey, desiredAccess, &objAttr);
        if (!NT_SUCCESS(st) || hKey == nullptr) {
            return false;
        }

        constexpr KEY_INFORMATION_CLASS InfoClass = KeyFullInformation;
        std::vector<BYTE> infoBuf(512);
        ULONG returnedLen = 0;

        st = pNtQueryKey(hKey, InfoClass, infoBuf.data(), static_cast<ULONG>(infoBuf.size()), &returnedLen);

        if (!NT_SUCCESS(st) && returnedLen > infoBuf.size()) {
            infoBuf.resize(returnedLen);
            st = pNtQueryKey(hKey, InfoClass, infoBuf.data(), static_cast<ULONG>(infoBuf.size()), &returnedLen);
        }

        bool hasValues = false;
        if (NT_SUCCESS(st) && returnedLen >= sizeof(KEY_FULL_INFORMATION)) {
            auto* kfi = reinterpret_cast<PKEY_FULL_INFORMATION>(infoBuf.data());
            const DWORD valueCount = static_cast<DWORD>(kfi->Values); // values, not subkeys
            hasValues = (valueCount > 0);
        }
        else {
            pNtClose(hKey);
            return false;
        }

        pNtClose(hKey);

        return hasValues;
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
        const HDEVINFO hDevInfo = SetupDiGetClassDevsW(&GUID_DEVCLASS_DISPLAY, nullptr, nullptr, DIGCF_PRESENT);
        if (hDevInfo == INVALID_HANDLE_VALUE) {
            debug(L"ACPI_SIGNATURE: No display device detected");
            return true;
        }

        SP_DEVINFO_DATA devInfo;
        ZeroMemory(&devInfo, sizeof(devInfo));
        devInfo.cbSize = sizeof(devInfo);
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

        for (DWORD idx = 0; SetupDiEnumDeviceInfo(hDevInfo, idx, &devInfo); ++idx) {
            DEVPROPTYPE propType = 0;
            DWORD requiredSize = 0;

            // query required size (bytes)
            SetupDiGetDevicePropertyW(hDevInfo, &devInfo, &key, &propType, nullptr, 0, &requiredSize, 0);
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || requiredSize == 0) {
                if (GetLastError() == ERROR_NOT_FOUND) {
                    debug(L"ACPI_SIGNATURE: No dedicated display/GPU detected");
                    SetupDiDestroyDeviceInfoList(hDevInfo);
                    return false;
                }
                else {
                    continue;
                }
            }

            // fetch buffer (multi-sz)
            std::vector<BYTE> buffer(requiredSize);
            if (!SetupDiGetDevicePropertyW(hDevInfo, &devInfo, &key, &propType,
                buffer.data(), requiredSize, &requiredSize, 0))
            {
                continue;
            }

            const wchar_t* ptr = reinterpret_cast<const wchar_t*>(buffer.data());
            // number of wchar_t slots in buffer
            const size_t total_wchars = requiredSize / sizeof(wchar_t);
            const wchar_t* buf_end = ptr + (total_wchars ? total_wchars : 0);

#ifdef __VMAWARE_DEBUG__
            for (const wchar_t* p = ptr; p < buf_end && *p; p += (wcslen(p) + 1)) {
                debug(L"ACPI_SIGNATURE: ", p);
            }
#endif

            static const wchar_t acpiPrefix[] = L"#ACPI(S";
            static const wchar_t acpiParen[] = L"ACPI(";

            // First pass: QEMU-style "#ACPI(Sxx...)" and generic "ACPI(Sxx)"
            for (const wchar_t* p = ptr; p < buf_end && *p; p += (wcslen(p) + 1)) {
                if (has_excluded_token(p)) {
                    debug(L"ACPI_SIGNATURE: Valid signature -> ", p);
                    continue;
                }

                // search for "#ACPI(S"
                const wchar_t* search = p;
                while (true) {
                    const wchar_t* found = wcsstr(search, acpiPrefix);
                    if (!found) break;

                    // after "#ACPI(S" we expect two hex chars
                    const wchar_t* hexpos = found + wcslen(acpiPrefix); // first hex char
                    if (hexpos && hexpos[0] && hexpos[1]) {
                        wchar_t b = hexpos[0];
                        wchar_t s = hexpos[1];
                        if (is_hex(b) && is_hex(s)) {
                            const wchar_t after = hexpos[2]; // may be '_' or ')'
                            if (after == L'_' || after == L')') {
                                SetupDiDestroyDeviceInfoList(hDevInfo);
                                return core::add(brands::QEMU);
                            }
                        }
                    }
                    search = found + 1;
                }

                // search for "ACPI(" then check for "S" + two hex digits
                search = p;
                while (true) {
                    const wchar_t* found = wcsstr(search, acpiParen);
                    if (!found) break;
                    const wchar_t* start = found + wcslen(acpiParen); // char after '('
                    if (start && start[0] && start[1] && start[2]) {
                        if (start[0] == L'S' && is_hex(start[1]) && is_hex(start[2])) {
                            SetupDiDestroyDeviceInfoList(hDevInfo);
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
                        SetupDiDestroyDeviceInfoList(hDevInfo);
                        return core::add(brands::HYPERV);
                    }
                }
            }
        }

        SetupDiDestroyDeviceInfoList(hDevInfo);
        return false;
    }


    /**
     * @brief Check if after raising two traps at the same RIP, a hypervisor interferes with the instruction pointer delivery
     * @category Windows, x86
     * @implements VM::TRAP
     */
    [[nodiscard]] static bool trap() {
        bool hypervisorCaught = false;
    #if (x86)
        // when a single-step (TF) and hardware breakpoint (DR0) collide, Intel CPUs set both DR6.BS and DR6.B0 to report both events, which help make this detection trick
        // AMD CPUs prioritize the breakpoint, setting only its corresponding bit in DR6 and clearing the single-step bit, which is why this technique is not compatible with AMD
        if (!cpu::is_intel()) {
            return false;
        }

        // push flags, set TF-bit, pop flags, execute a dummy instruction, then return
        constexpr u8 trampoline[] = {
            0x9C,                         // pushfq
            0x81, 0x04, 0x24,             // OR DWORD PTR [RSP], 0x10100
            0x00, 0x01, 0x01, 0x00,
            0x9D,                         // popfq
            0x0F, 0xA2,                   // cpuid (or any other trappable instruction, but this one is ok since it has to be trapped in every x86 hv)
            0x90, 0x90, 0x90,             // NOPs to pad to breakpoint offset
            0xC3                          // ret
        };
        SIZE_T trampSize = sizeof(trampoline);

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

        const auto pNtAllocateVirtualMemory = reinterpret_cast<NtAllocateVirtualMemory_t>(funcs[0]);
        const auto pNtProtectVirtualMemory = reinterpret_cast<NtProtectVirtualMemory_t>(funcs[1]);
        const auto pNtFreeVirtualMemory = reinterpret_cast<NtFreeVirtualMemory_t>(funcs[2]);
        const auto pNtFlushInstructionCache = reinterpret_cast<NtFlushInstructionCache_t>(funcs[3]);
        const auto pNtClose = reinterpret_cast<NtClose_t>(funcs[4]);
        const auto pNtGetContextThread = reinterpret_cast<NtGetContextThread_t>(funcs[5]);
        const auto pNtSetContextThread = reinterpret_cast<NtSetContextThread_t>(funcs[6]);

        if (!pNtAllocateVirtualMemory || !pNtProtectVirtualMemory || !pNtFlushInstructionCache ||
            !pNtFreeVirtualMemory || !pNtGetContextThread || !pNtSetContextThread || !pNtClose) {
            return false;
        }

        PVOID execMem = nullptr;
        SIZE_T regionSize = trampSize;
        const HANDLE hCurrentProcess = reinterpret_cast<HANDLE>(-1LL);
        NTSTATUS st = pNtAllocateVirtualMemory(hCurrentProcess, &execMem, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(st) || !execMem) {
            return false;
        }
        memcpy(execMem, trampoline, trampSize);

        {
            PVOID tmpBase = execMem;
            SIZE_T tmpSz = trampSize;
            ULONG oldProt = 0;
            st = pNtProtectVirtualMemory(hCurrentProcess, &tmpBase, &tmpSz, PAGE_EXECUTE_READ, &oldProt);
            if (!NT_SUCCESS(st)) {
                PVOID freeBase = execMem; SIZE_T freeSize = trampSize;
                pNtFreeVirtualMemory(hCurrentProcess, &freeBase, &freeSize, MEM_RELEASE);
                return false;
            }
        }

        pNtFlushInstructionCache(hCurrentProcess, execMem, trampSize);

        u8 hitCount = 0;

        CONTEXT origCtx{};
        origCtx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        const HANDLE hCurrentThread = reinterpret_cast<HANDLE>(-2LL);

        if (!NT_SUCCESS(pNtGetContextThread(hCurrentThread, &origCtx))) {
            PVOID freeBase = execMem; SIZE_T freeSize = trampSize;
            pNtFreeVirtualMemory(hCurrentProcess, &freeBase, &freeSize, MEM_RELEASE);
            return false;
        }

        // set Dr0 to trampoline+offset (step triggers here)
        CONTEXT dbgCtx = origCtx;
        const uintptr_t baseAddr = reinterpret_cast<uintptr_t>(execMem);
        dbgCtx.Dr0 = baseAddr + 11; // single step breakpoint address
        dbgCtx.Dr7 = 1;             // enable local breakpoint 0

        if (!NT_SUCCESS(pNtSetContextThread(hCurrentThread, &dbgCtx))) {
            pNtSetContextThread(hCurrentThread, &origCtx);
            PVOID freeBase = execMem; SIZE_T freeSize = trampSize;
            pNtFreeVirtualMemory(hCurrentProcess, &freeBase, &freeSize, MEM_RELEASE);
            return false;
        }

        auto vetExceptions = [&](u32 code, EXCEPTION_POINTERS* info) -> u8 {
            // if not single-step, hypervisor likely swatted our trap
            if (code != static_cast<DWORD>(0x80000004L)) {
                hypervisorCaught = true;
                return EXCEPTION_CONTINUE_SEARCH;
            }
            // count breakpoint hits
            hitCount++;
            // validate exception address matches our breakpoint location
            if (reinterpret_cast<uintptr_t>(info->ExceptionRecord->ExceptionAddress) != baseAddr + 11) {
                hypervisorCaught = true;
                return EXCEPTION_EXECUTE_HANDLER;
            }
            // check if Trap Flag and DR0 contributed
            const u64 status = info->ContextRecord->Dr6;
            const bool fromTrapFlag = (status & (1ULL << 14)) != 0;
            const bool fromDr0 = (status & 1ULL) != 0;
            if (!fromTrapFlag || !fromDr0) {
                if (util::hyper_x() != HYPERV_ARTIFACT_VM)
                    hypervisorCaught = true; // detects type 1 Hyper-V too, which we consider legitimate
            }
            return EXCEPTION_EXECUTE_HANDLER;
        };

        __try {
            reinterpret_cast<void(*)()>(execMem)();
        }
        __except (vetExceptions(_exception_code(), reinterpret_cast<EXCEPTION_POINTERS*>(_exception_info()))) {
            // if we didn't hit exactly once, assume hypervisor interference
            if (hitCount != 1) {
                hypervisorCaught = true;
            }
        }

        pNtSetContextThread(hCurrentThread, &origCtx);

        PVOID freeBase = execMem; SIZE_T freeSize = trampSize;
        pNtFreeVirtualMemory(hCurrentProcess, &freeBase, &freeSize, MEM_RELEASE);
    #endif
        return hypervisorCaught;
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

        const auto pNtAllocateVirtualMemory = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG)>(funcs[0]);
        const auto pNtProtectVirtualMemory = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG)>(funcs[1]);
        const auto pNtFlushInstructionCache = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, PVOID, SIZE_T)>(funcs[2]);
        const auto pNtFreeVirtualMemory = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG)>(funcs[3]);

        if (!pNtAllocateVirtualMemory || !pNtProtectVirtualMemory || !pNtFlushInstructionCache || !pNtFreeVirtualMemory) {
            return false;
        }

        const HANDLE hCurrentProcess = reinterpret_cast<HANDLE>(-1LL);
        PVOID base = nullptr;
        SIZE_T regionSize = sizeof(ud_opcodes);
        NTSTATUS st = pNtAllocateVirtualMemory(hCurrentProcess, &base, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(st) || !base) {
            return false;
        }

        memcpy(base, ud_opcodes, sizeof(ud_opcodes));

        ULONG oldProtect = 0;
        st = pNtProtectVirtualMemory(hCurrentProcess, &base, &regionSize, PAGE_EXECUTE_READ, &oldProtect);
        if (!NT_SUCCESS(st)) {
            pNtFreeVirtualMemory(hCurrentProcess, &base, &regionSize, MEM_RELEASE);
            return false;
        }

        pNtFlushInstructionCache(hCurrentProcess, base, regionSize);

        __try {
            reinterpret_cast<void(*)()>(base)();
        }
        __except (GetExceptionCode() == EXCEPTION_ILLEGAL_INSTRUCTION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
            saw_ud = true;
        }

        pNtFreeVirtualMemory(hCurrentProcess, &base, &regionSize, MEM_RELEASE);

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

        struct VMCallInfo {
            u32 structsize;
            u32 level2pass;
            u32 command;
        };

        VMCallInfo vmcallInfo = {};
        u64 vmcallResult = 0;

        constexpr u8 intelTemplate[44] = {
            0x48,0xBA,0,0,0,0,0,0,0,0,                     // mov rdx, imm64   ; PW1
            0x48,0xB9,0,0,0,0,0,0,0,0,                     // mov rcx, imm64   ; PW3
            0x48,0xB8,0,0,0,0,0,0,0,0,                     // mov rax, imm64   ; &vmcallInfo
            0x0F,0x01,0xC1,                                // vmcall
            0x48,0xA3,0,0,0,0,0,0,0,0,                     // mov [imm64], rax ; &vmcallResult
            0xC3                                           // ret
        };

        constexpr u8 amdTemplate[44] = {
            0x48,0xBA,0,0,0,0,0,0,0,0,                     // mov rdx, imm64   ; PW1
            0x48,0xB9,0,0,0,0,0,0,0,0,                     // mov rcx, imm64   ; PW3
            0x48,0xB8,0,0,0,0,0,0,0,0,                     // mov rax, imm64   ; &vmcallInfo
            0x0F,0x01,0xD9,                                // vmmcall (AMD)
            0x48,0xA3,0,0,0,0,0,0,0,0,                     // mov [imm64], rax ; &vmcallResult
            0xC3                                           // ret
        };

        const SIZE_T stubSize = sizeof(intelTemplate);
        const bool isAmd = cpu::is_amd();

        const HANDLE hCurrentProcess = reinterpret_cast<HANDLE>(-1LL);
        const HMODULE ntdll = util::get_ntdll();
        if (!ntdll) return false;

        const char* names[] = { "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtFlushInstructionCache", "NtFreeVirtualMemory" };
        void* funcs[ARRAYSIZE(names)] = {};
        util::get_function_address(ntdll, names, funcs, ARRAYSIZE(names));

        const auto pNtAllocateVirtualMemory = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG)>(funcs[0]);
        const auto pNtProtectVirtualMemory = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG)>(funcs[1]);
        const auto pNtFlushInstructionCache = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, PVOID, SIZE_T)>(funcs[2]);
        const auto pNtFreeVirtualMemory = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG)>(funcs[3]);

        if (!pNtAllocateVirtualMemory || !pNtProtectVirtualMemory || !pNtFlushInstructionCache || !pNtFreeVirtualMemory) {
            return false;
        }

        PVOID stub = nullptr;
        SIZE_T regionSize = stubSize;
        NTSTATUS st = pNtAllocateVirtualMemory(hCurrentProcess, &stub, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(st) || !stub) return false;

        if (isAmd) {
            memcpy(stub, amdTemplate, stubSize);
        }
        else {
            memcpy(stub, intelTemplate, stubSize);
        }

        // rdx imm64
        // rcx imm64
        // rax imm64
        // mov [imm64], rax immediate
        *reinterpret_cast<u64*>(reinterpret_cast<u8*>(stub) + 2) = PW1;
        *reinterpret_cast<u64*>(reinterpret_cast<u8*>(stub) + 12) = PW3;
        *reinterpret_cast<u64*>(reinterpret_cast<u8*>(stub) + 22) = reinterpret_cast<u64>(static_cast<void*>(&vmcallInfo));
        *reinterpret_cast<u64*>(reinterpret_cast<u8*>(stub) + 35) = reinterpret_cast<u64>(static_cast<void*>(&vmcallResult));

        ULONG oldProtect = 0;
        st = pNtProtectVirtualMemory(hCurrentProcess, &stub, &regionSize, PAGE_EXECUTE_READ, &oldProtect);
        if (!NT_SUCCESS(st)) {
            pNtFreeVirtualMemory(hCurrentProcess, &stub, &regionSize, MEM_RELEASE);
            return false;
        }

        pNtFlushInstructionCache(hCurrentProcess, stub, regionSize);

        auto tryPass = [&]() -> bool {
            vmcallInfo.structsize = static_cast<u32>(sizeof(VMCallInfo));
            vmcallInfo.level2pass = PW2;
            vmcallInfo.command = 0;
            vmcallResult = 0;

            __try {
                reinterpret_cast<void(*)()>(stub)();
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { // EXCEPTION_ILLEGAL_INSTRUCTION normally, EXCEPTION_ACCESS_VIOLATION_READ on edge-cases
                vmcallResult = 0;
            }

            return (((vmcallResult >> 24) & 0xFF) == 0xCE); // the VM returns status in bits 24–31; Cheat Engine uses 0xCE here
        };

        const bool found = tryPass();

        pNtFreeVirtualMemory(hCurrentProcess, &stub, &regionSize, MEM_RELEASE);

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
    #if (CLANG || GCC)
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

        using NtQuerySysInfo_t = NTSTATUS(__stdcall*)(
            SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG
        );
        NtQuerySysInfo_t pNtQuery = reinterpret_cast<NtQuerySysInfo_t>(functions[0]);
        if (!pNtQuery)
            return false;

        // determine required buffer size
        const SYSTEM_INFORMATION_CLASS SysBootInfo = static_cast<SYSTEM_INFORMATION_CLASS>(140);
        ULONG needed = 0;
        NTSTATUS st = pNtQuery(SysBootInfo, nullptr, 0, &needed);
        if (st != static_cast<NTSTATUS>(0xC0000023) && st != static_cast<NTSTATUS>(0x80000005) && st != static_cast<NTSTATUS>(0xC0000004)) 
            return false;

        static std::vector<u8> buffer;
        if (buffer.size() < needed)
            buffer.resize(needed);

        // fetch the boot-logo data
        st = pNtQuery(SysBootInfo, buffer.data(), needed, &needed);
        if (!NT_SUCCESS(st))
            return false;

        // parse header to locate the bitmap
        struct BootLogoInfo { ULONG Flags, BitmapOffset; };
        const auto* info = reinterpret_cast<BootLogoInfo*>(buffer.data());
        const u8* bmp = buffer.data() + info->BitmapOffset;
        const size_t size = static_cast<size_t>(needed) - info->BitmapOffset;

        // 8 byte chunks
        u64 crcReg = 0xFFFFFFFFull;
        const size_t qwords = size >> 3;
        const auto* ptr = reinterpret_cast<const u64*>(bmp);
        // unrolling the loop can lead to better instruction scheduling
        size_t i = 0;
        __try {
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

            for (size_t j = 0, r = size & 7; j < r; ++j) {
                crc = _mm_crc32_u8(crc, tail[j]);
            }
            crc ^= 0xFFFFFFFFu;

            debug("BOOT_LOGO: size=", needed, ", flags=", info->Flags, ", offset=", info->BitmapOffset, ", crc=0x", std::hex, crc);

            switch (crc) {
                case 0x110350C5: return core::add(brands::QEMU); // TianoCore EDK2
                case 0x87c39681: return core::add(brands::HYPERV);
                case 0xf6829262: return core::add(brands::VBOX);
                default:         return false;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false; // EXCEPTION_ILLEGAL_INSTRUCTION due to lack of SSE4.2 instruction set
        }   
    #else
        return false;
    #endif
    }


    /**
     * @brief Check for any signs of VMs in Windows kernel object entities 
     * @category Windows
     * @implements VM::OBJECTS
     */
    [[nodiscard]] static bool objects() {
        struct OBJECT_DIRECTORY_INFORMATION {
            UNICODE_STRING Name;
            UNICODE_STRING TypeName;
        };

        using POBJECT_DIRECTORY_INFORMATION = OBJECT_DIRECTORY_INFORMATION*;
        constexpr auto DIRECTORY_QUERY = 0x0001;
        constexpr NTSTATUS STATUS_NO_MORE_ENTRIES = 0x8000001A;

        HANDLE hDir = nullptr;
        OBJECT_ATTRIBUTES objAttr{};
        UNICODE_STRING dirName{};
        NTSTATUS status;

        const HMODULE ntdll = util::get_ntdll();
        if (!ntdll) return false;

        const char* names[] = { "NtOpenDirectoryObject", "NtQueryDirectoryObject", "NtClose" };
        void* funcs[ARRAYSIZE(names)] = {};
        util::get_function_address(ntdll, names, funcs, ARRAYSIZE(names));

        const auto pNtOpenDirectoryObject = reinterpret_cast<NTSTATUS(__stdcall*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES)>(funcs[0]);
        const auto pNtQueryDirectoryObject = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG)>(funcs[1]);
        const auto pNtClose = reinterpret_cast<NTSTATUS(__stdcall*)(HANDLE)>(funcs[2]);

        if (!pNtOpenDirectoryObject || !pNtQueryDirectoryObject || !pNtClose) return false;

        const wchar_t* deviceDirPath = L"\\Device";
        dirName.Buffer = (PWSTR)deviceDirPath;
        dirName.Length = (USHORT)(wcslen(deviceDirPath) * sizeof(wchar_t));
        dirName.MaximumLength = dirName.Length + sizeof(wchar_t);

        InitializeObjectAttributes(&objAttr, &dirName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        status = pNtOpenDirectoryObject(&hDir, DIRECTORY_QUERY, &objAttr);

        if (!NT_SUCCESS(status)) {
            return false;
        }

        std::vector<BYTE> buffer(4096);
        constexpr size_t MAX_DIR_BUFFER = 64 * 1024; 
        ULONG context = 0;
        ULONG returnedLength = 0;

        while (true) {
            status = pNtQueryDirectoryObject(
                hDir,
                buffer.data(),
                static_cast<ULONG>(buffer.size()),
                TRUE,   // ReturnSingleEntry
                FALSE,
                &context,
                &returnedLength
            );

            if (status == STATUS_NO_MORE_ENTRIES) {
                break;
            }

            if (!NT_SUCCESS(status)) {
                if (returnedLength > buffer.size()) {
                    size_t newSize = static_cast<size_t>(returnedLength);
                    if (newSize > MAX_DIR_BUFFER) newSize = MAX_DIR_BUFFER;
                    if (newSize <= buffer.size()) {
                        pNtClose(hDir);
                        return false;
                    }
                    try {
                        buffer.resize(newSize);
                    }
                    catch (...) {
                        pNtClose(hDir);
                        return false;
                    }
                    continue;
                }
                pNtClose(hDir);
                return false;
            }

            const size_t usedLen = (returnedLength == 0) ? buffer.size() : static_cast<size_t>(returnedLength);
            if (usedLen < sizeof(OBJECT_DIRECTORY_INFORMATION) || usedLen > buffer.size()) {
                pNtClose(hDir);
                return false;
            }

            const POBJECT_DIRECTORY_INFORMATION pOdi = reinterpret_cast<POBJECT_DIRECTORY_INFORMATION>(buffer.data());

            const uintptr_t bufBase = reinterpret_cast<uintptr_t>(buffer.data());
            const uintptr_t bufEnd = bufBase + usedLen;

            std::wstring objectName;
            bool gotName = false;

            const size_t nameBytes = static_cast<size_t>(pOdi->Name.Length);
            const uintptr_t namePtr = reinterpret_cast<uintptr_t>(pOdi->Name.Buffer);

            if (nameBytes > 0 && (nameBytes % sizeof(wchar_t) == 0)) {
                const uintptr_t minValidPtr = bufBase + sizeof(OBJECT_DIRECTORY_INFORMATION);
                if (namePtr >= minValidPtr && (namePtr + nameBytes) <= bufEnd && (namePtr % sizeof(wchar_t) == 0)) {
                    const wchar_t* wname = reinterpret_cast<const wchar_t*>(namePtr);
                    const size_t wlen = nameBytes / sizeof(wchar_t);
                    bool foundTerm = false;
                    for (size_t i = 0; i < wlen; ++i) {
                        if (wname[i] == L'\0') { objectName.assign(wname, i); foundTerm = true; break; }
                    }
                    if (!foundTerm) {
                        objectName.assign(wname, wlen);
                    }
                    gotName = true;
                }
            }

            if (!gotName) {
                const uintptr_t altStart = bufBase + sizeof(OBJECT_DIRECTORY_INFORMATION);
                if (altStart >= bufEnd) {
                    pNtClose(hDir);
                    return false;
                }
                const size_t maxBytes = bufEnd - altStart;
                if (maxBytes < sizeof(wchar_t)) {
                    pNtClose(hDir);
                    return false;
                }
                const wchar_t* altPtr = reinterpret_cast<const wchar_t*>(buffer.data() + (altStart - bufBase));
                const size_t maxChars = maxBytes / sizeof(wchar_t);

                size_t realChars = 0;
                for (; realChars < maxChars; ++realChars) {
                    if (altPtr[realChars] == L'\0') break;
                }
                if (realChars == maxChars) {
                    pNtClose(hDir);
                    return false;
                }
                objectName.assign(altPtr, realChars);
                gotName = true;
            }

            if (!gotName) {
                pNtClose(hDir);
                return false;
            }

            if (objectName == L"VmGenerationCounter") {
                pNtClose(hDir);
                debug("OBJECTS: Detected VmGenerationCounter");
                return core::add(brands::HYPERV);
            }
            if (objectName == L"VmGid") {
                pNtClose(hDir);
                debug("OBJECTS: Detected VmGid");
                return core::add(brands::HYPERV);
            }
        }

        pNtClose(hDir);
        return false;
    }


    /**
     * @brief Check for known NVRAM signatures that are present on virtual firmware
     * @category Windows
     * @warning Permissions required
     * @implements VM::NVRAM
     */
    [[nodiscard]] static bool nvram_vars() {
        struct VARIABLE_NAME { ULONG NextEntryOffset; GUID VendorGuid; WCHAR Name[1]; };
        using PVARIABLE_NAME = VARIABLE_NAME*;
        using NtEnumerateSystemEnvironmentValuesEx_t = NTSTATUS(__stdcall*)(ULONG, PVOID, PULONG);

        bool found_dbDefault = false, found_dbxDefault = false, found_KEKDefault = false, found_PKDefault = false;
        bool found_MORCL = false;
        bool pk_checked = false;

        if (!util::is_admin()) return false;

        HANDLE hToken = nullptr;
        const HANDLE hCurrentProcess = reinterpret_cast<HANDLE>(-1LL);
        if (!OpenProcessToken(hCurrentProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return false;

        LUID luid{};
        bool priv_enabled = false;
        auto cleanup = [&]() {
            if (priv_enabled && hToken) {
                TOKEN_PRIVILEGES tpDisable{};
                tpDisable.PrivilegeCount = 1;
                tpDisable.Privileges[0].Luid = luid;
                tpDisable.Privileges[0].Attributes = 0;
                AdjustTokenPrivileges(hToken, FALSE, &tpDisable, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);
            }
            if (hToken) {
                CloseHandle(hToken);
                hToken = nullptr;
            }
            };

        if (!LookupPrivilegeValue(nullptr, SE_SYSTEM_ENVIRONMENT_NAME, &luid)) { cleanup(); return false; }

        TOKEN_PRIVILEGES tpEnable{};
        tpEnable.PrivilegeCount = 1;
        tpEnable.Privileges[0].Luid = luid;
        tpEnable.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tpEnable, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr);
        if (GetLastError() != ERROR_SUCCESS) { cleanup(); return false; }
        priv_enabled = true;

        bool hasFunction = false;
        bool success = false;
        std::vector<BYTE> resBuffer;
        ULONG bufferLength = 0;
        const HMODULE ntdll = util::get_ntdll();
        if (ntdll) {
            const char* names[] = { "NtEnumerateSystemEnvironmentValuesEx" };
            void* functions[1] = { nullptr };
            util::get_function_address(ntdll, names, functions, 1);
            const auto NtEnum = reinterpret_cast<NtEnumerateSystemEnvironmentValuesEx_t>(functions[0]);
            if (NtEnum) {
                hasFunction = true;
                NtEnum(1, nullptr, &bufferLength);
                if (bufferLength != 0) {
                    try { resBuffer.resize(bufferLength); }
                    catch (...) { resBuffer.clear(); bufferLength = 0; }
                    if (!resBuffer.empty()) {
                        const NTSTATUS status = NtEnum(1, resBuffer.data(), &bufferLength);
                        if (status == 0) { success = true; resBuffer.resize(bufferLength); }
                        else resBuffer.clear();
                    }
                }
            }
        }

        if (!hasFunction) {
            debug("NVRAM: NtEnumerateSystemEnvironmentValuesEx could not be resolved");
            cleanup();
            return false;
        }
        if (!success) {
            debug("NVRAM: System is not UEFI");
            cleanup();
            return false;
        }

        auto contains_redhat_ascii_ci = [](const BYTE* data, size_t len)->bool {
            static const char pattern[] = "red hat secure boot";
            const size_t plen = sizeof(pattern) - 1;
            if (len < plen) return false;
            for (size_t i = 0; i <= len - plen; ++i) {
                bool ok = true;
                for (size_t j = 0; j < plen; ++j) {
                    char c = static_cast<char>(data[i + j]);
                    unsigned char uc = static_cast<unsigned char>(c);
                    char lc = static_cast<char>(::tolower(uc));
                    if (lc != pattern[j]) { ok = false; break; }
                }
                if (ok) return true;
            }
            return false;
        };

        auto contains_redhat_utf16le_ci = [](const WCHAR* wdata, size_t wlen)->bool {
            static const wchar_t pattern[] = L"red hat secure boot";
            const size_t plen = (sizeof(pattern) / sizeof(pattern[0])) - 1;
            if (wlen < plen) return false;
            for (size_t i = 0; i <= wlen - plen; ++i) {
                bool ok = true;
                for (size_t j = 0; j < plen; ++j) {
                    wchar_t wc = wdata[i + j];
                    wchar_t lw = static_cast<wchar_t>(::towlower(wc));
                    if (lw != pattern[j]) { ok = false; break; }
                }
                if (ok) return true;
            }
            return false;
        };

        PVARIABLE_NAME varName = reinterpret_cast<PVARIABLE_NAME>(resBuffer.data());
        const size_t bufSize = resBuffer.size();
        constexpr size_t MAX_NAME_BYTES = 4096;

        while (true) {
            const uintptr_t basePtr = reinterpret_cast<uintptr_t>(resBuffer.data());
            const uintptr_t curPtr = reinterpret_cast<uintptr_t>(varName);
            if (curPtr < basePtr) break;
            const size_t offset = static_cast<size_t>(curPtr - basePtr);
            if (offset >= bufSize) break;

            const size_t nameOffset = offsetof(VARIABLE_NAME, Name);
            if (bufSize - offset < nameOffset) break;

            size_t nameMaxBytes = 0;
            if (varName->NextEntryOffset != 0) {
                const SIZE_T ne = static_cast<SIZE_T>(varName->NextEntryOffset);
                if (ne <= nameOffset) { cleanup(); return false; }
                if (ne > bufSize - offset) break;
                nameMaxBytes = ne - nameOffset;
            }
            else {
                if (offset + nameOffset >= bufSize) { cleanup(); return false; }
                nameMaxBytes = bufSize - (offset + nameOffset);
            }
            if (nameMaxBytes > MAX_NAME_BYTES) nameMaxBytes = MAX_NAME_BYTES;

            std::wstring_view nameView;
            if (nameMaxBytes >= sizeof(WCHAR)) {
                const WCHAR* namePtr = reinterpret_cast<const WCHAR*>(reinterpret_cast<const BYTE*>(varName) + nameOffset);
                const size_t maxChars = nameMaxBytes / sizeof(WCHAR);
                size_t realChars = 0;
                while (realChars < maxChars && namePtr[realChars] != L'\0') ++realChars;
                if (realChars == maxChars) { cleanup(); return false; }
                nameView = std::wstring_view(namePtr, realChars);
            }

            auto format_guid = [](const GUID& g)->std::wstring {
                wchar_t buf[40] = {};
                int written = _snwprintf_s(buf, _countof(buf), _TRUNCATE,
                    L"{%08lX-%04hX-%04hX-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                    static_cast<unsigned long>(g.Data1),
                    static_cast<u16>(g.Data2),
                    static_cast<u16>(g.Data3),
                    static_cast<u32>(g.Data4[0]), static_cast<u32>(g.Data4[1]),
                    static_cast<u32>(g.Data4[2]), static_cast<u32>(g.Data4[3]),
                    static_cast<u32>(g.Data4[4]), static_cast<u32>(g.Data4[5]),
                    static_cast<u32>(g.Data4[6]), static_cast<u32>(g.Data4[7]));
                if (written <= 0) return std::wstring();
                return std::wstring(buf);
            };

            if (!nameView.empty() && nameView.rfind(L"VMM", 0) == 0) {
                debug("NVRAM: Detected hypervisor signature");
                cleanup();
                return true;
            }

            if (nameView == L"dbDefault") found_dbDefault = true;
            else if (nameView == L"KEKDefault") found_KEKDefault = true;
            else if (nameView == L"PKDefault") found_PKDefault = true;
            else if (nameView == L"dbxDefault") found_dbxDefault = true;
            else if (nameView == L"MemoryOverwriteRequestControlLock") found_MORCL = true;

            if (!pk_checked && nameView == L"PKDefault") {
                const std::wstring guidStr = format_guid(varName->VendorGuid);
                if (guidStr.empty()) { cleanup(); return true; }

                DWORD bufSizeAttempt = 8192;
                std::vector<BYTE> valueBuf;
                for (int attempt = 0; attempt < 4; ++attempt) { // up to 128KB aprox
                    valueBuf.resize(bufSizeAttempt);
                    DWORD readLen = GetFirmwareEnvironmentVariableW(
                        std::wstring(nameView).c_str(), 
                        guidStr.c_str(),
                        valueBuf.data(),
                        bufSizeAttempt);
                    if (readLen > 0) {
                        valueBuf.resize(readLen);
                        break;
                    }
                    DWORD err = GetLastError();
                    if (err == ERROR_INSUFFICIENT_BUFFER) {
                        bufSizeAttempt *= 2;
                        continue;
                    }
                    valueBuf.clear();
                    break;
                }

                bool pk_has_redhat = false;
                if (!valueBuf.empty()) {
                    if (valueBuf.size() >= 2 && (valueBuf.size() % 2) == 0) {
                        const WCHAR* wptr = reinterpret_cast<const WCHAR*>(valueBuf.data());
                        size_t wlen = valueBuf.size() / sizeof(WCHAR);
                        if (contains_redhat_utf16le_ci(wptr, wlen)) pk_has_redhat = true;
                    }
                    if (!pk_has_redhat) {
                        if (contains_redhat_ascii_ci(valueBuf.data(), valueBuf.size())) pk_has_redhat = true;
                    }
                }

                pk_checked = true;
                if (pk_has_redhat) {
                    debug("NVRAM: QEMU detected");
                    cleanup();
                    return core::add(brands::QEMU);
                }
            }

            if (found_MORCL && found_dbDefault && found_dbxDefault && found_KEKDefault && found_PKDefault && pk_checked) {
                break;
            }

            if (varName->NextEntryOffset == 0) break;
            const SIZE_T ne = static_cast<SIZE_T>(varName->NextEntryOffset);
            const size_t nextOffset = offset + ne;
            if (nextOffset <= offset || nextOffset > bufSize) break;
            varName = reinterpret_cast<PVARIABLE_NAME>(reinterpret_cast<PBYTE>(resBuffer.data()) + nextOffset);
        }

        if (!found_MORCL) { debug("NVRAM: Missing MemoryOverwriteRequestControlLock"); cleanup(); return true; }
        if (!found_dbDefault) { debug("NVRAM: Missing dbDefault"); cleanup(); return true; }
        if (!found_dbxDefault) { debug("NVRAM: Missing dbxDefault"); cleanup(); return true; }
        if (!found_KEKDefault) { debug("NVRAM: Missing KEKDefault"); cleanup(); return true; }
        if (!found_PKDefault) { debug("NVRAM: Missing PKDefault"); cleanup(); return true; }

        cleanup();
        return false;
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
        auto decodeManufacturerFast = [](const BYTE* edid) __declspec(noinline) -> std::array<char, 4> {
            // edid[8..9] big-endian word
            const uint16_t word = static_cast<uint16_t>((edid[8] << 8) | edid[9]);
            const uint8_t c1 = static_cast<uint8_t>((word >> 10) & 0x1F);
            const uint8_t c2 = static_cast<uint8_t>((word >> 5) & 0x1F);
            const uint8_t c3 = static_cast<uint8_t>((word >> 0) & 0x1F);
            std::array<char, 4> out{ {'?','?','?','\0'} };
            if (c1 >= 1 && c1 <= 26) out[0] = static_cast<char>('A' + c1 - 1);
            if (c2 >= 1 && c2 <= 26) out[1] = static_cast<char>('A' + c2 - 1);
            if (c3 >= 1 && c3 <= 26) out[2] = static_cast<char>('A' + c3 - 1);
            return out;
        };

        auto isThreeUpperAlphaFast = [](const std::array<char, 4>& m) -> bool {
            return (m[0] >= 'A' && m[0] <= 'Z') &&
                (m[1] >= 'A' && m[1] <= 'Z') &&
                (m[2] >= 'A' && m[2] <= 'Z');
        };

        auto descHasUpperPrefixMonitorFast = [](const char* desc) -> bool {
            if (!desc || desc[0] == '\0') return false;
            // Two tails to search: " Monitor" and " Display" (leading space)
            const char* tails[] = { " Monitor", " Display" };
            for (const char* tail : tails) {
                const char* p = strstr(desc, tail);
                while (p) {
                    // ensure not at position 0
                    if (p != desc) {
                        // walk backwards counting uppercase letters
                        const char* start = p;
                        size_t len = 0;
                        while (start > desc) {
                            --start;
                            unsigned char uc = static_cast<unsigned char>(*start);
                            if (uc >= 'A' && uc <= 'Z') {
                                ++len;
                                if (len > 8) break;
                            }
                            else break;
                        }
                        if (len >= 4 && len <= 8) {
                            // verify all are uppercase (we already did while walking)
                            return true;
                        }
                    }
                    p = strstr(p + 1, tail);
                }
            }
            return false;
        };

        auto getDevicePropertyA = [](HDEVINFO devInfo, SP_DEVINFO_DATA& devData, DWORD propId, std::string& out) -> bool {
            char small[512] = {};
            DWORD needed = 0;
            if (SetupDiGetDeviceRegistryPropertyA(devInfo, &devData, propId, nullptr, reinterpret_cast<PBYTE>(small), sizeof(small), &needed)) {
                out.assign(small);
                return true;
            }
            const DWORD err = GetLastError();
            if (err == ERROR_INSUFFICIENT_BUFFER && needed > 0 && needed < 65536) {
                std::vector<char> big(needed + 1);
                if (SetupDiGetDeviceRegistryPropertyA(devInfo, &devData, propId, nullptr, reinterpret_cast<PBYTE>(big.data()), static_cast<DWORD>(big.size()), &needed)) {
                    big[big.size() - 1] = '\0';
                    out.assign(big.data());
                    return true;
                }
            }
            out.clear();
            return false;
        };

        const HDEVINFO devInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_MONITOR, nullptr, nullptr, DIGCF_PRESENT);
        if (devInfo == INVALID_HANDLE_VALUE) return false;

        SP_DEVINFO_DATA devData{};
        devData.cbSize = sizeof(devData);

        for (DWORD index = 0; SetupDiEnumDeviceInfo(devInfo, index, &devData); ++index) {
            // open registry key for device
            const HKEY hDevKey = SetupDiOpenDevRegKey(devInfo, &devData, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ);
            if (hDevKey == INVALID_HANDLE_VALUE) continue;

            BYTE buffer[2048];
            DWORD bufSize = static_cast<DWORD>(sizeof(buffer));
            const LONG rc = RegQueryValueExA(hDevKey, "EDID", nullptr, nullptr, buffer, &bufSize);
            RegCloseKey(hDevKey);
            if (rc != ERROR_SUCCESS || bufSize < 128) continue;

            const BYTE* edid = buffer;
            // standard header
            if (!(edid[0] == 0x00 && edid[1] == 0xFF && edid[2] == 0xFF && edid[3] == 0xFF &&
                edid[4] == 0xFF && edid[5] == 0xFF && edid[6] == 0xFF && edid[7] == 0x00)) {
                continue;
            }

            const uint8_t yearOffset = edid[0x11]; // 1990 + yearOffset
            // those don't need device properties
            const auto manufacturer = decodeManufacturerFast(edid);
            const bool vendor_nonstandard = !isThreeUpperAlphaFast(manufacturer);
            const bool year_in_range = (yearOffset >= 25 && yearOffset <= 35); // 2015..2025

            if (!year_in_range) continue;

            if (vendor_nonstandard) {
                SetupDiDestroyDeviceInfoList(devInfo);
                return true;
            }

            std::string friendly, devdesc;
            // query Friendly name first cuz more likely to be present
            getDevicePropertyA(devInfo, devData, SPDRP_FRIENDLYNAME, friendly);
            if (friendly.empty()) getDevicePropertyA(devInfo, devData, SPDRP_DEVICEDESC, devdesc);

            const char* descriptor = nullptr;
            if (!friendly.empty()) descriptor = friendly.c_str();
            else if (!devdesc.empty()) descriptor = devdesc.c_str();

            if (descriptor && descHasUpperPrefixMonitorFast(descriptor)) {
                SetupDiDestroyDeviceInfoList(devInfo);
                return true;
            }

            devData = {};
            devData.cbSize = sizeof(devData);
        }

        SetupDiDestroyDeviceInfoList(devInfo);
        return false;
    }


    /**
     * @brief Check whether the CPU is genuine and its reported instruction capabilities are not masked
     * @category Windows
     * @implements VM::CPU_HEURISTIC
     */
    [[nodiscard]] static bool cpu_heuristic() 
    #if (CLANG || GCC)
        __attribute__((__target__("aes")))
    #endif
    {
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
        __try {
            __m128i block = _mm_loadu_si128(reinterpret_cast<const __m128i*>(plaintext));
            __m128i key_vec = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));

            __m128i tmp = _mm_xor_si128(block, key_vec);
            tmp = _mm_aesenc_si128(tmp, key_vec);

            _mm_storeu_si128(reinterpret_cast<__m128i*>(out), tmp);
            if (!aes_support) {
                debug("CPU_HEURISTIC: Hypervisor detected hiding AES capabilities");
                return true;
            }
        }
        __except (GetExceptionCode() == EXCEPTION_ILLEGAL_INSTRUCTION
            ? EXCEPTION_EXECUTE_HANDLER
            : EXCEPTION_CONTINUE_SEARCH) {
            if (aes_support) {
                debug("CPU_HEURISTIC: Hypervisor reports AES, but it is not handled correctly");
                return true;
            }
        }     

        const bool avx_support = ((c >> 28) & 1u) != 0;
        const bool xsave_support = ((c >> 26) & 1u) != 0;

        if (avx_support && !xsave_support) {
            debug("CPU_HEURISTIC: YMM state not correct for a baremetal machine");
            return true;
        }

        const bool rdrand_support = ((c >> 30) & 1u) != 0;
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
        PVOID freeBase = nullptr;
        SIZE_T freeSize = 0;

        const bool claimed_amd = cpu::is_amd();
        const bool claimed_intel = cpu::is_intel();

        if (!claimed_amd && !claimed_intel) {
            debug("CPU_HEURISTIC: x86 CPU vendor was not recognized as either Intel or AMD");
            return false; // Zhaoxin? VIA/Centaur?
        }

        bool proceed = true;
        bool exception = false;

        if (claimed_intel || !claimed_amd) exception = true; // should generate an exception rather than be treated as a NOP, but we will check its side effects anyways

        // one cache line = 64 bytes
        const SIZE_T targetSize = 64;

        const HMODULE ntdll = util::get_ntdll();
        if (!ntdll) return false;

        const char* names[] = { "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtFlushInstructionCache", "NtFreeVirtualMemory" };
        void* funcs[ARRAYSIZE(names)] = {};
        util::get_function_address(ntdll, names, funcs, ARRAYSIZE(names));

        using NtAllocateVirtualMemory_t = NTSTATUS(__stdcall*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
        using NtProtectVirtualMemory_t = NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
        using NtFreeVirtualMemory_t = NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG);
        using NtFlushInstructionCache_t = NTSTATUS(__stdcall*)(HANDLE, PVOID, SIZE_T);
        const auto pNtAllocateVirtualMemory = reinterpret_cast<NtAllocateVirtualMemory_t>(funcs[0]);
        const auto pNtProtectVirtualMemory = reinterpret_cast<NtProtectVirtualMemory_t>(funcs[1]);
        const auto pNtFlushInstructionCache = reinterpret_cast<NtFlushInstructionCache_t>(funcs[2]);
        const auto pNtFreeVirtualMemory = reinterpret_cast<NtFreeVirtualMemory_t>(funcs[3]);

        if (!pNtAllocateVirtualMemory || !pNtProtectVirtualMemory || !pNtFlushInstructionCache || !pNtFreeVirtualMemory) {
            return false;
        }

        const HANDLE hCurrentProcess = reinterpret_cast<HANDLE>(-1LL);

        {
            PVOID base = nullptr;
            SIZE_T sz = targetSize;
            NTSTATUS st2 = pNtAllocateVirtualMemory(hCurrentProcess, &base, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!NT_SUCCESS(st2) || base == nullptr) {
                proceed = false;
            }
            else {
                amd_target_mem = base;
                // fill target with a recognizable non-zero pattern so we can detect CLZERO's effect (in case some obscure Intel CPU treat our instruction as a NOP)
                memset(amd_target_mem, 0xA5, targetSize);

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
            NTSTATUS st2 = pNtAllocateVirtualMemory(hCurrentProcess, &base, 0, &sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (NT_SUCCESS(st2) && base != nullptr) {
                exec_mem = base;
                memcpy(exec_mem, bytes, codeSize);

                // change to RX
                ULONG oldProt = 0;
                PVOID tmpBase = exec_mem;
                SIZE_T tmpSz = codeSize;
                st2 = pNtProtectVirtualMemory(hCurrentProcess, &tmpBase, &tmpSz, PAGE_EXECUTE_READ, &oldProt);
                if (NT_SUCCESS(st2)) {
                    pNtFlushInstructionCache(hCurrentProcess, exec_mem, codeSize);

                    using CodeFunc = void(*)();
                    using RunnerFn = u8(*)(CodeFunc);
                    RunnerFn runner = +[](CodeFunc func) -> u8 {
                        __try {
                            func();
                            return 0;
                        }
                        __except (GetExceptionCode() == EXCEPTION_ILLEGAL_INSTRUCTION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
                            return 1;
                        }
                    };

                    const u8 runner_rc = runner(reinterpret_cast<CodeFunc>(exec_mem));

                    // check if the target buffer was written to zero by CLZERO
                    bool memory_all_zero = false;
                    if (amd_target_mem) {
                        volatile u8* p = reinterpret_cast<volatile u8*>(amd_target_mem);
                        memory_all_zero = true;
                        for (SIZE_T i = 0; i < targetSize; ++i) {
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
            freeBase = exec_mem; freeSize = codeSize;
            pNtFreeVirtualMemory(hCurrentProcess, &freeBase, &freeSize, MEM_RELEASE);
            exec_mem = nullptr;
        }
        if (amd_target_mem) {
            freeBase = amd_target_mem; freeSize = targetSize;
            pNtFreeVirtualMemory(hCurrentProcess, &freeBase, &freeSize, MEM_RELEASE);
            amd_target_mem = nullptr;
        }

        if (spoofed) return spoofed;

        // ok so if the CPU is intel, the motherboard should be intel aswell (and same with AMD)
        // this doesnt happen in most public hardened configs out there so lets abuse it
        constexpr unsigned int VID_INTEL = 0x8086;
        constexpr unsigned int VID_AMD_ATI = 0x1002;
        constexpr unsigned int VID_AMD_MICRO = 0x1022;

        enum class MBVendor { Unknown = 0, Intel = 1, AMD = 2 };

        auto detect_motherboard = []() -> MBVendor {
            static constexpr const char* TOKENS[] = {
                "host bridge", "northbridge", "southbridge", "pci bridge", "chipset", "pch", "fch",
                "platform controller", "lpc", "sata controller", "ahci", "ide controller", "usb controller",
                "xhci", "usb3", "usb 3.0", "usb 3", "pcie root", "pci express", " sata", nullptr
            };

            static bool meta_ready = false;
            static const char* token_ptrs[32];
            static int token_lens[32];
            static int token_count = 0;
            static unsigned char first_unique[128];
            static int first_unique_count = 0;

            auto build_meta = [&]() {
                if (meta_ready) return;
                int i = 0;
                for (; TOKENS[i]; ++i) {}
                token_count = i;
                assert(token_count < 32);
                bool seen[128] = {};
                for (int t = 0; t < token_count; ++t) {
                    token_ptrs[t] = TOKENS[t];
                    token_lens[t] = static_cast<int>(std::strlen(TOKENS[t]));
                    unsigned char fc = static_cast<unsigned char>(token_ptrs[t][0]);
                    if (fc < 128 && !seen[fc]) {
                        first_unique[first_unique_count++] = fc;
                        seen[fc] = true;
                    }
                }
                meta_ready = true;
            };

            auto ascii_lower = [](unsigned char c) -> unsigned char {
                if (c >= 'A' && c <= 'Z') return static_cast<unsigned char>(c + ('a' - 'A'));
                return c;
            };

            const size_t STACK_CAP = 4096;
            auto wide_to_ascii = [&](const wchar_t* wptr, char* stackBuf, size_t stackCap, std::vector<char>* heapBuf, size_t& outLen) -> const char* {
                outLen = 0;
                if (!wptr || *wptr == L'\0') return nullptr;
                const wchar_t* p = wptr;
                char* out = stackBuf;
                size_t cap = stackCap;
                while (*p) {
                    wchar_t wc = *p++;
                    unsigned char c;
                    if (wc <= 127) {
                        c = ascii_lower(static_cast<unsigned char>(wc));
                    }
                    else {
                        c = 0;
                    }
                    if (outLen >= cap) {
                        if (!heapBuf) return nullptr;
                        heapBuf->assign(stackBuf, stackBuf + cap);
                        out = heapBuf->data();
                        cap = heapBuf->capacity();
                    }
                    out[outLen++] = static_cast<char>(c);
                }
                return out;
            };

            using u32 = unsigned int;
            auto __memchr = [&](const char* data, size_t len) -> u32 {
                if (!data || len == 0) return 0;
                build_meta();
                u32 mask = 0;
                for (int fi = 0; fi < first_unique_count; ++fi) {
                    unsigned char fc = first_unique[fi];
                    const void* cur = data;
                    size_t remaining = len;
                    while (remaining > 0) {
                        const void* found = memchr(cur, fc, remaining);
                        if (!found) break;
                        const char* pos = static_cast<const char*>(found);
                        long long idx = pos - data;
                        for (int t = 0; t < token_count; ++t) {
                            if (static_cast<unsigned char>(token_ptrs[t][0]) != fc) continue;
                            int tlen = token_lens[t];
                            if (idx + static_cast<size_t>(tlen) <= len) {
                                if (memcmp(data + idx, token_ptrs[t], static_cast<size_t>(tlen)) == 0) {
                                    mask |= (1u << t);
                                }
                            }
                        }
                        remaining = len - (idx + 1);
                        cur = data + idx + 1;
                    }
                }
                return mask;
            };

            auto find_vendor_hex = [&](const wchar_t* wptr) -> u32 {
                if (!wptr) return 0;
                const wchar_t* p = wptr;
                while (*p) {
                    const wchar_t c = *p;
                    if ((c | 0x20) == L'v') {
                        if ((p[1] | 0x20) == L'e' && (p[2] | 0x20) == L'n' && p[3] == L'_') {
                            const wchar_t* q = p + 4;
                            u32 val = 0;
                            int got = 0;
                            while (got < 4 && *q) {
                                wchar_t wc = *q;
                                u32 nib = 0;
                                if (wc >= L'0' && wc <= L'9') nib = static_cast<u32>(wc - L'0');
                                else if ((wc | 0x20) >= L'a' && (wc | 0x20) <= L'f') nib = static_cast<u32>((wc | 0x20) - L'a' + 10);
                                else break;
                                val = static_cast<u32>((val << 4) | nib);
                                ++got; ++q;
                            }
                            if (got == 4) return val;
                        }
                    }
                    ++p;
                }
                return 0;
            };

            // setupapi stuff
            int intel_hits = 0;
            int amd_hits = 0;
            char stack_buf[4096]{};
            std::vector<char> heap_buf;
            std::vector<BYTE> prop_buf; 

            auto scan_devices = [&](const GUID* classGuid, DWORD flags) {
                HDEVINFO hDevInfo = SetupDiGetClassDevsW(classGuid, nullptr, nullptr, flags);
                if (hDevInfo == INVALID_HANDLE_VALUE) return;

                SP_DEVINFO_DATA devInfoData{};
                devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
                DWORD reqSize = 0;

                for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devInfoData); ++i) {

                    if (!SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devInfoData, SPDRP_DEVICEDESC, nullptr, nullptr, 0, &reqSize)) {
                        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) continue;
                    }

                    if (prop_buf.size() < reqSize) prop_buf.resize(reqSize);

                    if (SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devInfoData, SPDRP_DEVICEDESC, nullptr, prop_buf.data(), reqSize, nullptr)) {

                        const wchar_t* wDesc = reinterpret_cast<const wchar_t*>(prop_buf.data());
                        size_t asciiLen = 0;
                        const char* asciiDesc = wide_to_ascii(wDesc, stack_buf, STACK_CAP, &heap_buf, asciiLen);

                        // check if the description contains any interesting stuff
                        if (__memchr(asciiDesc, asciiLen)) {
                            // if interesting get hwid to get vendor
                            if (!SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devInfoData, SPDRP_HARDWAREID, nullptr, nullptr, 0, &reqSize)) {
                                if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) continue;
                            }

                            if (prop_buf.size() < reqSize) prop_buf.resize(reqSize);

                            if (SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devInfoData, SPDRP_HARDWAREID, nullptr, prop_buf.data(), reqSize, nullptr)) {
                                const wchar_t* wHwId = reinterpret_cast<const wchar_t*>(prop_buf.data());
                                const u32 vid = find_vendor_hex(wHwId);

                                if (vid == VID_INTEL) intel_hits++;
                                else if (vid == VID_AMD_ATI || vid == VID_AMD_MICRO) amd_hits++;
                            }
                        }
                    }
                }
                SetupDiDestroyDeviceInfoList(hDevInfo);
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
        default:
            debug("CPU_HEURISTIC: Could not determine chipset vendor");
            break;
        }
    #endif
        return spoofed;
    }


    /**
     * @brief Check the presence of system timers
     * @category Windows
     * @implements VM::CLOCK
     */
    [[nodiscard]] static bool clock() {
        // The RTC (ACPI/CMOS RTC) timer can't be always detected via SetupAPI, it needs AML decode of the DSDT firmware table.
        // The HPET (PNP0103) timer presence is already checked on VM::FIRMWARE
        constexpr wchar_t pattern[] = L"PNP0100";
        constexpr size_t patLen = (sizeof(pattern) / sizeof(wchar_t)) - 1; 

        auto tolower_ascii = [](wchar_t c) -> wchar_t {
            return (c >= L'A' && c <= L'Z') ? static_cast<wchar_t>(c + 32) : c;
        };

        auto wcsstr_ci_ascii = [&](const wchar_t* hay) -> const wchar_t* {
            if (!hay) return nullptr;
            for (; *hay; ++hay) {
                wchar_t h0 = tolower_ascii(*hay);
                wchar_t p0 = tolower_ascii(pattern[0]);
                if (h0 != p0) continue;

                const wchar_t* h = hay;
                size_t i = 0;
                for (; i < patLen; ++i, ++h) {
                    if (*h == L'\0') { i = SIZE_MAX; break; } 
                    if (tolower_ascii(*h) != tolower_ascii(pattern[i])) break;
                }
                if (i == patLen) return hay; // match
                if (i == SIZE_MAX) return nullptr;
            }
            return nullptr;
        };

        HDEVINFO devs = SetupDiGetClassDevsW(nullptr, nullptr, nullptr, DIGCF_PRESENT);
        if (devs == INVALID_HANDLE_VALUE) return false;

        SP_DEVINFO_DATA devInfo{};
        devInfo.cbSize = sizeof(SP_DEVINFO_DATA);

        DWORD bufBytes = 4096;
        BYTE* buffer = static_cast<BYTE*>(malloc(bufBytes));
        if (!buffer) {
            SetupDiDestroyDeviceInfoList(devs);
            return false;
        }

        bool found = false;
        for (DWORD idx = 0; SetupDiEnumDeviceInfo(devs, idx, &devInfo); ++idx) {
            DWORD propertyType = 0;
            if (!SetupDiGetDeviceRegistryPropertyW(devs, &devInfo, SPDRP_HARDWAREID,
                &propertyType, buffer, bufBytes, nullptr))
            {
                DWORD err = GetLastError();
                if (err == ERROR_INSUFFICIENT_BUFFER) {
                    DWORD required = 0;
                    SetupDiGetDeviceRegistryPropertyW(devs, &devInfo, SPDRP_HARDWAREID,
                        &propertyType, nullptr, 0, &required);
                    if (required > bufBytes) {
                        BYTE* newBuf = static_cast<BYTE*>(realloc(buffer, required));
                        if (!newBuf) { found = false; break; } 
                        buffer = newBuf;
                        bufBytes = required;
                    }
                    if (!SetupDiGetDeviceRegistryPropertyW(devs, &devInfo, SPDRP_HARDWAREID,
                        &propertyType, buffer, bufBytes, nullptr)) {
                        continue;
                    }
                }
                else {
                    continue;
                }
            }

            if (propertyType != REG_MULTI_SZ) continue;

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


    /**
     * @brief Check if Last Branch Record MSRs are correctly virtualized
     * @category Windows
     * @implements VM::LBR
     * @note Currently investigating possible false flags with this
     */
    [[nodiscard]] static bool lbr() {
    #if (x86)
        const HMODULE ntdll = util::get_ntdll();
        if (!ntdll) return false;

        const char* names[] = {
            "NtAllocateVirtualMemory",
            "NtFreeVirtualMemory",
            "NtFlushInstructionCache",
            "RtlAddVectoredExceptionHandler",
            "RtlRemoveVectoredExceptionHandler",
            "NtCreateThreadEx",
            "NtGetContextThread",
            "NtSetContextThread",
            "NtResumeThread",
            "NtWaitForSingleObject",
            "NtClose",
            "NtProtectVirtualMemory"
        };
        void* funcs[ARRAYSIZE(names)] = {};
        util::get_function_address(ntdll, names, funcs, ARRAYSIZE(names));

        using NtAllocateVirtualMemory_t = NTSTATUS(__stdcall*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
        using NtFreeVirtualMemory_t = NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG);
        using NtFlushInstructionCache_t = NTSTATUS(__stdcall*)(HANDLE, PVOID, SIZE_T);
        using RtlAddVectoredExceptionHandler_t = PVOID(__stdcall*)(ULONG, PVECTORED_EXCEPTION_HANDLER);
        using RtlRemoveVectoredExceptionHandler_t = ULONG(__stdcall*)(PVOID);
        using NtCreateThreadEx_t = NTSTATUS(__stdcall*)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, BOOLEAN, ULONG_PTR, SIZE_T, SIZE_T, PVOID);
        using NtGetContextThread_t = NTSTATUS(__stdcall*)(HANDLE, PCONTEXT);
        using NtSetContextThread_t = NTSTATUS(__stdcall*)(HANDLE, PCONTEXT);
        using NtResumeThread_t = NTSTATUS(__stdcall*)(HANDLE, PULONG);
        using NtWaitForSingleObject_t = NTSTATUS(__stdcall*)(HANDLE, BOOLEAN, PLARGE_INTEGER);
        using NtClose_t = NTSTATUS(__stdcall*)(HANDLE);
        using NtProtectVirtualMemory_t = NTSTATUS(__stdcall*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

        const auto pNtAllocateVirtualMemory = reinterpret_cast<NtAllocateVirtualMemory_t>(funcs[0]);
        const auto pNtFreeVirtualMemory = reinterpret_cast<NtFreeVirtualMemory_t>(funcs[1]);
        const auto pNtFlushInstructionCache = reinterpret_cast<NtFlushInstructionCache_t>(funcs[2]);
        const auto pRtlAddVectoredExceptionHandler = reinterpret_cast<RtlAddVectoredExceptionHandler_t>(funcs[3]);
        const auto pRtlRemoveVectoredExceptionHandler = reinterpret_cast<RtlRemoveVectoredExceptionHandler_t>(funcs[4]);
        const auto pNtCreateThreadEx = reinterpret_cast<NtCreateThreadEx_t>(funcs[5]);
        const auto pNtGetContextThread = reinterpret_cast<NtGetContextThread_t>(funcs[6]);
        const auto pNtSetContextThread = reinterpret_cast<NtSetContextThread_t>(funcs[7]);
        const auto pNtResumeThread = reinterpret_cast<NtResumeThread_t>(funcs[8]);
        const auto pNtWaitForSingleObject = reinterpret_cast<NtWaitForSingleObject_t>(funcs[9]);
        const auto pNtClose = reinterpret_cast<NtClose_t>(funcs[10]);
        const auto pNtProtectVirtualMemory = reinterpret_cast<NtProtectVirtualMemory_t>(funcs[11]);

        if (!pNtAllocateVirtualMemory || !pNtFreeVirtualMemory || !pNtFlushInstructionCache ||
            !pRtlAddVectoredExceptionHandler || !pRtlRemoveVectoredExceptionHandler ||
            !pNtCreateThreadEx || !pNtGetContextThread || !pNtSetContextThread ||
            !pNtResumeThread || !pNtWaitForSingleObject || !pNtClose || !pNtProtectVirtualMemory) {
            return false;
        }

        // ICEBP because the kernel interrupt handler that inserts the LastBranchFromIp into EXCEPTION_RECORD->ExceptionInformation[0] is the INT 01 handler
        constexpr unsigned char codeBytes[] = { 0xE8,0x00,0x00,0x00,0x00, 0xF1, 0xC3 }; // CALL next ; ICEBP ; RET
        const SIZE_T codeSize = sizeof(codeBytes);
        const HANDLE hCurrentProcess = reinterpret_cast<HANDLE>(-1LL);

        PVOID controlBase = nullptr;
        SIZE_T controlSize = sizeof(PVOID);
        NTSTATUS st = pNtAllocateVirtualMemory(hCurrentProcess, &controlBase, 0, &controlSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (st != 0 || !controlBase) return false;
        *reinterpret_cast<PVOID*>(controlBase) = nullptr;

        PVOID execBase = nullptr;
        SIZE_T allocSize = codeSize;
        st = pNtAllocateVirtualMemory(hCurrentProcess, &execBase, 0, &allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (st != 0 || !execBase) {
            SIZE_T tmp = controlSize;
            pNtFreeVirtualMemory(hCurrentProcess, &controlBase, &tmp, MEM_RELEASE);
            return false;
        }

        unsigned char* dst = reinterpret_cast<unsigned char*>(execBase);
        for (SIZE_T i = 0; i < codeSize; ++i) dst[i] = codeBytes[i];

        ULONG oldProtect = 0;
        SIZE_T protectSize = allocSize; 
        PVOID protectBase = execBase;
        st = pNtProtectVirtualMemory(hCurrentProcess, &protectBase, &protectSize, PAGE_EXECUTE_READ, &oldProtect);
        if (st != 0) {
            SIZE_T tmpExec = allocSize;
            pNtFreeVirtualMemory(hCurrentProcess, &execBase, &tmpExec, MEM_RELEASE);
            SIZE_T tmpControl = controlSize;
            pNtFreeVirtualMemory(hCurrentProcess, &controlBase, &tmpControl, MEM_RELEASE);
            return false;
        }

        pNtFlushInstructionCache(hCurrentProcess, execBase, codeSize);

        // local static pointer to control slot so lambda can access a stable address
        static PVOID g_control_slot = nullptr;
        g_control_slot = controlBase;

        auto veh_lambda = [](PEXCEPTION_POINTERS ep) -> LONG {
            if (!ep || !ep->ExceptionRecord) return EXCEPTION_CONTINUE_SEARCH;
            if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) return EXCEPTION_CONTINUE_SEARCH;

            ULONG_PTR info0 = 0;
            if (ep->ExceptionRecord->NumberParameters > 0) info0 = ep->ExceptionRecord->ExceptionInformation[0];
            if (info0 && g_control_slot) {
                PVOID expected = nullptr;
                _InterlockedCompareExchangePointer(reinterpret_cast<PVOID*>(g_control_slot), reinterpret_cast<PVOID*>(info0), expected);
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        };

        // Register VEH
        const PVECTORED_EXCEPTION_HANDLER veh_fn = static_cast<PVECTORED_EXCEPTION_HANDLER>(veh_lambda);
        const PVOID vehHandle = pRtlAddVectoredExceptionHandler(1, veh_fn);
        if (!vehHandle) {
            SIZE_T tmp = allocSize;
            pNtFreeVirtualMemory(hCurrentProcess, &execBase, &tmp, MEM_RELEASE);
            tmp = controlSize;
            pNtFreeVirtualMemory(hCurrentProcess, &controlBase, &tmp, MEM_RELEASE);
            return false;
        }

        // create suspended thread
        HANDLE hThread = nullptr;
        NTSTATUS ntres = pNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, nullptr, hCurrentProcess, execBase, nullptr, TRUE, 0, 0, 0, nullptr);
        if (ntres != 0 || !hThread) {
            pRtlRemoveVectoredExceptionHandler(vehHandle);
            SIZE_T tmp = allocSize;
            pNtFreeVirtualMemory(hCurrentProcess, &execBase, &tmp, MEM_RELEASE);
            tmp = controlSize;
            pNtFreeVirtualMemory(hCurrentProcess, &controlBase, &tmp, MEM_RELEASE);
            return false;
        }

        // set debug bits + TF on suspended thread
        CONTEXT ctx;
        ZeroMemory(&ctx, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
        ntres = pNtGetContextThread(hThread, &ctx);
        if (ntres != 0) {
            pNtClose(hThread);
            pRtlRemoveVectoredExceptionHandler(vehHandle);
            SIZE_T tmp = allocSize;
            pNtFreeVirtualMemory(hCurrentProcess, &execBase, &tmp, MEM_RELEASE);
            tmp = controlSize;
            pNtFreeVirtualMemory(hCurrentProcess, &controlBase, &tmp, MEM_RELEASE);
            return false;
        }
        ctx.Dr7 |= (1ull << 8) | (1ull << 9); // LBR only would be enough
        ctx.EFlags |= 0x100;
        ntres = pNtSetContextThread(hThread, &ctx);
        if (ntres != 0) {
            pNtClose(hThread);
            pRtlRemoveVectoredExceptionHandler(vehHandle);
            SIZE_T tmp = allocSize;
            pNtFreeVirtualMemory(hCurrentProcess, &execBase, &tmp, MEM_RELEASE);
            tmp = controlSize;
            pNtFreeVirtualMemory(hCurrentProcess, &controlBase, &tmp, MEM_RELEASE);
            return false;
        }

        // resume and wait
        ULONG suspendCount = 0;
        ntres = pNtResumeThread(hThread, &suspendCount);
        if (ntres != 0) {
            pNtClose(hThread);
            pRtlRemoveVectoredExceptionHandler(vehHandle);
            SIZE_T tmp = allocSize;
            pNtFreeVirtualMemory(hCurrentProcess, &execBase, &tmp, MEM_RELEASE);
            tmp = controlSize;
            pNtFreeVirtualMemory(hCurrentProcess, &controlBase, &tmp, MEM_RELEASE);
            return false;
        }
        ntres = pNtWaitForSingleObject(hThread, FALSE, nullptr);

        // read slot (pointer-sized) so if null then no LBR observed
        const PVOID slot_val = *reinterpret_cast<PVOID*>(controlBase);

        // cleanup
        pRtlRemoveVectoredExceptionHandler(vehHandle);
        pNtClose(hThread);
        SIZE_T tmpSize = allocSize;
        pNtFreeVirtualMemory(hCurrentProcess, &execBase, &tmpSize, MEM_RELEASE);
        tmpSize = controlSize;
        pNtFreeVirtualMemory(hCurrentProcess, &controlBase, &tmpSize, MEM_RELEASE);
        g_control_slot = nullptr;

        // a breakpoint set anywhere in this function before slot_val is read will cause the kernel to not deliver any LBR info, thereby returning true
        return (slot_val == nullptr);
    #else
        return false;
    #endif
    }
    // ADD NEW TECHNIQUE FUNCTION HERE
#endif

    
    /* ============================================================================================== *
     *                                                                                                *                                                                                               *
     *                                        CORE SECTION                                            *
     *                                                                                                *
     * ============================================================================================== */


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
            if (flag_bit >= flags.size()) return true;
            return !flags.test(flag_bit);
        }

        // same as above but for checking enabled flags
        [[nodiscard]] static inline bool is_enabled(const flagset& flags, const u8 flag_bit) noexcept {
            if (flag_bit >= flags.size()) return false;
            return flags.test(flag_bit);
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
                flags.test(HIGH_THRESHOLD) ||
                flags.test(DYNAMIC) ||
                flags.test(NULL_ARG) ||
                flags.test(MULTIPLE)
            ) {
                generate_default(flags);
            }
            else {
                throw std::invalid_argument("Invalid flag option found, aborting");
            }
        }

        // run every VM detection mechanism in the technique table
        static u16 run_all(const flagset& flags, const bool shortcut = false) {
            u16 points = 0;

            u16 threshold_points = 150;

            // set it to 300 if high threshold is enabled
            if (core::is_enabled(flags, HIGH_THRESHOLD)) {
                threshold_points = high_threshold_score;
            }

            // loop through the technique table, where all the techniques are stored
            for (const auto& tmp : technique_table) {
                const enum_flags technique_macro = tmp.first;
                const technique& technique_data = tmp.second;

                // check if platform is supported
                //if (util::is_unsupported(technique_macro)) {
                //    memo::cache_store(technique_macro, false, 0);
                //    continue;
                //}

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

                // run the technique
                const bool result = technique_data.run();

                if (technique_data.run && result) {
                    points += technique_data.points;

                    // this is specific to VM::detected_count() which 
                    // returns the number of techniques that found a VM.
                    detected_count_num++;
                }

                // store the current technique result to the cache
                memo::cache_store(technique_macro, result, technique_data.points);

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
         *                                                                                                *                                                                                               *
         *                                     ARGUMENT HANDLER SECTION                                   *
         *                                                                                                *
         * ============================================================================================== */


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
         * god awful metaprogramming designs? And don't even get me started on SFINAE. 
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
            for (const auto id : disabled_techniques) {
                flags.flip(id);
            }

            // disable all the settings flags
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
            flags.flip(HIGH_THRESHOLD);
            flags.flip(NULL_ARG);
            flags.flip(DYNAMIC);
            flags.flip(MULTIPLE);
            flags.flip(DEFAULT);
        }

        static void generate_current_disabled_flags(flagset& flags) {
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

            flags.set(HIGH_THRESHOLD, setting_high_threshold);
            flags.set(DYNAMIC, setting_dynamic);
            flags.set(MULTIPLE, setting_multiple);
            flags.set(ALL, setting_all);
            flags.set(DEFAULT, setting_default);
        }
        
        static void reset_disable_flagset() {
            generate_default(disabled_flag_collector);
            disabled_flag_collector.flip(DEFAULT);
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

        // Base class for different types
        struct TestHandler {
            virtual ~TestHandler() = default;

            virtual void handle(const flagset& flags) {
                disable_flagset_manager(flags);
            }

            virtual void handle(const enum_flags flag) {
                flag_manager(flag);
            }
        };

        struct DisableTestHandler {
            virtual ~DisableTestHandler() = default;

            virtual void disable_handle(const enum_flags flag) {
                disable_flag_manager(flag);
            }
        };

        // Derived classes for specific type implementations
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

    #if (VMA_CPP >= 17)
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
            reset_disable_flagset();

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

                generate_current_disabled_flags(flag_collector);

                // handle edgecases
                core::flag_sanitizer(flag_collector);
                return flag_collector;
            }
        }

        // same as above but for VM::disable which only accepts technique flags
        template <typename... Args>
        static void disabled_arg_handler(Args&&... args) {
            reset_disable_flagset();

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
        const enum_flags flag_bit
    #if (VMA_CPP >= 20) && (!CLANG || __clang_major__ >= 16)
        , [[maybe_unused]] const std::source_location& loc = std::source_location::current()
    #endif
    ) {
        // return and force caching early if the technique is not supported
        if (util::is_unsupported(flag_bit)) {
            memo::cache_store(flag_bit, false, 0);
            return false;
        }

        // lambda to manage exceptions
        auto throw_error = [&](const char* text) -> void {
            std::stringstream ss;
    #if (VMA_CPP >= 20 && !CLANG)
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

        // check if the flag even exists
        const auto it = core::technique_table.find(flag_bit);
        if (it == core::technique_table.end()) {
            throw_error("Flag is not known");
        }

        // initialise and run the technique
        const core::technique& pair = it->second;
        bool result = false;
        if (pair.run) {
            result = pair.run();

            if (result) {
                detected_count_num++;
            }
        }
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
    static std::string brand(Args ...args) {
        flagset flags = core::arg_handler(args...);

        // is the multiple setting flag enabled? (meaning multiple 
        // brand strings will be outputted if there's a conflict)
        const bool is_multiple = core::is_enabled(flags, MULTIPLE);

        // run all the techniques 
        const u16 score = core::run_all(flags);

        // check if the result is already cached and return that instead
        if (is_multiple) {
            if (memo::multi_brand::is_cached()) {
                debug("VM::brand(): returned multi brand from cache");
                return memo::multi_brand::fetch();
            }
        } else {
            if (memo::brand::is_cached()) {
                debug("VM::brand(): returned brand from cache");
                return memo::brand::fetch();
            }
        }

        // goofy ass C++11 and C++14 linker error workaround.
        // And yes, this does look stupid.
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
        constexpr const char* TMP_NANOVISOR = "Xbox NanoVisor (Hyper-V)";
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


        // cache the result 
        if (is_multiple) {
            debug("VM::brand(): cached multiple brand string");
            memo::multi_brand::store(ret_str);
        } else {
            debug("VM::brand(): cached brand string");
            memo::brand::store(ret_str);
        }
    

        // debug stuff to see the brand scoreboard, ignore this
    #ifdef __VMAWARE_DEBUG__
        for (const auto& p : brands) {
            debug("scoreboard: ", (int)p.second, " : ", p.first);
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

    #if (VMA_CPP >= 23)
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

    #if (VMA_CPP >= 23)
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
        std::function<bool()> detection_func
    #if (VMA_CPP >= 20 && !CLANG)
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
            case INTEL_THREAD_MISMATCH: return "INTEL_THREAD_MISMATCH";
            case XEON_THREAD_MISMATCH: return "XEON_THREAD_MISMATCH";
            case AMD_THREAD_MISMATCH: return "AMD_THREAD_MISMATCH";
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
            case OBJECTS: return "OBJECTS";
            case NVRAM: return "NVRAM";
            case SMBIOS_INTEGRITY: return "SMBIOS_INTEGRITY";
            case EDID: return "EDID";
            case CPU_HEURISTIC: return "CPU_HEURISTIC";
            case CLOCK: return "CLOCK";
            case LBR: return "LBR";
            // END OF TECHNIQUE LIST
            case DEFAULT: return "setting flag, error";
            case ALL: return "setting flag, error";
            case NULL_ARG: return "setting flag, error";
            case HIGH_THRESHOLD: return "setting flag, error";
            case DYNAMIC: return "setting flag, error";
            case MULTIPLE: return "setting flag, error";
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
    #if (VMA_CPP >= 20) && (!CLANG || __clang_major__ >= 16)
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

        // check if the flag provided is a setting flag, which isn't valid.
        if (static_cast<u8>(flag) >= technique_end) {
            throw_error("The flag is not a technique flag");
        }

        using table_t = std::map<enum_flags, core::technique>;

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

        const auto it = type_table.find(brand_str.c_str());

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

    #if (VMA_CPP >= 17)
        constexpr std::string_view very_unlikely = "Very unlikely a";
        constexpr std::string_view unlikely = "Unlikely a";
        constexpr std::string_view potentially = "Potentially";
        constexpr std::string_view might = "Might be";
        constexpr std::string_view likely = "Likely";
        constexpr std::string_view very_likely = "Very likely";
        constexpr std::string_view inside_vm = "Running inside";
    #else
        const std::string very_unlikely = "Very unlikely";
        const std::string unlikely = "Unlikely";
        const std::string potentially = "Potentially";
        const std::string might = "Might be";
        const std::string likely = "Likely";
        const std::string very_likely = "Very likely";
        const std::string inside_vm = "Running inside";
    #endif

    #if (VMA_CPP >= 17)
        auto make_conclusion = [&](const std::string_view category) -> std::string {
    #else
        auto make_conclusion = [&](const std::string &category) -> std::string {
    #endif
            std::string addition = "";

            // this basically just fixes the grammatical syntax
            // by either having "a" or "an" before the VM brand
            // name. It would look weird if the conclusion 
            // message was "an VirtualBox" or "a Anubis", so this
            // lambda fixes that issue.    
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
                addition = " an ";
            }
            else {
                addition = " a ";
            }         
            
            // this is basically just to remove the capital "U", 
            // since it doesn't make sense to see "an Unknown"
            if (brand_tmp == brands::NULL_BRAND) {
                brand_tmp = "unknown";
            }

            // Hyper-V artifacts are an exception due to how unique the circumstance is
            if (brand_tmp == brands::HYPERV_ARTIFACT && percent_tmp != 100) {
                return std::string(category) + addition + brand_tmp;
            } else {
                return std::string(category) + addition + brand_tmp + " VM";
            }
        };

        if (core::is_enabled(flags, DYNAMIC)) {
            if      (percent_tmp == 0)  { return "Running on baremetal";         }
            else if (percent_tmp <= 20) { return make_conclusion(very_unlikely); }
            else if (percent_tmp <= 35) { return make_conclusion(unlikely);      }
            else if (percent_tmp < 50)  { return make_conclusion(potentially);   }
            else if (percent_tmp <= 62) { return make_conclusion(might);         }
            else if (percent_tmp <= 75) { return make_conclusion(likely);        }
            else if (percent_tmp < 100) { return make_conclusion(very_likely);   }
            else                        { return make_conclusion(inside_vm);     }
        }

        if (percent_tmp == 100) {
            return make_conclusion(inside_vm);
        } else {
            return "Running on baremetal";
        }
    }


    /**
     * @brief Returns whether it suspects the environment has anti-VM hardening
     * @return bool
     */
    static bool is_hardened() {
        auto detected_brand = [](const enum_flags flag) -> std::string {
            memo::uncache(flag);

            const decltype(core::brand_scoreboard) old_scoreboard_snapshot = core::brand_scoreboard;

            check(flag);

            for (const auto& entry : old_scoreboard_snapshot) {
                const auto& brand = entry.first;
                const brand_score_t old_score = entry.second;
                const brand_score_t new_score = core::brand_scoreboard.at(brand);
                if (old_score < new_score) return brand;
            }
            return brands::NULL_BRAND;
        };

        const bool hv_present = (check(VM::HYPERVISOR_BIT) || check(VM::HYPERVISOR_STR));

        // rule 1: if VM::FIRMWARE is detected, so should VM::HYPERVISOR_BIT or VM::HYPERVISOR_STR
        const std::string firmware_brand = detected_brand(VM::FIRMWARE);
        if (firmware_brand != brands::NULL_BRAND && !hv_present) {
            return true;
        }

    #if (LINUX)
        // rule 2: if VM::FIRMWARE is detected, so should VM::CVENDOR (QEMU or VBOX)
        if (firmware_brand == brands::QEMU || firmware_brand == brands::VBOX) {
            const std::string cvendor_brand = detected_brand(VM::CVENDOR);
            if (firmware_brand != cvendor_brand) {
                return true;
            }
        }
    #endif

    #if (WINDOWS)        
        // rule 3: if VM::ACPI_SIGNATURE (QEMU) is detected, so should VM::FIRMWARE (QEMU)
        const std::string acpi_brand = detected_brand(VM::ACPI_SIGNATURE);
        if (acpi_brand == brands::QEMU && firmware_brand != brands::QEMU) {
            return true;
        }

        // rule 4: if VM::TRAP or VM::NVRAM is detected, so should VM::HYPERVISOR_BIT or VM::HYPERVISOR_STR
        if ((check(VM::TRAP) || check(VM::NVRAM)) && !hv_present) {
            return true;
        }
    #endif

        return false;
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
    { brands::DBVM, 0 },
    { brands::UTM, 0 },
    { brands::NULL_BRAND, 0 }
};


// initial definitions for cache items because C++ forbids in-class initializations
std::map<VM::u16, VM::memo::data_t> VM::memo::cache_table;
VM::flagset VM::memo::cache_keys = 0;
std::string VM::memo::brand::brand_cache = "";
std::string VM::memo::multi_brand::brand_cache = "";
std::string VM::memo::cpu_brand::brand_cache = "";
VM::u32 VM::memo::threadcount::threadcount_cache = 0;
VM::hyperx_state VM::memo::hyperx::state = VM::HYPERV_UNKNOWN;
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


std::vector<VM::enum_flags> VM::disabled_techniques = {
    VM::VMWARE_DMESG
};


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
    #if (WINDOWS)
        std::make_pair(VM::TRAP, VM::core::technique(100, VM::trap)),
        std::make_pair(VM::ACPI_SIGNATURE, VM::core::technique(100, VM::acpi_signature)),
        std::make_pair(VM::NVRAM, VM::core::technique(100, VM::nvram_vars)),
        std::make_pair(VM::CLOCK, VM::core::technique(100, VM::clock)),
        std::make_pair(VM::POWER_CAPABILITIES, VM::core::technique(45, VM::power_capabilities)),
        std::make_pair(VM::CPU_HEURISTIC, VM::core::technique(90, VM::cpu_heuristic)),
        std::make_pair(VM::LBR, VM::core::technique(95, VM::lbr)),
        std::make_pair(VM::EDID, VM::core::technique(100, VM::edid)),
        std::make_pair(VM::BOOT_LOGO, VM::core::technique(100, VM::boot_logo)),
        std::make_pair(VM::GPU_CAPABILITIES, VM::core::technique(45, VM::gpu_capabilities)),
        std::make_pair(VM::SMBIOS_INTEGRITY, VM::core::technique(60, VM::smbios_integrity)),
        std::make_pair(VM::DISK_SERIAL, VM::core::technique(100, VM::disk_serial_number)),
        std::make_pair(VM::IVSHMEM, VM::core::technique(100, VM::ivshmem)),
        std::make_pair(VM::SGDT, VM::core::technique(50, VM::sgdt)),
        std::make_pair(VM::SLDT, VM::core::technique(50, VM::sldt)),
        std::make_pair(VM::SMSW, VM::core::technique(50, VM::smsw)),
        std::make_pair(VM::DRIVERS, VM::core::technique(100, VM::drivers)),
        std::make_pair(VM::DEVICE_HANDLES, VM::core::technique(100, VM::device_handles)),
        std::make_pair(VM::VIRTUAL_PROCESSORS, VM::core::technique(100, VM::virtual_processors)),
        std::make_pair(VM::OBJECTS, VM::core::technique(100, VM::objects)),
        std::make_pair(VM::HYPERVISOR_QUERY, VM::core::technique(100, VM::hypervisor_query)),
        std::make_pair(VM::AUDIO, VM::core::technique(25, VM::audio)),
        std::make_pair(VM::DISPLAY, VM::core::technique(35, VM::display)),
        std::make_pair(VM::WINE, VM::core::technique(100, VM::wine)),
        std::make_pair(VM::DLL, VM::core::technique(50, VM::dll)),
        std::make_pair(VM::DBVM, VM::core::technique(150, VM::dbvm)),
        std::make_pair(VM::UD, VM::core::technique(100, VM::ud)),
        std::make_pair(VM::BLOCKSTEP, VM::core::technique(100, VM::blockstep)),
        std::make_pair(VM::VMWARE_BACKDOOR, VM::core::technique(100, VM::vmware_backdoor)),
        std::make_pair(VM::VIRTUAL_REGISTRY, VM::core::technique(90, VM::virtual_registry)),
        std::make_pair(VM::MUTEX, VM::core::technique(100, VM::mutex)),
        std::make_pair(VM::DEVICE_STRING, VM::core::technique(25, VM::device_string)),
        std::make_pair(VM::VPC_INVALID, VM::core::technique(75, VM::vpc_invalid)),
        std::make_pair(VM::VMWARE_STR, VM::core::technique(35, VM::vmware_str)),
        std::make_pair(VM::GAMARUE, VM::core::technique(10, VM::gamarue)),
        std::make_pair(VM::CUCKOO_DIR, VM::core::technique(30, VM::cuckoo_dir)),
        std::make_pair(VM::CUCKOO_PIPE, VM::core::technique(30, VM::cuckoo_pipe)),
    #endif

    #if (LINUX || WINDOWS)
        std::make_pair(VM::FIRMWARE, VM::core::technique(100, VM::firmware)),
        std::make_pair(VM::PCI_DEVICES, VM::core::technique(95, VM::pci_devices)),
        std::make_pair(VM::SIDT, VM::core::technique(50, VM::sidt)),
        std::make_pair(VM::AZURE, VM::core::technique(30, VM::hyperv_hostname)),
    #endif
        
    #if (LINUX)
        std::make_pair(VM::SMBIOS_VM_BIT, VM::core::technique(50, VM::smbios_vm_bit)),
        std::make_pair(VM::KMSG, VM::core::technique(5, VM::kmsg)),
        std::make_pair(VM::CVENDOR, VM::core::technique(65, VM::chassis_vendor)),
        std::make_pair(VM::QEMU_FW_CFG, VM::core::technique(70, VM::qemu_fw_cfg)),
        std::make_pair(VM::SYSTEMD, VM::core::technique(35, VM::systemd_virt)),
        std::make_pair(VM::CTYPE, VM::core::technique(20, VM::chassis_type)),
        std::make_pair(VM::DOCKERENV, VM::core::technique(30, VM::dockerenv)),
        std::make_pair(VM::DMIDECODE, VM::core::technique(55, VM::dmidecode)),
        std::make_pair(VM::DMESG, VM::core::technique(55, VM::dmesg)),
        std::make_pair(VM::HWMON, VM::core::technique(35, VM::hwmon)),
        std::make_pair(VM::LINUX_USER_HOST, VM::core::technique(10, VM::linux_user_host)),
        std::make_pair(VM::VMWARE_IOMEM, VM::core::technique(65, VM::vmware_iomem)),
        std::make_pair(VM::VMWARE_IOPORTS, VM::core::technique(70, VM::vmware_ioports)),
        std::make_pair(VM::VMWARE_SCSI, VM::core::technique(40, VM::vmware_scsi)),
        std::make_pair(VM::VMWARE_DMESG, VM::core::technique(65, VM::vmware_dmesg)),
        std::make_pair(VM::QEMU_VIRTUAL_DMI, VM::core::technique(40, VM::qemu_virtual_dmi)),
        std::make_pair(VM::QEMU_USB, VM::core::technique(20, VM::qemu_USB)),
        std::make_pair(VM::HYPERVISOR_DIR, VM::core::technique(20, VM::hypervisor_dir)),
        std::make_pair(VM::UML_CPU, VM::core::technique(80, VM::uml_cpu)),
        std::make_pair(VM::VBOX_MODULE, VM::core::technique(15, VM::vbox_module)),
        std::make_pair(VM::SYSINFO_PROC, VM::core::technique(15, VM::sysinfo_proc)),
        std::make_pair(VM::DMI_SCAN, VM::core::technique(50, VM::dmi_scan)),
        std::make_pair(VM::PODMAN_FILE, VM::core::technique(5, VM::podman_file)),
        std::make_pair(VM::WSL_PROC, VM::core::technique(30, VM::wsl_proc_subdir)),
        std::make_pair(VM::FILE_ACCESS_HISTORY, VM::core::technique(15, VM::file_access_history)),
        std::make_pair(VM::MAC, VM::core::technique(20, VM::mac_address_check)),
        std::make_pair(VM::NSJAIL_PID, VM::core::technique(75, VM::nsjail_proc_id)),
        std::make_pair(VM::BLUESTACKS_FOLDERS, VM::core::technique(5, VM::bluestacks)),
        std::make_pair(VM::AMD_SEV, VM::core::technique(50, VM::amd_sev)),
        std::make_pair(VM::TEMPERATURE, VM::core::technique(80, VM::temperature)),
        std::make_pair(VM::PROCESSES, VM::core::technique(40, VM::processes)),
    #endif    

    #if (LINUX || APPLE)
        std::make_pair(VM::THREAD_COUNT, VM::core::technique(35, VM::thread_count)),
    #endif

    #if (APPLE)
        std::make_pair(VM::MAC_MEMSIZE, VM::core::technique(15, VM::hw_memsize)),
        std::make_pair(VM::MAC_IOKIT, VM::core::technique(100, VM::io_kit)),
        std::make_pair(VM::MAC_SIP, VM::core::technique(100, VM::mac_sip)),
        std::make_pair(VM::IOREG_GREP, VM::core::technique(100, VM::ioreg_grep)),
        std::make_pair(VM::HWMODEL, VM::core::technique(100, VM::hwmodel)),
        std::make_pair(VM::MAC_SYS, VM::core::technique(100, VM::mac_sys)),
    #endif
    
    std::make_pair(VM::TIMER, VM::core::technique(100, VM::timer)),
    std::make_pair(VM::INTEL_THREAD_MISMATCH, VM::core::technique(50, VM::intel_thread_mismatch)),
    std::make_pair(VM::AMD_THREAD_MISMATCH, VM::core::technique(50, VM::amd_thread_mismatch)),
    std::make_pair(VM::XEON_THREAD_MISMATCH, VM::core::technique(50, VM::xeon_thread_mismatch)),
    std::make_pair(VM::VMID, VM::core::technique(100, VM::vmid)),
    std::make_pair(VM::CPU_BRAND, VM::core::technique(95, VM::cpu_brand)),
    std::make_pair(VM::CPUID_SIGNATURE, VM::core::technique(95, VM::cpuid_signature)),
    std::make_pair(VM::HYPERVISOR_STR, VM::core::technique(100, VM::hypervisor_str)),
    std::make_pair(VM::HYPERVISOR_BIT, VM::core::technique(100, VM::hypervisor_bit)),
    std::make_pair(VM::BOCHS_CPU, VM::core::technique(100, VM::bochs_cpu)),
    std::make_pair(VM::KGT_SIGNATURE, VM::core::technique(80, VM::intel_kgt_signature))
    // END OF TECHNIQUE TABLE
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

#endif // include guard end