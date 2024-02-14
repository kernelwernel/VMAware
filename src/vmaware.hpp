/**
 * ██╗   ██╗███╗   ███╗ █████╗ ██╗    ██╗ █████╗ ██████╗ ███████╗
 * ██║   ██║████╗ ████║██╔══██╗██║    ██║██╔══██╗██╔══██╗██╔════╝
 * ██║   ██║██╔████╔██║███████║██║ █╗ ██║███████║██████╔╝█████╗
 * ╚██╗ ██╔╝██║╚██╔╝██║██╔══██║██║███╗██║██╔══██║██╔══██╗██╔══╝
 *  ╚████╔╝ ██║ ╚═╝ ██║██║  ██║╚███╔███╔╝██║  ██║██║  ██║███████╗
 *   ╚═══╝  ╚═╝     ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ 1.0 version
 *
 *  A C++ VM detection library
 *
 *  - Made by: @kernelwernel (https://github.com/kernelwernel)
 *  - Contributed by:
 *      - @Requiem (https://github.com/NotRequiem)
 *      - @Alex (https://github.com/greenozon)
 *  - Repository: https://github.com/kernelwernel/VMAware
 *  - Docs: https://github.com/kernelwernel/VMAware/docs/documentation.md
 *  - Full credits: https://github.com/kernelwernel/VMAware#credits
 *  - License: GPL-3.0
 * 
 * 
 * ================================= SECTIONS ================================== 
 * - enums for publicly accessible techniques  => line 181
 * - struct for internal cpu operations        => line 320
 * - struct for internal memoization           => line 553
 * - struct for internal utility functions     => line 626
 * - start of internal VM detection techniques => line 1192
 * - start of public VM detection functions    => line 4403
 * - start of externally defined variables     => line 4654
 */

#pragma once

#if (defined(_MSC_VER) || defined(_WIN32) || defined(_WIN64) || defined(__MINGW32__))
#define MSVC 1
#define LINUX 0
#define APPLE 0
#elif (defined(__GNUC__) || defined(__linux__))
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
#if __cplusplus == 202302L
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
#else
#define CPP 0
#ifdef __VMAWARE_DEBUG__
#pragma message("using pre C++11 :(")
#endif
#endif

#if (CPP < 11 && !MSVC)
#error "VMAware only supports C++11 or above, set your compiler flag to '-std=c++20' for GCC/clang, or '/std:c++20' for MSVC"
#endif

#if (defined(__x86_64__) || defined(__i386__) || defined(_M_IX86) || defined(_M_X64))
#define x86 1
#else
#define x86 0
#endif

#if !(defined(MSVC) || defined(LINUX) || defined(APPLE))
#warning "Unknown OS detected, tests will be severely limited"
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
#include <limits>
#include <cstdint>
#include <map>
#include <array>
#include <algorithm>
#include <iostream>
#include <cassert>
#include <cmath>
#include <sstream>
#include <bitset>

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
#include <tlhelp32.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <shlwapi.h>
#include <shlobj_core.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "MPR")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#elif (LINUX)
#include <cpuid.h>
#include <x86intrin.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <net/if.h> 
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <immintrin.h>
#include <memory>
#elif (APPLE)
#include <sys/types.h>
#include <sys/sysctl.h>
#endif

#if (MSVC)
#pragma warning(pop) 
#endif

// macro shortcut to disable MSVC warnings
#if (MSVC)
#define MSVC_DISABLE_WARNING(...) __pragma(warning(disable : __VA_ARGS__))
#define MSVC_ENABLE_WARNING(...) __pragma(warning(default : __VA_ARGS__))
#else
#define MSVC_DISABLE_WARNING(...)
#define MSVC_ENABLE_WARNING(...)
#endif

MSVC_DISABLE_WARNING(4626 4514)

#ifdef __VMAWARE_DEBUG__
#define debug(...) VM::util::debug_msg(__VA_ARGS__)
#else
#define debug(...)
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

    static constexpr auto enum_line_start = __LINE__; // hacky way to fetch enum size
public:
    enum enum_flags : u8 {
        VMID = 1,
        BRAND,
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
        SUNBELT_VM,
        WINE_CHECK,
        VM_FILES,
        HWMODEL,
        DISK_SIZE,
        VBOX_DEFAULT,
        VBOX_NETWORK,
        COMPUTER_NAME,
        HOSTNAME,
        MEMORY,
        VM_PROCESSES,
        LINUX_USER_HOST,
        VBOX_WINDOW_CLASS,
        GAMARUE,
        WMIC,
        VMID_0X4,
        PARALLELS_VM,
        RDTSC_VMEXIT,
        LOADED_DLLS,
        QEMU_BRAND,
        BOCHS_CPU,
        VPC_BOARD,
        HYPERV_WMI,
        HYPERV_REG,
        BIOS_SERIAL,
        VBOX_FOLDERS,
        VBOX_MSSMBIOS,
        MAC_HYPERTHREAD,
        MAC_MEMSIZE,
        MAC_IOKIT,
        IOREG_GREP,
        MAC_SIP,
        KVM_REG,
        KVM_DRIVERS,
        KVM_DIRS,
        EXTREME,
        NO_MEMO
    };
private:
    static constexpr u8 enum_size = __LINE__ - enum_line_start - 4; // get enum size

public:
    // this will allow the enum to be used in the public interface as "VM::TECHNIQUE"
    enum enum_flags tmp_ignore_this = NO_MEMO;

    // constructor shit ignore this
    VM() = delete;
    VM(const VM&) = delete;
    VM(VM&&) = delete;

private:
    // for the bitset
    using flagset = std::bitset<enum_size>;

    // global values
    static flagset DEFAULT; // default bitset that will be run if no parameters are specified
    static flagset flags; // global flags
    static bool cpuid_supported; // cpuid check value
    
    // VM scoreboard table specifically for VM::brand()
#if (MSVC)
    static std::map<const char*, int> scoreboard;
#else
    static std::map<const char*, u8> scoreboard;
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
    static constexpr const char* COMODO = "Comodo";
    static constexpr const char* SUNBELT = "SunBelt";
    static constexpr const char* BOCHS = "Bochs";

    // macro for bypassing unused parameter warnings
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
        };

        // same as above but for array type parameters (MSVC specific)
        static void cpuid
        (
            int32_t x[4],
            const u32 a_leaf,
            const u32 c_leaf = 0xFF
        ) {
            // may be unmodified for older 32-bit processors, clearing just in case
            x[1] = 0;
            x[2] = 0;
#if (MSVC)
            __cpuidex((int32_t*)x, static_cast<int>(a_leaf), static_cast<int>(c_leaf));
#elif (LINUX)
            __cpuid_count(a_leaf, c_leaf, x[0], x[1], x[2], x[3]);
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

        // self-explanatory
        [[nodiscard]] static std::string get_brand() {
            if (!cpuid_supported) {
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

            return brand;
#endif
        }

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
                kvm = "KVMKVMKVM\0\0\0",
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
            constexpr std::array<std::string_view, 13> IDs{
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
                u32 x[4]{};
                cpu::cpuid(x[0], x[1], x[2], x[3], p_leaf);

                for (; start < end; start++) { 
                    *regs++ = x[start];
                }

                return true;
            };

            std::string brand = "";
            u32 sig_reg[3] = {0};

            if (!cpuid_thingy(p_leaf, sig_reg, 1)) {
                return false;
            }

            auto strconvert = [](u64 n) -> std::string {
                const std::string& str(reinterpret_cast<char*>(&n));
                return str;
            };

            std::stringstream ss;
            ss << strconvert(sig_reg[0]);
            ss << strconvert(sig_reg[2]);
            ss << strconvert(sig_reg[1]);

            brand = ss.str();

#ifdef __VMAWARE_DEBUG__
            debug(technique_name, brand);
#else
#if (CPP < 17)
            // bypass compiler warning about unused parameter, ignore this
            UNUSED(technique_name);
#endif
#endif

            const bool found = (std::find(std::begin(IDs), std::end(IDs), brand) != std::end(IDs));

            if (found) {
                if (brand == qemu) { return util::add(QEMU); }
                if (brand == vmware) { return util::add(VMWARE); }
                if (brand == vbox) { return util::add(VBOX); }
                if (brand == bhyve) { return util::add(BHYVE); }
                if (brand == kvm) { return util::add(KVM); }
                if (brand == hyperv) { return util::add(HYPERV); }
                if (brand == xta) { return util::add(MSXTA); }
                if (brand == parallels) { return util::add(PARALLELS); }
                if (brand == parallels2) { return util::add(PARALLELS); }
                if (brand == xen) { return util::add(XEN); }
                if (brand == acrn) { return util::add(ACRN); }
                if (brand == qnx) { return util::add(QNX); }
                if (brand == virtapple) { return util::add(VAPPLE); }
            }

            /**
             * This is added because there are inconsistent string 
             * values for KVM's manufacturer ID. For example, 
             * it gives as "KVMKMVMKV" when I run it under QEMU
             * but the Wikipedia article on CPUID says it's 
             * "KVMKVMKVM\0\0\0", like wtf????
             */
            if (brand.find("KVM") != std::string::npos) {
                return util::add(KVM);
            }

            return false;
        }
    };

    // memoization
    struct memo {
    private:
        // memoization structure
        MSVC_DISABLE_WARNING(4820)
        struct memo_struct {
            std::string get_brand;
            u8 get_percent;
            bool get_vm;

            // Default constructor
            memo_struct() : get_brand("Unknown"), get_percent(0), get_vm(false) {}

            // Constructor to initialize the members
            memo_struct(const std::string& brand, u8 percent, bool is_vm)
                : get_brand(brand), get_percent(percent), get_vm(is_vm) {}
        };
        MSVC_ENABLE_WARNING(4820)

    public:
        // memoize the value from VM::detect() in case it's ran again
        static std::map<bool, memo_struct> cache;

        // easier way to check if the result is memoized
        [[nodiscard]] static inline bool is_memoized() noexcept {
            return (
                util::disabled(NO_MEMO) && \
                cache.find(true) != cache.end()
            );
        }

        // get vm bool
        static bool get_vm() {
            memo_struct& tmp = cache[true];
            return tmp.get_vm;
        }

        // get vm brand
        static std::string get_brand() {
            memo_struct& tmp = cache[true];
            return tmp.get_brand;
        }

        // get vm percentage
        static u8 get_percent() {
            memo_struct& tmp = cache[true];
            return tmp.get_percent;
        }

        static constexpr u8
            FOUND_VM = 1,
            FOUND_BRAND = 2,
            FOUND_PERCENT = 3;

        static constexpr bool UNUSED_VM = false;
        static constexpr const char* UNUSED_BRAND = "";
        static constexpr u8 UNUSED_PERCENT = 0;

        static void memoize(const u8 p_flags, const bool is_vm, const std::string& vm_brand, const u8 vm_percent) {
            if (cache.find(true) != cache.end()) {
                return;
            }

            // default values
            bool local_is_vm = (p_flags & FOUND_VM) ? is_vm : detect(NO_MEMO);
            std::string local_vm_brand = (p_flags & FOUND_BRAND) ? vm_brand : brand(NO_MEMO);
            u8 local_vm_percent = (p_flags & FOUND_PERCENT) ? vm_percent : percentage(NO_MEMO);

            memo_struct tmp(local_vm_brand, local_vm_percent, local_is_vm);
            cache[true] = tmp;
        }
    };

    // miscellaneous functionalities
    struct util {
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
        }
#endif

#if (MSVC)
        // check if file exists
        [[nodiscard]] static bool exists(LPCSTR path) {
            return (GetFileAttributes(path) != INVALID_FILE_ATTRIBUTES) || (GetLastError() != ERROR_FILE_NOT_FOUND);
        }
#else
        [[nodiscard]] static bool exists(const char* path) {
#if (CPP >= 17)
            return std::filesystem::exists(path);
#elif (CPP >= 11)
            struct stat buffer;
            return (stat(path, &buffer) == 0);
#endif
        }
#endif

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

        // scan for keyword in string
        [[nodiscard]] static bool find(const std::string& base_str, const char* keyword) noexcept {
            return (base_str.find(keyword) != std::string::npos);
        };

        // for debug output
#ifdef __VMAWARE_DEBUG__
        template <typename... Args>
        static inline void debug_msg(Args... message) noexcept {
            constexpr const char* black_bg = "\x1B[48;2;0;0;0m";
            constexpr const char* bold = "\033[1m";
            constexpr const char* blue = "\x1B[38;2;00;59;193m";
            constexpr const char* ansiexit = "\x1B[0m";

            std::cout.setf(std::ios::fixed, std::ios::floatfield);
            std::cout.setf(std::ios::showpoint);

            std::cout << black_bg << bold << "[" << blue << "DEBUG" << ansiexit << bold << black_bg << "]" << ansiexit << " ";
            ((std::cout << message), ...);
            std::cout << "\n";
        }
#endif

        // directly return when adding a brand to the scoreboard for a more succint expression
#if (MSVC) 
        __declspec(noalias)
#elif (LINUX)
        [[gnu::const]]
#endif
        static inline bool add(const char* p_brand) noexcept {
            scoreboard.at(p_brand)++;
            return true;
        }

        /**
         * assert if the flag is enabled, far better expression than typing this:
         * if (!(flags & VMID)) {
         *    return false;
         * }
         *
         * compared to this:
         *
         * if (util::disabled(VMID)) {
         *    return false;
         * }
         */
#if (LINUX && __has_cpp_attribute(gnu::pure))
        [[gnu::pure]]
#endif
        [[nodiscard]] static inline bool disabled(const u8 flag_bit) noexcept {
            return (!flags.test(flag_bit));
        }

        // same as above but for checking enabled flags
#if (LINUX && __has_cpp_attribute(gnu::pure))
        [[gnu::pure]]
#endif
        [[nodiscard]] static inline bool enabled(const u8 flag_bit) noexcept {
            return (flags.test(flag_bit));
        }

        // basically std::system but it runs in the background with std::string output
        [[nodiscard]] static std::unique_ptr<std::string> sys_result(const char* cmd) try {
#if (CPP < 14)
            std::unique_ptr<std::string> tmp(nullptr);
            UNUSED(cmd);
            return tmp;
#else
#if (LINUX)
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
            if (!CreateProcess(NULL, const_cast<char*>(cmd), NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
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
            return std::make_unique<std::string>(result);
#endif
#endif
        }
        catch (...) {
#ifdef __VMAWARE_DEBUG__
            debug("sys_result: ", "catched error, returning nullptr");
#endif
            std::unique_ptr<std::string> tmp(nullptr);
            return tmp;
        }

        // get disk size in GB
        [[nodiscard]] static u32 get_disk_size() {
            u32 size = 0;
            constexpr u64 GB = (static_cast<VM::u64>(1024 * 1024) * 1024);

#if (LINUX)
            struct statvfs stat;

            if (statvfs("/", &stat) != 0) {
#ifdef __VMAWARE_DEBUG__
                debug("private util::get_disk_size( function: ", "failed to fetch disk size");
#endif
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
#ifdef __VMAWARE_DEBUG__
                debug("util::get_disk_size(: ", "failed to fetch size in GB");
#endif
            }
#endif

            if (size == 0) {
                return false;
            }

            // round to the nearest factor of 10
            const u32 result = static_cast<u32>(std::round((size / 10.0) * 10));

#ifdef __VMAWARE_DEBUG__
            debug("private util::get_disk_size( function: ", "disk size = ", result, "GB");
#endif

            return result;
        }

        // get physical RAM size in GB
        [[nodiscard]] static u64 get_physical_ram_size() {
#if (LINUX)
            if (!util::is_root()) {
#ifdef __VMAWARE_DEBUG__
                debug("private get_physical_ram_size function: ", "not root, returned 0");
#endif
                return 0;
            }

            auto result = util::sys_result("dmidecode --type 19 | grep 'Size' | grep '[[:digit:]]*'");

            if (result == nullptr) {
#ifdef __VMAWARE_DEBUG__
                debug("private get_physical_ram_size function: ", "invalid system result from dmidecode, returned 0");
#endif
                return 0;
            }

            const bool MB = (std::regex_search(*result, std::regex("MB")));
            const bool GB = (std::regex_search(*result, std::regex("GB")));

            if (!(MB || GB)) {
#ifdef __VMAWARE_DEBUG__
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
                }
                else if (in_number) {
                    break;
                }
            }

            if (number_str.empty()) {
#ifdef __VMAWARE_DEBUG__
                debug("private get_physical_ram_size_gb function: ", "string is empty, returned 0");
#endif
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
        MSVC_DISABLE_WARNING(5045)
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
        MSVC_ENABLE_WARNING(5045)


        // locates system information memory block in BIOS table
        SYSTEMINFORMATION* find_system_information(SMBIOSData* bios_data) {
            uint8_t* data = bios_data->SMBIOSTableData;

            while (data < bios_data->SMBIOSTableData + bios_data->Length)
            {
                uint8_t *next;
                SMBIOSHEADER *header = (SMBIOSHEADER*)data;

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
#endif

#if (MSVC)
    [[nodiscard]] static bool is_wow64() {
        BOOL isWow64 = FALSE;
        BOOL tmp = IsWow64Process(GetCurrentProcess(), &isWow64);
        return (tmp && isWow64);
    }
#endif
    };

private:
    /**
     * @brief Check CPUID output of manufacturer ID for known VMs/hypervisors
     * @category x86
     */
    [[nodiscard]] static bool vmid() try {
        if (!cpuid_supported || util::disabled(VMID)) {
            return false;
        }

#if (!x86)
        return false;
#else
        return cpu::vmid_template(0, "VMID: ");
#endif
    }
    catch (...) {
#ifdef __VMAWARE_DEBUG__
        debug("VMID: catched error, returned false");
#endif
        return false;
    }


    /**
     * @brief Check CPUID output of manufacturer ID for known VMs/hypervisors with leaf value 0x40000000
     * @category x86
     */
    [[nodiscard]] static bool vmid_0x4() try {
        if (!cpuid_supported || util::disabled(VMID_0X4)) {
            return false;
        }

#if (!x86)
        return false;
#else
        return cpu::vmid_template(0x40000000, "VMID_0x4: ");
#endif
    }
    catch (...) {
#ifdef __VMAWARE_DEBUG__
        debug("VMID_0x4: catched error, returned false");
#endif
        return false;
    }

    /**
     * @brief Check if CPU brand is a VM brand
     * @category x86
     */
    [[nodiscard]] static bool cpu_brand() try {
        if (!cpuid_supported || util::disabled(BRAND)) {
            return false;
        }

#if (!x86)
        return false;
#else
        std::string brand = cpu::get_brand();

        // TODO: might add more potential keywords, be aware that it could (theoretically) cause false positives
        constexpr std::array<const char*, 16> vmkeywords { {
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
#ifdef __VMAWARE_DEBUG__
                debug("BRAND_KEYWORDS: ", "match = ", *it);
#endif
                match_count++;
            }
        }

#ifdef __VMAWARE_DEBUG__
        debug("BRAND_KEYWORDS: ", "matches: ", static_cast<u32>(match_count));
#endif

        if (match_count > 0) {
            const auto qemu_regex = std::regex("QEMU", std::regex::icase);
            const bool qemu_match = std::regex_search(brand, qemu_regex);

            if (qemu_match) {
                return util::add(QEMU);
            }
        }

        return (match_count >= 1);
#endif
    }
    catch (...) {
#ifdef __VMAWARE_DEBUG__
        debug("BRAND_KEYWORDS: catched error, returned false");
#endif
        return false;
    }


    /**
     * @brief Match for QEMU CPU brand
     * @category x86
     */
    [[nodiscard]] static bool cpu_brand_qemu() try {
        if (!cpuid_supported || util::disabled(QEMU_BRAND)) {
            return false;
        }

#if (!x86)
        return false;
#else
        std::string brand = cpu::get_brand();

        std::regex pattern("QEMU Virtual CPU", std::regex_constants::icase);

        if (std::regex_match(brand, pattern)) {
            return util::add(QEMU);
        }

        return false;
#endif
    }
    catch (...) {
#ifdef __VMAWARE_DEBUG__
        debug("QEMU_BRAND: catched error, returned false");
#endif
        return false;
    }


    /**
     * @brief Check if hypervisor feature bit in CPUID is enabled (always false for physical CPUs)
     * @category x86
     */
    [[nodiscard]] static bool hypervisor_bit() try {
        if (!cpuid_supported || util::disabled(HYPERVISOR_BIT)) {
            return false;
        }
    
        #if (!x86)
            return false;
        #else
            u32 unused, ecx = 0;

        cpu::cpuid(unused, unused, ecx, unused, 1);

        return (ecx & (1 << 31));
#endif
    }
    catch (...) {
#ifdef __VMAWARE_DEBUG__
        debug("HYPERVISOR_BIT: catched error, returned false");
#endif
        return false;
    }


    /**
     * @brief Check if 0x40000000~0x400000FF cpuid input is present (mostly present in VMs, according to VMware)
     * @link https://kb.vmware.com/s/article/1009458
     * @category x86
     */
    MSVC_DISABLE_WARNING(5045)
    [[nodiscard]] static bool cpuid_0x4() try {
        if (!cpuid_supported || util::disabled(CPUID_0X4)) {
            return false;
        }

#if (!x86)
        return false;
#else
        u32 a, b, c, d = 0;

        for (u8 i = 0; i < 0xFF; i++) {
            cpu::cpuid(a, b, c, d, (cpu::leaf::hypervisor + i));
            if ((a + b + c + d) != 0) {
                return true;
            }
        }

        return false;
#endif
    }
    catch (...) {
#ifdef __VMAWARE_DEBUG__
        debug("CPUID_0x4: catched error, returned false");
#endif
        return false;
    }
    MSVC_ENABLE_WARNING(5045)


    /**
     * @brief Check for hypervisor brand string length (would be around 2 characters in a host machine)
     * @category x86
     */
    [[nodiscard]] static bool hypervisor_brand() try {
        if (util::disabled(HYPERVISOR_STR)) {
            return false;
        }

#if (!x86)
        return false;
#else
        char out[sizeof(int32_t) * 4 + 1] = { 0 }; // e*x size + number of e*x registers + null terminator
        cpu::cpuid((int*)out, cpu::leaf::hypervisor);

#ifdef __VMAWARE_DEBUG__
        debug("HYPERV_STR: eax: ", static_cast<u32>(out[0]),
            "\nebx: ", static_cast<u32>(out[1]),
            "\necx: ", static_cast<u32>(out[2]),
            "\nedx: ", static_cast<u32>(out[3])
        );
#endif

        return (std::strlen(out + 4) >= 4);
#endif
    }
    catch (...) {
#ifdef __VMAWARE_DEBUG__
        debug("HYPERVISOR_STR: catched error, returned false");
#endif
        return false;
    }


    /**
     * @brief Check if RDTSC is slow, if yes then it might be a VM
     * @category x86
     */
    [[nodiscard]] static bool rdtsc_check() try {
        if (util::disabled(RDTSC)) {
            return false;
        }

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

#ifdef __VMAWARE_DEBUG__
        debug("RDTSC: ", "acc = ", acc);
        debug("RDTSC: ", "acc/100 = ", acc / 100);
#endif

        return (acc / 100 > 350);
#elif (MSVC)
#define LODWORD(_qw)    ((DWORD)(_qw))
        u64 tsc1 = 0;
        u64 tsc2 = 0;
        u64 tsc3 = 0;
        for (INT i = 0; i < 10; i++) {
            tsc1 = __rdtsc();
            GetProcessHeap();
            tsc2 = __rdtsc();
            CloseHandle(0);
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
        if (util::disabled(SIDT5)) {
            return false;
        }

#if (!x86 || !LINUX)
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
#ifdef __VMAWARE_DEBUG__
        debug("SIDT5: catched error, returned false");
#endif
        return false;
    }


    /**
     * @brief Check if processor count is 1 or 2 (some VMs only have a single core)
     * @category All systems
     */
    [[nodiscard]] static bool thread_count() try {
        if (util::disabled(THREADCOUNT)) {
            return false;
        }

#ifdef __VMAWARE_DEBUG__
        debug("THREADCOUNT: ", "threads = ", std::thread::hardware_concurrency());
#endif

        return (std::thread::hardware_concurrency() <= 2);
    }
    catch (...) {
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
        if (util::disabled(MAC)) {
            return false;
        }

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
#ifdef __VMAWARE_DEBUG__
            debug("MAC: ", "not successful");
#endif
        }
#elif (MSVC)
        PIP_ADAPTER_INFO AdapterInfo;
        DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);

        char* mac_addr = static_cast<char*>(std::malloc(18));

        AdapterInfo = (IP_ADAPTER_INFO*)std::malloc(sizeof(IP_ADAPTER_INFO));

        if (AdapterInfo == NULL) {
            free(mac_addr);
            return false;
        }

        if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
            std::free(AdapterInfo);
            AdapterInfo = (IP_ADAPTER_INFO*)std::malloc(dwBufLen);
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
            return util::add(VBOX);
        }

        if (
            (compare(0x00, 0x0C, 0x29)) ||
            (compare(0x00, 0x1C, 0x14)) ||
            (compare(0x00, 0x50, 0x56)) ||
            (compare(0x00, 0x05, 0x69))
        ) {
            return util::add(VMWARE);
        }

        if (compare(0x00, 0x16, 0xE3)) {
            return util::add(XEN);
        }

        if (compare(0x00, 0x1C, 0x42)) {
            return util::add(PARALLELS);
        }

        if (compare(0x0A, 0x00, 0x27)) {
            return util::add(HYBRID);
        }

        return false;
    }
    catch (...) {
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
        if (util::disabled(TEMPERATURE)) {
            return false;
        }

#if (!LINUX)
        return false;
#else
        return (!util::exists("/sys/class/thermal/thermal_zone0/"));
#endif
    }
    catch (...) {
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
        if (util::disabled(SYSTEMD)) {
            return false;
        }

#if (!LINUX)
        return false;
#else
        if (!(util::exists("/usr/bin/systemd-detect-virt") || util::exists("/bin/systemd-detect-virt"))) {
#ifdef __VMAWARE_DEBUG__
            debug("SYSTEMD: ", "binary doesn't exist");
#endif
            return false;
        }

        const std::unique_ptr<std::string> result = util::sys_result("systemd-detect-virt");

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
    }
    catch (...) {
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
        if (util::disabled(CVENDOR)) {
            return false;
        }

#if (!LINUX)
        return false;
#else
        const char* vendor_file = "/sys/devices/virtual/dmi/id/chassis_vendor";

        if (util::exists(vendor_file)) {
            const std::string vendor = util::read_file(vendor_file);

            // TODO: More can be definitely added, I only tried QEMU and VMware so far
            if (vendor == "QEMU") { return util::add(QEMU); }
            if (vendor == "Oracle Corporation") { return util::add(VMWARE); }

#ifdef __VMAWARE_DEBUG__
            debug("CVENDOR: ", "unknown vendor = ", vendor);
#endif
        }
        else {
#ifdef __VMAWARE_DEBUG__
            debug("CVENDOR: ", "file doesn't exist");
#endif
        }

        return false;
#endif
    }
    catch (...) {
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
        if (util::disabled(CTYPE)) {
            return false;
        }

#if (!LINUX)
        return false;
#else
        const char* chassis = "/sys/devices/virtual/dmi/id/chassis_type";

        if (util::exists(chassis)) {
            return (stoi(util::read_file(chassis)) == 1);
        }
        else {
#ifdef __VMAWARE_DEBUG__
            debug("CTYPE: ", "file doesn't exist");
#endif
        }

        return false;
#endif
    }
    catch (...) {
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
        if (util::disabled(DOCKERENV)) {
            return false;
        }

#if (!LINUX)
        return false;
#else
        return (util::exists("/.dockerenv") || util::exists("/.dockerinit"));
#endif
    }
    catch (...) {
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
        if (util::disabled(DMIDECODE) || (util::is_root() == false)) {
            #ifdef __VMAWARE_DEBUG__
                debug("DMIDECODE: ", "precondition return called (root = ", util::is_root(), ")");
            #endif
            return false;
        }

#if (!LINUX)
        return false;
#else
        if (!(util::exists("/bin/dmidecode") || util::exists("/usr/bin/dmidecode"))) {
#ifdef __VMAWARE_DEBUG__
            debug("DMIDECODE: ", "binary doesn't exist");
#endif
            return false;
        }

        const std::unique_ptr<std::string> result = util::sys_result("dmidecode -t system | grep 'Manufacturer|Product' | grep -c \"QEMU|VirtualBox|KVM\"");

        if (*result == "" || result == nullptr) {
#ifdef __VMAWARE_DEBUG__
            debug("DMIDECODE: ", "invalid output");
#endif
            return false;
        }
        else if (*result == "QEMU") {
            return util::add(QEMU);
        }
        else if (*result == "VirtualBox") {
            return util::add(VBOX);
        }
        else if (*result == "KVM") {
            return util::add(KVM);
        }
        else if (std::atoi(result->c_str()) >= 1) {
            return true;
        }
        else {
#ifdef __VMAWARE_DEBUG__
            debug("DMIDECODE: ", "output = ", *result);
#endif
        }

        return false;
#endif
    }
    catch (...) {
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
        if (util::disabled(DMESG)) {
            return false;
        }

#if (!LINUX || CPP <= 11)
        return false;
#else
        if (!util::exists("/bin/dmesg") && !util::exists("/usr/bin/dmesg")) {
#ifdef __VMAWARE_DEBUG__
            debug("DMESG: ", "binary doesn't exist");
#endif
            return false;
        }

        const std::unique_ptr<std::string> result = util::sys_result("dmesg | grep -i hypervisor | grep -c \"KVM|QEMU\"");

        if (*result == "" || result == nullptr) {
            return false;
        }
        else if (*result == "KVM") {
            return util::add(KVM);
        }
        else if (*result == "QEMU") {
            return util::add(QEMU);
        }
        else if (std::atoi(result->c_str())) {
            return true;
        }
        else {
#ifdef __VMAWARE_DEBUG__
            debug("DMESG: ", "output = ", *result);
#endif
        }

        return false;
#endif
    }
    catch (...) {
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
        if (util::disabled(HWMON)) {
            return false;
        }

#if (!LINUX)
        return false;
#else
        return (!util::exists("/sys/class/hwmon/"));
#endif
    }
    catch (...) {
#ifdef __VMAWARE_DEBUG__
        debug("HWMON: catched error, returned false");
#endif
        return false;
    }


    /**
     * @brief Check for tons of VM-specific registry values
     * @category Windows
     */
    [[nodiscard]] static bool registry_key() try {
        if (util::disabled(REGISTRY)) {
            return false;
        }

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

#ifdef __VMAWARE_DEBUG__
        debug("REGISTRY: ", "score = ", static_cast<u32>(score));
#endif

        return (score >= 1);
#endif
    }
    catch (...) {
#ifdef __VMAWARE_DEBUG__
        debug("REGISTRY: catched error, returned false");
#endif
        return false;
    }


    /**
     * @brief checks for default usernames, often a sign of a VM 
     * @author: Some guy in a russian underground forum from a screenshot I saw, idk I don't speak russian ¯\_(ツ)_/¯
     * @category Windows
     */ 
    [[nodiscard]] static bool user_check() try {     
        if (util::disabled(USER)) {
            return false;
        }

#if (!MSVC)
        return false;
#else
        TCHAR user[UNLEN + 1]{};
        DWORD user_len = UNLEN + 1;
        GetUserName((TCHAR*)user, &user_len);
        std::string u(user, user + user_len);

#ifdef __VMAWARE_DEBUG__
        debug("USER: ", "output = ", u);
#endif

        if (u == "username") {
            return util::add(THREADEXPERT);
        }

        return (
            (u == "USER") ||      // Sandbox
            (u == "user") ||      // Sandbox 2
            (u == "currentuser")  // Normal
        );
#endif
    }
    catch (...) {
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
        if (util::disabled(SUNBELT_VM)) {
            return false;
        }

#if (!MSVC)
        return false;
#else
        if (util::exists("C:\\analysis")) {
            return util::add(SUNBELT);
        }

        return false;
#endif
    }
    catch (...) {
#ifdef __VMAWARE_DEBUG__
        debug("SUNBELT_VM: catched error, returned false");
#endif
        return false;
    }



    /**
     * @brief Check for VM-specific DLLs
     * @category Windows
     */
    [[nodiscard]] static bool DLL_check() try {
        if (util::disabled(DLL)) {
            return false;
        }

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
#ifdef __VMAWARE_DEBUG__
                debug("DLL: ", "LIB_INST detected true for real dll = ", dll);
#endif
                return true;
            }
            FreeLibrary(lib_inst);
        }

        for (auto& dll : false_dlls) {
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
    }
    catch (...) {
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
        if (util::disabled(VBOX_REG)) {
            return false;
        }

#if (!MSVC)
        return false;
#else
        HANDLE handle = CreateFile(_T("\\\\.\\VBoxMiniRdrDN"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

        if (handle != INVALID_HANDLE_VALUE) {
            CloseHandle(handle);
            return util::add(VBOX);
        }

        return false;
#endif
    }
    catch (...) {
#ifdef __VMAWARE_DEBUG__
        debug("VBOX_REG: catched error, returned false");
#endif
        return false;
    }


    /**
     * @brief Find VMware tools presence
     * @category Windows
     */
    [[nodiscard]] static bool vmware_registry() try {
        if (util::disabled(VMWARE_REG)) {
            return false;
        }

#if (!MSVC)
        return false;
#else
        HKEY hKey;
        // Use wide string literal
        bool result = (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_QUERY_VALUE, &hKey) == ERROR_SUCCESS);

#ifdef __VMAWARE_DEBUG__
        debug("VMWARE_REG: result = ", result);
#endif

        if (result == true) {
            return util::add(VMWARE);
        }

        return result;
#endif
    }
    catch (...) {
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
        if (util::disabled(CURSOR)) {
            return false;
        }

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
        if (util::disabled(WINE_CHECK)) {
            return false;
        }

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
#ifdef __VMAWARE_DEBUG__
        debug("WINE_CHECK: catched error, returned false");
#endif
        return false;
    }


    /**
     * @brief Find for VMware and VBox specific files
     * @category Windows
     */
    [[nodiscard]] static bool vm_files() try {
        if (util::disabled(VM_FILES)) {
            return false;
        }

#if (!MSVC)
        return false;
#else
        // points
        u8 vbox = 0;
        u8 vmware = 0;

        constexpr std::array<const char*, 26> files = { {
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
            "C:\\windows\\System32\\Drivers\\vmhgfs.dll",  // Note: there's a typo in the original code
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
            } };

        for (const auto file : files) {
            if (util::exists(file)) {
                const auto regex = std::regex(file, std::regex::icase);

                if (std::regex_search("vbox", regex)) {
#ifdef __VMAWARE_DEBUG__
                    debug("VM_FILES: found vbox file = ", file);
#endif
                    vbox++;
                }
                else {
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
            return util::add(VBOX);
        }
        else if (vbox < vmware) {
            return util::add(VMWARE);
        }
        else if (vbox == vmware) {
            return true;
        }

        return false;
#endif
    }
    catch (...) {
#ifdef __VMAWARE_DEBUG__
        debug("VM_FILES: catched error, returned false");
#endif
        return false;
    }


    /**
     * @brief Check for sysctl hardware model
     * @author MacRansom ransomware
     * @category MacOS
     */ 
    [[nodiscard]] static bool hwmodel() try {
        if (util::disabled(HWMODEL)) {
            return false;
        }

#if (!APPLE)
        return false;
#else
        auto result = util::sys_result("sysctl -n hw.model");

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
            return util::add(VMWARE);
        }

        // assumed true since it doesn't contain "Mac" string
        return true;
#endif
    }
    catch (...) {
#ifdef __VMAWARE_DEBUG__
        debug("HWMODEL: catched error, returned false");
#endif
        return false;
    }


    /**
     * @brief check if hyperthreading core count matches with physical expectations
     * @category MacOS
     * @author from MacRansom ransomware 
     * @link https://evasions.checkpoint.com/techniques/macos.html
     */
    [[nodiscard]] static bool mac_hyperthread() try {
        if (util::disabled(MAC_HYPERTHREAD)) {
            return false;
        }

#if (!APPLE)
        return false;
#else
        std::unique_ptr<std::string> result = util::sys_result("echo $((`sysctl -n hw.logicalcpu`/`sysctl -n hw.physicalcpu`))");

        return (*result != ("2"));
#endif
    }
    catch (...) {
#ifdef __VMAWARE_DEBUG__
        debug("MAC_HYPERTHREAD: catched error, returned false");
#endif
        return false;
    }


    /**
     * @brief Check if disk size is too low
     * @category Linux (for now)
     */
     [[nodiscard]] static bool disk_size() try {
        if (util::disabled(DISK_SIZE)) {
            return false;
        }

#if (!LINUX)
        return false;
#else
        const u32 size = util::get_disk_size();

#ifdef __VMAWARE_DEBUG__
        debug("DISK_SIZE: size = ", size);
#endif

        return (size <= 60); // in GB
#endif
    }
    catch (...) {
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
        if (util::disabled(VBOX_DEFAULT)) {
            return false;
        }

        const u32 disk = util::get_disk_size();
        const u64 ram = util::get_physical_ram_size();

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
    }
    catch (...) {
#ifdef __VMAWARE_DEBUG__
        debug("VBOX_DEFAULT: catched error, returned false");
#endif
        return false;
    }


   /**
    * @brief Check VBox network provider string
    * @todo fix WNetGetProviderName linker error
    */
    [[nodiscard]] static bool vbox_network_share() try {
        if (util::disabled(VBOX_NETWORK)) {
            return false;
        }

#if (!MSVC)
        return false;
#else
        u32 pnsize = 0x1000;
        char* provider = new char[pnsize];

        u32 retv = WNetGetProviderName(WNNC_NET_RDR2SAMPLE, provider, reinterpret_cast<LPDWORD>(&pnsize));
    
        if (retv == NO_ERROR) {
            return (lstrcmpi(provider, "VirtualBox Shared Folders") == 0);
        }

        return false;
#endif
    }
    catch (...) {
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
        if (util::disabled(COMPUTER_NAME)) {
            return false;
        }

#if (!MSVC)
        return false;
#else
        auto out_length = MAX_PATH;
        std::vector<u8> comp_name(static_cast<u32>(out_length), 0);
        GetComputerNameA((LPSTR)comp_name.data(), (LPDWORD)&out_length);

        auto compare = [&](const std::string& s) -> bool {
            return (std::strcmp((LPCSTR)comp_name.data(), s.c_str()) == 0);
        };

#ifdef __VMAWARE_DEBUG__
        debug("COMPUTER_NAME: fetched = ", (LPCSTR)comp_name.data());
#endif

        if (compare("InsideTm") || compare("TU-4NH09SMCG1HC")) { // anubis
#ifdef __VMAWARE_DEBUG__
            debug("COMPUTER_NAME: detected Anubis");
#endif

            return util::add(ANUBIS);
        }

        if (compare("klone_x64-pc") || compare("tequilaboomboom")) { // general
#ifdef __VMAWARE_DEBUG__
            debug("COMPUTER_NAME: detected general (VM but unknown)");
#endif

            return true;
        }

        return false;
#endif
    }
    catch (...) {
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
        if (util::disabled(HOSTNAME)) {
            return false;
        }

#if (!MSVC)
        return false;
#else
        auto out_length = MAX_PATH;
        std::vector<u8> dns_host_name(static_cast<u32>(out_length), 0);
        GetComputerNameExA(ComputerNameDnsHostname, (LPSTR)dns_host_name.data(), (LPDWORD)&out_length);

#ifdef __VMAWARE_DEBUG__
        debug("HOSTNAME: ", (LPCSTR)dns_host_name.data());
#endif

        return (!lstrcmpiA((LPCSTR)dns_host_name.data(), "SystemIT"));
#endif
    }
    catch (...) {
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
        if (util::disabled(MEMORY)) {
            return false;
        }

        constexpr u64 min_ram_1gb = (1024LL * (1024LL * (1024LL * 1LL)));
        const u64 ram = util::get_memory_space();

#ifdef __VMAWARE_DEBUG__
        debug("MEMORY: ram size (GB) = ", ram);
        debug("MEMORY: minimum ram size (GB) = ", min_ram_1gb);
#endif

        return (ram < min_ram_1gb);
    }
    catch (...) {
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
        if (util::disabled(VM_PROCESSES)) {
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
            return util::add(str);
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
    }
    catch (...) {
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
        if (util::disabled(LINUX_USER_HOST)) {
            return false;
        }

#if (!LINUX)
        return false;
#else
        if (util::is_root()) {
            return false;
        }

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
    }
    catch (...) {
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
        if (util::disabled(VBOX_WINDOW_CLASS)) {
            return false;
        }

#if (!MSVC)
        return false;
#else
        HWND hClass = FindWindow(_T("VBoxTrayToolWndClass"), NULL);
        HWND hWindow = FindWindow(NULL, _T("VBoxTrayToolWnd"));

        if (hClass || hWindow) {
            return util::add(VBOX);
        }

        return false;
#endif
    }
    catch (...) {
#ifdef __VMAWARE_DEBUG__
        debug("VBOX_WINDOW_CLASS: catched error, returned false");
#endif
        return false;
    }


    /**
     * @brief Gamarue ransomware check
     * @category Windows 
     */
    [[nodiscard]] static bool gamarue() try {
        if (util::disabled(GAMARUE)) {
            return false;
        }

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
            return util::add(SANDBOXIE);
        }

        hMod = GetModuleHandleW(L"dbghelp.dll"); // Thread Expert
        if (hMod != 0) {
            free(szBuff);
            return util::add(THREADEXPERT);
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
                    return util::add(JOEBOX);
                }
                else if (strcmp(szBuff, "76487-644-3177037-23510") == 0) { // CW Sandbox
                    free(szBuff);
                    return util::add(CWSANDBOX);
                }
                else if (strcmp(szBuff, "76487-337-8429955-22614") == 0) { // anubis
                    free(szBuff);
                    return util::add(ANUBIS);
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
#ifdef __VMAWARE_DEBUG__
        debug("GAMARUE: catched error, returned false");
#endif
        return false;
    }


    /**
     * @brief match WMIC output for computer system manufacturer
     * @category Windows
     * @note FIX SEGFAULT
     */
    [[nodiscard]] static bool wmic() try {
        if (util::disabled(WMIC)) {
            return false;
        }

            return false;

            /*
            #if (!MSVC)
                return false;
            #else
                auto check_wmic_presence = []() -> bool {
                    FILE* pipe = _popen("wmic /?", "r");

                    if (pipe) {
                        char buffer[128];
                        while (!feof(pipe)) {
                            if (fgets(buffer, 128, pipe) != nullptr)
                                return true;
                        }
                        _pclose(pipe);
                    } else {
                        return false;
                    }

                    return false;
                };

                if (check_wmic_presence() == false) {
                    return false;
                }

            std::unique_ptr<std::string> manufacturer = util::sys_result("WMIC COMPUTERSYSTEM GET MANUFACTURER");
           
            if (*manufacturer == "VirtualBox") {
                return util::add(VBOX);
            }

            std::unique_ptr<std::string> model = util::sys_result("WMIC COMPUTERSYSTEM GET MODEL");
            
            constexpr std::array<const char*, 16> vmkeywords {
                "qemu", "kvm", "virtual", "vm", 
                "vbox", "virtualbox", "vmm", "monitor", 
                "bhyve", "hyperv", "hypervisor", "hvisor", 
                "parallels", "vmware", "hvm", "qnx"
            };

            for (std::size_t i = 0; i < vmkeywords.size(); i++) {
                const auto regex = std::regex(vmkeywords.at(i), std::regex::icase);
                const bool match = std::regex_search(*model, regex);
                
                if (match) {
                    #ifdef __VMAWARE_DEBUG__
                        debug("WMIC: ", "match = ", vmkeywords.at(i));
                    #endif
                    return true;
                }
            }

            return false;
        #endif
        */
    }
    catch (...) {
#ifdef __VMAWARE_DEBUG__
        debug("WMIC: catched error, returned false");
#endif
        return false;
    }


    /**
     * @brief Check if the BIOS serial is valid
     * @category Linux
     */
    [[nodiscard]] static bool bios_serial() try {
        if (util::disabled(BIOS_SERIAL)) {
            return false;
        }

#if (!MSVC)
        return false;
#else
        std::unique_ptr<util::sys_info> info = std::make_unique<util::sys_info>();

        const std::string str = info->get_serialnumber();
        const std::size_t nl_pos = str.find('\n');

        if (nl_pos == std::string::npos) {
            return false;
        }

#ifdef __VMAWARE_DEBUG__
        debug("BIOS_SERIAL: ", str);
#endif
            
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
#ifdef __VMAWARE_DEBUG__
        debug("BIOS_SERIAL: catched error, returned false");
#endif
        return false;
    }


    /**
     * @brief check for any indication of parallels through BIOS stuff
     * @link https://stackoverflow.com/questions/1370586/detect-if-windows-is-running-from-within-parallels
     * @category Windows
     */ 
    [[nodiscard]] static bool parallels() try {
        if (util::disabled(PARALLELS_VM)) {
            return false;
        }

#if (!MSVC)
        return false;
#else
        std::unique_ptr<util::sys_info> info = std::make_unique<util::sys_info>();

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
            return util::add(PARALLELS);
        }

        return false;
#endif
    }
    catch (...) {
#ifdef __VMAWARE_DEBUG__
        debug("PARALLELS_VM:", "catched error, returned false");
#endif
        return false;
    }


    /**
        * @brief check VM through alternative RDTSC technique with VMEXIT
        * @category x86
        */
    [[nodiscard]] static bool rdtsc_vmexit() try {
        if (util::disabled(RDTSC_VMEXIT)) {
            return false;
        }

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

        return (avg >= 1000 || avg == 0);
    }
    catch (...) {
#ifdef __VMAWARE_DEBUG__
        debug("RDTSC_VMEXIT:", "catched error, returned false");
#endif
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
        if (util::disabled(LOADED_DLLS)) {
            return false;
        }

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
            "pstorec.dll",     // SunBelt Sandbox
            "vmcheck.dll",     // Virtual PC
            "wpespy.dll",      // WPE Pro
            "cmdvrt64.dll",    // Comodo Container
            "cmdvrt32.dll",    // Comodo Container
        } };

        for (const auto& key : szDlls) {
            const char* dll = key;

            hDll = GetModuleHandleA(dll);  // Use GetModuleHandleA for ANSI strings

            if (hDll != NULL && dll != NULL) {
                if (strcmp(dll, "sbiedll.dll") == 0) { return util::add(SANDBOXIE); }
                if (strcmp(dll, "pstorec.dll") == 0) { return util::add(SUNBELT); }
                if (strcmp(dll, "vmcheck.dll") == 0) { return util::add(VPC); }
                if (strcmp(dll, "cmdvrt32.dll") == 0) { return util::add(COMODO); }
                if (strcmp(dll, "cmdvrt64.dll") == 0) { return util::add(COMODO); }

                return true;
            }
        }

        return false;
#endif
    }
    catch (...) {
#ifdef __VMAWARE_DEBUG__
        debug("LOADED_DLLS:", "caught error, returned false");
#endif
        return false;
    }

    /**
     * @brief Do various Bochs-related CPU stuff
     * @category x86
     * @note Discovered by Peter Ferrie, Senior Principal Researcher, Symantec Advanced Threat Research peter_ferrie@symantec.com
     */
    [[nodiscard]] static bool bochs_cpu() try {
        if (!cpuid_supported || util::disabled(BOCHS_CPU)) {
            return false;
        }

#if (!x86)
        return false;
#else
        const bool intel = cpu::is_intel();
        const bool amd = cpu::is_amd();

        // if neither amd or intel, return false
        if (!(intel ^ amd)) {
            return false;
        }

        const std::string brand = cpu::get_brand();

        if (intel) {
            // technique 1: not a valid brand 
            if (brand == "              Intel(R) Pentium(R) 4 CPU        ") {
                return util::add(BOCHS);
            }
        }
        else if (amd) {
            // technique 2: "processor" should have a capital P
            if (brand == "AMD Athlon(tm) processor") {
                return util::add(BOCHS);
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
                return util::add(BOCHS);
            }
        }

        return false;
#endif
    }
    catch (...) {
#ifdef __VMAWARE_DEBUG__
        debug("BOCHS_CPU:", "catched error, returned false");
#endif
        return false;
    }


    /**
     * @brief Go through the motherboard and match for VPC-specific string
     * @category Windows
     */ 
    [[nodiscard]] static bool vpc_board() try {
        if (util::disabled(VPC_BOARD)) {
            return false;
        }

#if (!MSVC)
        return false;
#else
        HRESULT hres;

        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) {
#ifdef __VMAWARE_DEBUG__
            debug("VPC_BOARD: Failed to initialize COM library. Error code: ", hres);
#endif
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
#ifdef __VMAWARE_DEBUG__
            debug("VPC_BOARD: Failed to initialize security. Error code: ", hres);
#endif
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
#ifdef __VMAWARE_DEBUG__
            debug("VPC_BOARD: Failed to create IWbemLocator object. Error code: ", hres);
#endif
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
#ifdef __VMAWARE_DEBUG__
            debug("VPC_BOARD: Failed to connect to WMI. Error code: ", hres);
#endif
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
#ifdef __VMAWARE_DEBUG__
            debug("VPC_BOARD: Failed to set proxy blanket. Error code: ", hres);
#endif
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
#ifdef __VMAWARE_DEBUG__
            debug("VPC_BOARD: Query for Win32_BaseBoard failed. Error code: ", hres);
#endif
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
            return util::add(VPC);
        }

        return false;
#endif
    }
    catch (...) {
#ifdef __VMAWARE_DEBUG__
        debug("VPC_BOARD:", "catched error, returned false");
#endif
        return false;
    }


    /**
     * @brief get WMI query for HYPERV name
     * @category Windows
     * @note idea is from nettitude
     * @link https://labs.nettitude.com/blog/vm-detection-tricks-part-3-hyper-v-raw-network-protocol/
     */
    [[nodiscard]] static bool hyperv_wmi() try {
        if (util::disabled(HYPERV_WMI)) {
            return false;
        }

#if (!MSVC)
        return false;
#else
        HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) {
#ifdef __VMAWARE_DEBUG__
            debug("HYPERV_WMI: Failed to initialize COM library. Error code = ", hres);
#endif
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
#ifdef __VMAWARE_DEBUG__
            debug("HYPERV_WMI: Failed to initialize security. Error code = ", hres);
#endif
            CoUninitialize();
            return false;
        }

        // Connect to WMI
        IWbemLocator* pLoc = NULL;
        hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);

        if (FAILED(hres)) {
#ifdef __VMAWARE_DEBUG__
            debug("HYPERV_WMI: Failed to create IWbemLocator object. Error code = ", hres);
#endif
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
#ifdef __VMAWARE_DEBUG__
            debug("HYPERV_WMI: Could not connect. Error code = ", hres);
#endif
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
#ifdef __VMAWARE_DEBUG__
            debug("HYPERV_WMI: Could not set proxy blanket. Error code = ", hres);
#endif
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
#ifdef __VMAWARE_DEBUG__
            debug("HYPERV_WMI: ExecQuery failed. Error code = ", hres);
#endif
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
#ifdef __VMAWARE_DEBUG__
        debug("HYPERV_WMI: ", "catched error, returned false");
#endif
        return false;
    }


    /**
     * @brief compare for hyperv-specific string in registry
     * @category Windows
     * @note idea is from nettitude
     * @link https://labs.nettitude.com/blog/vm-detection-tricks-part-3-hyper-v-raw-network-protocol/
     */
    [[nodiscard]] static bool hyperv_registry() try {
        if (util::disabled(HYPERV_REG)) {
            return false;
        }

#if (!MSVC)
        return false;
#else
        constexpr const char* registryPath = "SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries";

        HKEY hKey;
        LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, reinterpret_cast<LPCWSTR>(registryPath), 0, KEY_READ, &hKey);

        if (result != ERROR_SUCCESS) {
#ifdef __VMAWARE_DEBUG__
            debug("HYPERV_WMI: Error opening registry key. Code: ", result);
#endif
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
#ifdef __VMAWARE_DEBUG__
        debug("HYPERV_WMI: ", "catched error, returned false");
#endif
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
        if (util::disabled(VBOX_FOLDERS)) {
            return false;
        }

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
                return util::add(VBOX);
            }
        }

        // Clean up the allocated buffer
        LocalFree(provider);

        return false;

#endif
    }
    catch (...) {
#ifdef __VMAWARE_DEBUG__
        debug("VBOX_FOLDERS: ", "catched error, returned false");
#endif
        return false;
    }


    /**
     * @brief Check VirtualBox MSSMBIOS registry for VM-specific strings
     * @category Windows
     * @note slightly modified from original code
     * @author @waleedassar
     * @link https://pastebin.com/fPY4MiYq
     */
    [[nodiscard]] static bool vbox_mssmbios() try {
        if (util::disabled(VBOX_MSSMBIOS)) {
            return false;
        }

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

        MSVC_DISABLE_WARNING(5045)
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
        MSVC_ENABLE_WARNING(5045)

        AllToUpper(p, length);

        // cleaner and better shortcut than typing reinterpret_cast<unsigned char*> a million times
        auto cast = [](char* p) -> unsigned char* {
            return reinterpret_cast<unsigned char*>(p);
        };

        unsigned char* x1 = ScanDataForString(cast(p), length, (unsigned char*)("INNOTEK GMBH"));
        unsigned char* x2 = ScanDataForString(cast(p), length, (unsigned char*)("VIRTUALBOX"));
        unsigned char* x3 = ScanDataForString(cast(p), length, (unsigned char*)("SUN MICROSYSTEMS"));
        unsigned char* x4 = ScanDataForString(cast(p), length, (unsigned char*)("VIRTUAL MACHINE"));
        unsigned char* x5 = ScanDataForString(cast(p), length, (unsigned char*)("VBOXVER"));

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
            return util::add(VBOX);
        }

        return false;
#endif
    }
    catch (...) {
#ifdef __VMAWARE_DEBUG__
        debug("VBOX_MSSMBIOS: ", "catched error, returned false");
#endif
        return false;
    }


    /**
     * @brief Check if memory is too low for MacOS system
     * @category MacOS
     * @link https://evasions.checkpoint.com/techniques/macos.html
     */
    [[nodiscard]] static bool hw_memsize() try {
        if (util::disabled(MAC_MEMSIZE)) {
            return false;
        }

#if (!APPLE)
        return false;
#else
        std::unique_ptr<std::string> result = util::sys_result("sysctl -n hw.memsize");
        const std::string ram = *result;

        if (ram == "0") {
            return false;
        }

#ifdef __VMAWARE_DEBUG__
        debug("MAC_MEMSIZE: ", "ram size = ", ram);
#endif

        for (const char c : ram) {
            if (!std::isdigit(c)) {
#ifdef __VMAWARE_DEBUG__
                debug("MAC_MEMSIZE: ", "found non-digit character, returned false");
#endif
                return false;
            }
        }

        const u64 ram_u64 = std::stoull(ram);

#ifdef __VMAWARE_DEBUG__
        debug("MAC_MEMSIZE: ", "ram size in u64 = ", ram_u64);
#endif

        constexpr u64 limit = 4000000000; // 4GB 

        return (ram_u64 <= limit);
#endif
    }
    catch (...) {
#ifdef __VMAWARE_DEBUG__
        debug("MAC_MEMSIZE: ", "catched error, returned false");
#endif
        return false;
    }


    /**
     * @brief Check MacOS' IO kit registry for VM-specific strings
     * @category MacOS
     * @link https://evasions.checkpoint.com/techniques/macos.html
     */
    [[nodiscard]] static bool io_kit() try {
        if (util::disabled(MAC_IOKIT)) {
            return false;
        }

#if (!APPLE)
        return false;
#else
        std::unique_ptr<std::string> platform_ptr = util::sys_result("ioreg -rd1 -c IOPlatformExpertDevice");
        std::unique_ptr<std::string> board_ptr = util::sys_result("ioreg -rd1 -c board-id");
        std::unique_ptr<std::string> manufacturer_ptr = util::sys_result("ioreg -rd1 -c manufacturer");

        const std::string platform = *platform_ptr;
        const std::string board = *board_ptr;
        const std::string manufacturer = *manufacturer_ptr;

        auto check_platform = [&]() -> bool {
            debug("IO_KIT: ", "platform = ", platform);

            for (const char c : platform) {
                if (!std::isdigit(c)) {
                    return false;
                }
            }

            return (platform == "0");
        };

        auto check_board = [&]() -> bool {
            debug("IO_KIT: ", "board = ", board);
            if (board == "") {
                return false;
            }

            if (find(board, "Mac")) {
                return false;
            }

            if (find(board, "VirtualBox")) {
                return util::add(VBOX);
            }

            if (find(board, "VMware")) {
                return util::add(VMWARE);
            }

            return true;
        };

        auto check_manufacturer = [&]() -> bool {
            debug("IO_KIT: ", "manufacturer = ", manufacturer);

            if (find(manufacturer, "Apple")) {
                return false;
            }

            if (find(manufacturer, "innotek")) {
                return util::add(VBOX);
            }

            return true;
        };

        return (
            check_platform() ||
            check_board() ||
            check_manufacturer()
        );
#endif            
    }
    catch (...) {
#ifdef __VMAWARE_DEBUG__
        debug("MAC_IOKIT: ", "catched error, returned false");
#endif
        return false;
    }


    /**
     * @brief Check for VM-strings in ioreg commands for MacOS
     * @category MacOS
     * @link https://evasions.checkpoint.com/techniques/macos.html
     */
    [[nodiscard]] static bool ioreg_grep() try {
        if (util::disabled(IOREG_GREP)) {
            return false;
        }

#if (!APPLE)
        return false;
#else
        auto check_usb = []() -> bool {
            std::unique_ptr<std::string> result = util::sys_result("ioreg -rd1 -c IOUSBHostDevice | grep \"USB Vendor Name\"");
            const std::string usb = *result;

            if (find(usb, "Apple")) {
                return false;
            }

            if (find(usb, "VirtualBox")) {
                return util::add(VBOX);
            }

            return true;
        };

        auto check_general = []() -> bool {
            std::unique_ptr<std::string> sys_vbox = util::sys_result("ioreg -l | grep -i -c -e \"virtualbox\" -e \"oracle\"");

            if (std::stoi(*sys_vbox) > 0) {
                return util::add(VBOX);
            }

            std::unique_ptr<std::string> sys_vmware = util::sys_result("ioreg -l | grep -i -c -e \"vmware\"");

            if (std::stoi(*sys_vmware) > 0) {
                return util::add(VMWARE);
            }

            return false;
        };

        auto check_rom = []() -> bool {
            std::unique_ptr<std::string> sys_rom = util::sys_result("system_profiler SPHardwareDataType | grep \"Boot ROM Version\"");
            const std::string rom = *sys_rom;

            if (find(rom, "VirtualBox")) {
                return util::add(VBOX);
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
#ifdef __VMAWARE_DEBUG__
        debug("IOREG_GREP: ", "catched error, returned false");
#endif
        return false;
    }


    /**
     * @brief Check if System Integrity Protection is disabled (likely a VM if it is)
     * @category MacOS
     * @link https://evasions.checkpoint.com/techniques/macos.html
     */
    [[nodiscard]] static bool mac_sip() try {
        if (util::disabled(MAC_SIP)) {
            return false;
        }

#if (!APPLE)
        return false;
#else
        std::unique_ptr<std::string> result = util::sys_result("csrutil status");
        const std::string tmp = *result;

#ifdef __VMAWARE_DEBUG__
        debug("MAC_SIP: ", "result = ", tmp);
#endif

        return (find(tmp, "disabled") || (!find(tmp, "enabled")));
#endif
    }
    catch (...) {
#ifdef __VMAWARE_DEBUG__
        debug("MAC_SIP: ", "catched error, returned false");
#endif
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
        if (util::disabled(KVM_REG)) {
            return false;
        }

#if (!MSVC)
        return false;
#else
        auto registry_exists = [](const char* key) -> bool {
            HKEY keyHandle;
            
            if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, key, 0, KEY_QUERY_VALUE, &keyHandle) == ERROR_SUCCESS) {
                RegCloseKey(keyHandle);
                return true;
            }

            return false;
        };

        constexpr std::array<const char*, 7> keys = {{
            "SYSTEM\\ControlSet001\\Services\\vioscsi",
            "SYSTEM\\ControlSet001\\Services\\viostor",
            "SYSTEM\\ControlSet001\\Services\\VirtIO-FS Service",
            "SYSTEM\\ControlSet001\\Services\\VirtioSerial",
            "SYSTEM\\ControlSet001\\Services\\BALLOON",
            "SYSTEM\\ControlSet001\\Services\\BalloonService",
            "SYSTEM\\ControlSet001\\Services\\netkvm",
        }};

        for (const auto& key : keys) {
            if (registry_exists(key)) {
                return util::add(KVM);
            }
        }

        return false;
#endif
    }
    catch (...) {
#ifdef __VMAWARE_DEBUG__
        debug("KVM_REG: ", "catched error, returned false");
#endif
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
        if (util::disabled(KVM_DRIVERS)) {
            return false;
        }

#if (!MSVC)
        return false;
#else
        constexpr std::array<const char*, 10> keys = {{
            "System32\\drivers\\balloon.sys",
            "System32\\drivers\\netkvm.sys",
            "System32\\drivers\\pvpanic.sys",
            "System32\\drivers\\viofs.sys",
            "System32\\drivers\\viogpudo.sys",
            "System32\\drivers\\vioinput.sys",
            "System32\\drivers\\viorng.sys",
            "System32\\drivers\\vioscsi.sys",
            "System32\\drivers\\vioser.sys",
            "System32\\drivers\\viostor.sys",
        }};

        TCHAR szWinDir[MAX_PATH] = _T("");
        TCHAR szPath[MAX_PATH] = _T("");
        PVOID OldValue = NULL;

        GetWindowsDirectory(szWinDir, MAX_PATH);

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
#ifdef __VMAWARE_DEBUG__
        debug("KVM_DRIVERS: ", "catched error, returned false");
#endif
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
        if (util::disabled(KVM_DIRS)) {
            return false;
        }

#if (!MSVC)
        return false;
#else
        TCHAR szProgramFile[MAX_PATH];
        TCHAR szPath[MAX_PATH] = _T("");
        TCHAR szTarget[MAX_PATH] = _T("Virtio-Win\\");

        if (util::is_wow64()) {
            ExpandEnvironmentStrings(_T("%ProgramW6432%"), szProgramFile, ARRAYSIZE(szProgramFile));
        } else {
            SHGetSpecialFolderPath(NULL, szProgramFile, CSIDL_PROGRAM_FILES, FALSE);
        }

        PathCombine(szPath, szProgramFile, szTarget);
        return util::exists(szPath);
#endif
    }
    catch (...) {
#ifdef __VMAWARE_DEBUG__
        debug("KVM_DIRS: ", "catched error, returned false");
#endif
        return false;
    }

    // __TECHNIQUE_LABEL, label for adding techniques above this point

    MSVC_DISABLE_WARNING(4820)
    struct technique {
        u8 points; 
        bool(*ptr)(); // function pointer
    };
    MSVC_ENABLE_WARNING(4820)

    static const std::map<u8, technique> table;

public:
    /**
     * @brief Check for a specific technique based on flag argument
     * @param u8 (flags from VM wrapper)
     * @return bool
     * @link https://github.com/kernelwernel/VMAware/blob/main/docs/documentation.md#vmcheck
     */
#if (CPP >= 20 && !defined(__clang__)) // not sure why clang doesn't support this lol
    [[nodiscard]] static bool check(const u8 p_flag = 0, const std::source_location& loc = std::source_location::current()) {
#else
    [[nodiscard]] static bool check(const u8 p_flag = 0) {
#endif
        auto throw_error = [&](const char* text) -> void {
            std::stringstream ss;
#if (CPP >= 20 && !defined(__clang__))
            ss << ", error in " << loc.function_name() << " at " << loc.file_name() << ":" << loc.line() << ")";
#endif
            ss << ". Consult the documentation's flag handler for VM::check()";
            throw std::invalid_argument(std::string(text) + ss.str());
        };

        if (p_flag > enum_size) {
            throw_error("Flag argument must be a valid");
        }

        if (p_flag == 0) {
            throw_error("Flag argument must contain at least a single option");
        }

        if (
            (p_flag == NO_MEMO) || \
            (p_flag == EXTREME)
        ) {
            throw_error("Flag argument must be a technique flag and not a settings flag");
        }

        // count should only have a single flag at this stage
        assert(p_flag > 0 && p_flag <= enum_size);

        // temporarily enable all flags so that every technique is enabled
        const flagset tmp_flags = VM::flags;
        VM::flags = []() -> flagset {
            flagset tmp = DEFAULT;
            tmp.set(CURSOR);
            return tmp;
        }();

        bool result = false;

        auto it = table.find(p_flag);

        if (VMAWARE_UNLIKELY(it == table.end())) {
            throw_error("Flag is not known");
        }

        const technique& pair = it->second;
        result = pair.ptr();

        VM::flags = tmp_flags;

        return result;
    }


    /**
     * @brief Fetch the VM brand
     * @param any combination of flags, can be optional
     * @return std::string
     * @returns VMware, VirtualBox, KVM, bhyve, QEMU, Microsoft Hyper-V, Microsoft x86-to-ARM, Parallels, Xen HVM, ACRN, QNX hypervisor, Hybrid Analysis, Sandboxie, Docker, Wine, Virtual Apple, Virtual PC, Unknown
     * @link https://github.com/kernelwernel/VMAware/blob/main/docs/documentation.md#vmbrand
     */
    [[nodiscard]] static std::string brand(const flagset p_flags = DEFAULT) {
        VM::flags = p_flags;

        if (memo::is_memoized()) {
#ifdef __VMAWARE_DEBUG__
            debug("memoization: returned cached result in brand()");
#endif
            return (memo::get_brand());
        }

        const char* current_brand = "";

        // fetch the brand with the most points in the scoreboard
#if (CPP >= 20)
        auto it = std::ranges::max_element(VM::scoreboard, {},
            [](const auto& pair) {
                return pair.second;
            }
        );

        if (it != scoreboard.end()) {
            if (
                std::none_of(scoreboard.cbegin(), scoreboard.cend(),
                    [](const auto& pair) {
                        return pair.second;
                    }
                )
            ) {
                current_brand = "Unknown";
            }
            else {
                current_brand = it->first;
            }
        }
        else {
            current_brand = "Unknown";
        }
#else
#if (MSVC)
        int max = 0;
#else
        u8 max = 0;
#endif

#if (CPP >= 17)
        for (const auto& [brand, points] : scoreboard) {
            if (points > max) {
                current_brand = brand;
                max = points;
            }
        }
#else
        for (auto it = scoreboard.cbegin(); it != scoreboard.cend(); ++it) {
            if (it->second > max) {
                current_brand = it->first;
                max = it->second;
            }
        }
#endif

        if (max == 0) {
            current_brand = "Unknown";
        }
#endif

        // goofy ass C++11 and C++14 linker error workaround
#if (CPP <= 14)
        constexpr const char* TMP_QEMU = "QEMU";
        constexpr const char* TMP_KVM = "KVM";
#else
        constexpr const char* TMP_QEMU = VM::QEMU;
        constexpr const char* TMP_KVM = VM::KVM;
#endif

        if (
            (scoreboard.at(TMP_QEMU) > 0) &&
            (scoreboard.at(TMP_KVM) > 0)
        ) {
            current_brand = "QEMU/KVM";
        }

#ifdef __VMAWARE_DEBUG__
        for (const auto p : scoreboard) {
            debug("scoreboard: ", (int)p.second, " : ", p.first);
        }
#endif

        if (util::disabled(NO_MEMO)) {
#ifdef __VMAWARE_DEBUG__
            debug("memoization: cached result in brand()");
#endif
            memo::memoize(memo::FOUND_BRAND, memo::UNUSED_VM, current_brand, memo::UNUSED_PERCENT);
        }

        return current_brand;
    }


    /**
     * @brief Detect if running inside a VM
     * @param any combination of flags, can be optional
     * @return bool
     * @link https://github.com/kernelwernel/VMAware/blob/main/docs/documentation.md#vmdetect
     */
    static bool detect(const flagset p_flags = DEFAULT) {
        VM::flags = p_flags;

        if (memo::is_memoized()) {
#ifdef __VMAWARE_DEBUG__
            debug("memoization: returned cached result in detect()");
#endif
            return (memo::get_vm());
        }

#ifdef __VMAWARE_DEBUG__
        debug("cpuid: is supported? : ", VM::cpuid_supported);
#endif

        bool result = false;
        u8 p = percentage(p_flags);

        if (util::enabled(EXTREME)) {
            result = (p > 0);
        }
        else {
            result = (p == 100);
        }

        if (util::disabled(NO_MEMO)) {
            memo::memoize(memo::FOUND_VM, result, memo::UNUSED_BRAND, memo::UNUSED_PERCENT);
        }

        return result;
    }


    /**
     * @brief Get the percentage of how likely it's a VM
     * @param any combination of flags, can be optional
     * @return std::uint8_t
     * @link https://github.com/kernelwernel/VMAware/blob/main/docs/documentation.md#vmpercentage
     */
    static u8 percentage(const flagset p_flags = DEFAULT) {
        VM::flags = p_flags;

        if (memo::is_memoized()) {
#ifdef __VMAWARE_DEBUG__
            debug("memoization: ", "returned cached result in VM::percentage()");
#endif
            return (memo::get_percent());
        }

        u16 points = 0;

        for (auto it = table.cbegin(); it != table.cend(); ++it) {
            const technique& pair = it->second;
            if (pair.ptr()) { // equivalent to std::invoke, not used bc of C++11 compatibility
                points += pair.points;
            }
        }

        u8 percent = 0;

        if (points > 100) {
            percent = 100;
        }
        else {
            percent = static_cast<u8>(points);
        }

        if (util::disabled(NO_MEMO)) {
            memo::memoize(memo::FOUND_PERCENT, memo::UNUSED_VM, memo::UNUSED_BRAND, percent);
        }

        return percent;
    }
};

MSVC_ENABLE_WARNING(4626 4514)

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
    { VM::THREADEXPERT, 0 },
    { VM::CWSANDBOX, 0 },
    { VM::COMODO, 0 },
    { VM::SUNBELT, 0 },
    { VM::BOCHS, 0 }
};


std::map<bool, VM::memo::memo_struct> VM::memo::cache;
VM::flagset VM::flags = 0;
VM::flagset VM::DEFAULT = []() -> flagset {
    flagset tmp;
    tmp.set(); // set all bits to 1
    tmp.flip(EXTREME);
    tmp.flip(NO_MEMO);
    return tmp;
}(); 


bool VM::cpuid_supported = []() -> bool {
    #if (!x86)
        return false;
    #elif (MSVC)
        int32_t info[4];
        __cpuid(info, 0);
        return (info[0] > 0);
    #elif (LINUX)
        u32 ext = 0;
        return (__get_cpuid_max(ext, nullptr) > 0);
    #else
        return false;
    #endif
}();


// the 0~100 points are debatable, but I think it's fine how it is. Feel free to disagree.
const std::map<VM::u8, VM::technique> VM::table = {
    { VM::VMID, { 100, VM::vmid }},
    { VM::BRAND, { 50, VM::cpu_brand }},
    { VM::HYPERVISOR_BIT, { 100, VM::hypervisor_bit }},
    { VM::CPUID_0X4, { 70, VM::cpuid_0x4 }},
    { VM::HYPERVISOR_STR, { 45, VM::hypervisor_brand }},
    { VM::RDTSC, { 20, VM::rdtsc_check }},
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
    { VM::SUNBELT_VM, { 10, VM::sunbelt_check }},
    { VM::WINE_CHECK, { 85, VM::wine }},
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
    { VM::GAMARUE, { 40, VM::gamarue }},
    { VM::WMIC, { 20, VM::wmic }},
    { VM::VMID_0X4, { 90, VM::vmid_0x4 }},
    { VM::PARALLELS_VM, { 50, VM::parallels }},
    { VM::RDTSC_VMEXIT, { 50, VM::rdtsc_vmexit }},
    { VM::LOADED_DLLS, { 75, VM::loaded_dlls }},
    { VM::QEMU_BRAND, { 100, VM::cpu_brand_qemu }},
    { VM::BOCHS_CPU, { 95, VM::bochs_cpu }},
    { VM::VPC_BOARD, { 20, VM::vpc_board }},
    { VM::HYPERV_WMI, { 80, VM::hyperv_wmi }},
    { VM::HYPERV_REG, { 80, VM::hyperv_registry }},
    { VM::BIOS_SERIAL, { 60, VM::bios_serial }},
    { VM::VBOX_FOLDERS, { 45, VM::vbox_shared_folders }},
    { VM::VBOX_MSSMBIOS, { 75, VM::vbox_mssmbios }},
    { VM::MAC_HYPERTHREAD, { 10, VM::mac_hyperthread }},
    { VM::MAC_MEMSIZE, { 30, VM::hw_memsize }},
    { VM::MAC_IOKIT, { 80, VM::io_kit }},
    { VM::IOREG_GREP, { 75, VM::ioreg_grep }},
    { VM::MAC_SIP, { 85, VM::mac_sip }},
    { VM::KVM_REG, { 75, VM::kvm_registry }},
    { VM::KVM_DRIVERS, { 55, VM::kvm_drivers }},
    { VM::KVM_DIRS, { 55, VM::kvm_directories }}

    // __TABLE_LABEL, add your technique above
    // { VM::FUNCTION, { POINTS, FUNCTION_POINTER }}
    // ^ template 
};
