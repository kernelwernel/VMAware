#pragma once

#include <functional>
#include <cstring>
#include <string>
#include <cstdlib>
#include <fstream>
#include <regex>
#include <thread>
#include <filesystem>
#include <iostream>
#include <limits>
#include <cstdint>
#include <bit>


// shorter and succinct macros
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
#if (defined(__APPLE__) || defined(__APPLE_CPP__))
    #define APPLE 1
#else
    #define APPLE 0
#endif
#if !(defined (MSVC) || defined(LINUX) || defined(APPLE))
    #warning "Unknown OS detected, tests will be severely limited"
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
    using f32 = float;
    using sv  = std::string_view;

    #if __has_cpp_attribute(__gnu__::__hot__)
    #define HOT [[__gnu__::__hot__]]
    #else
    #define HOT
    #endif

    #if (LINUX)
        // fetch file data
        [[nodiscard]] HOT static std::string getdata(const char* dir) {
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
        [[nodiscard]] HOT static std::unique_ptr<std::string> GetSysResult(const char *cmd) {
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
        }
    #endif

    // VM scoreboard table specifically for VM::brand()
    static inline std::unordered_map<sv, u8> VM_brands {
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
        { "Virtual Apple", 0 }
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
            a = x[0];
            b = x[1];
            c = x[2];
            d = x[3];
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

    // memoize the value from VM::detect() in case it's ran again
    static inline std::unordered_map<bool, std::pair<bool, sv>> memo;

    // cpuid check value
    static inline bool no_cpuid;

    // flags
    static inline u64 flags;





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

        // WINDOWS
        CURSOR = 1 << 30,

        ALL = std::numeric_limits<u64>::max();

private:
    // This can't be a lambda like the rest of the tests due to MSVC's assembler not allowing it for some random ass fucking reason
    // https://kb.vmware.com/s/article/1009458
/*
    static bool vmware_port(void) {
        /* TODO: find a solution for this
        if (!(flags & VMWARE_PORT)) {
            return false;
        }
        */
/*
        u32 a, b, c, d = 0;
        
        constexpr u32 vmware_magic = 0x564D5868, // magic hypervisor ID
                      vmware_port  = 0x5658,     // hypervisor port number
                      vmware_cmd   = 10,         // Getversion command identifier
                      u32_max      = std::numeric_limits<u32>::max(); // max for u32, idk why but it's required lol

        #if (LINUX)
            __asm__ __volatile__(
                "inl (%%dx)"
                : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                : "0"(0x564D5868), "1"(10), "2"(0x5658), "3"(0xFFFFFFFF)
                : "memory"
            );
        #elif (MSVC) // TODO: fix this code, i'm 99% sure it doesn't work anyway
            __asm {
                mov eax, vmware_magic
                mov ebx, vmware_cmd
                mov ecx, vmware_port
                mov edx, 0xFFFFFFFF
                in eax, dx
                mov vmware_magic, eax
                mov vmware_cmd, ecx
                mov vmware_port, edx
            }
        #endif

        if (b == vmware_magic) {
            VM_brands["VMware"]++;
            return true;
        }

        return false;
    };
*/
/*
    bool CheckHypervisorPort(void) {
    int is_vm = false;

    try {

        //#if (LINUX)

        u32 a, b, c, d = 0;

        constexpr u32 vmware_magic = 0x564D5868, // magic hypervisor ID
                    vmware_port  = 0x5658,     // hypervisor port number
                    vmware_cmd   = 10,         // Getversion command identifier
                    u32_max      = std::numeric_limits<u32>::max(); // max for u32, idk why but it's required lol

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
            "setzl %0\n\t"
            "popl %%ebx\n\t"
            "popl %%ecx\n\t"
            "popl %%edx\n\t"
            : "=a" (a), "=b" (b), "=c" (c), "=d" (d)
            : "0" (is_vm)
            : "memory"
        );


        #if _WIN32
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

        return is_vm;   
    } catch (...) {
        return false;
    }
}
*/





























    #if __x86_64__
        // check CPUID output of manufacturer ID for known VMs/hypervisors
        [[nodiscard]] bool vmid() try {
            if (no_cpuid || !(flags & VMID)) {
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

            // TODO: replace this fucking garbage
            auto cpuid_ex = [](u32 p_leaf, u32* regs, std::size_t start = 0, std::size_t end = 4) -> bool {
                #if (MSVC)
                    i32 x[4];
                    __cpuid((int*)x, leaf); 
                #elif (LINUX)
                    u32 x[4];
                    __cpuid(p_leaf, x[0], x[1], x[2], x[3]);
                #endif

                for (; start < end; start++) { 
                    *regs++ = static_cast<u32>(x[start]);
                }

                return true;
            };

            std::string brand = "";

            u32 sig_reg[3] = {0};
            if (!cpuid_ex(0, sig_reg, 1)) { return false; }

            u32 features;
            cpuid_ex(1, &features, 2, 3);

            auto strconvert = [](u64 n) -> std::string {
                const std::string &str(reinterpret_cast<char*>(&n));
                return str;
            };

            std::stringstream ss;
            ss << strconvert(sig_reg[0]);
            ss << strconvert(sig_reg[2]);
            ss << strconvert(sig_reg[1]);

            brand = ss.str();

            bool found = (std::find(std::begin(IDs), std::end(IDs), brand) != std::end(IDs));

            if (found) {
                if (brand == bhyve) { VM_brands["bhyve"]++; }
                if (brand == kvm) { VM_brands["KVM"]++; }
                if (brand == qemu) [[likely]] { VM_brands["QEMU"]++; }
                if (brand == hyperv) { VM_brands["Microsoft Hyper-V"]++; }
                if (brand == xta) { VM_brands["Microsoft x86-to-ARM"]++; }
                if (brand == vmware) [[likely]] { VM_brands["VMware"]++; }
                if (brand == vbox) [[likely]] { VM_brands["VirtualBox"]++; }
                if (brand == parallels) { VM_brands["Parallels"]++; }
                if (brand == parallels2) { VM_brands["Parallels"]++; }
                if (brand == xen) { VM_brands["Xen HVM"]++; }
                if (brand == acrn) { VM_brands["ACRN"]++; }
                if (brand == qnx) { VM_brands["QNX hypervisor"]++; }
                if (brand == virtapple) { VM_brands["Virtual Apple"]++; }
            }

            return found;
        } catch (...) { return false; }


        // check if CPU brand is a VM brand
        [[nodiscard]] bool cpu_brand() try {
            if (no_cpuid || !(flags & BRAND)) {
                return false;
            }

            // todo: check if this is even needed
            #if (LINUX)
                if (!__get_cpuid_max(0x80000004, nullptr)) {
                    return false;
                }
            #endif

            std::array<int, 4> intbuffer{};
            constexpr std::size_t intbufsize = sizeof(i32) * intbuffer.size();
            std::array<char, 64> charbuffer{};

            constexpr std::array<u32, 3> ids = {
                leaf::brand1,
                leaf::brand2,
                leaf::brand3
            };

            std::string brand{};

            for (const u32 &id : ids) {
                #if (MSVC)
                    __cpuid(intbuffer.data(), id);
                #elif (LINUX)
                    __cpuid(id, intbuffer.at(0), intbuffer.at(1), intbuffer.at(2), intbuffer.at(3));
                #endif

                std::memcpy(charbuffer.data(), intbuffer.data(), intbufsize);
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
        } catch (...) { return false; }

        // check if hypervisor feature bit in CPUID is enabled (always false for physical CPUs)
        [[nodiscard]] bool cpuid_hyperv() try {
            if (no_cpuid || !(flags & HYPERV_BIT)) {
                return false;
            }

            u32 unused, ecx = 0;

            cpuid(unused, unused, ecx, unused, 1);

            return (ecx & (1 << 31));
        } catch (...) { return false; }

        // check if 0x40000000~0x400000FF cpuid input is present (mostly present in VMs), at least according to https://kb.vmware.com/s/article/1009458
        [[nodiscard]] bool cpuid_0x4() try {
            if (no_cpuid || !(flags & CPUID_0x4)) {
                return false;
            }

            u32 a, b, c, d = 0;

            for (u8 i = 0; i < 0xFF; i++) {
                cpuid(a, b, c, d, (leaf::hyperv + i));
                if ((a + b + c + d) != 0) { return true; }
            }

            return false;
        } catch (...) { return false; }

        // check for hypervisor brand string length (would be around 2 characters in a host machine)
        [[nodiscard]] bool hyperv_brand() try {
            if (!(flags & HYPERV_STR)) {
                return false;
            }

            char out[sizeof(i32) * 4 + 1] = { 0 }; // e*x size + number of e*x registers + null terminator
            cpuid((int*)out, leaf::hyperv);
            return (std::strlen(out + 4) >= 4);
        } catch (...) { return false; }

        // check if RDTSC is slow, if it is then it might be a VM
        [[nodiscard]] bool rdtsc_check() try {
            if (!(flags & RDTSC)) {
                return false;
            }

            #if (LINUX)
                u32 a, b, c, d = 0;

                if (!__get_cpuid(leaf::proc_ext, &a, &b, &c, &d)) {
                    if (!(d & (1 << 27))) { return false; }
                }
                
                u32 s, acc = 0;
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
        } catch (...) { return false; }

        // check for vm presence using sidt instruction (TODO: check if this actually works)
        // credits: https://unprotect.it/technique/sidt-red-pill/
        [[nodiscard]] bool sidt_check() try {
            if (!(flags & SIDT)) {
                return false;
            }

            u64 idtr = 0;

            __asm__ __volatile__(
                "sidt %0"
                : "=m" (idtr)
            );

            return (idtr != 0);
        } catch (...) { return false; }
    #endif




























    // Check if processor count is 1 or 2 (some VMs only have a single core)
    [[nodiscard]] bool thread_count() try {
        if (!(flags & THREADCOUNT)) {
            return false;
        }

        return (std::thread::hardware_concurrency() <= 2);
    } catch (...) { return false; }
    

    // check if mac address starts with certain VM designated values
    [[nodiscard]] bool mac_address_check() try {
        if (!(flags & MAC)) {
            return false;
        }

        u8 mac[6];

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

            if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { return false; }

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

        return (
            // i'm not gonna make constexpr magic numbers for all of these, fuck that
            (mac[0] == 0x08 && mac[1] == 0x00 && mac[2] == 0x27) || // vbox

            (mac[0] == 0x00 && mac[1] == 0x0C && mac[2] == 0x29) || // vmware for all 4
            (mac[0] == 0x00 && mac[1] == 0x1C && mac[2] == 0x14) ||
            (mac[0] == 0x00 && mac[1] == 0x50 && mac[2] == 0x56) ||
            (mac[0] == 0x00 && mac[1] == 0x05 && mac[2] == 0x69) ||

            (mac[0] == 0x00 && mac[1] == 0x16 && mac[2] == 0xE3) || // Xen

            (mac[0] == 0x00 && mac[1] == 0x1C && mac[2] == 0x42) || // parallels
            (mac[0] == 0x0A && mac[1] == 0x00 && mac[2] == 0x27)    // hybrid analysis
        );
    } catch (...) { return false; }























            
#if (LINUX)
    // check if thermal directory is present, might not be present in VMs
    [[nodiscard]] bool temperature() try {
        if (!(flags & TEMPERATURE)) {
            return false;
        }

        return (!fs::exists("/sys/class/thermal/thermal_zone0/"));
    } catch (...) { return false; }


    // get result from systemd-detect-virt tool
    [[nodiscard]] bool systemd_virt() try {
        if (!(flags & SYSTEMD)) {
            return false;
        }

        if (!(fs::exists("/usr/bin/systemd-detect-virt") || fs::exists("/bin/systemd-detect-virt"))) {
            return false;
        }

        const std::unique_ptr<std::string> &result = GetSysResult("systemd-detect-virt");
        if (result == nullptr) { return false; }
        return (*result != "none");
    } catch (...) { return false; }


    // check if chassis vendor is a VM vendor
    [[nodiscard]] bool chassis_vendor() try {
        if (!(flags & CVENDOR)) {
            return false;
        }

        const char* vendor_file = "/sys/devices/virtual/dmi/id/chassis_vendor";

        if (fs::exists(vendor_file)) {
            const sv &vendor = getdata(vendor_file);
            constexpr std::array<sv, 2> ChassisVMs = {
                "QEMU", 
                "Oracle Corporation" 
            };

            for (auto ptr{ &ChassisVMs[0] }; ptr != &ChassisVMs[0] + std::size(ChassisVMs); ++ptr) {
                if (*ptr == vendor) { return true; }
            }
        }

        return false;
    } catch (...) { return false; }


    // Check if chassis type is invalid or not, might be a VM
    [[nodiscard]] bool chassis_type() try {
        if (!(flags & CTYPE)) {
            return false;
        }

        const char* chassis = "/sys/devices/virtual/dmi/id/chassis_type";
        
        if (fs::exists(chassis)) {
            return (stoi(getdata(chassis)) == 1);
        }

        return false;
    } catch (...) { return false; }


    // check if /.dockerenv or /.dockerinit file is present (most likely a docker container)
    [[nodiscard]] bool dockerenv() try {
        if (!(flags & DOCKER)) {
            return false;
        }

        return (fs::exists("/.dockerenv") || fs::exists("/.dockerinit"));
    } catch (...) { return false; }


    // check if demidecode output matches a VM brand
    [[nodiscard]] bool dmidecode() try {
        if (!(flags & DMIDECODE)) {
            return false;
        }

        if (!fs::exists("/bin/dmidecode") && !fs::exists("/usr/bin/dmidecode")) { return false; }
        
        if (getuid()) { 
            return false; 
        }

        return (stoi(*GetSysResult("dmidecode -t system | grep 'Manufacturer|Product' | grep -c \"QEMU|VirtualBox|KVM\"")) >= 1);
    } catch (...) { return false; }


    // check if dmesg command output matches a VM brand
    [[nodiscard]] bool dmesg() try {
        if (!(flags & DMESG)) {
            return false;
        }

        if (!fs::exists("/bin/dmesg") && !fs::exists("/usr/bin/dmesg")) { return false; }
        return (stoi(*GetSysResult("dmesg | grep -i hypervisor | grep -c \"KVM|QEMU\"")));
    } catch (...) { return false; }


    // check if /sys/class/hwmon/ directory is present. If not, likely a VM
    [[nodiscard]] bool hwmon = [&]() -> bool {
        if (!(flags & HWMON)) {
            return false;
        }

        return (!fs::exists("/sys/class/hwmon/"));
    } catch (...) { return false; }
    

    // [[nodiscard]] bool dmi_check() try {
    //     char string[10];
    //     GET_BIOS_SERIAL(string);
    //     if (!memcmp(string, "VMware-", 7) || !memcmp(string, "VMW", 3)) { return true; }
    //     else { return false; }
    // } catch (...) { return false; }












































public:
    [[nodiscard]] static bool check(const u64 flags) {
        const i32 count = std::popcount(flags);

        if (count > 1) {
            throw std::invalid_argument("Flag argument must only contain a single option, consult the documentation's flag list");
        }

        if (count == 0) {
            throw std::invalid_argument("Flag argument must contain at least a single option, consult the documentation's flag list");
        }

        // TODO: finish with the flag system here        
    }


    [[nodiscard]] static sv brand(void) {
        // check if result hasn't been memoized already
        if (memo.find(true) == memo.end()) {
            bool tmp = detect(); // [[nodiscard]] workaround
        }

        // check if no VM was detected
        if (memo[true].first == false) {
            return "Unknown"
        }

        return (memo[true].second);
    }


    [[nodiscard]] static bool detect(const u64 flags = (~(CURSOR) & ALL)) {
        namespace fs = std::filesystem;

        // load memoized value if it exists
        if (memo.find(true) != memo.end()) {
            return memo[true].first;
        }

        // check if cpuid isn't available
        VM::no_cpuid = !check_cpuid();



        std::cout << (vmid() ? "[  \x1B[38;2;94;214;114mDETECTED\x1B[0m  ]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]") << " Checking VMID...\n";
        std::cout << (cpu_brand() ? "[  \x1B[38;2;94;214;114mDETECTED\x1B[0m  ]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]") << " Checking CPU brand...\n";
        std::cout << (cpuid_hyperv() ? "[  \x1B[38;2;94;214;114mDETECTED\x1B[0m  ]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]") << " Checking CPUID hypervisor bit...\n";
        std::cout << (cpuid_0x4() ? "[  \x1B[38;2;94;214;114mDETECTED\x1B[0m  ]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]") << " Checking CPUID 0x4 leaf...\n";
        std::cout << (hyperv_brand() ? "[  \x1B[38;2;94;214;114mDETECTED\x1B[0m  ]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]") << " Checking hypervisor brand...\n";
        std::cout << (rdtsc_check() ? "[  \x1B[38;2;94;214;114mDETECTED\x1B[0m  ]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]") << " Checking RDTSC...\n";
        std::cout << (sidt_check() ? "[  \x1B[38;2;94;214;114mDETECTED\x1B[0m  ]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]") << " Checking sidt...\n";
        //std::cout << (vmware_port() ? "[  \x1B[38;2;94;214;114mDETECTED\x1B[0m  ]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]") << " Checking VMware port...\n";
        std::cout << (thread_count() ? "[  \x1B[38;2;94;214;114mDETECTED\x1B[0m  ]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]") << " Checking processor count...\n";
        std::cout << (mac_address_check() ? "[  \x1B[38;2;94;214;114mDETECTED\x1B[0m  ]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]") << " Checking MAC address...\n";
        std::cout << (temperature() ? "[  \x1B[38;2;94;214;114mDETECTED\x1B[0m  ]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]") << " Checking temperature...\n";
        std::cout << (systemd_virt() ? "[  \x1B[38;2;94;214;114mDETECTED\x1B[0m  ]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]") << " Checking systemd virtualisation...\n";
        std::cout << (chassis_vendor() ? "[  \x1B[38;2;94;214;114mDETECTED\x1B[0m  ]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]") << " Checking chassis vendor...\n";
        std::cout << (chassis_type() ? "[  \x1B[38;2;94;214;114mDETECTED\x1B[0m  ]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]") << " Checking chassis type...\n";
        std::cout << (dockerenv() ? "[  \x1B[38;2;94;214;114mDETECTED\x1B[0m  ]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]") << " Checking Dockerenv...\n";
        std::cout << (dmidecode() ? "[  \x1B[38;2;94;214;114mDETECTED\x1B[0m  ]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]") << " Checking dmidecode output...\n";
        std::cout << (dmesg() ? "[  \x1B[38;2;94;214;114mDETECTED\x1B[0m  ]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]") << " Checking dmesg output...\n";
        std::cout << (hwmon() ? "[  \x1B[38;2;94;214;114mDETECTED\x1B[0m  ]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]") << " Checking hwmon presence...\n";
        std::cout << "\n\n";

        f32 points = 0;

        if (thread_count()) { /*std::cout << "\nproccount: "*/ points += 1.5; }
        if (mac_address_check()) { /*std::cout << "\nmac: "*/ points += 3.5; }

        #if __x86_64__
            if (vmid()) { /*std::cout << "vmid: "*/ points += 6.5; }
            if (cpu_brand()) { /*std::cout << "\ncpubrand: "*/ points += 3; }
            if (cpuid_hyperv()) { /*std::cout << "\ncpuidhyperv: "*/ points += 5.5; }
            if (cpuid_0x4()) { /*std::cout << "\n0x4cpuid: "*/ points += 4; }
            if (hyperv_brand()) { /*std::cout << "\nhypervbrand: "*/ points += 4; }
            if (rdtsc_check()) { /*std::cout << "\nrdtsc: "*/ points += 1.5; }
            if (sidt_check()) { /*std::cout << "\nsidt: "*/ points += 4; }
            //if (vmware_port()) { /*std::cout << "\nvmwareport: "*/ points += 3; }
        #endif

        #if (LINUX)
            if (temperature()) { /*std::cout << "\ntemperature: "*/ points += 1; }
            if (systemd_virt()) { /*std::cout << "\nsystemd-virt: "*/ points += 5; }
            if (chassis_vendor()) { /*std::cout << "\nchassisvendor: "*/ points += 4.5; }
            if (chassis_type()) { /*std::cout << "\nchassistype: "*/ points += 1; }
            if (dockerenv()) { /*std::cout << "\ndockerenv: "*/ points += 3; }
            if (dmidecode()) { /*std::cout << "\ndmidecode: "*/ points += 4; }
            if (dmesg()) { /*std::cout << "\ndmesg: "*/ points += 3.5; }
            if (hwmon()) { /*std::cout << "\nhwmon: "*/ points += 0.5; }
        #elif (MSVC)
            if (VBoxCheck()) { /*std::cout << "\nvbox: "*/ points += 6.5; }
            if (VBoxCheck2()) { /*std::cout << "\nvbox2: "*/ points += 6.5; }
            if (VMwareCheck()) { /*std::cout << "\nvmware: "*/ points += 6.5; }
            if (VPC()) { /*std::cout << "\nvpc: "*/ points += 2; }
            if (CheckSandboxie()) { /*std::cout << "\nsandboxie: "*/ points += 4; }
            if (RegKeyVM()) { /*std::cout << "\nregkey: ";*/ points += 5; }
            if (RegKeyStrSearch()) { /*std::cout << "\nregkeystr: ";*/ points += 5; }
        #endif

/*
        std::cout << "\n\n RESULT: " << points << "/62 points, meets VM detection threashold " << (points / 6.5) << " times over\n\n";

        for (const auto& pair : VM_brands) {
            std::cout << (int)pair.second << " = " << pair.first << std::endl;
        }
*/
        /** 
         * you can change this threshold score to a maximum
         * of something like 10~14 if you want to be extremely
         * sure, but this can risk the result to be a false
         * negative if the detection bar is far too high.
         */
        const bool result = (points >= 6.5);

        // memoize the result in case VM::detect() is executed again
        memo[true].first = result;

        return result;
    }
};