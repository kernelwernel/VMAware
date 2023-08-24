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

#if defined(_MSC_VER)
    #include <intrin.h>
    #include <windows.h>
    #include <tchar.h>
    #include <stdbool.h>
    #include <stdio.h>
    #include <Iphlpapi.h>
    #include <Assert.h>
    #include <excpt.h>
    #pragma comment(lib, "iphlpapi.lib")
#elif defined(__clang__) || defined(__GNUC__)
    #include <cpuid.h>
    #include <x86intrin.h>
    #include <sys/stat.h>
    #include <sys/ioctl.h>
    #include <net/if.h> 
    #include <unistd.h>
    #include <netinet/in.h>
    #include <string.h>
    #include <memory>
#else
    #error "Unknown OS detected" 
#endif

/**
 * LINKS:
 *  https://artemonsecurity.com/vmde.pdf <= super useful
 *  https://stackoverflow.com/questions/41750144/c-how-to-detect-the-virtual-machine-your-application-is-running-in-has-focus
 *  https://www.first.org/resources/papers/conf2017/Countering-Innovative-Sandbox-Evasion-Techniques-Used-by-Malware.pdf <= extremely useful
 *  https://github.com/rrbranco/blackhat2012/blob/master/Csrc/VMDetection/VMDetection/VMDetection.cpp <= has loads of cool stuff
 * 
 * WINDOWS:
 *  https://berhanbingol.medium.com/virtualbox-detection-anti-detection-eng-54a4cde1b509
 *  https://intellitect.com/blog/how-to-detect-virtual-machine-execution/
 *  https://litigationconferences.com/wp-content/uploads/2017/05/Introduction-to-Evasive-Techniques-v1.0.pdf <= has further windows detections
 *  https://unprotect.it/technique/detecting-virtual-environment-process/ <= very helpful
 * 
 *  https://artemonsecurity.com/vmde.pdf <= has tons of potentially useful functions
 * 
 * https://stackoverflow.com/q/731428/18517076

 * 
 * NOTES:
 *  VMwareService.exe runs the VMware Tools Service as a child of services.exe. It can be identified by listing services.
 * https://www.codeproject.com/Articles/9823/Detect-if-your-program-is-running-inside-a-Virtual <= contains windows specific shit but it's useful
 * check ScoopyNG downloaded C source code for more detections <= important
 * 
 * 
 * 
 * https://evasions.checkpoint.com/ <= EXTREMELY IMPORTANT!!!!!!
 * 
 */


class VM {
private:
    using u8  = std::uint8_t;
    using u16 = std::uint16_t;
    using u32 = std::uint32_t;
    using u64 = std::uint64_t;
    using i8  = std::int8_t;
    using i16 = std::int16_t;
    using i32 = std::int32_t;
    using i64 = std::int64_t;
    using f32 = float;
    using f64 = double;
    using sv  = std::string_view;
    namespace fs = std::namespace;

    // memoize the value from VM::detect() in case it's ran again
    static inline std::unordered_map<bool, std::pair<bool, sv>> memo;

    #if __has_cpp_attribute(__gnu__::__hot__)
    [[__gnu__::__hot__]]
    #endif
    static std::string getdata(const char* dir) {
        std::ifstream file{};
        std::string data{};
        file.open(dir);
        if (file.is_open()) {
            file >> data;
        }
        file.close(); 
        return data;
    };

    #if __linux__
        #if __has_cpp_attribute(__gnu__::__hot__)
        [[__gnu__::__hot__]]
        #endif
        [[nodiscard]] static std::unique_ptr<std::string> GetSysResult(const char *cmd) noexcept {
            std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
            if (!pipe) { return nullptr; }
            std::string result{};
            std::array<char, 128> buffer{};
            while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
                result += buffer.data();
            }
            result.pop_back();
            return std::make_unique<std::string>(result);
        }
    #endif

    std::unordered_map<sv, uint8_t> VM_brands {
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
        { "Wine", 0 }
    };

public:
    [[nodiscard]] static bool detect(void) {
        if (memo.find(true) != memo.end()) {
            std::cout << "\n\n\nworks!\n\n\n";
            return memo[true].first;
        }

        #if __x86_64__
            // check CPUID output of manufacturer ID for known VMs






































            auto VMID = []() -> bool {
                try {
                    auto GetID = []() -> std::string {
                        auto cpuid_ex = [](unsigned int leaf, uint32_t* regs, size_t start = 0, size_t end = 4) -> bool {
                            #if (!defined(__x86_64__) && !defined(__i386__) && !defined(_M_IX86) && !defined(_M_X64))
                                return false;
                            #elif defined(_MSC_VER) || defined(__INTEL_COMPILER)
                                int x[4];
                                __cpuid((int*)x, leaf); 
                            #elif defined(__clang__) || defined(__GNUC__)
                                unsigned int x[4];
                                __cpuid(leaf, x[0], x[1], x[2], x[3]);
                            #else
                                return false;
                            #endif

                            for (; start < end; start++) { *regs++ = static_cast<uint32_t>(x[start]); } 
                            return true;
                        };

                        uint32_t sig_reg[3] = {0};
                        if (!cpuid_ex(0, sig_reg, 1)) { return "Not detected"; }

                        uint32_t features;
                        cpuid_ex(1, &features, 2, 3);

                        auto strconvert = [](uint64_t n) -> std::string {
                            const std::string &str(reinterpret_cast<char*>(&n));
                            return str;
                        };

                        std::stringstream ss;
                        ss << strconvert(sig_reg[0]);
                        ss << strconvert(sig_reg[2]);
                        ss << strconvert(sig_reg[1]);
                        return ss.str();
                    };

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

/*
                    constexpr std::array<sv, 13> IDs {
                        "bhyve bhyve ", " KVMKVMKVM  ", "TCGTCGTCGTCG",
                        "Microsoft Hv", "MicrosoftXTA", " prl hyperv ",
                        " lrpepyh  vr", "VMwareVMware", "VBoxVBoxVBox",
                        "XenVMMXenVMM", "ACRNACRNACRN", " QNXQVMBSQG ",
                        "VirtualApple"
                    };
*/


                    std::string brand = GetID();

                    bool found = (std::find(std::begin(IDs), std::end(IDs), brand) != std::end(IDs));

                    if (!found) {
                                
                    }

                    return found;
                } catch (...) { return false; }
            };






































            // check if CPU brand is a VM brand
            auto CPUbrand = []() -> bool {
                try {
                    #if __linux__
                        if (!__get_cpuid_max(0x80000004, NULL)) {
                            return "Unknown";
                        }
                    #endif
                    std::array<int, 4> intbuffer{};
                    constexpr size_t intbufsize = sizeof(int) * intbuffer.size();
                    std::array<char, 64> charbuffer{};
                    constexpr std::array<uint32_t, 3> ids = {
                        0x80000002,
                        0x80000003,
                        0x80000004
                    };

                    std::string brand{};

                    for (const uint32_t &id : ids) {
                        #if _MSC_VER
                            __cpuid(intbuffer.data(), id);
                        #elif __linux__
                            __cpuid(id, intbuffer.at(0), intbuffer.at(1), intbuffer.at(2), intbuffer.at(3));
                        #endif

                        memcpy(charbuffer.data(), intbuffer.data(), intbufsize);
                        brand += sv(charbuffer.data());
                    }

                    // TODO: might add more potential keywords, be aware that it could (theoretically) cause false positives
                    constexpr std::array<const char*, 16> vmkeywords {
                        "qemu", "kvm", "virtual", "vm", 
                        "vbox", "virtualbox", "vmm", "monitor", 
                        "bhyve", "hyperv", "hypervisor", "hvisor", 
                        "parallels", "vmware", "hvm", "qnx"
                    };

                    uint8_t matches = 0;    
                    for (size_t i = 0; i < vmkeywords.size(); i++) {
                        auto const regex = std::regex(vmkeywords.at(i), std::regex::icase);
                        matches += std::regex_search(brand, regex);
                    }

                    return (matches >= 1);
                } catch (...) { return false; }
            };

            // check if hypervisor feature bit in CPUID is enabled (always false for physical CPUs)
            auto CPUIDhyperv = []() -> bool {
                try {
                    uint32_t unused, ecx = 0;
                    __asm__ __volatile__(
                        "cpuid;"
                        : "=a" (unused), "=b" (unused), "=c" (ecx), "=d" (unused)
                        : "0" (0x1)
                    );

                    return (ecx & (1 << 31));
                } catch (...) { return false; }
            };

            // check if 0x40000000~0x400000FF cpuid input is present (mostly present in VMs)
            auto Check0x4CPUID = []() -> bool {
                try {
                    uint8_t leafcount = 0;
                    for (size_t i = 0; i < 256; i++) {
                        volatile uint32_t eax, ebx, ecx, edx = 0;
                        __asm__ __volatile__(
                            "cpuid;"
                            : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx)
                            : "0" (0x40000000 + i)
                        );
                        if (!(eax == 0 && ebx == 0 && ecx == 0 && edx == 0)) { leafcount += 1; }
                    }
                    return (leafcount >= 1);
                } catch (...) { return false; }
            };

            // check for hypervisor brand string length (would be around 2 characters in a host machine)
            auto HyperVbrand = []() {
                try {
                    char out[4 * 4 + 1] = { 0 };
                    __cpuidex((int*)out, 0x40000000, 0);
                    return (strlen(out + 4) >= 4);
                } catch (...) { return false; }
            };

            // check if RDTSC is slow, if it is then it might be a VM
            auto RDTSCcheck = []() -> bool {
                try {
                    #if __linux__
                        unsigned a, b, c, d = 0;
                        if (!__get_cpuid(0x80000001, &a, &b, &c, &d) && (d & (1<<27))) { return false; }
                        uint32_t s, acc = 0;
                        int out[4];
                        for (size_t i = 0; i < 100; ++i) {
                            s = __rdtsc();
                            __cpuidex(out, 0, 0);
                            acc += __rdtsc() - s;
                            
                        }
                        return (acc / 100 > 350);
                    #elif _MSC_VER
                        ULONGLONG tsc1 = 0;
                        ULONGLONG tsc2 = 0;
                        ULONGLONG avg = 0;
                        INT cpuInfo[4] = {};
                        for (INT i = 0; i < 10; i++)
                        {
                            tsc1 = __rdtsc();
                            __cpuid(cpuInfo, 0);
                            tsc2 = __rdtsc();
                            avg += (tsc2 - tsc1);
                        }
                        avg = avg / 10;
                        return (avg < 1000 && avg > 0) ? false : true;
                    #else
                        return false;
                    #endif
                } catch (...) { return false; }
            };

            // check for vm presence using sidt instruction (TODO: check if this actually works)
            auto sidtcheck = []() {
                try {
                    unsigned char idtr[6];
                    unsigned long idt = 0;

                    R"(
                        sidt idtr
                    )";

                    idt = *((unsigned long *)&idtr[2]);
                    return ((idt >> 24) == 0xff);
                } catch (...) { return false; }
            };

            // check for VMware port (TODO: check if this actually works)
            auto VMwarePort = []() -> bool {
                bool rc = false;
                try {
                    R"(
                        push edx
                        push ecx
                        push ebx
                        mov eax, 'VMXh'
                        mov ebx, 0
                        mov ecx, 10
                        mov edx, 'VX'
                        in eax, dx
                        cmp ebx, 'VMXh'
                        setz [rc]
                        pop ebx
                        pop ecx
                        pop edx
                    )";

                } catch (...) { return false; }
                return rc;
            };
        #endif

        // Check if processor count is 1 or 2 (some VMs only have a single core)
        auto ProcessorCount = []() -> bool {
            try {
                return (std::thread::hardware_concurrency() <= 2);
            } catch (...) { return false; }
        };

        // check if mac address starts with certain VM designated values
        auto MacCheck = []() -> bool {
            try {
                unsigned char mac[6];
                #if defined(__clang__) || defined(__GNUC__)
                    struct ifreq ifr;
                    struct ifconf ifc;
                    char buf[1024];
                    int success = 0;

                    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
                    if (sock == -1) { return false; };

                    ifc.ifc_len = sizeof(buf);
                    ifc.ifc_buf = buf;
                    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) { return false; }

                    struct ifreq* it = ifc.ifc_req;
                    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

                    for (; it != end; ++it) {
                        strcpy(ifr.ifr_name, it->ifr_name);
                        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
                            if (! (ifr.ifr_flags & IFF_LOOPBACK)) {
                                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                                    success = 1;
                                    break;
                                }
                            }
                        }
                        else { return false; }
                    }
                    if (success) { memcpy(mac, ifr.ifr_hwaddr.sa_data, 6); }
                #elif _MSC_VER
                    PIP_ADAPTER_INFO AdapterInfo;
                    DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);
                    char *mac_addr = (char*)malloc(18);

                    AdapterInfo = (IP_ADAPTER_INFO *) malloc(sizeof(IP_ADAPTER_INFO));
                    if (AdapterInfo == NULL) {
                        free(mac_addr);
                        return false;
                    }

                    if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
                        free(AdapterInfo);
                        AdapterInfo = (IP_ADAPTER_INFO *) malloc(dwBufLen);
                        if (AdapterInfo == NULL) {
                            free(mac_addr);
                            return false;
                        }
                    }

                    if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) {
                        PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
                        for (size_t i = 0; i < 6; i++) {
                            mac[i] = pAdapterInfo->Address[i];
                        }
                    }
                    free(AdapterInfo);
                #else
                    return false;
                #endif

                return (
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
        };

        auto VMwareHviserPort = []() -> bool {
            uint32_t eax, ebx, ecx, edx = 0;
            __asm__ __volatile__(
                "inl (%%dx)"
                : "=a"(eax), "=c"(ecx), "=d"(edx), "=b"(ebx)
                : "0"(0x564D5868), "1"(10), "2"(0x5658), "3"(std::numeric_limits<unsigned int>::max())
                : "memory"
            );

            return (ebx == 0x564D5868);
        };
/*
        auto dmi_check = []() {
            char string[10];
            GET_BIOS_SERIAL(string);
            if (!memcmp(string, "VMware-", 7) || !memcmp(string, "VMW", 3)) { return true; }
            else { return false; }
        }
*/
        #if __linux__
            // check if thermal directory is present, might not be present in VMs
            auto CheckTemperature = []() -> bool {
                try {
                    return (!fs::exists("/sys/class/thermal/thermal_zone0/"));
                } catch (...) { return false; }
            };

            // get result from systemd-detect-virt tool
            auto SystemdVirt = []() -> bool {
                try {
                    if (fs::exists("/usr/bin/systemd-detect-virt") || fs::exists("/bin/systemd-detect-virt")) {
                        const std::unique_ptr<std::string> &result = GetSysResult("systemd-detect-virt");
                        if (result == nullptr) { return false; }
                        return (*result != "none");
                    }
                    return false;
                } catch (...) { return false; }
            };

            // check if chassis vendor is a VM vendor
            auto ChassisVendor = []() -> bool {
                try {
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
            };

            // Check if chassis type is invalid or not, might be a VM
            auto ChassisType = []() noexcept -> bool {
                try {
                    const char* chassis = "/sys/devices/virtual/dmi/id/chassis_type";
                    return (
                        (fs::exists(chassis)) && \
                        (stoi(getdata(chassis)) == 1)
                    );
                } catch (...) { return false; }
            };

            // check if /.dockerenv or /.dockerinit file is present (most likely a docker container)
            auto Dockerenv = []() -> bool {
                try {
                    return (fs::exists("/.dockerenv") || fs::exists("/.dockerinit"));
                } catch (...) { return false; }
            };

            // check if demidecode output matches a VM brand
            auto dmidecode = []() -> bool {
                try {
                    if (!fs::exists("/bin/dmidecode") && !fs::exists("/usr/bin/dmidecode")) { return false; }
                    if (getuid()) { return false; }
                    return (stoi(*GetSysResult("dmidecode -t system | grep 'Manufacturer|Product' | grep -c \"QEMU|VirtualBox|KVM\"")) >= 1);
                } catch (...) { return false; }
            };

            // check if dmesg command output matches a VM brand
            auto dmesg = []() -> bool {
                try {
                    if (!fs::exists("/bin/dmesg") && !fs::exists("/usr/bin/dmesg")) { return false; }
                    return (stoi(*GetSysResult("dmesg | grep -i hypervisor | grep -c \"KVM|QEMU\"")));
                } catch (...) { return false; }
            };

            // check if /sys/class/hwmon/ directory is present. If not, likely a VM
            auto hwmon = []() -> bool {
                try {
                    struct stat info;
                    return (stat("/sys/class/hwmon/", &info) != 0);
                } catch (...) { return false; }
            };
        #elif _MSC_VER
            // Check vbox rdrdn
            auto VBoxCheck = []() -> bool {
                try {
                    HANDLE handle = CreateFile(_T("\\\\.\\VBoxMiniRdrDN"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                    if (handle != INVALID_HANDLE_VALUE) {
                        CloseHandle(handle);
                        return true;
                    }
                    return false;
                } catch (...) { return false; }
            }

            // check dsdt vbox
            auto VboxCheck2 = []() -> bool {
                try {
                    return (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\DSDT\\VBOX__", NULL, KEY_READ, &resultKey) == ERROR_SUCCESS);
                } catch (...) { return false; }
            };

            // find vmware tools presence
            auto VMwareCheck = []() -> bool {
                try {
                    HKEY hKey = 0;
                    DWORD dwType = REG_SZ;
                    char buf[255] = {0};
                    DWORD dwBufSize = sizeof(buf);
                    return (RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\VMware, Inc.\\VMware Tools"), 0, KEY_QUERY_VALUE, &hKey ) == ERROR_SUCCESS)
                } catch (...) { return false; }
            }

            auto VPC = []() -> bool {
                try {
                    auto IsInsideVPC_exceptionFilter = [](LPEXCEPTION_POINTERS ep) -> DWORD {
                        PCONTEXT ctx = ep->ContextRecord;
                        ctx->Ebx = -1;
                        ctx->Eip += 4;
                        return EXCEPTION_CONTINUE_EXECUTION;
                    }

                    auto InsideVPC = []() -> bool {
                        bool rc = false;
                        __try {
                            _asm push ebx
                            _asm mov  ebx, 0
                            _asm mov  eax, 1
                            _asm __emit 0Fh
                            _asm __emit 3Fh
                            _asm __emit 07h
                            _asm __emit 0Bh
                            _asm test ebx, ebx
                            _asm setz [rc]
                            _asm pop ebx
                        } __except(IsInsideVPC_exceptionFilter(GetExceptionInformation())) {};

                        return rc;
                    };
                } catch (...) { return false; }
            }

            auto CheckSandboxie = []() {
                BYTE IsSB = 0;
                ULONG hashA, hashB;
                HANDLE hKey;
                NTSTATUS Status;
                UNICODE_STRING ustrRegPath;
                OBJECT_ATTRIBUTES obja;

                WCHAR szObjectName[MAX_PATH * 2] = {0};
                hashA = HashFromStrW(REGSTR_KEY_USER);

                RtlInitUnicodeString(&ustrRegPath, REGSTR_KEY_USER);
                InitializeObjectAttributes(&obja, &ustrRegPath, OBJ_CASE_SENSITIVE, NULL, NULL);
                Status = NtOpenKey(&hKey, MAXIMUM_ALLOWED, &obja);
                if (NT_SUCCESS(Status)) {
                    if (QueryObjectName((HKEY)hKey, &szObjectName, MAX_PATH * 2, TRUE)) {
                        hashB = HashFromStrW(szObjectName);
                        if (hashB != hashA) { IsSB = 1; }
                    }
                    NtClose(hKey);
                }
                return IsSB;
            };

            // ================ REGISTRY SEARCHES ================

            auto RegKeyVM = []() -> {
                uint8_t score = 0;
                auto findregkey = [](HKEY hKey, char* regkey_s) -> void {
                    HKEY regkey;
                    LONG ret;

                    if (pafish_iswow64()) { ret = RegOpenKeyEx(hKey, regkey_s, 0, KEY_READ | KEY_WOW64_64KEY, &regkey); }
                    else { ret = RegOpenKeyEx(hKey, regkey_s, 0, KEY_READ, &regkey); }
                    if (ret == ERROR_SUCCESS) {
                        RegCloseKey(regkey);
                        score++;
                        return;
                    } else { return; }
                };

                // general
                key(HKEY_LOCAL_MACHINE, "HKLM\Software\Classes\Folder\shell\sandbox");

                // hyper-v
                key(HKEY_LOCAL_MACHINE, "HKLM\SOFTWARE\Microsoft\Hyper-V");
                key(HKEY_LOCAL_MACHINE, "HKLM\SOFTWARE\Microsoft\VirtualMachine");
                key(HKEY_LOCAL_MACHINE, "HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters");
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\vmicheartbeat");
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\vmicvss");
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\vmicshutdown");
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\vmicexchange");

                // parallels
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_1AB8*");

                // sandboxie
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\CurrentControlSet\Services\SbieDrv");
                key(HKEY_LOCAL_MACHINE, "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Sandboxie");

                // virtualbox
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_80EE*");
                key(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\ACPI\DSDT\VBOX__");
                key(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\ACPI\FADT\VBOX__");
                key(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\ACPI\RSDT\VBOX__");
                key(HKEY_LOCAL_MACHINE, "HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions");
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\VBoxGuest");
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\VBoxMouse");
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\VBoxService");
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\VBoxSF");
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\VBoxVideo");

                // virtualpc
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_5333*");
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\vpcbus");
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\vpc-s3");
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\vpcuhub");
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\msvmmouf");

                // vmware
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_15AD*");
                key(HKEY_LOCAL_MACHINE, "HKCU\SOFTWARE\VMware, Inc.\VMware Tools");
                key(HKEY_LOCAL_MACHINE, "HKLM\SOFTWARE\VMware, Inc.\VMware Tools");
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\vmdebug");
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\vmmouse");
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\VMTools");
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\VMMEMCTL");
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\vmware");
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\vmci");
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\vmx86");
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\CurrentControlSet\Enum\IDE\CdRomNECVMWar_VMware_IDE_CD*");
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\CurrentControlSet\Enum\IDE\CdRomNECVMWar_VMware_SATA_CD*");
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\CurrentControlSet\Enum\IDE\DiskVMware_Virtual_IDE_Hard_Drive*");
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\CurrentControlSet\Enum\IDE\DiskVMware_Virtual_SATA_Hard_Drive*");

                // wine
                key(HKEY_LOCAL_MACHINE, "HKCU\SOFTWARE\Wine");
                key(HKEY_LOCAL_MACHINE, "HKLM\SOFTWARE\Wine");

                // xen
                key(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\ACPI\DSDT\xen");
                key(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\ACPI\FADT\xen");
                key(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\ACPI\RSDT\xen");
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\xenevtchn");
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\xennet");
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\xennet6");
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\xensvc");
                key(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\xenvdb");
                return (score >= 1);
            };

            auto RegKeyStrSearch = []() -> bool {
                uint8_t score = 0;
                auto findkey = [](HKEY hKey, char * regkey_s, char * value_s, char * lookup) -> void {
                    HKEY regkey;
                    LONG ret;
                    DWORD size;
                    char value[1024], * lookup_str;
                    size_t lookup_size;

                    lookup_size = strlen(lookup);
                    lookup_str = malloc(lookup_size+sizeof(char));
                    strncpy(lookup_str, lookup, lookup_size+sizeof(char));
                    size = sizeof(value);

                    if (pafish_iswow64()) {
                        ret = RegOpenKeyEx(hKey, regkey_s, 0, KEY_READ | KEY_WOW64_64KEY, &regkey);
                    }
                    else {
                        ret = RegOpenKeyEx(hKey, regkey_s, 0, KEY_READ, &regkey);
                    }

                    if (ret == ERROR_SUCCESS) {
                        ret = RegQueryValueEx(regkey, value_s, NULL, NULL, (BYTE*)value, &size);
                        RegCloseKey(regkey);

                        if (ret == ERROR_SUCCESS) {
                            size_t i;
                            for (i = 0; i < strlen(value); i++) {
                                value[i] = toupper(value[i]);
                            }
                            for (i = 0; i < lookup_size; i++) {
                                lookup_str[i] = toupper(lookup_str[i]);
                            }
                            if (strstr(value, lookup_str) != NULL) {
                                free(lookup_str);
                                score++
                                return;
                            }
                        }
                    }

                    free(lookup_str);
                    return;
                };

                // general
                findkey(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\Description\System", "SystemBiosDate", "06/23/99");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\Description\System\BIOS", "SystemProductName", "A M I");

                // bochs
                findkey(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\Description\System", "SystemBiosVersion", "BOCHS");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\Description\System", "VideoBiosVersion", "BOCHS");

                // anubis
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion", "ProductID", "76487-337-8429955-22614");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductID", "76487-337-8429955-22614");

                // cwsandbox
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion", "ProductID", "76487-644-3177037-23510");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductID", "76487-644-3177037-23510");

                // joebox
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion", "ProductID", "55274-640-2673064-23950");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductID", "55274-640-2673064-23950");

                // parallels
                findkey(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\Description\System", "SystemBiosVersion", "PARALLELS");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\Description\System", "VideoBiosVersion", "PARALLELS");

                // qemu
                findkey(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0", "Identifier", "QEMU");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\Description\System", "SystemBiosVersion", "QEMU");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\Description\System", "VideoBiosVersion", "QEMU");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\Description\System\BIOS", "SystemManufacturer", "QEMU");

                // virtualbox
                findkey(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0", "", "");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 1\Scsi Bus 0\Target Id 0\Logical Unit Id 0", "", "");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 2\Scsi Bus 0\Target Id 0\Logical Unit Id 0", "", "");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\Description\System", "SystemBiosVersion", "VBOX");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\Description\System", "VideoBiosVersion", "VIRTUALBOX");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\Description\System\BIOS", "SystemProductName", "VIRTUAL");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\Disk\Enum", "DeviceDesc", "VBOX");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\Disk\Enum", "FriendlyName", "VBOX");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet002\Services\Disk\Enum", "DeviceDesc", "VBOX");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet002\Services\Disk\Enum", "FriendlyName", "VBOX");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet003\Services\Disk\Enum", "DeviceDesc", "VBOX");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet004\Services\Disk\Enum", "FriendlyName", "VBOX");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\CurrentControlSet\Control\SystemInformation", "SystemProductName", "VIRTUAL");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\CurrentControlSet\Control\SystemInformation", "SystemProductName", "VIRTUALBOX");

                // vmware
                findkey(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0", "Identifier", "VMWARE");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 1\Scsi Bus 0\Target Id 0\Logical Unit Id 0", "Identifier", "VMWARE");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\DEVICEMAP\Scsi\Scsi Port 2\Scsi Bus 0\Target Id 0\Logical Unit Id 0", "Identifier", "VMWARE");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\Description\System", "SystemBiosVersion", "VMWARE");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\Description\System", "SystemBiosVersion", "INTEL - 6040000");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\Description\System", "VideoBiosVersion", "VMWARE");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\Description\System\BIOS", "", "");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\Disk\Enum", "0", "VMware");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\Disk\Enum", "1", "VMware");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\Disk\Enum", "DeviceDesc", "VMware");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Services\Disk\Enum", "FriendlyName", "VMware");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet002\Services\Disk\Enum", "DeviceDesc", "VMware");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet002\Services\Disk\Enum", "FriendlyName", "VMware");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet003\Services\Disk\Enum", "DeviceDesc", "VMware");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet003\Services\Disk\Enum", "FriendlyName", "VMware");
                findkey(HKEY_LOCAL_MACHINE, "HKCR\Installer\Products", "ProductName", "vmware tools");
                findkey(HKEY_LOCAL_MACHINE, "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "DisplayName", "vmware tools");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "DisplayName", "vmware tools");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "DisplayName", "vmware tools");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0000", "CoInstallers32", "*vmx*");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0000", "DriverDesc", "VMware*");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0000", "InfSection", "vmx*");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0000", "ProviderName", "VMware*");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\ControlSet001\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0000\Settings", "Device Description", "VMware*");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\CurrentControlSet\Control\SystemInformation", "SystemProductName", "VMWARE");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\CurrentControlSet\Control\Video\{GUID}\Video", "Service", "vm3dmp");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\CurrentControlSet\Control\Video\{GUID}\Video", "Service", "vmx_svga");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\SYSTEM\CurrentControlSet\Control\Video\{GUID}\0000", "Device Description", "VMware SVGA*");
                findkey(HKEY_LOCAL_MACHINE, "HKLM\HARDWARE\Description\System\BIOS", "SystemProductName", "Xen");
            };








            
            // check against some of VMware blacklisted files
            auto VMwareFiles = []() -> bool {
                TCHAR* szPaths[] = {
                    // vmware
                    _T("system32\\drivers\\vmmouse.sys"),
                    _T("system32\\drivers\\vmhgfs.sys"),
                    _T("system32\\drivers\\hgfs.sys"),
                    _T("system32\\drivers\\vmx86.sys"),
                    _T("system32\\drivers\\vmxnet.sys"),
                    _T("system32\\drivers\\vmnet.sys"),

                    // virtualpc
                    _T("system32\\drivers\\vpc-s3.sys"),
                    _T("system32\\drivers\\vmsrvc.sys"),

                    // vbox
                    _T("system32\\drivers\\VBoxMouse.sys"), 	
                    _T("system32\\drivers\\VBoxGuest.sys"), 	
                    _T("system32\\drivers\\VBoxSF.sys"), 	
                    _T("system32\\drivers\\VBoxVideo.sys"), 	
                    _T("system32\\vboxdisp.dll"), 	
                    _T("system32\\vboxhook.dll"), 	
                    _T("system32\\vboxmrxnp.dll"), 	
                    _T("system32\\vboxogl.dll"), 	
                    _T("system32\\vboxoglarrayspu.dll"), 	
                    _T("system32\\vboxoglcrutil.dll"), 	
                    _T("system32\\vboxoglerrorspu.dll"), 	
                    _T("system32\\vboxoglfeedbackspu.dll"), 	
                    _T("system32\\vboxoglpackspu.dll"), 	
                    _T("system32\\vboxoglpassthroughspu.dll"), 	
                    _T("system32\\vboxservice.exe"), 	
                    _T("system32\\vboxtray.exe"), 	
                    _T("system32\\VBoxControl.exe"),

                    // parallels 	
                    _T("system32\\drivers\\prleth.sys"),
                    _T("system32\\drivers\\prlfs.sys"),
                    _T("system32\\drivers\\prlmouse.sys"),
                    _T("system32\\drivers\\prlvideo.sys"),
                    _T("system32\\drivers\\prltime.sys"),
                    _T("system32\\drivers\\prl_pv32.sys"),
                    _T("system32\\drivers\\prl_paravirt_32.sys")
                };
                
                WORD dwlength = sizeof(szPaths) / sizeof(szPaths[0]);
                TCHAR szWinDir[MAX_PATH] = _T("");
                TCHAR szPath[MAX_PATH] = _T("");
                GetWindowsDirectory(szWinDir, MAX_PATH);
                
                for (size_t i = 0; i < dwlength; i++)
                {
                    PathCombine(szPath, szWinDir, szPaths[i]);
                    TCHAR msg[256] = _T("");
                    if (fs::exists(szPath)) { return true; }
                }
                return false;
            };












            auto VMwareDir = []() -> bool {
                TCHAR szProgramFile[MAX_PATH];
                TCHAR szPath[MAX_PATH] = _T("");
                TCHAR szTarget[MAX_PATH] = _T("VMware\\");
                if (IsWoW64()) { ExpandEnvironmentStrings(_T("%ProgramW6432%"), szProgramFile, ARRAYSIZE(szProgramFile)); }
                else { SHGetSpecialFolderPath(NULL, szProgramFile, CSIDL_PROGRAM_FILES, FALSE); }
                PathCombine(szPath, szProgramFile, szTarget);
                return fs::exists(szPath);
            };










            auto SandboxPath = []() -> bool {
                char path[500];
                size_t i;
                DWORD pathsize = sizeof(path);

                GetModuleFileName(NULL, path, pathsize);

                for (i = 0; i < strlen(path); i++) {
                    path[i] = toupper(path[i]);
                }

                return ((strstr(path, "\\SAMPLE") != NULL) || (strstr(path, "\\VIRUS") != NULL) || (strstr(path, "SANDBOX") != NULL));
            };







            // ================== UI ==================
            auto VboxUIWindow = []() -> bool {
                HWND hClass = FindWindow(_T("VBoxTrayToolWndClass"), NULL);
                HWND hWindow = FindWindow(NULL, _T("VBoxTrayToolWnd"));
                return (hClass || hWindow);
            };



            auto enumWindowsCheck = [](bool& detected) -> bool {
                auto enumProc = [](HWND, LPARAM lParam) -> bool {
                    if (LPDWORD pCnt = reinterpret_cast<LPDWORD>(lParam)) { *pCnt++; }
                    return true;
                };

                DWORD winCnt = 0;

                if (!EnumWindows(enumProc,LPARAM(&winCnt))) { return false; }

                return (winCnt < 10);
            };



            // ====================== TIME ======================
            auto MeasureTime = []() -> bool {
                auto Timeskip1 = []() -> bool {
                    DWORD StartingTick, TimeElapsedMs;
                    LARGE_INTEGER DueTime;
                    HANDLE hTimer = NULL;
                    TIMER_BASIC_INFORMATION TimerInformation;
                    ULONG ReturnLength;

                    hTimer = CreateWaitableTimer(NULL, TRUE, NULL);
                    DueTime.QuadPart = Timeout * (-10000LL);

                    StartingTick = GetTickCount();
                    SetWaitableTimer(hTimer, &DueTime, 0, NULL, NULL, 0);
                    do {
                        Sleep(Timeout/10);
                        NtQueryTimer(hTimer, TimerBasicInformation, &TimerInformation, sizeof(TIMER_BASIC_INFORMATION), &ReturnLength);
                    } while (!TimerInformation.TimerState);

                    CloseHandle(hTimer);

                    TimeElapsedMs = GetTickCount() - StartingTick;
                    return (abs((LONG)(TimeElapsedMs - Timeout)) > Timeout / 2);
                };

                auto Timeskip2 = []() -> bool {
                    LARGE_INTEGER StartingTime, EndingTime;
                    LARGE_INTEGER Frequency;
                    DWORD TimeElapsedMs;

                    QueryPerformanceFrequency(&Frequency);
                    QueryPerformanceCounter(&StartingTime);

                    Sleep(Timeout);

                    QueryPerformanceCounter(&EndingTime);
                    TimeElapsedMs = (DWORD)(1000ll * (EndingTime.QuadPart - StartingTime.QuadPart) / Frequency.QuadPart);
                    return (abs((LONG)(TimeElapsedMs - Timeout)) > Timeout / 2);
                };

                auto Timeskip3 = []() -> bool {
                    ULONGLONG tick;
                    DWORD TimeElapsedMs;

                    tick = GetTickCount64();
                    Sleep(Timeout);
                    TimeElapsedMs = GetTickCount64() - tick;

                    printf("Requested delay: %d, elapsed time: %d\n", Timeout, TimeElapsedMs);

                    return (abs((LONG)(TimeElapsedMs - Timeout)) > Timeout / 2);
                };

                auto SysTime = []() -> bool {
                    SYSTEM_TIME_OF_DAY_INFORMATION  SysTimeInfo;
                    ULONGLONG time;
                    LONGLONG diff;

                    Sleep(60000); // should trigger sleep skipping
                    GetSystemTimeAsFileTime((LPFILETIME)&time);

                    NtQuerySystemInformation(SystemTimeOfDayInformation, &SysTimeInfo, sizeof(SysTimeInfo), 0);
                    diff = time - SysTimeInfo.CurrentTime.QuadPart;
                    return (abs(diff) > 10000000);
                }

                auto NtDelay = []() -> bool {
                    LONGLONG SavedTimeout = Timeout * (-10000LL);
                    DelayInterval->QuadPart = SavedTimeout;
                    status = NtDelayExecution(TRUE, DelayInterval);
                    return (DelayInterval->QuadPart != SavedTimeout);
                };

                return (
                    [](){
                        uint8_t score = 0;
                        score += Timeskip1();
                        score += Timeskip2();
                        score += Timeskip3();
                        score += SysTime();
                        score += NtDelay();
                        return (score >= 4); 
                    }()
                );
            };




            auto rdtsc_diff_locky = []() -> bool {
                ULONGLONG tsc1;
                ULONGLONG tsc2;
                ULONGLONG tsc3;
                for (size_t i = 0; i < 10; i++)
                {
                    tsc1 = __rdtsc();
                    GetProcessHeap();
                    tsc2 = __rdtsc();
                    CloseHandle(0);
                    tsc3 = __rdtsc();
                    if (((DWORD)(tsc3) - (DWORD)(tsc2)) / ((DWORD)(tsc2) - (DWORD)(tsc1)) >= 10) { return false; }
                }
                return true;
            };






            auto check_last_boot_time() -> bool {
                SYSTEM_TIME_OF_DAY_INFORMATION  SysTimeInfo;
                LARGE_INTEGER LastBootTime;
                
                NtQuerySystemInformation(SystemTimeOfDayInformation, &SysTimeInfo, sizeof(SysTimeInfo), 0);
                LastBootTime = wmi_Get_LastBootTime();
                return (wmi_LastBootTime.QuadPart - SysTimeInfo.BootTime.QuadPart) / 10000000 != 0;
            };




            auto HookDelay = []() -> bool {
                __declspec(align(4)) BYTE aligned_bytes[sizeof(LARGE_INTEGER) * 2];
                DWORD tick_start, time_elapsed_ms;
                DWORD Timeout = 10000;
                PLARGE_INTEGER DelayInterval = (PLARGE_INTEGER)(aligned_bytes + 1);
                NTSTATUS status;

                DelayInterval->QuadPart = Timeout * (-10000LL);
                tick_start = GetTickCount();
                status = NtDelayExecution(FALSE, DelayInterval);
                time_elapsed_ms = GetTickCount() - tick_start;
                return (time_elapsed_ms > 500 || status != STATUS_DATATYPE_MISALIGNMENT);
            };


            auto DelayIntervalCheck = []() -> bool {
                return (NtDelayExecution(FALSE, (PLARGE_INTEGER)0) != STATUS_ACCESS_VIOLATION);
            };




            // ========================= process =======================
            auto CheckVMProcs = []() -> bool {
                uint8_t score = 0;
                auto CheckRunningProc = [](const std::string &proc_name) -> void {
                    HANDLE hSnapshot;
                    PROCESSENTRY32 pe = {};

                    pe.dwSize = sizeof(pe);
                    bool present = false;
                    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

                    if (hSnapshot == INVALID_HANDLE_VALUE) { return; }
                    if (Process32First(hSnapshot, &pe)) {
                        do {
                            if (!StrCmpI(pe.szExeFile, proc_name.c_str())) {
                                present = true;
                                break;
                            }
                        } while (Process32Next(hSnapshot, &pe));
                    }
                    CloseHandle(hSnapshot);

                    score += present;
                    return;
                }

                // JoeBox
                CheckRunningProc("joeboxserver.exe");
                CheckRunningProc("joeboxcontrol.exe");

                // Parallels
                CheckRunningProc("prl_cc.exe");
                CheckRunningProc("prl_tools.exe");

                // Virtualbox
                CheckRunningProc("vboxservice.exe");
                CheckRunningProc("vboxtray.exe");

                // Virtual PC
                CheckRunningProc("vmsrvc.exe");
                CheckRunningProc("vmusrvc.exe");

                // VMware
                CheckRunningProc("vmtoolsd.exe");
                CheckRunningProc("vmacthlp.exe");
                CheckRunningProc("vmwaretray.exe");
                CheckRunningProc("vmwareuser.exe");
                CheckRunningProc("vmware.exe");
                CheckRunningProc("vmount2.exe");

                // Xen
                CheckRunningProc("xenservice.exe");
                CheckRunningProc("xsvc_depriv.exe");

                // WPE Pro
                CheckRunningProc("WPE Pro.exe");

                return (score >= 1);
            };












            auto loaded_dlls = []() -> bool {
                HMODULE hDll;
                TCHAR* szDlls[] = {
                    _T("sbiedll.dll"),
                    _T("dbghelp.dll"),
                    _T("api_log.dll"),
                    _T("dir_watch.dll"),
                    _T("pstorec.dll"),
                    _T("vmcheck.dll"),
                    _T("wpespy.dll"),
                };

                WORD dwlength = sizeof(szDlls) / sizeof(szDlls[0]);
                for (int i = 0; i < dwlength; i++)
                {
                    TCHAR msg[256] = _T("");
                    //_stprintf_s(msg, sizeof(msg) / sizeof(TCHAR), _T("Checking if process loaded modules contains: %s "), szDlls[i]);

                    hDll = GetModuleHandle(szDlls[i]);
                    return (!(hDll == NULL));
                }
            };


            auto WineExports = []() -> bool {
                auto CheckWine[](const std::string &module, const std::string &proc) -> bool {
                    HMODULE hKernel32;
                    hKernel32 = GetModuleHandle(_T(module));
                    if (hKernel32 == NULL) { return false; }
                    return (!(GetProcAddress(hKernel32, proc) == NULL));
                };

                return (
                    CheckWine("kernel32.dll", "wine_get_unix_file_name") && \
                    CheckWine("ntdll.dll", "wine_get_version");
                );
            };





            auto CheckLoadedDLLs = []() -> bool {
                std::vector<std::string> real_dlls = {
                    "kernel32.dll",
                    "networkexplorer.dll",
                    "NlsData0000.dll"
                };
                std::vector<std::string> false_dlls = {
                    "NetProjW.dll",
                    "Ghofr.dll",
                    "fg122.dll"
                };
                HMODULE lib_inst;

                for (auto &dll : real_dlls) {
                    lib_inst = LoadLibraryA(dll.c_str());
                    if (lib_inst == nullptr) {
                        return true;
                    }
                    FreeLibrary(lib_inst);
                }

                for (auto &dll : false_dlls) {
                    lib_inst = LoadLibraryA(dll.c_str());
                    if (lib_inst != nullptr) {
                        return true;
                    }
                }

                return false;
            };











            auto GetUser = []() -> bool {
                DWORD size = UNLEN + 1;
                auto user = GetUserName( (TCHAR*)name, &size );
                return (
                    (user == "username") ||
                    (user =="USER") ||
                    (user =="user") ||
                    (user =="currentuser")
                );
            };

        #elif __APPLE__
            
        //https://evasions.checkpoint.com/techniques/macos.html

        auto ioreg = []() -> bool {
            return (stoi(*GetSysResult("ioreg -l | grep -i -c -e \"virtualbox\" -e \"oracle\" -e \"vmware\"")) >= 1);
        };
        #endif


        std::cout << "\nChecking VMID... " << (VMID() ? "[\x1B[38;2;94;214;114mDETECTED\x1B[0m]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]");
        std::cout << "\nChecking CPU brand... " << (CPUbrand() ? "[\x1B[38;2;94;214;114mDETECTED\x1B[0m]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]");
        std::cout << "\nChecking CPUID hypervisor bit... " << (CPUIDhyperv() ? "[\x1B[38;2;94;214;114mDETECTED\x1B[0m]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]");
        std::cout << "\nChecking CPUID 0x4 leaf... " << (Check0x4CPUID() ? "[\x1B[38;2;94;214;114mDETECTED\x1B[0m]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]");
        std::cout << "\nChecking hypervisor brand... " << (HyperVbrand() ? "[\x1B[38;2;94;214;114mDETECTED\x1B[0m]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]");
        std::cout << "\nChecking RDTSC... " << (RDTSCcheck() ? "[\x1B[38;2;94;214;114mDETECTED\x1B[0m]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]");
        std::cout << "\nChecking sidt... " << (sidtcheck() ? "[\x1B[38;2;94;214;114mDETECTED\x1B[0m]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]");
        std::cout << "\nChecking VMware port... " << (VMwarePort() ? "[\x1B[38;2;94;214;114mDETECTED\x1B[0m]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]");
        std::cout << "\nChecking processor count... " << (ProcessorCount() ? "[\x1B[38;2;94;214;114mDETECTED\x1B[0m]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]");
        std::cout << "\nChecking MAC address... " << (MacCheck() ? "[\x1B[38;2;94;214;114mDETECTED\x1B[0m]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]");
        std::cout << "\nChecking temperature... " << (CheckTemperature() ? "[\x1B[38;2;94;214;114mDETECTED\x1B[0m]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]");
        std::cout << "\nChecking systemd virtualisation... " << (SystemdVirt() ? "[\x1B[38;2;94;214;114mDETECTED\x1B[0m]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]");
        std::cout << "\nChecking chassis vendor... " << (ChassisVendor() ? "[\x1B[38;2;94;214;114mDETECTED\x1B[0m]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]");
        std::cout << "\nChecking chassis type... " << (ChassisType() ? "[\x1B[38;2;94;214;114mDETECTED\x1B[0m]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]");
        std::cout << "\nChecking Dockerenv... " << (Dockerenv() ? "[\x1B[38;2;94;214;114mDETECTED\x1B[0m]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]");
        std::cout << "\nChecking dmidecode output... " << (dmidecode() ? "[\x1B[38;2;94;214;114mDETECTED\x1B[0m]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]");
        std::cout << "\nChecking dmesg output... " << (dmesg() ? "[\x1B[38;2;94;214;114mDETECTED\x1B[0m]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]");
        std::cout << "\nChecking hwmon presence... " << (hwmon() ? "[\x1B[38;2;94;214;114mDETECTED\x1B[0m]" : "[\x1B[38;2;239;75;75mNOT DETECTED\x1B[0m]");
        std::cout << "\n\n";

        float points = 0;

        // TODO: make this process inside of a thread pool
        if (ProcessorCount()) { std::cout << "\nproccount: "; points += 3.5; }
        if (MacCheck()) { std::cout << "\nmac: "; points += 3.5; }

        #if __x86_64__
            if (VMID()) { std::cout << "vmid: "; points += 6.5; }
            if (CPUbrand()) { std::cout << "\ncpubrand: "; points += 3; }
            if (CPUIDhyperv()) { std::cout << "\ncpuidhyperv: "; points += 5.5; }
            if (Check0x4CPUID()) { std::cout << "\n0x4cpuid: "; points += 4; }
            if (HyperVbrand()) { std::cout << "\nhypervbrand: "; points += 4; }
            if (RDTSCcheck()) { std::cout << "\nrdtsc: "; points += 2.5; }
            if (sidtcheck()) { std::cout << "\nsidt: "; points += 4; }
            if (VMwarePort()) { std::cout << "\nvmwareport: "; points += 3; }
        #endif

        #if __linux__
            if (CheckTemperature()) { std::cout << "\ntempdir: "; points += 1; }
            if (SystemdVirt()) { std::cout << "\nsystemd-virt: "; points += 5; }
            if (ChassisVendor()) { std::cout << "\nchassisvendor: "; points += 4.5; }
            if (ChassisType()) { std::cout << "\nchassistype: "; points += 1; }
            if (Dockerenv()) { std::cout << "\ndockerenv: "; points += 3; }
            if (dmidecode()) { std::cout << "\ndmidecode: "; points += 4; }
            if (dmesg()) { std::cout << "\ndmesg: "; points += 3.5; }
            if (hwmon()) { std::cout << "\nhwmon: "; points += 0.5; }
        #elif _MSC_VER
            if (VBoxCheck()) { std::cout << "\nvbox: "; points += 6.5; }
            if (VBoxCheck2()) { std::cout << "\nvbox2: "; points += 6.5; }
            if (VMwareCheck()) { std::cout << "\nvmware: "; points += 6.5; }
            if (VPC()) { std::cout << "\nvpc: "; points += 2; }
            if (CheckSandboxie()) { std::cout << "\nsandboxie: "; points += 4; }
            if (RegKeyVM()) { std::cout << "\nregkey: "; pointa += 5; }
            if (RegKeyStrSearch()) { std::cout << "\nregkeystr: "; pointa += 5; }
        #elif __APPLE__

        #endif

        std::cout << "\n\n RESULT: " << points << "/62 points, meets VM detection threashold " << (points / 6.5) << " times over\n\n";

        /** 
         * you can change this threshold score to a maximum
         * of something like 10~14 if you want to be extremely
         * sure, but this can risk the result to be a false
         * negative if the detection bar is far too high.
         */
        return (points >= 6.5);
    }
};