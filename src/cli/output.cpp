#include "../vmaware.hpp"
#include "output.hpp"
#include "windows_tui.hpp"
#include "globals.hpp"

#include <chrono>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <vector>
#include <fstream>

#if (CLI_LINUX)
    #include <unistd.h>
#endif

const char* color(const u8 score, const bool is_hardened) {
    if (arg_bitset.test(NO_ANSI)) {
        return "";
    }

    if (is_hardened) {
        return green.c_str();
    }

    if (arg_bitset.test(DYNAMIC)) {
        if (score == 0) { return red.c_str(); }
        if (score <= 12) { return red.c_str(); }
        if (score <= 25) { return red_orange.c_str(); }
        if (score < 50) { return red_orange.c_str(); }
        if (score <= 62) { return orange.c_str(); }
        if (score <= 75) { return green_orange.c_str(); }
        if (score < 100) { return green.c_str(); }
        if (score == 100) { return green.c_str(); }
    }
    else {
        if (score == 100) {
            return green.c_str();
        }

        return red.c_str();
    }
    return "";
}

bool is_admin() {
#if (CLI_LINUX)
    const uid_t uid = getuid();
    const uid_t euid = geteuid();
    const bool is_root = ((uid != euid) || (euid == 0));
    return is_root;
#elif (CLI_WINDOWS)
    bool is_admin = false;
    HANDLE hToken = nullptr;
    if (OpenProcessToken(reinterpret_cast<HANDLE>(-1LL), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation{};
        DWORD dwSize;
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize)) {
            if (elevation.TokenIsElevated) {
                is_admin = true;
            }
        }
        CloseHandle(hToken);
    }
    return is_admin;
#endif
}

#if (CLI_LINUX)
static bool are_perms_required(const VM::enum_flags flag) {
    if (is_admin()) {
        return false;
    }

    switch (flag) {
        case VM::VMWARE_DMESG:
        case VM::DMIDECODE:
        case VM::DMESG:
        case VM::QEMU_USB:
        case VM::KMSG:
        case VM::SMBIOS_VM_BIT:
        case VM::NVRAM: return true;
        default: return false;
    }
}
#endif

static bool is_disabled(const VM::enum_flags flag) {
    if (arg_bitset.test(ALL)) {
        return false;
    }

    for (const auto f : VM::disabled_techniques) {
        if (f == flag) {
            return true;
        }
    }

    return false;
}

static bool is_unsupported(const VM::enum_flags flag) {
    if ((flag >= VM::HYPERVISOR_BIT) && (flag <= VM::KGT_SIGNATURE)) {
        return false;
    }
#if (CLI_LINUX)
    return (!((flag >= VM::LINUX_START) && (flag <= VM::LINUX_END)));
#elif (CLI_WINDOWS)
    return (!((flag >= VM::WINDOWS_START) && (flag <= VM::WINDOWS_END)));
#elif (CLI_APPLE)
    return (!((flag >= VM::MACOS_START) && (flag <= VM::MACOS_END)));
#else
    return false;
#endif
}

static std::pair<bool, VM::enum_flags> string_to_technique(const std::string& name) {
    for (u8 i = VM::technique_begin; i < static_cast<u8>(VM::technique_end); ++i) {
        const VM::enum_flags flag = static_cast<VM::enum_flags>(i);
        if (VM::flag_to_string(flag) == name) {
            return { true, flag };
        }
    }

    return { false, VM::NULL_ARG };
}

bool is_vm_brand_multiple(const std::string& vm_brand) {
    return (vm_brand.find(" or ") != std::string::npos);
}

const char* get_vm_description(const std::string& vm_brand) {
    if (is_vm_brand_multiple(vm_brand)) {
        return "";
    }

    struct brand_entry { const char* brand; const char* description; };

    static const brand_entry table[] = {
        { VM::brands::VBOX, "Oracle VirtualBox (formerly Sun VirtualBox, Sun xVM VirtualBox and InnoTek VirtualBox) is a free and commercial hosted hypervisor for x86 and Apple ARM64 virtualization developed by Oracle Corporation initially released in 2007. It supports Intel's VT-x and AMD's AMD-V hardware-assisted virtualization, while providing an extensive feature set as a staple of its flexibility and wide use cases." },
        { VM::brands::VMWARE, "VMware is a free and commercial type 2 hypervisor initially released in 1999 and acquired by EMC, then Dell, and finally Broadcom Inc in 2023. It was the first commercially successful company to virtualize the x86 architecture, and has since produced many sub-versions of the hypervisor since its inception. It uses binary translation to re-write the code dynamically for a faster performance." },
        { VM::brands::VMWARE_EXPRESS, "VMware Express (formerly VMware GSX Server Express) was a free entry-level version of VMware's hosted hypervisor for small-scale virtualization. Released in 2003, it offered basic VM management capabilities but lacked advanced features like VMotion. Discontinued in 2006 as VMware shifted focus to enterprise solutions like ESX and vSphere." },
        { VM::brands::VMWARE_ESX, "VMware ESX (Elastic Sky X) was a type 1 bare-metal hypervisor released in 2001 for enterprise environments. It introduced VMFS clustered filesystems and direct hardware access through its service console. Deprecated in 2010 in favor of the lighter ESXi architecture, which removed the Linux-based service console for improved security." },
        { VM::brands::VMWARE_GSX, "VMware GSX Server (Ground Storm X) was a commercial type 2 hypervisor (2001-2006) for Windows/Linux hosts, targeting departmental server consolidation. Supported features like VM snapshots and remote management through VI Web Access. Discontinued as VMware transitioned to ESX's bare-metal architecture for better performance in enterprise environments." },
        { VM::brands::VMWARE_WORKSTATION, "VMware Workstation is a commercial type 2 hypervisor for Windows/Linux hosts, first released in 1999. Enables nested virtualization, 4K display support, and DirectX 11/OpenGL 4.1 acceleration. Popular with developers for testing multi-tier configurations and legacy OS compatibility through its Unity view mode." },
        { VM::brands::VMWARE_FUSION, "VMware Fusion was a macOS-hosted hypervisor (2007-2024) that allowed Intel-based Macs to run Windows/Linux VMs with Metal graphics acceleration and Retina display support. Discontinued due to Apple's transition to ARM64 architecture with Apple Silicon chips, which required significant architectural changes incompatible with x86 virtualization." },
        { VM::brands::VMWARE_HARD, "VMWare Hardener Loader is an open-source detection mitigation loader to harden vmware virtual machines against VM detection for Windows (vista~win10) x64 guests." },
        { VM::brands::BHYVE, R"(bhyve (pronounced "bee hive", formerly written as BHyVe for "BSD hypervisor") is a free type 2 hosted hypervisor initially written for FreeBSD. It can also be used on a number of illumos based distributions including SmartOS, OpenIndiana, and OmniOS. bhyve has a modern codebase and uses fewer resources compared to its competitors. In the case of FreeBSD, the resource management is more efficient.)" },
        { VM::brands::KVM, "KVM is a free and open source module of the Linux kernel released in 2007. It uses hardware virtualization extensions, and has had support for hot swappable vCPUs, dynamic memory management, and Live Migration. It also reduces the impact that memory write-intensive workloads have on the migration process. KVM emulates very little hardware components, and it defers to a higher-level client application such as QEMU." },
        { VM::brands::QEMU, "The Quick Emulator (QEMU) is a free and open-source emulator that uses dynamic binary translation to emulate a computer's processor. It translates the emulated binary codes to an equivalent binary format which is executed by the machine. It provides a variety of hardware and device models for the VM, while often being combined with KVM. However, no concrete evidence of KVM was found for this system." },
        { VM::brands::QEMU_KVM, "QEMU (a free and open-source emulator that uses dynamic binary translation to emulate a computer's processor) is being used with Kernel-based Virtual Machine (KVM, a free and open source module of the Linux kernel) to virtualize hardware at near-native speeds." },
        { VM::brands::KVM_HYPERV, "KVM-HyperV integration allows Linux KVM hosts to expose Hyper-V-compatible paravirtualization interfaces to Windows guests. Enables performance optimizations like enlightened VMCS (Virtual Machine Control Structure) and TSC (Time Stamp Counter) synchronization, reducing overhead for Windows VMs running on Linux hypervisors." },
        { VM::brands::QEMU_KVM_HYPERV, "A QEMU/KVM virtual machine with Hyper-V enlightenments. These features make Windows and Hyper-V guests think they're running on top of a Hyper-V compatible hypervisor and use Hyper-V specific features." },
        { VM::brands::HYPERV, "Hyper-V is Microsoft's proprietary native hypervisor that can create x86 VMs on Windows. Released in 2008, it supercedes previous virtualization solutions such as Microsoft Virtual Server and Windows VirtualPC. Hyper-V uses partitioning to isolate the guest OSs, and has \"enlightenment\" features for bypassing device emulation layers, allowing for faster execution including when Windows is virtualized on Linux." },
        { VM::brands::HYPERV_VPC, "Either Hyper-V or VirtualPC were detected. Hyper-V is Microsoft's proprietary native hypervisor that can create x86 VMs on Windows. Virtual PC is a discontinued x86 emulator software for Microsoft Windows hosts and PowerPC-based Mac hosts." },
        { VM::brands::PARALLELS, "Parallels is a hypervisor providing hardware virtualization for Mac computers. It was released in 2006 and is developed by Parallels, a subsidiary of Corel. It is a hardware emulation virtualization software, using hypervisor technology that works by mapping the host computer's hardware resources directly to the VM's resources. Each VM thus operates with virtually all the resources of a physical computer." },
        { VM::brands::XEN, "Xen is a free and open-source type 1 hypervisor. Originally developed by the University of Cambridge Computer Laboratory and is now being developed by the Linux Foundation with support from Intel, Arm Ltd, Huawei, AWS, Alibaba Cloud, AMD, and more. It runs in a more privileged CPU state than any other software on the machine, except for firmware. It uses GNU GRUB as its bootloader, and then loads a paravirtualized host OS into the host domain (dom0)." },
        { VM::brands::ACRN, "ACRN is an open source reference type 1 hypervisor stack made by the Linux Foundation Project targeting the IoT, Embedded, Edge segments. Its objective is to cater to the needs of those who require to run Virtual Machines with Real-Time characteristics, or where Functional Safety workloads need to be isolated from other workloads running on the same hardware platform." },
        { VM::brands::QNX, "QNX Hypervisor is a real-time virtualization platform for embedded systems, enabling concurrent execution of QNX Neutrino RTOS and Linux/Android on ARM/x86. Provides time partitioning with <1 microsecond interrupt latency for automotive systems, certified to ISO 26262 ASIL D safety standards. Used in Audi MIB3 and BMW iDrive systems." },
        { VM::brands::HYBRID, "Hybrid Analysis is a sandbox that combines basic and dynamic analysis techniques to detect malicious code that is trying to hide. It extracts indicators of compromise (IOCs) from both runtime data and memory dump analysis, providing a comprehensive approach to malware analysis." },
        { VM::brands::SANDBOXIE, "Sandboxie is an open-source OS-level virtualization solution for Microsoft Windows, an application sandbox for Windows that redirects file/registry writes to virtualized storage. Acquired by Sophos in 2019 and open-sourced in 2020, it uses kernel-mode drivers (SbieDrv.sys) to isolate processes without full VM overhead. Commonly used for testing untrusted software or browsing securely." },
        { VM::brands::DOCKER, "Docker is a set of platform as a service (PaaS) products that use OS-level virtualization to deliver software in packages called containers. The service has both free and premium tiers. The software that hosts the containers is called Docker Engine. It's used to automate the deployment of applications in lightweight containers so that applications can work efficiently in different environments in isolation." },
        { VM::brands::WINE, "Wine is a free and open-source compatibility layer to allow application software and computer games developed for Microsoft Windows to run on Unix-like operating systems. Developers can compile Windows applications against WineLib to help port them to Unix-like systems. Wine is predominantly written using black-box testing reverse-engineering, to avoid copyright issues. No code emulation or virtualization occurs." },
        { VM::brands::VPC, "Microsoft Virtual PC (2004-2011) was a consumer-focused type 2 hypervisor for running Windows XP/Vista guests. Featured \"Undo Disks\" for rollback capability and host-guest integration components. Discontinued after Windows 7's XP Mode due to Hyper-V's emergence, lacking hardware-assisted virtualization support." },
        { VM::brands::ANUBIS, "Anubis is a tool for analyzing the behavior of Windows PE-executables with special focus on the analysis of malware. Execution of Anubis results in the generation of a report file that contains enough information to give a human user a very good impression about the purpose and the actions of the analyzed binary. The generated report includes detailed data about modifications made to the Windows registry or the file system, about interactions with the Windows Service Manager or other processes and of course it logs all generated network traffic." },
        { VM::brands::JOEBOX, "Joe Sandbox (formerly JoeBox) is a cloud-based malware analysis solution with Deep Learning classification. Features multi-OS analysis (Windows/Linux/Android), memory forensics, and MITRE ATT&CK mapping. Offers hybrid analysis combining static/dynamic techniques with 400+ behavioral indicators for enterprise threat hunting." },
        { VM::brands::THREATEXPERT, "ThreatExpert was an automated malware analysis service (2007-2013) that provided behavioral reports via web API. Pioneered mass-scale analysis with heuristic detection of packers/rootkits. Discontinued as competing services like VirusTotal and Hybrid Analysis adopted similar cloud-based approaches with richer feature sets." },
        { VM::brands::CWSANDBOX, "CWSandbox is a tool for malware analysis, developed by Carsten Willems as part of his thesis and Ph.D. studies." },
        { VM::brands::COMODO, "Comodo is a proprietary sandbox running an isolated operating environment. Comodo have integrated sandboxing technology directly into the security architecture of Comodo Internet Security to complement and strengthen the Firewall, Defense+ and Antivirus modules of their product line. It features a hybrid of user mode hooks along with a kernel mode driver, preventing any modification to files or registry on the host machine." },
        { VM::brands::BOCHS, "Bochs (pronounced \"box\") is a free and open-source portable IA-32 and x86-64 IBM PC compatible emulator and debugger mostly written in C++. Bochs is mostly used for OS development and to run other guest OSs inside already running host OSs, while emulating the hardware needed such as hard drives, CD drives, and floppy drives. It doesn't utilize any host CPU virtualization features, therefore is slower than most virtualization software." },
        { VM::brands::NVMM, "NVMM (NetBSD Virtual Machine Monitor) is NetBSD's native hypervisor for NetBSD 9.0. It provides a virtualization API, libnvmm, that can be leveraged by emulators such as QEMU. A unique property of NVMM is that the kernel never accesses guest VM memory, only creating it. Intel's Hardware Accelerated Execution Manager (HAXM) provides an alternative solution for acceleration in QEMU for Intel CPUs only, similar to Linux's KVM." },
        { VM::brands::BSD_VMM, "BSD VMM is FreeBSD's kernel subsystem powering the bhyve hypervisor. Implements Intel VT-x/AMD-V virtualization with direct device assignment (PCI passthrough). Supports UEFI boot and VirtIO paravirtualized devices, optimized for FreeBSD guests with FreeBSD-specific virtio_net(4) and virtio_blk(4) drivers." },
        { VM::brands::INTEL_HAXM, "HAXM was created to bring Intel Virtualization Technology to Windows and macOS users. Today both Microsoft Hyper-V and macOS HVF have added support for Intel Virtual Machine Extensions. The project is discontinued." },
        { VM::brands::UNISYS, "Unisys Secure Partitioning (s-Par\xC2\xAE) is firmware made by ClearPath Forward that provides the capability to run multiple operating environments concurrently on the same computer hardware: for example, Linux and Windows operating environments. Unlike virtualization technologies and virtual machines, each s-Par operating environment has dedicated hardware resources\xE2\x80\x94instruction processor cores, memory, and input/output components. Each s-Par operating environment is referred to as a secure partition (or just \xE2\x80\x9Cpartition,\xE2\x80\x9D for short). A secure partition is sometimes referred to as a hard partition." },
        { VM::brands::LMHS, "LMHS is Lockheed Martin's native hypervisor. I assume you got this result because you're an employee in the company and you're doing security testing. But if you're not, how the hell did you get this result? Did you steal a US military fighter jet or something? I'm genuinely curious. I really don't expect anybody to have this result frankly but I'll assume it's just a false positive (please create an issue in the repo if it is)." },
        { VM::brands::CUCKOO, "Cuckoo Sandbox is an open-source automated malware analysis system. Executes files in isolated environments (VirtualBox/QEMU) while monitoring API calls, network traffic, and memory changes. Features YARA rule matching and CAPE (Customized Automated Processing Engine) extensions for advanced threat hunting and IOC extraction." },
        { VM::brands::BLUESTACKS, "BlueStacks is a chain of cloud-based cross-platform products developed by the San Francisco-based company of the same name. The BlueStacks App Player enables the execution of Android applications on computers running Microsoft Windows or macOS. It functions through an Android emulator referred to as App Player. The basic features of the software are available for free, while advanced features require a paid monthly subscription." },
        { VM::brands::JAILHOUSE, "Jailhouse is a free and open source partitioning Hypervisor based on Linux, made by Siemens. It is able to run bare-metal applications or (adapted) operating systems besides Linux. For this purpose, it configures CPU and device virtualization features of the hardware platform in a way that none of these domains, called \"cells\", can interfere with each other in an unacceptable way." },
        { VM::brands::APPLE_VZ, "Apple Virtualization Framework (VZ) is a macOS 12+ API for creating ARM64 VMs on Apple Silicon. Provides para-virtualized devices via VirtIO and Rosetta 2 binary translation for x86_64 Linux guests. Used by Lima and UTM to run Linux distributions natively on M1/M2 Macs without traditional hypervisor overhead." },
        { VM::brands::INTEL_KGT, "Intel Kernel Guard Technology (KGT) is a policy specification and enforcement framework for ensuring runtime integrity of kernel and platform assets. Demonstrated secure enclaves for critical OS components using VT-x/EPT before being superseded by CET (Control-flow Enforcement Technology) and HyperGuard in Windows 10." },
        { VM::brands::AZURE_HYPERV, "Azure Hyper-V is Microsoft's cloud-optimized hypervisor variant powering Azure VMs. Implements Azure-specific virtual devices like NVMe Accelerated Networking and vTPMs. Supports nested virtualization for running Hyper-V/containers within Azure VMs, enabling cloud-based CI/CD pipelines and dev/test environments." },
        { VM::brands::SIMPLEVISOR, "SimpleVisor is a minimalist Intel VT-x hypervisor by Alex Ionescu for Windows/Linux research. Demonstrates EPT-based memory isolation and hypercall handling. Used to study VM escapes and hypervisor rootkits, with hooks for intercepting CR3 changes and MSR accesses." },
        { VM::brands::HYPERV_ROOT, "VMAware detected Hyper-V operating as a type 1 hypervisor, not as a guest virtual machine. Although your hardware/firmware signatures match Microsoft's Hyper-V architecture, we determined that you're running on baremetal. This prevents false positives, as Windows sometimes runs under Hyper-V (type 1) hypervisor." },
        { VM::brands::UML, "User-Mode Linux (UML) allows running Linux kernels as user-space processes using ptrace-based virtualization. Primarily used for kernel debugging and network namespace testing. Offers lightweight isolation without hardware acceleration, but requires host/guest kernel version matching for stable operation." },
        { VM::brands::POWERVM, "IBM PowerVM is a type 1 hypervisor for POWER9/10 systems, supporting Live Partition Mobility and Shared Processor Pools. Implements VIOS (Virtual I/O Server) for storage/networking virtualization, enabling concurrent AIX, IBM i, and Linux workloads with RAS features like predictive failure analysis." },
        { VM::brands::GCE, "Google Compute Engine (GCE) utilizes KVM-based virtualization with custom Titanium security chips for hardware root of trust. Features live migration during host maintenance and shielded VMs with UEFI secure boot. Underpins Google Cloud's Confidential Computing offering using AMD SEV-SNP memory encryption." },
        { VM::brands::OPENSTACK, "OpenStack is an open-source cloud OS managing compute (Nova), networking (Neutron), and storage (Cinder) resources. Supports multiple hypervisors (KVM/Xen/Hyper-V) through driver plugins. Widely used in private clouds with features like Heat orchestration and Octavia load balancing." },
        { VM::brands::KUBEVIRT, "KubeVirt is a VM management add-on for Kubernetes. It provides a common ground for virtualization solutions on top of Kubernetes by extending its core by adding additional virtualization resource types where the Kubernetes API can be used to manage these VM resources alongside all other resources Kubernetes provides. Its functionality is to provide a runtime in order to define and manage VMs." },
        { VM::brands::AWS_NITRO, "AWS Nitro is Amazon's hypervisor for EC2, offloading network/storage to dedicated Nitro Cards. Uses Firecracker microVMs for Lambda/Fargate serverless compute. Provides bare-metal instance types (i3en.metal) with 3x better EBS throughput compared to traditional Xen-based instances." },
        { VM::brands::PODMAN, "Podman is a daemonless container engine by Red Hat using Linux namespaces/cgroups. Supports rootless containers and Docker-compatible CLI syntax. Integrates with systemd for service management and Quadlet for declarative container definitions. Part of the Podman Desktop suite for Kubernetes development." },
        { VM::brands::WSL, "Windows Subsystem for Linux (WSL) is a feature of Microsoft Windows that allows for using a Linux environment without the need for a separate VM or dual booting. WSL requires fewer resources (CPU, memory, and storage) than a full virtual machine (a common alternative for using Linux in Windows), while also allowing the use of both Windows and Linux tools on the same set of files." },
        { VM::brands::OPENVZ, "OpenVZ is a container-based virtualization for Linux using kernel-level isolation. Provides checkpointing and live migration through ploop storage. Requires matching host/guest kernel versions, largely superseded by LXC/LXD due to Docker's popularity and kernel namespace flexibility." },
        { VM::brands::BAREVISOR, "BareVisor is a research-focused type 1 hypervisor emphasizing minimal TCB (Trusted Computing Base). Supports x86/ARM with <10K LoC for secure enclave experiments. Used in academia to study TEEs (Trusted Execution Environments) and hypervisor-based intrusion detection systems." },
        { VM::brands::HYPERPLATFORM, "HyperPlatform is an Intel VT-x research hypervisor for Windows kernel introspection. Provides APIs for EPT hooking and MSR filtering. Used to develop anti-cheat systems and kernel exploit detectors by monitoring CR3 switches and exception handling." },
        { VM::brands::MINIVISOR, "MiniVisor is a research hypervisor written as a UEFI and Windows driver for the educational purpose for Intel processors. This MiniVisor, as a UEFI driver, provides the ability to inspect system activities even before the operating system boots, while as a Windows driver, allows developers to debug it with familiar tools like WinDbg." },
        { VM::brands::INTEL_TDX, "Intel TDX (Trust Domain Extensions) enhances VM confidentiality in cloud environments. Encrypts VM memory and registers using MKTME (Multi-Key Total Memory Encryption), isolating \"trust domains\" from hypervisors. Part of Intel's vPro platform for confidential computing on Xeon Scalable processors." },
        { VM::brands::LKVM, "LKVM (Linux Kernel Virtual Machine) is a minimal KVM frontend for Linux kernel testing. Provides CLI tools like `lkvm run` for quick VM creation with built-in 9pfs support. Used alongside QEMU for rapid boot testing and kernel panic debugging." },
        { VM::brands::AMD_SEV, "AMD Secure Encrypted Virtualization (SEV) encrypts VM memory with EPYC processor-based AES keys. Isolates guests from hypervisors using ASIDs (Address Space Identifiers), protecting against physical attacks and malicious cloud providers. Supported in Linux/KVM via libvirt SEV options." },
        { VM::brands::AMD_SEV_ES, "AMD SEV-Encrypted State (SEV-ES) extends SEV by encrypting CPU register states during VM exits. Prevents hypervisors from inspecting guest register contents, mitigating attacks using VMRUN/VMEXIT timing side channels. Requires guest OS modifications for secure interrupt handling." },
        { VM::brands::AMD_SEV_SNP, "AMD SEV-Secure Nested Paging (SEV-SNP) adds memory integrity protection to SEV-ES. Uses reverse map tables (RMP) to prevent hypervisor-mediated replay/spoofing attacks. Enables attested launch for cloud workloads via guest policy certificates and AMD's Key Distribution Service (KDS)." },
        { VM::brands::NEKO_PROJECT, "Neko Project II is an emulator designed for emulating PC-98 computers. They are a lineup of Japanese 16-bit and 32-bit personal computers manufactured by NEC from 1982 to 2003. While based on Intel processors, it uses an in-house architecture making it incompatible with IBM clones." },
        { VM::brands::NOIRVISOR, "NoirVisor is a hardware-accelerated hypervisor with support to complex functions and purposes. It is designed to support processors based on x86 architecture with hardware-accelerated virtualization feature. For example, Intel processors supporting Intel VT-x or AMD processors supporting AMD-V meet the requirement. It was made by Zero-Tang." },
        { VM::brands::QIHOO, "360 sandbox is a part of 360 Total Security. Similar to other sandbox software, it provides a virtualized environment where potentially malicious or untrusted programs can run without affecting the actual system. Qihoo 360 Sandbox is commonly used for testing unknown applications, analyzing malware behavior, and protecting users from zero-day threats." },
        { VM::brands::DBVM, "DBVM is a ultra-lightweight virtual machine host that makes Windows run in a virtual machine so that Cheat Engine can operate at a higher level than the OS using a device driver. Instead of virtualizing devices it generally passes on interrupts unaltered meaning it has a very small impact on performance." },
        { VM::brands::UTM, "UTM for macOS is a free, open-source virtualization and emulation app that brings full-featured virtual machines to both Intel and Apple Silicon Macs. It employs Apple's Hypervisor virtualization framework to run ARM64 operating systems on Apple Silicon at near native speeds. On other architectures, it employs software emulation through QEMU." },
        { VM::brands::COMPAQ, "Compaq FX!32 is an emulator that is designed to run Win32 programs for the DEC instruction set architecture. Released in 1996, it was developed by developed by Digital Equipment Corporation (DEC) to support their Alpha microprocessors. It analyzed the way programs worked and, after the program ran, used binary translation to produce dynamic-link library (DLL) files of native Alpha code that the application could execute the next time it ran." },
        { VM::brands::INSIGNIA, "RealPC was an emulator for the Macintosh line of PCs. It emulated a Pentium-based PC to run Windows NT, Windows 95, and Windows 98 programs. It was discontinued in 2003." },
        { VM::brands::CONNECTIX, "Connectix VirtualPC was the predecessor to Microsoft's VirtualPC. Originally developed as a Macintosh application for System 7.5 and released by Connectix in June 1997, it supported various OS's such as Linux and old versions of Windows. It was bought by Microsoft in February 2003." },
        { VM::brands::CONTAINERD, "Containerd is an industry-standard container runtime used as the core engine beneath Docker, Kubernetes, and other container platforms. It manages the complete container lifecycle including image transfer, storage, execution, and supervision." },
        { VM::brands::NULL_BRAND, "Indicates no detectable virtualization brand. This result may occur on bare-metal systems, unsupported/obscure hypervisors, or when anti-detection techniques (e.g., VM escaping) are employed by the guest environment." }
    };

    for (const auto& entry : table) {
        if (vm_brand == entry.brand) {
            return entry.description;
        }
    }
    return "";
}

static void checker(const VM::enum_flags flag, const char* message) {
    std::string enum_name;

    if (arg_bitset.test(ENUMS)) {
        enum_name = grey + " [VM::" + VM::flag_to_string(flag) + "]" + ansi_exit;
    }

    if (is_disabled(flag)) {
        disabled_count++;
        std::ostringstream skip_oss;
        skip_oss << tag_skipped << " " << grey << "Skipped " << message << "." << ansi_exit;
        PRINT_LINE(skip_oss.str());
        return;
    }

    if (is_unsupported(flag)) {
        unsupported_count++;
        if (arg_bitset.test(ALL) == false) {
            return;
        }
    }

    supported_count++;

    auto start_time = std::chrono::high_resolution_clock::now();
    const bool result = VM::check(flag);
    auto end_time = std::chrono::high_resolution_clock::now();

    const double ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();

    if (arg_bitset.test(DETECTED_ONLY) && !result) {
        return;
    }

    #if (CLI_LINUX)
        if (are_perms_required(flag)) {
            no_perms_count++;
            VM::check(flag);
            std::ostringstream perms_oss;
            perms_oss << tag_no_perms << " " << grey << "Skipped " << message << "." << ansi_exit;
            PRINT_LINE(perms_oss.str());
            return;
        }
    #endif

    std::ostringstream cycle_oss;
    cycle_oss << dim << message << " | " << white << std::fixed << std::setprecision(4) << ms << " ms" << ansi_exit;
    #if (CLI_WINDOWS)
        g_tui.addCycle(cycle_oss.str());
    #endif

    std::ostringstream msg_oss;

    if (result) {
        msg_oss << white << tag_detected << " " << white << "Checking " << message << "..." << ansi_exit << enum_name;
    } else {
        msg_oss << tag_not_detected << " " << grey << "Checking " << message << "..." << ansi_exit << enum_name;
    }

    PRINT_LINE(msg_oss.str());
}

bool parse_disable_token(const char* token) {
    const std::string tok(token);
    std::vector<std::string> names;
    std::string current;

    for (const char c : tok) {
        if (c == ',') {
            if (!current.empty()) {
                names.push_back(current);
                current.clear();
            }
        } else {
            current += c;
        }
    }

    if (!current.empty()) {
        names.push_back(current);
    }

    for (const auto& name : names) {
        const std::pair<bool, VM::enum_flags> technique = string_to_technique(name);

        const bool found = technique.first;
        const VM::enum_flags flag = technique.second;

        if (!found) {
            std::cerr << "Unknown technique \"" << name << "\", aborting\n";
            return false;
        }

        VM::disabled_techniques.push_back(flag);
    }

    return true;
}

void generate_json(const char* output) {
    std::vector<std::string> json;

    json.emplace_back("{");
    json.emplace_back("\n\t\"is_detected\": ");

    if (VM::detect()) {
        json.emplace_back("true,");
    }
    else {
        json.emplace_back("false,");
    }

    json.emplace_back("\n\t\"brand\": \"");
    json.push_back(VM::brand());
    json.emplace_back("\",");

    json.emplace_back("\n\t\"conclusion\": \"");
    json.push_back(VM::conclusion());
    json.emplace_back("\",");

    json.emplace_back("\n\t\"percentage\": ");
    json.push_back(std::to_string(static_cast<int>(VM::percentage())));
    json.emplace_back(",");

    json.emplace_back("\n\t\"detected_technique_count\": ");
    json.push_back(std::to_string(VM::technique_count));
    json.emplace_back(",");

    json.emplace_back("\n\t\"vm_type\": \"");
    json.push_back(VM::type());
    json.emplace_back("\",");

    json.emplace_back("\n\t\"is_hardened\": ");

    if (VM::is_hardened()) {
        json.emplace_back("true,");
    } else {
        json.emplace_back("false,");
    }

    json.emplace_back("\n\t\"detected_techniques\": [");

    const auto detected_status = VM::detected_enums();

    if (detected_status.empty()) {
        json.emplace_back("]\n}");
    } else {
        for (size_t i = 0; i < detected_status.size(); i++) {
            json.emplace_back("\n\t\t\"");
            json.push_back(VM::flag_to_string(detected_status[i]));

            if (i == detected_status.size() - 1) {
                json.emplace_back("\"");
            } else {
                json.emplace_back("\",");
            }
        }
        json.emplace_back("\n\t]\n}");
    }

    std::ofstream file(output);

    if (!file) {
        std::cerr << "Failed to open/create file\n";
        return;
    }

    for (const auto& line : json) {
        file << line;
    }

    file.close();
}

u32 get_technique_count() {
    return static_cast<u32>(VM::technique_count);
}

int run_stdout(bool high_threshold, bool all, bool dynamic) {
    return static_cast<int>(!VM::detect(
        high_threshold ? VM::HIGH_THRESHOLD : VM::NULL_ARG,
        all ? VM::ALL : VM::NULL_ARG,
        dynamic ? VM::DYNAMIC : VM::NULL_ARG
    ));
}

u32 run_percent(bool high_threshold, bool all, bool dynamic) {
    return static_cast<u32>(VM::percentage(
        high_threshold ? VM::HIGH_THRESHOLD : VM::NULL_ARG,
        all ? VM::ALL : VM::NULL_ARG,
        dynamic ? VM::DYNAMIC : VM::NULL_ARG
    ));
}

bool run_detect(bool high_threshold, bool all, bool dynamic) {
    return VM::detect(
        high_threshold ? VM::HIGH_THRESHOLD : VM::NULL_ARG,
        all ? VM::ALL : VM::NULL_ARG,
        dynamic ? VM::DYNAMIC : VM::NULL_ARG
    );
}

std::string run_brand(bool high_threshold, bool all, bool dynamic) {
    return VM::brand(
        VM::MULTIPLE,
        high_threshold ? VM::HIGH_THRESHOLD : VM::NULL_ARG,
        all ? VM::ALL : VM::NULL_ARG,
        dynamic ? VM::DYNAMIC : VM::NULL_ARG
    );
}

std::string run_type(bool high_threshold, bool all, bool dynamic) {
    return VM::type(
        VM::MULTIPLE,
        high_threshold ? VM::HIGH_THRESHOLD : VM::NULL_ARG,
        all ? VM::ALL : VM::NULL_ARG,
        dynamic ? VM::DYNAMIC : VM::NULL_ARG
    );
}

std::string run_conclusion(bool high_threshold, bool all, bool dynamic) {
    return VM::conclusion(
        VM::MULTIPLE,
        high_threshold ? VM::HIGH_THRESHOLD : VM::NULL_ARG,
        all ? VM::ALL : VM::NULL_ARG,
        dynamic ? VM::DYNAMIC : VM::NULL_ARG
    );
}

void general(bool high_threshold, bool all, bool dynamic, const char* output_file) {
    const VM::enum_flags high_thresh_arg = high_threshold ? VM::HIGH_THRESHOLD : VM::NULL_ARG;
    const VM::enum_flags all_arg = all ? VM::ALL : VM::NULL_ARG;
    const VM::enum_flags dynamic_arg = dynamic ? VM::DYNAMIC : VM::NULL_ARG;

    #if (CLI_LINUX)
        [[maybe_unused]] const bool notes_enabled = !arg_bitset.test(NOTES);
    #endif

    std::ofstream output_fstream;
    std::streambuf* original_cout_buf = nullptr;

    if (output_file) {
        output_fstream.open(output_file);
        if (!output_fstream) {
            std::cerr << "Failed to open/create file \"" << output_file << "\"\n";
        } else {
            original_cout_buf = std::cout.rdbuf(output_fstream.rdbuf());
            arg_bitset.set(NO_ANSI);
        }
    }

    if (arg_bitset.test(NO_ANSI)) {
        tag_detected = ("[  DETECTED  ]");
        tag_not_detected = ("[NOT DETECTED]");
        tag_skipped = ("[  DISABLED  ]");
        tag_notes = ("[    NOTE    ]");
        bold = ""; 
        underline = ""; 
        ansi_exit = ""; 
        red = ""; 
        orange = "";
        green = ""; 
        red_orange = ""; 
        green_orange = "";
        grey = ""; 
        white = "";
    }

    #if (CLI_WINDOWS)
        std::unique_ptr<DebugInterceptor> interceptor;
        if (!arg_bitset.test(NO_ANSI) && arg_bitset.test(RICH)) {
            g_tui.init();
            interceptor = std::make_unique<DebugInterceptor>(std::cout.rdbuf());
            std::cout.rdbuf(interceptor.get());
        }
    #endif

    #if (CLI_LINUX)
        if (notes_enabled && !is_admin()) {
            PRINT_LINE("Running under root might give better results");
        }
    #elif (CLI_WINDOWS)
        if (!is_admin() && arg_bitset.test(RICH)) {
            do {
                std::ostringstream _oss;
                _oss << red << "Not running as administrator, NVRAM checks will not run.\n";
                g_tui.printLeft(_oss.str());
            } while (0);
        }
    #endif

    const auto t1 = std::chrono::high_resolution_clock::now();

    checker(VM::VMID, "VMID");
    checker(VM::CPU_BRAND, "CPU brand");
    checker(VM::HYPERVISOR_BIT, "CPUID hypervisor bit");
    checker(VM::HYPERVISOR_STR, "hypervisor str");
    checker(VM::THREAD_COUNT, "thread count");
    checker(VM::MAC, "MAC addresses");
    checker(VM::TEMPERATURE, "temperature");
    checker(VM::SYSTEMD, "systemd virtualisation");
    checker(VM::CVENDOR, "chassis vendor");
    checker(VM::CTYPE, "chassis type");
    checker(VM::DOCKERENV, "Dockerenv");
    checker(VM::DMIDECODE, "dmidecode output");
    checker(VM::DMESG, "dmesg output");
    checker(VM::HWMON, "hwmon presence");
    checker(VM::DLL, "DLLs");
    checker(VM::WINE, "Wine");
    checker(VM::HWMODEL, "hw.model");
    checker(VM::PROCESSES, "processes");
    checker(VM::LINUX_USER_HOST, "default Linux user/host");
    checker(VM::GAMARUE, "gamarue ransomware technique");
    checker(VM::BOCHS_CPU, "BOCHS CPU techniques");
    checker(VM::MAC_MEMSIZE, "MacOS hw.memsize");
    checker(VM::MAC_IOKIT, "MacOS registry IO-kit");
    checker(VM::IOREG_GREP, "IO registry grep");
    checker(VM::MAC_SIP, "MacOS SIP");
    checker(VM::AUDIO, "audio devices");
    checker(VM::HANDLES, "device handles");
    checker(VM::VPC_INVALID, "VPC invalid instructions");
    checker(VM::SYSTEM_REGISTERS, "Task segment and descriptor tables");
    checker(VM::VMWARE_IOMEM, "/proc/iomem file");
    checker(VM::VMWARE_IOPORTS, "/proc/ioports file");
    checker(VM::VMWARE_SCSI, "/proc/scsi/scsi file");
    checker(VM::VMWARE_DMESG, "VMware dmesg");
    checker(VM::VMWARE_STR, "STR instruction");
    checker(VM::VMWARE_BACKDOOR, "VMware IO port backdoor");
    checker(VM::MUTEX, "mutex strings");
    checker(VM::THREAD_MISMATCH, "thread count mismatch");
    checker(VM::CUCKOO_DIR, "Cuckoo directory");
    checker(VM::CUCKOO_PIPE, "Cuckoo pipe");
    checker(VM::AZURE, "Azure Hyper-V");
    checker(VM::DISPLAY, "display");
    checker(VM::DEVICE_STRING, "bogus device string");
    checker(VM::BLUESTACKS_FOLDERS, "BlueStacks folders");
    checker(VM::CPUID_SIGNATURE, "CPUID signatures");
    checker(VM::KGT_SIGNATURE, "Intel KGT signature");
    checker(VM::QEMU_VIRTUAL_DMI, "QEMU virtual DMI directory");
    checker(VM::QEMU_USB, "QEMU USB");
    checker(VM::HYPERVISOR_DIR, "hypervisor directory (Linux)");
    checker(VM::UML_CPU, "User-mode Linux CPU");
    checker(VM::KMSG, "/dev/kmsg hypervisor message");
    checker(VM::VBOX_MODULE, "VBox kernel module");
    checker(VM::SYSINFO_PROC, "/proc/sysinfo");
    checker(VM::DMI_SCAN, "DMI scan");
    checker(VM::SMBIOS_VM_BIT, "SMBIOS VM bit");
    checker(VM::PODMAN_FILE, "podman file");
    checker(VM::WSL_PROC, "WSL string in /proc");
    checker(VM::DRIVERS, "driver names");
    checker(VM::DISK_SERIAL, "disk serial number");
    checker(VM::IVSHMEM, "IVSHMEM device");
    checker(VM::GPU_CAPABILITIES, "GPU capabilities");
    checker(VM::POWER_CAPABILITIES, "power capabilities");
    checker(VM::QEMU_FW_CFG, "QEMU fw_cfg device");
    checker(VM::VIRTUAL_PROCESSORS, "virtual processors");
    checker(VM::HYPERVISOR_QUERY, "hypervisor query");
    checker(VM::AMD_SEV_MSR, "AMD-SEV MSR");
    checker(VM::VIRTUAL_REGISTRY, "registry emulation");
    checker(VM::FIRMWARE, "firmware");
    checker(VM::FILE_ACCESS_HISTORY, "low file access count");
    checker(VM::CONTAINER_PID, "container PID");
    checker(VM::DEVICES, "PCI vendor/device ID");
    checker(VM::ACPI_SIGNATURE, "ACPI device signatures");
    checker(VM::UD, "undefined exceptions");
    checker(VM::DBVM, "DBVM hypervisor");
    checker(VM::BOOT_LOGO, "boot logo");
    checker(VM::MAC_SYS, "system profiler");
    checker(VM::KERNEL_OBJECTS, "kernel objects");
    checker(VM::NVRAM, "NVRAM");
    checker(VM::EDID, "EDID");
    checker(VM::CLOCK, "system timers");
    checker(VM::MSR, "model specific registers");
    checker(VM::CPU_HEURISTIC, "instruction capabilities");
    checker(VM::INTERRUPT_SHADOW, "interrupt shadows");
    checker(VM::TRAP, "hypervisor interception");
    checker(VM::KVM_INTERCEPTION, "KVM interception");
    checker(VM::HYPERVISOR_HOOK, "EPT/NPT hooking");
    checker(VM::SINGLE_STEP, "single step behavior");
    checker(VM::EIP_OVERFLOW, "instructions in compat mode");
    checker(VM::SVM_EXCEPTIONS, "SVM exceptions");
    checker(VM::CGROUP, "cgroup namespace");
    checker(VM::TIMER, "timing anomalies");

    const auto t2 = std::chrono::high_resolution_clock::now();
    const VM::vmaware vm(VM::MULTIPLE, high_thresh_arg, all_arg, dynamic_arg);
    std::vector<std::string> summary;

    const std::string brand = vm.brand;
    const bool is_red = ((brand == VM::brands::NULL_BRAND) || (brand == VM::brands::HYPERV_ROOT));
    summary.push_back(bold + "\nVM brand: " + ansi_exit + (is_red ? red : green) + brand + ansi_exit);

    if (!is_vm_brand_multiple(vm.brand)) {
        const std::string current_color = (vm.type == "Unknown" || vm.type == "Host machine") ? red : green;
        summary.push_back(bold + "VM type: " + ansi_exit + current_color + vm.type + ansi_exit);
    }

    const char* percent_color = nullptr;

    if (vm.percentage == 0) {
        percent_color = red.c_str();
    } else if (vm.percentage < 25) {
        percent_color = red_orange.c_str();
    } else if (vm.percentage < 50) {
        percent_color = orange.c_str();
    } else if (vm.percentage < 75) {
        percent_color = green_orange.c_str();
    } else {
        percent_color = green.c_str();
    }

    summary.push_back(bold + "VM likeliness: " + ansi_exit + percent_color + std::to_string(static_cast<u32>(vm.percentage)) + "%" + ansi_exit);

    summary.push_back(bold + "VM confirmation: " + ansi_exit + (vm.is_vm ? green : red) + (vm.is_vm ? "true" : "false") + ansi_exit);

    const char* count_color = nullptr;

    switch (vm.detected_count) {
        case 0: count_color = red.c_str(); break;
        case 1: count_color = red_orange.c_str(); break;
        case 2: count_color = orange.c_str(); break;
        case 3: count_color = orange.c_str(); break;
        case 4: count_color = green_orange.c_str(); break;
        default: count_color = green.c_str();
    }

    summary.push_back(bold + "VM detections: " + ansi_exit + count_color + std::to_string(static_cast<u32>(vm.detected_count)) + "/" + std::to_string(static_cast<u32>(vm.technique_count)) + ansi_exit);
    summary.push_back(bold + "VM hardening: " + ansi_exit + (vm.is_hardened ? (green + "likely") : (grey + "unlikely")) + ansi_exit);
    summary.emplace_back("");

    if (arg_bitset.test(VERBOSE)) {
        summary.push_back(bold + "Unsupported detections: " + ansi_exit + std::to_string(static_cast<u32>(unsupported_count)));
        summary.push_back(bold + "Supported detections: " + ansi_exit + std::to_string(static_cast<u32>(supported_count)));
        summary.push_back(bold + "No permission detections: " + ansi_exit + std::to_string(static_cast<u32>(no_perms_count)));
        summary.push_back(bold + "Disabled detections: " + ansi_exit + std::to_string(static_cast<u32>(disabled_count)));

        const std::chrono::duration<double, std::milli> elapsed = t2 - t1;
        summary.push_back(bold + "Execution speed: " + ansi_exit + std::to_string(elapsed.count()) + "ms");
        summary.emplace_back("");
    }

    if (vm.brand != VM::brands::NULL_BRAND) {
        const std::string description = get_vm_description(vm.brand);
        if (!description.empty()) {
            summary.push_back(bold + underline + "VM description:" + ansi_exit);
            std::vector<std::string> divided_description;
            std::istringstream stream(description);
            std::string word_snippet;

            while (stream >> word_snippet) {
                divided_description.push_back(word_snippet);
            }

            std::size_t char_count = 0;
            for (auto it = divided_description.begin(); it != divided_description.end(); ++it) {
                char_count += it->length() + 1;
                if (char_count <= 60) {
                    continue;
                }

                if ((static_cast<unsigned long long>(char_count) - 1) >= (static_cast<unsigned long long>(60) + 3)) {
                    it = divided_description.insert(it + 1, "\n");
                    char_count = it->length() + 1;
                } else {
                    continue;
                }
            }

            std::ostringstream desc_oss;
            for (const auto& str : divided_description) {
                desc_oss << str << ((str != "\n") ? " " : "");
            }

            std::istringstream format_stream(desc_oss.str());
            std::string current_line;
            while (std::getline(format_stream, current_line)) {
                summary.push_back(current_line);
            }
            summary.emplace_back("");
        }
    }

    const std::string is_bold = (vm.is_vm ? bold : "");
    const char* conclusion_color = color(vm.percentage, vm.is_hardened);

    summary.push_back(
        bold + 
        "===== CONCLUSION: " + 
        ansi_exit + 
        conclusion_color + 
        is_bold + 
        vm.conclusion + 
        ansi_exit + 
        bold + 
        " =====\n" + 
        ansi_exit
    );

#if (CLI_WINDOWS)
    if (!arg_bitset.test(NO_ANSI) && arg_bitset.test(RICH)) {
        g_tui.drawSummaryBox(summary);

        g_tui.finalize();

        if (g_tui.raw_out) {
            *(g_tui.raw_out) << "\x1B[90mPress Enter, Q, or Ctrl+C to exit. Exceptions (Left/Right), Timings (Up/Down), Debug (PgUp/PgDn) to scroll.\x1B[0m\n";
        } else {
            std::cout << "\x1B[90mPress Enter, Q, or Ctrl+C to exit. Exceptions (Left/Right), Timings (Up/Down), Debug (PgUp/PgDn) to scroll.\x1B[0m\n";
        }

        constexpr u8 KEY_ESCAPE_PREFIX = 0;
        constexpr u8 KEY_EXTENDED = 224;
        constexpr u8 KEY_UP = 72;
        constexpr u8 KEY_DOWN = 80;
        constexpr u8 KEY_PAGE_UP = 73;
        constexpr u8 KEY_PAGE_DOWN = 81;
        constexpr u8 KEY_LEFT = 75;
        constexpr u8 KEY_RIGHT = 77;
        constexpr u8 KEY_CTRL_C = 3;

        while (true) {
            int ch = _getch();

            if (ch == KEY_ESCAPE_PREFIX || ch == KEY_EXTENDED) {
                ch = _getch();

                switch (ch) {
                    case KEY_UP: g_tui.scrollCyclesUp(); continue;
                    case KEY_DOWN: g_tui.scrollCyclesDown(); continue;
                    case KEY_PAGE_UP: g_tui.scrollDebugUp(); continue;
                    case KEY_PAGE_DOWN: g_tui.scrollDebugDown(); continue;
                    case KEY_LEFT: g_tui.scrollExceptionsUp(); continue;
                    case KEY_RIGHT: g_tui.scrollExceptionsDown(); continue;
                    default: continue;
                }
            }

            bool should_break = false;

            switch (ch) {
                case '\r':
                case '\n':
                case 'q':
                case 'Q':
                case KEY_CTRL_C:
                    should_break = true;
            }

            if (should_break) {
                break;
            }
        }

        if (interceptor) {
            std::cout.rdbuf(interceptor->original);
        }
    } else {
        for (const auto& l : summary) {
            std::cout << l << "\n";
        }
    }
#else
    for (const auto& line : summary) {
        std::cout << line << "\n";
    }

    if (original_cout_buf) {
        std::cout.rdbuf(original_cout_buf);
    }
#endif
}