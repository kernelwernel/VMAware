# Documentation

## Contents
- [`VM::detect()`](#vmdetect)
- [`VM::percentage()`](#vmpercentage)
- [`VM::brand()`](#vmbrand)
- [`VM::check()`](#vmcheck)
- [`VM::add_custom()`](#vmaddcustom)
- [Flag table](#flag-table)
- [Non-technique flags](#non-technique-flags)
- [Variables](#variables)
- [CLI arguments](#cli-documentation)


<br>

## `VM::detect()`

This is basically the main function you're looking for, which returns a bool. If the parameter is set to nothing, all the recommended checks will be performed. But you can optionally set what techniques are used.

```cpp
#include "vmaware.hpp"

int main() {
    /**
     * The basic way to detect a VM where the default checks will 
     * be performed. This is the recommended usage of the library.
     */ 
    bool is_vm = VM::detect();


    /**
     * This does the exact same as above, but as an explicit alternative.
     */ 
    bool is_vm2 = VM::detect(VM::DEFAULT);


    /**
     * Essentially means only the CPU brand, MAC, and hypervisor bit techniques 
     * should be performed. Note that the less flags you provide, the more 
     * likely the result will not be accurate. If you just want to check for 
     * a single technique, use VM::check() instead. Also, read the flag table
     * at the end of this doc file for a full list of technique flags.
     */
    bool is_vm3 = VM::detect(VM::CPU_BRAND, VM::MAC, VM::HYPERVISOR_BIT);


    /**
     * All checks are performed including the cursor check, 
     * which waits 5 seconds for any human mouse interaction 
     * to detect automated virtual environments. This is the 
     * only technique that's disabled by default but if you're 
     * fine with having a 5 second delay, add VM::ALL 
     */ 
    bool is_vm4 = VM::detect(VM::ALL);


    /**
     * If you don't want the value to be memoized for whatever reason, 
     * you can set the VM::NO_MEMO flag and the result will not be cached. 
     * It's recommended to use this flag if you're only using one function
     * from the public interface a single time in total, so no unneccessary 
     * caching will be operated when you're not going to re-use the previously 
     * stored result at the end. 
     */ 
    bool is_vm5 = VM::detect(VM::NO_MEMO);


    /**
     * This will set the threshold bar to detect a VM higher than the default threshold.
     * Use this if you want to be extremely sure if it's a VM, but this can risk the result
     * to be a false negative. Use VM::percentage() for a more precise result if you want.
     */ 
    bool is_vm6 = VM::detect(VM::HIGH_THRESHOLD);


    /**
     * If you want to disable any technique for whatever reason, use VM::DISABLE(...).
     * This code snippet essentially means "perform all the default flags, but only 
     * disable the VM::RDTSC technique". 
     */ 
    bool is_vm7 = VM::detect(VM::DISABLE(VM::RDTSC));


    /**
     * Same as above, but you can disable multiple techniques at the same time.
     */ 
    bool is_vm8 = VM::detect(VM::DISABLE(VM::VMID, VM::RDTSC, VM::HYPERVISOR_BIT));


    /**
     * Hyper-V may be run on host systems where every host program could be virtualised by 
     * default. This is a Hyper-V specific problem where the library would make it seem 
     * like it gave you a false positive on a host system, even though it is in fact 
     * running inside a Hyper-V VM. The library will heuristically detect and disable 
     * Hyper-V default host virtualisations as "not running in a VM". This flag will
     * disable this heuristic mechanism. 
     * 
     * For further information, please check the VM::ENABLE_HYPERV_HOST flag information
     * in the non-technique flags section (situated around the end of this documentation).
     */ 
    bool is_vm9 = VM::detect(VM::ENABLE_HYPERV_HOST);


    /**
     * This is just an example to show that you can use a combination of different
     * flags and non-technique flags with the above examples. 
     */ 
    bool is_vm10 = VM::detect(VM::DEFAULT, VM::NO_MEMO, VM::HIGH_THRESHOLD, VM::DISABLE(VM::RDTSC, VM::VMID));

}
```

<br>

## `VM::percentage()`
This will return a `std::uint8_t` between 0 and 100. It'll return the certainty of whether it has detected a VM based on all the techniques available as a percentage. The lower the value, the less chance it's a VM. The higher the value, the more likely it is. 

```cpp
#include "vmaware.hpp"
#include <iostream>
#include <cstdint>

int main() {
    // uint8_t and unsigned char works too
    const std::uint8_t percent = VM::percentage();

    if (percent == 100) {
        std::cout << "Definitely a VM!\n";
    } else if (percent == 0) {
        std::cout << "Definitely NOT a VM";
    } else {
        std::cout << "Unsure if it's a VM";
    }

    // converted to std::uint32_t for console character encoding reasons
    std::cout << "percentage: " << static_cast<std::uint32_t>(percent) << "%\n"; 
}
```

> [!NOTE]
> you can use the same flag system as shown with `VM::detect()` for this function.

<br>

## `VM::brand()`
This will essentially return the VM brand as a `std::string`. The exact possible brand string return values are: 
- `VirtualBox`
- `VMware`
- `VMware Express`
- `VMware ESX`
- `VMware GSX`
- `VMware Workstation`
- `VMware Fusion`
- `bhyve`
- `QEMU`
- `KVM`
- `KVM Hyper-V Enlightenment`
- `QEMU+KVM`
- `Virtual PC`
- `Microsoft Hyper-V`
- `Microsoft Virtual PC/Hyper-V`
- `Microsoft x86-to-ARM`
- `Parallels`
- `Xen HVM`
- `ACRN`
- `QNX hypervisor`
- `Hybrid Analysis`
- `Sandboxie`
- `Docker`
- `Wine`
- `Virtual Apple`
- `Anubis`
- `JoeBox`
- `Thread Expert`
- `CWSandbox`
- `Comodo`
- `Bochs`
- `Lockheed Martin LMHS`   (yes, you read that right. The library can detect VMs running on US military fighter jets)
- `NVMM`
- `OpenBSD VMM`
- `Intel HAXM`
- `Unisys s-Par`
- `Cuckoo`
- `BlueStacks`
- `Jailhouse`
- `Apple VZ`
- `Intel KGT (Trusty)`

If none were detected, it will return `Unknown`. It's often NOT going to produce a satisfying result due to technical difficulties with accomplishing this, on top of being highly dependent on what mechanisms detected a VM. This is especially true for VMware sub-versions (ESX, GSX, Fusion, etc...) Don't rely on this function for critical operations as if it's your golden bullet. It's arguably unreliable and it'll most likely return `Unknown` (assuming it is actually running under a VM).

```cpp
#include "vmaware.hpp"
#include <string>

int main() {
    const std::string result = VM::brand();

    if (result == "KVM") {
        // do KVM specific stuff
    } else if (result == "VirtualBox") {
        // do vbox specific stuff
    } else {
        // you get the idea
    }
}
```


On rare occasions, there might be cases where there's multiple brands that have been detected, which might cause a conflicting output with an inaccurate result. To prevent this, you can use the `VM::MULTIPLE` flag that returns a **message** rather than a **VM brand string**. For example, if it found 2 conflicting brands, it will return `VMware or VirtualBox`. For 3 conflicts, it's `VMware or VirtualBox or QEMU` and so on.


```cpp
#include "vmaware.hpp"
#include <string>

int main() {
    // format: "vmbrand1 or vmbrand2 [or vmbrandx...]"
    const std::string result = VM::brand(VM::MULTIPLE);

    // example output: "VMware or Bochs"
    std::cout << result << "\n";

    // Keep in mind that there's no limit to how many conflicts there can be.
    // And if there's no conflict, it'll revert back to giving the brand string
    // normally as if the VM::MULTIPLE wasn't there
}
```

> [!NOTE]
> you can use the same flag system as shown with `VM::detect()` for `VM::brand()`

> [!IMPORTANT]
> `VM::MULTIPLE` has no effect for any other function other than `VM::brand()`


<br>

## `VM::check()`
This takes a single flag argument and returns a `bool`. It's essentially the same as `VM::detect()` but it doesn't have a scoring system. It only returns the technique's effective output. The reason why this exists is because it allows end-users to have fine-grained control over what is being executed and what isn't. 

`VM::detect()` is meant for a range of techniques to be evaluated in the bigger picture with weights and biases in its scoring system, while `VM::check()` is meant for a single technique to be evaluated without any weights or anything extra. It very simply just gives you what the technique has found on its own. For example:

```cpp
#include "vmaware.hpp"
#include <iostream>

int main() {
    if (VM::check(VM::VMID)) {
        std::cout << "VMID technique detected a VM!\n";
    }

    if (VM::check(VM::HYPERVISOR_BIT)) {
        std::cout << "Hypervisor bit is set, most definitely a VM!\n";
    }
}
```

<br>



<br>

## `VM::add_custom()`
This function allows you to add your own custom VM detection techniques to the scoring system. The first parameter is the percentage score (0 to 100) of how likely it's a VM if your custom code returns `true`, and the second parameter should either be a lambda, a function pointer, or a `std::function<bool()>`

```cpp
// Example 1 with function pointers

bool new_technique() {
    // add your VM detection code here
    return true; 
}

VM::add_custom(50, new_technique);
```

```cpp
// Example 2 with lambdas

VM::add_custom(50, []() -> bool { 
    // add your VM detection code here
    return true; 
});

auto new_technique = []() -> bool { 
    // add your VM detection code here
    return true;
}

VM::add_custom(50, new_technique);
```

```cpp
// Example 3 with std::function

std::function<bool()> new_technique = []() -> bool {
    // add your VM detection code here
    return true;
};

VM::add_custom(50, new_technique);
```

<br>

# Flag table
VMAware provides a convenient way to not only check for VMs, but also have the flexibility and freedom for the end-user to choose what techniques are used with complete control over what gets executed or not. This is handled with a flag system.


| ID | Flag alias | Description | Cross-platform? (empty = yes) | Certainty | Admin? | GPL-3.0? | 32-bit? |
| -- | ---------- | ----------- | --------------- | --------- | ------ | -------- | ------- |
| 0 | `VM::VMID` | Check if the CPU manufacturer ID matches that of a VM brand |  | 100% |  |  |  |
| 1 | `VM::CPU_BRAND` | Check if the CPU brand string contains any indications of VM keywords |  | 50% |  |  |  |
| 2 | `VM::HYPERVISOR_BIT` | Check if the hypervisor bit is set (always false on physical CPUs) |  | 100% |  |  |  |
| 3 |`VM::CPUID_0X4` | Check if there are any leaf values between 0x40000000 and 0x400000FF that changes the CPUID output |  | 20% |  |  |  |
| 4 | `VM::HYPERVISOR_STR` | Check if brand string length is long enough (would be around 2 characters in a host machine while it's longer in a hypervisor) |  | 45% |  |  |  |
| 5 | `VM::RDTSC` | Benchmark RDTSC and evaluate its speed, usually it's very slow in VMs | Linux and Windows | 10% |  |  |  |
| 6 | `VM::SIDT5` | Check if the 5th byte after sidt is null | Linux | 45% |  |  |  |
| 7 | `VM::THREADCOUNT` | Check if there are only 1 or 2 threads, which is a common pattern in VMs with default settings (nowadays physical CPUs should have at least 4 threads for modern CPUs) |  | 35% |  |  |  |
| 8 | `VM::MAC` | Check if the system's MAC address matches with preset values for certain VMs | Linux and Windows | 60% |  |  |  |
| 9 | `VM::TEMPERATURE` | Check for the presence of CPU temperature sensors (mostly not present in VMs) | Linux | 15% |    |  |
| 10 | `VM::SYSTEMD` | Get output from systemd-detect-virt tool | Linux | 70% |  |  |  |
| 11 | `VM::CVENDOR` | Check if the chassis has any VM-related keywords | Linux | 65% |  |  |  |
| 12 | `VM::CTYPE` | Check if the chassis type is valid (usually not in VMs) | Linux | 10% |  |  |  |
| 13 | `VM::DOCKERENV` | Check if any docker-related files are present such as /.dockerenv and /.dockerinit | Linux | 80% |  |  |  |
| 14 | `VM::DMIDECODE` | Get output from dmidecode tool and grep for common VM keywords | Linux | 55% | Admin |  |  |
| 15 | `VM::DMESG` | Get output from dmesg tool and grep for common VM keywords | Linux | 55% |  |  |  |
| 16 | `VM::HWMON` | Check if HWMON is present (if not, likely a VM) | Linux | 75% |  |  |  |
| 17 | `VM::CURSOR`  | Check if cursor isn't active (sign of automated VM environment) | Windows | 5% |  |  |  |
| 18 | `VM::VMWARE_REG` | Look for any VMware-specific registry data | Windows | 65% |  |  |  |
| 19 | `VM::VBOX_REG` | Look for any VirtualBox-specific registry data | Windows | 65% |  |  |  |
| 20 | `VM::USER` | Match the username for any defaulted ones | Windows | 35% |  |  |  |
| 21 | `VM::DLL` | Match for VM-specific DLLs | Windows | 50% |  |  |  |
| 22 | `VM::REGISTRY` | Look throughout the registry for all sorts of VMs | Windows | 75% |  |  |  |
| 23 | `VM::CWSANDBOX_VM` | Detect for Sunbelt technology CWSandbox VM | Windows | 10% |  |  |  |
| 24 | `VM::WINE_CHECK` | Find for a Wine-specific file | Windows | 85% |  | GPL |  |
| 25 | `VM::VM_FILES` | Find if any VM-specific files exists | Windows | 10% |  |  |  |
| 26 | `VM::HWMODEL` | Check if the sysctl for the hwmodel does not contain the "Mac" string | MacOS | 75% |  |  |  |
| 27 | `VM::DISK_SIZE` | Check if disk size is under or equal to 50GB | Linux | 60% |  |  |  |
| 28 | `VM::VBOX_DEFAULT` | Check for default RAM and DISK sizes set by VirtualBox | Linux and Windows | 55% | Admin |  |  |
| 29 | `VM::VBOX_NETWORK` | Check VBox network provider string | Windows | 70% |  |  |   |
| 30 | `VM::COMPUTER_NAME` | Check for computer name string | Windows | 40% |  | GPL |  |
| 31 | `VM::HOSTNAME` | Check if hostname is specific | Windows | 25% |  | GPL |  |
| 32 | `VM::MEMORY` | Check if memory space is far too low for a physical machine | Windows | 35% |  | GPL |  |
| 33 | `VM::VM_PROCESSES` | Check for any VM processes that are active | Windows | 30% |  |  |  |
| 34 | `VM::LINUX_USER_HOST` | Check for default VM username and hostname for linux | Linux | 25% |  |  |  |
| 35 | `VM::VBOX_WINDOW_CLASS` | Check for the window class for VirtualBox | Windows | 10% |  | GPL |  |
| 36 | `VM::GAMARUE` | Check for Gamarue ransomware technique which compares VM-specific Window product IDs | Windows | 40% |  |  |  |
| 37 | `VM::VMID_0X4` | Check if the CPU manufacturer ID matches that of a VM brand with leaf 0x40000000 |  | 100% |  |  |  |
| 38 | `VM::PARALLELS_VM` | Check for indications of Parallels VM | Windows | 50% |  |  |  |
| 39 | `VM::RDTSC_VMEXIT` | Check for RDTSC technique with VMEXIT |  | 25% |  |  |  |
| 40 | `VM::LOADED_DLLS` | Check for DLLs of multiple VM brands | Windows | 75% |  | GPL |  |
| 41 | `VM::QEMU_BRAND` | Check for QEMU CPU brand with cpuid |  | 100% |  |  |  |
| 42 | `VM::BOCHS_CPU` | Check for Bochs cpuid emulation oversights |  | 95% |  |  |  |
| 43 | `VM::VPC_BOARD` | Check for VPC specific string in motherboard manufacturer | Windows | 20% |  |  |  |
| 44 | `VM::HYPERV_WMI` | Check for Hyper-V wmi output | Windows | 80% |  |  |  |
| 45 | `VM::HYPERV_REG` | Check for Hyper-V strings in registry | Windows | 80% |  |  |  |
| 46 | `VM::BIOS_SERIAL` | Check if BIOS serial number is null | Windows | 60% |  |  |  |
| 47 | `VM::VBOX_FOLDERS` | Check for VirtualBox-specific string for shared folder ID | Windows | 45% |  |  |  |
| 48 | `VM::MSSMBIOS` | Check VirtualBox MSSMBIOS registry for VM-specific strings | Windows | 75% |  |  |  |
| 49 | `VM::MAC_MEMSIZE` | Check if memory is too low for MacOS system | MacOS | 30% |  |  |  |
| 50 | `VM::MAC_IOKIT` | Check MacOS' IO kit registry for VM-specific strings | MacOS | 80% |  |  |  |
| 51 | `VM::IOREG_GREP` | Check for VM-strings in ioreg commands for MacOS | MacOS | 75% |  |  |  |
| 52 | `VM::MAC_SIP` | Check if System Integrity Protection is disabled (likely a VM if it is) | MacOS | 85% |  |  |  |
| 53 | `VM::KVM_REG` | Check for KVM-specific registry strings | Windows | 75% |  | GPL |  |
| 54 | `VM::KVM_DRIVERS` | Check for KVM-specific system files in system driver directory | Windows | 55% |  | GPL |  |
| 55 | `VM::KVM_DIRS` | Check for KVM-specific directories | Windows | 55% |  | GPL |  |
| 56 | `VM::HKLM_REGISTRIES` | Check for HKLM-based registry keys | Windows | 70% |  |  |  |
| 57 | `VM::AUDIO` | Check if audio device is present | Windows | 35% |  | GPL |  |
| 58 | `VM::QEMU_GA` | Check for the "qemu-ga" process | Linux | 20% |  |  |  |
| 59 | `VM::VALID_MSR` | Check for valid MSR value | Windows | 35% |  |  |  |
| 60 | `VM::QEMU_PROC` | Check for QEMU processes | Windows | 30% |  |  |  |
| 61 | `VM::QEMU_DIR` | Check for QEMU-specific blacklisted directories | Windows | 45% |  | GPL |  |
| 62 | `VM::VPC_PROC` | Check for VPC processes | Windows | 30% |  |  |  |
| 63 | `VM::VPC_INVALID` | Check for official VPC method | Windows | 75% |  |  | 32-bit |
| 64 | `VM::SIDT` | Check for sidt instruction method | Linux, Windows | 30% |  |  |  |
| 65 | `VM::SGDT` | Check for sgdt instruction method | Windows | 30% |  |  | 32-bit |
| 66 | `VM::SLDT` | Check for sldt instruction method | Windows | 15% |  |  | 32-bit |
| 67 | `VM::OFFSEC_SIDT` | Check for Offensive Security SIDT method | Windows | 60% |  |  | 32-bit |
| 68 | `VM::OFFSEC_SGDT` | Check for Offensive Security SGDT method | Windows | 60% |  |  | 32-bit |
| 69 | `VM::OFFSEC_SLDT` | Check for Offensive Security SLDT method | Windows | 20% |  |  | 32-bit |
| 70 | `VM::VPC_SIDT` | Check for VPC range for SIDT | Windows | 15% |  |  | 32-bit |
| 71 | `VM::HYPERV_BOARD` | Check for Hyper-V string in motherboard | Windows | 45% |  |  |  |
| 72 | `VM::VM_FILES_EXTRA` | Check for VPC and Parallels files | Windows | 70% |  |  |  |
| 73 | `VM::VMWARE_IOMEM` | Check for VMware string in /proc/iomem | Linux | 65% |  |  |  |
| 74 | `VM::VMWARE_IOPORTS` | Check for VMware string in /proc/ioports | Linux | 70% |  |  |  |
| 75 | `VM::VMWARE_SCSI` | Check for VMware string in /proc/scsi/scsi | Linux | 40% |  |  |  |
| 76 | `VM::VMWARE_DMESG` | Check for VMware-specific device name in dmesg output | Linux | 65% |  |  |  |
| 77 | `VM::VMWARE_STR` | Check using str assembly instruction | Windows | 35% |  |  |  |
| 78 | `VM::VMWARE_BACKDOOR` | Check for official VMware io port backdoor technique | Windows | 100% |  |  | 32-bit |
| 79 | `VM::VMWARE_PORT_MEM` | Check for VMware memory using IO port backdoor | Windows | 85% |  |  | 32-bit |
| 80 | `VM::SMSW` | Check for SMSW assembly instruction technique | Windows | 30% |  |  | 32-bit |
| 81 | `VM::MUTEX` | Check for mutex strings of VM brands | Windows | 85% |  |  |  |
| 82 | `VM::UPTIME` | Check if uptime is less than or equal to 2 minutes |  | 10% |  |  |  |
| 83 | `VM::ODD_CPU_THREADS` | Check if the CPU has an odd number of CPU threads |  | 80% |  |  |  |
| 84 | `VM::INTEL_THREAD_MISMATCH` | Check if Intel "i series" CPUs have mismatched thread counts based on a database of threads on models |  | 85% |  |  |  |
| 85 | `VM::XEON_THREAD_MISMATCH` | Check if Intel Xeon CPUs have mismatched threads (same as above technique) |  | 85% |  |  |  |
| 86 | `VM::NETTITUDE_VM_MEMORY` | Check for specific VM memory regions | Windows | 75% |  |  |  |
| 87 | `VM::VMWARE_DEVICES` | Check for VMware device systems | Windows | 60% |  | GPL |  |
| 88 | `VM::HYPERV_CPUID` | Check for specific CPUID bit results in ecx |  | 20% |  |  |  |
| 89 | `VM::CUCKOO_DIR` | Check for Cuckoo specific directory | Windows | 15% |  |  |  |
| 90 | `VM::CUCKOO_PIPE` | Check for Cuckoo specific piping mechanism | Windows | 20% |  |  |  |
| 91 | `VM::HYPERV_HOSTNAME` | Check for default Azure hostname format (Azure uses Hyper-V as their base VM brand) | Windows, Linux | 50% |  |  |  |
| 92 | `VM::GENERAL_HOSTNAME` | Check for general hostnames that match with certain VM brands | Windows, Linux | 20% |  |  |  |
| 93 | `VM::SCREEN_RESOLUTION` | Check for pre-set screen resolutions commonly found in VMs | Windows | 10% |  |  |  |
| 94 | `VM::DEVICE_STRING` | Check for acceptance of bogus device string | Windows | 25% |  |  |  |
| 95 | `VM::MOUSE_DEVICE` | Check for presence of mouse device | Windows | 20% |  | GPL |  |
| 96 | `VM::HYPERV_SIGNATURE` | Check for "Hv#1" string in CPUID |  | 95% |  |  |  |
| 97 | `VM::HYPERV_BITMASK` | Check for reserved Hyper-V CPUID bitmask |  | 40% |  |  |  |
| 98 | `VM::KVM_BITMASK` | Check for reserved Hyper-V CPUID bitmask |  | 40% |  |  |  |
| 99 | `VM::CPUID_SPACING` | Check for 0x100 spacing in hypervisor leaf |  | 60% |  |  |  |
| 100 | `VM::KGT_SIGNATURE` | Check for Intel KGT (Trusty branch) hypervisor signature in CPUID |  | 80% |  |  |  |


<br>

# Non-technique flags
| Flag | Description |
|------|-------------|
| `VM::ALL` | This will enable all the technique flags, including the cursor check that's disabled by default. |
| `VM::NO_MEMO` | This will disable memoization, meaning the result will not be fetched through a previous computation of the `VM::detect()` function. Use this if you're only using a single function from the `VM` struct for a performance boost. |
| `VM::DEFAULT` | This represents a range of flags which are enabled if no default argument is provided. |
| `VM::ENABLE_HYPERV_HOST` | Windows 11 (and 10 if enabled manually) may have Hyper-V as a default virtualisation solution for any host program even if the OS is running as host. There isn't a way to detect whether the host program is ran in default virtualisation mode, or manually intended virtualisation. This is a Hyper-V specific problem, and the library will use heuristical methods to discard Hyper-V's host virtualiser as not running in a VM by default. But if this flag is enabled then it will still count it regardless of the risk that it might be Hyper-V's default host virtualisation for every host program. So basically this flag means that "I'm aware this program might be running in a default virtualised environment on host, but I'll still count this as running in a VM anyway whether it's default virtualisation or manually intended virtualisation". |
| `VM::MULTIPLE` | This is specific to `VM::brand()`. This will basically return a `std::string` message of what brands could be involved. For example, it could return "`VMware or VirtualBox`" instead of having a single brand string output. This has no effect if applied to any other functions than `VM::brand()`. |   
| `VM::HIGH_THRESHOLD` | This is specific to `VM::detect()` and `VM::percentage()`, which will set the threshold bar to confidently detect a VM by 3x higher. |

<br>

# Variables
| Variable | Type | Description |
|----------|------|-------------|
| `VM::technique_count` | `std::uint8_t` | This will store the number of VM detection techniques |
| `VM::technique_vector` | `std::vector<std::uint8_t>` | This will store all the technique macros as a vector. Useful if you're trying to loop through all the techniques for whatever operation you're performing. |

<br>

# CLI documentation
| Shorthand | Full command | Description |
|-----------|--------------|-------------|
| -h | --help | Prints the help menu |
| -v | --version | Prints the version and miscellaneous details |
| -d | --detect | Prints the VM detection result (1 = VM, 0 = baremetal) |
| -s | --stdout | Returns either 0 or 1 to STDOUT without any text output (0 = VM, 1 = baremetal) |
| -b | --brand | Prints the most likely brand |
| -l | --brand-list | Prints all the possible VM brand strings the CLI supports |
| -c | --conclusion | Prints the conclusion message string |
| -p | --percent | Prints the VM likeliness percentage between 0 and 100 |
| -n | --number | Prints the number of VM detection techniques it can performs |
|    | --disable-hyperv-host | Disable the possibility of Hyper-V default virtualisation result on host OS (this can be used as a combination with the above commands) |

> [!NOTE]
> If you want a general result of everything combined above, do not put any arguments. This is the intended way to use the CLI tool.
>