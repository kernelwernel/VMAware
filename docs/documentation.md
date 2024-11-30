# Documentation

## Contents
- [`VM::detect()`](#vmdetect)
- [`VM::percentage()`](#vmpercentage)
- [`VM::brand()`](#vmbrand)
- [`VM::check()`](#vmcheck)
- [`VM::add_custom()`](#vmaddcustom)
- [`VM::type()`](#vmtype)
- [`VM::conclusion()`](#vmconclusion)
- [`VM::detected_count()`](#vmdetected_count)
- [`VM::vmaware struct`](#vmaware-struct)
- [Flag table](#flag-table)
- [Brand table](#brand-table)
- [Setting flags](#setting-flags)
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
     * There are roughly 1/3 of all techniques that are considered to be "spoofable",
     * meaning that anybody can potentially cause a false positive by exploiting the
     * fact that the spoofable techniques checks for things that anybody can modify
     * (file data, registry, directories, etc...). This category of techniques are disabled 
     * by default, but they can be enabled with the VM::SPOOFABLE flag.
     */
    bool is_vm3 = VM::detect(VM::SPOOFABLE);


    /**
     * All checks are performed including spoofable techniques
     * and a few other techniques that are disabled by default,
     * one of which is VM::CURSOR which waits 5 seconds for any 
     * human mouse interaction to detect automated virtual environments.
     * If you're fine with having a 5 second delay, add VM::ALL 
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
     * Essentially means only the CPU brand, MAC, and hypervisor bit techniques 
     * should be performed. Note that the less flags you provide, the more 
     * likely the result will not be accurate. If you just want to check for 
     * a single technique, use VM::check() instead. Also, read the flag table
     * at the end of this doc file for a full list of technique flags.
     */
    bool is_vm7 = VM::detect(VM::CPU_BRAND, VM::MAC, VM::HYPERVISOR_BIT);


    /**
     * If you want to disable any technique for whatever reason, use VM::DISABLE(...).
     * This code snippet essentially means "perform all the default flags, but only 
     * disable the VM::RDTSC technique". 
     */ 
    bool is_vm8 = VM::detect(VM::DISABLE(VM::RDTSC));


    /**
     * Same as above, but you can disable multiple techniques at the same time.
     */ 
    bool is_vm9 = VM::detect(VM::DISABLE(VM::VMID, VM::RDTSC, VM::HYPERVISOR_BIT));


    /**
     * This is just an example to show that you can use a combination of 
     * different flags and non-technique flags with the above examples. 
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
        std::cout << "Definitely NOT a VM\n";
    } else {
        std::cout << "Unsure if it's a VM\n";
    }

    // converted to std::uint32_t for console character encoding reasons
    std::cout << "percentage: " << static_cast<std::uint32_t>(percent) << "%\n"; 
}
```

> [!NOTE]
> you can use the same flag system as shown with `VM::detect()` for this function.

<br>

## `VM::brand()`
This will essentially return the VM brand as a `std::string`. All the brands are listed [here](#brand-table)

If none were detected, it will return `Unknown`. It should be noted that this could be a common scenario even if you're running inside a VM due to technical difficulties with accomplishing this. This is especially true for VMware sub-versions (ESX, GSX, Fusion, etc...). It's not recommended to rely on this function for critical operations as if your whole program depends on it.

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
This takes a single technique argument and returns a `bool`. It essentially returns a technique's effective output. Nothing more, nothing less.


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

## `VM::type()`
This will return the VM type (or architecture) as a `std::string` based on the brand found. The possible return values are listed [here](#brand-table) in the `type` column.

```cpp
#include "vmaware.hpp"
#include <iostream>

int main() {
    // example output: VirtualBox is a Hypervisor (type 2) VM
    std::cout << VM::brand() " is a " << VM::type() << " VM\n";
}
```


<br>

## `VM::conclusion()`
This will return the "conclusion" message of what the overall result is as a `std::string`. The `[brand]` part might contain a brand or may as well be empty, depending on whether a brand has been found.
- `Running on baremetal`
- `Very unlikely a [brand] VM`
- `Unlikely a [brand] VM`
- `Potentially a [brand] VM`
- `Might be a [brand] VM`
- `Likely a [brand] VM`
- `Very likely a [brand] VM`
- `Running inside a [brand] VM`

<br>

## `VM::detected_count()`
This will fetch the number of techniques that have been detected as a `std::uint8_t`. Can't get any more simpler than that ¯\_(ツ)_/¯, how's your day btw?

<br>

# vmaware struct
If you prefer having an object to store all the relevant information about the program's environment instead of calling static member functions, you can use the `VM::vmaware` struct:

```cpp
struct vmaware {
    std::string brand;
    std::string type;
    std::string conclusion;
    bool is_vm;
    std::uint8_t percentage;
    std::uint8_t detected_count;
    std::uint8_t technique_count;
}; 
```

example:
```cpp
#include "vmaware.hpp"
#include <iostream>

int main() {
    VM::vmaware vm;

    std::cout << "Is this a VM? = " << vm.is_vm << "\n";
    std::cout << "How many techniques detected a VM? = " << vm.detected_count << "%\n";
    std::cout << "What's the VM's type? = " << vm.type << "%\n";
    std::cout << "What's the overview in a human-readable message?" << vm.conclusion << "\n";
}
```

> [!NOTE]
> the flag system is compatible for the struct constructor.


<br>


# Flag table
VMAware provides a convenient way to not only check for VMs, but also have the flexibility and freedom for the end-user to choose what techniques are used with complete control over what gets executed or not. This is handled with a flag system.


| Flag alias | Description | Cross-platform? (empty = yes) | Certainty | Admin? | GPL-3.0? | 32-bit only? | Spoofable? | Notes |
| ---------- | ----------- | ----------------------------- | --------- | ------ | -------- | ------------ | ---------- | ----- |
| `VM::VMID` | Check CPUID output of manufacturer ID for known VMs/hypervisors at leaf 0 |  | 100% |  |  |  |  |  |
| `VM::CPU_BRAND` | Check if CPU brand model contains any VM-specific string snippets |  | 50% |  |  |  |  |  |
| `VM::HYPERVISOR_BIT` | Check if hypervisor feature bit in CPUID eax bit 31 is enabled (always false for physical CPUs) |  | 100% |  |  |  |  |  |
| `VM::HYPERVISOR_STR` | Check for hypervisor brand string length (would be around 2 characters in a host machine) |  | 45% |  |  |  |  |  |
| `VM::RDTSC` | Benchmark RDTSC and evaluate its speed, usually it's very slow in VMs | Linux and Windows | 10% |  |  |  |  | Disabled by default |
| `VM::THREADCOUNT` | Check if there are only 1 or 2 threads, which is a common pattern in VMs with default settings (nowadays physical CPUs should have at least 4 threads for modern CPUs) |  | 35% |  |  |  |  |  |
| `VM::MAC` | Check if mac address starts with certain VM designated values | Linux and Windows | 60% |  |  |  | Spoofable |  |
| `VM::TEMPERATURE` | Check if thermal directory in linux is present, might not be present in VMs | Linux | 15% |    |  |  |  |
| `VM::SYSTEMD` | Check result from systemd-detect-virt tool | Linux | 70% |  |  |  |  |  |
| `VM::CVENDOR` | Check if the chassis vendor is a VM vendor | Linux | 65% |  |  |  |  |  |
| `VM::CTYPE` | Check if the chassis type is valid (it's very often invalid in VMs) | Linux | 10% |  |  |  |  |  |
| `VM::DOCKERENV` | Check if /.dockerenv or /.dockerinit file is present | Linux | 80% |  |  |  | Spoofable |  |
| `VM::DMIDECODE` | Check if dmidecode output matches a VM brand | Linux | 55% | Admin |  |  |  |  |
| `VM::DMESG` | Check if dmesg output matches a VM brand | Linux | 55% | Admin |  |  |  |  |
| `VM::HWMON` | Check if /sys/class/hwmon/ directory is present. If not, likely a VM | Linux | 75% |  |  |  | Spoofable |  |
| `VM::SIDT5` | Check if the 5th byte after sidt is null | Linux | 45% |  |  |  |  |  |
| `VM::CURSOR` |  Check if cursor isn't active for 5 seconds (sign of automated VM environment) | Windows | 5% |  |  |  | Spoofable | Disabled by default |
| `VM::VMWARE_REG` | Check for VBox RdrDN | Windows | 65% |  |  |  | Spoofable |  |
| `VM::VBOX_REG` | Look for any VirtualBox-specific registry data | Windows | 65% |  |  |  | Spoofable |  |
| `VM::USER` | checks for default usernames, often a sign of a VM | Windows | 35% |  |  |  | Spoofable |  |
| `VM::DLL` | Check for VM-specific DLLs | Windows | 50% |  |  |  | Spoofable |  |
| `VM::REGISTRY` |  Check for VM-specific registry values | Windows | 75% |  |  |  | Spoofable |  |
| `VM::CWSANDBOX_VM` | Check if CWSandbox-specific file exists | Windows | 10% |  |  |  | Spoofable |  |
| `VM::VM_FILES` | Find for VMware and VBox specific files | Windows | 10% |  |  |  | Spoofable |  |
| `VM::HWMODEL` | Check if the sysctl for the hwmodel does not contain the "Mac" string | MacOS | 75% |  |  |  | Spoofable |  |
| `VM::DISK_SIZE` | Check if disk size is under or equal to 50GB | Linux | 60% |  |  |  |  |  |
| `VM::VBOX_DEFAULT` | Check for default RAM and DISK sizes set by VirtualBox | Linux and Windows | 55% | Admin |  |  |  |  |
| `VM::VBOX_NETWORK` | Check for VirtualBox network provider string | Windows | 70% |  |  |   |  |  |
| `VM::COMPUTER_NAME` | Check if the computer name (not username to be clear) is VM-specific | Windows | 40% |  | GPL |  | Spoofable |  |
| `VM::WINE_CHECK` | Check wine_get_unix_file_name file for Wine | Windows | 85% |  | GPL |  |  |  |
| `VM::HOSTNAME` | Check if hostname is specific | Windows | 25% |  | GPL |  | Spoofable |  |
| `VM::MEMORY` | Check if memory space is far too low for a physical machine | Windows | 35% |  | GPL |  |  |  |
| `VM::VBOX_WINDOW_CLASS` | Check for the window class for VirtualBox | Windows | 10% |  | GPL |  |  |  |
| `VM::LOADED_DLLS` | Check for loaded DLLs in the process | Windows | 75% |  | GPL |  | Spoofable |  |
| `VM::KVM_REG` | Check for KVM-specific registry strings | Windows | 75% |  | GPL |  | Spoofable |  |
| `VM::KVM_DRIVERS` | Check for KVM-specific .sys files in system driver directory | Windows | 55% |  | GPL |  | Spoofable |  |
| `VM::KVM_DIRS` | Check for KVM directory "Virtio-Win" | Windows | 55% |  | GPL |  | Spoofable |  |
| `VM::AUDIO` | Check if audio device is present | Windows | 35% |  | GPL |  |  |  |
| `VM::QEMU_DIR` | Check for QEMU-specific blacklisted directories | Windows | 45% |  | GPL |  | Spoofable |  |
| `VM::MOUSE_DEVICE` | Check for the presence of a mouse device | Windows | 20% |  | GPL |  | Spoofable |  |
| `VM::VM_PROCESSES` | Check for any VM processes that are active | Windows | 30% |  |  |  | Spoofable |  |
| `VM::LINUX_USER_HOST` | Check for default VM username and hostname for linux | Linux | 25% |  |  |  | Spoofable |  |
| `VM::GAMARUE` | Check for Gamarue ransomware technique which compares VM-specific Window product IDs | Windows | 40% |  |  |  | Spoofable |  |
| `VM::VMID_0X4` | Check if the CPU manufacturer ID matches that of a VM brand with leaf 0x40000000 |  | 100% |  |  |  |  |  |
| `VM::PARALLELS_VM` | Check for any indication of Parallels VM through BIOS data | Windows | 50% |  |  |  |  |  |
| `VM::RDTSC_VMEXIT` | check through alternative RDTSC technique with VMEXIT |  | 25% |  |  |  |  | Disabled by default |
| `VM::QEMU_BRAND` | Match for QEMU CPU brands with "QEMU Virtual CPU" string |  | 100% |  |  |  |  |  |
| `VM::BOCHS_CPU` | Check for various Bochs-related emulation oversights through CPU checks |  | 95% |  |  |  |  |  |
| `VM::VPC_BOARD` | Check through the motherboard and match for VirtualPC-specific string | Windows | 20% |  |  |  |  |  |
| `VM::HYPERV_WMI` | Check WMI query for "Hyper-V RAW" string | Windows | 80% |  |  |  |  |  |
| `VM::HYPERV_REG` | Check presence for Hyper-V specific string in registry | Windows | 80% |  |  |  | Spoofable |  |
| `VM::BIOS_SERIAL` | Check if the BIOS serial is valid (null = VM) | Windows | 60% |  |  |  |  |  |
| `VM::VBOX_FOLDERS` | Check for VirtualBox-specific string for shared folder ID | Windows | 45% |  |  |  |  |  |
| `VM::MSSMBIOS` | Check MSSMBIOS registry for VM-specific strings | Windows | 75% |  |  |  |  |  |
| `VM::MAC_MEMSIZE` | Check if memory is too low for MacOS system | MacOS | 30% |  |  |  | Spoofable |  |
| `VM::MAC_IOKIT` | Check MacOS' IO kit registry for VM-specific strings | MacOS | 80% |  |  |  | Spoofable |  |
| `VM::IOREG_GREP` | Check for VM-strings in ioreg commands for MacOS | MacOS | 75% |  |  |  | Spoofable |  |
| `VM::MAC_SIP` | Check if System Integrity Protection is disabled (likely a VM if it is) | MacOS | 85% |  |  |  | Spoofable |  |
| `VM::HKLM_REGISTRIES` | Check HKLM registries for specific VM strings | Windows | 70% |  |  |  | Spoofable |  |
| `VM::QEMU_GA` | Check for "qemu-ga" process | Linux | 20% |  |  |  | Spoofable |  |
| `VM::VALID_MSR` | check for valid MSR value 0x40000000 | Windows | 35% |  |  |  |  |  |
| `VM::QEMU_PROC` | Check for QEMU processes | Windows | 30% |  |  |  | Spoofable |  |
| `VM::VPC_PROC` | Check for VPC processes | Windows | 30% |  |  |  | Spoofable |  |
| `VM::VPC_INVALID` | Check for official VPC method | Windows | 75% |  |  | 32-bit |  |  |
| `VM::SIDT` | Check for sidt instruction method | Linux, Windows | 30% |  |  |  |  |  |
| `VM::SGDT` | Check for sgdt instruction method | Windows | 30% |  |  | 32-bit |  |  |
| `VM::SLDT` | Check for sldt instruction method | Windows | 15% |  |  | 32-bit |  |  |
| `VM::OFFSEC_SIDT` | Check for Offensive Security SIDT method | Windows | 60% |  |  | 32-bit |  |  |
| `VM::OFFSEC_SGDT` | Check for Offensive Security SGDT method | Windows | 60% |  |  | 32-bit |  |  |
| `VM::OFFSEC_SLDT` | Check for Offensive Security SLDT method | Windows | 20% |  |  | 32-bit |  |  |
| `VM::HYPERV_BOARD` | Check for Hyper-V specific string in motherboard | Windows | 45% |  |  |  |  |  |
| `VM::VM_FILES_EXTRA` | Check for VPC and Parallels files | Windows | 70% |  |  |  | Spoofable |  |
| `VM::VPC_SIDT` | Check for sidt method with VPC's 0xE8XXXXXX range | Windows | 15% |  |  | 32-bit |  |  |
| `VM::VMWARE_IOMEM` | Check for VMware string in /proc/iomem | Linux | 65% |  |  |  |  |  |
| `VM::VMWARE_IOPORTS` | Check for VMware string in /proc/ioports | Linux | 70% |  |  |  |  |  |
| `VM::VMWARE_SCSI` | Check for VMware string in /proc/scsi/scsi | Linux | 40% |  |  |  |  |  |
| `VM::VMWARE_DMESG` | Check for VMware-specific device name in dmesg output | Linux | 65% | Admin |  |  |  | Disabled by default |
| `VM::VMWARE_STR` | Check str assembly instruction method for VMware | Windows | 35% |  |  |  |  |  |
| `VM::VMWARE_BACKDOOR` | Check for official VMware io port backdoor technique | Windows | 100% |  |  | 32-bit |  |  |
| `VM::VMWARE_PORT_MEM` | Check for VMware memory using IO port backdoor | Windows | 85% |  |  | 32-bit |  |  |
| `VM::SMSW` | Check for SMSW assembly instruction technique | Windows | 30% |  |  | 32-bit |  |  |
| `VM::MUTEX` | Check for mutex strings of VM brands | Windows | 85% |  |  |  |  |  |
| `VM::UPTIME` | Check if uptime is less than or equal to 2 minutes |  | 10% |  |  |  | Spoofable |  |
| `VM::ODD_CPU_THREADS` | Check for odd CPU threads, usually a sign of modification through VM setting because 99% of CPUs have even numbers of threads |  | 80% |  |  |  |  |  |
| `VM::INTEL_THREAD_MISMATCH` | Check for Intel CPU thread count database if it matches the system's thread count |  | 60% |  |  |  |  |  |
| `VM::XEON_THREAD_MISMATCH` | Same as above, but for Xeon Intel CPUs |  | 85% |  |  |  |  |  |
| `VM::NETTITUDE_VM_MEMORY` | Check for memory regions to detect VM-specific brands | Windows | 75% |  |  |  |  |  |
| `VM::CPUID_BITSET` |  Check for CPUID technique by checking whether all the bits equate to more than 4000 |  | 20% |  |  |  |  |  |
| `VM::CUCKOO_DIR` | Check for cuckoo directory using crt and WIN API directory functions | Windows | 15% |  |  |  | Spoofable |  |
| `VM::CUCKOO_PIPE` | Check for Cuckoo specific piping mechanism | Windows | 20% |  |  |  | Spoofable |  |
| `VM::HYPERV_HOSTNAME` | Check for default Azure hostname format regex (Azure uses Hyper-V as their base VM brand) | Windows, Linux | 50% |  |  |  | Spoofable |  |
| `VM::GENERAL_HOSTNAME` | Check for commonly set hostnames by certain VM brands | Windows, Linux | 20% |  |  |  | Spoofable |  |
| `VM::SCREEN_RESOLUTION` | Check for pre-set screen resolutions commonly found in VMs | Windows | 10% |  |  |  |  |  |
| `VM::DEVICE_STRING` | Check if bogus device string would be accepted | Windows | 25% |  |  |  |  |  |
| `VM::BLUESTACKS_FOLDERS` |  Check for the presence of BlueStacks-specific folders | Linux | 15% |  |  |  | Spoofable |  |
| `VM::CPUID_SIGNATURE` | Check for signatures in leaf 0x40000001 in CPUID |  | 95% |  |  |  |  |  |
| `VM::HYPERV_BITMASK` | Check for Hyper-V CPUID bitmask range for reserved values |  | 20% |  |  |  |  |  |
| `VM::KVM_BITMASK` | Check for KVM CPUID bitmask range for reserved values |  | 40% |  |  |  |  |  |
| `VM::KGT_SIGNATURE` | Check for Intel KGT (Trusty branch) hypervisor signature in CPUID |  | 80% |  |  |  |  |  |
| `VM::VMWARE_DMI` | Check for VMware DMI strings in BIOS serial number | Windows | 30% |  |  |  |  |  |
| `VM::EVENT_LOGS` | Check for presence of Hyper-V in the Windows Event Logs | Windows | 30% |  |  |  | Spoofable |  |
| `VM::QEMU_VIRTUAL_DMI` | Check for presence of QEMU in the /sys/devices/virtual/dmi/id directory | Linux | 40% |  |  |  |  |  |
| `VM::QEMU_USB` | Check for presence of QEMU in the /sys/kernel/debug/usb/devices directory | Linux | 20% |  |  |  |  |  |
| `VM::HYPERVISOR_DIR` | Check for presence of any files in /sys/hypervisor directory | Linux | 20% |  |  |  |  |  |
| `VM::UML_CPU` | Check for the "UML" string in the CPU brand | Linux | 80% |  |  |  |  |  |
| `VM::KMSG` | Check for any indications of hypervisors in the kernel message logs | Linux | 10% |  |  |  | Spoofable |  |
| `VM::VM_PROCS` | Check for a Xen VM process | Linux | 20% |  |  |  | Spoofable |  |
| `VM::VBOX_MODULE` | Check for a VBox kernel module | Linux | 15% |  |  |  |  |  |
| `VM::SYSINFO_PROC` | Check for potential VM info in /proc/sysinfo | Linux | 15% |  |  |  |  |  |
| `VM::DEVICE_TREE` | Check for specific files in /proc/device-tree directory | Linux | 20% |  |  |  |  |  |
| `VM::DMI_SCAN` | Check for string matches of VM brands in the linux DMI | Linux | 50% |  |  |  |  |  |
| `VM::SMBIOS_VM_BIT` | Check for the VM bit in the SMBIOS data | Linux | 50% |  |  |  |  |  |
| `VM::PODMAN_FILE` | Check for podman file in /run/ | Linux | 15% |  |  |  | Spoofable |  |
| `VM::WSL_PROC` | Check for WSL or microsoft indications in /proc/ subdirectories | Linux | 30% |  |  |  |  |  |
| `VM::ANYRUN_DRIVER` | Check for any.run driver presence | Windows | 65% |  |  |  |  | Removed from the lib, only available in the CLI |
| `VM::ANYRUN_DIRECTORY` | Check for any.run directory and handle the status code | Windows | 35% |  |  |  |  | Removed from the lib, only available in the CLI |
| `VM::GPU_CHIPTYPE` | Check for known VM vendors in the GPU chip manufacturer | Windows | 100% |  |  |  |  |  |
| `VM::DRIVER_NAMES` | Check for VM-specific names for drivers | Windows | 50% |  |  |  |  |  |
| `VM::VBOX_IDT` | Check for the VirtualBox IDT base address | Windows | 75% |  |  |  |  |  |
| `VM::HDD_SERIAL` | Check for HDD serial number | Windows | 100% |  |  |  |  |  |
| `VM::PORT_CONNECTORS` | Check for physical connection ports | Windows | 50% |  |  |  |  |  |
| `VM::QEMU_HDD` | Check for QEMU keyword in HDD model | Windows | 75% |  |  |  |  |  |
| `VM::ACPI_HYPERV` | Check for Hyper-V string in ACPI data | Windows | 85% |  |  |  |  |  |


<br>

# Brand table

This is the table of all the brands the library supports.

| Variable alias | String | VM type | Notes |
| -------------- | ------ | ------- | ----- |
| `VM::brands::NULL_BRAND` | Unknown | Unknown |  |
| `VM::brands::VBOX` | VirtualBox | Hypervisor (type 2) |  |
| `VM::brands::VMWARE` | VMware | Hypervisor (type 2) |  |
| `VM::brands::VMWARE_EXPRESS` | VMware Express | Hypervisor (type 2) |  |
| `VM::brands::VMWARE_ESX` | VMware ESX | Hypervisor (type 1) |  |
| `VM::brands::VMWARE_GSX` | VMware GSX | Hypervisor (type 2) |  |
| `VM::brands::VMWARE_WORKSTATION` | VMware Workstation | Hypervisor (type 2) |  |
| `VM::brands::VMWARE_FUSION` | VMware Fusion | Hypervisor (type 2) |  |
| `VM::brands::BHYVE` | bhyve | Hypervisor (type 1) |  |
| `VM::brands::KVM` | KVM | Hypervisor (type 1) |  |
| `VM::brands::QEMU` | QEMU | Emulator/Hypervisor (type 2) |  |
| `VM::brands::QEMU_KVM` | QEMU+KVM | Hypervisor (type 1) |  |
| `VM::brands::KVM_HYPERV` | KVM Hyper-V Enlightenment | Hypervisor (type 1) |  |
| `VM::brands::QEMU_KVM_HYPERV` | QEMU+KVM Hyper-V Enlightenment | Hypervisor (type 1) |  |
| `VM::brands::HYPERV` | Microsoft Hyper-V | Hypervisor (type 1) |  |
| `VM::brands::HYPERV_VPC` | Microsoft Virtual PC/Hyper-V | Hypervisor (either type 1 or 2) |  |
| `VM::brands::MSXTA` | Microsoft x86-to-ARM | Emulator |  |
| `VM::brands::PARALLELS` | Parallels | Hypervisor (type 2) |  |
| `VM::brands::XEN` | Xen HVM | Hypervisor (type 1) |  |
| `VM::brands::ACRN` | ACRN | Hypervisor (type 1) |  |
| `VM::brands::QNX` | QNX hypervisor | Hypervisor (type 1) |  |
| `VM::brands::HYBRID` | Hybrid Analysis | Sandbox |  |
| `VM::brands::SANDBOXIE` | Sandboxie | Sandbox |  |
| `VM::brands::DOCKER` | Docker | Container |  |
| `VM::brands::WINE` | Wine | Compatibility layer |  |
| `VM::brands::APPLE_ROSETTA` | Apple Rosetta 2 | Binary Translation Layer/Emulator |  |
| `VM::brands::VPC` | Virtual PC | Hypervisor (type 2) |  |
| `VM::brands::ANUBIS` | Anubis | Sandbox |  |
| `VM::brands::JOEBOX` | JoeBox | Sandbox |  |
| `VM::brands::THREATEXPERT` | ThreatExpert | Sandbox |  |
| `VM::brands::CWSANDBOX` | CWSandbox | Sandbox |  |
| `VM::brands::COMODO` | Comodo | Sandbox |  |
| `VM::brands::BOCHS` | Bochs | Emulator |  |
| `VM::brands::NVMM` | NetBSD NVMM | Hypervisor (type 2) |  |
| `VM::brands::BSD_VMM` | OpenBSD VMM | Hypervisor (type 2) |  |
| `VM::brands::INTEL_HAXM` | Intel HAXM | Hypervisor (type 1) |  |
| `VM::brands::UNISYS` | Unisys s-Par | Partitioning Hypervisor |  |
| `VM::brands::LMHS` | Lockheed Martin LMHS | Hypervisor (unknown type) | Yes, you read that right. The library can detect VMs running on US military fighter jets, apparently |
| `VM::brands::CUCKOO` | Cuckoo | Sandbox |  |
| `VM::brands::BLUESTACKS` | BlueStacks | Emulator |  |
| `VM::brands::JAILHOUSE` | Jailhouse | Partitioning Hypervisor |  |
| `VM::brands::APPLE_VZ` | Apple VZ | Unknown |  |
| `VM::brands::INTEL_KGT` | Intel KGT (Trusty) | Hypervisor (type 1) |  |
| `VM::brands::AZURE_HYPERV` | Microsoft Azure Hyper-V | Hypervisor (type 1) |  |
| `VM::brands::NANOVISOR` | Xbox NanoVisor (Hyper-V) | Hypervisor (type 1) |  |
| `VM::brands::SIMPLEVISOR` | SimpleVisor | Hypervisor (type 1) |  |
| `VM::brands::HYPERV_ARTIFACT` | Hyper-V artifact (not an actual VM) | Unknown |  |
| `VM::brands::UML` | User-mode Linux | Paravirtualised/Hypervisor (type 2) |  |
| `VM::brands::POWERVM` | IBM PowerVM | Hypervisor (type 1) |  |
| `VM::brands::GCE` | Google Compute Engine (KVM) | Hypervisor (type 1) |  |
| `VM::brands::OPENSTACK` | OpenStack (KVM) | Hypervisor (type 1) |  |
| `VM::brands::KUBEVIRT` | KubeVirt (KVM) | Hypervisor (type 1) |  |
| `VM::brands::AWS_NITRO` | AWS Nitro System EC2 (KVM-based) | Hypervisor (type 1) |  |
| `VM::brands::PODMAN` | Podman | Container |  |
| `VM::brands::WSL` | WSL | Hybrid Hyper-V (type 1 and 2) | The type is debatable |
| `VM::brands::OPENVZ` | OpenVZ | Container |  |
| N/A | ANY.RUN | Sandbox | Removed from the lib, available only in the CLI |



<br>

# Setting flags
| Flag | Description |
|------|-------------|
| `VM::ALL` | This will enable all the technique flags, including spoofable techniques and cursor check that are disabled by default. |
| `VM::NO_MEMO` | This will disable memoization, meaning the result will not be fetched through a previous computation of the `VM::detect()` function. Use this if you're only using a single function from the `VM` struct for a performance boost. |
| `VM::DEFAULT` | This represents a range of flags which are enabled if no default argument is provided. |
| `VM::MULTIPLE` | This is specific to `VM::brand()`. This will basically return a `std::string` message of what brands could be involved. For example, it could return "`VMware or VirtualBox`" instead of having a single brand string output. This has no effect if applied to any other functions than `VM::brand()`. |   
| `VM::HIGH_THRESHOLD` | This is specific to `VM::detect()` and `VM::percentage()`, which will set the threshold bar to confidently detect a VM by 3x higher. |
| `VM::SPOOFABLE` | This will enable all the "spoofable" techniques (which are 1/3 of the total amount of techniques) |

<br>

# Variables
| Variable | Type | Description |
|----------|------|-------------|
| `VM::technique_count` | `std::uint16_t` | This will store the number of VM detection techniques |
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
| -n | --number | Prints the number of VM detection techniques it can perform |
| -t | --type | Returns the VM type (if a VM was found) |
|    | --disable-notes | No notes will be provided |
|    | --spoofable | Allow spoofable techniques to be ran (not included by default) |
|    | --high-threshold | A higher theshold bar for a VM detection will be applied |
|    | --no-color | Removes all the color, this is added due to some terminals not supporting ANSI escape codes while cluttering the output |
> [!NOTE]
> If you want a general result of everything combined above, do not put any arguments. This is the intended way to use the CLI tool.
>