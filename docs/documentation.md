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
     * be performed. This is the recommended usage of the lib.
     */ 
    bool is_vm = VM::detect();


    /**
     * This does the exact same as above, but as an explicit alternative.
     */ 
    bool is_vm2 = VM::detect(VM::DEFAULT);


    /**
     * All checks are performed including spoofable techniques
     * and a few other techniques that are disabled by default,
     * one of which is VM::CURSOR which waits 5 seconds for any 
     * human mouse interaction to detect automated virtual environments.
     * If you're fine with having a 5 second delay, add VM::ALL 
     */ 
    bool is_vm3 = VM::detect(VM::ALL);


    /**
     * If you don't want the value to be memoized for whatever reason, 
     * you can set the VM::NO_MEMO flag and the result will not be cached. 
     * It's recommended to use this flag if you're only using one function
     * from the public interface a single time in total, so no unneccessary 
     * caching will be operated when you're not going to re-use the previously 
     * stored result at the end. 
     */ 
    bool is_vm4 = VM::detect(VM::NO_MEMO);


    /**
     * This will set the threshold bar to detect a VM higher than the default threshold.
     * Use this if you want to be extremely sure if it's a VM, but this can risk the result
     * to be a false negative. Use VM::percentage() for a more precise result if you want.
     */ 
    bool is_vm5 = VM::detect(VM::HIGH_THRESHOLD);


    /**
     * Essentially means only the CPU brand, MAC, and hypervisor bit techniques 
     * should be performed. Note that the less flags you provide, the more 
     * likely the result will not be accurate. If you just want to check for 
     * a single technique, use VM::check() instead. Also, read the flag table
     * at the end of this doc file for a full list of technique flags.
     */
    bool is_vm6 = VM::detect(VM::CPU_BRAND, VM::MAC, VM::HYPERVISOR_BIT);


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
     * This is just an example to show that you can use a combination of 
     * different flags and non-technique flags with the above examples. 
     */ 
    bool is_vm9 = VM::detect(VM::NO_MEMO, VM::HIGH_THRESHOLD, VM::DISABLE(VM::RDTSC, VM::VMID));

    return 0;
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

    return 0;
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

    return 0;
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

    return 0;
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

    return 0;
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
    return 0;
}
```


<br>

## `VM::conclusion()`
This will return the "conclusion" message of what the overall result is as a `std::string`. By default, there are 2 possible outputs:
- `Running on baremetal`
- `Running inside a [brand] VM`

The `[brand]` part might contain a brand or may as well be empty, depending on whether a brand has been found. Additionally, you can extend this by adding the `VM::DYNAMIC` flag which will now allow much more variadic  potential outputs:
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

## `VM::flag_to_string()`
This will take a technique flag enum as an argument and return the string version of it. For example:
```cpp
#include "vmaware.hpp"
#include <iostream>

int main() {
    const std::string name = VM::flag_to_string(VM::VMID);
    std::cout << "VM::" << name << "\n"; 
    // Output: VM::VMID 
    // (nothing more, nothing less)

    return 0;
}
```

The reason why this exists is because it can be useful for debugging purposes. It should be noted that the "VM::" part is not included in the string output, so that's based on the programmer's choice if it should remain in the string or not. The example given above is obviously useless since the whole code can be manually handwritten, but the function is especially convenient if it's being used with [`VM::technique_vector`](#variables). For example:

```cpp
#include "vmaware.hpp"
#include <iostream>

int main() {
    // this will loop through all the enums in the technique_vector variable,
    // and then checks each of them and outputs the enum that was detected
    for (const auto technique_enum : VM::technique_vector) {
        if (VM::check(technique_enum)) {
            const std::string name = VM::flag_to_string(technique_enum);
            std::cout << "VM::" << name << " was detected\n";
        }
    }

    return 0;
}
```

<br>

## `VM::detected_enums()`
This is a function that will return a vector of all the technique flags that were detected as running in a VM. The return type is `std::vector<VM::enum_flags>`, and it's designed to give a more programmatic overview of the result. 

```cpp
#include "vmaware.hpp"
#include <iostream>

int main() {
    std::vector<VM::enum_flags> flag_list = VM::detected_enums();

    for (const auto flag : flag_list) {
        std::cout << "VM::" << VM::flag_to_string(flag) << " was detected" << "\n"; 
    }

    return 0;
}
```

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


| Flag alias | Description | Cross-platform? (empty = yes) | Certainty | Admin? | GPL-3.0? | 32-bit only? | Notes |
| ---------- | ----------- | ----------------------------- | --------- | ------ | -------- | ------------ | ----- |
| `VM::VMID` | Check CPUID output of manufacturer ID for known VMs/hypervisors at leaf 0 and 0x40000000-0x40000100 |  | 100% |  |  |  |  |
| `VM::CPU_BRAND` | Check if CPU brand model contains any VM-specific string snippets |  | 50% |  |  |  |  |  |
| `VM::HYPERVISOR_BIT` | Check if hypervisor feature bit in CPUID eax bit 31 is enabled (always false for physical CPUs) |  | 100% |  |  |  |  |
| `VM::HYPERVISOR_STR` | Check for hypervisor brand string length (would be around 2 characters in a host machine) |  | 75% |  |  |  |  |
| `VM::TIMER` | Check for timing anomalies in the system |  | 45% |  |  |  |  |  |
| `VM::THREADCOUNT` | Check if there are only 1 or 2 threads, which is a common pattern in VMs with default settings (nowadays physical CPUs should have at least 4 threads for modern CPUs) |  | 35% |  |  |  |  |
| `VM::MAC` | Check if mac address starts with certain VM designated values | Linux and Windows | 20% |  |  |  |  |
| `VM::TEMPERATURE` | Check if thermal directory in linux is present, might not be present in VMs | Linux | 15% |    |  |  |
| `VM::SYSTEMD` | Check result from systemd-detect-virt tool | Linux | 35% |  |  |  |  |
| `VM::CVENDOR` | Check if the chassis vendor is a VM vendor | Linux | 65% |  |  |  |  |
| `VM::CTYPE` | Check if the chassis type is valid (it's very often invalid in VMs) | Linux | 20% |  |  |  |  |
| `VM::DOCKERENV` | Check if /.dockerenv or /.dockerinit file is present | Linux | 30% |  |  |  |  |
| `VM::DMIDECODE` | Check if dmidecode output matches a VM brand | Linux | 55% | Admin |  |  |  |
| `VM::DMESG` | Check if dmesg output matches a VM brand | Linux | 55% | Admin |  |  |  |
| `VM::HWMON` | Check if /sys/class/hwmon/ directory is present. If not, likely a VM | Linux | 35% |  |  |  |  |
| `VM::SIDT5` | Check if the 5th byte after sidt is null | Linux | 45% |  |  |  |  |
| `VM::DLL` | Check for VM-specific DLLs | Windows | 25% |  |  |  |  |
| `VM::REGISTRY` |  Check for VM-specific registry values | Windows | 50% |  |  |  |  |
| `VM::VM_FILES` | Find for VM-specific specific files | Windows | 25% |  |  |  |  |
| `VM::HWMODEL` | Check if the sysctl for the hwmodel does not contain the "Mac" string | MacOS | 100% |  |  |  |  |
| `VM::DISK_SIZE` | Check if disk size is under or equal to 50GB | Linux | 60% |  |  |  |  |
| `VM::VBOX_DEFAULT` | Check for default RAM and DISK sizes set by VirtualBox | Linux and Windows | 25% | Admin |  |  | Admin only needed for Linux |
| `VM::VBOX_NETWORK` | Check for VirtualBox network provider string | Windows | 100% |  |  |   |  |
| `VM::COMPUTER_NAME` | Check if the computer name (not username to be clear) is VM-specific | Windows | 10% |  | GPL |  |  |
| `VM::WINE_CHECK` | Check wine_get_unix_file_name file for Wine | Windows | 100% |  | GPL |  |  |
| `VM::HOSTNAME` | Check if hostname is specific | Windows | 10% |  | GPL |  |  |
| `VM::KVM_DIRS` | Check for KVM directory "Virtio-Win" | Windows | 30% |  | GPL |  |  |
| `VM::QEMU_DIR` | Check for QEMU-specific blacklisted directories | Windows | 30% |  | GPL |  |  |
| `VM::POWER_CAPABILITIES` | Check what power states are enabled | Windows | 50% |  | GPL |  |  |
| `VM::SETUPAPI_DISK` | Checks for virtual machine signatures in disk drive device identifiers | Windows | 100% |  | GPL |  |  |
| `VM::VM_PROCESSES` | Check for any VM processes that are active | Windows | 15% |  |  |  |  |
| `VM::LINUX_USER_HOST` | Check for default VM username and hostname for linux | Linux | 10% |  |  |  |  |
| `VM::GAMARUE` | Check for Gamarue ransomware technique which compares VM-specific Window product IDs | Windows | 10% |  |  |  |  |
| `VM::BOCHS_CPU` | Check for various Bochs-related emulation oversights through CPU checks |  | 100% |  |  |  |  |
| `VM::MSSMBIOS` | Check MSSMBIOS registry for VM-specific signatures | Windows | 100% |  |  |  |  |
| `VM::MAC_MEMSIZE` | Check if memory is too low for MacOS system | MacOS | 15% |  |  |  |  |
| `VM::MAC_IOKIT` | Check MacOS' IO kit registry for VM-specific strings | MacOS | 100% |  |  |  |  |
| `VM::IOREG_GREP` | Check for VM-strings in ioreg commands for MacOS | MacOS | 100% |  |  |  |  |
| `VM::MAC_SIP` | Check if System Integrity Protection is disabled (likely a VM if it is) | MacOS | 40% |  |  |  |  |
| `VM::HKLM_REGISTRIES` | Check HKLM registries for specific VM strings | Windows | 25% |  |  |  |  |
| `VM::QEMU_GA` | Check for "qemu-ga" process | Linux | 10% |  |  |  |  |
| `VM::VPC_INVALID` | Check for official VPC method | Windows | 75% |  |  | 32-bit |  |
| `VM::SIDT` | Check for sidt instruction method | Windows | 25% |  |  |  |  |
| `VM::SGDT` | Check for sgdt instruction method | Windows | 30% |  |  | 32-bit |  |
| `VM::SLDT` | Check for sldt instruction method | Windows | 15% |  |  | 32-bit |  |
| `VM::OFFSEC_SIDT` | Check for Offensive Security SIDT method | Windows | 60% |  |  | 32-bit |  |
| `VM::OFFSEC_SGDT` | Check for Offensive Security SGDT method | Windows | 60% |  |  | 32-bit |  |
| `VM::OFFSEC_SLDT` | Check for Offensive Security SLDT method | Windows | 20% |  |  | 32-bit |  |
| `VM::VPC_SIDT` | Check for sidt method with VPC's 0xE8XXXXXX range | Windows | 15% |  |  | 32-bit |  |
| `VM::VMWARE_IOMEM` | Check for VMware string in /proc/iomem | Linux | 65% |  |  |  |  |
| `VM::VMWARE_IOPORTS` | Check for VMware string in /proc/ioports | Linux | 70% |  |  |  |  |
| `VM::VMWARE_SCSI` | Check for VMware string in /proc/scsi/scsi | Linux | 40% |  |  |  |  |
| `VM::VMWARE_DMESG` | Check for VMware-specific device name in dmesg output | Linux | 65% | Admin |  |  | Disabled by default |
| `VM::VMWARE_STR` | Check str assembly instruction method for VMware | Windows | 35% |  |  |  |  |
| `VM::VMWARE_BACKDOOR` | Check for official VMware io port backdoor technique | Windows | 100% |  |  | 32-bit |  |
| `VM::VMWARE_PORT_MEM` | Check for VMware memory using IO port backdoor | Windows | 85% |  |  | 32-bit |  |
| `VM::SMSW` | Check for SMSW assembly instruction technique | Windows | 30% |  |  | 32-bit |  |
| `VM::MUTEX` | Check for mutex strings of VM brands | Windows | 85% |  |  |  |  |
| `VM::ODD_CPU_THREADS` | Check for odd CPU threads, usually a sign of modification through VM setting because 99% of CPUs have even numbers of threads |  | 80% |  |  |  |  |
| `VM::INTEL_THREAD_MISMATCH` | Check for Intel CPU thread count database if it matches the system's thread count |  | 95% |  |  |  |  |
| `VM::XEON_THREAD_MISMATCH` | Same as above, but for Xeon Intel CPUs |  | 95% |  |  |  |  |
| `VM::NETTITUDE_VM_MEMORY` | Check for memory regions to detect VM-specific brands | Windows | 100% | |  |  |  |
| `VM::CPUID_BITSET` |  Check for CPUID technique by checking whether all the bits equate to more than 4000 |  | 25% |  |  |  |  |
| `VM::CUCKOO_DIR` | Check for cuckoo directory using crt and WIN API directory functions | Windows | 30% |  |  |  |  |
| `VM::CUCKOO_PIPE` | Check for Cuckoo specific piping mechanism | Windows | 30% |  |  |  |  |
| `VM::HYPERV_HOSTNAME` | Check for default Azure hostname format regex (Azure uses Hyper-V as their base VM brand) | Windows, Linux | 30% |  |  |  |  |
| `VM::GENERAL_HOSTNAME` | Check for commonly set hostnames by certain VM brands | Windows, Linux | 10% |  |  |  |  |
| `VM::SCREEN_RESOLUTION` | Check for pre-set screen resolutions commonly found in VMs | Windows | 20% |  |  |  |  |
| `VM::DEVICE_STRING` | Check if bogus device string would be accepted | Windows | 25% |  |  |  |  |
| `VM::BLUESTACKS_FOLDERS` |  Check for the presence of BlueStacks-specific folders | Linux | 5% |  |  |  |  |
| `VM::CPUID_SIGNATURE` | Check for signatures in leaf 0x40000001 in CPUID |  | 95% |  |  |  |  |
| `VM::KVM_BITMASK` | Check for KVM CPUID bitmask range for reserved values |  | 40% |  |  |  |  |
| `VM::KGT_SIGNATURE` | Check for Intel KGT (Trusty branch) hypervisor signature in CPUID |  | 80% |  |  |  |  |
| `VM::QEMU_VIRTUAL_DMI` | Check for presence of QEMU in the /sys/devices/virtual/dmi/id directory | Linux | 40% |  |  |  |  |
| `VM::QEMU_USB` | Check for presence of QEMU in the /sys/kernel/debug/usb/devices directory | Linux | 20% |  |  |  |  |
| `VM::HYPERVISOR_DIR` | Check for presence of any files in /sys/hypervisor directory | Linux | 20% |  |  |  |  |
| `VM::UML_CPU` | Check for the "UML" string in the CPU brand | Linux | 80% |  |  |  |  |
| `VM::KMSG` | Check for any indications of hypervisors in the kernel message logs | Linux | 5% |  |  |  |  |
| `VM::VM_PROCS` | Check for a Xen VM process | Linux | 10% |  |  |  |  |
| `VM::VBOX_MODULE` | Check for a VBox kernel module | Linux | 15% |  |  |  |  |
| `VM::SYSINFO_PROC` | Check for potential VM info in /proc/sysinfo | Linux | 15% |  |  |  |  |
| `VM::DEVICE_TREE` | Check for specific files in /proc/device-tree directory | Linux | 20% |  |  |  |  |
| `VM::DMI_SCAN` | Check for string matches of VM brands in the linux DMI | Linux | 50% |  |  |  |  |
| `VM::SMBIOS_VM_BIT` | Check for the VM bit in the SMBIOS data | Linux | 50% |  |  |  |  |
| `VM::PODMAN_FILE` | Check for podman file in /run/ | Linux | 5% |  |  |  |  |
| `VM::WSL_PROC` | Check for WSL or microsoft indications in /proc/ subdirectories | Linux | 30% |  |  |  |  |
| `VM::ANYRUN_DRIVER` | Check for any.run driver presence | Windows | 65% |  |  |  |  | Removed from the lib, only available in the CLI |
| `VM::ANYRUN_DIRECTORY` | Check for any.run directory and handle the status code | Windows | 35% |  |  |  |  | Removed from the lib, only available in the CLI |
| `VM::DRIVER_NAMES` | Check for VM-specific names for drivers | Windows | 100% |  |  |  |  |
| `VM::VM_SIDT` | Check for unknown IDT base address | Windows | 100% |  |  |  |  |
| `VM::HDD_SERIAL` | Check for serial numbers of virtual disks | Windows | 100% |  |  |  |  |
| `VM::PORT_CONNECTORS` | Check for physical connection ports | Windows | 25% |  |  |  | This technique is known to false flag on devices like Surface Pro |
| `VM::GPU` | Check for GPU capabilities and specific GPU signatures related to VMs | Windows | 100% | Admin |  |  | Admin only needed for some heuristics |
| `VM::VM_DEVICES` | Check for VM-specific devices | Windows | 45% |  |  |  |  |
| `VM::VM_MEMORY` | Check for specific VM memory traces in certain processes | Windows | 65% |  |  |  |  |
| `VM::IDT_GDT_MISMATCH` | Check if the IDT and GDT base virtual addresses mismatch between different CPU cores when called from usermode under a root partition | Windows | 50% |  |  |  |  |
| `VM::PROCESSOR_NUMBER` | Check for number of processors | Windows | 50% |  |  |  |  |
| `VM::NUMBER_OF_CORES` | Check for number of cores | Windows | 50% |  |  |  |  |
| `VM::ACPI_TEMPERATURE` | Check for device's temperature | Windows | 25% |  |  |  |  |
| `VM::PROCESSOR_ID` | Check if any processor has an empty Processor ID using SMBIOS data | Windows | 25% |  |  |  |  |
| `VM::SYS_QEMU` | Check for existence of "qemu_fw_cfg" directories within /sys/module and /sys/firmware | Linux | 70% |  |  |  |  |
| `VM::LSHW_QEMU` | Check for QEMU string instances with lshw command | Linux | 80% |  |  |  |  |
| `VM::VIRTUAL_PROCESSORS` | Check if the number of maximum virtual processors matches the maximum number of logical processors | Windows | 50% |  |  |  |  |
| `VM::HYPERV_QUERY` | Check if a call to NtQuerySystemInformation with the 0x9f leaf fills a _SYSTEM_HYPERVISOR_DETAIL_INFORMATION structure | Windows | 100% |  |  |  |  |
| `VM::BAD_POOLS` | Check for system pools allocated by hypervisors | Windows | 80% |  |  |  |  |
| `VM::AMD_SEV` | Check for AMD-SEV MSR running on the system | Linux and MacOS | 50% | Admin |  |  |  |
| `VM::AMD_THREAD_MISMATCH` | Check for AMD CPU thread count database if it matches the system's thread count |  | 95% |  |  |  |  |
| `VM::NATIVE_VHD` | Checks if the OS was booted from a VHD container |  | 100% |  |  |  |  |
| `VM::NATIVE_VHD` | Check for OS being booted from a VHD container | Windows | 100% |  |  |  |  |
| `VM::VIRTUAL_REGISTRY` | Check for particular object directory which is present in Sandboxie virtual environment but not in usual host systems | Windows | 65% |  |  |  |  |
| `VM::FIRMWARE` | Check for VM signatures and patched strings by hardeners in firmware, while ensuring the BIOS serial is valid | Windows | 90% |  |  |  |  |
| `VM::FILE_ACCESS_HISTORY` | Check if the number of accessed files are too low for a human-managed environment | Linux | 15% |  |  |  |  |
| `VM::AUDIO` | Check if audio device is present | Windows | 25% |  |  |  |  |
| `VM::UNKNOWN_MANUFACTURER` | Check if the CPU manufacturer is not known |  | 50% |  |  |  |  |
| `VM::OSXSAVE` | Check if running xgetbv in the XCR0 extended feature register triggers an exception | Windows | 50% |  |  |  |  |
| `VM::NSJAIL_PID` | Check if process status matches with nsjail patterns with PID anomalies | Linux | 75% |  |  |  |  |
<!-- ADD TECHNIQUE DETAILS HERE -->

<br>

# Brand table

This is the table of all the brands the lib supports.

| String | Variable alias | VM type | Notes |
| -------------- | ------ | ------- | ----- |
| Unknown | `VM::brands::NULL_BRAND` | Unknown | This is the default brand it returns if none were found |
| VirtualBox | `VM::brands::VBOX` | Hypervisor (type 2) |  |
| VMware | `VM::brands::VMWARE` | Hypervisor (type 2) |  |
| VMware Express | `VM::brands::VMWARE_EXPRESS` | Hypervisor (type 2) |  |
| VMware ESX | `VM::brands::VMWARE_ESX` | Hypervisor (type 1) |  |
| VMware GSX | `VM::brands::VMWARE_GSX` | Hypervisor (type 2) |  |
| VMware Workstation | `VM::brands::VMWARE_WORKSTATION` | Hypervisor (type 2) |  |
| VMware Fusion | `VM::brands::VMWARE_FUSION` | Hypervisor (type 2) |  |
| VMware (with VmwareHardenedLoader) | `VM::brands::VMWARE_HARD` | Hypervisor (type 2) | See the [repository](https://github.com/hzqst/VmwareHardenedLoader) |
| bhyve | `VM::brands::BHYVE` | Hypervisor (type 2) |  |
| KVM | `VM::brands::KVM` | Hypervisor (type 1) |  |
| QEMU | `VM::brands::QEMU` | Emulator/Hypervisor (type 2) |  |
| QEMU+KVM | `VM::brands::QEMU_KVM` | Hypervisor (type 1) |  |
| KVM Hyper-V Enlightenment | `VM::brands::KVM_HYPERV` | Hypervisor (type 1) |  |
| QEMU+KVM Hyper-V Enlightenment | `VM::brands::QEMU_KVM_HYPERV` | Hypervisor (type 1) |  |
| Microsoft Hyper-V | `VM::brands::HYPERV` | Hypervisor (type 1) |  |
| Microsoft Virtual PC/Hyper-V | `VM::brands::HYPERV_VPC` | Hypervisor (either type 1 or 2) |  |
| Parallels | `VM::brands::PARALLELS` | Hypervisor (type 2) |  |
| Xen HVM | `VM::brands::XEN` | Hypervisor (type 1) |  |
| ACRN | `VM::brands::ACRN` | Hypervisor (type 1) |  |
| QNX hypervisor | `VM::brands::QNX` | Hypervisor (type 1) |  |
| Hybrid Analysis | `VM::brands::HYBRID` | Sandbox |  |
| Sandboxie | `VM::brands::SANDBOXIE` | Sandbox |  |
| Docker | `VM::brands::DOCKER` | Container |  |
| Wine | `VM::brands::WINE` | Compatibility layer |  |
| Virtual PC  | `VM::brands::VPC` | Hypervisor (type 2) |  |
| Anubis | `VM::brands::ANUBIS` | Sandbox |  |
| JoeBox | `VM::brands::JOEBOX` | Sandbox |  |
| ThreatExpert | `VM::brands::THREATEXPERT` | Sandbox |  |
| CWSandbox | `VM::brands::CWSANDBOX` | Sandbox |  |
| Comodo | `VM::brands::COMODO` | Sandbox |  |
| Bochs | `VM::brands::BOCHS` | Emulator |  |
| NetBSD NVMM | `VM::brands::NVMM` | Hypervisor (type 2) |  |
| OpenBSD VMM | `VM::brands::BSD_VMM` | Hypervisor (type 2) |  |
| Intel HAXM | `VM::brands::INTEL_HAXM` | Hypervisor (type 1) |  |
| Unisys s-Par | `VM::brands::UNISYS` | Partitioning Hypervisor |  |
| Lockheed Martin LMHS  | `VM::brands::LMHS` | Hypervisor (unknown type) | Yes, you read that right. The lib can detect VMs running on US military fighter jets, apparently |
| Cuckoo | `VM::brands::CUCKOO` | Sandbox |  |
| BlueStacks | `VM::brands::BLUESTACKS` | Emulator |  |
| Jailhouse | `VM::brands::JAILHOUSE` | Partitioning Hypervisor |  |
| Apple VZ | `VM::brands::APPLE_VZ` | Unknown |  |
| Intel KGT (Trusty) | `VM::brands::INTEL_KGT` | Hypervisor (type 1) |  |
| Microsoft Azure Hyper-V | `VM::brands::AZURE_HYPERV` | Hypervisor (type 1) |  |
| Xbox NanoVisor (Hyper-V) | `VM::brands::NANOVISOR` | Hypervisor (type 1) |  |
| SimpleVisor | `VM::brands::SIMPLEVISOR` | Hypervisor (type 1) |  |
| Hyper-V artifact (not an actual VM) | `VM::brands::HYPERV_ARTIFACT` | Unknown |  |
| User-mode Linux | `VM::brands::UML` | Paravirtualised/Hypervisor (type 2) |  |
| IBM PowerVM | `VM::brands::POWERVM` | Hypervisor (type 1) |  |
| OpenStack (KVM) | `VM::brands::OPENSTACK` | Hypervisor (type 1) |  |
| KubeVirt (KVM) | `VM::brands::KUBEVIRT` | Hypervisor (type 1) |  |
| AWS Nitro System EC2 (KVM-based) | `VM::brands::AWS_NITRO` | Hypervisor (type 1) |  |
| Podman | `VM::brands::PODMAN` | Container |  |
| WSL | `VM::brands::WSL` | Hybrid Hyper-V (type 1 and 2) | The type is debatable, it's not exactly clear |
| OpenVZ | `VM::brands::OPENVZ` | Container |  |
| ANY.RUN | N/A | Sandbox | Removed from the lib, available only in the CLI |
| Barevisor | `VM::brands::BAREVISOR` | Hypervisor (type 1) |  |
| HyperPlatform | `VM::brands::HYPERPLATFORM` | Hypervisor (type 1) |  |
| MiniVisor | `VM::brands::MINIVISOR` | Hypervisor (type 1) |  |
| Intel TDX | `VM::brands::INTEL_TDX` | Trusted Domain |  |
| LKVM | `VM::brands::LKVM` | Hypervisor (type 1) |  |
| AMD SEV | `VM::brands::AMD_SEV` | VM encryptor |  |
| AMD SEV-ES | `VM::brands::AMD_SEV_ES` | VM encryptor |  |
| AMD SEV-SNP | `VM::brands::AMD_SEV_SNP` | VM encryptor |  |
| Neko Project II | `VM::brands::NEKO_PROJECT` | Emulator |  | 
| Google Compute Engine (KVM) | `VM::brands::GCE` | Cloud VM service |  |
| NoirVisor | `VM::brands::NOIRVISOR` | Hypervisor (type 1) |  |
| Qihoo 360 Sandbox | `VM::brands::QIHOO` | Sandbox |  |
| nsjail | `VM::brands::NSJAIL` | Process isolator |  |

<br>

# Setting flags
| Flag | Description | Specific to |
|------|-------------|-------------|
| `VM::ALL` | This will enable all the technique flags, including checks that are disabled by default. |  |
| `VM::NO_MEMO` | This will disable memoization, meaning the result will not be fetched through a previous computation of the techniques. For example, if you run all the techniques with VM::detect(), this will save all the technique results in a small cache and if you decide to use VM::percentage() afterwards, the result for that function will retrieve the precomputed results from that cache. Use this if you're only using a single total number of functions from the `VM` struct so that no unnecessary caching will be performed. |  |
| `VM::DEFAULT` | This represents a range of flags which are enabled if no default argument is provided. |
| `VM::MULTIPLE` | This will basically return a `std::string` message of what brands could be involved. For example, it could return "`VMware or VirtualBox`" instead of having a single brand string output. | VM::brand() |   
| `VM::HIGH_THRESHOLD` | This will set the threshold bar to confidently detect a VM by 3x higher. | VM::detect() and VM::percentage() |
| `VM::DYNAMIC` | This will add 8 options to the conclusion message rather than 2, each with their own varying likelihoods. | VM::conclusion() |
| `VM::NULL_ARG` | Does nothing, meant as a placeholder flag mainly for CLI purposes. It's best to ignore this.|  |

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
|    | --high-threshold | A higher theshold bar for a VM detection will be applied |
|    | --no-ansi | Removes all the ANSI encodings (color and text style). This is added due to some terminals not supporting ANSI escape codes while cluttering the output |
|    | --dynamic | allow the conclusion message to be dynamic (8 possibilities instead of only 2) |
|    | --verbose | add more information to the output  |
|    | --compact | ignore the unsupported techniques from the CLI output and thus make it more compact |
|    | --mit | ignore the GPL techniques and run only the MIT-supported ones |
|    | --enums | display the technique enum name used by the lib |
> [!NOTE]
> If you want a general result with the default settings, do not put any arguments. This is the intended way to use the CLI tool.
>