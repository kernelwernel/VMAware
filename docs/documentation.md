# Documentation

## Contents
- [`VM::detect()`](#vmdetect)
- [`VM::percentage()`](#vmpercentage)
- [`VM::brand()`](#vmbrand)
- [`VM::check()`](#vmcheck)
- [`VM::add_custom()`](#vmadd_custom)
- [`VM::type()`](#vmtype)
- [`VM::conclusion()`](#vmconclusion)
- [`VM::detected_count()`](#vmdetected_count)
- [`VM::is_hardened()`](#vmis_hardened)
- [`(advanced) VM::flag_to_string()`](#vmflag_to_string)
- [`(advanced) VM::detected_enums()`](#vmdetected_enums)
- [vmaware struct](#vmaware-struct)
- [Notes and overall things to avoid](#notes-and-overall-things-to-avoid)
- [Flag table](#flag-table)
- [Brand table](#brand-table)
- [Setting flags](#setting-flags)
- [Variables](#variables)
- [CLI documentation](#cli-documentation)


<br>

## `VM::detect()`

This is basically the main function you're looking for, which returns a bool. If no parameter is provided, all the recommended checks will be performed. But you can optionally set what techniques are used.

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
     * All checks are performed including techniques that are
     * disabled by default for a viariety of reasons. There are
     * around 5 technique that are disabled. If you want all 
     * techniques for the sake of completeness, then you can use
     * this flag but remember that there may be potential 
     * performance bottlenecks and an increase in false positives.
     */ 
    bool is_vm3 = VM::detect(VM::ALL);


    /**
     * This will raise the detection threshold above the default level.
     * Use this if you want to be extremely sure if it's a VM, but this 
     * increases the chance of a false negative. Use VM::percentage() 
     * for a more precise result if you want.
     */ 
    bool is_vm4 = VM::detect(VM::HIGH_THRESHOLD);


    /**
     * Essentially means only the CPU brand, MAC, and hypervisor bit techniques 
     * should be performed. Note that the less technique flags you provide, the more 
     * likely the result will not be accurate. If you just want to check for 
     * a single technique, use VM::check() instead. Also, read the flag table
     * at the end of this doc file for a full list of technique flags.
     */
    bool is_vm5 = VM::detect(VM::CPU_BRAND, VM::MAC, VM::HYPERVISOR_BIT);


    /**
     * If you want to disable any technique for whatever reason, use VM::DISABLE(...).
     * This code snippet essentially means "perform all the default flags, but only 
     * disable the VM::RDTSC technique". 
     */ 
    bool is_vm6 = VM::detect(VM::DISABLE(VM::RDTSC));


    /**
     * Same as above, but you can disable multiple techniques at the same time.
     */ 
    bool is_vm7 = VM::detect(VM::DISABLE(VM::VMID, VM::RDTSC, VM::HYPERVISOR_BIT));


    /**
     * This is just an example to show that you can use a combination of 
     * different flags and non-technique flags with the above examples. 
     */ 
    bool is_vm8 = VM::detect(VM::DEFAULT, VM::HIGH_THRESHOLD, VM::DISABLE(VM::RDTSC, VM::VMID));
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
This will essentially return the VM brand as a `std::string`. All the brands and brand alias variables are listed [here](#brand-table)

If none were detected, it will return `Unknown`. It should be noted that this could be a common scenario even if you're running inside a VM due to technical difficulties with accomplishing this. This is especially true for VMware sub-versions (ESX, GSX, Fusion, etc...). It's not recommended to rely on this function for critical operations as if your whole program depends on it.

```cpp
#include "vmaware.hpp"
#include <string>

int main() {
    const std::string result = VM::brand();

    if (result == "KVM") {
        // do KVM specific stuff
    } else if (result == "VirtualBox") {
        // you get the idea
    } else if (result == brands::VMWARE) {
        // having manual string comparisons like the two
        // previous ones can lead to typos which will 
        // make the whole check completely redundant.
        // So the lib provides hardcoded string variables 
        // as aliases to avoid these kinds of situations. 
        // They are located in the aforementioned brand table
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
    std::cout << VM::brand() << " is a " << VM::type() << " VM\n";
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
This will fetch the number of techniques that have been detected as a `std::uint8_t`.

```cpp
#include "vmaware.hpp"
#include <iostream>

int main() {
    const std::uint8_t count = VM::detected_count();

    // output: 7 techniques were detected
    std::cout << count << " techniques were detected" << "\n"; 

    // note that if it's baremetal, it should be 0.
    // if it's a VM, it should have at least 4 to  
    // maybe around 15 max. The most I've seen was 
    // around 18 but that only occurs very rarely.

    return 0;
}
```

<br>

## `VM::is_hardened()`

This will detect whether the environment has any hardening indications as a `bool`. 

Internally, this function works by analysing which combination of techniques are expected to be detected together. If a certain combination rule is mismatched, it indicates some kind of tampering of the system which assumes some sort of VM hardening.


> [!WARNING]
> This function should **NOT** be depended on for critical code. This is still a beta feature that hasn't been widely stress-tested as of 2.5.0. It works more as a heuristic assumption rather than a concrete guarantee.


```cpp
#include "vmaware.hpp"
#include <iostream>

int main() {
    if (VM::detect()) {
        if (VM::is_hardened()) {
            std::cout << "Potential hardening detected" << "\n";
        } else {
            std::cout << "Unsure if hardened" << "\n";
        }
    }

    return 0;
}
```

<br>

## `VM::flag_to_string()`
This will take a technique flag enum as an argument and return the string version of it. For example:
```cpp
#include "vmaware.hpp"
#include <iostream>

int main() {
    const std::string name = VM::flag_to_string(VM::VMID);

    // output: VM::VMID 
    std::cout << "VM::" << name << "\n"; 

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

# Notes and overall things to avoid
❌ 1. Do NOT rely on the percentage to determine whether you're in a VM. The lib is not designed for this way, and you're potentially increasing false positives. Use VM::detect() instead for that job.

❌ 2. Do NOT depend your whole program on whether a specific brand was found. VM::brand() will not guarantee it'll give you the result you're looking for even if the environment is in fact that specific VM brand.

> [!TIP]
> It should also be mentioned that it's recommended for the end-user to create a wrapper around the header file. C++ compilation is notoriously slow compared to C or other systems programming languages, and recompiling the header over and over again is a time waste, especially considering there's around 10k lines of code in it. This is incredibly unreliable and cumbersome for large-scale projects utilising the lib. If you have a build configuration that supports header dependency handling or [incremental compilation](https://en.wikipedia.org/wiki/Incremental_compiler) (which is present in most build systems such as CMake), you can fix the issue by doing something like this:
> ```cpp
> // wrapper.hpp
> #include <string>
> 
> namespace wrapper {
>     bool is_this_a_vm();
>     std::string vm_brand_name();
> }
> ```
> 
> ```cpp
> // wrapper.cpp
> #include "vmaware.hpp"
> #include "wrapper.hpp"
> 
> bool wrapper::is_this_a_vm() {
>     return VM::detect();
> }
> 
> std::string wrapper::vm_brand_name() {
>     return VM::brand();
> }
> ```
> 
> ```cpp
> // something.cpp
> #include "wrapper.hpp"
> 
> void something() {
>     if (wrapper::is_this_a_vm()) {
>         std::cout << wrapper::vm_brand_name() << "\n";
>     }
> }
> ```
> 
> This wrapper structure would prevent any avoidable recompilations as opposed to potentially recompiling the vmaware.hpp file for every build that modifies the source that #includes the lib, especially if there's a deep hierarchy of file dependencies within your project.

<br>

# Flag table
VMAware provides a convenient way to not only check for VMs, but also have the flexibility and freedom for the end-user to choose what techniques are used with complete control over what gets executed or not. This is handled with a flag system.

| Icon | Platform |
| --- | --- |
| 🐧 | Linux |
| 🪟 | Windows |
| 🍏 | macOS |

<!-- START OF TECHNIQUE DOCUMENTATION -->

| Flag alias | Description | Supported platforms | Certainty | Admin? | 32-bit only? | Notes | Code implementation |
| ---------- | ----------- | ------------------- | --------- | ------ | ------------ | ----- | ------------------- |
| `VM::VMID` | Check CPUID output of manufacturer ID for known VMs/hypervisors at leaf 0 and 0x40000000-0x40000100 | 🐧🪟🍏 | 100% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L2255) |
| `VM::CPU_BRAND` | Check if CPU brand model contains any VM-specific string snippets | 🐧🪟🍏 | 95% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L2273) |
| `VM::HYPERVISOR_BIT` | Check if hypervisor feature bit in CPUID ECX bit 31 is enabled (always false for physical CPUs) | 🐧🪟🍏 | 100% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L2347) |
| `VM::HYPERVISOR_STR` | Check for hypervisor brand string length (would be around 2 characters in a host machine) | 🐧🪟🍏 | 100% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L2378) |
| `VM::TIMER` | Check for timing anomalies in the system | 🐧🪟🍏 | 100% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L4204) |
| `VM::THREAD_COUNT` | Check if there are only 1 or 2 threads, which is a common pattern in VMs with default settings, nowadays physical CPUs should have at least 4 threads for modern CPUs | 🐧🪟🍏 | 35% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L6512) |
| `VM::MAC` | Check if mac address starts with certain VM designated values | 🐧 | 20% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L4608) |
| `VM::TEMPERATURE` | Check for device's temperature | 🐧 | 80% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L5458) |
| `VM::SYSTEMD` | Check result from systemd-detect-virt tool | 🐧 | 35% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L4489) |
| `VM::CVENDOR` | Check if the chassis vendor is a VM vendor | 🐧 | 65% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L4513) |
| `VM::CTYPE` | Check if the chassis type is valid (it's very often invalid in VMs) | 🐧 | 20% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L4538) |
| `VM::DOCKERENV` | Check if /.dockerenv or /.dockerinit file is present | 🐧 | 30% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L4556) |
| `VM::DMIDECODE` | Check if dmidecode output matches a VM brand | 🐧 | 55% | Admin |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L4571) |
| `VM::DMESG` | Check if dmesg output matches a VM brand | 🐧 | 55% | Admin |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L4714) |
| `VM::HWMON` | Check if /sys/class/hwmon/ directory is present. If not, likely a VM | 🐧 | 35% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L4755) |
| `VM::DLL` | Check for VM-specific DLLs | 🪟 | 50% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L6808) |
| `VM::HWMODEL` | Check if the sysctl for the hwmodel does not contain the "Mac" string | 🍏 | 100% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L6536) |
| `VM::WINE` | Check if the function "wine_get_unix_file_name" is present and if the OS booted from a VHD container | 🪟 | 100% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L6839) |
| `VM::POWER_CAPABILITIES` | Check what power states are enabled | 🪟 | 45% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L6878) |
| `VM::PROCESSES` | Check for any VM processes that are active | 🐧 | 40% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L5469) |
| `VM::LINUX_USER_HOST` | Check for default VM username and hostname for linux | 🐧 | 10% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L4765) |
| `VM::GAMARUE` | Check for Gamarue ransomware technique which compares VM-specific Window product IDs | 🪟 | 10% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L6938) |
| `VM::BOCHS_CPU` | Check for various Bochs-related emulation oversights through CPU checks | 🐧🪟🍏 | 100% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L2406) |
| `VM::MAC_MEMSIZE` | Check if memory is too low for MacOS system | 🍏 | 15% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L6569) |
| `VM::MAC_IOKIT` | Check MacOS' IO kit registry for VM-specific strings | 🍏 | 100% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L6602) |
| `VM::IOREG_GREP` | Check for VM-strings in ioreg commands for MacOS | 🍏 | 100% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L6699) |
| `VM::MAC_SIP` | Check for the status of System Integrity Protection and hv_mm_present | 🍏 | 100% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L6756) |
| `VM::VPC_INVALID` | Check for official VPC method | 🪟 | 75% |  | 32-bit |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L7036) |
| `VM::SIDT` | Check for uncommon IDT virtual addresses | 🐧🪟 | 50% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L5496) |
| `VM::SGDT` | Check for sgdt instruction method | 🪟 | 50% |  |  | code documentation paper in /papers/www.offensivecomputing.net_vm.pdf (top-most byte signature) | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L7087) |
| `VM::SLDT` | Check for sldt instruction method | 🪟 | 50% |  | 32-bit |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L7155) |
| `VM::SMSW` | Check for SMSW assembly instruction technique | 🪟 | 50% |  | 32-bit |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L7210) |
| `VM::VMWARE_IOMEM` | Check for VMware string in /proc/iomem | 🐧 | 65% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L4794) |
| `VM::VMWARE_IOPORTS` | Check for VMware string in /proc/ioports | 🐧 | 70% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L5304) |
| `VM::VMWARE_SCSI` | Check for VMware string in /proc/scsi/scsi | 🐧 | 40% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L5103) |
| `VM::VMWARE_DMESG` | Check for VMware-specific device name in dmesg output | 🪟 | 65% | Admin |  | Disabled by default | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L5122) |
| `VM::VMWARE_STR` | Check str assembly instruction method for VMware | 🪟 | 35% |  | 32-bit |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L7237) |
| `VM::VMWARE_BACKDOOR` | Check for official VMware io port backdoor technique | 🪟 | 100% |  | 32-bit |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L7262) |
| `VM::MUTEX` | Check for mutex strings of VM brands | 🪟 | 100% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L7323) |
| `VM::INTEL_THREAD_MISMATCH` | Check for Intel I-series CPU thread count database if it matches the system's thread count | 🐧🪟🍏 | 50% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L2487) |
| `VM::XEON_THREAD_MISMATCH` | Check for Intel Xeon CPU thread count database if it matches the system's thread count | 🐧🪟🍏 | 50% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L3464) |
| `VM::AMD_THREAD_MISMATCH` | Check for AMD CPU thread count database if it matches the system's thread count | 🐧🪟🍏 | 50% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L3620) |
| `VM::CUCKOO_DIR` | Check for cuckoo directory using crt and WIN API directory functions | 🪟 | 30% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L7409) |
| `VM::CUCKOO_PIPE` | Check for Cuckoo specific piping mechanism | 🪟 | 30% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L7465) |
| `VM::AZURE` |  |  | 30% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L1) |
| `VM::DISPLAY` | Check for display configurations commonly found in VMs | 🪟 | 35% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L7521) |
| `VM::DEVICE_STRING` | Check if bogus device string would be accepted | 🪟 | 25% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L7556) |
| `VM::BLUESTACKS_FOLDERS` | Check for the presence of BlueStacks-specific folders | 🐧 | 5% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L4810) |
| `VM::CPUID_SIGNATURE` | Check for signatures in leaf 0x40000001 in CPUID | 🐧🪟🍏 | 95% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L4151) |
| `VM::KGT_SIGNATURE` | Check for Intel KGT (Trusty branch) hypervisor signature in CPUID | 🐧🪟🍏 | 80% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L4180) |
| `VM::QEMU_VIRTUAL_DMI` | Check for presence of QEMU in the /sys/devices/virtual/dmi/id directory | 🐧 | 40% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L4891) |
| `VM::QEMU_USB` | Check for presence of QEMU in the /sys/kernel/debug/usb/devices directory | 🐧 | 20% | Admin |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L4920) |
| `VM::HYPERVISOR_DIR` | Check for presence of any files in /sys/hypervisor directory | 🐧 | 20% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L4948) |
| `VM::UML_CPU` | Check for the "UML" string in the CPU brand | 🐧 | 80% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L4996) |
| `VM::KMSG` | Check for any indications of hypervisors in the kernel message logs | 🐧 | 5% | Admin |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L5026) |
| `VM::VBOX_MODULE` | Check for a VBox kernel module | 🐧 | 15% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L5080) |
| `VM::SYSINFO_PROC` | Check for potential VM info in /proc/sysinfo | 🐧 | 15% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L5156) |
| `VM::DMI_SCAN` | Check for string matches of VM brands in the linux DMI | 🐧 | 50% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L5178) |
| `VM::SMBIOS_VM_BIT` | Check for the VM bit in the SMBIOS data | 🐧 | 50% | Admin |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L5259) |
| `VM::PODMAN_FILE` | Check for podman file in /run/ | 🐧 | 5% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L5289) |
| `VM::WSL_PROC` | Check for WSL or microsoft indications in /proc/ subdirectories | 🐧 | 30% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L5321) |
| `VM::DRIVERS` | Check for VM-specific names for drivers | 🪟 | 100% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L7573) |
| `VM::DISK_SERIAL` | Check for serial numbers of virtual disks | 🪟 | 100% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L7671) |
| `VM::IVSHMEM` | Check for IVSHMEM device presence | 🪟 | 100% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L7890) |
| `VM::GPU_CAPABILITIES` | Check for GPU capabilities related to VMs | 🪟 | 45% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L7989) |
| `VM::DEVICE_HANDLES` | Check for vm-specific devices | 🪟 | 100% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L8027) |
| `VM::QEMU_FW_CFG` | Detect QEMU fw_cfg interface. This first checks the Device Tree for a fw-cfg node or hypervisor tag, then verifies the presence of the qemu_fw_cfg module and firmware directories in sysfs. | 🐧 | 70% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L5349) |
| `VM::VIRTUAL_PROCESSORS` | Check if the number of virtual and logical processors are reported correctly by the system | 🪟 | 100% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L8130) |
| `VM::HYPERVISOR_QUERY` | Check if a call to NtQuerySystemInformation with the 0x9f leaf fills a _SYSTEM_HYPERVISOR_DETAIL_INFORMATION structure | 🪟 | 100% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L8160) |
| `VM::AMD_SEV` | Check for AMD-SEV MSR running on the system | 🐧🍏 | 50% | Admin |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L4833) |
| `VM::VIRTUAL_REGISTRY` | Check for particular object directory which is present in Sandboxie virtual environment but not in usual host systems | 🪟 | 90% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L8221) |
| `VM::FIRMWARE` | Check for VM signatures on all firmware tables | 🐧🪟 | 100% | Admin |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L5650) |
| `VM::FILE_ACCESS_HISTORY` | Check if the number of accessed files are too low for a human-managed environment | 🐧 | 15% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L5379) |
| `VM::AUDIO` | Check if no waveform-audio output devices are present in the system | 🪟 | 25% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L8306) |
| `VM::NSJAIL_PID` | Check if process status matches with nsjail patterns with PID anomalies | 🐧 | 75% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L5406) |
| `VM::PCI_DEVICES` | Check for PCI vendor and device IDs that are VM-specific | 🐧🪟 | 95% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L6077) |
| `VM::ACPI_SIGNATURE` | Check for VM-specific ACPI device signatures | 🪟 | 100% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L8404) |
| `VM::TRAP` | Check if after raising two traps at the same RIP, a hypervisor interferes with the instruction pointer delivery | 🪟 | 100% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L8549) |
| `VM::UD` | Check if no waveform-audio output devices are present in the system | 🪟 | 25% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L8306) |
| `VM::BLOCKSTEP` | Check if a hypervisor does not properly restore the interruptibility state after a VM-exit in compatibility mode | 🪟 | 100% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L8776) |
| `VM::DBVM` | Check if Dark Byte's VM is present | 🪟 | 150% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L8823) |
| `VM::BOOT_LOGO` | Check boot logo for known VM images | 🪟 | 100% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L8942) |
| `VM::MAC_SYS` | Check for VM-strings in system profiler commands for MacOS | 🍏 | 100% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L6783) |
| `VM::OBJECTS` | Check for any signs of VMs in Windows kernel object entities | 🪟 | 100% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L9034) |
| `VM::NVRAM` | Check for known NVRAM signatures that are present on virtual firmware | 🪟 | 100% | Admin |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L9203) |
| `VM::SMBIOS_INTEGRITY` | Check if SMBIOS is malformed/corrupted in a way that is typical for VMs | 🪟 | 60% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L9534) |
| `VM::EDID` | Check for non-standard EDID configurations | 🪟 | 100% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L9545) |
| `VM::CPU_HEURISTIC` | Check whether the CPU is genuine and its reported instruction capabilities are not masked | 🪟 | 90% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L9779) |
| `VM::CLOCK` | Check the presence of system timers | 🪟 | 100% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L10217) |
| `VM::POST` | Check for anomalies in BIOS POST time | 🪟 | 100% |  |  |  | [link](https://github.com/kernelwernel/VMAware/tree/main/src/vmaware.hpp#L10312) |
<!-- END OF TECHNIQUE DOCUMENTATION -->

<br>

# Brand table

This is the table of all the brands the lib supports.

| String | Variable alias | VM type | Notes |
| ------ | -------------- | ------- | ----- |
| Unknown | `brands::NULL_BRAND` | Unknown | This is the default brand it returns if none were found |
| VirtualBox | `brands::VBOX` | Hypervisor (type 2) |  |
| VMware | `brands::VMWARE` | Hypervisor (type 2) |  |
| VMware Express | `brands::VMWARE_EXPRESS` | Hypervisor (type 2) |  |
| VMware ESX | `brands::VMWARE_ESX` | Hypervisor (type 1) |  |
| VMware GSX | `brands::VMWARE_GSX` | Hypervisor (type 2) |  |
| VMware Workstation | `brands::VMWARE_WORKSTATION` | Hypervisor (type 2) |  |
| VMware Fusion | `brands::VMWARE_FUSION` | Hypervisor (type 2) |  |
| VMware (with VmwareHardenedLoader) | `brands::VMWARE_HARD` | Hypervisor (type 2) | See the [repository](https://github.com/hzqst/VmwareHardenedLoader) |
| bhyve | `brands::BHYVE` | Hypervisor (type 2) |  |
| KVM | `brands::KVM` | Hypervisor (type 1) |  |
| QEMU | `brands::QEMU` | Emulator/Hypervisor (type 2) |  |
| QEMU+KVM | `brands::QEMU_KVM` | Hypervisor (type 1) |  |
| KVM Hyper-V Enlightenment | `brands::KVM_HYPERV` | Hypervisor (type 1) |  |
| QEMU+KVM Hyper-V Enlightenment | `brands::QEMU_KVM_HYPERV` | Hypervisor (type 1) |  |
| Microsoft Hyper-V | `brands::HYPERV` | Hypervisor (type 1) |  |
| Microsoft Virtual PC/Hyper-V | `brands::HYPERV_VPC` | Hypervisor (either type 1 or 2) |  |
| Parallels | `brands::PARALLELS` | Hypervisor (type 2) |  |
| Xen HVM | `brands::XEN` | Hypervisor (type 1) |  |
| ACRN | `brands::ACRN` | Hypervisor (type 1) |  |
| QNX hypervisor | `brands::QNX` | Hypervisor (type 1) |  |
| Hybrid Analysis | `brands::HYBRID` | Sandbox |  |
| Sandboxie | `brands::SANDBOXIE` | Sandbox |  |
| Docker | `brands::DOCKER` | Container |  |
| Wine | `brands::WINE` | Compatibility layer |  |
| Virtual PC  | `brands::VPC` | Hypervisor (type 2) |  |
| Anubis | `brands::ANUBIS` | Sandbox |  |
| JoeBox | `brands::JOEBOX` | Sandbox |  |
| ThreatExpert | `brands::THREATEXPERT` | Sandbox |  |
| CWSandbox | `brands::CWSANDBOX` | Sandbox |  |
| Comodo | `brands::COMODO` | Sandbox |  |
| Bochs | `brands::BOCHS` | Emulator |  |
| NetBSD NVMM | `brands::NVMM` | Hypervisor (type 2) |  |
| OpenBSD VMM | `brands::BSD_VMM` | Hypervisor (type 2) |  |
| Intel HAXM | `brands::INTEL_HAXM` | Hypervisor (type 1) |  |
| Unisys s-Par | `brands::UNISYS` | Partitioning Hypervisor |  |
| Lockheed Martin LMHS  | `brands::LMHS` | Hypervisor (unknown type) | Yes, you read that right. The lib can detect VMs running on US military fighter jets, apparently. |
| Cuckoo | `brands::CUCKOO` | Sandbox |  |
| BlueStacks | `brands::BLUESTACKS` | Emulator |  |
| Jailhouse | `brands::JAILHOUSE` | Partitioning Hypervisor |  |
| Apple VZ | `brands::APPLE_VZ` | Unknown |  |
| Intel KGT (Trusty) | `brands::INTEL_KGT` | Hypervisor (type 1) |  |
| Microsoft Azure Hyper-V | `brands::AZURE_HYPERV` | Hypervisor (type 1) |  |
| Xbox NanoVisor (Hyper-V) | `brands::NANOVISOR` | Hypervisor (type 1) |  |
| SimpleVisor | `brands::SIMPLEVISOR` | Hypervisor (type 1) |  |
| Hyper-V artifact (not an actual VM) | `brands::HYPERV_ARTIFACT` | Unknown | Windows Hyper-V has a tendency to modify host hardware values with VM values. In other words, this brand signifies that you're running on a host system, but the Hyper-V that's installed (either by default or manually by the user) is misleadingly making the whole system look like it's in a VM when in reality it's not. <br><br> For more information, refer to [this graph](https://github.com/kernelwernel/VMAware/blob/main/assets/hyper-x/v5/Hyper-X_version_5.drawio.png). |
| User-mode Linux | `brands::UML` | Paravirtualised/Hypervisor (type 2) |  |
| IBM PowerVM | `brands::POWERVM` | Hypervisor (type 1) |  |
| OpenStack (KVM) | `brands::OPENSTACK` | Hypervisor (type 1) |  |
| KubeVirt (KVM) | `brands::KUBEVIRT` | Hypervisor (type 1) |  |
| AWS Nitro System EC2 (KVM-based) | `brands::AWS_NITRO` | Hypervisor (type 1) |  |
| Podman | `brands::PODMAN` | Container |  |
| WSL | `brands::WSL` | Hybrid Hyper-V (type 1 and 2) | This is a type 1 at the fundamental level, but WSL has components that are reminiscent of type 2 VM designs to an extent. |
| OpenVZ | `brands::OPENVZ` | Container |  |
| ANY.RUN | N/A | Sandbox | Removed from the lib, available only in the CLI due to ethical reasons. |
| Barevisor | `brands::BAREVISOR` | Hypervisor (type 1) |  |
| HyperPlatform | `brands::HYPERPLATFORM` | Hypervisor (type 1) |  |
| MiniVisor | `brands::MINIVISOR` | Hypervisor (type 1) |  |
| Intel TDX | `brands::INTEL_TDX` | Trusted Domain |  |
| LKVM | `brands::LKVM` | Hypervisor (type 1) |  |
| AMD SEV | `brands::AMD_SEV` | VM encryptor |  |
| AMD SEV-ES | `brands::AMD_SEV_ES` | VM encryptor |  |
| AMD SEV-SNP | `brands::AMD_SEV_SNP` | VM encryptor |  |
| Neko Project II | `brands::NEKO_PROJECT` | Emulator |  | 
| Google Compute Engine (KVM) | `brands::GCE` | Cloud VM service |  |
| NoirVisor | `brands::NOIRVISOR` | Hypervisor (type 1) |  |
| Qihoo 360 Sandbox | `brands::QIHOO` | Sandbox |  |
| nsjail | `brands::NSJAIL` | Process isolator |  |
| DBVM | `brands::DBVM` | Hypervisor (type 1) | See the [Cheat Engine's Website](https://www.cheatengine.org/aboutdbvm.php) |

<br>

# Setting flags
| Flag | Description | Specific to |
|------|-------------|-------------|
| `VM::ALL` | This will enable all the technique flags, including checks that are disabled by default. |  |
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
| -o | --output | Set the output path for files, specifically with the --json command |
|    | --disable-notes | No notes will be provided |
|    | --high-threshold | A higher threshold bar for a VM detection will be applied |
|    | --no-ansi | Removes all the ANSI encodings (color and text style). This is added due to some terminals not supporting ANSI escape codes while cluttering the output |
|    | --dynamic | allow the conclusion message to be dynamic (8 possibilities instead of only 2) |
|    | --verbose | add more information to the output  |
|    | --enums | display the technique enum name used by the lib |
|    | --detected-only | Only display the techniques that were detected |
|    | --json | Output a json-formatted file of the results |

> [!NOTE]
> If you want a general result with the default settings, do not put any arguments. This is the intended way to use the CLI tool.
>
