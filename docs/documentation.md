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
- [Overall things to avoid](#overall-things-to-avoid)
- [Flag table](#flag-table)
- [Brand table](#brand-table)
- [Setting flags](#setting-flags)
- [Variables](#variables)
- [CLI arguments](#cli-documentation)


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
     * performance bottlenecks and in increase in false positives.
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
     * should be performed. Note that the less flags you provide, the more 
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
     * If you don't want the value to be memoized for whatever reason, 
     * you can set the VM::NO_MEMO flag and the result will not be cached. 
     * It's recommended to use this flag if you're only using one function
     * from the public interface a single time, so no unnecessary  
     * caching will be operated when you're not going to re-use the previously 
     * stored result at the end. 
     */ 
    bool is_vm8 = VM::detect(VM::NO_MEMO);


    /**
     * This is just an example to show that you can use a combination of 
     * different flags and non-technique flags with the above examples. 
     */ 
    bool is_vm9 = VM::detect(VM::DEFAULT, VM::NO_MEMO, VM::HIGH_THRESHOLD, VM::DISABLE(VM::RDTSC, VM::VMID));
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
        // So the lib provides hardcoded strings as aliases
        // to avoid these kinds of situations. They are
        // located in the aforementioned brand table
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
This will fetch the number of techniques that have been detected as a `std::uint8_t`. Can't get any simpler than that.
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

# Overall things to avoid
❌ 1. Do NOT rely on the percentage to determine whether you're in a VM. The lib is not designed for this way, and you're potentially increasing false positives. Use VM::detect() instead for that job.

❌ 2. Do NOT depend your whole program on whether a specific brand was found. VM::brand() will not guarantee it'll give you the result you're looking for even if the environment is in fact that specific VM brand.

❌ 3. Do NOT use VM::NO_MEMO flag if you're not sure what you're doing, this can potentially hamper the performance significantly.

<br>

# Flag table
VMAware provides a convenient way to not only check for VMs, but also have the flexibility and freedom for the end-user to choose what techniques are used with complete control over what gets executed or not. This is handled with a flag system.

| Icon | Platform |
| --- | --- |
| 🐧 | Linux |
| 🪟 | Windows |
| 🍏 | macOS |

| Flag alias | Description | Supported platforms | Certainty | Admin? | GPL-3.0? | 32-bit only? | Notes | Code implementation |
| ---------- | ----------- | ----------------------------- | --------- | ------ | -------- | ------------ | ----- | ------------------- |
| `VM::VMID` | Check CPUID output of manufacturer ID for known VMs/hypervisors at leaf 0 and 0x40000000-0x40000100 | 🐧🪟🍏 | 100% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L2525) |
| `VM::CPU_BRAND` | Check if CPU brand model contains any VM-specific string snippets | 🐧🪟🍏 | 95% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L2545) |
| `VM::HYPERVISOR_BIT` | Check if hypervisor feature bit in CPUID eax bit 31 is enabled (always false for physical CPUs) | 🐧🪟🍏 | 100% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L2601) |
| `VM::HYPERVISOR_STR` | Check for hypervisor brand string length (would be around 2 characters in a host machine) | 🐧🪟🍏 | 75% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L2622) |
| `VM::TIMER` | Check for timing anomalies in the system | 🐧🪟🍏 | 45% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L8169 ) |
| `VM::THREAD_COUNT` | Check if there are only 1 or 2 threads, which is a common pattern in VMs with default settings (nowadays physical CPUs should have at least 4 threads for modern CPUs) | 🐧🍏 | 35% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L2649) |
| `VM::MAC` | Check if mac address starts with certain VM designated values | 🐧 | 20% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L2671) |
| `VM::TEMPERATURE` | Check for device's temperature | 🐧🪟 | 15% |  |  |  | Disabled by default | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L2804) |
| `VM::SYSTEMD` | Check result from systemd-detect-virt tool | 🐧 | 35% |  |  |  |  |  [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L2818) |
| `VM::CVENDOR` | Check if the chassis vendor is a VM vendor | 🐧 | 65% |  |  |  |  |  [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L2671) |
| `VM::CTYPE` | Check if the chassis type is valid (it's very often invalid in VMs) | 🐧 | 20% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L2875) |
| `VM::DOCKERENV` | Check if /.dockerenv or /.dockerinit file is present | 🐧 | 30% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L2897) |
| `VM::DMIDECODE` | Check if dmidecode output matches a VM brand | 🐧 | 55% | Admin |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L2915) |
| `VM::DMESG` | Check if dmesg output matches a VM brand | 🐧 | 55% | Admin |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L2956) |
| `VM::HWMON` | Check if /sys/class/hwmon/ directory is present. If not, likely a VM | 🐧 | 35% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L2993) |
| `VM::DLL` | Check for VM-specific DLLs | 🪟 | 50% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L3057) |
| `VM::REGISTRY_KEY` |  Check for VM-specific registry keys | 🪟 | 50% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L3092) |
| `VM::REGISTRY_VALUES` | Check HKLM registries for specific VM strings | 🪟 | 25% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L4397) |
| `VM::FILES` | Find for VM-specific specific files | 🪟 | 50% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L3286) |
| `VM::HWMODEL` | Check if the sysctl for the hwmodel does not contain the "Mac" string | 🍏 | 100% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L3429) |
| `VM::DISK_SIZE` | Check if disk size is under or equal to 50GB | 🐧 | 60% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L3465) |
| `VM::VBOX_DEFAULT` | Check for default RAM and DISK sizes set by VirtualBox | 🐧🪟 | 25% | Admin |  |  | Admin only needed for Linux | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L3491) |
| `VM::VBOX_NETWORK` | Check for VirtualBox network provider string | 🪟 | 100% |  |  |   |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L3576) |
| `VM::WINE` | Check if the function "wine_get_unix_file_name" is present and if the OS booted from a VHD container  | 🪟 | 100% |  | GPL |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L3633) |
| `VM::POWER_CAPABILITIES` | Check what power states are enabled | 🪟 | 50% |  | GPL |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L3738) |
| `VM::SETUPAPI_DISK` | Check for virtual machine signatures in disk drive device identifiers | 🪟 | 100% |  | GPL |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L3762) |
| `VM::PROCESSES` | Check for any VM processes that are active | 🪟 | 15% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L3831) |
| `VM::LINUX_USER_HOST` | Check for default VM username and hostname for linux | 🐧 | 10% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L3884) |
| `VM::GAMARUE` | Check for Gamarue ransomware technique which compares VM-specific Window product IDs | 🪟 | 10% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L3911) |
| `VM::BOCHS_CPU` | Check for various Bochs-related emulation oversights through CPU checks | 🐧🪟🍏 | 100% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L3968) |
| `VM::MAC_MEMSIZE` | Check if memory is too low for MacOS system | 🍏 | 15% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L4194) |
| `VM::MAC_IOKIT` | Check MacOS' IO kit registry for VM-specific strings | 🍏 | 100% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L4231) |
| `VM::IOREG_GREP` | Check for VM-strings in ioreg commands for MacOS | 🍏 | 100% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L4317) |
| `VM::MAC_SIP` | Check if System Integrity Protection is disabled (likely a VM if it is) | 🍏 | 40% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L4378) |
| `VM::VPC_INVALID` | Check for official VPC method | 🪟 | 75% |  |  | 32-bit |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L4532) |
| `VM::SIDT` | Check for uncommon IDT virtual addresses | 🐧🪟 | 45% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L4587) |
| `VM::SGDT` | Check for uncommon GDT virtual addresses | 🪟 | 45% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L4640) |
| `VM::SLDT` | Check for uncommon LDT virtual addresses | 🪟 | 45% |  |  | 32-bit |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L4668) |
| `VM::SMSW` | Check for SMSW assembly instruction technique | 🪟 | 45% |  |  | 32-bit |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L5040) |
| `VM::VMWARE_IOMEM` | Check for VMware string in /proc/iomem | 🐧 | 65% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L4807) |
| `VM::VMWARE_IOPORTS` | Check for VMware string in /proc/ioports | 🐧 | 70% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L4828) |
| `VM::VMWARE_SCSI` | Check for VMware string in /proc/scsi/scsi | 🐧 | 40% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L4849) |
| `VM::VMWARE_DMESG` | Check for VMware-specific device name in dmesg output | 🐧 | 65% | Admin |  |  | Disabled by default | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L4870) |
| `VM::VMWARE_STR` | Check str assembly instruction method for VMware | 🪟 | 35% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L4909) |
| `VM::VMWARE_BACKDOOR` | Check for official VMware io port backdoor technique | 🪟 | 100% |  |  | 32-bit |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L4932) |
| `VM::MUTEX` | Check for mutex strings of VM brands | 🪟 | 100% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L5070) |
| `VM::ODD_CPU_THREADS` | Check for odd CPU threads, usually a sign of modification through VM setting because 99% of CPUs have even numbers of threads | 🐧🪟🍏 | 80% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L5115) |
| `VM::INTEL_THREAD_MISMATCH` | Check for Intel CPU thread count database if it matches the system's thread count | 🐧🪟🍏 | 95% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L5215) |
| `VM::XEON_THREAD_MISMATCH` | Same as above, but for Xeon Intel CPUs | 🐧🪟🍏 | 95% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L6217) |
| `VM::AMD_THREAD_MISMATCH` | Check for AMD CPU thread count database if it matches the system's thread count | 🐧🪟🍏 | 95% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L8871) |
| `VM::CUCKOO_DIR` | Check for cuckoo directory using crt and WIN API directory functions | 🪟 | 30% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L6655) |
| `VM::CUCKOO_PIPE` | Check for Cuckoo specific piping mechanism | 🪟 | 30% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L6679) |
| `VM::HYPERV_HOSTNAME` | Check for default Azure hostname format (Azure uses Hyper-V as their base VM brand) | 🐧🪟 | 30% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L6706) |
| `VM::GENERAL_HOSTNAME` | Check for display configurations related to VMs | 🐧🪟 | 10% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L6753) |
| `VM::DISPLAY` | Check for pre-set screen resolutions commonly found in VMs | 🪟 | 35% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L6789) |
| `VM::DEVICE_STRING` | Check if bogus device string would be accepted | 🪟 | 25% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L6821) |
| `VM::BLUESTACKS_FOLDERS` |  Check for the presence of BlueStacks-specific folders | 🐧 | 5% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L6842) |
| `VM::CPUID_SIGNATURE` | Check for signatures in leaf 0x40000001 in CPUID | 🐧🪟🍏 | 95% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L6865) |
| `VM::KGT_SIGNATURE` | Check for Intel KGT (Trusty branch) hypervisor signature in CPUID | 🐧🪟🍏 | 80% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L6931) |
| `VM::QEMU_VIRTUAL_DMI` | Check for presence of QEMU in the /sys/devices/virtual/dmi/id directory | 🐧 | 40% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L6956) |
| `VM::QEMU_USB` | Check for presence of QEMU in the /sys/kernel/debug/usb/devices directory | 🐧 | 20% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L6986) |
| `VM::HYPERVISOR_DIR` | Check for presence of any files in /sys/hypervisor directory | 🐧 | 20% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L7018) |
| `VM::UML_CPU` | Check for the "UML" string in the CPU brand | 🐧 | 80% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L7070) |
| `VM::KMSG` | Check for any indications of hypervisors in the kernel message logs | 🐧 | 5% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L7103) |
| `VM::VBOX_MODULE` | Check for a VBox kernel module | 🐧 | 15% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L7184) |
| `VM::SYSINFO_PROC` | Check for potential VM info in /proc/sysinfo | 🐧 | 15% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L7211) |
| `VM::DMI_SCAN` | Check for string matches of VM brands in the linux DMI | 🐧 | 50% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L7256) |
| `VM::SMBIOS_VM_BIT` | Check for the VM bit in the SMBIOS data | 🐧 | 50% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L7340) |
| `VM::PODMAN_FILE` | Check for podman file in /run/ | 🐧 | 5% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L7374) |
| `VM::WSL_PROC` | Check for WSL or microsoft indications in /proc/ subdirectories | 🐧 | 30% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L7393) |
| `VM::ANYRUN_DRIVER` | Check for any.run driver presence | 🪟 | 65% |  |  |  | Removed from the lib, only available in the CLI | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/cli.cpp#L679) |
| `VM::ANYRUN_DIRECTORY` | Check for any.run directory and handle the status code | 🪟 | 35% |  |  |  | Removed from the lib, only available in the CLI | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/cli.cpp#L713) |
| `VM::DRIVERS` | Check for VM-specific names for drivers | 🪟 | 100% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L7426) |
| `VM::DISK_SERIAL` | Check for serial numbers of virtual disks | 🪟 | 100% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L7581) |
| `VM::PORT_CONNECTORS` | Check for physical connection ports | 🪟 | 25% |  |  |  | This technique is known to false flag on devices like Surface Pro, disabled by default | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L7700) |
| `VM::IVSHMEM` | Check for IVSHMEM device absense | 🪟 | 100% |  |  |  |  |
| `VM::GPU_CAPABILITIES` | Check for GPU capabilities related to VMs | 🪟 | 100% | Admin |  |  | Admin only needed for some heuristics | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L7785) |
| `VM::GPU_VM_STRINGS` | Check for specific GPU string signatures related to VMs | 🪟 | 100% |  |  |  | If GPU_CAPABILITIES also flags, the score will have 50 added instead of 100 | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L7730) |
| `VM::DEVICE_HANDLES` | Check for VM-specific devices | 🪟 | 100% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L7848) |
| `VM::LOGICAL_PROCESSORS` | Check for number of logical processors | 🪟 | 50% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L7999) |
| `VM::PHYSICAL_PROCESSORS` | Check for number of physical cores | 🪟 | 50% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L8024) |
| `VM::QEMU_FW_CFG` | Check for QEMU fw_cfg interface | 🐧 | 70% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L8330) |
| `VM::LSHW_QEMU` | Check for QEMU string instances with lshw command | 🐧 | 80% |  |  |  | Disabled by default | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L8364) |
| `VM::VIRTUAL_PROCESSORS` | Check if the number of virtual and logical processors are reported correctly by the system | 🪟 | 100% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L8411) |
| `VM::HYPERV_QUERY` | Check if a call to NtQuerySystemInformation with the 0x9f leaf fills a _SYSTEM_HYPERVISOR_DETAIL_INFORMATION structure | 🪟 | 100% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L8451) |
| `VM::POOLS` | Check for system pools allocated by hypervisors | 🪟 | 80% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L8513) |
| `VM::AMD_SEV` | Check for AMD-SEV MSR running on the system | 🐧🍏 | 50% | Admin |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L8812) |
| `VM::VIRTUAL_REGISTRY` | Check for particular object directory which is present in Sandboxie virtual environment but not in usual host systems | 🪟 | 90% |  |  |  | Admin only needed for Linux | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L9505) |
| `VM::FIRMWARE` | Check for VM signatures on all firmware tables | 🐧🪟 | 100% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L9601) |
| `VM::FILE_ACCESS_HISTORY` | Check if the number of accessed files are too low for a human-managed environment | 🐧 | 15% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L9950) |
| `VM::AUDIO` | Check if no waveform-audio output devices are present in the system | 🪟 | 25% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L9980) |
| `VM::CPU_VENDOR` | Check if the CPU vendor signature contain mixed keywords | 🐧🪟🍏 | 100% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L10016) |
| `VM::NSJAIL_PID` | Check if process status matches with nsjail patterns with PID anomalies | 🐧 | 75% |  |  |  | Disabled by default | [link](https://github.com/kernelwernel/VMAware/blob/8cb2491b1c7d2cb7300d1d698b7c64c953b4ae75/src/vmaware.hpp#L10083) |
| `VM::TPM` | Check if the system has a physical TPM by matching the TPM manufacturer against known physical TPM chip vendors | 🪟 | 50% |  |  |  |  | [link](https://github.com/kernelwernel/VMAware/blob/fb66db9fdd7894edebe5eeade4b0148a08bd5514/src/vmaware.hpp#L10011)|
| `VM::PCI_VM_DEVICE_ID` | Check for PCI vendor and device IDs that are VM-specific | 🐧🪟 | 90% |  |  |  |  |  |
| `VM::QEMU_PASSTHROUGH` | Check for QEMU's hot-plug signature | 🪟 | 100% |  |  |  |  |  |

<!-- ADD TECHNIQUE DETAILS HERE -->

<br>

# Brand table

This is the table of all the brands the lib supports.

| String | Variable alias | VM type | Notes |
| -------------- | ------ | ------- | ----- |
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
| WSL | `brands::WSL` | Hybrid Hyper-V (type 1 and 2) | The type is debatable, it's not exactly clear. |
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
| Hypervisor-Phantom | `brands::HYPERVISOR_PHANTOM` | Sandbox | See the [repository](https://github.com/Scrut1ny/Hypervisor-Phantom) |

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
|    | --high-threshold | A higher threshold bar for a VM detection will be applied |
|    | --no-ansi | Removes all the ANSI encodings (color and text style). This is added due to some terminals not supporting ANSI escape codes while cluttering the output |
|    | --dynamic | allow the conclusion message to be dynamic (8 possibilities instead of only 2) |
|    | --verbose | add more information to the output  |
|    | --enums | display the technique enum name used by the lib |
|    | --detected-only | Only display the techniques that were detected |
> [!NOTE]
> If you want a general result with the default settings, do not put any arguments. This is the intended way to use the CLI tool.
>
