# Documentation
# `VM::detect()`

This is basically the only thing you need, which returns a bool. If the parameter is set to default, all the recommended checks will be performed. But you can optionally set what techniques are used:

```cpp
int main() {
    /**
     * The basic way to detect a VM where most checks will be 
     * performed. This is the recommended usage of the library.
     */ 
    bool is_vm = VM::detect();


    /**
     * Essentially means only the brand, MAC, and hypervisor 
     * bit techniques should be performed. Note that the less 
     * flags you provide, the more likely the result whether 
     * it's running in a VM will not be accurate.
     */ 
    bool is_vm2 = VM::detect(VM::BRAND | VM::MAC | VM::HYPERV_BIT);


    /**
     * All checks are performed including the cursor check, 
     * which waits 5 seconds for any human mouse interaction 
     * to detect automated virtual environments. This is the 
     * only technique that's disabled by default but if you 
     * want to include it, add VM::ALL which is NOT RECOMMENDED
     */ 
    bool is_vm3 = VM::detect(VM::ALL);


    /**
     * If you don't want the value to be memoized for whatever
     * reason, you can set the VM::NO_MEMO flag and the result
     * will not be cached. Keep in mind that this could take a 
     * performance hit.
     */ 
    bool is_vm3 = VM::detect(VM::ALL | VM::NO_MEMO);
}
```


# `VM::brand()`
This will essentially return the VM brand as a std::string_view if it detected a VM. The possible brand string return values are: `VMware`, `VirtualBox`, `KVM`, `bhyve`, `QEMU`, `Microsoft Hyper-V`, `Microsoft x86-to-ARM`, `Parallels`, `Xen HVM`, `ACRN`, `QNX hypervisor`, `Hybrid Analysis`, `Sandboxie`, `Docker`, `Wine`, and `Virtual Apple`. If none were detected, it will return `Unknown`.

```cpp
int main() {
    std::string_view result = VM::brand();

    if (result == "KVM") {
        // do KVM specific stuff
    } else if (result == "VirtualBox") {
        // do vbox specific stuff
    } else {
        // do stuff
    }
}
```

# `VM::check()`
This takes a single flag argument and returns a `bool`. It's essentially the same as `VM::detect()` but it doesn't have a scoring system. It only returns the technique's effective output. The reason why this exists is because it allows end-users to have fine-grained control over what is being executed and what isn't. 

`VM::detect()` is meant for a range of techniques to be evaluated in the bigger picture with weights and biases in its scoring system, while `VM::check()` is meant for a single technique to be evaluated without any weighted points or anything extra. It just gives you what the technique has found by its own. For example:

```cpp
if (VM::check(VM::VMID)) {
    std::cout << "VMID technique detected a VM!\n";
}

if (VM::check(VM::HYPERV_BIT)) {
    std::cout << "Hypervisor bit is set, most definitely a VM!\n";
}

// invalid
bool result = VM::check(VM::SIDT | VM::RDTSC);
```


# Flag table
VMAware provides a convenient way to not only check for VMs, but also have the flexibility and freedom for the end-user to choose what techniques are used with complete control over what gets executed or not. This is handled with a flag system.


| Technique | Description | Flag alias | Cross-platform? |
| --------- | ----------- | ---------- | --------------- |
| VMID | Check if the CPU manufacturer ID matches that of a VM brand | `VM::VMID` | Yes |
| Brand check | Check if the CPU brand string contains any indications of VM keywords | `VM::BRAND` | Yes |
| Hypervisor bit | Check if the hypervisor bit is set (always false on physical CPUs) | `VM::HYPERV_BIT` | Yes |
| 0x4 CPUID | Check if there are any leaf values between 0x40000000 and 0x400000FF that changes the CPUID output | `VM::CPUID_0x4` | Yes |
| Hypervisor length | Check if brand string length is long enough (would be around 2 characters in a host machine while it's longer in a hypervisor) | `VM::HYPERV_STR` | Yes |
| RDTSC check | Benchmark RDTSC and evaluate its speed, usually it's very slow in VMs | `VM::RDTSC` | Linux and Windows |
| SIDT check | Check if SIDT instructions does anything to the interrupt descriptor table | `VM::SIDT` | Linux |
| SIDT 5 check | Check if the 5th byte after sidt is null | `VM::SIDT5` | Linux |
| VMware port | Check if VMware port number 0x5658 is present | `VM::VMWARE_PORT` | Linux and Windows |
| Thread count | Check if there are only 1 or 2 threads, which is a common pattern in VMs with default settings (nowadays physical CPUs should have at least 4 threads for modern CPUs) | `VM::THREADCOUNT` | Yes |
| MAC address match | Check if the system's MAC address matches with preset values for certain VMs | `VM::MAC` | Linux and Windows |
| Check temperature | Check for the presence of CPU temperature sensors (mostly not present in VMs) | `VM::TEMPERATURE` | Linux |
| Check chassis vendor | Check if the chassis has any VM-related keywords | `VM::CVENDOR` | Linux |
| Check chassis type | Check if the chassis type is valid (usually not in VMs) | `VM::CTYPE` | Linux |
| Check docker | Check if any docker-related files are present such as /.dockerenv and /.dockerinit | `VM::DOCKER` | Linux |
| Check dmidecode | Get output from dmidecode tool and grep for common VM keywords | `VM::DMIDECODE` | Linux |
| Check dmesg | Get output from dmesg tool and grep for common VM keywords | `VM::DMESG` | Linux |
| Check HWMON | Check if HWMON is present (if not, likely a VM) | `VM::HWMON` | Linux |
| Analyse cursor | Check if cursor isn't active (sign of automated VM environment) | `VM::CURSOR` | Windows |
| Check VMware registry | Look for any VMware-specific registry data | `VM::VMWARE_REG` | Windows |
| Check Vbox registry | Look for any VirtualBox-specific registry data | `VM::VBOX_REG` | Windows |
| Check usernames | Match the username for any defaulted ones | `VM::USER` | Windows |
| Check DLLs | Match for VM-specific DLLs | `VM::DLL` | Windows |
| Check registry | Look throughout the registry for all sorts of VMs | `VM::REGISTRY` | Windows |
| Check Sunbelt | Detect for Sunbelt technology | `VM::SUNBELT` | Windows |
| Check Wine | Find for a Wine-specific file | `VM::WINE` | Windows |

# Non-technique flags
| Flag | Description |
|------|-------------|
| `VM::ALL` | This will enable all the flags technique flags, including the cursor check. |
| `VM::NO_MEMO` | This will disable memoization, meaning the result will not be fetched through a previous computation of the VM::detect function. Not sure why you'd need this, but it will take a performance hit if enabled. |
