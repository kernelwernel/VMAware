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
     * Essentially means only the brand, MAC, and hypervisor bit techniques 
     * should be performed. Note that the less flags you provide, the more 
     * likely the result will not be accurate. If you just want to check for 
     * a single technique, use VM::check() instead.
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
     * If you don't want the value to be memoized for whatever reason, 
     * you can set the VM::NO_MEMO flag and the result will not be cached. 
     * Keep in mind that this could take a performance hit.
     */ 
    bool is_vm3 = VM::detect(VM::ALL | VM::NO_MEMO);
}
```


# `VM::brand()`
This will essentially return the VM brand as a `std::string`. The brand string return values are: 
- `VMware`
- `VirtualBox`
- `KVM`
- `bhyve`
- `QEMU`
- `Microsoft Hyper-V`
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
- `Virtual PC`
- `Anubis`
- `JoeBox`
- `Thread Expert`
- `CW Sandbox`

If none were detected, it will return `Unknown`. It's often not going to produce a satisfying result due to technical difficulties with accomplishing this, on top of being highly dependant on what mechanisms detected a VM. Don't rely on this function too much.

```cpp
int main() {
    const std::string result = VM::brand();

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

`VM::detect()` is meant for a range of techniques to be evaluated in the bigger picture with weights and biases in its scoring system, while `VM::check()` is meant for a single technique to be evaluated without any points or anything extra. It just gives you what the technique has found on its own. For example:

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


| Flag alias | Description | Cross-platform? | Certainty | Root required? |
| ---------- | ----------- | --------------- | --------- | -------------- |
| `VM::VMID` | Check if the CPU manufacturer ID matches that of a VM brand | Yes | 100% |  |
| `VM::BRAND` | Check if the CPU brand string contains any indications of VM keywords | Yes | 50% |  |
| `VM::HYPERV_BIT` | Check if the hypervisor bit is set (always false on physical CPUs) | Yes | 95% |  |
|`VM::CPUID_0x4` | Check if there are any leaf values between 0x40000000 and 0x400000FF that changes the CPUID output | Yes | 70% |  |
| `VM::HYPERV_STR` | Check if brand string length is long enough (would be around 2 characters in a host machine while it's longer in a hypervisor) | Yes | 45% |  |
| `VM::RDTSC` | Benchmark RDTSC and evaluate its speed, usually it's very slow in VMs | Linux and Windows | 20% |  |
| `VM::SIDT` | Check if SIDT instructions does anything to the interrupt descriptor table | Linux | 65% |  |
| `VM::SIDT5` | Check if the 5th byte after sidt is null | Linux | 45% |  |
| `VM::VMWARE_PORT` | Check if VMware port number 0x5658 is present | Linux and Windows | 80% |  |
| `VM::THREADCOUNT` | Check if there are only 1 or 2 threads, which is a common pattern in VMs with default settings (nowadays physical CPUs should have at least 4 threads for modern CPUs) | Yes | 35% |  |
| `VM::MAC` | Check if the system's MAC address matches with preset values for certain VMs | Linux and Windows | 90% |  |
| `VM::TEMPERATURE` | Check for the presence of CPU temperature sensors (mostly not present in VMs) | Linux | 15% |  |
| `VM::SYSTEMD` | Get output from systemd-detect-virt tool | Linux | 70% |  |
| `VM::CVENDOR` | Check if the chassis has any VM-related keywords | Linux | 65% |  |
| `VM::CTYPE` | Check if the chassis type is valid (usually not in VMs) | Linux | 10% |  |
| `VM::DOCKERENV` | Check if any docker-related files are present such as /.dockerenv and /.dockerinit | Linux | 80% |  |
| `VM::DMIDECODE` | Get output from dmidecode tool and grep for common VM keywords | Linux | 55% | Yes |
| `VM::DMESG` | Get output from dmesg tool and grep for common VM keywords | Linux | 55% |  |
| `VM::HWMON` | Check if HWMON is present (if not, likely a VM) | Linux | 75% |  |
| `VM::CURSOR`  | Check if cursor isn't active (sign of automated VM environment) | Windows | 10% |  |
| `VM::VMWARE_REG` | Look for any VMware-specific registry data | Windows | 65% |  |
| `VM::VBOX_REG` | Look for any VirtualBox-specific registry data | Windows | 65% |  |
| `VM::USER` | Match the username for any defaulted ones | Windows | 35% |  |
| `VM::DLL` | Match for VM-specific DLLs | Windows | 50% |  |
| `VM::REGISTRY` | Look throughout the registry for all sorts of VMs | Windows | 75% |  |
| `VM::SUNBELT` | Detect for Sunbelt technology | Windows | 10% |  |
| `VM::WINE_CHECK` | Find for a Wine-specific file | Windows | 85% |  |
| `VM::BOOT` | Analyse the OS uptime | Yes | 5% |  |
| `VM::VM_FILES` | Find if any VM-specific files exists | Windows | 20% |  |
| `VM::HWMODEL` | Check if the sysctl for the hwmodel does not contain the "Mac" string | MacOS | 75% |  |
| `VM::DISK_SIZE` | Check if disk size is under or equal to 50GB | Linux | 60% |  |
| `VM::VBOX_DEFAULT` | Check for default RAM and DISK sizes set by VirtualBox | Linux and Windows | 55% | Yes |
| `VM::VBOX_NETWORK` | Check VBox network provider string | Windows | 70% |  |
| `VM::COMPUTER_NAME` | Check for computer name string | Windows | 40% |  |
| `VM::MEMORY` | Check if memory space is far too low for a physical machine | Windows | 35% |  |
| `VM::VM_PROCESSES` | Check for any VM processes that are active | Windows | 30% |  |
| `VM::LINUX_USER_HOST` | Check for default VM username and hostname for linux | Linux | 35% |  |
| `VM::VBOX_WINDOW_CLASS` | Check for the window class for VirtualBox | 10% |  |
| `VM::WINDOWS_NUMBER` | Check top-level default window level | 20% |  | 
| `VM::GAMARUE` | Check for Gamarue ransomeware technique which compares VM-specific Window product IDs | 40% |  | 

# Non-technique flags
| Flag | Description |
|------|-------------|
| `VM::ALL` | This will enable all the technique flags, including the cursor check. |
| `VM::NO_MEMO` | This will disable memoization, meaning the result will not be fetched through a previous computation of the VM::detect function. Not sure why you'd need this, but it will take a performance hit if enabled. |
