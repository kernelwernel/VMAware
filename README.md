<h1 align="center">VMAware</h1>
<br>

**VMAware** is an open-source, cross-platform*, header-only, and incredibly simple C++ library for virtual machine (VM) detection.

It utilises a comprehensive list of low-level and high-level techniques that gets accounted in a scoring system. The library is meant to be stupidly easy to use and minimal as possible, with only **3** functions for its entire interface.

The library supports VMware, VirtualBox, QEMU, and obscure VMs you've probably never heard of. It also supports semi-VM technologies like hypervisors, docker, and wine.


# Examples
```cpp
#include "vmaware.hpp"
#include <iostream>

int main() {
    if (VM::detect()) {
        std::cout << "Virtual machine detected!\n";
        std::cout << "VM name: " << VM::brand() << "\n";
    } else {
        std::cout << "Nothing detected\n";
    }
}
```


# Flag table
VMAware provides a convenient way to not only check for VMs, but also have the flexibility and freedom for the end-user to choose what techniques are used with fine-grained control over what gets executed or not. This is handled with a flag system.


| Technique | Description | Flag alias | Cross-platform? |
| --------- | ----------- | ---------- | --------------- |
| VMID | Check if the CPU manufacturer ID matches that of a VM brand | `VM::VMID` | Yes |
| Brand check | Check if the CPU brand string contains any indications of VM keywords | `VM::BRAND` | Yes |
| Hypervisor bit | Check if the hypervisor bit is set (always false on physical CPUs) | `VM::HYPERV_BIT` | Yes |
| 0x4 CPUID | Check if there are any leaf values between 0x40000000 and 0x400000FF that changes the CPUID output | `VM::CPUID_0x4` | Yes |
| Hypervisor length | Check if brand string length is long enough (would be around 2 characters in a host machine while it's longer in a hypervisor) | `VM::HYPERV_STR` | Yes |
| RDTSC check | Benchmark RDTSC and evaluate its speed, usually it's very slow in VMs | `VM::RDTSC` | Linux and Windows |
| SIDT check | Check if SIDT instructions does anything to the interrupt descriptor table | `VM::SIDT` | Linux |
| VMware port | Check if VMware port number 0x5658 is present | `VM::VMWARE_PORT` | Linux and Windows |
| Thread count | Check if there are only 1 or 2 threads, which is a common pattern in VMs with default settings on (nowadays there should be at least 4 threads for modern CPUs) | `VM::THREADCOUNT` | Yes |
| MAC address match | Check if the system's MAC address matches with preset values for certain VMs | `VM::MAC` | Linux and Windows |
| Check temperature | Check for the presence of CPU temperature sensors (mostly not present in VMs) | `VM::TEMPERATURE` | Linux |
| Check chassis vendor | Check if the chassis has any VM-related keywords | `VM::CVENDOR` | Linux |
| Check chassis type | Check if the chassis type is valid (usually not in VMs) | `VM::CTYPE` | Linux |
| Check docker | Check if any docker-related files are present such as /.dockerenv and /.dockerinit | `VM::DOCKER` | Linux |
| Check dmidecode | Get output from dmidecode tool and grep for common VM keywords | `VM::DMIDECODE` | Linux |
| Check dmesg | Get output from dmesg tool and grep for common VM keywords | `VM::DMESG` | Linux |
| Check HWMON | Check if HWMON is present (if not, likely a VM) | `VM::HWMON` | Linux |


# Installation
To install, simply download or copy and paste the [vmaware.hpp] file to your project. No CMake or any of those build frameworks are necessary, it's literally that simple.


# Documentation
### `VM::detect()`

This is basically the only thing you need, which returns a `bool`. If the parameter is set to default, all the checks will be performed*. But you can optionally set what techniques are used like this:

```cpp
int main() {
    // essentially means only the brand, MAC, and hypervisor bit techniques should be performed
    std::uint64_t flags = (VM::BRAND | VM::MAC | VM::HYPERV_BIT);

    // return true or false based on the provided flags
    return VM::detect(flags);
}
```
NOTE: The less flags you provide, the more likely the result is NOT going to be accurate.


### `VM::brand()`
This will essentially output the VM brand if it detected one. The possible brand strings are: `VMware`, `VirtualBox`, `KVM`, `bhyve`, `QEMU`, `Microsoft Hyper-V`, `Microsoft x86-to-ARM`, `Parallels`, `Xen HVM`, `ACRN`, `QNX hypervisor`, `Hybrid Analysis`, `Sandboxie`, `Docker`, `Wine`, `Virtual Apple`. If none were detected, it will return "`Unknown`".



### `VM::check()`
This takes a single flag argument and returns a `bool`. It's essentially the same as `VM::detect()` but it doesn't have a scoring system. It only returns the technique's effective output.


*\*All checks are performed except for the cursor check, which waits 5 seconds for any human mouse interaction to detect automated virtual environments. This is the only technique that's disabled by default but if you want to include it, make sure to add the `VM::ALL` or `VM::CURSOR` flags*


# Why not pafish or Al-khaser?
Although [pafish](https://github.com/a0rtega/pafish) and [Al-khaser](https://github.com/LordNoteworthy/al-khaser) are great projects that have the same aim as this library, They are only supported for Windows. Not only are they non-compatible with Linux and MacOS, they are not designed as something that people can programmatically use for their own needs. VMAware on the other hand, provides a friendly interface for programmers to interact with the core of the detection engine.

This library is not meant to be a competitor to the aforementioned projects, but rather as an alternative with better freedom and practical usage. My goal is to bring something new to the table in the current VM detection software landscape that any C++ programmer can use without difficulty.


# Credits



# Legal
This library is not soliciting the development of malware (It's most likely going to be flagged by AVs anyway). I am __NOT__ responsible nor liable for any damage you cause through any malicious usage of VMAware. 

License: GPL