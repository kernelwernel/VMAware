<h1 align="center">VMAware</h1>
<br>

<p align="center">
  <img src="assets/banner.jpg" width="500" title="VMAware">
</p>


**VMAware** (not to be confused with VMware) is an open-source, cross-platform, and incredibly simple C++ library for virtual machine detection.


It utilises a comprehensive list of low-level and high-level anti-VM techniques that gets accounted in a scoring system. The library is meant to be stupidly easy to use, and it's designed for anticheat developers, security researchers, VM engineers, and pretty much anybody who needs a practical and rock-solid VM detection mechanism in their project.


The library is:
- Very easy to use, with only 3 functions in its public interface
- Very flexible with fine-grained control
- Cross-platform (to an extent)
- Header-only
- Available with C++11 and above
- Able to detect VMware, VirtualBox, QEMU, KVM, Parallels, and much more!
- Able to detect semi-VM technologies like hypervisors, docker, and wine
- Able to determine the VM brand
- Incredibly fast (takes around 1~5 milliseconds)
- Memoized, meaning past results are cached and retrieved if ran again for performance benefits 

The library is currently a beta, so more improvements and cross-compatibility fixes are planned.

<br>

# Example 🧪
```cpp
#include "vmaware.hpp"
#include <iostream>

int main() {
    if (VM::detect()) {
        std::cout << "Virtual machine detected!\n";
        std::cout << "VM name: " << VM::brand() << "\n";
    } else {
        std::cout << "Running in baremetal\n";
    }
}
```

<br>

# CLI tool 🔧
This project also provides a tiny, but handy CLI tool utilising the full potential of what the library can do.

<img src="assets/image.png" width="500" title="cli">

<br>

# Installation 📥
To install the library, simply download or copy and paste the [vmaware.hpp](src/vmaware.hpp) file to your project. No CMake or build frameworks are necessary, it's literally that simple.

However, if you want the full project (globally accessible headers with <vmaware.hpp> and the CLI tool), follow these commands:
```bash
git clone https://github.com/kernelwernel/VMAware 
cd VMAware
sudo make install
```
> NOTE: I'm most likely going to change my username in the future. If the github link doesn't exist, search for the VMAware project and you should find it.

<br>

# Documentation 📒
You can view the full docs [here](docs/documentation.md)

<br>

# Credits ✒️
- [Check Point Research](https://research.checkpoint.com/)
- [Unprotect Project](https://unprotect.it/)
- [Al-Khaser](https://github.com/LordNoteworthy/al-khaser)
- [pafish](https://github.com/a0rtega/pafish)
- [Matteo Malvica](https://www.matteomalvica.com)

<br>

# Legal 📜
This library is __NOT__ soliciting the development of malware (it's most likely going to be flagged by AVs anyway). I am not responsible nor liable for any damage you cause through any malicious usage of this project. 

License: GPL-3.0