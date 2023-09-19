<h1 align="center">VMAware</h1>
<br>
<p align="center">
<img src="assets/banner.jpg" align="center" width="500" title="VMAware">
<br>
<img alt="GitHub Workflow Status (with event)" align="center" src="https://img.shields.io/github/actions/workflow/status/kernelwernel/VMAware/cmake-multi-platform.yml">
<img alt="GitHub" align="center" src="https://img.shields.io/github/license/kernelwernel/VMAware">
</p>

**VMAware** (not to be confused with VMware) is an open-source, cross-platform, and incredibly simple C++ library for virtual machine detection.

It utilises a comprehensive list of low-level and high-level anti-VM techniques that gets accounted in a scoring system. The library is meant to be stupidly easy to use, with additional features such as brand detection.

The library is:
- Very easy to use, with only 3 functions in its public interface
- Very flexible with fine-grained control
- Cross-platform (to an extent)
- Header-only
- Available with C++11 and above
- Able to detect VMware, VirtualBox, QEMU, KVM, Parallels, and much more
- Able to detect semi-VM technologies like hypervisors, docker, and wine
- Able to determine the VM brand
- Memoized, meaning past results are cached and retrieved if ran again for performance benefits 

- - -

**IMPORTANT:** The library is currently a beta, so more improvements and cross-compatibility fixes are planned (especially for Windows which I'm currently working on fixing). Although the project is improving on a daily basis, I don't recommend using this for any serious projects for now.

- - -


## Example 🧪
```cpp
#include "vmaware.hpp"
#include <iostream>

int main() {
    if (VM::detect()) {
        std::cout << "Virtual machine detected!" << std::endl;
        std::cout << "VM name: " << VM::brand() << std::endl;
    } else {
        std::cout << "Running in baremetal" << std::endl;
    }
}
```


## CLI tool 🔧
This project also provides a tiny, but handy CLI tool utilising the full potential of what the library can do.

<img src="assets/image.png" width="500" title="cli">


## Installation 📥
To install the library, simply download or copy and paste the [vmaware.hpp](src/vmaware.hpp) file to your project. No CMake or build frameworks are necessary, it's literally that simple.

However, if you want the full project (globally accessible headers with <vmaware.hpp> and the CLI tool), follow these commands:
```bash
git clone https://github.com/kernelwernel/VMAware 
cd VMAware
mkdir build
cd build
cmake ..
sudo make install
```
> NOTE: I'm most likely going to change my username in the future. If the github link doesn't exist, search for the VMAware project and you should find it.


## Documentation 📒
You can view the full docs [here](docs/documentation.md). Trust me, it's not too intimidating.


## Q&A ❓
- Who is this library for?
> It's designed for security researchers, VM engineers, anticheat developers*, and pretty much anybody who needs a practical and rock-solid VM detection mechanism in their project. For example, if you're making a VM and you're testing the effectiveness of concealing itself, or if you're a malware analyst and you want to check if your VM environment is good enough.

- Why another VM detection project?
> There's already loads of projects that have the same goal such as [InviZzzible](https://github.com/CheckPointSW/InviZzzible), [pafish](https://github.com/a0rtega/pafish) and [Al-Khaser](https://github.com/LordNoteworthy/al-khaser). But the difference between the aforementioned projects is that they have little to no support with non-Windows systems. On top of this, I wanted the core detection techniques to be accessible programmatically for everybody to get something useful out of it rather than providing just a CLI tool like the projects above.

- Is it possible to spoof the result?
> Yes. There are some techniques that are trivially spoofable, and there's nothing the library can do about it whether it's a false negative or even a false positive. This is a problem that every VM detection project is facing, which is why the library is trying to test every technique possible to get the best result based on the environment it's running under. 

- Can I use this for malware?
> This project is not soliciting the development of malware for any malicious intentions. Even if you intend to use it that way, it'll most likely be flagged by antiviruses anyway.

- If it's designed for anti-cheat, why is it GPL?
> I used/modified a few GPL-3.0 code from other projects. Works that are derived from that license must use the same license, so I had no choice but to use it. An open-source anti-cheat sounds like a bad idea, and frankly it is for a few reasons. Although it's possible, this isn't a good library for anti-cheats in that regard even if it can be used for that purpose. On the other hand, it can prevent exploit developers probing the game in a VM or anybody attempting a ban evasion, which is worth a mention.

- When will a 1.0 be available?
> Pretty soon, maybe around November (I just started university a few days ago, so I can't guarantee anything)


## Issues and pull requests 
If you have any suggestions, ideas, or any sort of contribution, feel free to ask! I'll be more than happy to discuss. If you want to personally say something for whatever reason, my discord is `kr.nl`

If you found this project useful, a star would be appreciated :)


## Credits ✒️
- [Check Point Research](https://research.checkpoint.com/)
- [Unprotect Project](https://unprotect.it/)
- [Al-Khaser](https://github.com/LordNoteworthy/al-khaser)
- [pafish](https://github.com/a0rtega/pafish)
- [Matteo Malvica](https://www.matteomalvica.com)


## Legal 📜
I am not responsible nor liable for any damage you cause through any malicious usage of this project. 

License: GPL-3.0