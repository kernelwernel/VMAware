<h1 align="center">VMAware</h1>
<br>
<p align="center">
<img src="assets/banner.jpg" align="center" width="500" title="VMAware">
<br>
<img alt="GitHub Workflow Status (with event)" align="center" src="https://img.shields.io/github/actions/workflow/status/kernelwernel/VMAware/cmake-multi-platform.yml">
<img alt="GitHub" align="center" src="https://img.shields.io/github/license/kernelwernel/VMAware">
</p>

**VMAware** (not to be confused with VMware) is a cross-platform C++ library for virtual machine detection.

It utilises a comprehensive list of low-level and high-level anti-VM techniques that gets accounted in a scoring system. The library is meant to be stupidly easy to use, designed for anybody wanting to integrate the library to their project without a hassle.

The library is:
- Very easy to use, with only 4 functions in its public interface
- Very flexible, with total fine-grained control over what gets executed
- Cross-platform (Windows + MacOS + Linux)
- Header-only
- Available with C++11 and above
- Features up to 50+ techniques
- Able to detect VMware, VirtualBox, QEMU, KVM, Parallels, and [much more](https://github.com/kernelwernel/VMAware/blob/v0.2/docs/documentation.md#vmbrand)
- Able to detect semi-VM technologies like hypervisors, docker, and wine
- Able to guess the VM brand
- Memoized, meaning past results are cached and retrieved if ran again for performance benefits 

- - -

**IMPORTANT:** The library is currently in the alpha stage, so more improvements and cross-compatibility fixes are planned (especially for MacOS and Windows which I'm currently working on improving). I don't recommend using this for any serious projects for now.

Also, this library doesn't guarantee it'll be accurate. If you found a false negative then please create an issue with information on what your VM is, what OS you're using, and other useful details.

- - -

<br>

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
    
    std::cout << "VM certainty: " << VM::percentage() << "%" << std::endl;
}
```

<br>

## CLI tool 🔧
This project also provides a tiny, but handy CLI tool utilising the full potential of what the library can do. Also, running the CLI as root would give better results.

<img src="assets/demo.png" width="500" title="cli">

<br>

## Installation 📥
To install the library, download or copy paste the `vmaware.hpp` file in the [release section](https://github.com/kernelwernel/VMAware/releases/) to your project. No CMake or shared object linkages are necessary, it's literally that simple.

However, if you want the full project (globally accessible headers with <vmaware.hpp> and the CLI tool), follow these commands:
```bash
git clone https://github.com/kernelwernel/VMAware 
cd VMAware
```

### FOR LINUX:
```bash
sudo dnf/apt/yum update -y # change this to whatever your distro is
mkdir build
cd build
cmake ..
sudo make install
```

### FOR WINDOWS:
```bash
cmake -S . -B build/ -G "Visual Studio 16 2019"
```
> NOTE: I'm most likely going to change my username in the future. If the github link doesn't exist, search for the VMAware project and you should find it.

<br>

## Documentation 📒
You can view the full docs [here](docs/documentation.md). Trust me, it's not too intimidating.

<br>

## Q&A ❓
- Who is this library for?
> It's designed for security researchers, VM engineers, and pretty much anybody who needs a practical and rock-solid VM detection mechanism in their project. For example, if you're making a VM and you're testing the effectiveness of concealing itself, or if you're a malware analyst and you want to check if your VM environment is good enough.

- Why another VM detection project?
> There's already loads of projects that have the same goal such as [InviZzzible](https://github.com/CheckPointSW/InviZzzible), [pafish](https://github.com/a0rtega/pafish) and [Al-Khaser](https://github.com/LordNoteworthy/al-khaser). But the difference between the aforementioned projects is that they don't provide a programmable interface to interact with the detection mechanisms, on top of having little to no support for non-Windows systems. I wanted the core detection techniques to be accessible programmatically in a cross-platform way for everybody to get something useful out of it rather than providing just a CLI tool like those projects.

- Is it possible to spoof the result?
> Yes. There are some techniques that are trivially spoofable, and there's nothing the library can do about it whether it's a deliberate false negative or even a false positive. This is a problem that every VM detection project is facing, which is why the library is trying to test every technique possible to get the best result based on the environment it's running under. 

- Can I use this for malware?
> This project is not soliciting the development of malware for obvious reasons. Even if you intend to use it for concealment purposes, it'll most likely be flagged by antiviruses anyway.

- When will a 1.0 be available?
> Pretty soon, maybe around january 2024 (I just started university, so I can't guarantee anything)

<br>

## Issues and pull requests 📬
If you have any suggestions, ideas, or any sort of contribution, feel free to ask! I'll be more than happy to discuss. If you want to personally ask something in private, my discord is `kr.nl`

Contribution guidelines can be found [here](CONTRIBUTING.md).

If you found this project useful, a star would be appreciated :)

<br>

## Credits ✒️
- [Check Point Research](https://research.checkpoint.com/)
- [Unprotect Project](https://unprotect.it/)
- [Al-Khaser](https://github.com/LordNoteworthy/al-khaser)
- [pafish](https://github.com/a0rtega/pafish)
- [Matteo Malvica](https://www.matteomalvica.com)
- N. Rin, EP_X0FF
- [Peter Ferrie, Symantec](https://github.com/peterferrie)
- [Graham Sutherland, LRQA Nettitude](https://www.nettitude.com/uk/)

<br>

## Legal 📜
I am not responsible nor liable for any damage you cause through any malicious usage of this project. 

License: GPL-3.0
