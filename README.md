<p align="center">
<img src="assets/banner.jpg" align="center" width="500" title="VMAware">
<br>
<img align="center" src="https://img.shields.io/github/actions/workflow/status/kernelwernel/VMAware/cmake-multi-platform.yml">
<img align="center" src="https://img.shields.io/github/downloads/kernelwernel/VMAware/total">
<img align="center" src="https://img.shields.io/github/license/kernelwernel/auto-stuff">
<a href="https://deepwiki.com/kernelwernel/VMAware"><img align="center" src="https://deepwiki.com/badge.svg" alt="Ask DeepWiki"></a>
<a href="https://github.com/kernelwernel/VMAware/actions/workflows/code_ql_analysis.yml">
  <img align="center" src="https://github.com/kernelwernel/VMAware/actions/workflows/code_ql_analysis.yml/badge.svg" alt="CodeQL Analysis">
</a>
</p>

**VMAware** (VM + Aware) is a cross-platform C++ library for virtual machine detection.

- - -

The library is:
- Very easy to use
- Cross-platform (Windows + MacOS + Linux)
- Features around 100 unique VM detection techniques [[list](https://github.com/kernelwernel/VMAware/blob/main/docs/documentation.md#flag-table)]
- Features the most cutting-edge techniques
- Able to detect over 70 VM brands including VMware, VirtualBox, QEMU, Hyper-V, and much more [[list](https://github.com/kernelwernel/VMAware/blob/main/docs/documentation.md#brand-table)]
- Able to beat VM hardeners
- Compatible with x86 and ARM, with backwards compatibility for 32-bit systems
- Very flexible, with total fine-grained control over which techniques get executed
- Able to detect various VM and semi-VM technologies like hypervisors, emulators, containers, sandboxes, and so on
- Available with C++11 and above
- Header-only
- Free of any external dependencies
- Memoized, meaning past results are cached and retrieved if ran again for performance benefits 
- Fully MIT-licensed, allowing unrestricted use and distribution

<br>

> [!NOTE]
> We are looking for Chinese translators. If you'd like to contribute with translating this README, feel free to give us a PR! Credit will be provided.


<br>


## Example 🧪
```cpp
#include "vmaware.hpp"
#include <iostream>

int main() {
    if (VM::detect()) {
        std::cout << "Virtual machine detected!" << "\n";
    } else {
        std::cout << "Running on baremetal" << "\n";
    }

    std::cout << "VM name: " << VM::brand() << "\n";
    std::cout << "VM type: " << VM::type() << "\n";
    std::cout << "VM certainty: " << (int)VM::percentage() << "%" << "\n";
}
```

possible output:
```
Virtual machine detected!
VM name: VirtualBox
VM type: Hypervisor (type 2)
VM certainty: 100%
```

<br>

## Structure ⚙️

<p align="center">
<img src="assets/vmaware.png" align="center" title="VMAware">
<br>
</p>

<br>

## CLI tool 🔧
This project also provides a tiny, but handy CLI tool utilising the full potential of what the library can do. It'll give you all sorts of details about the environment it's running under.

<img src="assets/demo.jpg" title="cli">

<!-- Try it out on [Compiler Explorer](https://godbolt.org/z/4sKa1sqrW)!-->

<br>

## Installation 📥
To install the library, download the `vmaware.hpp` file in the latest [release section](https://github.com/kernelwernel/VMAware/releases/latest) to your project. The binaries are also located there. No CMake or shared object linkages are necessary, it's literally that simple.

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

### FOR MACOS:
```bash
mkdir build
cd build
cmake ..
sudo make install
```

### FOR WINDOWS:
```bash
cmake -S . -B build/ -G "Visual Studio 16 2019"
```

Optionally, you can create a debug build by appending `-DCMAKE_BUILD_TYPE=Debug` to the cmake arguments.

<br>

### CMake installation
```cmake
# edit this
set(DIRECTORY "/path/to/your/directory/")

set(DESTINATION "${DIRECTORY}vmaware.hpp")

if (NOT EXISTS ${DESTINATION})
    message(STATUS "Downloading VMAware")
    set(URL "https://github.com/kernelwernel/VMAware/releases/latest/download/vmaware.hpp")
    file(DOWNLOAD ${URL} ${DESTINATION} SHOW_PROGRESS)
else()
    message(STATUS "VMAware already downloaded, skipping")
endif()
```

The module file and function version is located [here](auxiliary/vmaware_download.cmake)


<br>

## Documentation and code overview 📒
You can view the full docs [here](docs/documentation.md). All the details such as functions, techniques, settings, and examples are provided. Trust me, it's not too intimidating ;)

If you want to learn about the architecture and design of the library, head over to https://deepwiki.com/kernelwernel/VMAware

<br>

## Q&A ❓

<details>
<summary>How does it work?</summary>
<br>

> It utilises a comprehensive list of low-level and high-level anti-VM techniques that gets accounted in a scoring system. The scores (0-100) for each technique are arbitrarily given, and every technique that has detected a VM will have their score added to a single accumulative point, where a threshold point number will decide whether it's actually running in a VM.

</details>

<details>
<summary>Who is this library for and what are the use cases?</summary>
<br>

> It's designed for security researchers, VM engineers, anticheat developers, and pretty much anybody who needs a practical and rock-solid VM detection mechanism in their project. For example, the library is suitable if you're making a VM and you're testing the effectiveness of concealing itself. If you're a proprietary software developer, the library is useful to thwart against reverse engineers. If you're a malware analyst and you want to check the concealment capability of your VM, this would be the perfect tool to benchmark how well-concealed your VM is against malware. 
> 
> Additionally, software could adjust the behaviour of their program based on the detected environment. It could be useful for debugging and testing purposes, while system administrators could manage configurations differently. Finally, some applications might want to legally restrict usage in VMs as a license clause to prevent unauthorized distribution or testing.
>
> There are also projects that utilise our tool such as [Hypervisor-Phantom](https://codeberg.org/Scrut1ny/Hypervisor-Phantom), which is an advanced malware analysis project that we helped strengthen their hypervisor environment and undetectability. 
> 
</details>

<details>
<summary>Why another VM detection project?</summary>
<br>

> There's already loads of projects that have the same goal such as 
<a href="https://github.com/CheckPointSW/InviZzzible">InviZzzible</a>, <a href="https://github.com/a0rtega/pafish">pafish</a> and <a href="https://github.com/LordNoteworthy/al-khaser">Al-Khaser</a>. But the difference between the aforementioned projects is that they don't provide a programmable interface to interact with the detection mechanisms, on top of having little to no support for non-Windows systems. Additionally, the VM detections in all those projects are often not sophisticated enough to be practically applied to real-world scenarios while not providing enough VM detection techniques. An additional hurdle is that they are all GPL projects, so using them for proprietary projects (which would be the main audience for such a functionality), is out of the question. 
>
> Pafish and InviZzzible have been abandoned for years. Although Al-Khaser does receive occasional updates and has a wide scope of detections that VMAware doesn't provide (anti-debugging, anti-injection, and so on), it still falls short due to the previously mentioned problems above.
> 
> While those projects have been useful to VMAware to some extent, we wanted to make them far better. My goal was to make the detection techniques to be accessible programmatically in a cross-platform and flexible way for everybody to get something useful out of it rather than providing just a CLI tool. It also contains a larger quantity of techniques, so it's basically just a VM detection framework on steroids that focuses on practical and realistic usability for any scenario.

</details>

<!--
<details>
<summary>How does it compare to paid VM detection libraries?</summary>
<br>

> There are several paid software solutions available for protecting software licenses from reverse engineering or cracking, such as <a href="https://docs.sentinel.thalesgroup.com/home.htm">Thales' Sentinel RMS</a> and <a href="https://vmpsoft.com/">VMProtect</a>. These tools include VM detection as part of their feature set, though their primary focus is not necessarily VM detection unlike this project.
</details>
-->

<details>
<summary>Wouldn't it make it inferior for having the project open source?</summary>
<br>

> The only downside to VMAware is that it's fully open source, which makes the job of bypassers easier compared to having it closed source. However, I'd argue that's a worthy tradeoff by having as many VM detection techniques in an open and interactive manner rather than trying to obfuscate. Having it open source means we can have valuable community feedback to strengthen the library more effectively and accurately through discussions, collaborations, and competition against anti-anti-vm projects and malware analysis tools which try to hide it's a VM. 
> 
> All of this combined has further advanced the forefront innovations in the field of VM detections much more productively, compared to having it closed source. This is what made the project the best VM detection framework out there, and bypassing it has shown to be an immense challenge due to the sheer number of sophisticated and never-before-seen techniques we employ that other VM detectors don't use whether open or closed source (to our knowledge).
>
> In other words, it's about better quality AND quantity, better feedback, and better openness over security through obfuscation. It's the same reason why OpenSSH, OpenSSL, the Linux kernel, and other security-based software projects are relatively secure because of how there's more people helping to make it better compared to people trying to probe the source code with malicious intent. VMAware has this philosophy, and if you know anything about security, you should be familiar with the phrase: "Security through obfuscation is NOT security".

</details>


<details>
<summary>How effective are VM hardeners against the lib?</summary>
<br>

> Publicly known hardeners are not effective and most of them on Windows have been beaten, but this doesn't mean that the lib is immune to them. We challenged the most famous ones we know, and that's why we created a bypass against them as our main focus. Custom hardeners that we may not be aware of might have a theoretical advantage, but they are substantially more difficult to produce.

</details>


<details>
<summary>Is it possible to spoof the result?</summary>
<br>

> Yes. There are some techniques that are trivially spoofable, and there's nothing the library can do about it whether it's a deliberate false positive or even a false negative. This is a problem that every VM detection project is facing whether closed or open source, which is why the library is trying to test every technique possible to get the best result based on the environment it's running under. Remember, EVERYTHING is technically spoofable.

</details>


<details>
<summary>How is it developed?</summary>
<br>

> We first try to come up with ideas and make prototype techniques in the dev branch. We merge the dev branch to main around once a week because we want to make sure the techniques work as intended in a real-world system before it's utilised. The new techniques would be left on the main branch for people to test, and then we add them to the release for everybody to try it out.

</details>

<details>
<summary>What about using this for malware?</summary>
<br>

> This project is not soliciting the development of malware for obvious reasons. Even if you intend to use it for concealment purposes, it'll most likely be flagged by antiviruses anyway and nothing is obfuscated to begin with.

</details>

<details>
<summary>I have linker errors when compiling</summary>
<br>

> If you're compiling with gcc or clang, add the <code>-lm</code> and <code>-lstdc++</code> flags, or use g++/clang++ compilers instead. If you're receiving linker errors from a brand new VM environment on Linux, update your system with `sudo apt/dnf/yum update -y` to install the necessary C++ components.

</details>

<br>

## Issues, discussions, pull requests, and inquiries 📬
If you have any suggestions, ideas, or any sort of contribution, feel free to ask! I'll be more than happy to discuss either in the [issue](https://github.com/kernelwernel/VMAware/issues) or [discussion](https://github.com/kernelwernel/VMAware/discussions) sections. We usually reply fairly quickly. If you want to personally ask something in private, our discords are `kr.nl` and `shenzken`

For email inquiries: `jeanruyv@gmail.com`

And if you found this project useful, a star would be appreciated :)

<br>

## Credits, contributors, and acknowledgements ✒️
- [kernelwernel](https://github.com/kernelwernel) (Maintainer and developer)
- [Requiem](https://github.com/NotRequiem) (Maintainer and co-developer)
- [Check Point Research](https://research.checkpoint.com/)
- [Unprotect Project](https://unprotect.it/)
- [Al-Khaser](https://github.com/LordNoteworthy/al-khaser)
- [pafish](https://github.com/a0rtega/pafish)
- [Matteo Malvica](https://www.matteomalvica.com)
- N. Rin, EP_X0FF
- [Peter Ferrie, Symantec](https://github.com/peterferrie)
- [Graham Sutherland, LRQA Nettitude](https://www.nettitude.com/uk/)
- [Alex](https://github.com/greenozon)
- [Marek Knápek](https://github.com/MarekKnapek)
- [Vladyslav Miachkov](https://github.com/fameowner99)
- [(Offensive Security) Danny Quist](chamuco@gmail.com)
- [(Offensive Security) Val Smith](mvalsmith@metasploit.com)
- Tom Liston + Ed Skoudis
- [Tobias Klein](https://www.trapkit.de/index.html)
- [(S21sec) Alfredo Omella](https://www.s21sec.com/)
- [hfiref0x](https://github.com/hfiref0x)
- [Waleedassar](http://waleedassar.blogspot.com)
- [一半人生](https://github.com/TimelifeCzy)
- [Thomas Roccia (fr0gger)](https://github.com/fr0gger)
- [systemd project](https://github.com/systemd/systemd)
- mrjaxser
- [iMonket](https://github.com/PrimeMonket)
- Eric Parker's discord community 
- [ShellCode33](https://github.com/ShellCode33)
- [Georgii Gennadev (D00Movenok)](https://github.com/D00Movenok)
- [utoshu](https://github.com/utoshu)
- [Jyd](https://github.com/jyd519)
- [git-eternal](https://github.com/git-eternal)
- [dmfrpro](https://github.com/dmfrpro)
- [Teselka](https://github.com/Teselka)
- [Kyun-J](https://github.com/Kyun-J)
- [luukjp](https://github.com/luukjp)

<br>

## Legal 📜
I am not responsible nor liable for any damage you cause through any malicious usage of this project. 

License: MIT
