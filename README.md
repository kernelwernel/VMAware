# VMAware
**VMAware** is an open-source, cross-platform, and incredibly simple C++ library for virtual machine (VM) detection.

It utilises multiple low-level and high-level techniques that gets accounted in a scoring system with a certain threashold to be confident in its evaluation. The library is meant to be as stupidly simple and minimal as possible, with only **2** functions for its entire public interface.

The library supports VMware, VirtualBox ... and even non-VM technologies like docker, wine, and hypervisors.


# Example
```cpp
#include "vmaware.hpp"
#include <iostream>

int main() {
    if (VM::detect()) {
        std::cout << "Virtual machine detected!\n";
        std::cout << "VM name: " << VM::brand() << "\n";
    } else {
        std::cout << "Nothing was detected\n";
    }
}
```

compiler explorer demo: add link here


# Demo


# Why not pafish or Al-khaser?
Although pafish(link) is a great project that has the same aim as this library, it is only supported for Windows. Not only is it non-compatible with Linux and MacOS, it's not designed as something that people can programmatically use for their own needs. VMAware on the other hand provides a friendly interface for programmers to interact with the core of the detection engine. 

This library is not meant to be a competitor to pafish, but rather an alternative with better flexibility over its usage. On top of this, the project hasn't been updated for over 2 years as of writing, and I want to bring something new to the table in the current VM detection software landscape.


# Credits



# Legal
This library is not soliciting the development of malware. I am not legally responsible nor liable for any damage you cause through any malicious usage of VMAware.