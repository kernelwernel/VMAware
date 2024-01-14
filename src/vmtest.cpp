#include "vmaware.hpp"
#include <iostream>

int main(void) {
    //std::cout << VM::detect(VM::DEFAULT & ~(VM::VMID)) << "\n";
    std::cout << VM::detect() << "\n";
    return 0;
}