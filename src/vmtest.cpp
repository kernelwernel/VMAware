#include "vmaware.hpp"
#include <iostream>

int main(void) {
    std::cout << VM::get_ram_size() << "\n";
    return 0;
}