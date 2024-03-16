#include "../src/vmaware.hpp"
#include <iostream>

int main(void) {
    std::cout << VM::detect() << "\n";
    return 0;
}