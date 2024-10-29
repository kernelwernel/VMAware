/**
 * ██╗   ██╗███╗   ███╗ █████╗ ██╗    ██╗ █████╗ ██████╗ ███████╗
 * ██║   ██║████╗ ████║██╔══██╗██║    ██║██╔══██╗██╔══██╗██╔════╝
 * ██║   ██║██╔████╔██║███████║██║ █╗ ██║███████║██████╔╝█████╗  
 * ╚██╗ ██╔╝██║╚██╔╝██║██╔══██║██║███╗██║██╔══██║██╔══██╗██╔══╝  
 *  ╚████╔╝ ██║ ╚═╝ ██║██║  ██║╚███╔███╔╝██║  ██║██║  ██║███████╗
 *   ╚═══╝  ╚═╝     ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
 * 
 *  C++ VM detection library
 * 
 * ===============================================================
 *
 *  This program will scan for IDT values based on the execution
 *  of multiple threads, which allows us to collect IDT information
 *  which could be potentially used for VM detections.
 * 
 * ===============================================================
 * 
 *  - Made by: @Requiem (https://github.com/NotRequiem)
 *  - Repository: https://github.com/kernelwernel/VMAware
 *  - License: GPL 3.0
 */ 

#include <iostream>
#include <thread>
#include <vector>
#include <pthread.h>
#include <sched.h>
#include <unistd.h>

#ifdef _MSC_VER
#include <intrin.h>
#else
#include <x86intrin.h>
#endif

#pragma pack(push, 1)
struct IDTR {
    uint16_t limit;
    uint64_t base;
};
#pragma pack(pop)

void print_idt_base() {
    IDTR idtr;

#ifdef _MSC_VER
    __sidt(&idtr);
#else
    asm volatile ("sidt %0" : "=m" (idtr));
#endif

    uint64_t idt_base = idtr.base;
    std::cout << "Thread ID: " << std::this_thread::get_id() << " | IDT base address: 0x" << std::hex << idt_base << "\n";
}

// Function to bind a thread to a specific core on Linux
void set_thread_affinity(unsigned int core_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);  // Clear the CPU set
    CPU_SET(core_id, &cpuset);  // Set the desired core

    // Get the current thread
    pthread_t current_thread = pthread_self();

    // Set thread affinity to the specific core
    if (pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpuset) != 0) {
        std::cerr << "Error setting thread affinity\n";
    }
}

// Function to run code on multiple cores
void run_on_multiple_cores(int times) {
    unsigned int num_threads = std::thread::hardware_concurrency();
    std::cout << "Running on " << num_threads << " threads (multiple cores)...\n";

    for (int i = 0; i < times; ++i) {
        std::vector<std::thread> threads;
        for (unsigned int j = 0; j < num_threads; ++j) {
            threads.emplace_back([j]() {
                set_thread_affinity(j);  // Bind thread to core j
                print_idt_base();
            });
        }

        for (auto& thread : threads) {
            thread.join();
        }
    }
}

// Function to run code on a single core
void run_on_single_core(int times) {
    std::cout << "Running on a single core...\n";
    set_thread_affinity(0);  // Bind thread to core 0

    for (int i = 0; i < times; ++i) {
        print_idt_base();
    }
}

int main() {
    int iterations = 5;
    run_on_multiple_cores(iterations);
    run_on_single_core(iterations);

    return 0;
}