#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h>
#include <cpuid.h>

#define NUM_ITERATIONS 100000

int main() {
    uint64_t start, end, total_cycles = 0;
    unsigned int eax, ebx, ecx, edx;

    for (int i = 0; i < NUM_ITERATIONS; i++) {
        // Measure time for CPUID
        start = __rdtsc();
        __cpuid(0, eax, ebx, ecx, edx);
        end = __rdtsc();

        total_cycles += (end - start); // Accumulate the cycles
    }

    // Calculate and print the average time
    double average_cycles = (double)total_cycles / NUM_ITERATIONS;
    printf("Average CPUID took %.2f cycles over %d iterations.\n", average_cycles, NUM_ITERATIONS);

    return 0;
}