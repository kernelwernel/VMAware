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
 *  Benchmark Utility: Measures performance of VM detection primitives
 *  with cross-platform nanosecond precision timing and adaptive unit
 *  formatting. Supports Windows, Linux, and macOS.
 *
 * ===============================================================
 *
 *  - Repository: https://github.com/kernelwernel/VMAware
 *  - License: GPL 3.0
 */

#include "../src/vmaware.hpp"
#include <iostream>
#include <string>
#include <cmath>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__linux__)
#include <time.h>
#elif defined(__APPLE__)
#include <mach/mach_time.h>
#endif

class Benchmark {
public:
    static uint64_t get_timestamp() {
#if defined(_WIN32)
        LARGE_INTEGER counter;
        QueryPerformanceCounter(&counter);
        return counter.QuadPart;
#elif defined(__linux__)
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return static_cast<uint64_t>(ts.tv_sec) * 1e9 + ts.tv_nsec;
#elif defined(__APPLE__)
        return mach_absolute_time();
#else
        return 0;
#endif
    }

    static double get_elapsed(uint64_t start, uint64_t end) {
#if defined(_WIN32)
        static LARGE_INTEGER freq;
        QueryPerformanceFrequency(&freq);
        return (end - start) * 1e9 / freq.QuadPart; // Convert to nanoseconds
#elif defined(__linux__)
        return end - start; // Already in nanoseconds
#elif defined(__APPLE__)
        static mach_timebase_info_data_t timebase;
        if (timebase.denom == 0) mach_timebase_info(&timebase);
        return (end - start) * timebase.numer / timebase.denom;
#else
        return 0;
#endif
    }

    static std::string format_duration(double ns) {
        const double abs_ns = std::abs(ns);
        if (abs_ns >= 1e6) return std::to_string(ns / 1e6) + " ms";
        if (abs_ns >= 1e3) return std::to_string(ns / 1e3) + " µs";
        return std::to_string(ns) + " ns";
    }
};

int main(void) {
    // Measurement variables
    uint64_t start, end;
    bool is_detected;
    std::string vm_brand, vm_type;
    uint8_t vm_percent;

    // Benchmark VM::detect()
    start = Benchmark::get_timestamp();
    is_detected = VM::detect();
    end = Benchmark::get_timestamp();
    const double detect_time = Benchmark::get_elapsed(start, end);

    // Benchmark VM::brand()
    start = Benchmark::get_timestamp();
    vm_brand = VM::brand();
    end = Benchmark::get_timestamp();
    const double brand_time = Benchmark::get_elapsed(start, end);

    // Benchmark VM::type()
    start = Benchmark::get_timestamp();
    vm_type = VM::type();
    end = Benchmark::get_timestamp();
    const double type_time = Benchmark::get_elapsed(start, end);

    // Benchmark VM::percentage()
    start = Benchmark::get_timestamp();
    vm_percent = VM::percentage();
    end = Benchmark::get_timestamp();
    const double percent_time = Benchmark::get_elapsed(start, end);

    // Program output
    std::cout << (is_detected ? "Virtual machine detected!\n" : "Running on baremetal\n")
        << "VM name: " << vm_brand << "\n"
        << "VM type: " << vm_type << "\n"
        << "VM certainty: " << static_cast<int>(vm_percent) << "%\n\n"
        << "Benchmark Results:\n"
        << "VM::detect():    " << Benchmark::format_duration(detect_time) << "\n"
        << "VM::brand():     " << Benchmark::format_duration(brand_time) << "\n"
        << "VM::type():      " << Benchmark::format_duration(type_time) << "\n"
        << "VM::percentage(): " << Benchmark::format_duration(percent_time) << "\n";

    return 0;
}