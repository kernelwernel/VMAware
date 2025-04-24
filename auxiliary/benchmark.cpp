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
 *  VMAwareBenchmark Utility: Measures performance of VM detection primitives
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

const std::string bold = "\033[1m";
const std::string ansi_exit = "\x1B[0m";
const std::string red = "\x1B[38;2;239;75;75m"; 
const std::string green = "\x1B[38;2;94;214;114m";
const std::string orange = "\x1B[38;2;255;180;5m";

class VMAwareBenchmark {
public:
    static inline uint64_t get_timestamp() {
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

    static inline double get_elapsed(uint64_t start, uint64_t end) {
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
        if (abs_ns >= 1e6) return bold + red + std::to_string(ns / 1e6) + " ms" + ansi_exit;
        if (abs_ns >= 1e3) return orange + std::to_string(ns / 1e3) + " µs" + ansi_exit;
        return green + std::to_string(ns) + " ns" + ansi_exit;
    }
};

static void enable_ansi_on_windows() {
#if defined(_WIN32)
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return;

    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode)) return;

    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;
    SetConsoleMode(hOut, dwMode);
#endif
}

int main(void) {
    enable_ansi_on_windows();

    // Measurement variables
    uint64_t start, end;
    bool is_detected;
    std::string vm_brand, vm_type;
    uint8_t vm_percent;

    /* ================================================ NO MEMOIZATION CATEGORY ================================================ */

    // VMAwareBenchmark VM::detect(VM::NO_MEMO)
    start = VMAwareBenchmark::get_timestamp();
    is_detected = VM::detect(VM::NO_MEMO);
    end = VMAwareBenchmark::get_timestamp();
    const double detect_time_no_memo = VMAwareBenchmark::get_elapsed(start, end);

    // VMAwareBenchmark VM::brand()
    start = VMAwareBenchmark::get_timestamp();
    vm_brand = VM::brand(VM::NO_MEMO);
    end = VMAwareBenchmark::get_timestamp();
    const double brand_time_no_memo = VMAwareBenchmark::get_elapsed(start, end);

    // VMAwareBenchmark VM::type()
    start = VMAwareBenchmark::get_timestamp();
    vm_type = VM::type(VM::NO_MEMO);
    end = VMAwareBenchmark::get_timestamp();
    const double type_time_no_memo = VMAwareBenchmark::get_elapsed(start, end);

    // VMAwareBenchmark VM::percentage()
    start = VMAwareBenchmark::get_timestamp();
    vm_percent = VM::percentage(VM::NO_MEMO);
    end = VMAwareBenchmark::get_timestamp();
    const double percent_time_no_memo = VMAwareBenchmark::get_elapsed(start, end);

    /* ================================================ DEFAULT CATEGORY ================================================ */

    // VMAwareBenchmark VM::detect()
    start = VMAwareBenchmark::get_timestamp();
    is_detected = VM::detect();
    end = VMAwareBenchmark::get_timestamp();
    const double detect_time = VMAwareBenchmark::get_elapsed(start, end);

    // VMAwareBenchmark VM::brand()
    start = VMAwareBenchmark::get_timestamp();
    vm_brand = VM::brand();
    end = VMAwareBenchmark::get_timestamp();
    const double brand_time = VMAwareBenchmark::get_elapsed(start, end);

    // VMAwareBenchmark VM::type()
    start = VMAwareBenchmark::get_timestamp();
    vm_type = VM::type();
    end = VMAwareBenchmark::get_timestamp();
    const double type_time = VMAwareBenchmark::get_elapsed(start, end);

    // VMAwareBenchmark VM::percentage()
    start = VMAwareBenchmark::get_timestamp();
    vm_percent = VM::percentage();
    end = VMAwareBenchmark::get_timestamp();
    const double percent_time = VMAwareBenchmark::get_elapsed(start, end);

    // Program output
    std::cout << (is_detected ? "Virtual machine detected!\n" : "Running on baremetal\n")
        << "VM name: " << vm_brand << "\n"
        << "VM type: " << vm_type << "\n"
        << "VM certainty: " << static_cast<int>(vm_percent) << "%\n\n"
        << "Benchmark Results (Default):\n"
        << "VM::detect():    " << VMAwareBenchmark::format_duration(detect_time) << "\n"
        << "VM::brand():     " << VMAwareBenchmark::format_duration(brand_time) << "\n"
        << "VM::type():      " << VMAwareBenchmark::format_duration(type_time) << "\n"
        << "VM::percentage(): " << VMAwareBenchmark::format_duration(percent_time) << "\n\n"
        << "Benchmark Results (not cached):\n"
        << "VM::detect(VM::NO_MEMO):    " << VMAwareBenchmark::format_duration(detect_time_no_memo) << "\n"
        << "VM::brand(VM::NO_MEMO):     " << VMAwareBenchmark::format_duration(brand_time_no_memo) << "\n"
        << "VM::type(VM::NO_MEMO):      " << VMAwareBenchmark::format_duration(type_time_no_memo) << "\n"
        << "VM::percentage(VM::NO_MEMO): " << VMAwareBenchmark::format_duration(percent_time_no_memo) << "\n\n";

    for (const VM::enum_flags technique_enum : VM::technique_vector) {
        start = VMAwareBenchmark::get_timestamp();

        const bool result = VM::check(technique_enum, VM::NO_MEMO);

        end = VMAwareBenchmark::get_timestamp();
        const double technique_time = VMAwareBenchmark::get_elapsed(start, end);
    
        std::cout << 
            "VM::" << 
            VM::flag_to_string(technique_enum) << 
            ": " << 
            VMAwareBenchmark::format_duration(technique_time) << 
            "\n";
    }

    std::cout << "\n";

    return 0;
}
