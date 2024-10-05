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
 *  This program serves as an internal tool for fuzzing cpuid values 
 *  and comparing them between baremetal outputs and VM outputs.
 * 
 * ===============================================================
 * 
 *  - Made by: @kernelwernel (https://github.com/kernelwernel)
 *  - Repository: https://github.com/kernelwernel/VMAware
 *  - License: GPL 3.0
 */ 


#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdatomic.h>
#include <string.h>
#include <stdlib.h>

#if (defined(_MSC_VER) || defined(_WIN32) || defined(_WIN64) || defined(__MINGW32__))
    #define MSVC 1
    #define LINUX 0
#elif (defined(__GNUC__) || defined(__linux__))
    #define MSVC 0
    #define LINUX 1
#else
    #error "Unknown OS, aborting"
#endif

#if (LINUX)
    #include <cpuid.h>
    #include <sched.h>
    #include <pthread.h>
    #include <unistd.h>
    #include <sys/sysinfo.h>
#else 
    #include <intrin.h>
#endif

// branching macros
#define unlikely(x) __builtin_expect(!!(x), 0)
#define likely(x)   __builtin_expect(!!(x), 1)

// cpu brand shit for ecx idfk
#define intel_ecx 0x6c65746e
#define amd_ecx 0x69746e65

// cpuid leaf values
#define manufacturer 0x00000000
#define proc_info 0x00000001
#define cache_tlb 0x00000002
#define serial 0x00000003
#define topology 0x00000004
#define topology2 0x0000000B
#define management 0x00000006
#define extended 0x00000007 // ecx = 0
#define extended2 0x00000007 // ecx = 1
#define extended3 0x00000007 // ecx = 2
#define xsave 0x0000000D
#define xsave2 0x0000000D // ecx = >2
#define xsave3 0x0000000D // ecx = 0
#define xsave4 0x0000000D // ecx = 1
#define sgx 0x00000012 // ecx = 0
#define sgx2 0x00000012 // ecx = 1
#define sgx3 0x00000012 // ecx = >2
#define proc_trace 0x00000014 // ecx = 0
#define aes 0x00000019
#define avx10 0x00000024 // ecx = 0
#define vm0 0x40000000
#define vm1 0x40000001
#define vm2 0x40000002
#define vm3 0x40000003
#define extended_proc_info 0x80000001
#define hypervisor 0x40000000
#define max_leaf 0x80000000
#define brand1 0x80000002
#define brand2 0x80000003
#define brand3 0x80000004
#define L1_cache 0x80000005
#define L2_cache 0x80000006
#define capabilities 0x80000007
#define virtual 0x80000008
#define svm 0x8000000A
#define enc_mem_cap 0x8000001F
#define ext_info2 0x80000021
#define amd_easter_egg 0x8fffffff
#define centaur_ext 0xC0000000
#define centaur_feature 0xC0000001

// index macros
#define eax 0
#define ebx 1
#define ecx 2
#define edx 3 

// cli flags
#define leaf_mode 1
#define scan_mode 2

// miscellaneous
#define null_leaf 0xFF
#define breakpoint 10000000


// basic cpuid wrapper
static void cpuid
(
    uint32_t *x,
    const uint64_t leaf,
    const uint64_t subleaf
) {
    #if (MSVC)
        __cpuidex((int32_t*)x, (int32_t)(leaf), (int32_t)(subleaf));
    #elif (LINUX)
        __cpuid_count(leaf, subleaf, x[0], x[1], x[2], x[3]);
    #endif
};

// get highest eax leaf 
static uint32_t get_highest_leaf() {
    uint32_t reg[4];
    cpuid(reg, max_leaf, null_leaf);
    return (reg[eax]);
}

// scan for predetermined leafs
void leaf_mode_fuzzer(const uint64_t p_max_leaf) {
    uint32_t reg[4];
    const uint32_t leafs[40] = { 
        manufacturer, proc_info, cache_tlb, 
        serial, topology, topology2, 
        management, extended, extended2, 
        extended3, xsave, xsave2 , 
        xsave3, xsave4, sgx, 
        sgx2, sgx3 , proc_trace, 
        aes, avx10, extended_proc_info, 
        hypervisor, max_leaf, brand1, 
        brand2, brand3, L1_cache, 
        L2_cache, capabilities, virtual, 
        svm, enc_mem_cap, ext_info2, 
        amd_easter_egg, centaur_ext, centaur_feature,
        vm0, vm1, vm2, vm3
    };

    const size_t leaf_arr_size = (sizeof(leafs) / sizeof(leafs[0]));    

    for (int i = 0; i < leaf_arr_size; i++) {
        if (leafs[i] >= p_max_leaf) {
            continue;
        }

        cpuid(reg, leafs[i], null_leaf);

        if (likely(
            reg[eax] || \
            reg[ebx] || \
            reg[ecx] || \
            reg[edx]
        )) {
            printf("leaf = %d\n", i);
            printf("eax = 0x%0X\n", reg[eax]);
            printf("ebx = 0x%0X\n", reg[ebx]);
            printf("ecx = 0x%0X\n", reg[ecx]);
            printf("edx = 0x%0X\n\n", reg[edx]);
        }
    }
}


int main(int argc, char *argv[]) {
    uint8_t flags = 0;

    if (argc == 1) {
        flags |= leaf_mode;
    } else if (argc == 2) {
        if (strcmp(argv[2], "--leaf") == 0) {
            flags |= leaf_mode;
        } else {
            printf("%s", "Unknown flag provided, aborting\n");
            return 1;
        }
    } else {
        printf("%s", "Too many flags provided, only use either --leaf or --scan\n");
        return 1;
    }

    const uint64_t high_leaf = get_highest_leaf();
    printf("highest leaf = 0x%0lX\n", high_leaf);

    if (flags & leaf_mode) {
        leaf_mode_fuzzer(high_leaf);
    } else if (flags & scan_mode) {
        //scan_mode_fuzzer(high_leaf);
    } else {
        return 1;
    }

    return 0;
}