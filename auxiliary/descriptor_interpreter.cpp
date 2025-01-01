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
 *  This program will utilize CPUID instructions to interpret
 *  processor features and other details to debug potential issues
 *  when doing virtual machine detections.
 *
 *
 * ===============================================================
 *
 *  - Made by: @Requiem (https://github.com/NotRequiem)
 *  - Repository: https://github.com/kernelwernel/VMAware
 *  - License: GPL 3.0
 */

#include <iostream>
#include <iomanip>
#include <array>
#include <bitset>
#include <vector>

#if defined(_MSC_VER)
#include <intrin.h> 
static void cpuid(int code, unsigned int& eax, unsigned int& ebx, unsigned int& ecx, unsigned int& edx) {
    int cpuInfo[4];
    __cpuid(cpuInfo, code);
    eax = cpuInfo[0];
    ebx = cpuInfo[1];
    ecx = cpuInfo[2];
    edx = cpuInfo[3];
}
#else
static void cpuid(int code, unsigned int& eax, unsigned int& ebx, unsigned int& ecx, unsigned int& edx) {
    __asm__ __volatile__(
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(code)
    );
}
#endif

inline static bool is_valid_register(unsigned int reg) {
    return (reg & 0x80000000) == 0;  // Check if MSB (bit 31) is 0 (valid information)
}

static void queryCacheDetails() {
    unsigned int eax = 4;  // CPUID leaf 4H
    unsigned int ecx = 0;  // Start with index 0
    unsigned int ebx, edx, ecx_out;
    unsigned int prev_ecx = -1;  // Initialize to an invalid value to ensure first iteration

    while (true) {
        cpuid(eax, ecx, ebx, ecx_out, edx);

        // Extract Cache Type (Bits 31:24 of EBX)
        unsigned int cacheType = (ebx >> 24) & 0xFF;

        if (cacheType == 0 || (ecx == prev_ecx)) {
            break;
        }

        // Extract ways, partitions, line size, and sets
        unsigned int ways = ((ebx >> 22) & 0x3FF);        // Number of ways (bits 31:22 of EBX)
        unsigned int partitions = ((ebx >> 12) & 0x3FF);  // Number of partitions (bits 21:12 of EBX)
        unsigned int lineSize = (ebx & 0xFFF);            // Line size (bits 11:0 of EBX)
        unsigned int sets = ecx_out;                      // Number of sets (ECX)

        // Cache size calculation formula
        unsigned int cacheSize = (ways + 1) * (partitions + 1) * (lineSize + 1) * (sets + 1);

        std::cout << "Cache Level " << ecx << ": ";
        std::cout << "Type = " << cacheType << ", ";
        std::cout << "Size = " << cacheSize << " bytes, ";
        std::cout << "Ways = " << ways + 1 << ", ";
        std::cout << "Partitions = " << partitions + 1 << ", ";
        std::cout << "Line Size = " << lineSize + 1 << " bytes, ";
        std::cout << "Sets = " << sets + 1 << "\n";

        prev_ecx = ecx;

        // get next cache level
        ecx++;
    }
}

static void getCMPSSOperations() {
    unsigned int eax = 0x18;  // CPUID leaf 18H
    unsigned int ecx = 0;     
    unsigned int ebx, edx, ecx_out;

    cpuid(eax, ecx, ebx, ecx_out, edx);

    // The returned value of EBX (and possibly ECX) should determine which CMPSS pseudo-op is in effect.
    unsigned int cmpOpCode = ebx & 0x7;  // Extract lower 3 bits to map to CMPSS pseudo-op

    switch (cmpOpCode) {
    case 0:
        std::cout << "Pseudo-Op: CMPEQSS xmm1, xmm2\n";
        break;
    case 1:
        std::cout << "Pseudo-Op: CMPLTSS xmm1, xmm2\n";
        break;
    case 2:
        std::cout << "Pseudo-Op: CMPLESS xmm1, xmm2\n";
        break;
    case 3:
        std::cout << "Pseudo-Op: CMPUNORDSS xmm1, xmm2\n";
        break;
    case 4:
        std::cout << "Pseudo-Op: CMPNEQSS xmm1, xmm2\n";
        break;
    case 5:
        std::cout << "Pseudo-Op: CMPNLTSS xmm1, xmm2\n";
        break;
    case 6:
        std::cout << "Pseudo-Op: CMPNLESS xmm1, xmm2\n";
        break;
    case 7:
        std::cout << "Pseudo-Op: CMPORDSS xmm1, xmm2\n";
        break;
    default:
        std::cout << "Unknown CMPSS operation\n";
        break;
    }
}

static void interpret_cpuid_descriptors(unsigned int eax, unsigned int ebx, unsigned int ecx, unsigned int edx) {
    std::array<unsigned int, 4> registers = { eax, ebx, ecx, edx };

    for (size_t i = 0; i < 4; i++) {
        unsigned int reg = registers[i];
        std::cout << "Register " << std::hex << std::setw(2) << std::setfill('0') << i << " (" << reg << "):\n";

        // Ignore the least significant byte (AL) of EAX (AL always contains 0x01, so we skip it)
        if (i == 0) {
            reg &= 0xFFFFFF00;  // Mask out the AL byte (least-significant byte of EAX)
        }

        // Check if the register contains valid information (MSB should be 0)
        if (is_valid_register(reg)) {
            // Parse each byte (descriptor) in the register
            for (int byte = 0; byte < 4; byte++) {
                unsigned int descriptor = (reg >> (8 * byte)) & 0xFF;

                // If descriptor is 0x01, ignore it (it's the least-significant byte in EAX)
                if (descriptor == 0x01) {
                    continue;
                }

                std::cout << "  Descriptor 0x" << std::hex << std::setw(2) << std::setfill('0') << descriptor << ": ";

                // https://www.felixcloutier.com/x86/cpuid#tbl-3-12
                switch (descriptor) {
                case 0x00:  std::cout << "General: Null descriptor, this byte contains no information.\n"; break;
                case 0x01:  std::cout << "TLB: Instruction TLB: 4 KByte pages, 4-way set associative, 32 entries.\n"; break;
                case 0x02:  std::cout << "TLB: Instruction TLB: 4 MByte pages, fully associative, 2 entries.\n"; break;
                case 0x03:  std::cout << "TLB: Data TLB: 4 KByte pages, 4-way set associative, 64 entries.\n"; break;
                case 0x04:  std::cout << "TLB: Data TLB: 4 MByte pages, 4-way set associative, 8 entries.\n"; break;
                case 0x05:  std::cout << "TLB: Data TLB1: 4 MByte pages, 4-way set associative, 32 entries.\n"; break;
                case 0x06:  std::cout << "Cache: 1st-level instruction cache: 8 KBytes, 4-way set associative, 32 byte line size.\n"; break;
                case 0x08:  std::cout << "Cache: 1st-level instruction cache: 16 KBytes, 4-way set associative, 32 byte line size.\n"; break;
                case 0x09:  std::cout << "Cache: 1st-level instruction cache: 32KBytes, 4-way set associative, 64 byte line size.\n"; break;
                case 0x0A:  std::cout << "Cache: 1st-level data cache: 8 KBytes, 2-way set associative, 32 byte line size.\n"; break;
                case 0x0B:  std::cout << "TLB: Instruction TLB: 4 MByte pages, 4-way set associative, 4 entries.\n"; break;
                case 0x0C:  std::cout << "Cache: 1st-level data cache: 16 KBytes, 4-way set associative, 32 byte line size.\n"; break;
                case 0x0D:  std::cout << "Cache: 1st-level data cache: 16 KBytes, 4-way set associative, 64 byte line size.\n"; break;
                case 0x0E:  std::cout << "Cache: 1st-level data cache: 24 KBytes, 6-way set associative, 64 byte line size.\n"; break;
                case 0x1D:  std::cout << "Cache: 2nd-level cache: 128 KBytes, 2-way set associative, 64 byte line size.\n"; break;
                case 0x21:  std::cout << "Cache: 2nd-level cache: 256 KBytes, 8-way set associative, 64 byte line size.\n"; break;
                case 0x22:  std::cout << "Cache: 3rd-level cache: 512 KBytes, 4-way set associative, 64 byte line size, 2 lines per sector.\n"; break;
                case 0x23:  std::cout << "Cache: 3rd-level cache: 1 MBytes, 8-way set associative, 64 byte line size, 2 lines per sector.\n"; break;
                case 0x24:  std::cout << "Cache: 2nd-level cache: 1 MBytes, 16-way set associative, 64 byte line size.\n"; break;
                case 0x25:  std::cout << "Cache: 3rd-level cache: 2 MBytes, 8-way set associative, 64 byte line size, 2 lines per sector.\n"; break;
                case 0x29:  std::cout << "Cache: 3rd-level cache: 4 MBytes, 8-way set associative, 64 byte line size, 2 lines per sector.\n"; break;
                case 0x2C:  std::cout << "Cache: 1st-level data cache: 32 KBytes, 8-way set associative, 64 byte line size.\n"; break;
                case 0x30:  std::cout << "Cache: 1st-level instruction cache: 32 KBytes, 8-way set associative, 64 byte line size.\n"; break;
                case 0x40:  std::cout << "Cache: No 2nd-level cache or, if processor contains a valid 2nd-level cache, no 3rd-level cache.\n"; break;
                case 0x41:  std::cout << "Cache: 2nd-level cache: 128 KBytes, 4-way set associative, 32 byte line size.\n"; break;
                case 0x42:  std::cout << "Cache: 2nd-level cache: 256 KBytes, 4-way set associative, 32 byte line size.\n"; break;
                case 0x43:  std::cout << "Cache: 2nd-level cache: 512 KBytes, 4-way set associative, 32 byte line size.\n"; break;
                case 0x44:  std::cout << "Cache: 2nd-level cache: 1 MByte, 4-way set associative, 32 byte line size.\n"; break;
                case 0x45:  std::cout << "Cache: 2nd-level cache: 2 MByte, 4-way set associative, 32 byte line size.\n"; break;
                case 0x46:  std::cout << "Cache: 3rd-level cache: 4 MByte, 4-way set associative, 64 byte line size.\n"; break;
                case 0x47:  std::cout << "Cache: 3rd-level cache: 8 MByte, 8-way set associative, 64 byte line size.\n"; break;
                case 0x48:  std::cout << "Cache: 2nd-level cache: 3MByte, 12-way set associative, 64 byte line size.\n"; break;
                case 0x49:  std::cout << "Cache: 3rd-level cache: 4MB, 16-way set associative, 64-byte line size (Intel Xeon processor MP, Family 0FH, Model 06H); 2nd-level cache: 4 MByte, 16-way set associative, 64 byte line size.\n"; break;
                case 0x4A:  std::cout << "Cache: 3rd-level cache: 6MByte, 12-way set associative, 64 byte line size.\n"; break;
                case 0x4B:  std::cout << "Cache: 3rd-level cache: 8MByte, 16-way set associative, 64 byte line size.\n"; break;
                case 0x4C:  std::cout << "Cache: 3rd-level cache: 12MByte, 12-way set associative, 64 byte line size.\n"; break;
                case 0x4D:  std::cout << "Cache: 3rd-level cache: 16MByte, 16-way set associative, 64 byte line size.\n"; break;
                case 0x4E:  std::cout << "Cache: 2nd-level cache: 6MByte, 24-way set associative, 64 byte line size.\n"; break;
                case 0x4F:  std::cout << "TLB: Instruction TLB: 4 KByte pages, 32 entries.\n"; break;
                case 0x50:  std::cout << "TLB: Instruction TLB: 4 KByte and 2-MByte or 4-MByte pages, 64 entries.\n"; break;
                case 0x51:  std::cout << "TLB: Instruction TLB: 4 KByte and 2-MByte or 4-MByte pages, 128 entries.\n"; break;
                case 0x52:  std::cout << "TLB: Instruction TLB: 4 KByte and 2-MByte or 4-MByte pages, 256 entries.\n"; break;
                case 0x55:  std::cout << "TLB: Instruction TLB: 2-MByte or 4-MByte pages, fully associative, 7 entries.\n"; break;
                case 0x56:  std::cout << "TLB: Data TLB0: 4 MByte pages, 4-way set associative, 16 entries.\n"; break;
                case 0x57:  std::cout << "TLB: Data TLB0: 4 KByte pages, 4-way associative, 16 entries.\n"; break;
                case 0x59:  std::cout << "TLB: Data TLB0: 4 KByte pages, fully associative, 16 entries.\n"; break;
                case 0x5A:  std::cout << "TLB: Data TLB0: 2 MByte or 4 MByte pages, 4-way set associative, 32 entries.\n"; break;
                case 0x5B:  std::cout << "TLB: Data TLB: 4 KByte and 4 MByte pages, 64 entries.\n"; break;
                case 0x5C:  std::cout << "TLB: Data TLB: 4 KByte and 4 MByte pages,128 entries.\n"; break;
                case 0x5D:  std::cout << "TLB: Data TLB: 4 KByte and 4 MByte pages,256 entries.\n"; break;
                case 0x60:  std::cout << "Cache: 1st-level data cache: 16 KByte, 8-way set associative, 64 byte line size.\n"; break;
                case 0x61:  std::cout << "TLB: Instruction TLB: 4 KByte pages, fully associative, 48 entries.\n"; break;
                case 0x63:  std::cout << "TLB: Data TLB: 2 MByte or 4 MByte pages, 4-way set associative, 32 entries and a separate array with 1 GByte pages, 4-way set associative, 4 entries.\n"; break;
                case 0x64:  std::cout << "TLB: Data TLB: 4 KByte pages, 4-way set associative, 512 entries.\n"; break;
                case 0x66:  std::cout << "Cache: 1st-level data cache: 8 KByte, 4-way set associative, 64 byte line size.\n"; break;
                case 0x67:  std::cout << "Cache: 1st-level data cache: 16 KByte, 4-way set associative, 64 byte line size.\n"; break;
                case 0x68:  std::cout << "Cache: 1st-level data cache: 32 KByte, 4-way set associative, 64 byte line size.\n"; break;
                case 0x6A:  std::cout << "Cache: uTLB: 4 KByte pages, 8-way set associative, 64 entries.\n"; break;
                case 0x6B:  std::cout << "Cache: DTLB: 4 KByte pages, 8-way set associative, 256 entries.\n"; break;
                case 0x6C:  std::cout << "Cache: DTLB: 2M/4M pages, 8-way set associative, 128 entries.\n"; break;
                case 0x6D:  std::cout << "Cache: DTLB: 1 GByte pages, fully associative, 16 entries.\n"; break;
                case 0x70:  std::cout << "Cache: Trace cache: 12 K-μop, 8-way set associative.\n"; break;
                case 0x71:  std::cout << "Cache: Trace cache: 16 K-μop, 8-way set associative.\n"; break;
                case 0x72:  std::cout << "Cache: Trace cache: 32 K-μop, 8-way set associative.\n"; break;
                case 0x76:  std::cout << "TLB: Instruction TLB: 2M/4M pages, fully associative, 8 entries.\n"; break;
                case 0x78:  std::cout << "Cache: 2nd-level cache: 1 MByte, 4-way set associative, 64 byte line size.\n"; break;
                case 0x79:  std::cout << "Cache: 2nd-level cache: 128 KByte, 8-way set associative, 64 byte line size, 2 lines per sector.\n"; break;
                case 0x7A:  std::cout << "Cache: 2nd-level cache: 256 KByte, 8-way set associative, 64 byte line size, 2 lines per sector.\n"; break;
                case 0x7B:  std::cout << "Cache: 2nd-level cache: 512 KByte, 8-way set associative, 64 byte line size, 2 lines per sector.\n"; break;
                case 0x7C:  std::cout << "Cache: 2nd-level cache: 1 MByte, 8-way set associative, 64 byte line size, 2 lines per sector.\n"; break;
                case 0x7D:  std::cout << "Cache: 2nd-level cache: 2 MByte, 8-way set associative, 64 byte line size.\n"; break;
                case 0x7F:  std::cout << "Cache: 2nd-level cache: 512 KByte, 2-way set associative, 64-byte line size.\n"; break;
                case 0x80:  std::cout << "Cache: 2nd-level cache: 512 KByte, 8-way set associative, 64-byte line size.\n"; break;
                case 0x82:  std::cout << "Cache: 2nd-level cache: 256 KByte, 8-way set associative, 32 byte line size.\n"; break;
                case 0x83:  std::cout << "Cache: 2nd-level cache: 512 KByte, 8-way set associative, 32 byte line size.\n"; break;
                case 0x84:  std::cout << "Cache: 2nd-level cache: 1 MByte, 8-way set associative, 32 byte line size.\n"; break;
                case 0x85:  std::cout << "Cache: 2nd-level cache: 2 MByte, 8-way set associative, 32 byte line size.\n"; break;
                case 0x86:  std::cout << "Cache: 2nd-level cache: 512 KByte, 4-way set associative, 64 byte line size.\n"; break;
                case 0x87:  std::cout << "Cache: 2nd-level cache: 1 MByte, 8-way set associative, 64 byte line size.\n"; break;
                case 0xA0:  std::cout << "DTLB: 4k pages, fully associative, 32 entries.\n"; break;
                case 0xB0:  std::cout << "Instruction TLB: 4 KByte pages, 4-way set associative, 128 entries.\n"; break;
                case 0xB1:  std::cout << "Instruction TLB: 2M pages, 4-way, 8 entries or 4M pages, 4-way, 4 entries.\n"; break;
                case 0xB2:  std::cout << "Instruction TLB: 4KByte pages, 4-way set associative, 64 entries.\n"; break;
                case 0xB3:  std::cout << "Data TLB: 4 KByte pages, 4-way set associative, 128 entries.\n"; break;
                case 0xB4:  std::cout << "Data TLB1: 4 KByte pages, 4-way associative, 256 entries.\n"; break;
                case 0xB5:  std::cout << "Instruction TLB: 4KByte pages, 8-way set associative, 64 entries.\n"; break;
                case 0xB6:  std::cout << "Instruction TLB: 4KByte pages, 8-way set associative, 128 entries.\n"; break;
                case 0xBA:  std::cout << "Data TLB1: 4 KByte pages, 4-way associative, 64 entries.\n"; break;
                case 0xC0:  std::cout << "Data TLB: 4 KByte and 4 MByte pages, 4-way associative, 8 entries.\n"; break;
                case 0xC1:  std::cout << "Shared 2nd-Level TLB: 4 KByte/2MByte pages, 8-way associative, 1024 entries.\n"; break;
                case 0xC2:  std::cout << "DTLB: 4 KByte/2 MByte pages, 4-way associative, 16 entries.\n"; break;
                case 0xC3:  std::cout << "Shared 2nd-Level TLB: 4 KByte /2 MByte pages, 6-way associative, 1536 entries. Also 1GBbyte pages, 4-way, 16 entries.\n"; break;
                case 0xC4:  std::cout << "DTLB: 2M/4M Byte pages, 4-way associative, 32 entries.\n"; break;
                case 0xCA:  std::cout << "Shared 2nd-Level TLB: 4 KByte pages, 4-way associative, 512 entries.\n"; break;
                case 0xD0:  std::cout << "3rd-level cache: 512 KByte, 4-way set associative, 64 byte line size.\n"; break;
                case 0xD1:  std::cout << "3rd-level cache: 1 MByte, 4-way set associative, 64 byte line size.\n"; break;
                case 0xD2:  std::cout << "3rd-level cache: 2 MByte, 4-way set associative, 64 byte line size.\n"; break;
                case 0xD6:  std::cout << "3rd-level cache: 1 MByte, 8-way set associative, 64 byte line size.\n"; break;
                case 0xD7:  std::cout << "3rd-level cache: 2 MByte, 8-way set associative, 64 byte line size.\n"; break;
                case 0xD8:  std::cout << "3rd-level cache: 4 MByte, 8-way set associative, 64 byte line size.\n"; break;
                case 0xDC:  std::cout << "3rd-level cache: 1.5 MByte, 12-way set associative, 64 byte line size.\n"; break;
                case 0xDD:  std::cout << "3rd-level cache: 3 MByte, 12-way set associative, 64 byte line size.\n"; break;
                case 0xDE:  std::cout << "3rd-level cache: 6 MByte, 12-way set associative, 64 byte line size.\n"; break;
                case 0xE2:  std::cout << "3rd-level cache: 2 MByte, 16-way set associative, 64 byte line size.\n"; break;
                case 0xE3:  std::cout << "3rd-level cache: 4 MByte, 16-way set associative, 64 byte line size.\n"; break;
                case 0xE4:  std::cout << "3rd-level cache: 8 MByte, 16-way set associative, 64 byte line size.\n"; break;
                case 0xEA:  std::cout << "3rd-level cache: 12MByte, 24-way set associative, 64 byte line size.\n"; break;
                case 0xEB:  std::cout << "3rd-level cache: 18MByte, 24-way set associative, 64 byte line size.\n"; break;
                case 0xEC:  std::cout << "3rd-level cache: 24MByte, 24-way set associative, 64 byte line size.\n"; break;
                case 0xF0:  std::cout << "64-Byte prefetching.\n"; break;
                case 0xF1:  std::cout << "128-Byte prefetching.\n"; break;
                case 0xFE:  getCMPSSOperations(); break;
                case 0xFF:  queryCacheDetails(); break;
                default:    std::cout << "Unknown descriptor.\n"; break;
                }
            }
        }
        else {
            std::cout << "  Invalid descriptor data.\n";
        }
    }
}

static bool is_intel() {
    constexpr std::uint32_t intel_ecx1 = 0x6c65746e; // "ntel"
    constexpr std::uint32_t intel_ecx2 = 0x6c65746f; // "otel", this is because some Intel CPUs have a rare manufacturer string of "GenuineIotel"

    std::uint32_t unused, ecx = 0;
    cpuid(0, unused, unused, ecx, unused);

    return ((ecx == intel_ecx1) || (ecx == intel_ecx2));
}

int main() {
    if (!is_intel()) {
        std::cout << "Intel CPU not detected.\n";
        system("pause");
        return 1;
    }

    unsigned int eax, ebx, ecx, edx;

    // Cache/Prefetch/TLB Information
    cpuid(0x02, eax, ebx, ecx, edx);

    std::cout << "CPUID query result:" << std::endl;
    std::cout << "EAX: " << std::hex << eax << std::endl;
    std::cout << "EBX: " << std::hex << ebx << std::endl;
    std::cout << "ECX: " << std::hex << ecx << std::endl;
    std::cout << "EDX: " << std::hex << edx << std::endl;

    std::cout << "\nInterpreted Cache and TLB Descriptors:" << std::endl;
    interpret_cpuid_descriptors(eax, ebx, ecx, edx);

    system("pause");
    return 0;
}
