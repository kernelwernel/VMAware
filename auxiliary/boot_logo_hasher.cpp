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
 *  This program computes a CRC32 checksum of boot logo images
 *  via hardware‐accelerated intrinsics in 8-byte chunks.
 *
 * ===============================================================
 *
 *  - Made by: @Requiem (https://github.com/NotRequiem)
 *  - Repository: https://github.com/kernelwernel/VMAware
 *  - License: MIT
 */

#include <fstream>
#include <vector>
#include <iostream>
#include <cstdint>

#if defined(_MSC_VER)
#include <intrin.h>     
#else
#include <nmmintrin.h>  
#endif

static inline uint32_t crc32c_file(const char* filename) {
    std::ifstream in{ filename, std::ios::binary | std::ios::ate };
    if (!in.is_open()) {
        std::cerr << "Error: cannot open file " << filename << "\n";
        return 0;
    }

    auto size = in.tellg();
    in.seekg(0, std::ios::beg);

    std::vector<uint8_t> buf(static_cast<size_t>(size));
    if (!in.read(reinterpret_cast<char*>(buf.data()), size)) {
        std::cerr << "Error: failed to read file\n";
        return 0;
    }

    // CRC32‑C (Castagnoli) over the entire file buffer
    uint32_t crc = 0xFFFFFFFFu;

#if defined(_M_X64) || defined(__x86_64__)
    // 8‑byte chunks
    size_t       q64 = buf.size() / 8;
    auto const* p64 = reinterpret_cast<uint64_t const*>(buf.data());
    for (size_t i = 0; i < q64; ++i) {
        crc = static_cast<uint32_t>(_mm_crc32_u64(crc, p64[i]));
    }
    // tail
    auto const* tail8 = reinterpret_cast<uint8_t const*>(p64 + q64);
    for (size_t i = 0, r = buf.size() & 7; i < r; ++i) {
        crc = _mm_crc32_u8(crc, tail8[i]);
    }
#else
    // 4‑byte chunks
    size_t       q32 = buf.size() / 4;
    auto const* p32 = reinterpret_cast<uint32_t const*>(buf.data());
    for (size_t i = 0; i < q32; ++i) {
        crc = _mm_crc32_u32(crc, p32[i]);
    }
    // tail
    auto const* tail4 = reinterpret_cast<uint8_t const*>(p32 + q32);
    for (size_t i = 0, r = buf.size() & 3; i < r; ++i) {
        crc = _mm_crc32_u8(crc, tail4[i]);
    }
#endif

    return crc ^ 0xFFFFFFFFu;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <bmp-file> [...]\n";
        return 1;
    }
    for (int i = 1; i < argc; ++i) {
        uint32_t h = crc32c_file(argv[i]);
        std::cout
            << argv[i]
            << ": 0x"
            << std::hex << std::uppercase << h
            << std::dec << "\n";
    }
    return 0;
}
