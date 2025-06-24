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

#include <immintrin.h>
#include <fstream>
#include <vector>
#include <iostream>
#include <cstdint>

static inline uint32_t crc32c_bmp(const char* filename) {
    std::ifstream in{ filename, std::ios::binary | std::ios::ate };
    if (!in) return 0;
    auto size = in.tellg();
    in.seekg(0, std::ios::beg);

    std::vector<uint8_t> buf(static_cast<size_t>(size));
    in.read(reinterpret_cast<char*>(buf.data()), size);

    // offset in BMP header (bytes 10–13)
    uint32_t offset = *reinterpret_cast<uint32_t*>(buf.data() + 10);
    uint8_t* bmp = buf.data() + offset;
    size_t  len = buf.size() - offset;

#if defined(_M_X64) || defined(__x86_64__)
    uint64_t crc64 = 0xFFFFFFFFull;
    auto     q64 = len / 8;
    auto const* p64 = reinterpret_cast<uint64_t const*>(bmp);
    for (size_t i = 0; i < q64; ++i)
        crc64 = _mm_crc32_u64(crc64, p64[i]);

    uint32_t crc = static_cast<uint32_t>(crc64);
    auto const* tail = reinterpret_cast<uint8_t const*>(p64 + q64);
    for (size_t i = 0, r = len & 7; i < r; ++i)
        crc = _mm_crc32_u8(crc, tail[i]);
#else
    uint32_t crc = 0xFFFFFFFFu;
    auto     q32 = len / 4;
    auto const* p32 = reinterpret_cast<uint32_t const*>(bmp);
    for (size_t i = 0; i < q32; ++i)
        crc = _mm_crc32_u32(crc, p32[i]);

    auto const* tail = reinterpret_cast<uint8_t const*>(p32 + q32);
    for (size_t i = 0, r = len & 3; i < r; ++i)
        crc = _mm_crc32_u8(crc, tail[i]);
#endif

    return crc ^ 0xFFFFFFFFu;
}

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        uint32_t h = crc32c_bmp(argv[i]);
        std::cout << argv[i]
            << ": 0x" << std::hex << std::uppercase << h
            << std::dec << "\n";
    }
    return 0;
}
