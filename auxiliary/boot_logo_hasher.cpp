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
    auto size = in.tellg();
    in.seekg(0);
    std::vector<uint8_t> buf(size);
    in.read(reinterpret_cast<char*>(buf.data()), size);

    // BMP offset at bytes 10–13
    uint32_t offset = *reinterpret_cast<uint32_t*>(buf.data() + 10);
    uint8_t* bmp = buf.data() + offset;
    size_t len = buf.size() - offset;

    uint64_t crcReg = 0xFFFFFFFFull;
    size_t qwords = len / 8;
    auto ptr = reinterpret_cast<uint64_t*>(bmp);
    for (size_t i = 0; i < qwords; ++i)
        crcReg = _mm_crc32_u64(crcReg, ptr[i]);

    uint32_t crc = static_cast<uint32_t>(crcReg);
    auto tail = reinterpret_cast<uint8_t*>(ptr + qwords);
    for (size_t i = 0, r = len & 7; i < r; ++i)
        crc = _mm_crc32_u8(crc, tail[i]);

    return crc ^ 0xFFFFFFFFu;
}

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        uint32_t h = crc32c_bmp(argv[i]);
        std::cout << argv[i] << ": 0x" << std::hex << std::uppercase << h << "\n";
    }
}
