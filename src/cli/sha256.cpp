#include "sha256.hpp"
#include "strings.hpp"

#include <vector>
#include <fstream>

#if (CLI_WINDOWS)
    #include <windows.h>
#elif (CLI_APPLE)
    #include <mach-o/dyld.h>
    #include <climits>
    #include <cstdlib>
#else
    #include <unistd.h>
    #include <climits>
    #include <cstdlib>
#endif

SHA256::SHA256() {
    s[0] = 0x6a09e667;
    s[1] = 0xbb67ae85;
    s[2] = 0x3c6ef372;
    s[3] = 0xa54ff53a;
    s[4] = 0x510e527f;
    s[5] = 0x9b05688c;
    s[6] = 0x1f83d9ab;
    s[7] = 0x5be0cd19;
}

u32 SHA256::rotr(u32 x, int n) {
    return (x >> n) | (x << (32 - n));
}

u32 SHA256::ch(u32 x, u32 y, u32 z) {
    return (x & y) ^ (~x & z);
}

u32 SHA256::maj(u32 x, u32 y, u32 z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

u32 SHA256::ep0(u32 x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

u32 SHA256::ep1(u32 x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

u32 SHA256::sig0(u32 x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

u32 SHA256::sig1(u32 x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

void SHA256::transform() {
    static const u32 k[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };

    u32 m[64]{};

    for (u32 i = 0, j = 0; i < 16; ++i, j += 4) {
        m[i] = (u32)buf[j] << 24 | (u32)buf[j + 1] << 16 | (u32)buf[j + 2] << 8 | (u32)buf[j + 3];
    }

    for (u32 i = 16; i < 64; ++i) {
        m[i] = sig1(m[i - 2]) + m[i - 7] + sig0(m[i - 15]) + m[i - 16];
    }

    u32 a = s[0];
    u32 b = s[1];
    u32 c = s[2];
    u32 d = s[3];
    u32 e = s[4];
    u32 f = s[5];
    u32 g = s[6];
    u32 h = s[7];

    for (u32 i = 0; i < 64; ++i) {
        u32 t1 = h + ep1(e) + ch(e, f, g) + k[i] + m[i];
        u32 t2 = ep0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    s[0] += a;
    s[1] += b;
    s[2] += c;
    s[3] += d;
    s[4] += e;
    s[5] += f;
    s[6] += g;
    s[7] += h;
}

void SHA256::update(const u8* data, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        buf[len++] = data[i];
        if (len == 64) {
            transform();
            bits += 512;
            len = 0;
        }
    }
}

void SHA256::final(u8 out[32]) {
    size_t i = len;
    if (len < 56) {
        buf[i++] = 0x80;
        while (i < 56) {
            buf[i++] = 0;
        }
    } else {
        buf[i++] = 0x80;
        while (i < 64) {
            buf[i++] = 0;
        }
        transform();
        for (size_t j = 0; j < 56; ++j) {
            buf[j] = 0;
        }
    }

    bits += (u64)len * 8;
    for (int j = 0; j < 8; ++j) {
        buf[63 - j] = (u8)((bits >> (8 * j)) & 0xFF);
    }

    transform();
    for (i = 0; i < 4; ++i) {
        for (size_t j = 0; j < 8; ++j) {
            out[i + (j * 4)] = (u8)((s[j] >> (24 - (i * 8))) & 0xFF);
        }
    }
}

std::string exe_path() {
#if (CLI_WINDOWS)
    std::vector<char> buf(32768);
    DWORD r = GetModuleFileNameA(NULL, buf.data(), (DWORD)buf.size());

    if (r == 0 || r >= buf.size()) {
        return {};
    }

    return std::string(buf.data(), r);
#elif (CLI_APPLE)
    uint32_t sz = 0;
    _NSGetExecutablePath(nullptr, &sz);
    std::vector<char> b(sz);

    if (_NSGetExecutablePath(b.data(), &sz) != 0) {
        return {};
    }

    std::vector<char> resolved(PATH_MAX);

    if (realpath(b.data(), resolved.data())) {
        return std::string(resolved.data());
    }

    return std::string(b.data());
#else
    std::vector<char> b(PATH_MAX);
    ssize_t l = ::readlink("/proc/self/exe", b.data(), b.size() - 1);

    if (l <= 0) {
        return {};
    }

    b[(size_t)l] = '\0';
    std::vector<char> resolved(PATH_MAX);

    if (realpath(b.data(), resolved.data())) {
        return resolved.data();
    }

    return b.data();
#endif
}

std::string compute_self_sha256() {
    std::string path = exe_path();
    if (path.empty()) {
        return {};
    }

    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) {
        return {};
    }

    SHA256 sha;

    std::vector<char> chunk(static_cast<size_t>(64 * 1024));
    while (ifs) {
        ifs.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
        std::streamsize r = ifs.gcount();
        if (r > 0) {
            sha.update(reinterpret_cast<const u8*>(chunk.data()), static_cast<size_t>(r));
        }
    }

    u8 digest[32];
    sha.final(digest);

    std::string out;
    out.reserve(64);

    static constexpr char hex[] = "0123456789abcdef";

    for (unsigned char i : digest) {
        out.push_back(hex[(i >> 4) & 0xF]);
        out.push_back(hex[i & 0xF]);
    }

    return out;
}
