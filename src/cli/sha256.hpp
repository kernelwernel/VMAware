#pragma once

#include <cstddef>
#include <string>
#include "types.hpp"

struct SHA256 {
    u8 buf[64] = {};
    u32 len = 0;
    u64 bits = 0;
    u32 s[8] = {};

    SHA256();

    static u32 rotr(const u32 x, const u32 n);
    static u32 ch(const u32 x, const u32 y, const u32 z);
    static u32 maj(const u32 x, const u32 y, const u32 z);
    static u32 ep0(const u32 x);
    static u32 ep1(const u32 x);
    static u32 sig0(const u32 x);
    static u32 sig1(const u32 x);

    void transform();

    void update(const u8* data, const size_t n);

    void final(u8 out[32]);
};

std::string exe_path();
std::string compute_self_sha256();
