#pragma once
// 标志位与运算辅助（方案书：标志位惰性/按需计算，交给 Clang DCE）
#include <cstdint>
#include "x64_runtime.h"

static inline void set_zsp(X64Ctx* c, uint64_t r, int width) {
    uint64_t mask = width >= 8 ? ~0ULL : ((1ULL << (width * 8)) - 1);
    r &= mask;
    c->zf = (r == 0);
    c->sf = ((r >> (width * 8 - 1)) & 1) != 0;
}

static inline uint64_t add_flags(X64Ctx* c, uint64_t a, uint64_t b, int width) {
    uint64_t mask = width >= 8 ? ~0ULL : ((1ULL << (width * 8)) - 1);
    uint64_t r = (a + b) & mask;
    set_zsp(c, r, width);
    c->cf = ((a & mask) + (b & mask)) > mask;
    uint64_t signbit = 1ULL << (width * 8 - 1);
    c->of = (((a ^ r) & (b ^ r)) & signbit) != 0;
    return r;
}

static inline uint64_t sub_flags(X64Ctx* c, uint64_t a, uint64_t b, int width) {
    uint64_t mask = width >= 8 ? ~0ULL : ((1ULL << (width * 8)) - 1);
    uint64_t r = (a - b) & mask;
    set_zsp(c, r, width);
    c->cf = (a & mask) < (b & mask);
    uint64_t signbit = 1ULL << (width * 8 - 1);
    c->of = (((a ^ b) & (a ^ r)) & signbit) != 0;
    return r;
}

static inline uint64_t logic_flags(X64Ctx* c, uint64_t r, int width) {
    c->cf = false;
    c->of = false;
    set_zsp(c, r, width);
    return r;
}

// 写寄存器：32 位写清零高 32 位；8/16 位写保留高位（方案书硬性要求）
static inline void write_reg(X64Ctx* c, int regid, uint64_t v, int width) {
    uint64_t* preg = nullptr;
    switch (regid) {
        case 0: preg = &c->rax; break;
        case 1: preg = &c->rcx; break;
        case 2: preg = &c->rdx; break;
        case 3: preg = &c->rbx; break;
        case 4: preg = &c->rsp; break;
        case 5: preg = &c->rbp; break;
        case 6: preg = &c->rsi; break;
        case 7: preg = &c->rdi; break;
        case 8: preg = &c->r8; break;
        case 9: preg = &c->r9; break;
        case 10: preg = &c->r10; break;
        case 11: preg = &c->r11; break;
        case 12: preg = &c->r12; break;
        case 13: preg = &c->r13; break;
        case 14: preg = &c->r14; break;
        case 15: preg = &c->r15; break;
        default: return;
    }
    if (width >= 8) {
        *preg = v;
    } else if (width == 4) {
        *preg = (uint32_t)v;
    } else {
        uint64_t mask = (1ULL << (width * 8)) - 1;
        *preg = (*preg & ~mask) | (v & mask);
    }
}

static inline uint64_t read_reg(X64Ctx* c, int regid, int width) {
    uint64_t v = 0;
    switch (regid) {
        case 0: v = c->rax; break;
        case 1: v = c->rcx; break;
        case 2: v = c->rdx; break;
        case 3: v = c->rbx; break;
        case 4: v = c->rsp; break;
        case 5: v = c->rbp; break;
        case 6: v = c->rsi; break;
        case 7: v = c->rdi; break;
        case 8: v = c->r8; break;
        case 9: v = c->r9; break;
        case 10: v = c->r10; break;
        case 11: v = c->r11; break;
        case 12: v = c->r12; break;
        case 13: v = c->r13; break;
        case 14: v = c->r14; break;
        case 15: v = c->r15; break;
        default: return 0;
    }
    if (width < 8) {
        uint64_t mask = (1ULL << (width * 8)) - 1;
        v &= mask;
    }
    return v;
}
