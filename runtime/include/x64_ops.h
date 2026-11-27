#pragma once
// 标志位与运算辅助（方案书：标志位惰性/按需计算，交给 Clang DCE）
#include <cstdint>
#include "x64_runtime.h"

static inline void set_zsp(X64Ctx* c, uint64_t r, int width) {
    uint64_t mask = width >= 8 ? ~0ULL : ((1ULL << (width * 8)) - 1);
    r &= mask;
    c->zf = (r == 0);
    c->pf = (__builtin_parity((unsigned)(r & 0xFF)) == 0);  // PF：低字节偶数个 1
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

static inline uint64_t sbb_flags(X64Ctx* c, uint64_t a, uint64_t b, int width) {
    uint64_t mask = width >= 8 ? ~0ULL : ((1ULL << (width * 8)) - 1);
    uint64_t borrow = c->cf ? 1ULL : 0ULL;
    uint64_t sub = (b + borrow) & mask;
    uint64_t r = (a - sub) & mask;
    set_zsp(c, r, width);
    c->cf = (a & mask) < sub;
    uint64_t signbit = 1ULL << (width * 8 - 1);
    c->of = (((a ^ b) & (a ^ r)) & signbit) != 0;
    return r;
}

// ADC：a + b + CF。以前 lifter 里没有 adc 分支，直接整函数占位
// （artifact stub_list：19 个函数只缺 adc）。CF 用「加 carry-in 后的和是否越界」判，
// 与 sbb_flags 用 (b+borrow) 的口径一致，保证 CF 链在 add/adc 之间可传递。
static inline uint64_t adc_flags(X64Ctx* c, uint64_t a, uint64_t b, int width) {
    uint64_t mask = width >= 8 ? ~0ULL : ((1ULL << (width * 8)) - 1);
    uint64_t carry = c->cf ? 1ULL : 0ULL;
    uint64_t r0 = (a & mask) + (b & mask);
    uint64_t r = (r0 + carry) & mask;
    set_zsp(c, r, width);
    c->cf = (r0 > mask) || (r0 + carry > mask);
    uint64_t signbit = 1ULL << (width * 8 - 1);
    c->of = (((a ^ r) & (b ^ r)) & signbit) != 0;
    return r;
}

static inline uint64_t logic_flags(X64Ctx* c, uint64_t r, int width) {
    c->cf = false;
    c->of = false;
    set_zsp(c, r, width);
    return r;
}

// 写寄存器：32 位写清零高 32 位；8/16 位写保留高位（方案书硬性要求）
// CPUID / RDTSC：x86 宿主用真实指令，其它架构返回稳定占位值
static inline void x64_cpuid(uint32_t leaf, uint32_t sub,
                             uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
#if defined(__x86_64__) || defined(__i386__)
    unsigned int eax, ebx, ecx, edx;
    __asm__ __volatile__("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                         : "a"(leaf), "c"(sub));
    *a = eax; *b = ebx; *c = ecx; *d = edx;
#else
    (void)leaf; (void)sub;
    *a = 0x756E6547; *b = 0x49656E69; *c = 0x6C65746E; *d = 0x000006F2;  // "GenuineIntel"
#endif
}

static inline uint64_t x64_rdtsc() {
#if defined(__x86_64__) || defined(__i386__)
    unsigned int lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#else
    return 0;
#endif
}

static inline uint64_t x64_ctz(uint64_t v, int bits) {
    if (!v) return (uint64_t)bits;
    return (uint64_t)__builtin_ctzll(v);
}
static inline uint64_t x64_clz(uint64_t v, int bits) {
    if (!v) return (uint64_t)bits;
    if (bits == 64) return (uint64_t)__builtin_clzll(v);
    return (uint64_t)(__builtin_clzll(v) - (64 - bits));
}
// BSR 与 LZCNT 不是一回事：
//   bsr  = "从高位往低位扫，最高的 1 在第几位"（bit index，0 起）
//   lzcnt/clz = "前面有几个 0"
// 之前 bsr 被映射到 x64_clz，于是 0x0FFFFFFFFFFFFFFF 得到 4 而不是 59，
// 随后 `shl rax,cl` 把 1<<59 算成 1<<4=16，`cmp rdx,rax / ja` 于是把
// 合法的 newcount=64 判成非法，抛 length_error("invalid hash bucket count")。
static inline uint64_t x64_bsr(uint64_t v, int bits) {
    if (!v) return (uint64_t)bits;          // 未定义，按 0 处理（上层只用来算移位量）
    return (uint64_t)((bits - 1) - (int)x64_clz(v, bits));
}

static inline uint64_t x64_popcnt(uint64_t v, int bits) {
    (void)bits;
    return (uint64_t)__builtin_popcountll(v);
}

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

// ---- XMM 辅助 ----
static inline void xmm_write_bytes(X64Ctx* c, int idx, const void* src, int bytes) {
    std::memcpy(&c->xmm[idx], src, (size_t)bytes);
}
static inline uint64_t xmm_u64(X64Ctx* c, int idx) {
    uint64_t v;
    std::memcpy(&v, &c->xmm[idx], 8);
    return v;
}
static inline void xmm_set_u64(X64Ctx* c, int idx, uint64_t v) {
    std::memcpy(&c->xmm[idx], &v, 8);
}
static inline float xmm_f32(X64Ctx* c, int idx) { return c->xmm[idx].f32[0]; }
static inline void xmm_set_f32(X64Ctx* c, int idx, float v) { c->xmm[idx].f32[0] = v; }
static inline double xmm_f64(X64Ctx* c, int idx) { return c->xmm[idx].f64[0]; }
static inline void xmm_set_f64(X64Ctx* c, int idx, double v) { c->xmm[idx].f64[0] = v; }

// ---- 位运算辅助 ----
template <typename T> static inline T rotl(T v, T n) {
    int s = (int)(n & (sizeof(T) * 8 - 1));
    return (T)((v << s) | (v >> ((int)sizeof(T) * 8 - s)));
}
template <typename T> static inline T rotr(T v, T n) {
    int s = (int)(n & (sizeof(T) * 8 - 1));
    return (T)((v >> s) | (v << ((int)sizeof(T) * 8 - s)));
}
static inline uint64_t bswap64(uint64_t v) {
    return __builtin_bswap64(v);
}

// ---- 字符串指令（Windows ABI 要求 DF=0）----
static inline uint64_t x64_stride_dir(X64Ctx* c, int bytes) {
    return c->df ? (uint64_t)(-(int64_t)bytes) : (uint64_t)bytes;
}

static inline void x64_stos(X64Ctx* c, int bytes, int rep) {
    uint64_t count = rep ? c->rcx : 1;
    uint64_t mask = bytes >= 8 ? ~0ULL : ((1ULL << (bytes * 8)) - 1);
    uint64_t val = c->rax & mask;
    uint64_t step = x64_stride_dir(c, bytes);
    for (uint64_t i = 0; i < count; ++i) {
        if (bytes == 1) mem_write<uint8_t>(c, c->rdi, (uint8_t)val);
        else if (bytes == 2) mem_write<uint16_t>(c, c->rdi, (uint16_t)val);
        else if (bytes == 4) mem_write<uint32_t>(c, c->rdi, (uint32_t)val);
        else mem_write<uint64_t>(c, c->rdi, val);
        c->rdi += step;
    }
    if (rep) c->rcx = 0;
}

static inline void x64_movs(X64Ctx* c, int bytes, int rep) {
    uint64_t count = rep ? c->rcx : 1;
    uint64_t step = x64_stride_dir(c, bytes);
    for (uint64_t i = 0; i < count; ++i) {
        if (bytes == 1) mem_write<uint8_t>(c, c->rdi, mem_read<uint8_t>(c, c->rsi));
        else if (bytes == 2) mem_write<uint16_t>(c, c->rdi, mem_read<uint16_t>(c, c->rsi));
        else if (bytes == 4) mem_write<uint32_t>(c, c->rdi, mem_read<uint32_t>(c, c->rsi));
        else mem_write<uint64_t>(c, c->rdi, mem_read<uint64_t>(c, c->rsi));
        c->rdi += step; c->rsi += step;
    }
    if (rep) c->rcx = 0;
}

static inline void x64_lods(X64Ctx* c, int bytes, int rep) {
    uint64_t count = rep ? c->rcx : 1;
    uint64_t step = x64_stride_dir(c, bytes);
    for (uint64_t i = 0; i < count; ++i) {
        uint64_t v = 0;
        if (bytes == 1) v = mem_read<uint8_t>(c, c->rsi);
        else if (bytes == 2) v = mem_read<uint16_t>(c, c->rsi);
        else if (bytes == 4) v = mem_read<uint32_t>(c, c->rsi);
        else v = mem_read<uint64_t>(c, c->rsi);
        write_reg(c, 0, v, bytes);
        c->rsi += step;
    }
    if (rep) c->rcx = 0;
}

static inline void x64_scas(X64Ctx* c, int bytes, int rep, int repne) {
    uint64_t step = x64_stride_dir(c, bytes);
    for (;;) {
        uint64_t v = 0;
        if (bytes == 1) v = mem_read<uint8_t>(c, c->rdi);
        else if (bytes == 2) v = mem_read<uint16_t>(c, c->rdi);
        else if (bytes == 4) v = mem_read<uint32_t>(c, c->rdi);
        else v = mem_read<uint64_t>(c, c->rdi);
        (void)sub_flags(c, c->rax, v, bytes);
        c->rdi += step;
        if (!rep) break;
        c->rcx -= 1;
        if (c->rcx == 0) break;
        if (!repne && !c->zf) break;
        if (repne && c->zf) break;
    }
}

static inline void x64_cmps(X64Ctx* c, int bytes, int rep, int repne) {
    uint64_t step = x64_stride_dir(c, bytes);
    for (;;) {
        uint64_t a = 0, b = 0;
        if (bytes == 1) { a = mem_read<uint8_t>(c, c->rsi); b = mem_read<uint8_t>(c, c->rdi); }
        else if (bytes == 2) { a = mem_read<uint16_t>(c, c->rsi); b = mem_read<uint16_t>(c, c->rdi); }
        else if (bytes == 4) { a = mem_read<uint32_t>(c, c->rsi); b = mem_read<uint32_t>(c, c->rdi); }
        else { a = mem_read<uint64_t>(c, c->rsi); b = mem_read<uint64_t>(c, c->rdi); }
        (void)sub_flags(c, a, b, bytes);
        c->rsi += step; c->rdi += step;
        if (!rep) break;
        c->rcx -= 1;
        if (c->rcx == 0) break;
        if (!repne && !c->zf) break;
        if (repne && c->zf) break;
    }
}

#include "x64_sse_helpers.h"
