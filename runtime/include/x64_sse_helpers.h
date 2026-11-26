#pragma once
// 阶段 5b：核心 SSE/浮点指令辅助（ARM64 安全：一律 memcpy，不依赖对齐强转）
#include <cmath>
#include <cstdint>
#include <cstring>

#include "x64_runtime.h"

// 供转译代码直接使用的内存访问小工具（使用当前 ctx）
inline X64Ctx* sse_ctx() { return cur_ctx_ptr(); }
inline uint64_t g_u64(uint64_t a) { return mem_read<uint64_t>(sse_ctx(), a); }
inline void g_st64(uint64_t a, uint64_t v) { mem_write<uint64_t>(sse_ctx(), a, v); }
inline void g_st32(uint64_t a, uint32_t v) { mem_write<uint32_t>(sse_ctx(), a, v); }
inline float g_f32(uint64_t a) { return mem_read<float>(sse_ctx(), a); }
inline double g_f64(uint64_t a) { return mem_read<double>(sse_ctx(), a); }
inline uint64_t g_u128(uint64_t a) { return mem_read<uint64_t>(sse_ctx(), a); }

namespace sse {

inline float f32(const XmmReg& r, int i) {
    float v;
    std::memcpy(&v, &r.u32[i], 4);
    return v;
}
inline void set_f32(XmmReg& r, int i, float v) { std::memcpy(&r.u32[i], &v, 4); }

inline double f64(const XmmReg& r, int i) {
    double v;
    std::memcpy(&v, &r.u64[i], 8);
    return v;
}
inline void set_f64(XmmReg& r, int i, double v) { std::memcpy(&r.u64[i], &v, 8); }

// x86-64 CVTTSS2SI：NaN / 超界统一返回 INT32_MIN
inline int32_t cvttss2si(float f) {
    if (std::isnan(f) || f >= 2147483648.0f || f < -2147483648.0f) return (int32_t)0x80000000u;
    return (int32_t)f;
}
inline int64_t cvttsd2si(double d) {
    if (std::isnan(d) || d >= 9223372036854775808.0 || d < -9223372036854775808.0)
        return (int64_t)0x8000000000000000ull;
    return (int64_t)d;
}

// UCOMISS / COMISS：无序(NaN) -> ZF=PF=CF=1
inline void ucomiss(X64Ctx* c, float a, float b) {
    c->of = false;
    c->sf = false;
    c->pf = false;
    if (std::isnan(a) || std::isnan(b)) {
        c->zf = true;
        c->cf = true;
        c->pf = true;
    } else if (a < b) {
        c->zf = false;
        c->cf = true;
    } else if (a == b) {
        c->zf = true;
        c->cf = false;
    } else {
        c->zf = false;
        c->cf = false;
    }
}

inline void ucomisd(X64Ctx* c, double a, double b) {
    c->of = false;
    c->sf = false;
    c->pf = false;
    if (std::isnan(a) || std::isnan(b)) {
        c->zf = true;
        c->cf = true;
        c->pf = true;
    } else if (a < b) {
        c->zf = false;
        c->cf = true;
    } else if (a == b) {
        c->zf = true;
        c->cf = false;
    } else {
        c->zf = false;
        c->cf = false;
    }
}


// ---------------- AVX（VEX 编码）辅助 ----------------
// 语义要点（与真机一致）：
//   * VEX **128 位**写操作会把目标寄存器高 128 位清零（所以 SSE 代码不受影响）；
//   * VEX 256 位操作读写 32 字节；
//   * vzeroupper 把所有寄存器的高 128 位清零。
// 高 128 位存在 ctx->ymm_hi[reg]（见 X64Ctx 注释）。
namespace avx {

inline void get_lo(X64Ctx* c, int reg, uint64_t out[2]) {
    out[0] = c->xmm[reg].u64[0];
    out[1] = c->xmm[reg].u64[1];
}
inline void set_lo(X64Ctx* c, int reg, const uint64_t in[2]) {
    c->xmm[reg].u64[0] = in[0];
    c->xmm[reg].u64[1] = in[1];
}
inline void get_hi(X64Ctx* c, int reg, uint64_t out[2]) {
    std::memcpy(out, c->ymm_hi[reg], 16);
}
inline void set_hi(X64Ctx* c, int reg, const uint64_t in[2]) {
    std::memcpy(c->ymm_hi[reg], in, 16);
}
inline void zero_hi(X64Ctx* c, int reg) { std::memset(c->ymm_hi[reg], 0, 16); }
inline void zero_all_hi(X64Ctx* c) { std::memset(c->ymm_hi, 0, sizeof(c->ymm_hi)); }

// 从 guest 内存装载 16/32 字节到寄存器（VEX 写：128 位时高半清零）
inline void load(X64Ctx* c, int reg, uint64_t addr, int bytes) {
    c->xmm[reg].u64[0] = mem_read<uint64_t>(c, addr);
    c->xmm[reg].u64[1] = mem_read<uint64_t>(c, addr + 8ULL);
    if (bytes == 32) {
        uint64_t hi[2];
        hi[0] = mem_read<uint64_t>(c, addr + 16ULL);
        hi[1] = mem_read<uint64_t>(c, addr + 24ULL);
        set_hi(c, reg, hi);
    } else {
        zero_hi(c, reg);
    }
}
// 存 16/32 字节到 guest 内存
inline void store(X64Ctx* c, uint64_t addr, int reg, int bytes) {
    mem_write<uint64_t>(c, addr, c->xmm[reg].u64[0]);
    mem_write<uint64_t>(c, addr + 8ULL, c->xmm[reg].u64[1]);
    if (bytes == 32) {
        uint64_t hi[2];
        get_hi(c, reg, hi);
        mem_write<uint64_t>(c, addr + 16ULL, hi[0]);
        mem_write<uint64_t>(c, addr + 24ULL, hi[1]);
    }
}


// 整条指令级别的 AVX 操作：生成代码只调用这些函数，避免把位运算展开成一堆
// 生成字符串（那样一有笔误就要等 40 分钟的全量编译才发现）。
inline void rd_reg(X64Ctx* c, int reg, int bytes, uint8_t out[32]) {
    std::memcpy(out, &c->xmm[reg], 16);
    if (bytes == 32) std::memcpy(out + 16, c->ymm_hi[reg], 16);
    else std::memset(out + 16, 0, 16);
}
inline void wr_reg(X64Ctx* c, int reg, int bytes, const uint8_t in[32]) {
    std::memcpy(&c->xmm[reg], in, 16);
    if (bytes == 32) std::memcpy(c->ymm_hi[reg], in + 16, 16);
    else std::memset(c->ymm_hi[reg], 0, 16);   // VEX 128 位写：高半清零
}
inline void read_mem(X64Ctx* c, uint64_t addr, int bytes, uint8_t out[32]) {
    for (int i = 0; i < bytes; i += 8) {
        uint64_t v = mem_read<uint64_t>(c, addr + (uint64_t)i);
        std::memcpy(out + i, &v, 8);
    }
    if (bytes < 32) std::memset(out + bytes, 0, (size_t)(32 - bytes));
}
inline void write_mem(X64Ctx* c, uint64_t addr, int bytes, const uint8_t in[32]) {
    for (int i = 0; i < bytes; i += 8) {
        uint64_t v = 0;
        std::memcpy(&v, in + i, 8);
        mem_write<uint64_t>(c, addr + (uint64_t)i, v);
    }
}

inline void mov_reg(X64Ctx* c, int d, int s, int bytes) {
    uint8_t t[32]; rd_reg(c, s, bytes, t); wr_reg(c, d, bytes, t);
}
inline void mov_load(X64Ctx* c, int d, uint64_t addr, int bytes) {
    uint8_t t[32]; read_mem(c, addr, bytes, t); wr_reg(c, d, bytes, t);
}
inline void mov_store(X64Ctx* c, uint64_t addr, int s, int bytes) {
    uint8_t t[32]; rd_reg(c, s, bytes, t); write_mem(c, addr, bytes, t);
}

// 位运算（xor/and/or），第二源可以是寄存器或内存
inline void bitop_reg(X64Ctx* c, int d, int s1, int s2, int bytes, int op) {
    uint8_t a[32], b[32];
    rd_reg(c, s1, bytes, a);
    rd_reg(c, s2, bytes, b);
    for (int i = 0; i < bytes; ++i)
        a[i] = (op == 0) ? (uint8_t)(a[i] ^ b[i]) : (op == 1) ? (uint8_t)(a[i] & b[i]) : (uint8_t)(a[i] | b[i]);
    wr_reg(c, d, bytes, a);
}
inline void bitop_mem(X64Ctx* c, int d, int s1, uint64_t addr, int bytes, int op) {
    uint8_t a[32], b[32];
    rd_reg(c, s1, bytes, a);
    read_mem(c, addr, bytes, b);
    for (int i = 0; i < bytes; ++i)
        a[i] = (op == 0) ? (uint8_t)(a[i] ^ b[i]) : (op == 1) ? (uint8_t)(a[i] & b[i]) : (uint8_t)(a[i] | b[i]);
    wr_reg(c, d, bytes, a);
}

// 逐元素比较相等：相等给全 1，否则全 0（lane 宽度 1/2/4 字节）
inline void cmpeq_reg(X64Ctx* c, int d, int s1, int s2, int bytes, int lane) {
    uint8_t a[32], b[32];
    rd_reg(c, s1, bytes, a);
    rd_reg(c, s2, bytes, b);
    for (int i = 0; i + lane <= bytes; i += lane) {
        bool eq = true;
        for (int k = 0; k < lane; ++k) if (a[i + k] != b[i + k]) { eq = false; break; }
        for (int k = 0; k < lane; ++k) a[i + k] = eq ? 0xFF : 0x00;
    }
    wr_reg(c, d, bytes, a);
}

inline uint32_t pmovmskb(X64Ctx* c, int s, int bytes) {
    uint8_t t[32];
    rd_reg(c, s, bytes, t);
    uint32_t m = 0;
    for (int i = 0; i < bytes; ++i)
        if (t[i] & 0x80) m |= (1u << i);
    return m;
}

// vinsertf128 / vextractf128：imm 的最低位选低/高 128 位
inline void insertf128(X64Ctx* c, int d, int s1, int s2, int imm) {
    uint8_t t[32], src[32];
    rd_reg(c, s1, 32, t);
    rd_reg(c, s2, 32, src);
    if (imm & 1) std::memcpy(t + 16, src, 16);
    else         std::memcpy(t, src, 16);
    wr_reg(c, d, 32, t);
}
inline void extractf128(X64Ctx* c, int d, int s, int imm) {
    uint8_t t[32];
    rd_reg(c, s, 32, t);
    uint8_t out[32];
    std::memcpy(out, t + ((imm & 1) ? 16 : 0), 16);
    std::memset(out + 16, 0, 16);
    wr_reg(c, d, 16, out);
}
inline void zeroupper(X64Ctx* c) { zero_all_hi(c); }

}  // namespace avx

}  // namespace sse
