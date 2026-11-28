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
// 真正的 16 字节装载：g_u128 名字像 128 位，实际只读 8 字节（历史遗留），
// 不能拿来给 `XmmReg s_ = ...` 赋值 —— run 46021918695 就是这么编挂的：
//   shard_031.cpp:158536:23: error: conversion from 'uint64_t' to non-scalar type 'XmmReg'
// 这里按两段 8 字节用 mem_read 读，ARM64 上也不做对齐强转。
inline XmmReg g_ld128(uint64_t a) {
    XmmReg r{};
    r.u64[0] = mem_read<uint64_t>(sse_ctx(), a);
    r.u64[1] = mem_read<uint64_t>(sse_ctx(), a + 8);
    return r;
}

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

// x86-64 CVTSS2SI / CVTSD2SI：**带舍入**（按 MXCSR 的舍入模式，默认就近取偶）。
// 与上面的 CVTT* 只差舍入方式；stub_list 里 cvtsd2si 出现在 9 个函数里，
// 之前没实现，整函数被占位。NaN / 超界按 SDM 给的是「整数不定值」。
inline int32_t cvtss2si(float f) {
    const double r = std::nearbyint((double)f);   // 先舍入再判界，避免 2^31-0.4 这类舍入后越界
    if (std::isnan(r) || r >= 2147483648.0 || r < -2147483648.0) return (int32_t)0x80000000u;
    return (int32_t)r;
}
inline int64_t cvtsd2si(double d) {
    const double r = std::nearbyint(d);
    if (std::isnan(r) || r >= 9223372036854775808.0 || r < -9223372036854775808.0)
        return (int64_t)0x8000000000000000ull;
    return (int64_t)r;
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

// 第二源是内存的形式：`vpcmpeqw ymm1,ymm1,YMMWORD PTR [r9]`
inline void cmpeq_mem(X64Ctx* c, int d, int s1, uint64_t addr, int bytes, int lane) {
    uint8_t a[32], b[32];
    rd_reg(c, s1, bytes, a);
    read_mem(c, addr, bytes, b);
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
// ---- 批次3：VEX 整数逐 lane 运算 ----
// 为什么：stub_list 前 30 名里 vcomisd 17 / vpsubd 10 / vpsravd 8 / vpshufb 8 /
// vpsrlq 7 / vpaddd 5 / vpmaxsd 5 全落在这一族，每补一条就整函数解锁 5~17 个。
// 全部按字节读写（rd_reg/wr_reg），因此 128/256 位通用，VEX 128 位写的高半清零
// 由 wr_reg 统一负责，不用每条指令各写一遍。
// unit ∈ {1,2,4,8}；op: 0=add 1=sub 2=max 3=min；sgn 决定 max/min 按有符号比。
inline int64_t lane_get(const uint8_t* p, int unit) {
    int64_t v = 0;
    std::memcpy(&v, p, (size_t)unit);
    return v;
}
inline void lane_put(uint8_t* p, int unit, int64_t v) { std::memcpy(p, &v, (size_t)unit); }
// unit < 8 时把高位置成符号位（有符号 max/min、算术右移要用）
inline int64_t lane_sext(int64_t v, int unit) {
    if (unit >= 8) return v;
    const uint64_t mask = (1ULL << (unit * 8)) - 1ULL;
    const uint64_t sign = 1ULL << (unit * 8 - 1);
    uint64_t u = (uint64_t)v & mask;
    if (u & sign) u |= ~mask;
    return (int64_t)u;
}
inline void i_binop_core(uint8_t* a, const uint8_t* b, int bytes, int unit, int op, bool sgn) {
    for (int i = 0; i + unit <= bytes; i += unit) {
        int64_t x = lane_get(a + i, unit), y = lane_get(b + i, unit);
        if (sgn) { x = lane_sext(x, unit); y = lane_sext(y, unit); }
        int64_t r;
        switch (op) {
            case 0:  r = x + y; break;
            case 1:  r = x - y; break;
            case 2:  r = (x > y) ? x : y; break;
            default: r = (x < y) ? x : y; break;
        }
        lane_put(a + i, unit, r);   // 只写回 unit 字节，模 2^bits 截断自动完成
    }
}
inline void i_binop(X64Ctx* c, int d, int s1, int s2, int bytes, int unit, int op, bool sgn) {
    uint8_t a[32], b[32];
    rd_reg(c, s1, bytes, a);
    rd_reg(c, s2, bytes, b);
    i_binop_core(a, b, bytes, unit, op, sgn);
    wr_reg(c, d, bytes, a);
}
inline void i_binop_mem(X64Ctx* c, int d, int s1, uint64_t addr, int bytes, int unit, int op, bool sgn) {
    uint8_t a[32], b[32];
    rd_reg(c, s1, bytes, a);
    read_mem(c, addr, bytes, b);
    i_binop_core(a, b, bytes, unit, op, sgn);
    wr_reg(c, d, bytes, a);
}
// 单个 lane 的移位。op: 0=shl 1=shr(逻辑) 2=sar(算术)。
// 越界按 SDM：逻辑移给 0，算术右移给符号位（负数 -1，非负 0）。
inline void i_shift_one(uint8_t* p, int unit, int op, int sh) {
    const int bits = unit * 8;
    int64_t v = lane_get(p, unit);
    if (sh < 0) sh = 0;
    if (op == 0)      v = (sh >= bits) ? 0 : (int64_t)((uint64_t)v << sh);
    else if (op == 1) v = (sh >= bits) ? 0 : (int64_t)((uint64_t)v >> sh);
    else {
        v = lane_sext(v, unit);
        v = (sh >= bits) ? (v < 0 ? -1 : 0) : (v >> sh);
    }
    lane_put(p, unit, v);
}
// 立即数/统一计数形式（vpsrlq/vpsrld/vpsllq + imm，以及计数来自 XMM 低 64 位的形式）
inline void i_shift(X64Ctx* c, int d, int s1, int op, int unit, int sh, int bytes) {
    uint8_t a[32];
    rd_reg(c, s1, bytes, a);
    for (int i = 0; i + unit <= bytes; i += unit) i_shift_one(a + i, unit, op, sh);
    wr_reg(c, d, bytes, a);
}
// 计数来自源寄存器低 64 位（VEX 变长移位里「计数在 xmm」的那一版）
inline void i_shift_reg(X64Ctx* c, int d, int s1, int s2, int op, int unit, int bytes) {
    uint8_t a[32], b[32];
    rd_reg(c, s1, bytes, a);
    rd_reg(c, s2, bytes, b);
    const int sh = (int)(lane_get(b, 8) & 0xFFULL);
    for (int i = 0; i + unit <= bytes; i += unit) i_shift_one(a + i, unit, op, sh);
    wr_reg(c, d, bytes, a);
}
inline void i_shift_mem(X64Ctx* c, int d, int s1, uint64_t addr, int op, int unit, int bytes) {
    uint8_t a[32], b[32];
    rd_reg(c, s1, bytes, a);
    read_mem(c, addr, bytes, b);
    const int sh = (int)(lane_get(b, 8) & 0xFFULL);
    for (int i = 0; i + unit <= bytes; i += unit) i_shift_one(a + i, unit, op, sh);
    wr_reg(c, d, bytes, a);
}
// 每 lane 各自一个计数（vpsravd / vpsravw）
inline void i_shift_lane(X64Ctx* c, int d, int s1, int s2, int op, int unit, int bytes) {
    uint8_t a[32], b[32];
    rd_reg(c, s1, bytes, a);
    rd_reg(c, s2, bytes, b);
    for (int i = 0; i + unit <= bytes; i += unit)
        i_shift_one(a + i, unit, op, (int)(lane_get(b + i, unit) & 0xFF));
    wr_reg(c, d, bytes, a);
}
inline void i_shift_lane_mem(X64Ctx* c, int d, int s1, uint64_t addr, int op, int unit, int bytes) {
    uint8_t a[32], b[32];
    rd_reg(c, s1, bytes, a);
    read_mem(c, addr, bytes, b);
    for (int i = 0; i + unit <= bytes; i += unit)
        i_shift_one(a + i, unit, op, (int)(lane_get(b + i, unit) & 0xFF));
    wr_reg(c, d, bytes, a);
}
// vpshufb：每 16 字节一个独立索引表；索引最高位为 1 时该字节写 0
inline void pshufb(X64Ctx* c, int d, int s1, int s2, int bytes) {
    uint8_t a[32], b[32], o[32];
    rd_reg(c, s1, bytes, a);
    rd_reg(c, s2, bytes, b);
    for (int i = 0; i < bytes; ++i) {
        const int base = i & ~0xF;
        o[i] = (b[i] & 0x80) ? (uint8_t)0 : a[base + (b[i] & 0x0F)];
    }
    wr_reg(c, d, bytes, o);
}
inline void pshufb_mem(X64Ctx* c, int d, int s1, uint64_t addr, int bytes) {
    uint8_t a[32], b[32], o[32];
    rd_reg(c, s1, bytes, a);
    read_mem(c, addr, bytes, b);
    for (int i = 0; i < bytes; ++i) {
        const int base = i & ~0xF;
        o[i] = (b[i] & 0x80) ? (uint8_t)0 : a[base + (b[i] & 0x0F)];
    }
    wr_reg(c, d, bytes, o);
}

inline void zeroupper(X64Ctx* c) { zero_all_hi(c); }

}  // namespace avx

// ---------------- SSE4.1 PTEST / SSE4.2 PCMPESTR* ----------------
// 为什么需要：run 45999239672 里 `[UNIMPL FUNC] va=0x140d1a1b0 missing=pcmpestrm,ptest`
// 出现 4 次，紧接着调用方就抛 `std::out_of_range`（_Xran）——ucrt 的 SSE4.2 字符串例程
// 整个被占位成「返回 0」，调用方按它给的 0 去取子串就越界。补齐才能整函数翻出来。
//
// PTEST：ZF = ((SRC1 & SRC2) == 0)，CF = ((SRC1 & ~SRC2) == 0)，SF/OF/AF/PF = 0
inline void ptest(X64Ctx* c, const XmmReg& a, const XmmReg& b) {
    bool and_zero = true, andn_zero = true;
    for (int i = 0; i < 2; ++i) {
        if (a.u64[i] & b.u64[i]) and_zero = false;
        if (b.u64[i] & ~a.u64[i]) andn_zero = false;   // SDM：CF = (SRC2 & ~SRC1) == 0
    }
    c->zf = and_zero;
    c->cf = andn_zero;
    c->sf = false;
    c->of = false;
    c->pf = false;
}

// PCMPxSTRx 公共核心。**操作数角色按 SDM/intrinsic 定义**（_mm_cmpestri(needle, la, haystack, lb, mode)）：
//   a = needle（第一操作数，长度取 EAX），b = haystack（第二操作数，长度取 EDX）。
//   IntRes2 的第 i 位 = **haystack 第 i 个元素**命中，所以 index 直接就是 haystack 下标。
// 聚合函数：0 equal any（b[i] ∈ {a[*]}）、1 ranges（b[i] ∈ 某个 [a[2k], a[2k+1]]）、
//           2 equal each（a[i] == b[i]）、3 equal ordered（b[i..i+nA-1] == a[0..nA-1]）。
// imm8：[1:0] 元素位宽/符号，[3:2] 聚合函数，[4] 极性，[6] 索引/掩码选择。
struct PcmpStr {
    uint32_t bits = 0;   // IntRes2：haystack 元素命中位图
    int n_elem = 16;     // 元素个数上限（字节 16，字 8）
};

// 长度寄存器按 SDM 解释：取绝对值，饱和到元素上限
inline int pcmp_len(uint64_t v, int max_elem) {
    const int64_t s = (int64_t)(int32_t)(uint32_t)v;
    const int64_t a = (s < 0) ? -s : s;
    return (int)(a > max_elem ? max_elem : a);
}

inline int32_t pcmp_elem(const uint8_t* p, int i, int unit, bool sgn) {
    if (unit == 1) {
        const uint8_t u = p[i];
        return sgn ? (int32_t)(int8_t)u : (int32_t)u;
    }
    uint16_t u = 0;
    std::memcpy(&u, p + i * 2, 2);
    return sgn ? (int32_t)(int16_t)u : (int32_t)u;
}

inline PcmpStr pcmp_core(const XmmReg& a, const XmmReg& b, int nA, int nB, uint8_t imm) {
    const int fmt = imm & 3;
    const int unit = (fmt == 1 || fmt == 3) ? 2 : 1;
    const bool sgn = (fmt >= 2);
    const int agg = (imm >> 2) & 3;
    const int n_elem = 16 / unit;
    const uint32_t full = (1u << n_elem) - 1u;
    PcmpStr r;
    r.n_elem = n_elem;
    if (nA > n_elem) nA = n_elem;
    if (nB > n_elem) nB = n_elem;
    if (nA < 0) nA = 0;
    if (nB < 0) nB = 0;

    const uint8_t* pa = (const uint8_t*)&a;
    const uint8_t* pb = (const uint8_t*)&b;
    uint32_t bits = 0;
    if (agg == 2) {                            // equal each：全 n 个元素逐个比较
        // 硬件实测（workflow pcmp-hw，2026-11-28）：equal-each 比全部 16/8 个元素，
        // la/lb 只影响 CF/ZF/SF，不裁剪位图。旧实现只比前 nB 个、还要求 i<nA，
        // 与 CPU 不符（hw=0xffff，旧模型=0x3）。
        for (int i = 0; i < n_elem; ++i)
            if (pcmp_elem(pb, i, unit, sgn) == pcmp_elem(pa, i, unit, sgn))
                bits |= (1u << i);
    } else {
        for (int i = 0; i < nB; ++i) {         // 位图下标 = haystack 位置
            const int32_t h = pcmp_elem(pb, i, unit, sgn);
            bool hit = false;
            if (agg == 0) {                    // equal any
                for (int j = 0; j < nA; ++j)
                    if (h == pcmp_elem(pa, j, unit, sgn)) { hit = true; break; }
            } else if (agg == 1) {             // ranges：needle 两两成区间
                for (int j = 0; j + 1 < nA; j += 2) {
                    const int32_t lo = pcmp_elem(pa, j, unit, sgn);
                    const int32_t hi = pcmp_elem(pa, j + 1, unit, sgn);
                    if (lo <= h && h <= hi) { hit = true; break; }
                }
            } else {                           // equal ordered：A 的前缀出现在 i 处
                // **不能**用 `i + nA <= nB` 当硬条件（run 46005327501 的 objdump：
                // 调用方 bsr→btr 枚举候选，再逐位完整比对；只有「部分前缀也置位」才成立）。
                const int k_max = (nA < nB - i) ? nA : (nB - i);
                hit = true;
                for (int k = 0; k < k_max; ++k)
                    if (pcmp_elem(pb, i + k, unit, sgn) != pcmp_elem(pa, k, unit, sgn)) { hit = false; break; }
            }
            if (hit) bits |= (1u << i);
        }
    }
    // 硬件实测：equal-ordered 且 nA=0 是真空匹配，位图全 1（旧模型给 0）。
    if (agg == 3 && nA == 0) bits = full;
    // 极性（imm8[4]）：硬件对全部 n 位取反（旧实现按 nB 掩码，hw=0xfffd vs 旧 0x5）。
    if (imm & 0x10) bits = (~bits) & full;
    r.bits = bits & full;
    return r;
}

// 算术标志按 SDM 的非标准写法：
//   CF = IntRes2 != 0；ZF = |EDX| < 上限（haystack 短于整段）；SF = |EAX| < 上限；
//   OF = IntRes2[0]；AF = PF = 0。
inline void pcmp_flags(X64Ctx* c, const PcmpStr& r, int nA, int nB) {
    c->cf = (r.bits != 0);
    c->zf = (nB < r.n_elem);
    c->sf = (nA < r.n_elem);
    c->of = (r.bits & 1u) != 0;
    c->pf = false;
}

// PCMPESTRM：结果写 XMM0。imm8[6]=0 写位掩码（低 16/8 位），=1 写元素掩码（命中元素整段置 1）。
inline void pcmpestrm(X64Ctx* c, const XmmReg& a, const XmmReg& b, uint8_t imm) {
    const int fmt = imm & 3;
    const int unit = (fmt == 1 || fmt == 3) ? 2 : 1;
    const int n_elem = 16 / unit;
    const int nA = pcmp_len(c->rax, n_elem);
    const int nB = pcmp_len(c->rdx, n_elem);
    const PcmpStr r = pcmp_core(a, b, nA, nB, imm);
    pcmp_flags(c, r, nA, nB);
    XmmReg out{};
    if (imm & 0x40) {                          // 元素掩码
        for (int i = 0; i < n_elem; ++i) {
            if (!(r.bits & (1u << i))) continue;
            if (unit == 1) out.u8[i] = 0xFF;
            else out.u16[i] = 0xFFFF;
        }
    } else {                                   // 位掩码，其余位清零
        out.u32[0] = r.bits;
    }
    c->xmm[0] = out;
}

// PCMPESTRI：结果 index 写 ECX（无匹配给 16/8）；imm8[6]=0 取最低置位，=1 取最高置位。
inline void pcmpestri(X64Ctx* c, const XmmReg& a, const XmmReg& b, uint8_t imm) {
    const int fmt = imm & 3;
    const int unit = (fmt == 1 || fmt == 3) ? 2 : 1;
    const int n_elem = 16 / unit;
    const int nA = pcmp_len(c->rax, n_elem);
    const int nB = pcmp_len(c->rdx, n_elem);
    const PcmpStr r = pcmp_core(a, b, nA, nB, imm);
    pcmp_flags(c, r, nA, nB);
    int idx = n_elem;
    if (r.bits) {
        if (imm & 0x40) {
            for (int i = 0; i < n_elem; ++i) if (r.bits & (1u << i)) idx = i;
        } else {
            for (int i = 0; i < n_elem; ++i) if (r.bits & (1u << i)) { idx = i; break; }
        }
    }
    c->rcx = (uint64_t)(uint32_t)idx;
}

// PCMPISTRI：隐式长度版（长度由串尾 0 决定，**不读** RAX/RDX）。
// 长度口径取「第一个 0 之前的元素个数」（不含 0 本身）：
//   MSVC 的 strstr 把 needle 放进 xmm 后靠这个长度做 equal-ordered 匹配，
//   若把终止 0 也算进长度，匹配还会要求 haystack 同位置也是 0，等于只在串尾命中 —— 与 strstr 语义相反。
//   顺带：haystack 的 0 落在第 15 字节时，不含 0 的长度=15 < 16，pcmp_flags 才能正确置 zf（串已结束）。
inline int pcmp_implen(const XmmReg& r, int n_elem, int unit) {
    for (int i = 0; i < n_elem; ++i) {
        if (unit == 1) { if (r.u8[i] == 0) return i; }
        else            { if (r.u16[i] == 0) return i; }
    }
    return n_elem;
}

inline void pcmpistri(X64Ctx* c, const XmmReg& a, const XmmReg& b, uint8_t imm) {
    const int fmt = imm & 3;
    const int unit = (fmt == 1 || fmt == 3) ? 2 : 1;
    const int n_elem = 16 / unit;
    const int nA = pcmp_implen(a, n_elem, unit);
    const int nB = pcmp_implen(b, n_elem, unit);
    const PcmpStr r = pcmp_core(a, b, nA, nB, imm);
    pcmp_flags(c, r, nA, nB);
    int idx = n_elem;
    if (r.bits) {
        if (imm & 0x40) {
            for (int i = 0; i < n_elem; ++i) if (r.bits & (1u << i)) idx = i;
        } else {
            for (int i = 0; i < n_elem; ++i) if (r.bits & (1u << i)) { idx = i; break; }
        }
    }
    c->rcx = (uint64_t)(uint32_t)idx;
}



}  // namespace sse

// lifter 生成的代码按**全局**命名空间写 `avx::xxx`（见 lifter/src/lifter_core.cpp
// 里 AVX 那一组发射），但 avx 实际嵌在 sse 里（因为它要用 sse 的 helper）。
// 这里补一个命名空间别名，让 `avx::` 在所有分片里都可见——否则只有真正用到
// AVX 指令的那个分片会报 'avx' has not been declared（stage3 shard_049 实测）。
namespace avx = sse::avx;
