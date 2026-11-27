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
inline void zeroupper(X64Ctx* c) { zero_all_hi(c); }

// ---------------- SSE4.1 PTEST / SSE4.2 PCMPESTRM ----------------
// 为什么需要：run 45999239672 里 `[UNIMPL FUNC] va=0x140d1a1b0 missing=pcmpestrm,ptest`
// 出现 4 次，紧接着调用方就抛 `std::out_of_range`（_Xran）——ucrt 的 SSE4.2 字符串例程
// 整个被占位成「返回 0」，调用方按它给的 0 去取子串就越界。补齐这两条才能整函数翻出来。
//
// PTEST：ZF = ((src1 & src2) == 0)，CF = ((src1 & ~src2) == 0)，SF/OF/AF/PF = 0
inline void ptest(X64Ctx* c, const XmmReg& a, const XmmReg& b) {
    bool and_zero = true, andn_zero = true;
    for (int i = 0; i < 2; ++i) {
        if (a.u64[i] & b.u64[i]) and_zero = false;
        if (a.u64[i] & ~b.u64[i]) andn_zero = false;
    }
    c->zf = and_zero;
    c->cf = andn_zero;
    c->sf = false;
    c->of = false;
    c->af = false;
    c->pf = false;
}

// PCMPESTRM xmm_A, xmm_B/m128, imm8：显式长度（EAX = A 的元素数，EDX = B 的元素数）
// 的字符串比较，结果写 **XMM0** 低 16 位（imm8[6]=0 写 mask，=1 写 index）。
// 实测站点（0x140d1a430）：`66 0f 3a 60 36 0c` = pcmpestrm xmm6, [rsi], 0x0c
//   → 无符号字节 + equal-ordered + 正极性 + **mask 输出**，正是「在 16 字节块里找 needle」。
// 这里实现：字节元素（imm[1:0]==00 或 10 都按字节位宽处理）+ equal-any(00) / equal-ordered(11)
// + 四种极性；字元素（01/11）与 ranges(01) 未实现，按「无匹配」处理（并置 SF 让调用方走慢路径）。
inline void pcmpestrm(X64Ctx* c, const XmmReg& a, const XmmReg& b, uint8_t imm, XmmReg& dst) {
    const int elem_bits = ((imm & 3) == 1 || (imm & 3) == 3) ? 16 : 8;
    const int max_elem = (elem_bits == 8) ? 16 : 8;
    int nA = (int)(uint32_t)c->rax;   // 有符号来源：负数按 0 处理
    int nB = (int)(uint32_t)c->rdx;
    if (nA < 0) nA = 0;
    if (nB < 0) nB = 0;
    if (nA > max_elem) nA = max_elem;
    if (nB > max_elem) nB = max_elem;

    uint32_t intres1 = 0;
    const int agg = (imm >> 2) & 3;
    if (elem_bits == 8) {
        uint8_t A[16], B[16];
        std::memcpy(A, &a, 16);
        std::memcpy(B, &b, 16);
        for (int i = 0; i < nA; ++i) {
            if (agg == 0) {                       // equal any：A[i] 出现在 B 里
                for (int j = 0; j < nB; ++j)
                    if (A[i] == B[j]) { intres1 |= 1u << i; break; }
            } else if (agg == 3) {                // equal ordered：A 整段出现在 B 的 i 处
                if (i + nA > nB) continue;
                bool ok = true;
                for (int k = 0; k < nA; ++k)
                    if (A[k] != B[i + k]) { ok = false; break; }
                if (ok) intres1 |= 1u << i;
            }
        }
    }

    const uint32_t valid_mask = (nB >= max_elem) ? 0xFFFFu : ((nB <= 0) ? 0u : ((1u << nB) - 1u));
    uint32_t intres2 = intres1;
    switch ((imm >> 4) & 3) {
        case 0: intres2 = intres1; break;                    // 正极性
        case 1: intres2 = (~intres1) & 0xFFFFu; break;        // 负极性
        case 2: intres2 = intres1 & valid_mask; break;        // masked positive
        default: intres2 = (~intres1) & valid_mask; break;    // masked negative
    }
    intres2 &= 0xFFFFu;

    c->cf = nA < max_elem;
    c->zf = nB < max_elem;
    c->sf = intres2 == 0;
    c->of = intres1 != 0;
    c->af = false;
    c->pf = false;

    uint32_t out = 0;
    if (imm & 0x40) {                    // index 输出：最低置位下标，无匹配给 max_elem
        int idx = max_elem;
        for (int i = 0; i < max_elem; ++i)
            if (intres2 & (1u << i)) { idx = i; break; }
        out = (uint32_t)idx;
    } else {
        out = intres2;
    }
    dst.u32[0] = out;
    dst.u32[1] = 0;
    dst.u32[2] = 0;
    dst.u32[3] = 0;
}

}  // namespace avx

}  // namespace sse

// lifter 生成的代码按**全局**命名空间写 `avx::xxx`（见 lifter/src/lifter_core.cpp
// 里 AVX 那一组发射），但 avx 实际嵌在 sse 里（因为它要用 sse 的 helper）。
// 这里补一个命名空间别名，让 `avx::` 在所有分片里都可见——否则只有真正用到
// AVX 指令的那个分片会报 'avx' has not been declared（stage3 shard_049 实测）。
namespace avx = sse::avx;
