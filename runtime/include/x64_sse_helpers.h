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

}  // namespace sse
