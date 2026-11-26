// 变参桥 C 侧：AAPCS64(x0..x7 / d0..d7 / 栈上第 9 个起) -> Darwin 扁平 va_list
#include "bionic_shim.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// 取下一个参数：前 8 个在寄存器槽；第 9 个起落在调用方栈上，
// 整数与浮点共用同一个顺序栈游标（AAPCS64 规定栈上参数按出现顺序排）。
static uint64_t pick(const uint64_t* reg, int* idx, const uint64_t* stack, int stack_n, int* si) {
    int i = *idx;
    uint64_t v;
    if (i < 8) {
        v = reg[i];
    } else {
        v = (stack && *si < stack_n) ? stack[(*si)++] : 0;
    }
    (*idx)++;
    return v;
}

int mew_vararg_build(uint64_t* out, int cap, const char* fmt,
                     const uint64_t* x, int xi, const uint64_t* d, int di,
                     const uint64_t* stack_args, int stack_n) {
    int n = 0;
    int si = 0;                  // 整数/浮点共用的栈参数游标
    const char* p = fmt;
    while (p && *p && n < cap) {
        if (*p != '%') { p++; continue; }
        p++;
        if (*p == '%') { p++; continue; }
        while (*p && strchr("-+ #0'", *p)) p++;
        // 动态宽度 %*d / %.*f：先从整数槽吃一个
        if (*p == '*') { out[n++] = pick(x, &xi, stack_args, stack_n, &si); p++; }
        while (*p >= '0' && *p <= '9') p++;
        if (*p == '.') {
            p++;
            if (*p == '*') { out[n++] = pick(x, &xi, stack_args, stack_n, &si); p++; }
            while (*p >= '0' && *p <= '9') p++;
        }
        while (*p && strchr("hljztLq", *p)) p++;
        char conv = *p ? *p++ : 0;
        int is_fp = (conv=='f'||conv=='F'||conv=='e'||conv=='E'||conv=='g'||conv=='G'||conv=='a'||conv=='A');
        if (is_fp) out[n++] = pick(d, &di, stack_args, stack_n, &si);
        else        out[n++] = pick(x, &xi, stack_args, stack_n, &si);
    }
    return n;
}

int mew_vararg_snprintf(const uint64_t* x, const uint64_t* d, const uint64_t* stk) {
    char* buf = (char*)(uintptr_t)x[0];
    size_t cap = (size_t)x[1];
    const char* fmt = (const char*)(uintptr_t)x[2];
    uint64_t flat[32];
    mew_vararg_build(flat, 32, fmt, x, 3, d, 0, stk, 16);
    return vsnprintf(buf, cap, fmt, (va_list)flat);
}

int mew_vararg_android_log_print(const uint64_t* x, const uint64_t* d, const uint64_t* stk) {
    const char* tag = (const char*)(uintptr_t)x[1];
    const char* fmt = (const char*)(uintptr_t)x[2];
    uint64_t flat[32];
    mew_vararg_build(flat, 32, fmt, x, 3, d, 0, stk, 16);
    fprintf(stderr, "[%s] ", tag ? tag : "?");
    vfprintf(stderr, fmt, (va_list)flat);
    fputc('\n', stderr);
    return 0;
}
