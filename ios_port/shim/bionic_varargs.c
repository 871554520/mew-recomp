// 变参桥的 C 侧：把 AAPCS64 的 x0..x7 / d0..d7 摊平成 Darwin 的扁平 va_list。
// Darwin ARM64：va_list 就是 char*，所有可变参数按格式串顺序连续排在 8 字节槽里。
#include "bionic_shim.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// 按格式串把 x_slots/d_slots 交替取出来，拼成连续的 8 字节数组
int mew_vararg_build(uint64_t* out, int cap, const char* fmt,
                     const uint64_t* x, int xi, const uint64_t* d, int di) {
    int n = 0;
    const char* p = fmt;
    while (p && *p && n < cap) {
        if (*p != '%') { p++; continue; }
        p++;
        if (*p == '%') { p++; continue; }
        while (*p && strchr("-+ #0'", *p)) p++;
        while (*p >= '0' && *p <= '9') p++;
        if (*p == '.') { p++; while (*p >= '0' && *p <= '9') p++; }
        while (*p && strchr("hljztLq", *p)) p++;
        char conv = *p ? *p++ : 0;
        int is_fp = (conv=='f'||conv=='F'||conv=='e'||conv=='E'||conv=='g'||conv=='G'||conv=='a'||conv=='A');
        if (is_fp) {
            out[n++] = d[di < 8 ? di : 7];
            if (di < 8) di++;
        } else {
            out[n++] = x[xi < 8 ? xi : 7];
            if (xi < 8) xi++;
        }
    }
    return n;
}

// bionic_snprintf(buf, size, fmt, ...)
int mew_vararg_snprintf(const uint64_t* x, const uint64_t* d) {
    char* buf = (char*)(uintptr_t)x[0];
    size_t cap = (size_t)x[1];
    const char* fmt = (const char*)(uintptr_t)x[2];
    uint64_t flat[32];
    int n = mew_vararg_build(flat, 32, fmt, x, 3, d, 0);
    (void)n;
    return vsnprintf(buf, cap, fmt, (va_list)flat);
}

// __android_log_print(prio, tag, fmt, ...)
int mew_vararg_android_log_print(const uint64_t* x, const uint64_t* d) {
    const char* tag = (const char*)(uintptr_t)x[1];
    const char* fmt = (const char*)(uintptr_t)x[2];
    uint64_t flat[32];
    mew_vararg_build(flat, 32, fmt, x, 3, d, 0);
    fprintf(stderr, "[%s] ", tag ? tag : "?");
    vfprintf(stderr, fmt, (va_list)flat);
    fputc('\n', stderr);
    return 0;
}
