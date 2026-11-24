// 方案书 5：Win64 ABI → iOS POSIX 垫片示例
#include "x64_runtime.h"

#ifndef __APPLE__
#include <unistd.h>
static uint64_t fake_ticks() { return 0; }
#else
#include <mach/mach_time.h>
#include <unistd.h>
static uint64_t fake_ticks() { return mach_absolute_time(); }
#endif

void shim_KERNEL32_QueryPerformanceCounter(X64Ctx* ctx) {
    uint64_t out_ptr = ctx->rcx;
    mem_write<uint64_t>(ctx, out_ptr, fake_ticks());
    ctx->rax = 1;
    ctx->rsp += 8;
}

void shim_KERNEL32_Sleep(X64Ctx* ctx) {
    uint32_t ms = static_cast<uint32_t>(ctx->rcx);
    usleep(static_cast<useconds_t>(ms) * 1000U);
    ctx->rsp += 8;
}

#define STUB_API(DLL, NAME)                                                    \
    void shim_##DLL##_##NAME(X64Ctx* ctx) {                                    \
        std::fprintf(stderr, "[UNIMP API] %s!%s (rcx=0x%llx rdx=0x%llx)\n",    \
                     #DLL, #NAME, (unsigned long long)ctx->rcx,                \
                     (unsigned long long)ctx->rdx);                            \
        std::abort();                                                          \
    }
