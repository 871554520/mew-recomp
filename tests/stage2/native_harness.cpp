// 阶段 2 对照 harness（原生侧）：跑转译出来的 C++
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <execinfo.h>
#include <signal.h>
#include <unistd.h>

#include "x64_runtime.h"
#include "x64_ops.h"

// 由 lifter 生成的函数声明（构建时把 generated/lifted.cpp 一起编译）
void lifted_entry(X64Ctx* ctx);

namespace {
constexpr size_t kBufSize = 0x20000;   // 128 KB 模拟堆区
constexpr size_t kBufBias = 0x8000;    // 缓冲区中部作为“对象”起点，允许 [ptr-0x4000 .. ptr+0x8000]
constexpr size_t kStackSize = 1 << 20;

unsigned long long fnv1a(const unsigned char* p, size_t n) {
    unsigned long long h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; ++i) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}
}  // namespace

namespace {
void crash_handler(int sig, siginfo_t* si, void*) {
    void* bt[32];
    int n = backtrace(bt, 32);
    std::fprintf(stderr, "[ARM64-CRASH] sig=%d fault=0x%llx frames=%d\n", sig,
                 (unsigned long long)(uintptr_t)si->si_addr, n);
    backtrace_symbols_fd(bt, n, 2);
    std::fflush(stderr);
    _exit(139);
}
void install_crash_handler() {
    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGBUS, &sa, nullptr);
    sigaction(SIGILL, &sa, nullptr);
}
}  // namespace

int main(int argc, char** argv) {
    install_crash_handler();
    if (argc < 2) {
        std::fprintf(stderr, "usage: native_harness <ptr_mask_hex> [a0 a1 a2 a3]\n");
        return 2;
    }
    unsigned int mask = (unsigned int)std::strtoull(argv[1], nullptr, 16);
    unsigned long long a[4] = {0, 0, 0, 0};
    for (int i = 0; i < 4 && i + 2 < argc; ++i)
        a[i] = std::strtoull(argv[i + 2], nullptr, 16);

    static unsigned char buf[kBufSize];
    static unsigned char stack_mem[kStackSize];
    std::memset(buf, 0, sizeof(buf));
    std::memset(stack_mem, 0, sizeof(stack_mem));

    const unsigned long long bufp = (unsigned long long)(uintptr_t)(buf + kBufBias);
    for (int i = 0; i < 4; ++i)
        if (mask & (1u << i)) a[i] = bufp;

    X64Ctx ctx;
    std::memset(&ctx, 0, sizeof(ctx));
    ctx.rcx = a[0];
    ctx.rdx = a[1];
    ctx.r8 = a[2];
    ctx.r9 = a[3];
    ctx.rsp = (unsigned long long)(uintptr_t)(stack_mem + kStackSize - 64);

    std::fprintf(stderr, "[harness] ctx=%p rsp=0x%llx rcx=0x%llx buf=%p\n",
                 (void*)&ctx, (unsigned long long)ctx.rsp, (unsigned long long)ctx.rcx, (void*)buf);
    std::fflush(stderr);
    lifted_entry(&ctx);

    std::printf("{\"rax\": %llu, \"h\": %llu}\n",
                (unsigned long long)ctx.rax, fnv1a(buf, sizeof(buf)));
    return 0;
}
