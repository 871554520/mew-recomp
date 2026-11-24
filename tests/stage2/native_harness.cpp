// 阶段 2 对照 harness（原生侧）：跑转译出来的 C++
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include "x64_runtime.h"
#include "x64_ops.h"

// 由 lifter 生成的函数声明（构建时把 generated/lifted.cpp 一起编译）
void lifted_entry(X64Ctx* ctx);

int main(int argc, char** argv) {
    unsigned long long a[4] = {0, 0, 0, 0};
    for (int i = 0; i < 4 && i + 1 < argc; ++i) a[i] = strtoull(argv[i + 1], nullptr, 16);

    // 模拟栈：单独一块 1MB
    static unsigned char stack_mem[1 << 20];
    unsigned long long top = (unsigned long long)(uintptr_t)(stack_mem + sizeof(stack_mem) - 64);

    X64Ctx ctx;
    std::memset(&ctx, 0, sizeof(ctx));
    ctx.rcx = a[0];
    ctx.rdx = a[1];
    ctx.r8 = a[2];
    ctx.r9 = a[3];
    ctx.rsp = top;

    lifted_entry(&ctx);

    std::printf("{\"rax\": %llu}\n", (unsigned long long)ctx.rax);
    return 0;
}
