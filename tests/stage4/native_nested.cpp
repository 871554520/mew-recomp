// 阶段 4 对照 harness（原生侧）：转译后的闭包在宿主上跑，与 Wine 侧原版机器码对拍
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>

#include "x64_runtime.h"
#include "x64_ops.h"
#include "pe_image.h"

void lifted_entry(X64Ctx* ctx);

// 转译代码的「按名派发」路径始终引用 mew_call_api_by_name：dispatch_indirect 遇到
// 未绑定的 IAT 槽时会把槽里的 RVA 解成 API 名再经它调用实现（x64_runtime.h:662）。
// stage3 里这个定义由 shims/win32_kernel32.cpp 提供，而 nested PoC 的链接行不带垫片 TU，
// 于是 8 个候选里有 5 个在链接期全灭（run 46065291572：
// `undefined reference to mew_call_api_by_name`，其余 3 个败在编译期声明）。
// 这里给一个 weak 兜底：返回 0 = 本 harness「未处理该 API」，语义上等价于
// 「PoC 不跑垫片」，不会假装执行成功。weak 的好处是将来 harness 真把 shims 带进来时，
// 强定义会自动覆盖它，不用再改测试。
extern "C" __attribute__((weak)) int mew_call_api_by_name(const char* name, X64Ctx* ctx) {
    (void)name;
    (void)ctx;
    return 0;
}

namespace {
constexpr size_t kBufSize = 0x20000;
constexpr size_t kBufBias = 0x8000;

unsigned long long fnv1a(const unsigned char* p, size_t n) {
    unsigned long long h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; ++i) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}
}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: native_nested <mask_hex> [a0 a1 a2 a3]\n");
        return 2;
    }
    unsigned int mask = (unsigned int)std::strtoull(argv[1], nullptr, 16);
    unsigned long long a[4] = {0, 0, 0, 0};
    for (int i = 0; i < 4 && i + 2 < argc; ++i) a[i] = std::strtoull(argv[i + 2], nullptr, 16);

    GuestImage img;
    std::string err;
    if (!load_pe_image("Mewgenics.exe", &img, &err)) {
        std::fprintf(stderr, "load image failed: %s\n", err.c_str());
        return 1;
    }

    static unsigned char buf[kBufSize];
    std::memset(buf, 0, sizeof(buf));
    unsigned long long host_buf = (unsigned long long)(uintptr_t)(buf + kBufBias);
    unsigned long long guest_buf = (unsigned long long)((int64_t)host_buf - img.mem_bias);
    for (int i = 0; i < 4; ++i)
        if (mask & (1u << i)) a[i] = guest_buf;

    X64Ctx ctx;
    init_guest_thread_ctx(&ctx, img);
    ctx.rcx = a[0];
    ctx.rdx = a[1];
    ctx.r8 = a[2];
    ctx.r9 = a[3];

    lifted_entry(&ctx);

    std::printf("{\"rax\": %llu, \"h\": %llu}\n",
                (unsigned long long)ctx.rax, fnv1a(buf, sizeof(buf)));
    return 0;
}
