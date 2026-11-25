// 阶段 4 对照 harness（原生侧）：转译后的闭包在宿主上跑，与 Wine 侧原版机器码对拍
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>

#include "x64_runtime.h"
#include "x64_ops.h"
#include "pe_image.h"

void lifted_entry(X64Ctx* ctx);

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
