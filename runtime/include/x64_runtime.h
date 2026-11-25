#pragma once
// 方案书 4.2：寄存器上下文与间接调用分发表
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unordered_map>

struct alignas(16) XmmReg {
    union {
        uint8_t  u8[16];
        uint32_t u32[4];
        uint64_t u64[2];
        float    f32[4];
        double   f64[2];
    };
};

struct X64Ctx {
    uint64_t rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    XmmReg   xmm[16];
    bool zf, sf, cf, of;
    int64_t mem_bias;
};

using RecompFn = void (*)(X64Ctx*);

inline std::unordered_map<uint64_t, RecompFn>& g_dispatch_table() {
    static std::unordered_map<uint64_t, RecompFn> tbl;
    return tbl;
}

inline void register_recomp_fn(uint64_t guest_va, RecompFn fn) {
    g_dispatch_table()[guest_va] = fn;
}

inline void dispatch_indirect(uint64_t target_va, X64Ctx* ctx) {
    auto& tbl = g_dispatch_table();
    auto it = tbl.find(target_va);
    if (it != tbl.end()) {
        it->second(ctx);
        return;
    }
    std::fprintf(stderr, "[FATAL] Unmapped indirect target: 0x%llx\n",
                 static_cast<unsigned long long>(target_va));
    std::abort();
}

template <typename T>
inline T mem_read(X64Ctx* ctx, uint64_t guest_addr) {
    T v;
    std::memcpy(&v, reinterpret_cast<const void*>(guest_addr + ctx->mem_bias), sizeof(T));
    return v;
}

template <typename T>
inline void mem_write(X64Ctx* ctx, uint64_t guest_addr, T val) {
    std::memcpy(reinterpret_cast<void*>(guest_addr + ctx->mem_bias), &val, sizeof(T));
}

// ---------------- 阶段 3 占位与日志 ----------------
#define UNIMPL_INSN(RIP, MNEM)                                                   \
    do {                                                                         \
        std::fprintf(stderr, "[UNIMPL INSN] rip=0x%llx mnemonic=%s\n",           \
                     (unsigned long long)(RIP), (MNEM));                         \
        std::abort();                                                            \
    } while (0)

#define UNIMPL_API(NAME)                                                         \
    do {                                                                         \
        std::fprintf(stderr, "[UNIMPL API] %s\n", (NAME));                       \
        std::abort();                                                            \
    } while (0)

#define UNIMPL_FUNC(VA)                                                          \
    do {                                                                         \
        std::fprintf(stderr, "[UNIMPL FUNC] va=0x%llx\n",                        \
                     (unsigned long long)(VA));                                  \
        std::abort();                                                            \
    } while (0)

// 由生成的 dispatch_table.cpp 提供
void init_dispatch_table(const char* extra_url = nullptr, void* extra = nullptr);
