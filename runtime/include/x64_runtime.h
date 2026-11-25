#pragma once
// 方案书 4.2：寄存器上下文与间接调用分发表
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unordered_map>
#include <algorithm>
#include <vector>

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
    bool zf, sf, cf, of, pf, df;
    int64_t mem_bias;
    uint64_t gs_base;   // 伪 TEB 的 guest 地址（gs:[disp] 路由到这里）
    uint64_t fs_base;
};

using RecompFn = void (*)(X64Ctx*);

inline std::unordered_map<uint64_t, RecompFn>& g_dispatch_table() {
    static std::unordered_map<uint64_t, RecompFn> tbl;
    return tbl;
}

inline std::vector<uint64_t>& dispatch_vas() {
    static std::vector<uint64_t> v;
    return v;
}

inline void register_recomp_fn(uint64_t guest_va, RecompFn fn) {
    g_dispatch_table()[guest_va] = fn;
    dispatch_vas().push_back(guest_va);
}

inline void init_dispatch_diag() {
    auto& v = dispatch_vas();
    std::sort(v.begin(), v.end());
}

static inline bool mew_unimpl_continue() {
    static int cached = -1;
    if (cached < 0) { const char* v = std::getenv("MEW_UNIMPL_CONTINUE"); cached = (v && v[0] == '1') ? 1 : 0; }
    return cached == 1;
}

static inline bool mew_safe_mem() {
    static int cached = -1;
    if (cached < 0) { const char* v = std::getenv("MEW_SAFE_MEM"); cached = (v && v[0] == '1') ? 1 : 0; }
    return cached == 1;
}

inline void dispatch_indirect(uint64_t target_va, X64Ctx* ctx) {
    auto& tbl = g_dispatch_table();
    auto it = tbl.find(target_va);
    if (it != tbl.end()) {
        it->second(ctx);
        return;
    }
    // 诊断：找最近的下界函数，判断是“函数内偏移”还是“完全在表外”
    auto& v = dispatch_vas();
    auto it2 = std::lower_bound(v.begin(), v.end(), target_va);
    uint64_t near_lo = 0;
    if (it2 != v.begin()) near_lo = *(it2 - 1);
    std::fprintf(stderr, "[FATAL] Unmapped indirect target: 0x%llx (nearest_lo=0x%llx delta=%lld)\n",
                 static_cast<unsigned long long>(target_va),
                 (unsigned long long)near_lo,
                 (long long)((int64_t)target_va - (int64_t)near_lo));
    if (mew_unimpl_continue()) return;  // 收集模式：记录后继续，便于观察后续路径
    std::abort();
}

// ---------------- guest 已映射区间登记（垫片防崩） ----------------
struct GuestMemRange { uint64_t lo, hi; };

inline std::vector<GuestMemRange>& guest_mem_ranges() {
    static std::vector<GuestMemRange> r;
    return r;
}

inline void register_guest_range(uint64_t guest_lo, uint64_t len) {
    if (!len) return;
    guest_mem_ranges().push_back({guest_lo, guest_lo + len});
}

inline bool guest_mapped(uint64_t addr, size_t n = 1) {
    if (!addr) return false;
    for (const auto& r : guest_mem_ranges())
        if (addr >= r.lo && addr + n <= r.hi) return true;
    return false;
}

template <typename T>
inline T mem_read(X64Ctx* ctx, uint64_t guest_addr) {
    T v;
    std::memset(&v, 0, sizeof(T));
    if (mew_safe_mem() && !guest_mapped(guest_addr, sizeof(T))) {
        static int logged = 0;
        if (logged < 20) {
            std::fprintf(stderr, "[SAFE] unmapped read addr=0x%llx size=%zu\n",
                         (unsigned long long)guest_addr, sizeof(T));
            ++logged;
        }
        return v;
    }
    std::memcpy(&v, reinterpret_cast<const void*>(guest_addr + ctx->mem_bias), sizeof(T));
    return v;
}

template <typename T>
inline void mem_write(X64Ctx* ctx, uint64_t guest_addr, T val) {
    if (mew_safe_mem() && !guest_mapped(guest_addr, sizeof(T))) {
        static int logged = 0;
        if (logged < 20) {
            std::fprintf(stderr, "[SAFE] unmapped write addr=0x%llx size=%zu\n",
                         (unsigned long long)guest_addr, sizeof(T));
            ++logged;
        }
        return;
    }
    std::memcpy(reinterpret_cast<void*>(guest_addr + ctx->mem_bias), &val, sizeof(T));
}

// ---------------- 阶段 3 占位与日志 ----------------
// MEW_UNIMPL_CONTINUE=1 时只记录并返回（用于批量收集缺失项），否则中止
#define UNIMPL_INSN(RIP, MNEM)                                                   \
    do {                                                                         \
        std::fprintf(stderr, "[UNIMPL INSN] rip=0x%llx mnemonic=%s\n",           \
                     (unsigned long long)(RIP), (MNEM));                         \
        if (mew_unimpl_continue()) return;                                       \
        std::abort();                                                            \
    } while (0)

#define UNIMPL_API(NAME)                                                         \
    do {                                                                         \
        std::fprintf(stderr, "[UNIMPL API] %s\n", (NAME));                       \
        if (mew_unimpl_continue()) { ctx->rax = 0; return; }                     \
        std::abort();                                                            \
    } while (0)

#define UNIMPL_FUNC(VA)                                                          \
    do {                                                                         \
        std::fprintf(stderr, "[UNIMPL FUNC] va=0x%llx\n",                        \
                     (unsigned long long)(VA));                                  \
        if (mew_unimpl_continue()) return;                                       \
        std::abort();                                                            \
    } while (0)

// 由生成的 dispatch_table.cpp 提供
void init_dispatch_table(const char* extra_url = nullptr, void* extra = nullptr);
