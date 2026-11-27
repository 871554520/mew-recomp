#pragma once
// 方案书 4.2：寄存器上下文与间接调用分发表
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/mman.h>
#include "guest_heap.h"
#include <unistd.h>
#include <unordered_map>
#include <algorithm>
#include <vector>
#include <map>
#include <mutex>

struct X64Ctx;  // 前向声明：环形追踪与 SSE 辅助早于完整定义

// 运行时兜底桥（定义在 shims/win32_kernel32.cpp）：按 API 名直接执行垫片。
// dispatch_indirect 遇到「未绑定的 IAT 槽」时把槽里的 RVA 解成 API 名，再经这里调用实现。
extern "C" int mew_call_api_by_name(const char* name, X64Ctx* ctx);

struct alignas(16) XmmReg {
    union {
        uint8_t  u8[16];
        uint16_t u16[8];
        uint32_t u32[4];
        uint64_t u64[2];
        float    f32[4];
        double   f64[2];
    };
};

struct TraceEntry {
    uint64_t va;
    const char* tag;   // 普通函数为 nullptr，垫片传 API 名
    uint64_t rcx;
    uint64_t ret;      // 调用点（函数入口时的返回地址），用于定位是谁调的这一层
};

struct CallRingTrace {
    static constexpr size_t N = 64;
    TraceEntry buf[N]{};
    size_t idx = 0;

    void push(uint64_t va, const char* tag, uint64_t rcx, uint64_t ret = 0) {
        buf[idx & (N - 1)] = TraceEntry{va, tag, rcx, ret};
        idx++;
    }

    // 只打印最后 n 帧（周期采样用）
    void dump_tail(size_t n) const {
        size_t start = idx > n ? idx - n : 0;
        for (size_t i = start; i < idx; ++i) {
            const auto& e = buf[i & (N - 1)];
            if (e.tag) std::fprintf(stderr, "    [%zu] API  %s\n", i, e.tag);
            else std::fprintf(stderr, "    [%zu] FUNC sub_0x%llx (rcx=0x%llx)\n", i,
                              (unsigned long long)e.va, (unsigned long long)e.rcx);
        }
    }

    void dump(const char* reason) const {
        std::fprintf(stderr, "\n===== CALL RING TRACE (%s) =====\n", reason);
        size_t start = idx > N ? idx - N : 0;
        for (size_t i = start; i < idx; ++i) {
            const auto& e = buf[i & (N - 1)];
            if (e.tag)
                std::fprintf(stderr, "  [%zu] API  %s (rcx=0x%llx ret=0x%llx)\n", i, e.tag,
                             (unsigned long long)e.rcx, (unsigned long long)e.ret);
            else
                std::fprintf(stderr, "  [%zu] FUNC sub_0x%llx (rcx=0x%llx ret=0x%llx)\n", i,
                             (unsigned long long)e.va, (unsigned long long)e.rcx,
                             (unsigned long long)e.ret);
        }
        std::fprintf(stderr, "====================================\n");
    }
};

inline CallRingTrace& call_trace() {
    static thread_local CallRingTrace t;
    return t;
}

inline X64Ctx*& cur_ctx_ptr() {
    static X64Ctx* p = nullptr;
    return p;
}

inline uint64_t& cur_fn_va() {
    static uint64_t v = 0;
    return v;
}

// 入口观测：MEW_TRACE_FN=0x<va> 时，每次进入该函数打印一次寄存器快照（前 40 次）。
inline const std::vector<uint64_t>& mew_trace_fns() {
    static const std::vector<uint64_t> v = [] {
        std::vector<uint64_t> out;
        const char* e = std::getenv("MEW_TRACE_FN");
        if (!e) return out;
        const char* p = e;
        while (*p) {
            char* end = nullptr;
            unsigned long long x = std::strtoull(p, &end, 0);
            if (end == p) break;
            out.push_back((uint64_t)x);
            p = end;
            while (*p == ',' || *p == ' ') ++p;
        }
        return out;
    }();
    return v;
}

// 支持 `MEW_TRACE_FN=0xaaa,0xbbb`：多个函数一起观测（入口 + 返回点都会打印）。
inline bool mew_trace_match(uint64_t va) {
    for (uint64_t x : mew_trace_fns()) if (x == va) return true;
    return false;
}

inline uint64_t mew_trace_fn() {
    const auto& v = mew_trace_fns();
    return v.empty() ? 0ULL : v.front();
}

// MEW_TRACE_MEM=0x<va>[,0x<va>...]：配合 MEW_TRACE_FN，进入被观测函数时
// 依次打印这些固定地址的 qword 内容。用来一次性看清「哨兵全局 / cookie / 链表头」
// 到底是什么值（例子：0x1413bb4e8,0x1413bb500,0x1412f2880）。
inline const std::vector<uint64_t>& mew_trace_mem() {
    static const std::vector<uint64_t> v = [] {
        std::vector<uint64_t> out;
        const char* e = std::getenv("MEW_TRACE_MEM");
        if (!e) return out;
        const char* p = e;
        while (*p) {
            char* end = nullptr;
            unsigned long long x = std::strtoull(p, &end, 0);
            if (end == p) break;
            out.push_back((uint64_t)x);
            p = end;
            while (*p == ',' || *p == ' ') ++p;
        }
        return out;
    }();
    return v;
}

// 活锁刹车：run 45951868177 出现过「同一个 compare 被调用 2.67 亿次」的活锁，
// 表现为 SAFE 趟 timeout（不是慢，是死循环），整轮只拿到一条 SAMPLE，诊断价值极低。
// 这里在函数入口统计「连续相同 (VA, rcx, rdx)」的次数，超过阈值就 dump 调用环并 abort，
// 把超时变成一次带现场的崩溃。MEW_LIVELOCK_N 可调，0 表示关闭。
inline uint64_t& mew_livelock_n() {
    static uint64_t v = [] {
        const char* e = std::getenv("MEW_LIVELOCK_N");
        if (e) return (uint64_t)std::strtoull(e, nullptr, 0);
        return (uint64_t)20000000ULL;   // 默认 2000 万次，正常循环远远到不了
    }();
    return v;
}
inline void mew_livelock_note(uint64_t va, uint64_t rcx, uint64_t rdx) {
    const uint64_t limit = mew_livelock_n();
    if (!limit) return;
    // 指纹：把 (VA, rcx, rdx) 混成一个数，便于比较"两步前"的状态。
    uint64_t fp = va * 0x9E3779B97F4A7C15ULL;
    fp ^= (rcx + 0x165667B19E3779F9ULL) * 0xC2B2AE3D27D4EB4FULL;
    fp ^= (rdx + 0x27D4EB2F165667C5ULL) * 0x9E3779B185EBCA87ULL;
    // run 45953571612 的活锁是**二周期** A,B,A,B…（memcmp / string::compare 交替），
    // 每一步的 (VA,rcx,rdx) 都在变，所以"连续相同"永远凑不满。
    // 这里同时检测"与两步前相同"的跑长度，二周期才会被抓住。
    static uint64_t prev1 = 0, prev2 = 0, run_same = 0, run_cycle = 0;
    if (fp == prev2) {
        if (++run_cycle >= limit) {
            std::fprintf(stderr,
                "[LIVELOCK] 二周期 fp=0x%llx va=0x%llx rcx=0x%llx 连续 %llu 次（阈值 %llu）\n",
                (unsigned long long)fp, (unsigned long long)va,
                (unsigned long long)rcx, (unsigned long long)run_cycle,
                (unsigned long long)limit);
            call_trace().dump("livelock");
            std::abort();
        }
    } else {
        run_cycle = 0;
    }
    prev2 = prev1;
    prev1 = fp;
    static uint64_t last_va = 0, last_rcx = 0, last_rdx = 0, run = 0;
    if (va == last_va && rcx == last_rcx && rdx == last_rdx) {
        if (++run >= limit) {
            std::fprintf(stderr,
                "[LIVELOCK] va=0x%llx rcx=0x%llx rdx=0x%llx 连续 %llu 次（阈值 %llu）\n",
                (unsigned long long)va, (unsigned long long)rcx,
                (unsigned long long)rdx, (unsigned long long)run,
                (unsigned long long)limit);
            call_trace().dump("livelock");
            std::abort();
        }
    } else {
        last_va = va; last_rcx = rcx; last_rdx = rdx; run = 1;
    }
}

// 是否已经进过 exe 的 main（0x1409b5230）。
// 依据：`ret` 被 lift 成 `ctx->rsp += 8; return;`，也就是**每个 guest 函数都直接返回
// 到宿主**。所以我们从 _initterm 内部 resume 回去以后，_initterm 跑完最后一条 `ret`
// 是 return 回宿主，而不是"回到 __scrt_common_main_seh 继续调 main"——main 天然不会跑。
// 必须在链尾显式补一次 main，但要先确认它没被跑过，否则会重复初始化。
inline bool& mew_saw_main() {
    static bool v = false;
    return v;
}
inline void mew_note_entry(uint64_t va) {
    if (va == 0x1409b5230ULL) mew_saw_main() = true;
}

#define MEW_SET_CUR_FN(CTX, VA)                                                   \
    do {                                                                          \
        cur_ctx_ptr() = (CTX);                                                    \
        cur_fn_va() = (uint64_t)(VA);                                             \
        mew_note_entry((uint64_t)(VA));                                           \
        mew_livelock_note((uint64_t)(VA), (CTX)->rcx, (CTX)->rdx);                \
        call_trace().push((uint64_t)(VA), nullptr, (CTX)->rcx, mew_guest_ret(CTX)); \
        {                                                                         \
            FnEntryFrame& _f = fn_entry_frame();                                  \
            _f.rsp = (CTX)->rsp; _f.rbx = (CTX)->rbx; _f.rbp = (CTX)->rbp;        \
            _f.rsi = (CTX)->rsi; _f.rdi = (CTX)->rdi; _f.r12 = (CTX)->r12;        \
            _f.r13 = (CTX)->r13; _f.r14 = (CTX)->r14; _f.r15 = (CTX)->r15;        \
            _f.valid = true;                                                      \
        }                                                                         \
        if (mew_trace_match((uint64_t)(VA))) {                                   \
            static int _mew_tn = 0;                                               \
            if (_mew_tn++ < 40) {                                                 \
                std::fprintf(stderr,                                               \
                    "[fn] 0x%llx rcx=0x%llx rdx=0x%llx r8=0x%llx r9=0x%llx rsp=0x%llx rax=0x%llx\n", \
                    (unsigned long long)(VA), (unsigned long long)(CTX)->rcx,      \
                    (unsigned long long)(CTX)->rdx, (unsigned long long)(CTX)->r8, \
                    (unsigned long long)(CTX)->r9, (unsigned long long)(CTX)->rsp, \
                    (unsigned long long)(CTX)->rax);                              \
                /* callee-saved 也要打：0x140385f80 里紧跟容量检查的是            \
                   `cmp [_Mysize], r12` + `je <too long>`，r12 的取值直接分流     \
                   「第 9 次被一个假的 max_size 卡住」和「该 rehash 却没 rehash」。*/ \
                std::fprintf(stderr,                                               \
                    "[fn]   rbx=0x%llx rsi=0x%llx rdi=0x%llx rbp=0x%llx "          \
                    "r12=0x%llx r13=0x%llx r14=0x%llx r15=0x%llx\n",              \
                    (unsigned long long)(CTX)->rbx, (unsigned long long)(CTX)->rsi, \
                    (unsigned long long)(CTX)->rdi, (unsigned long long)(CTX)->rbp, \
                    (unsigned long long)(CTX)->r12, (unsigned long long)(CTX)->r13, \
                    (unsigned long long)(CTX)->r14, (unsigned long long)(CTX)->r15); \
                mew_probe_qword("[fn:rcx+0x88]", (CTX)->rcx + 0x88);              \
                mew_probe_qword("[fn:rdx]", (CTX)->rdx);                          \
                for (uint64_t _a : mew_trace_mem()) {                              \
                    mew_probe_qword("[mem]", _a);                                   \
                    mew_probe_triple("[triple]", _a);                               \
                }                                                                   \
                mew_probe_chain("[fn:[[rcx]]]", (CTX)->rcx);                      \
            }                                                                     \
        }                                                                         \
    } while (0)
// 最近一次进入的垫片（Win32 API）名字。垫片不经过 MEW_SET_CUR_FN，所以
// cur_fn_va() 会停在调用者的函数上，`[SAFE]` 日志就指错人；有了这个名字，
// 能直接看出「是不是垫片里写崩的、是哪个垫片」。
// 最近一条「做内存写」的 guest 指令地址。由 lifter 在每次 storeExpr 前写一次，
// SAFE 日志带上它，就能把「在哪个函数里」精确到「哪一条指令」。
inline uint64_t& last_mem_pc() {
    static uint64_t v = 0;
    return v;
}
inline const char*& cur_api_name() {
    static const char* v = "";
    return v;
}
#define MEW_TRACE_API(CTX, NAME) \
    do {                                                                       \
        cur_api_name() = (NAME);                                               \
        call_trace().push(0, (NAME), (CTX)->rcx, mew_guest_ret(CTX));          \
    } while (0)

struct X64Ctx {
    uint64_t rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    XmmReg   xmm[16];
    // AVX：x86-64 只有 16 个 XMM 寄存器，VEX 编码把它们扩成 256 位（YMM）。
    // 项目原本只建模低 128 位；这里单独存每个寄存器的高 128 位，避免改动 XmmReg
    // 影响已有的生成代码（它们都按 xmm[i].u64[0/1] 访问）。
    // 规矩（与真机一致）：VEX **128 位**写操作会把高 128 位清零；只有 256 位写才动它。
    alignas(16) uint8_t ymm_hi[16][16];
    bool zf, sf, cf, of, pf, df;
    int64_t mem_bias;
    uint64_t gs_base;   // 伪 TEB 的 guest 地址（gs:[disp] 路由到这里）
    uint64_t fs_base;
};

// 函数入口帧快照：占位指令（UNIMPL_INSN）让函数"提前 return"时，
// 会把 epilogue 整段跳过 —— rsp 不平、rbx/rbp/rsi/rdi/r12-r15 停在被改写后的值。
// 实测代价：__acrt_initialize_locks 清空 rbx 后撞到占位直接返回，
// 调用方 __acrt_execute_initializers 的 `add rbx,0x10; mov rax,[rbx]` 就读到 [0x10] 崩掉。
// 因此占位返回前必须把入口帧原样恢复，保证 ABI 干净。
struct FnEntryFrame {
    uint64_t rsp, rbx, rbp, rsi, rdi, r12, r13, r14, r15;
    bool valid;
};
inline FnEntryFrame& fn_entry_frame() {
    static thread_local FnEntryFrame f{};
    return f;
}
inline void restore_entry_frame(X64Ctx* c) {
    const FnEntryFrame& f = fn_entry_frame();
    if (!f.valid || !c) return;
    c->rsp = f.rsp;
    c->rbx = f.rbx;
    c->rbp = f.rbp;
    c->rsi = f.rsi;
    c->rdi = f.rdi;
    c->r12 = f.r12;
    c->r13 = f.r13;
    c->r14 = f.r14;
    c->r15 = f.r15;
}


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

inline void record_missing_entry(uint64_t target_va, uint64_t caller_fn) {
    if (target_va >= 0x140001000ULL && target_va < 0x140e3f000ULL) {
        if (FILE* fp = std::fopen("discovered_entries.txt", "a")) {
            std::fprintf(fp, "0x%llx # caller=0x%llx\n",
                         (unsigned long long)target_va, (unsigned long long)caller_fn);
            std::fclose(fp);
        }
    }
}

// 合成地址（0x5000000xx）调用追踪钩子：post=0 调用前，post=1 调用后。
using ApiTraceHook = void (*)(uint64_t, X64Ctx*, int);
inline ApiTraceHook& api_trace_hook() {
    static ApiTraceHook h = nullptr;
    return h;
}

// ABI 守卫：Win64 规定 rbx/rbp/rsi/rdi/r12-r15 由被调方保存恢复。
// 若某个转译函数或垫片没恢复，上层循环（例如 __acrt_execute_initializers 的
// `mov rax,[rbx]` / `add rbx,0x10`）就会读到垃圾地址。
inline bool mew_abi_guard_on() {
    static int v = [] { const char* e = std::getenv("MEW_ABI_GUARD"); return (e && e[0] == '1') ? 1 : 0; }();
    return v == 1;
}

struct AbiSnapshot {
    uint64_t rbx, rbp, rsi, rdi, r12, r13, r14, r15, rsp;
};
inline AbiSnapshot abi_snap(const X64Ctx* c) {
    return AbiSnapshot{c->rbx, c->rbp, c->rsi, c->rdi, c->r12, c->r13, c->r14, c->r15, c->rsp};
}
inline void abi_check(X64Ctx* c, const AbiSnapshot& s, uint64_t target, uint64_t caller);

// MEW_STACK_REPAIR=1：调用边界强制平衡模拟栈。
// 实测存在 rsp 逐层漏 8 字节（-8/-24/-48/-64），会让 MSVC 的 stack cookie
// （xor rsp）校验失败 → __fastfail(2)。修复前先用它把执行流推过去。
inline bool mew_stack_repair_on() {
    static int v = [] { const char* e = std::getenv("MEW_STACK_REPAIR"); return (e && e[0] == '1') ? 1 : 0; }();
    return v == 1;
}

// 调用点用：期望返回后 rsp == 调用前的 rsp + push 的数量（direct call 压 1 个）
inline void abi_guard_after_call(X64Ctx* ctx, const AbiSnapshot& s, uint64_t target, uint64_t caller,
                                 long long expect_delta) {
    if (mew_stack_repair_on()) {
        long long d = (long long)(ctx->rsp - s.rsp);
        if (d != expect_delta) {
            static int fixed = 0;
            if (fixed++ < 40)
                std::fprintf(stderr, "[rsp-repair] target=0x%llx caller=0x%llx delta=%lld -> %lld\n",
                             (unsigned long long)target, (unsigned long long)caller, d, expect_delta);
            ctx->rsp = s.rsp + (uint64_t)expect_delta;
        }
    }
    abi_check(ctx, s, target, caller);
}

inline void abi_check(X64Ctx* c, const AbiSnapshot& s, uint64_t target, uint64_t caller) {
    static int logged = 0;
    static int repaired = 0;
    const long long dsp = (long long)(c->rsp - s.rsp);
    const bool reg_bad = c->rbx != s.rbx || c->rbp != s.rbp || c->rsi != s.rsi || c->rdi != s.rdi ||
                         c->r12 != s.r12 || c->r13 != s.r13 || c->r14 != s.r14 || c->r15 != s.r15;
    // 调用边界恢复 callee-saved 是 x64 ABI 的**硬保证**（rbx/rbp/rsi/rdi/r12-r15 由被调方
    // 负责恢复），所以按快照写回**等价于严格执行 ABI**，不改变语义。
    // 需要它的原因：我们在「跨 fragment / 共享序言尾声」这类边界上偶尔恢复不全——
    // 实测 0x140386180 返回时 rsi/rdi 被下游覆盖（rsi:0x10013eb0->0x1413c60c8、
    // rdi:0x100021a0->0x200），把 caller 的循环指针毁掉，于是插入循环无限跑
    // （map size 一路涨到 65/223 才被 timeout 掐掉）。
    // 跟着 MEW_STACK_REPAIR 开关走：线上实验阶段默认开，修复完边界问题可以关掉验证。
    if (reg_bad && mew_stack_repair_on()) {
        if (repaired++ < 40)
            std::fprintf(stderr,
                "[abi-repair] target=0x%llx caller=0x%llx 恢复 callee-saved "
                "rbx:0x%llx->0x%llx rsi:0x%llx->0x%llx rdi:0x%llx->0x%llx rbp:0x%llx->0x%llx\n",
                (unsigned long long)target, (unsigned long long)caller,
                (unsigned long long)c->rbx, (unsigned long long)s.rbx,
                (unsigned long long)c->rsi, (unsigned long long)s.rsi,
                (unsigned long long)c->rdi, (unsigned long long)s.rdi,
                (unsigned long long)c->rbp, (unsigned long long)s.rbp);
        c->rbx = s.rbx; c->rbp = s.rbp; c->rsi = s.rsi; c->rdi = s.rdi;
        c->r12 = s.r12; c->r13 = s.r13; c->r14 = s.r14; c->r15 = s.r15;
    }
    if (logged > 40) return;
    const bool bad = reg_bad || (dsp != 0 && dsp != 8);
    if (!bad) return;
    ++logged;
    call_trace().dump("abi-violation");
    std::fprintf(stderr,
        "[ABI VIOLATION] target=0x%llx caller=0x%llx rbx:0x%llx->0x%llx rsi:0x%llx->0x%llx "
        "rdi:0x%llx->0x%llx rbp:0x%llx->0x%llx rsp_delta=%lld\n",
        (unsigned long long)target, (unsigned long long)caller,
        (unsigned long long)s.rbx, (unsigned long long)c->rbx,
        (unsigned long long)s.rsi, (unsigned long long)c->rsi,
        (unsigned long long)s.rdi, (unsigned long long)c->rdi,
        (unsigned long long)s.rbp, (unsigned long long)c->rbp, dsp);
}

// is_call=true 表示这是 call（调用方已经 push 了模拟返回地址）；
// 目标若是合成地址上的垫片，垫片不会执行 ret，必须由这里补一次 rsp += 8，
// 否则返回地址永久留在栈上，调用方的 add rsp,0x20 / pop rbx 全部错位。
// 观测某个调用方发出的每一次间接调用（用于看清初始化器循环的完整顺序）
inline uint64_t mew_trace_caller() {
    static uint64_t v = [] {
        const char* e = std::getenv("MEW_TRACE_CALLER");
        return e ? (uint64_t)std::strtoull(e, nullptr, 0) : 0ULL;
    }();
    return v;
}

// 返回点观测：MEW_TRACE_FN 指定的函数在 ret 前打印 rbx/rsi/rdi/rsp
inline void mew_ret_trace(X64Ctx* c) {
    if (!c) return;
    if (!mew_trace_match(cur_fn_va())) return;
    static int n = 0;
    if (n++ > 60) return;
    std::fprintf(stderr, "[ret] fn=0x%llx rbx=0x%llx rsi=0x%llx rdi=0x%llx rsp=0x%llx rax=0x%llx\n",
                 (unsigned long long)cur_fn_va(), (unsigned long long)c->rbx,
                 (unsigned long long)c->rsi, (unsigned long long)c->rdi,
                 (unsigned long long)c->rsp, (unsigned long long)c->rax);
}
#define MEW_RET_TRACE(CTX) mew_ret_trace(CTX)

inline bool tracer_note(bool on, uint64_t target, bool is_call, uint64_t rsp0, uint64_t rbx0) {
    static int n = 0;
    if (!on || n >= 40) return false;
    std::fprintf(stderr, "[disp#%02d] target=0x%llx is_call=%d rsp_in=0x%llx rbx_in=0x%llx\n",
                 n + 1, (unsigned long long)target, (int)is_call,
                 (unsigned long long)rsp0, (unsigned long long)rbx0);
    ++n;
    return true;
}
inline void tracer_done(bool on, uint64_t target, X64Ctx* c) {
    if (!on || !c) return;
    std::fprintf(stderr, "        -> done target=0x%llx rsp_out=0x%llx rbx=0x%llx rsi=0x%llx rdi=0x%llx\n",
                 (unsigned long long)target, (unsigned long long)c->rsp,
                 (unsigned long long)c->rbx, (unsigned long long)c->rsi,
                 (unsigned long long)c->rdi);
}

// ---- 间接调用环形缓冲（MEW_TRACE_IND=1）----
// 为什么不是「前 300 行」：卡死发生在 29 分钟之后，前 300 行全被开头几分钟的
// 普通间接调用占满，反而拿不到卡死那一次。这里只保留**最后 64 条**，
// 由 mew_ind_dump() 在 timeout/崩溃时吐出来。
struct IndRec { uint64_t target, caller; uint8_t is_call, in_tbl; };
inline IndRec* mew_ind_ring() {
    static IndRec buf[64];
    return buf;
}
inline uint64_t& mew_ind_head() {
    static uint64_t h = 0;
    return h;
}
inline void mew_ind_note(uint64_t target, uint64_t caller, bool is_call, bool in_tbl) {
    IndRec* b = mew_ind_ring();
    const uint64_t h = mew_ind_head();
    b[h & 63].target = target;
    b[h & 63].caller = caller;
    b[h & 63].is_call = is_call ? 1 : 0;
    b[h & 63].in_tbl = in_tbl ? 1 : 0;
    mew_ind_head() = h + 1;
}
inline void mew_ind_dump() {
    const uint64_t h = mew_ind_head();
    if (!h) return;
    const uint64_t n = h < 64 ? h : 64;
    std::fprintf(stderr, "[indring] 最近 %llu 条间接调用/跳转（共 %llu 条）:\n",
                 (unsigned long long)n, (unsigned long long)h);
    for (uint64_t i = 0; i < n; ++i) {
        const IndRec& r = mew_ind_ring()[(h - n + i) & 63];
        std::fprintf(stderr, "[indring] target=0x%llx caller=0x%llx is_call=%d in_tbl=%d\n",
                     (unsigned long long)r.target, (unsigned long long)r.caller,
                     (int)r.is_call, (int)r.in_tbl);
    }
    std::fflush(stderr);
}

// 前置声明：下面 dispatch_indirect 的「未绑定 IAT 槽」分支要用 guest_mapped / mem_read，
// 而它们的定义在文件更后面（shim-syntax 门禁 run 46047193129 报的就是这里）。
inline bool guest_mapped(uint64_t addr, size_t n);
template <typename T>
inline T mem_read(X64Ctx* ctx, uint64_t guest_addr);

inline void dispatch_indirect(uint64_t target_va, X64Ctx* ctx, bool is_call = false) {
    const bool trace_this = mew_trace_caller() && cur_fn_va() == mew_trace_caller();
    const uint64_t t_rsp0 = ctx ? ctx->rsp : 0;
    const uint64_t t_rbx0 = ctx ? ctx->rbx : 0;
    const bool t_hit = tracer_note(trace_this, target_va, is_call, t_rsp0, t_rbx0);
    (void)t_hit;
    auto& tbl = g_dispatch_table();
    auto it = tbl.find(target_va);
    // 诊断（MEW_TRACE_IND=1）：把每个间接跳转/调用的**运行时解析目标**打出来。
    // run 46023439342 卡死在 0x140d1f7e4 的 `call qword [rip+0x11fe17]` 上：29 条
    // [SAMPLE] 的 rsp 一模一样，说明卡在那次调用里没返回。槽位 0x140e3f620 在文件里
    // 是字面量 0x12e651a（.reloc 里没有 DIR64），若运行时还是它，目标根本不在镜像里；
    // 若变成了别的地址，那就是我们 loader 的重定位/初始化把它改写了 —— 两种结论要
    // shim 的对象完全不同，所以先把实际值打出来。最多 300 行，避免刷爆日志。
    if (const char* ti = std::getenv("MEW_TRACE_IND")) {
        if (ti[0] == '1') {
            mew_ind_note(target_va, cur_fn_va(), is_call, it != tbl.end());
            static int ind_logged = 0;
            if (ind_logged < 20) {
                ++ind_logged;
                std::fprintf(stderr, "[ind] #%d target=0x%llx caller=0x%llx is_call=%d in_tbl=%d\n",
                             ind_logged, (unsigned long long)target_va,
                             (unsigned long long)cur_fn_va(), (int)is_call,
                             (int)(it != tbl.end() ? 1 : 0));
            }
        }
    }
    if (it != tbl.end()) {
        const bool guard = mew_abi_guard_on();
        const uint64_t caller = cur_fn_va();
        AbiSnapshot snap = guard ? abi_snap(ctx) : AbiSnapshot{};
        if (target_va >= 0x500000000ULL && target_va < 0x500100000ULL) {
            if (api_trace_hook()) api_trace_hook()(target_va, ctx, 0);
            it->second(ctx);
            if (guard) abi_check(ctx, snap, target_va, caller);
            if (api_trace_hook()) api_trace_hook()(target_va, ctx, 1);
            // 垫片替代了目标函数体，目标函数本该用 ret 弹一次返回地址；
            // 无论外层是 call 还是尾跳（含 CFG 蹦床 jmp rax），都必须由这里补弹。
            (void)is_call;
            ctx->rsp += 8;
            tracer_done(trace_this, target_va, ctx);
            cur_fn_va() = caller;
            return;
        }
        const uint64_t rsp_in = ctx ? ctx->rsp : 0;
        it->second(ctx);
        if (guard) abi_check(ctx, snap, target_va, caller);
        // 栈纪律兜底（run 45937873457 定的案）：
        //   call 形态：调用方已经 push 了模拟返回地址，被调函数正常收尾会让 rsp 恰好 +8；
        //   尾跳形态：**不要动**。CFG 蹦床（call 0x140dab670 = jmp [slot]）和 TLS 回调
        //   都会让 rsp 合法地偏离入口值——被调代码自己的 ret 会弹掉上一层压的返回地址，
        //   强行拉回等于把那次 pop 抵消掉。实测这样会制造一串「修了又被修回来」的噪声
        //   （[rsp-fix] 成对出现 target=0x140dab670 is_call=1 与 is_call=0）。
        // 被调函数只要中途因为「未实现间接跳转」在收集模式下提前 return，就走不到自己的
        // ret，这 8 字节永久留在栈上：上层函数收尾时 mov rbx,[rsp+0x30] / pop rdi 全部
        // 错位一格，实测 rbx 被读成返回地址 0x140d6a947、rdi 从 0x20 变 0，
        // 随后 lea r9,[r14+rbx*8] 算出 0xa16b57c28，崩在 mov [r9],rdx。
        if (ctx && is_call) {
            const uint64_t want = rsp_in + 8;
            if (ctx->rsp != want) {
                static int rsp_fixed = 0;
                if (rsp_fixed++ < 20)
                    std::fprintf(stderr,
                                 "[rsp-fix] target=0x%llx caller=0x%llx is_call=1 rsp=0x%llx -> 0x%llx\n",
                                 (unsigned long long)target_va, (unsigned long long)caller,
                                 (unsigned long long)ctx->rsp, (unsigned long long)want);
                ctx->rsp = want;
            }
        } else if (ctx && ctx->rsp != rsp_in) {
            static int tail_logged = 0;
            if (tail_logged++ < 10)
                std::fprintf(stderr,
                             "[rsp-tail] target=0x%llx caller=0x%llx 尾跳 rsp 偏离 0x%llx -> 0x%llx（不动）\n",
                             (unsigned long long)target_va, (unsigned long long)caller,
                             (unsigned long long)rsp_in, (unsigned long long)ctx->rsp);
        }
        tracer_done(trace_this, target_va, ctx);
        cur_fn_va() = caller;   // 恢复调用者：否则返回点/SAFE 日志会指到被调函数
        return;
    }
    // 未解析的导入 → 函数指针就是 0，guest 会 `call 0` / `jmp 0`。真机上这是崩溃，
    // 在这个移植里却是**可选功能没实现**的正常表现：steam_api64 是 LoadLibrary +
    // GetProcAddress 动态取的，GetProcAddress 对未知名字返回 0，调用方不判空就直接调
    // （[main] 之后第一道墙，见复盘 0.6 节：SteamInternal_ContextInit / SteamAPI_RunCallbacks）。
    // 所以 target==0 单独处理成「返回 0 的空桩」：call 形态补弹返回地址，然后继续跑。
    // 其它未映射目标仍然是 FATAL —— 那些是「地址算错了」或「真入口没登记」，
    // 静默吞掉会把真正的问题藏起来（thunk 那次就是靠 FATAL 才定案的）。
    if (!target_va) {
        static int null_logged = 0;
        if (null_logged++ < 20)
            std::fprintf(stderr,
                         "[api] indirect call target=0（未解析的导入）in_fn=0x%llx is_call=%d -> 当作返回 0\n",
                         (unsigned long long)cur_fn_va(), (int)is_call);
        // 前三次把调用环尾巴打出来：`call [rsp+0x38]` 这种站点的"0"到底是谁传下来的，
        // 只有看调用链才知道（run 46047307348 的三次视频初始化失败全靠这条定位）。
        if (null_logged <= 3) call_trace().dump("null-target");
        if (ctx) {
            ctx->rax = 0;
            if (is_call) ctx->rsp += 8;
        }
        tracer_done(trace_this, target_va, ctx);
        return;
    }
    // ---- 未绑定的 IAT 槽（P0-A）------------------------------------------
    // `call qword [0x140e3f620]` 这种槽如果**没被 lifter 枚举到**（延迟导入、或描述符
    // 被跳过），运行期读到的还是文件里的原值：一个指向 IMAGE_IMPORT_BY_NAME 的 RVA
    // （实测 0x12e651a，落在 .rdata）。真值本应是函数指针，于是被当函数调 → FATAL/卡死。
    // 这里把 RVA 反解成 API 名并按「未实现的导入」处理（返回 0、调用形态补弹返回地址），
    // 既不再 abort，也让日志直接报出缺的是哪个 API。
    {
        static const uint64_t kImageBase = 0x140000000ULL;
        if (ctx && target_va >= 0x1000 && target_va < kImageBase) {
            char api[128] = {0};
            const uint64_t name_va = kImageBase + target_va + 2;   // 跳过 WORD hint
            if (guest_mapped(name_va, 1)) {
                for (int i = 0; i < 127; ++i) {
                    const char ch = (char)mem_read<uint8_t>(ctx, name_va + (uint64_t)i);
                    if (!ch) break;
                    api[i] = ch;
                }
            }
            static int iat_logged = 0;
            const bool handled = api[0] && mew_call_api_by_name(api, ctx) != 0;
            if (iat_logged++ < 40)
                std::fprintf(stderr,
                             "[iat-unbound] slot_rva=0x%llx api=%s in_fn=0x%llx is_call=%d -> %s\n",
                             (unsigned long long)target_va,
                             api[0] ? api : "<unreadable>",
                             (unsigned long long)cur_fn_va(), (int)is_call,
                             handled ? "调用垫片" : "返回 0");
            // api=<unreadable> 说明目标既不是镜像 RVA 也不是函数指针，而是**从栈/堆上读来的
            // 垃圾值**（实测 0x58 / 0x2 / 0x50934f30 / 0x7f34793ff700）。前三次打调用环，
            // 才能看出是谁把这种东西当函数指针传下来的。
            if (!api[0] && iat_logged <= 3) call_trace().dump("bad-pointer");
            if (handled) {
                if (is_call) ctx->rsp += 8;   // 与 lifter 改写路径一致：垫片返回后弹掉返回地址
                tracer_done(trace_this, target_va, ctx);
                return;
            }
            ctx->rax = 0;
            if (is_call) ctx->rsp += 8;
            tracer_done(trace_this, target_va, ctx);
            return;
        }
    }
    // 诊断：找最近的下界函数，判断是“函数内偏移”还是“完全在表外”
    auto& v = dispatch_vas();
    auto it2 = std::lower_bound(v.begin(), v.end(), target_va);
    uint64_t near_lo = 0;
    if (it2 != v.begin()) near_lo = *(it2 - 1);
    // 同一个 miss 目标可能出现几十万次（run 45937873457 的二次构建里 0x140dab8c8
    // 重复了 937727 次，单份日志被撑到 112 MB）。只对每个目标打前 3 次完整现场，
    // 之后每 10 万次补一行计数，既保住诊断信息又不让日志爆掉。
    static std::unordered_map<uint64_t, uint64_t> miss_hits;
    const uint64_t hits = ++miss_hits[target_va];
    const bool full = hits <= 3;
    if (full || hits % 100000 == 0)
        std::fprintf(stderr, "[FATAL] Unmapped indirect target: 0x%llx (nearest_lo=0x%llx delta=%lld) in_fn=0x%llx hits=%llu\n",
                     static_cast<unsigned long long>(target_va),
                     (unsigned long long)near_lo,
                     (long long)((int64_t)target_va - (int64_t)near_lo),
                     (unsigned long long)cur_fn_va(),
                     (unsigned long long)hits);
    // 目标落在镜像内、且该地址处是可打印 ASCII 时把字符串打出来：
    // 一眼区分「槽里是名字描述符」和「槽里是游戏数据指针」。
    // run 46051381022 的 `Unmapped indirect target: 0x140efc4ac` 查下去就是 ".rdata 里的 \"OK\""
    // —— 说明 SDL 弹窗函数把一个**指向字符串的指针**当函数调了，不是普通野指针。
    if (full && ctx && target_va >= 0x140000000ULL && target_va < 0x141570000ULL &&
        guest_mapped(target_va, 2)) {
        char txt[48];
        int n = 0;
        for (; n < 47; ++n) {
            const uint8_t ch = mem_read<uint8_t>(ctx, target_va + (uint64_t)n);
            if (ch < 32 || ch > 126) break;
            txt[n] = (char)ch;
        }
        txt[n] = 0;
        if (n >= 2) std::fprintf(stderr, "[FATAL]   该地址处是字符串 \"%s\"\n", txt);
    }
    // guard-dispatch 蹦床：槽里不是有效代码指针时，真正目标通常在 rax。
    // 但这个回退会自杀式递归（rax 常常就是调用者本身，实测 0x140d3e654 -> 0x140d6adc8
    // 无限循环到超时），因此默认关闭，只在显式要求时启用。
    static const bool allow_rax_fallback = [] {
        const char* e = std::getenv("MEW_GUARD_RAX_FALLBACK");
        return e && e[0] == '1';
    }();
    if (allow_rax_fallback && ctx && ctx->rax && ctx->rax != target_va) {
        auto it3 = tbl.find(ctx->rax);
        if (it3 != tbl.end()) {
            std::fprintf(stderr, "[shim] guard-dispatch fallback slot=0x%llx -> rax=0x%llx\n",
                         (unsigned long long)target_va, (unsigned long long)ctx->rax);
            it3->second(ctx);
            return;
        }
    }
    record_missing_entry(target_va, cur_fn_va());
    static int miss_logged = 0;
    if (miss_logged++ < 3) call_trace().dump("dispatch miss");
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

// 宿主地址是否真的映射（mincore 不触碰内存内容，只查页表）。
// 用于放行那些由垫片/系统库分配、但没经过我们登记表的合法堆地址。
inline bool host_page_mapped(uint64_t addr, size_t n) {
    static const long page = sysconf(_SC_PAGESIZE);
    if (!page) return false;
    uint64_t lo = addr & ~(uint64_t)(page - 1);
    uint64_t hi = (addr + n - 1) & ~(uint64_t)(page - 1);
    unsigned char vec = 0;
    for (uint64_t a = lo; a <= hi; a += (uint64_t)page)
        if (mincore(reinterpret_cast<void*>(a), (size_t)page, &vec) != 0) return false;
    return true;
}

inline bool guest_mapped(uint64_t addr, size_t n = 1) {
    if (!addr) return false;
    // O(1)：固定 Guest 堆池 / 镜像 / 栈区 都在这几条区间比较里
    if (g_guest_heap.contains(addr, n)) return true;
    for (const auto& r : guest_mem_ranges())
        if (addr >= r.lo && addr + n <= r.hi) return true;
    // 未登记的地址：交给宿主页表判断。bias=0 时 guest 地址就是宿主地址，
    // 这样 malloc/系统库给的内存不会被 SAFE_MEM 误杀（实测 0x140d6cb90 往堆对象写字段）。
    return host_page_mapped(addr, n);
}

// 函数/垫片入口处的返回地址（= guest 栈顶）。用来在调用环里定位"是谁调的这一层"。
inline uint64_t mew_guest_ret(X64Ctx* ctx) {
    if (!ctx) return 0;
    if (ctx->rsp <= 0x10000ULL || ctx->rsp >= 0x7fffffff0000ULL) return 0;
    if (!guest_mapped(ctx->rsp, 8)) return 0;
    uint64_t ret = 0;
    std::memcpy(&ret, reinterpret_cast<const void*>((uintptr_t)(ctx->rsp + ctx->mem_bias)), sizeof(ret));
    return ret;
}

// MEW_WATCH=0xaddr[,0xaddr...]：对指定地址的读写打点（定位"谁把它清零了"）。
inline std::vector<uint64_t>& mew_watch_addrs() {
    static std::vector<uint64_t> v = [] {
        std::vector<uint64_t> out;
        const char* e = std::getenv("MEW_WATCH");
        if (e) {
            std::string s(e);
            size_t p = 0;
            while (p <= s.size()) {
                size_t q = s.find(',', p);
                std::string tok = s.substr(p, q == std::string::npos ? std::string::npos : q - p);
                if (!tok.empty()) out.push_back(std::strtoull(tok.c_str(), nullptr, 0));
                if (q == std::string::npos) break;
                p = q + 1;
            }
        }
        return out;
    }();
    return v;
}
inline bool mew_watch_on() {
    static const bool on = !mew_watch_addrs().empty();
    return on;
}
inline uint64_t mew_bits(const void* p, size_t n) {
    uint64_t b = 0;
    if (n > 8) n = 8;
    std::memcpy(&b, p, n);
    return b;
}
inline bool mew_watch_hit(uint64_t addr, size_t n) {
    if (!mew_watch_on()) return false;
    for (uint64_t w : mew_watch_addrs())
        if (addr <= w && w < addr + n) return true;
    return false;
}

template <typename T>
inline T mem_read(X64Ctx* ctx, uint64_t guest_addr) {
    T v;
    std::memset(&v, 0, sizeof(T));
    if (mew_safe_mem() && !guest_mapped(guest_addr, sizeof(T))) {
        static int logged = 0;
        if (logged < 20) {
            std::fprintf(stderr,
                         "[SAFE] unmapped read addr=0x%llx size=%zu in_fn=0x%llx ret=0x%llx "
                         "rax=0x%llx rcx=0x%llx rdx=0x%llx rbx=0x%llx rsi=0x%llx rdi=0x%llx rbp=0x%llx rsp=0x%llx api=%s pc=0x%llx\n",
                         (unsigned long long)guest_addr, sizeof(T),
                         (unsigned long long)cur_fn_va(),
                         (unsigned long long)mew_guest_ret(ctx),
                         (unsigned long long)ctx->rax, (unsigned long long)ctx->rcx,
                         (unsigned long long)ctx->rdx, (unsigned long long)ctx->rbx,
                         (unsigned long long)ctx->rsi, (unsigned long long)ctx->rdi,
                         (unsigned long long)ctx->rbp, (unsigned long long)ctx->rsp,
                         cur_api_name()[0] ? cur_api_name() : "-",
                         (unsigned long long)last_mem_pc());
            if (logged < 3) call_trace().dump("safe-mem");
            ++logged;
        }
        return v;
    }
    std::memcpy(&v, reinterpret_cast<const void*>(guest_addr + ctx->mem_bias), sizeof(T));
    if (mew_watch_hit(guest_addr, sizeof(T))) {
        static int n = 0;
        // 上限从 60 提到 240：加了 mask/_Vec 五个地址以后，60 条预算会在
        // 初始化器第 3~4 次插入时就烧光，后面真正关键的"第 9 次"反而打不出来。
        if (n++ < 240)
            std::fprintf(stderr, "[watch] R addr=0x%llx size=%zu val=0x%llx in_fn=0x%llx\n",
                         (unsigned long long)guest_addr, sizeof(T),
                         (unsigned long long)mew_bits(&v, sizeof(T)),
                         (unsigned long long)cur_fn_va());
    }
    return v;
}

template <typename T>
inline void mem_write(X64Ctx* ctx, uint64_t guest_addr, T val) {
    if (mew_safe_mem() && !guest_mapped(guest_addr, sizeof(T))) {
        static int logged = 0;
        if (logged < 20) {
            std::fprintf(stderr,
                         "[SAFE] unmapped write addr=0x%llx size=%zu in_fn=0x%llx ret=0x%llx "
                         "rax=0x%llx rcx=0x%llx rdx=0x%llx rbx=0x%llx rsi=0x%llx rdi=0x%llx rbp=0x%llx rsp=0x%llx api=%s pc=0x%llx\n",
                         (unsigned long long)guest_addr, sizeof(T),
                         (unsigned long long)cur_fn_va(),
                         (unsigned long long)mew_guest_ret(ctx),
                         (unsigned long long)ctx->rax, (unsigned long long)ctx->rcx,
                         (unsigned long long)ctx->rdx, (unsigned long long)ctx->rbx,
                         (unsigned long long)ctx->rsi, (unsigned long long)ctx->rdi,
                         (unsigned long long)ctx->rbp, (unsigned long long)ctx->rsp,
                         cur_api_name()[0] ? cur_api_name() : "-",
                         (unsigned long long)last_mem_pc());
            if (logged < 3) call_trace().dump("safe-mem-w");
            ++logged;
        }
        return;
    }
    std::memcpy(reinterpret_cast<void*>(guest_addr + ctx->mem_bias), &val, sizeof(T));
    if (mew_watch_hit(guest_addr, sizeof(T))) {
        static int n = 0;
        if (n++ < 240)
            std::fprintf(stderr, "[watch] W addr=0x%llx size=%zu val=0x%llx in_fn=0x%llx\n",
                         (unsigned long long)guest_addr, sizeof(T),
                         (unsigned long long)mew_bits(&val, sizeof(T)),
                         (unsigned long long)cur_fn_va());
    }
}

// ---------------- 阶段 3 占位与日志 ----------------
// MEW_UNIMPL_CONTINUE=1 时只记录并返回（用于批量收集缺失项），否则中止
//
// 长跑（rc=124 被 timeout 杀掉）时逐行打印会淹掉日志、也没法一眼看出「还差哪些 API」。
// 所以每条占位同时记进聚合表，退出/收到 SIGTERM 前打一张按次数排序的表。
inline std::mutex& mew_unimpl_mu() {
    static std::mutex m;
    return m;
}
inline std::map<std::string, unsigned long long>& mew_unimpl_api_counts() {
    static std::map<std::string, unsigned long long> m;
    return m;
}
inline std::map<unsigned long long, unsigned long long>& mew_unimpl_func_counts() {
    static std::map<unsigned long long, unsigned long long> m;
    return m;
}

inline void mew_unimpl_note_api(const char* name) {
    std::lock_guard<std::mutex> lk(mew_unimpl_mu());
    mew_unimpl_api_counts()[name]++;
}
inline void mew_unimpl_note_func(unsigned long long va) {
    std::lock_guard<std::mutex> lk(mew_unimpl_mu());
    mew_unimpl_func_counts()[va]++;
}

// 打一张表：distinct 数 + 总次数 + 前若干项。
// 这个函数会在 SIGTERM 处理器里被调用（timeout 杀掉长跑进程前抢救统计），
// 所以刻意做到「不分配内存」：不加 vector、不排序，直接按 map 顺序打，条目数封顶。
// 互斥锁用 try_lock：拿不到就跳过，绝不把超时信号变成死锁。
inline void mew_unimpl_dump(const char* why) {
    std::unique_lock<std::mutex> lk(mew_unimpl_mu(), std::try_to_lock);
    if (!lk.owns_lock()) {
        std::fprintf(stderr, "\n[UNIMPL TABLE] skipped (%s): 统计锁被占用\n", why ? why : "?");
        std::fflush(stderr);
        return;
    }
    auto& a = mew_unimpl_api_counts();
    unsigned long long atotal = 0;
    for (const auto& kv : a) atotal += kv.second;
    std::fprintf(stderr, "\n===== UNIMPL API TABLE (%s) distinct=%zu total=%llu =====\n",
                 why ? why : "?", a.size(), atotal);
    size_t shown = 0;
    for (const auto& kv : a) {
        if (shown++ >= 20) { std::fprintf(stderr, "  ... 其余 %zu 项略\n", a.size() - 20); break; }
        std::fprintf(stderr, "  %-52s %llu\n", kv.first.c_str(), kv.second);
    }
    auto& f = mew_unimpl_func_counts();
    unsigned long long ftotal = 0;
    for (const auto& kv : f) ftotal += kv.second;
    std::fprintf(stderr, "===== UNIMPL FUNC TABLE (%s) distinct=%zu total=%llu =====\n",
                 why ? why : "?", f.size(), ftotal);
    shown = 0;
    for (const auto& kv : f) {
        if (shown++ >= 10) { std::fprintf(stderr, "  ... 其余 %zu 项略\n", f.size() - 10); break; }
        std::fprintf(stderr, "  0x%-16llx %llu\n", kv.first, kv.second);
    }
    std::fflush(stderr);
}

#define UNIMPL_INSN(RIP, MNEM)                                                   \
    do {                                                                         \
        std::fprintf(stderr, "[UNIMPL INSN] rip=0x%llx mnemonic=%s\n",           \
                     (unsigned long long)(RIP), (MNEM));                         \
        if (mew_unimpl_continue()) return;                                       \
        std::abort();                                                            \
    } while (0)

#define UNIMPL_API(NAME)                                                         \
    do {                                                                         \
        mew_unimpl_note_api(NAME);                                               \
        std::fprintf(stderr, "[UNIMPL API] %s\n", (NAME));                       \
        if (mew_unimpl_continue()) { ctx->rax = 0; return; }                     \
        std::abort();                                                            \
    } while (0)

#define UNIMPL_FUNC(VA)                                                          \
    do {                                                                         \
        mew_unimpl_note_func((unsigned long long)(VA));                          \
        std::fprintf(stderr, "[UNIMPL FUNC] va=0x%llx\n",                        \
                     (unsigned long long)(VA));                                  \
        if (mew_unimpl_continue()) return;                                       \
        std::abort();                                                            \
    } while (0)

// 整函数占位：打印缺失的助记符，并保持调用约定平衡。
// 被 call 进来时栈顶是模拟返回地址（call 前由调用方 push），返回前必须弹掉，
// 否则调用方 rsp 偏移 8 字节；被尾跳（jmp）进来时栈顶不是返回地址，不能弹。
inline bool mew_pop_if_retaddr(X64Ctx* c) {
    if (!c) return false;
    if (!guest_mapped(c->rsp, 8)) return false;
    uint64_t v = 0;
    std::memcpy(&v, reinterpret_cast<const void*>((uintptr_t)(c->rsp + c->mem_bias)), 8);
    if (v >= 0x140000000ULL && v < 0x141400000ULL) { c->rsp += 8; return true; }
    return false;
}

#define UNIMPL_FUNC_M(VA, MNEMS)                                                 \
    do {                                                                         \
        mew_unimpl_note_func((unsigned long long)(VA));                          \
        std::fprintf(stderr, "[UNIMPL FUNC] va=0x%llx missing=%s\n",             \
                     (unsigned long long)(VA), (MNEMS));                         \
        if (mew_unimpl_continue()) {                                             \
            mew_pop_if_retaddr(cur_ctx_ptr());                                   \
            return;                                                              \
        }                                                                        \
        std::abort();                                                            \
    } while (0)

// int N（N != 3）：x64 上 int 0x29 = __fastfail，int 0x2c = 断言。
// 旧实现把它当未知占位跳过，导致 CRT 致命路径被静默吞掉、后续空指针崩溃。
inline void mew_dump_guest_str(const char* tag, uint64_t va) {
    if (va < 0x140000000ULL || va >= 0x141400000ULL) return;
    if (!guest_mapped(va, 1)) return;
    const char* p = reinterpret_cast<const char*>((uintptr_t)(va + cur_ctx_ptr()->mem_bias));
    char buf[160];
    size_t n = 0;
    for (; n + 1 < sizeof(buf); ++n) {
        char c = p[n];
        if (!c) break;
        buf[n] = (c >= 0x20 && c < 0x7f) ? c : '.';
    }
    buf[n] = 0;
    if (n >= 2) std::fprintf(stderr, "    %s=0x%llx \"%s\"\n", tag,
                             (unsigned long long)va, buf);
}

// 读一个 guest 指针指向的 qword；不可映射时打印 n/a
// 读 [va] 得到指针 p，再依次打印 p、[p]、[p+8]、[p+0x10]。
// 用来一次看清「容器 -> 节点头 -> 节点三个字段」这条链（0x140d6a8b4 就是这么走的）。
inline void mew_probe_chain(const char* tag, uint64_t va) {
    if (!va || !guest_mapped(va, 8) || !cur_ctx_ptr()) {
        std::fprintf(stderr, "    %s=0x%llx -> n/a\n", tag, (unsigned long long)va);
        return;
    }
    uint64_t p = 0;
    std::memcpy(&p, reinterpret_cast<void*>(va + cur_ctx_ptr()->mem_bias), 8);
    std::fprintf(stderr, "    %s: ptr=0x%llx\n", tag, (unsigned long long)p);
    if (!p) return;
    for (int i = 0; i < 3; ++i) {
        uint64_t at = p + (uint64_t)i * 8;
        if (!guest_mapped(at, 8)) {
            std::fprintf(stderr, "    %s: [0x%llx] -> n/a\n", tag, (unsigned long long)at);
            continue;
        }
        uint64_t v = 0;
        std::memcpy(&v, reinterpret_cast<void*>(at + cur_ctx_ptr()->mem_bias), 8);
        std::fprintf(stderr, "    %s: [0x%llx] = 0x%016llx\n", tag,
                     (unsigned long long)at, (unsigned long long)v);
    }
}

// 一次打印 [va]、[va+8]、[va+0x10] 三个字段。用于容器全局
// （0x1413bb4e8 是 {begin,tail,end} 三连，三个都 cookie 表示空表，
// 只看第一个 qword 会误判成「装了编码值」）。
inline void mew_probe_triple(const char* tag, uint64_t va) {
    if (!va || !cur_ctx_ptr()) return;
    for (int i = 0; i < 3; ++i) {
        uint64_t at = va + (uint64_t)i * 8;
        if (!guest_mapped(at, 8)) {
            std::fprintf(stderr, "    %s[0x%llx] -> n/a\n", tag, (unsigned long long)at);
            continue;
        }
        uint64_t v = 0;
        std::memcpy(&v, reinterpret_cast<const void*>((uintptr_t)(at + cur_ctx_ptr()->mem_bias)), 8);
        std::fprintf(stderr, "    %s[0x%llx] = 0x%016llx\n", tag,
                     (unsigned long long)at, (unsigned long long)v);
    }
}

inline void mew_probe_qword(const char* tag, uint64_t va) {
    if (!va || !guest_mapped(va, 8) || !cur_ctx_ptr()) {
        std::fprintf(stderr, "    %s=0x%llx -> n/a\n", tag, (unsigned long long)va);
        return;
    }
    uint64_t v = 0;
    std::memcpy(&v, reinterpret_cast<const void*>((uintptr_t)(va + cur_ctx_ptr()->mem_bias)), 8);
    std::fprintf(stderr, "    %s=0x%llx -> 0x%llx\n", tag, (unsigned long long)va,
                 (unsigned long long)v);
}

// __fastfail 的 ecx 子码（附录 E / The Old New Thing）。0xC0000409 只是外壳，
// 真正原因在子码里；垫片里同时打印名字，避免被 STATUS_STACK_BUFFER_OVERRUN 误导。
inline const char* mew_fastfail_name(unsigned code) {
    switch (code) {
        case 0: return "LEGACY_GS_VIOLATION";
        case 1: return "VTGUARD_CHECK_FAILURE";
        case 2: return "STACK_COOKIE_CHECK_FAILURE";
        case 3: return "CORRUPT_LIST_ENTRY";
        case 4: return "INCORRECT_STACK";
        case 5: return "INVALID_ARG";
        case 6: return "GS_COOKIE_INIT";
        case 7: return "FATAL_APP_EXIT";
        case 8: return "RANGE_CHECK_FAILURE";
        default: return "UNKNOWN";
    }
}

#define MEW_FASTFAIL(CTX, RIP, CODE)                                             \
    do {                                                                         \
        std::fprintf(stderr, "[FASTFAIL] rip=0x%llx int=0x%x name=%s in_fn=0x%llx\n", \
                     (unsigned long long)(RIP), (unsigned)(CODE),                \
                     mew_fastfail_name((unsigned)(CODE)),                        \
                     (unsigned long long)cur_fn_va());                           \
        std::fprintf(stderr, "    rcx=0x%llx rdx=0x%llx r8=0x%llx r9=0x%llx rsp=0x%llx\n", \
                     (unsigned long long)(CTX)->rcx, (unsigned long long)(CTX)->rdx,     \
                     (unsigned long long)(CTX)->r8, (unsigned long long)(CTX)->r9,       \
                     (unsigned long long)(CTX)->rsp);                            \
        /* 非易失寄存器：abort 路径上它们保存着"是谁判定失败"的对象指针 */       \
        std::fprintf(stderr, "    rdi=0x%llx rsi=0x%llx rbx=0x%llx rbp=0x%llx rax=0x%llx\n", \
                     (unsigned long long)(CTX)->rdi, (unsigned long long)(CTX)->rsi,     \
                     (unsigned long long)(CTX)->rbx, (unsigned long long)(CTX)->rbp,     \
                     (unsigned long long)(CTX)->rax);                            \
        std::fprintf(stderr, "    r12=0x%llx r13=0x%llx r14=0x%llx r15=0x%llx\n", \
                     (unsigned long long)(CTX)->r12, (unsigned long long)(CTX)->r13,     \
                     (unsigned long long)(CTX)->r14, (unsigned long long)(CTX)->r15);    \
        mew_probe_qword("[rsi]", (CTX)->rsi);                                    \
        mew_probe_qword("[rdi+0x88]", (CTX)->rdi + 0x88);                        \
        mew_probe_qword("[rdi+0x90]", (CTX)->rdi + 0x90);                        \
        mew_probe_qword("[rdi+0x3a8]", (CTX)->rdi + 0x3a8);                      \
        mew_probe_qword("[flags 0x1412f2f80]", 0x1412f2f80ULL);                  \
        mew_probe_qword("[rbx]", (CTX)->rbx);                                    \
        mew_dump_guest_str("rcx_str", (CTX)->rcx);                               \
        mew_dump_guest_str("rdx_str", (CTX)->rdx);                               \
        mew_dump_guest_str("r8_str", (CTX)->r8);                                 \
        mew_dump_guest_str("r9_str", (CTX)->r9);                                 \
        for (int _i = 0; _i < 12; ++_i) {                                        \
            uint64_t _a = (CTX)->rsp + (uint64_t)_i * 8;                          \
            if (!guest_mapped(_a, 8)) break;                                      \
            uint64_t _v = 0;                                                      \
            std::memcpy(&_v, reinterpret_cast<const void*>((uintptr_t)(_a + (CTX)->mem_bias)), 8); \
            std::fprintf(stderr, "    [rsp+0x%x]=0x%llx\n", _i * 8, (unsigned long long)_v);       \
            mew_dump_guest_str("  str", _v);                                      \
        }                                                                        \
        call_trace().dump("fastfail");                                           \
        /* 真实语义：__fastfail 永不返回。以前在 MEW_UNIMPL_CONTINUE 下 return，   \
           会让 abort 的兜底路径继续跑，产生垃圾指针与十万级 dispatch miss，        \
           日志全是噪声。除非显式要求继续，否则到此终止。 */                       \
        if (mew_unimpl_continue() && std::getenv("MEW_FASTFAIL_CONTINUE")) return; \
        std::fflush(stderr);                                                     \
        std::_Exit(3);                                                           \
    } while (0)

// 由生成的 dispatch_table.cpp 提供
void init_dispatch_table(const char* extra_url = nullptr, void* extra = nullptr);
