#pragma once
// x64 SEH / C++ EH 支撑层
//   1) 从映射好的 PE 里读 .pdata（异常目录），实现 RtlLookupFunctionEntry 语义
//   2) 解释 UNWIND_INFO 实现虚拟展开（等价 RtlVirtualUnwind）
//   3) RaiseException 时按帧派发 personality routine，让 try/catch 真正展开
//
// 前提：镜像钉在 0x140000000（bias=0），guest 地址即宿主地址，
//       可把 .pdata / UNWIND_INFO 当宿主指针直接解引用。
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <csetjmp>

#include "x64_runtime.h"

namespace seh {

// ---------------- CONTEXT（x64 布局，只用前 0x100 字节） ----------------
struct Ctx64 {
    uint64_t P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;  // 0x00
    uint32_t ContextFlags, MxCsr;                             // 0x30, 0x34
    uint16_t SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;        // 0x38..
    uint32_t EFlags;                                          // 0x44
    uint64_t Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;                    // 0x48
    uint64_t Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;          // 0x78
    uint64_t R8, R9, R10, R11, R12, R13, R14, R15;            // 0xb8
    uint64_t Rip;                                             // 0xf8
};
static_assert(offsetof(Ctx64, Rip) == 0xf8, "CONTEXT layout mismatch");
static_assert(offsetof(Ctx64, Rsp) == 0x98, "CONTEXT layout mismatch");

static constexpr size_t kContextSize = 0x4d0;  // 真实 CONTEXT 大小

// ---------------- EXCEPTION_RECORD ----------------
struct ExcRec {
    uint32_t Code;
    uint32_t Flags;
    uint64_t Record;
    uint64_t Address;
    uint32_t NumberParameters;
    uint32_t _pad;
    uint64_t Information[15];
};
static_assert(sizeof(ExcRec) == 0x98, "EXCEPTION_RECORD size mismatch");

// personality 的第四个参数
struct DispatcherContext {
    uint64_t ControlPc;
    uint64_t FunctionEntry;
    uint64_t EstablisherFrame;
    uint64_t TargetIp;
    uint64_t ContextRecord;
    uint64_t LanguageHandler;
    uint64_t HandlerData;
    uint64_t HistoryTable;
    uint32_t ScopeIndex;
    uint32_t Fill0;
};

enum : int { kContinueExecution = 0, kContinueSearch = 1 };

// ---------------- 内存读写原语 ----------------
inline uint32_t rd32(uint64_t va) { uint32_t v = 0; std::memcpy(&v, (const void*)(uintptr_t)va, 4); return v; }
inline uint16_t rd16(uint64_t va) { uint16_t v = 0; std::memcpy(&v, (const void*)(uintptr_t)va, 2); return v; }
inline uint64_t rd64(uint64_t va) { uint64_t v = 0; std::memcpy(&v, (const void*)(uintptr_t)va, 8); return v; }
inline void wr64(uint64_t va, uint64_t v) { std::memcpy((void*)(uintptr_t)va, &v, 8); }

// ---------------- GPR 按 id 访问 ----------------
inline uint64_t reg_get(const Ctx64* c, int id) {
    switch (id) {
        case 0: return c->Rax; case 1: return c->Rcx; case 2: return c->Rdx; case 3: return c->Rbx;
        case 4: return c->Rsp; case 5: return c->Rbp; case 6: return c->Rsi; case 7: return c->Rdi;
        case 8: return c->R8; case 9: return c->R9; case 10: return c->R10; case 11: return c->R11;
        case 12: return c->R12; case 13: return c->R13; case 14: return c->R14; case 15: return c->R15;
        default: return 0;
    }
}
inline void reg_set(Ctx64* c, int id, uint64_t v) {
    switch (id) {
        case 0: c->Rax = v; break; case 1: c->Rcx = v; break; case 2: c->Rdx = v; break;
        case 3: c->Rbx = v; break; case 4: c->Rsp = v; break; case 5: c->Rbp = v; break;
        case 6: c->Rsi = v; break; case 7: c->Rdi = v; break; case 8: c->R8 = v; break;
        case 9: c->R9 = v; break; case 10: c->R10 = v; break; case 11: c->R11 = v; break;
        case 12: c->R12 = v; break; case 13: c->R13 = v; break; case 14: c->R14 = v; break;
        case 15: c->R15 = v; break;
    }
}

// ---------------- 镜像与 .pdata ----------------
struct ImageInfo {
    uint64_t base = 0;
    uint64_t size = 0;
    uint64_t pdata = 0;
    uint32_t pdata_count = 0;
    bool ready = false;
};
inline ImageInfo& image() { static ImageInfo i; return i; }

inline void init_image(uint64_t base, uint64_t size) {
    ImageInfo& im = image();
    im.base = base;
    im.size = size;
    im.ready = false;
    if (!base || !size) return;
    uint64_t pe = rd32(base + 0x3c) + base;
    if (rd32(pe) != 0x00004550) return;
    uint16_t optsz = rd16(pe + 20);
    (void)optsz;
    uint64_t opt = pe + 24;
    uint64_t dd = opt + 112 + 3 * 8;  // DataDirectory[3] = Exception
    uint32_t rva = rd32(dd), bytes = rd32(dd + 4);
    if (!rva || !bytes) return;
    im.pdata = base + rva;
    im.pdata_count = bytes / 12;
    im.ready = true;
    std::fprintf(stderr, "[seh] image base=0x%llx pdata=0x%llx entries=%u\n",
                 (unsigned long long)im.base, (unsigned long long)im.pdata, im.pdata_count);
}

struct FuncEntry {
    uint64_t begin = 0;
    uint64_t end = 0;
    uint64_t unwind = 0;
    uint64_t entry_va = 0;  // RUNTIME_FUNCTION 自身地址
};

inline bool lookup_function_entry(uint64_t pc, FuncEntry* out) {
    ImageInfo& im = image();
    if (!im.ready) return false;
    if (pc < im.base || pc >= im.base + im.size) return false;
    uint32_t rva = (uint32_t)(pc - im.base);
    uint32_t lo = 0, hi = im.pdata_count;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        uint64_t e = im.pdata + (uint64_t)mid * 12;
        uint32_t b = rd32(e), en = rd32(e + 4);
        if (rva < b) hi = mid;
        else if (rva >= en) lo = mid + 1;
        else {
            out->begin = im.base + b;
            out->end = im.base + en;
            out->unwind = im.base + rd32(e + 8);
            out->entry_va = e;
            return true;
        }
    }
    return false;
}

// ---------------- UNWIND_INFO ----------------
struct UnwindInfo {
    uint8_t version = 0, flags = 0, prolog = 0, codes = 0;
    uint8_t frame_reg = 0, frame_off = 0;
    uint64_t codes_va = 0;
    uint64_t handler = 0;
    bool has_handler = false;
};

inline void read_unwind_info(uint64_t vi, UnwindInfo* u, int depth = 0) {
    if (!vi || depth > 4) return;
    uint8_t b[4] = {0, 0, 0, 0};
    std::memcpy(b, (const void*)(uintptr_t)vi, 4);
    u->version = b[0] & 0x7;
    u->flags = (uint8_t)(b[0] >> 3);
    u->prolog = b[1];
    u->codes = b[2];
    u->frame_reg = b[3] & 0xF;
    u->frame_off = (uint8_t)(b[3] >> 4);
    u->codes_va = vi + 4;
    uint64_t tail = u->codes_va + (uint64_t)u->codes * 2;
    if (u->codes & 1) tail += 2;  // 代码数组 4 字节对齐
    if (u->flags & 4) {           // UNW_FLAG_CHAININFO
        uint64_t cvi = image().base + rd32(tail + 8);
        uint64_t ch_handler = u->handler;
        bool ch_has = u->has_handler;
        read_unwind_info(cvi, u, depth + 1);
        if (ch_has && !u->has_handler) { u->has_handler = true; u->handler = ch_handler; }
        return;
    }
    if (u->flags & 3) {  // EHANDLER | UHANDLER
        u->has_handler = true;
        u->handler = image().base + rd32(tail);
    }
}

// 虚拟展开一帧。control_pc 是当前帧里的 PC；c 是该帧的上下文。
inline void virtual_unwind(uint64_t control_pc, Ctx64* c, uint64_t* out_handler,
                           uint64_t* out_estab, bool verbose) {
    FuncEntry fe;
    uint64_t pc = control_pc ? control_pc - 1 : 0;  // Windows 惯例：pc-1 查表
    if (!lookup_function_entry(pc, &fe)) {
        c->Rip = rd64(c->Rsp);
        c->Rsp += 8;
        if (out_handler) *out_handler = 0;
        if (out_estab) *out_estab = c->Rsp;
        if (verbose)
            std::fprintf(stderr, "[seh]   pc=0x%llx leaf -> rip=0x%llx rsp=0x%llx\n",
                         (unsigned long long)control_pc, (unsigned long long)c->Rip,
                         (unsigned long long)c->Rsp);
        return;
    }
    UnwindInfo u;
    read_unwind_info(fe.unwind, &u);
    uint32_t off = (uint32_t)(pc - fe.begin);
    if (u.prolog && off < u.prolog) {
        // prologue 中途：只应用已执行的序言指令（保守做法：按 code_off <= off 过滤）
    } else {
        off = 0xFFFFFFFFu;
    }
    for (int i = 0; i < u.codes; ++i) {
        uint64_t slot = u.codes_va + (uint64_t)i * 2;
        uint8_t code_off = 0, info = 0;
        std::memcpy(&code_off, (const void*)(uintptr_t)slot, 1);
        std::memcpy(&info, (const void*)(uintptr_t)(slot + 1), 1);
        uint8_t op = info & 0xF, opinfo = (uint8_t)(info >> 4);
        if (off != 0xFFFFFFFFu && code_off > off) continue;
        switch (op) {
            case 0:  // UWOP_PUSH_NONVOL
                reg_set(c, opinfo, rd64(c->Rsp));
                c->Rsp += 8;
                break;
            case 1: {  // UWOP_ALLOC_LARGE
                uint32_t size;
                if (opinfo == 0) { size = (uint32_t)rd16(slot + 2) * 8u; ++i; }
                else { size = rd32(slot + 2); i += 2; }
                c->Rsp += size;
                break;
            }
            case 2:  // UWOP_ALLOC_SMALL
                c->Rsp += (uint64_t)opinfo * 8u + 8u;
                break;
            case 3:  // UWOP_SET_FPREG
                c->Rsp = reg_get(c, u.frame_reg) - (uint64_t)u.frame_off * 16u;
                break;
            case 4: {  // UWOP_SAVE_NONVOL
                uint32_t o = (uint32_t)rd16(slot + 2) * 8u;
                reg_set(c, opinfo, rd64(c->Rsp + o));
                ++i;
                break;
            }
            case 5: {  // UWOP_SAVE_NONVOL_FAR
                uint32_t o = rd32(slot + 2);
                reg_set(c, opinfo, rd64(c->Rsp + o));
                i += 2;
                break;
            }
            case 8: ++i; break;      // UWOP_SAVE_XMM128
            case 9: i += 2; break;   // UWOP_SAVE_XMM128_FAR
            case 10: c->Rsp += 0x40; break;  // UWOP_PUSH_MACHFRAME
            default: break;
        }
    }
    uint64_t estab = c->Rsp;
    c->Rip = rd64(c->Rsp);
    c->Rsp += 8;
    if (out_handler) *out_handler = u.has_handler ? u.handler : 0;
    if (out_estab) *out_estab = estab;
    if (verbose)
        std::fprintf(stderr,
                     "[seh]   pc=0x%llx fn=0x%llx..0x%llx %s=0x%llx estab=0x%llx -> rip=0x%llx rsp=0x%llx\n",
                     (unsigned long long)control_pc, (unsigned long long)fe.begin,
                     (unsigned long long)fe.end, u.has_handler ? "handler" : "nohandler",
                     (unsigned long long)u.handler, (unsigned long long)estab,
                     (unsigned long long)c->Rip, (unsigned long long)c->Rsp);
}

// ---------------- X64Ctx <-> CONTEXT ----------------
inline void ctx_to_win(const X64Ctx* c, Ctx64* w) {
    std::memset(w, 0, sizeof(*w));
    w->ContextFlags = 0x10000f;
    w->EFlags = (uint32_t)((c->cf ? 1u : 0u) | (c->pf ? 4u : 0u) | (c->zf ? 0x40u : 0u) |
                           (c->sf ? 0x80u : 0u) | (c->of ? 0x800u : 0u));
    w->Rax = c->rax; w->Rcx = c->rcx; w->Rdx = c->rdx; w->Rbx = c->rbx;
    w->Rsp = c->rsp; w->Rbp = c->rbp; w->Rsi = c->rsi; w->Rdi = c->rdi;
    w->R8 = c->r8; w->R9 = c->r9; w->R10 = c->r10; w->R11 = c->r11;
    w->R12 = c->r12; w->R13 = c->r13; w->R14 = c->r14; w->R15 = c->r15;
}
inline void win_to_ctx(const Ctx64* w, X64Ctx* c) {
    c->rax = w->Rax; c->rcx = w->Rcx; c->rdx = w->Rdx; c->rbx = w->Rbx;
    c->rsp = w->Rsp; c->rbp = w->Rbp; c->rsi = w->Rsi; c->rdi = w->Rdi;
    c->r8 = w->R8; c->r9 = w->R9; c->r10 = w->R10; c->r11 = w->R11;
    c->r12 = w->R12; c->r13 = w->R13; c->r14 = w->R14; c->r15 = w->R15;
    c->cf = (w->EFlags & 1) != 0; c->pf = (w->EFlags & 4) != 0;
    c->zf = (w->EFlags & 0x40) != 0; c->sf = (w->EFlags & 0x80) != 0;
    c->of = (w->EFlags & 0x800) != 0;
}

// ---------------- 恢复执行：longjmp 回宿主派发点 ----------------
inline std::jmp_buf& resume_buf() { static std::jmp_buf b; return b; }
inline bool& resume_armed() { static bool v = false; return v; }
inline Ctx64& resume_ctx() { static Ctx64 w; return w; }

inline void resume_at(uint64_t rip, const Ctx64& w) {
    Ctx64 t = w;
    t.Rip = rip;
    resume_ctx() = t;
    if (!resume_armed()) {
        std::fprintf(stderr, "[seh] resume requested but not armed (rip=0x%llx)\n",
                     (unsigned long long)rip);
        std::_Exit(70);
    }
    resume_armed() = false;
    std::longjmp(resume_buf(), 1);
}

inline bool seh_dispatch_enabled() {
    static int v = [] { const char* e = std::getenv("MEW_SEH_DISPATCH"); return (e && e[0] == '1') ? 1 : 0; }();
    return v == 1;
}

// 调用 guest personality routine
inline int call_personality(X64Ctx* c, uint64_t handler, uint64_t record_va, uint64_t estab,
                            uint64_t context_va, uint64_t disp_va) {
    const uint64_t rsp0 = c->rsp;
    c->rsp -= 8;
    wr64(c->rsp, 0);   // 占位返回地址槽
    c->rsp -= 0x20;    // shadow space
    c->rcx = record_va;
    c->rdx = estab;
    c->r8 = context_va;
    c->r9 = disp_va;
    dispatch_indirect(handler, c);
    c->rsp = rsp0;
    return (int)(uint32_t)c->rax;
}

// 派发异常；返回 false = 没人处理（调用方决定后续）
inline bool raise_exception_dispatch(X64Ctx* c, uint32_t code, uint32_t flags,
                                     uint32_t nparams, const uint64_t* params) {
    if (!image().ready) return false;
    const uint64_t rsp_at_throw = c->rsp;
    const uint64_t ret_addr = 0;
    uint64_t ret = 0;
    std::memcpy(&ret, (const void*)(uintptr_t)rsp_at_throw, 8);
    (void)ret_addr;
    std::fprintf(stderr, "[seh] dispatch code=0x%x flags=0x%x throw_pc=0x%llx rsp=0x%llx dispatch=%d\n",
                 code, flags, (unsigned long long)ret, (unsigned long long)rsp_at_throw,
                 (int)seh_dispatch_enabled());

    uint64_t scratch = (rsp_at_throw - 0x1200) & ~(uint64_t)15;
    if (!guest_mapped(scratch, 0x800)) {
        std::fprintf(stderr, "[seh] scratch unmapped 0x%llx\n", (unsigned long long)scratch);
        return false;
    }
    const uint64_t record_va = scratch;
    const uint64_t context_va = scratch + 0x100;
    const uint64_t disp_va = scratch + 0x600;

    ExcRec rec;
    std::memset(&rec, 0, sizeof(rec));
    rec.Code = code;
    rec.Flags = flags;
    rec.Address = ret;
    rec.NumberParameters = nparams > 15 ? 15 : nparams;
    for (uint32_t i = 0; i < rec.NumberParameters; ++i) rec.Information[i] = params ? params[i] : 0;
    std::memcpy((void*)(uintptr_t)record_va, &rec, sizeof(rec));

    Ctx64 cur;
    ctx_to_win(c, &cur);
    cur.Rip = ret;
    cur.Rsp = rsp_at_throw + 8;
    std::memset((void*)(uintptr_t)context_va, 0, kContextSize);
    std::memcpy((void*)(uintptr_t)context_va, &cur, sizeof(cur));

    for (int depth = 1; depth <= 512; ++depth) {
        FuncEntry fe;
        UnwindInfo u;
        const bool have_fe = lookup_function_entry(cur.Rip ? cur.Rip - 1 : 0, &fe);
        if (have_fe) read_unwind_info(fe.unwind, &u);
        std::fprintf(stderr, "[seh] depth=%d pc=0x%llx fn=%s0x%llx handler=%s0x%llx\n", depth,
                     (unsigned long long)cur.Rip, have_fe ? "" : "leaf/",
                     (unsigned long long)(have_fe ? fe.begin : 0),
                     (have_fe && u.has_handler) ? "" : "none/",
                     (unsigned long long)(have_fe && u.has_handler ? u.handler : 0));
        if (seh_dispatch_enabled() && have_fe && u.has_handler) {
            Ctx64 here = cur;
            std::memcpy((void*)(uintptr_t)context_va, &here, sizeof(here));
            DispatcherContext dc;
            std::memset(&dc, 0, sizeof(dc));
            dc.ControlPc = cur.Rip;
            dc.FunctionEntry = fe.entry_va;
            dc.EstablisherFrame = cur.Rsp;
            dc.ContextRecord = context_va;
            std::memcpy((void*)(uintptr_t)disp_va, &dc, sizeof(dc));
            int disp = call_personality(c, u.handler, record_va, cur.Rsp, context_va, disp_va);
            std::fprintf(stderr, "[seh]   handler 0x%llx -> %d\n",
                         (unsigned long long)u.handler, disp);
            if (disp == kContinueExecution) {
                Ctx64 after;
                std::memcpy(&after, (const void*)(uintptr_t)context_va, sizeof(after));
                win_to_ctx(&after, c);
                if (after.Rip) {
                    std::fprintf(stderr, "[seh] continue execution at rip=0x%llx rsp=0x%llx\n",
                                 (unsigned long long)after.Rip, (unsigned long long)after.Rsp);
                    resume_at(after.Rip, after);
                }
                return true;
            }
        }
        virtual_unwind(cur.Rip, &cur, nullptr, nullptr, true);
        if (!cur.Rip) break;
    }
    std::fprintf(stderr, "[seh] unhandled: frame chain exhausted\n");
    return false;
}

}  // namespace seh
