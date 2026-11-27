// 阶段 5：宿主启动器 —— 加载 PE 镜像、初始化主线程 ctx、调用入口点
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <execinfo.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <unistd.h>

#include "x64_runtime.h"
#include "pe_image.h"
#include "seh_x64.h"

namespace {
// 每 15 秒采样一次调用环顶部，用来判断"卡死"发生在哪个循环里
void sample_handler(int) {
    static int tick = 0;
    // 关键：调用环只记「函数进入」，如果 guest 卡在**某个函数体内的循环**上
    // （lift 出来的 L_xxx goto 循环不会产生新条目），环会完全冻结——
    // run 45978138365 就是这样：idx 卡在 12027、29 分钟一次都没动过，
    // 只剩最后一帧可看。所以采样必须同时打出**当前正在执行的函数**和最后一条内存指令。
    std::fprintf(stderr, "[SAMPLE %d] cur_fn=0x%llx last_pc=0x%llx cur_rcx=0x%llx cur_rsp=0x%llx\n",
                 ++tick, (unsigned long long)cur_fn_va(), (unsigned long long)last_mem_pc(),
                 cur_ctx_ptr() ? (unsigned long long)cur_ctx_ptr()->rcx : 0ULL,
                 cur_ctx_ptr() ? (unsigned long long)cur_ctx_ptr()->rsp : 0ULL);
    call_trace().dump_tail(6);
    std::fflush(stderr);
}

void timeout_handler(int) {
    std::fprintf(stderr, "\n[TIMEOUT] terminated by watchdog\n");
    call_trace().dump("timeout");
    // 聚合表放在最末：workflow 只 tail 40 行，这张表要落在尾巴上才看得见
    mew_unimpl_dump("timeout");
    std::fflush(stderr);
    _exit(124);
}

void crash_handler(int sig, siginfo_t* si, void*) {
    void* bt[64];
    int n = backtrace(bt, 64);
    std::fprintf(stderr, "\n[CRASH] signal=%d fault=0x%llx frames=%d\n", sig,
                 (unsigned long long)(uintptr_t)si->si_addr, n);
    backtrace_symbols_fd(bt, n, 2);
    // 崩溃时把最近 64 层调用环打出来：哪个 guest 函数、rcx 是什么、谁调的
    call_trace().dump("crash");
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
    sigaction(SIGFPE, &sa, nullptr);
    sigaction(SIGABRT, &sa, nullptr);
    struct sigaction ta;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_handler = timeout_handler;
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGALRM, &sa, nullptr);

    if (std::getenv("MEW_SAMPLE_SEC")) {
        struct sigaction sa2;
        std::memset(&sa2, 0, sizeof(sa2));
        sa2.sa_handler = sample_handler;
        sigaction(SIGALRM, &sa2, nullptr);
        struct itimerval it;
        it.it_interval.tv_sec = std::atol(std::getenv("MEW_SAMPLE_SEC"));
        it.it_interval.tv_usec = 0;
        it.it_value = it.it_interval;
        setitimer(ITIMER_REAL, &it, nullptr);
    }
}
}  // namespace

// ---- 诊断探针：__security_cookie 到底是不是 0 ----
// stage3 的崩溃（fault=0xc06b57238）怀疑是「cookie 全局还没初始化就拿去解码指针」。
// 这个 PE 的 LoadConfig.SecurityCookie 指向 0x1412f2880，.data 里的初值是
// 0x00002B992DDFA232（MSVC 的默认 cookie 值）。探针把它在**进入 entry 之前**
// 的真实值打出来：是 0 就说明我们的加载器把 .data 清掉了，非 0 就说明 cookie
// 一直是好的、崩溃另有原因。
static void probe_security_cookie(const char* exe, const GuestImage& img) {
    FILE* fp = std::fopen(exe, "rb");
    if (!fp) return;
    uint32_t peOff = 0;
    std::fseek(fp, 0x3c, SEEK_SET);
    if (std::fread(&peOff, 4, 1, fp) != 1) { std::fclose(fp); return; }
    long opt = (long)peOff + 24;
    uint16_t magic = 0;
    std::fseek(fp, opt, SEEK_SET);
    if (std::fread(&magic, 2, 1, fp) != 1) { std::fclose(fp); return; }
    long dirOff = (magic == 0x20b) ? (opt + 112) : (opt + 96);
    uint32_t lcRva = 0;
    std::fseek(fp, dirOff + 10 * 8, SEEK_SET);
    if (std::fread(&lcRva, 4, 1, fp) != 1) { std::fclose(fp); return; }
    std::fclose(fp);
    if (!lcRva) { std::fprintf(stderr, "[probe] 这个 PE 没有 LoadConfig\n"); return; }
    uint64_t lcVa = img.orig_image_base + lcRva;
    if (lcVa + 0x60 < img.orig_image_base || lcVa + 0x60 >= img.orig_image_base + img.image_size) {
        std::fprintf(stderr, "[probe] LoadConfig 越界 0x%llx\n", (unsigned long long)lcVa);
        return;
    }
    uint64_t cookie_va = *reinterpret_cast<uint64_t*>(guest_ptr(img, lcVa + 0x58));
    if (cookie_va < img.orig_image_base || cookie_va + 8 > img.orig_image_base + img.image_size) {
        std::fprintf(stderr, "[probe] SecurityCookie 指向界外 0x%llx（=0 说明没被初始化）\n",
                     (unsigned long long)cookie_va);
        return;
    }
    uint64_t v = *reinterpret_cast<uint64_t*>(guest_ptr(img, cookie_va));
    std::fprintf(stderr, "[probe] __security_cookie @0x%llx 进 entry 前的值 = 0x%016llx%s\n",
                 (unsigned long long)cookie_va, (unsigned long long)v,
                 v ? "" : "  <<< 是 0，说明 .data 被清掉了");
}

// ---- PE 的 TLS 目录 ----
// `__declspec(thread)` 在 x64 上是编译器直接发 `mov rax, gs:[0x58 + 8*_tls_index]`：
// 槽里放的是**指向该模块 TLS 块的指针**，块内容由加载器从 TLS 模板拷过来。
// 我们之前既没分配这个块、也没往槽里写指针，于是所有线程局部变量读出来都是 0，
// CRT 拿 0 当对象指针再 `mov [rax],ebx` 就崩了（stage3 实测写 0xc06b57238）。
// 这里按 Windows 加载器的做法补上：分配块 -> 拷模板 -> 写 _tls_index -> 填 TlsSlots[0]。
static uint64_t setup_pe_tls(const char* exe, const GuestImage& img, X64Ctx* ctx) {
    FILE* fp = std::fopen(exe, "rb");
    if (!fp) return 0;
    uint32_t peOff = 0;
    std::fseek(fp, 0x3c, SEEK_SET);
    if (std::fread(&peOff, 4, 1, fp) != 1) { std::fclose(fp); return 0; }
    long opt = (long)peOff + 24;
    uint16_t magic = 0;
    std::fseek(fp, opt, SEEK_SET);
    if (std::fread(&magic, 2, 1, fp) != 1) { std::fclose(fp); return 0; }
    long dirOff = (magic == 0x20b) ? (opt + 112) : (opt + 96);
    uint32_t tlsRva = 0, tlsSize = 0;
    std::fseek(fp, dirOff + 9 * 8, SEEK_SET);
    if (std::fread(&tlsRva, 4, 1, fp) != 1) { std::fclose(fp); return 0; }
    if (std::fread(&tlsSize, 4, 1, fp) != 1) { std::fclose(fp); return 0; }
    std::fclose(fp);
    if (!tlsRva) {
        std::fprintf(stderr, "[tls] 这个 PE 没有 TLS 目录\n");
        return 0;
    }
    uint64_t tlsVa = img.orig_image_base + tlsRva;
    auto rd64 = [&](int i) {
        return *reinterpret_cast<uint64_t*>(guest_ptr(img, tlsVa + (uint64_t)i * 8));
    };
    uint64_t start = rd64(0), end = rd64(1), addrIdx = rd64(2), addrCb = rd64(3);
    uint64_t zfill = rd64(4) & 0xFFFFFFFFULL;
    uint64_t rawBytes = (end > start) ? (end - start) : 0;
    uint64_t total = rawBytes + zfill;
    uint64_t blk = 0;
    if (total) {
        blk = g_guest_heap.alloc((size_t)total, /*zero_init=*/true);
        if (blk && rawBytes)
            std::memcpy(guest_ptr(img, blk), guest_ptr(img, start), (size_t)rawBytes);
    }
    if (addrIdx) *reinterpret_cast<uint32_t*>(guest_ptr(img, addrIdx)) = 0;  // _tls_index = 0

    // 关键：x64 的 TEB+0x58 是 **ThreadLocalStoragePointer**，指向一个 64 项的指针数组，
    // 模块自己的 TLS 块要挂在 数组[_tls_index] 上。MSVC 生成的访问序列是
    //     mov  rax, gs:[58h]
    //     mov  r14, [rax + _tls_index*8]     ← 这里才拿到模块 TLS 块
    // 上一版直接把块指针写进 0x58，少了一层间接，导致回调 #1 里
    //     mov rdi, [r14+0x20]                ← r14 其实是模板首 8 字节，崩溃读 0x20
    uint64_t slots = g_guest_heap.alloc(64 * 8, /*zero_init=*/true);
    if (slots) {
        *reinterpret_cast<uint64_t*>(guest_ptr(img, slots)) = blk;      // slot[0] = 模块 TLS 块
        *reinterpret_cast<uint64_t*>(guest_ptr(img, ctx->gs_base + 0x58)) = slots;
    }
    std::fprintf(stderr, "[tls] ThreadLocalStoragePointer=0x%llx slots[0]=0x%llx\n",
                 (unsigned long long)slots, (unsigned long long)blk);
    std::fprintf(stderr,
                 "[tls] 目录 rva=0x%x 模板=0x%llx..0x%llx zero=0x%llx block=0x%llx index=0 callbacks=0x%llx\n",
                 tlsRva, (unsigned long long)start, (unsigned long long)end,
                 (unsigned long long)zfill, (unsigned long long)blk,
                 (unsigned long long)addrCb);
    return addrCb;
}

// ---- 受控实验：伪造一段 guest 地址区间 ----
// MEW_MAP_FAKE=0x<va>:0x<size>[,0x<va>:0x<size>...]
// 用来做「让那次写成功，看接下来走到哪」的实验：不掩盖根因，但能把问题从
// 「崩在这一条写」变成「写进去之后谁读它」。默认不开启。
static void map_fake_ranges(const GuestImage& img) {
    const char* e = std::getenv("MEW_MAP_FAKE");
    if (!e || !*e) return;
    const char* p = e;
    while (*p) {
        char* end = nullptr;
        unsigned long long va = std::strtoull(p, &end, 0);
        if (end == p) break;
        p = end;
        while (*p == ' ' || *p == ':') ++p;
        unsigned long long sz = std::strtoull(p, &end, 0);
        if (end == p) break;
        p = end;
        while (*p == ',' || *p == ' ') ++p;
        if (!va || !sz) continue;
        void* want = reinterpret_cast<void*>(va + (uint64_t)img.mem_bias);
        void* got = mmap(want, (size_t)sz, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (got == MAP_FAILED) {
            std::fprintf(stderr, "[map] 伪造区间失败 va=0x%llx size=0x%llx\n",
                         (unsigned long long)va, (unsigned long long)sz);
            continue;
        }
        register_guest_range(va, sz);
        std::fprintf(stderr, "[map] 伪造区间 va=0x%llx size=0x%llx host=%p\n",
                     (unsigned long long)va, (unsigned long long)sz, got);
    }
}

// ---- 最小伪 PEB ----
// x64 的 TEB+0x60 是 PROCESS_ENVIRONMENT_BLOCK 指针。扫了整个 exe，只有两处
// `mov rax,gs:[60h]`，都在 CRT 初始化里，用法固定：
//     rax = gs:[0x60]      ; PEB
//     rcx = [rax+0x20]     ; PEB->ProcessParameters
//     cmp dword [rcx+8], 0
// 我们的伪 TEB 是清零页，这一格是 0 → TLS 修好之后紧接着就会在这里崩。
// 所以补一个够用的 PEB：ProcessParameters 指向一块清零的 RTL_USER_PROCESS_PARAMETERS，
// 顺带把 ImageBaseAddress 填上（有些 CRT 路径会用它算模块范围）。
static void setup_peb(const GuestImage& img, X64Ctx* ctx) {
    uint64_t peb = g_guest_heap.alloc(0x400, /*zero_init=*/true);
    uint64_t params = g_guest_heap.alloc(0x100, /*zero_init=*/true);
    if (!peb || !params) return;
    *reinterpret_cast<uint64_t*>(guest_ptr(img, peb + 0x10)) = img.orig_image_base;  // ImageBaseAddress
    *reinterpret_cast<uint64_t*>(guest_ptr(img, peb + 0x20)) = params;               // ProcessParameters
    *reinterpret_cast<uint64_t*>(guest_ptr(img, ctx->gs_base + 0x60)) = peb;          // TEB.ProcessEnvironmentBlock
    std::fprintf(stderr, "[peb] 伪 PEB=0x%llx ProcessParameters=0x%llx image_base=0x%llx\n",
                 (unsigned long long)peb, (unsigned long long)params,
                 (unsigned long long)img.orig_image_base);
}

// ---- 执行 TLS 回调 ----
// Windows 加载器在进 entry 之前，会按数组顺序把每个 TLS 回调以
// DLL_PROCESS_ATTACH(1) 调一遍。CRT 里有不少线程级初始化就挂在这里，
// 跳过它们的话，后面拿到的线程局部结构可能是半成品（实测：装载 TLS 块之后
// 崩溃点前移了 0x2f0 = 模板大小 752 字节，说明这条路已经接通，只差回调）。
static void run_tls_callbacks(const GuestImage& img, X64Ctx* ctx, uint64_t callbacks_va) {
    if (!callbacks_va) return;
    for (int i = 0; i < 32; ++i) {
        uint64_t cb = *reinterpret_cast<uint64_t*>(guest_ptr(img, callbacks_va + (uint64_t)i * 8));
        if (!cb) break;
        // 压一个 0 当返回地址：回调里的 ret 弹到它，lifter 会直接返回宿主
        ctx->rsp -= 8;
        *reinterpret_cast<uint64_t*>(guest_ptr(img, ctx->rsp)) = 0;
        ctx->rcx = 1;   // DLL_PROCESS_ATTACH
        ctx->rdx = 0;   // lpReserved
        std::fprintf(stderr, "[tls] 调用回调 #%d @0x%llx ...\n", i, (unsigned long long)cb);
        std::fflush(stderr);
        dispatch_indirect(cb, ctx);
        std::fprintf(stderr, "[tls] 回调 #%d 已返回 rsp=0x%llx\n", i,
                     (unsigned long long)ctx->rsp);
        std::fflush(stderr);
    }
}

int main(int argc, char** argv) {
    std::fprintf(stderr, "[runner] marker: seh headers linked, dispatch=%d\n",
                 (int)seh::seh_dispatch_enabled());
    install_crash_handler();
    const char* exe = argc > 1 ? argv[1] : "Mewgenics.exe";
    uint64_t call_va = 0;
    size_t   call_obj_size = 0;
    unsigned long long cargs[4] = {0, 0, 0, 0};
    for (int i = 2; i < argc; ++i) {
        if (std::strcmp(argv[i], "--call") == 0 && i + 1 < argc) call_va = std::strtoull(argv[++i], nullptr, 0);
        else if (std::strcmp(argv[i], "--call-obj") == 0 && i + 2 < argc) {
            call_va = std::strtoull(argv[++i], nullptr, 0);
            call_obj_size = (size_t)std::strtoull(argv[++i], nullptr, 0);
        }
        else if (std::strcmp(argv[i], "--arg") == 0 && i + 1 < argc) {
            const char* p = argv[++i];
            int k = 0;
            while (*p && k < 4) {
                char* end = nullptr;
                cargs[k++] = std::strtoull(p, &end, 0);
                if (end == p) break;
                p = end;
                if (*p == ',') ++p;
            }
        }
    }
    GuestImage img;
    std::string err;
    if (!load_pe_image(exe, &img, &err)) {
        std::fprintf(stderr, "load image failed: %s\n", err.c_str());
        return 1;
    }

    uint64_t entry = img.orig_image_base;
    {
        FILE* fp = std::fopen(exe, "rb");
        if (fp) {
            uint32_t peOff = 0;
            std::fseek(fp, 0x3c, SEEK_SET);
            std::fread(&peOff, 4, 1, fp);
            uint32_t entryRva = 0;
            std::fseek(fp, (long)peOff + 24 + 16, SEEK_SET);
            std::fread(&entryRva, 4, 1, fp);
            std::fclose(fp);
            entry = img.orig_image_base + entryRva;
        }
    }

    std::printf("runner: image_base=0x%llx entry=0x%llx bias=%lld\n",
                (unsigned long long)img.orig_image_base,
                (unsigned long long)entry, (long long)img.mem_bias);

    init_dispatch_table();

    X64Ctx ctx;
    init_guest_thread_ctx(&ctx, img);

    // 必须在 init_guest_thread_ctx 之后：要往伪 TEB 的 TlsSlots 里写模块 TLS 块指针
    uint64_t tls_callbacks = setup_pe_tls(exe, img, &ctx);
    probe_security_cookie(exe, img);
    map_fake_ranges(img);
    setup_peb(img, &ctx);
    run_tls_callbacks(img, &ctx, tls_callbacks);
    if (!call_va) {
        ctx.rcx = 0;   // hInstance
        ctx.rdx = 0;   // hPrevInstance
        ctx.r8 = 0;    // lpCmdLine
        ctx.r9 = 1;    // nCmdShow
    } else {
        if (call_obj_size) {
            uint64_t obj = g_guest_heap.alloc(call_obj_size, true);
            std::fprintf(stderr, "runner: --call-obj allocated 0x%llx (%zu bytes, zeroed)\n",
                         (unsigned long long)obj, call_obj_size);
            cargs[0] = obj;
        }
        ctx.rcx = cargs[0];
        ctx.rdx = cargs[1];
        ctx.r8 = cargs[2];
        ctx.r9 = cargs[3];
        entry = call_va;
        std::printf("runner: direct call 0x%llx args=%llu,%llu,%llu,%llu\n",
                    (unsigned long long)entry, cargs[0], cargs[1], cargs[2], cargs[3]);
    }

    // 定向预置：0x1413c60b0 是哈希容器负载因子检查读取的那个浮点。
    // 它落在可写 data 区、文件初值是 0x001a99ca（约 2.4e-39，几乎必然是垃圾），
    // 而 check 是 `comiss mlf, ratio ; jae 跳过 ; 否则抛 length_error`——
    // mlf 只要不是 1.0 就几乎一定抛。手动解出的写出点 0x1400254ba 写的是
    // 0x1413c60b8（相邻另一个字段），不是这里。先用 MEW_SEED_MLF=1 试预置 1.0f，
    // 验证「该全局从未被正确初始化」这条假设；默认关，不改变未开开关时的行为。
    if (const char* e = std::getenv("MEW_SEED_MLF"); e && e[0] == '1') {
        const uint64_t addr = 0x1413c60b0ULL;
        const uint32_t one = 0x3f800000u;   // 1.0f
        uint32_t prev = 0;
        auto* dst = reinterpret_cast<void*>((uintptr_t)(addr + (uint64_t)img.mem_bias));
        std::memcpy(&prev, dst, 4);
        std::memcpy(dst, &one, 4);
        std::fprintf(stderr, "[seed] 0x%llx (max_load_factor) 0x%08x -> 0x3f800000\n",
                     (unsigned long long)addr, prev);
    }

    std::printf("runner: calling entry...\n");
    std::fflush(stdout);

    // SEH 恢复点：异常派发里 resume_at() 会 longjmp 回这里，
    // 然后把宿主上下文换成"展开后恢复的目标上下文"，从新的 Rip 继续跑。
    seh::init_image_va(reinterpret_cast<uint64_t>(img.host_base), img.image_size,
                       img.pdata_va, img.pdata_bytes);
    uint64_t next_entry = entry;
    volatile bool from_resume = false;
    int rounds = 0;
    for (; rounds < 128; ++rounds) {
        if (from_resume) {
            seh::win_to_ctx(&seh::resume_ctx(), &ctx);
            next_entry = seh::resume_ctx().Rip;
            std::fprintf(stderr, "[seh] RESUME #%d rip=0x%llx rsp=0x%llx rbp=0x%llx\n", rounds,
                         (unsigned long long)next_entry, (unsigned long long)ctx.rsp,
                         (unsigned long long)ctx.rbp);
        }
        seh::resume_armed() = true;
        if (setjmp(seh::resume_buf()) == 0) {
            dispatch_indirect(next_entry, &ctx);
            break;  // guest 正常返回
        }
        from_resume = true;
    }
    std::printf("runner: entry returned rax=%llu resumes=%d\n",
                (unsigned long long)ctx.rax, rounds);

    // 初始化链到此为止：_initterm 的 ret 已经回宿主，resume 目标（0x140d6aef5）
    // 不再有效。必须在这里把 SKIP_INIT 的 resume 关掉，否则下面补调的 main 只要
    // 抛一次异常就会被拽回已经走完的 _initterm 循环（run 45985646254：
    // `[main] main 内部又走到 resume（rip=0x140d6aef5），不再继续`），
    // main 的调用栈被整根扔掉，gpak/CreateFileW 永远不会出现。
    seh::skip_init_after_chain() = true;

    // ---- 链尾补 main（MEW_CALL_MAIN=1）----
    // 为什么必须要补：`ret` 被 lift 成 `ctx->rsp += 8; return;`，也就是每个 guest
    // 函数都直接**返回宿主**。我们从 _initterm 内部 resume 回去、把剩下的全局构造器
    // 跑完以后，_initterm 最后那条 `ret` 只会 return 回宿主，不会像正常 CRT 那样
    // "返回到 __scrt_common_main_seh，再由它 call main"。所以 main 天然不会跑。
    // 判据：run 45958412796 的 phase2 已经证明帧链能走到 _initterm；a64051b 把
    // SKIP_INIT 的起点也改成 [rsp] 以后，预期是 `entry returned ... resumes=1`。
    // 这条补调就是紧接在那一行之后，用**同一个 ctx（rsp 已经是 _initterm 弹完
    // 返回地址的层级，等价于 call main 之前的 rsp）**把 main 跑起来。
    if (const char* e = std::getenv("MEW_CALL_MAIN"); e && e[0] == '1') {
        uint64_t main_va = 0x1409b5230ULL;   // main(argc,argv) 包装器：sub rsp,0x28 / call 0x1409b9967
        if (const char* m = std::getenv("MEW_MAIN_VA")) main_va = std::strtoull(m, nullptr, 0);
        auto& tbl = g_dispatch_table();
        if (mew_saw_main()) {
            std::fprintf(stderr, "[main] 已经进过 main（0x%llx），不重复调用\n",
                         (unsigned long long)main_va);
        } else if (rounds <= 0) {
            std::fprintf(stderr, "[main] 没有发生 resume（初始化链没被跳过），不补调 main\n");
        } else if (tbl.find(main_va) == tbl.end()) {
            std::fprintf(stderr, "[main] 0x%llx 不在派发表里，跳过补调\n",
                         (unsigned long long)main_va);
        } else {
            // argv 放 guest 堆：argv[0] = exe 名，argv[1] = NULL。
            const char* name = "Mewgenics.exe";
            const size_t nlen = std::strlen(name);
            uint64_t str = g_guest_heap.alloc(nlen + 1, true);
            uint64_t argv = g_guest_heap.alloc(16, true);
            if (str && argv) {
                for (size_t i = 0; i < nlen; ++i)
                    mem_write<uint8_t>(&ctx, str + i, (uint8_t)name[i]);
                mem_write<uint64_t>(&ctx, argv, str);
                mem_write<uint64_t>(&ctx, argv + 8, 0);
                ctx.rcx = 1;      // argc
                ctx.rdx = argv;   // argv
                ctx.rax = 0;
                std::fprintf(stderr,
                             "[main] 链尾补调 main 0x%llx argc=1 argv=0x%llx (argv[0]=\"%s\") "
                             "rsp=0x%llx\n",
                             (unsigned long long)main_va, (unsigned long long)argv, name,
                             (unsigned long long)ctx.rsp);
                seh::resume_armed() = true;
                if (setjmp(seh::resume_buf()) == 0) {
                    dispatch_indirect(main_va, &ctx);
                    std::printf("runner: main returned rax=%llu\n",
                                (unsigned long long)ctx.rax);
                } else {
                    std::fprintf(stderr,
                                 "[main] main 内部又走到 resume（rip=0x%llx），不再继续\n",
                                 (unsigned long long)seh::resume_ctx().Rip);
                }
            } else {
                std::fprintf(stderr, "[main] argv 分配失败 str=0x%llx argv=0x%llx，跳过\n",
                             (unsigned long long)str, (unsigned long long)argv);
            }
        }
    }
    mew_unimpl_dump("exit");
    return 0;
}
