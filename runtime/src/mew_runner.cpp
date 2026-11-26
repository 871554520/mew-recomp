// 阶段 5：宿主启动器 —— 加载 PE 镜像、初始化主线程 ctx、调用入口点
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <execinfo.h>
#include <signal.h>
#include <sys/time.h>
#include <unistd.h>

#include "x64_runtime.h"
#include "pe_image.h"
#include "seh_x64.h"

namespace {
// 每 15 秒采样一次调用环顶部，用来判断"卡死"发生在哪个循环里
void sample_handler(int) {
    static int tick = 0;
    std::fprintf(stderr, "[SAMPLE %d] top frames:\n", ++tick);
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
static void setup_pe_tls(const char* exe, const GuestImage& img, X64Ctx* ctx) {
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
    uint32_t tlsRva = 0, tlsSize = 0;
    std::fseek(fp, dirOff + 9 * 8, SEEK_SET);
    if (std::fread(&tlsRva, 4, 1, fp) != 1) { std::fclose(fp); return; }
    if (std::fread(&tlsSize, 4, 1, fp) != 1) { std::fclose(fp); return; }
    std::fclose(fp);
    if (!tlsRva) {
        std::fprintf(stderr, "[tls] 这个 PE 没有 TLS 目录\n");
        return;
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
    if (blk) *reinterpret_cast<uint64_t*>(guest_ptr(img, ctx->gs_base + 0x58)) = blk;
    std::fprintf(stderr,
                 "[tls] 目录 rva=0x%x 模板=0x%llx..0x%llx zero=0x%llx block=0x%llx index=0 callbacks=0x%llx\n",
                 tlsRva, (unsigned long long)start, (unsigned long long)end,
                 (unsigned long long)zfill, (unsigned long long)blk,
                 (unsigned long long)addrCb);
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
    setup_pe_tls(exe, img, &ctx);
    probe_security_cookie(exe, img);
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
    mew_unimpl_dump("exit");
    return 0;
}
