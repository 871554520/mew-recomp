// 阶段 5 P0：KERNEL32 启动链与文件 I/O 垫片（Linux/macOS 宿主）
// 约定：所有指针参数是 guest 地址，转宿主指针用 guest_ptr_from_ctx（加到 mem_bias）
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <ctime>
#include <string>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <unordered_set>
#include <unordered_map>
#include <malloc.h>
#include <dirent.h>
#include <cctype>
#include <pthread.h>
#include <sched.h>      // sched_yield()：SleepConditionVariableSRW 释放 SRW 后让一下 CPU
#include <sys/mman.h>
#include <sys/stat.h>
#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

#include "x64_runtime.h"
#include "win32_common.h"
#include "seh_x64.h"

// ---- 前向声明：动态加载表可能在定义之前引用 ----
// wglGetProcAddress 要用；**必须放在全局作用域**——放进匿名命名空间会与
// 文件后段的定义构成两个候选，gcc 报 "call of overloaded ... is ambiguous"。
uint64_t shim_KERNEL32_LookupSynthetic(const char* name);
void shim_KERNEL32_FlsAlloc(X64Ctx*);
void shim_KERNEL32_FlsFree(X64Ctx*);
void shim_KERNEL32_FlsGetValue(X64Ctx*);
void shim_KERNEL32_FlsSetValue(X64Ctx*);
void shim_KERNEL32_RtlCaptureContext(X64Ctx*);
void shim_KERNEL32_RtlLookupFunctionEntry(X64Ctx*);
void shim_KERNEL32_RtlVirtualUnwind(X64Ctx*);
void shim_KERNEL32_RtlPcToFileHeader(X64Ctx*);
void shim_KERNEL32_OutputDebugStringA(X64Ctx*);
void shim_KERNEL32_GetCommandLineA(X64Ctx*);
void shim_KERNEL32_GetCommandLineW(X64Ctx*);
void shim_SHELL32_CommandLineToArgvW(X64Ctx*);
void shim_KERNEL32_GetEnvironmentStringsW(X64Ctx*);
void shim_KERNEL32_GetStartupInfoW(X64Ctx*);
void shim_KERNEL32_EncodePointer(X64Ctx*);
void shim_KERNEL32_DecodePointer(X64Ctx*);
void shim_KERNEL32_AppPolicyGetProcessTerminationMethod(X64Ctx*);
void shim_KERNEL32_IsProcessorFeaturePresent(X64Ctx*);
void shim_KERNEL32_GetStdHandle(X64Ctx*);
void shim_KERNEL32_GetFileType(X64Ctx*);
// ---- 动态加载表引用的全部垫片前向声明 ----
void shim_KERNEL32_AppPolicyGetProcessTerminationMethod(X64Ctx*);
void shim_KERNEL32_CloseHandle(X64Ctx*);
void shim_KERNEL32_CreateEventW(X64Ctx*);
void shim_KERNEL32_CreateFileW(X64Ctx*);
void shim_KERNEL32_CreateFileA(X64Ctx*);
void shim_KERNEL32_FindFirstFileExW(X64Ctx*);
// FindFirstFileExW（定义在 455 行附近）要转调 FindFirstFileW，而后者定义在 1100 多行，
// 所以这里必须先声明 —— 否则 -fsyntax-only 会报 was not declared in this scope
// （踩过一次：只有 kApis 表那处（2400 多行）的声明，455 行的函数体看不到）。
void shim_KERNEL32_FindFirstFileW(X64Ctx*);
void shim_KERNEL32_GetFileAttributesExW(X64Ctx*);
void shim_KERNEL32_CreateThread(X64Ctx*);
// steam_api64 三个（定义在文件末尾的强符号，覆盖 shims_auto.cpp 的弱占位）
void shim_STEAM_API64_SteamAPI_RestartAppIfNecessary(X64Ctx*);
void shim_STEAM_API64_SteamInternal_SteamAPI_Init(X64Ctx*);
void shim_STEAM_API64_SteamInternal_ContextInit(X64Ctx*);
void shim_KERNEL32_DecodePointer(X64Ctx*);
void shim_KERNEL32_DeleteCriticalSection(X64Ctx*);
void shim_KERNEL32_EncodePointer(X64Ctx*);
void shim_KERNEL32_EnterCriticalSection(X64Ctx*);
void shim_KERNEL32_ExitProcess(X64Ctx*);
void shim_KERNEL32_FlsAlloc(X64Ctx*);
void shim_KERNEL32_FlsFree(X64Ctx*);
void shim_KERNEL32_FlsGetValue(X64Ctx*);
void shim_KERNEL32_FlsSetValue(X64Ctx*);
void shim_KERNEL32_FlushFileBuffers(X64Ctx*);
void shim_KERNEL32_GetACP(X64Ctx*);
void shim_KERNEL32_GetCPInfo(X64Ctx*);
void shim_KERNEL32_GetCommandLineA(X64Ctx*);
void shim_KERNEL32_GetCommandLineW(X64Ctx*);
void shim_KERNEL32_GetCurrentProcess(X64Ctx*);
void shim_KERNEL32_GetCurrentProcessId(X64Ctx*);
void shim_KERNEL32_GetCurrentThread(X64Ctx*);
void shim_KERNEL32_GetCurrentThreadId(X64Ctx*);
void shim_KERNEL32_GetEnvironmentStringsW(X64Ctx*);
void shim_KERNEL32_GetFileAttributesW(X64Ctx*);
void shim_KERNEL32_GetFileSize(X64Ctx*);
void shim_KERNEL32_GetFileSizeEx(X64Ctx*);
void shim_KERNEL32_GetFileType(X64Ctx*);
void shim_KERNEL32_GetLastError(X64Ctx*);
void shim_KERNEL32_GetModuleFileNameW(X64Ctx*);
void shim_KERNEL32_GetModuleHandleA(X64Ctx*);
void shim_KERNEL32_GetModuleHandleExW(X64Ctx*);
void shim_KERNEL32_GetModuleHandleExA(X64Ctx*);
void shim_KERNEL32_GetModuleHandleW(X64Ctx*);
void shim_KERNEL32_GetOEMCP(X64Ctx*);
void shim_KERNEL32_GetProcessHeap(X64Ctx*);
void shim_KERNEL32_GetStartupInfoW(X64Ctx*);
void shim_KERNEL32_GetStdHandle(X64Ctx*);
void shim_KERNEL32_GetStringTypeW(X64Ctx*);
void shim_KERNEL32_GetSystemInfo(X64Ctx*);
void shim_KERNEL32_GetSystemTimeAsFileTime(X64Ctx*);
void shim_KERNEL32_GetSystemTimePreciseAsFileTime(X64Ctx*);
void shim_KERNEL32_GetTickCount(X64Ctx*);
void shim_KERNEL32_GetTickCount64(X64Ctx*);
void shim_KERNEL32_HeapAlloc(X64Ctx*);
void shim_KERNEL32_HeapFree(X64Ctx*);
void shim_KERNEL32_InitializeCriticalSectionAndSpinCount(X64Ctx*);
void shim_KERNEL32_InitializeSListHead(X64Ctx*);
void shim_KERNEL32_IsDebuggerPresent(X64Ctx*);
void shim_KERNEL32_IsProcessorFeaturePresent(X64Ctx*);
void shim_KERNEL32_IsValidCodePage(X64Ctx*);
void shim_KERNEL32_IsValidLocale(X64Ctx*);
void shim_KERNEL32_LCMapStringW(X64Ctx*);
void shim_KERNEL32_LeaveCriticalSection(X64Ctx*);
void shim_KERNEL32_MultiByteToWideChar(X64Ctx*);
void shim_KERNEL32_OutputDebugStringA(X64Ctx*);
void shim_KERNEL32_OutputDebugStringW(X64Ctx*);
void shim_KERNEL32_QueryPerformanceCounter(X64Ctx*);
void shim_KERNEL32_QueryPerformanceFrequency(X64Ctx*);
void shim_KERNEL32_RaiseException(X64Ctx*);
void shim_KERNEL32_ReadFile(X64Ctx*);
void shim_KERNEL32_ResetEvent(X64Ctx*);
void shim_KERNEL32_RtlCaptureContext(X64Ctx*);
void shim_KERNEL32_RtlLookupFunctionEntry(X64Ctx*);
void shim_KERNEL32_RtlPcToFileHeader(X64Ctx*);
void shim_KERNEL32_RtlUnwind(X64Ctx*);
void shim_KERNEL32_RtlVirtualUnwind(X64Ctx*);
void shim_KERNEL32_SetEndOfFile(X64Ctx*);
void shim_KERNEL32_SetEvent(X64Ctx*);
void shim_KERNEL32_SetFilePointerEx(X64Ctx*);
void shim_KERNEL32_SetLastError(X64Ctx*);
void shim_KERNEL32_SetThreadPriority(X64Ctx*);
void shim_KERNEL32_SetUnhandledExceptionFilter(X64Ctx*);
void shim_KERNEL32_Sleep(X64Ctx*);
void shim_KERNEL32_SwitchToThread(X64Ctx*);
void shim_KERNEL32_TlsAlloc(X64Ctx*);
void shim_KERNEL32_TlsFree(X64Ctx*);
void shim_KERNEL32_TlsGetValue(X64Ctx*);
void shim_KERNEL32_TlsSetValue(X64Ctx*);
void shim_KERNEL32_TryEnterCriticalSection(X64Ctx*);
void shim_KERNEL32_UnhandledExceptionFilter(X64Ctx*);
void shim_KERNEL32_VirtualAlloc(X64Ctx*);
void shim_KERNEL32_VirtualFree(X64Ctx*);
void shim_KERNEL32_VirtualProtect(X64Ctx*);
void shim_KERNEL32_WaitForMultipleObjects(X64Ctx*);
void shim_KERNEL32_WaitForSingleObject(X64Ctx*);
void shim_KERNEL32_WideCharToMultiByte(X64Ctx*);
void shim_KERNEL32_WriteFile(X64Ctx*);



namespace {
thread_local uint64_t g_tls[1024];
bool g_tls_used[1024] = {false};
std::mutex g_tls_mu;

// Win32 的「最后一次错误」。为什么必须有：以前 GetLastError 恒返回 0，
// 于是 MSVC 把**任何** Win32 失败都翻译成 error_code(0, system_category())；
// 而 FormatMessageW(0) 在真机上拿不到消息 → MSVC 的 _Winerror_message 返回
// "unknown error"（小写、无数字）。这正是 run 46088817207 里那条
//   [cxx-eh] #2 filesystem_error what="create_directories: unknown error"
// 里一个错误码都看不到的原因，也让它看起来像"没有错误码"的怪现象。
// 现在由各垫片在失败时写入，GetLastError 如实返回。
thread_local uint32_t g_last_error = 0;
inline void mew_set_last_error(uint32_t e) { g_last_error = e; }
FILE* g_stdout_file = nullptr;

FILE* file_from_handle(uint64_t h) { return (FILE*)(uintptr_t)HandleTable::instance().get(h); }

// Windows 路径 -> 宿主路径：去盘符、反斜杠转斜杠、统一挂到 MEW_DATA_DIR 下
std::string host_path_from_guest(X64Ctx* c, uint64_t wpath) {
    std::string s = guest_wstr(c, wpath);
    for (char& ch : s) if (ch == '\\') ch = '/';
    if (s.size() >= 2 && s[1] == ':') s = s.substr(2);          // "C:/x" -> "/x"
    while (!s.empty() && s[0] == '/') s.erase(s.begin());       // 去掉前导斜杠
    const char* root = std::getenv("MEW_DATA_DIR");
    std::string base = (root && *root) ? std::string(root) : std::string(".");
    if (!s.empty() && s[0] == '.') { size_t k = 0; while (k < s.size() && (s[k] == '.' || s[k] == '/')) ++k; s = s.substr(k); }
    return base + "/" + s;
}

// 大小写不敏感地找文件（Linux 上 Windows 路径经常大小写不符）
std::string find_case_insensitive(const std::string& path) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (f) { std::fclose(f); return path; }
    // 逐级目录匹配（最多 8 层）
    std::vector<std::string> parts;
    {
        std::string cur;
        for (char ch : path) { if (ch == '/') { if (!cur.empty()) parts.push_back(cur); cur.clear(); } else cur.push_back(ch); }
        if (!cur.empty()) parts.push_back(cur);
    }
    std::string acc = path.rfind('/', 0) == 0 ? "/" : "";
    for (size_t i = 0; i < parts.size(); ++i) {
        std::string want = parts[i];
        bool last = (i + 1 == parts.size());
        std::string cand = acc + (acc.empty() || acc.back() == '/' ? "" : "/") + want;
        if (last) {
            FILE* g = std::fopen(cand.c_str(), "rb");
            if (g) { std::fclose(g); return cand; }
        } else {
            // 目录：用 opendir 找大小写匹配项
            DIR* d = opendir(cand.empty() ? "." : cand.c_str());
            if (!d) {
                DIR* d2 = opendir(acc.empty() ? "." : acc.c_str());
                if (d2) {
                    std::string low = want; for (char& ch : low) ch = (char)std::tolower((unsigned char)ch);
                    struct dirent* de;
                    while ((de = readdir(d2))) {
                        std::string nm = de->d_name, nl = nm;
                        for (char& ch : nl) ch = (char)std::tolower((unsigned char)ch);
                        if (nl == low) { want = nm; break; }
                    }
                    closedir(d2);
                }
            } else closedir(d);
            cand = acc + (acc.empty() || acc.back() == '/' ? "" : "/") + want;
        }
        acc = cand;
    }
    return path;
}

std::mutex g_gpak_mu;
std::unordered_map<uint64_t, bool> g_gpak_handles;
void maybe_probe_gpak(FILE* f, uint64_t handle, const std::string& path) {
    if (path.find("gpak") == std::string::npos) return;
    unsigned char head[16] = {0};
    long cur = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    size_t got = std::fread(head, 1, sizeof(head), f);
    std::fseek(f, cur, SEEK_SET);
    if (got >= 4 && std::memcmp(head, "GPAK", 4) == 0) {
        std::fprintf(stderr, "[STAGE5 PASS] opened %s head=", path.c_str());
        for (size_t i = 0; i < got; ++i) std::fprintf(stderr, "%02x", head[i]);
        std::fprintf(stderr, "\n");
    } else {
        std::fprintf(stderr, "[STAGE5] opened %s but head is not GPAK (first %zu bytes)\n", path.c_str(), got);
    }
    std::lock_guard<std::mutex> lk(g_gpak_mu);
    g_gpak_handles[handle] = true;
}
}  // namespace

// ---------------- 内存 ----------------
// VirtualAlloc/VirtualFree 同理：只 munmap 自己映射过的区间。
// 若 guest 拿 malloc 出来的地址调 VirtualFree，munmap 会把 glibc 堆整块抹掉，
// 之后任何 free 都会崩，现场极难定位。
std::mutex g_virt_mu;
std::unordered_map<void*, size_t> g_virt_ranges;

void shim_KERNEL32_VirtualAlloc(X64Ctx* c) {
    uint64_t size = arg1(c);
    // 同样走固定堆池（匿名 mmap 天然零页，等价于 MEM_COMMIT 语义）
    uint64_t g = g_guest_heap.alloc(size ? (size_t)size : 0x1000, true);
    ret0(c, g);
}

void shim_KERNEL32_VirtualFree(X64Ctx* c) {
    uint64_t a = arg0(c);
    if (!a) { ret0(c, 1); return; }
    if (g_guest_heap.owns(a)) {
        g_guest_heap.free_block(a);
        ret0(c, 1);
    } else {
        std::fprintf(stderr, "[shim] VirtualFree(0x%llx) ignored: outside guest heap pool\n",
                     (unsigned long long)a);
        ret0(c, 0);
    }
}

void shim_KERNEL32_VirtualProtect(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_KERNEL32_GetProcessHeap(X64Ctx* c) { ret0(c, 1); }

// 自己分配的块登记表：guest 只会释放它拿到的块，但被转译的 CRT 在异常路径上
// 可能释放「不是我们 malloc 出来的地址」或重复释放，直接 free() 会让 glibc 段错误
// （实测崩溃点：__libc_free ← shim_KERNEL32_HeapFree ← sub_140d6d140）。
std::mutex g_heap_mu;
std::unordered_set<void*> g_heap_blocks;

void shim_KERNEL32_HeapAlloc(X64Ctx* c) {
    size_t n = (size_t)arg2(c);
    uint32_t flags = (uint32_t)arg1(c);
    // 统一走固定 Guest 堆池：地址一定落在堆区，SAFE_MEM 用区间比较 O(1) 放行
    // 天文数字的申请（实测 malloc(2^64-0x2B0)、malloc(1GiB)）光凭尺寸看不出是谁算的，
    // 一超过阈值就把 guest 调用环打出来：那个减法溢出的现场才是要找的东西。
    if (n > (64u << 20)) call_trace().dump("huge alloc");
    uint64_t g = g_guest_heap.alloc(n ? n : 1, (flags & 0x8u) != 0);  // HEAP_ZERO_MEMORY=0x8
    // 返回 0 时把 caller 也打出来：这类请求通常是「路径解析器拿到坏指针后算出的天文数字」，
    // 栈上那一层的 caller 才是要查的对象。
    // 节流：HeapAlloc 是热路径，以前**每次调用都打**，run 46055985114 里
    // 0x140d1f7e4 的循环分配了几百万次 → runner.err 涨到 1.88 GB，artifact 没法读。
    // 前 2000 次全打（初始化现场够用），之后每 10 万次补一行计数，NULL 一律要打。
    static uint64_t logged = 0;
    ++logged;
    if (!g || logged <= 2000 || (logged % 100000) == 0)
        std::fprintf(stderr, "[shim] HeapAlloc(%zu, flags=0x%x)=0x%llx caller=0x%llx%s [n=%llu]\n",
                     n, flags, (unsigned long long)g, (unsigned long long)cur_fn_va(),
                     g ? "" : " (NULL: refused)", (unsigned long long)logged);
    ret0(c, g);
}

void shim_KERNEL32_HeapFree(X64Ctx* c) {
    uint64_t a = arg2(c);
    if (!a) { ret0(c, 1); return; }
    if (g_guest_heap.owns(a)) {
        g_guest_heap.free_block(a);
        ret0(c, 1);
    } else {
        std::fprintf(stderr, "[shim] HeapFree(0x%llx) ignored: outside guest heap pool\n",
                     (unsigned long long)a);
        ret0(c, 0);
    }
}

// ---------------- Heap 家族其余成员 ----------------
// 实测证据（run 45873066277）：HeapAlloc(16) 成功后 CRT 紧接着调 HeapReAlloc，
// 而 HeapReAlloc 当时只有自动生成的弱占位（打印 [UNIMPL API] 后返回 0），
// 调用方把 NULL 存进链表槽，下一轮读 [NULL+0x10] 就成了 fault=0x10。
// 结论：这一族必须是真实现，不能靠「返回非零假装成功」。
namespace {
constexpr uint32_t kHeapZeroMemory    = 0x8u;
constexpr uint32_t kHeapInPlaceOnly   = 0x10u;
}  // namespace

void shim_KERNEL32_HeapReAlloc(X64Ctx* c) {
    const uint32_t flags = (uint32_t)arg1(c);
    const uint64_t mem = arg2(c);
    size_t n = (size_t)arg3(c);
    static int logged = 0;
    const bool verbose = logged++ < 30;

    // 语义对齐 Windows：lpMem == NULL 等价于 HeapAlloc；dwBytes == 0 也要给有效指针
    if (!mem) {
        if (n > (64u << 20)) call_trace().dump("huge alloc(realloc)");
        uint64_t g = g_guest_heap.alloc(n ? n : 1, (flags & kHeapZeroMemory) != 0);
        if (!g && n > (1u << 24))
            std::fprintf(stderr, "[shim] HeapReAlloc(NULL, %zu) refused caller=0x%llx\n",
                         n, (unsigned long long)cur_fn_va());
        if (verbose)
            std::fprintf(stderr, "[shim] HeapReAlloc(NULL, %zu, flags=0x%x)=0x%llx (as alloc) caller=0x%llx\n",
                         n, flags, (unsigned long long)g, (unsigned long long)cur_fn_va());
        ret0(c, g);
        return;
    }
    if (!g_guest_heap.owns(mem)) {
        std::fprintf(stderr, "[shim] HeapReAlloc(0x%llx, %zu) refused: outside guest heap pool\n",
                     (unsigned long long)mem, n);
        ret0(c, 0);
        return;
    }
    if (n == 0) n = 1;
    const size_t old_cap = g_guest_heap.size_of(mem);  // 已对齐的物理大小
    size_t new_cap = (n + 15ULL) & ~static_cast<size_t>(15ULL);
    if (!new_cap) new_cap = 16;

    // 先试原地扩：只有「最新一块」能扩，bump 堆永远不缩
    if (g_guest_heap.grow_in_place(mem, new_cap, (flags & kHeapZeroMemory) != 0)) {
        g_guest_heap.set_requested(mem, n);
        if (verbose)
            std::fprintf(stderr, "[shim] HeapReAlloc(0x%llx -> %zu) in-place ok caller=0x%llx\n",
                         (unsigned long long)mem, n, (unsigned long long)cur_fn_va());
        ret0(c, mem);
        return;
    }
    if (flags & kHeapInPlaceOnly) {
        if (verbose)
            std::fprintf(stderr, "[shim] HeapReAlloc(0x%llx -> %zu) refused: IN_PLACE_ONLY\n",
                         (unsigned long long)mem, n);
        ret0(c, 0);
        return;
    }

    // 退化成 HeapAlloc + memcpy + 释放旧块（旧块内存不回收，杜绝 use-after-free）
    uint64_t p = g_guest_heap.alloc(n, false);
    // 堆池拒绝（size 是坏指针算出来的天文数字）时必须先返回 NULL，
    // 否则下面的 memcpy 会往地址 0 写，把「申请失败」变成「野写」。
    if (!p) {
        std::fprintf(stderr, "[shim] HeapReAlloc(0x%llx -> %zu) refused: pool declined caller=0x%llx\n",
                     (unsigned long long)mem, n, (unsigned long long)cur_fn_va());
        ret0(c, 0);
        return;
    }
    const size_t cp = old_cap < n ? old_cap : n;
    if (cp) {
        std::memcpy(reinterpret_cast<void*>((uintptr_t)(p + c->mem_bias)),
                    reinterpret_cast<const void*>((uintptr_t)(mem + c->mem_bias)), cp);
    }
    if ((flags & kHeapZeroMemory) && cp < n) {
        std::memset(reinterpret_cast<void*>((uintptr_t)(p + c->mem_bias + cp)), 0, n - cp);
    }
    g_guest_heap.free_block(mem);
    if (verbose)
        std::fprintf(stderr, "[shim] HeapReAlloc(0x%llx -> %zu)=0x%llx (moved) caller=0x%llx\n",
                     (unsigned long long)mem, n, (unsigned long long)p,
                     (unsigned long long)cur_fn_va());
    ret0(c, p);
}

void shim_KERNEL32_HeapSize(X64Ctx* c) {
    uint64_t mem = arg2(c);
    size_t n = mem ? g_guest_heap.requested(mem) : 0;
    static int logged = 0;
    if (logged++ < 10)
        std::fprintf(stderr, "[shim] HeapSize(0x%llx)=%zu caller=0x%llx\n",
                     (unsigned long long)mem, n, (unsigned long long)cur_fn_va());
    ret0(c, n ? (uint64_t)n : (uint64_t)-1);
}

void shim_KERNEL32_HeapValidate(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_KERNEL32_HeapCompact(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_KERNEL32_HeapCreate(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_KERNEL32_HeapDestroy(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_KERNEL32_HeapSetInformation(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_KERNEL32_HeapQueryInformation(X64Ctx* c) {
    // (hHeap, HeapInformationClass, HeapInformation, HeapInformationLength, lpReturnLength)
    const uint64_t info = arg2(c);
    const size_t  len  = (size_t)arg3(c);
    if (info && len) std::memset(guest_ptr_from_ctx(c, info), 0, len);
    if (arg4(c)) mem_write<uint32_t>(c, arg4(c), 0);
    ret0(c, 1);
}

void shim_KERNEL32_FreeEnvironmentStringsW(X64Ctx* c) {
    // 与 GetEnvironmentStringsW 配对：那边是一次 guest_alloc 的常驻块，这里只需承认
    static int logged = 0;
    if (logged++ < 5)
        std::fprintf(stderr, "[shim] FreeEnvironmentStringsW(0x%llx) caller=0x%llx\n",
                     (unsigned long long)arg0(c), (unsigned long long)cur_fn_va());
    ret0(c, 1);
}

// ---------------- 文件 ----------------
void shim_KERNEL32_CreateFileW(X64Ctx* c) { mew_api_hit("CreateFileW");
    std::string path = find_case_insensitive(host_path_from_guest(c, arg0(c)));
    uint32_t access = (uint32_t)arg1(c);
    const char* mode = (access & 0x40000000u) ? "wb+" : ((access & 0x80000000u) ? "rb" : "rb");
    FILE* f = std::fopen(path.c_str(), mode);
    std::fprintf(stderr, "[shim] CreateFileW(\"%s\", 0x%x) = %p\n", path.c_str(), access, (void*)f);
    if (!f) { ret0(c, (uint64_t)-1); return; }
    uint64_t h = HandleTable::instance().add(f);
    maybe_probe_gpak(f, h, path);
    ret0(c, h);
}

// CreateFileA：ANSI 版，语义与 W 版一致。原来没有垫片，落到自动弱桩返回 0，
// 调用方会当成「打不开文件」——而这条路径在日志里连痕迹都没有。
void shim_KERNEL32_CreateFileA(X64Ctx* c) {
    std::string win = guest_wstr(c, arg0(c));            // 复用同一套 W 字符处理
    std::string path = find_case_insensitive(host_path_from_guest(c, arg0(c)));
    uint32_t access = (uint32_t)arg1(c);
    const char* mode = (access & 0x40000000u) ? "wb+" : "rb";
    FILE* f = std::fopen(path.c_str(), mode);
    std::fprintf(stderr, "[shim] CreateFileA(\"%s\", 0x%x) = %p caller=0x%llx\n",
                 path.c_str(), access, (void*)f, (unsigned long long)cur_fn_va());
    (void)win;
    if (!f) { ret0(c, (uint64_t)-1); return; }
    ret0(c, HandleTable::instance().add(f));
}

// FindFirstFileExW：现代枚举入口，游戏完全可能只用它。先让它出声，
// 并把调用环打出来（前 3 次），这样「游戏是否开始找资源」有据可查。
// FindFirstFileExW 只是 FindFirstFileW 的带 flag 版本；infoLevel 我们一律按
// FindExInfoStandard 处理（dir/path 直接 stat 就有），所以共用同一套枚举。
void shim_KERNEL32_FindFirstFileExW(X64Ctx* c) { shim_KERNEL32_FindFirstFileW(c); }

// ---------------- USER32 的 DPI / Touch 系列 ----------------
// windows video driver 的 CreateDevice（0x140bfb770）会对 USER32.DLL 逐个
// GetProcAddress 取下面 8 个，包装函数 0x140c03100 在拿到 0 时会 SetError
// 并返回 0，而调用方紧跟 `test rax,rax; je <整个 CreateDevice 失败>`。
// 实测日志里这 8 个**全部返回 0x0**，于是 windows driver 永远建不起来，
// SDL_VideoInit 里 rdi 拿不到设备、_this 永远为 0、SDL_CreateWindow 入口即失败。
// 返回值按「成功」的语义给：BOOL 类给 1；context 类给一个非零句柄；
// awareness 给 1(DpiAwarenessUnaware) —— 这是最保守且不会触发重算的取值。
void shim_USER32_SetProcessDPIAware(X64Ctx* c) { ret0(c, 1); }
void shim_USER32_SetProcessDpiAwarenessContext(X64Ctx* c) { ret0(c, 1); }
void shim_USER32_SetThreadDpiAwarenessContext(X64Ctx* c) { ret0(c, 1); }   // 返回旧 ctx
void shim_USER32_GetThreadDpiAwarenessContext(X64Ctx* c) { ret0(c, 1); }
void shim_USER32_GetAwarenessFromDpiAwarenessContext(X64Ctx* c) { ret0(c, 1); }  // UNAWARE
void shim_USER32_AreDpiAwarenessContextsEqual(X64Ctx* c) { ret0(c, arg0(c) == arg1(c) ? 1u : 0u); }
void shim_USER32_IsValidDpiAwarenessContext(X64Ctx* c) { ret0(c, 1); }
void shim_USER32_RegisterTouchWindow(X64Ctx* c) { ret0(c, 1); }
void shim_USER32_GetTouchInputInfo(X64Ctx* c) { ret0(c, 1); }
void shim_USER32_CloseTouchInputHandle(X64Ctx* c) { ret0(c, 1); }

// ---------------- 路径规范化 + Local 堆（std::filesystem 的依赖）----------------
// MSVC 的 std::filesystem 需要绝对化/规范化路径时走这一组：
//   LocalAlloc -> GetFullPathNameW -> LocalFree
// 这三个我们**一个都没实现**，直接后果在 run 46085714325 里可见：
//   * UNIMPL API TABLE 只剩 LocalFree(distinct=1 total=2)，紧贴 RaiseException 之前
//   * GetFullPathNameW 一次都没出现 —— 因为 LocalAlloc 先失败，没缓冲区可用
//   * create_directories 的复核只查了盘符根（三次 GetFileAttributesExW("./")），
//     叶子路径一次都没查到，正好符合「规范化阶段就把路径丢了」
void shim_KERNEL32_LocalAlloc(X64Ctx* c) {
    const uint32_t flags = (uint32_t)arg0(c);
    const size_t n = (size_t)arg1(c);
    // LMEM_ZEROINIT = 0x40；统一走固定 Guest 堆池，地址一定落在堆区
    const uint64_t g = g_guest_heap.alloc(n ? n : 1, (flags & 0x40u) != 0);
    static int traced = 0;
    if (traced++ < 16)
        std::fprintf(stderr, "[shim] LocalAlloc(flags=0x%x, %zu) -> 0x%llx caller=0x%llx\n",
                     flags, n, (unsigned long long)g, (unsigned long long)cur_fn_va());
    ret0(c, g);
}
void shim_KERNEL32_LocalFree(X64Ctx* c) {
    // guest 堆没有逐个 free 的通道；Win32 语义里「成功返回 NULL」，
    // 所以返回 0 既符合语义，也不会让上游把 LocalFree 当成失败。
    ret0(c, 0);
}

void shim_KERNEL32_GetFullPathNameW(X64Ctx* c) {
    const std::string in = guest_wstr(c, arg0(c));
    const uint32_t cap = (uint32_t)arg1(c);
    const uint64_t buf = arg2(c);
    const uint64_t part = arg3(c);   // lpFilePart

    std::string s = in;
    for (char& ch : s) if (ch == '\\') ch = '/';
    if (s.size() < 2 || s[1] != ':') s = "C:/" + s;   // 我们只有一个盘：C:
    const std::string drv = s.substr(0, 2);
    const std::string rest = s.substr(2);
    const bool abs = !rest.empty() && rest[0] == '/';
    std::vector<std::string> segs;
    size_t i = 0;
    while (i < rest.size()) {
        while (i < rest.size() && rest[i] == '/') ++i;
        size_t j = i;
        while (j < rest.size() && rest[j] != '/') ++j;
        const std::string seg = rest.substr(i, j - i);
        if (seg == "..") { if (!segs.empty()) segs.pop_back(); }
        else if (!seg.empty() && seg != ".") segs.push_back(seg);
        i = j;
    }
    std::string out = drv + (abs ? "/" : "");
    for (size_t k = 0; k < segs.size(); ++k) {
        if (k) out += "/";
        out += segs[k];
    }
    const uint64_t need = (uint64_t)out.size() + 1;

    static int traced = 0;
    if (traced++ < 24)
        std::fprintf(stderr, "[shim] GetFullPathNameW(\"%s\") -> \"%s\" cap=%u caller=0x%llx\n",
                     in.c_str(), out.c_str(), cap, (unsigned long long)cur_fn_va());

    if (!buf || cap < need) { ret0(c, need); return; }   // 缓冲区不够：返回所需大小
    uint16_t* p = (uint16_t*)guest_ptr_from_ctx(c, buf);
    for (size_t k = 0; k < out.size(); ++k) p[k] = (uint16_t)(unsigned char)out[k];
    p[out.size()] = 0;
    if (part && guest_mapped(part, 8)) {
        uint64_t off = out.size();
        while (off > 0 && out[off - 1] != '/') --off;
        mem_write<uint64_t>(c, part, off < out.size() ? buf + off * 2 : 0);
    }
    ret0(c, (uint64_t)out.size());
}

// GetFileAttributesExW：拿不到时返回 FALSE 并置 last error。
// 同样先出声，避免「文件存在但游戏以为不存在」被静默吞掉。
void shim_KERNEL32_GetFileAttributesExW(X64Ctx* c) {
    const std::string raw  = guest_wstr(c, arg0(c));
    const std::string path = find_case_insensitive(host_path_from_guest(c, arg0(c)));
    const uint64_t out = arg2(c);   // lpFileInformation（第 3 个参数 = r8）
    // 以前这里只 fopen 判"能不能打开"，**一个字节都没往 lpFileInformation 写**。
    // MSVC 的 std::filesystem::create_directories 建完目录后正是用
    // GetFileAttributesExW（不是 GetFileAttributesW）复核：它读 dwFileAttributes，
    // 拿到 0 就认为「既不是目录也不是文件」，直接抛
    //   filesystem_error("create_directories: unknown error")
    // run 上实测就是 `[shim] GetFileAttributesExW("./")=TRUE` 却仍然抛异常 ——
    // 返回 TRUE 但结构是空的，等于什么都没说。
    struct stat st;
    // 空路径必须失败：Windows 上 GetFileAttributesExW(L"") 返回 FALSE 且
    // GetLastError=ERROR_PATH_NOT_FOUND(3)。以前我们把 "" 翻译成 "./" 然后报 TRUE，
    // 等于告诉 std::filesystem「这个并不存在的路径组件其实是个目录」，它就会一路
    // 走下去、最后抛 filesystem_error。run 46088817207 里连续三次
    //   [shim] GetFileAttributesExW(guest="" host="./")=TRUE attr=0x10
    // 紧接着就是 [cxx-eh] #2，证据链就在这里。
    const bool ok = !raw.empty() && !path.empty() && ::stat(path.c_str(), &st) == 0;
    if (!ok) mew_set_last_error(raw.empty() ? 3u : 2u);   // 3=PATH_NOT_FOUND / 2=FILE_NOT_FOUND
    const uint32_t attr = ok ? (S_ISDIR(st.st_mode) ? 0x10u : 0x80u) : 0u;
    if (ok && out) {
        // WIN32_FILE_ATTRIBUTE_DATA（36 字节，x64）
        //   +0  dwFileAttributes      DWORD
        //   +4  ftCreationTime        FILETIME (2 x DWORD)
        //   +12 ftLastAccessTime      FILETIME
        //   +20 ftLastWriteTime       FILETIME
        //   +28 nFileSizeHigh         DWORD
        //   +32 nFileSizeLow          DWORD
        // FILETIME 是「1601-01-01 起的 100ns 数」，和 unix time 差 11644473600 秒。
        const uint64_t ft = ((uint64_t)st.st_mtime + 11644473600ULL) * 10000000ULL;
        const uint64_t at = ((uint64_t)st.st_atime + 11644473600ULL) * 10000000ULL;
        const uint64_t sz = (uint64_t)st.st_size;
        mem_write<uint32_t>(c, out + 0,  attr);
        mem_write<uint32_t>(c, out + 4,  (uint32_t)(ft & 0xFFFFFFFFu));
        mem_write<uint32_t>(c, out + 8,  (uint32_t)(ft >> 32));
        mem_write<uint32_t>(c, out + 12, (uint32_t)(at & 0xFFFFFFFFu));
        mem_write<uint32_t>(c, out + 16, (uint32_t)(at >> 32));
        mem_write<uint32_t>(c, out + 20, (uint32_t)(ft & 0xFFFFFFFFu));
        mem_write<uint32_t>(c, out + 24, (uint32_t)(ft >> 32));
        mem_write<uint32_t>(c, out + 28, (uint32_t)(sz >> 32));
        mem_write<uint32_t>(c, out + 32, (uint32_t)(sz & 0xFFFFFFFFu));
    }
    static int traced = 0;
    if (traced++ < 24) {
        // 同时打 **guest 原始路径** 和翻译后的宿主路径：`std::filesystem` 抛异常时我们
        // 一直只看到翻译结果（连续三次都是 "./"），无法判断引擎到底问的是 C:\、C: 还是别的。
        std::fprintf(stderr,
                     "[shim] GetFileAttributesExW(guest=\"%s\" host=\"%s\" ptr=0x%llx)=%s attr=0x%x size=%lld caller=0x%llx\n",
                     raw.c_str(), path.c_str(), (unsigned long long)arg0(c),
                     ok ? "TRUE" : "FALSE", attr,
                     ok ? (long long)st.st_size : -1LL,
                     (unsigned long long)cur_fn_va());
    }
    ret0(c, ok ? 1u : 0u);
}

void shim_KERNEL32_ReadFile(X64Ctx* c) { mew_api_hit("ReadFile");
    FILE* f = file_from_handle(arg0(c));
    uint64_t buf = arg1(c);
    uint32_t want = (uint32_t)arg2(c);
    uint64_t got_ptr = arg3(c);
    size_t got = 0;
    if (f && buf && want) {
        got = std::fread(guest_ptr_from_ctx(c, buf), 1, want, f);
    }
    if (got_ptr) mem_write<uint32_t>(c, got_ptr, (uint32_t)got);
    ret0(c, 1);
}

void shim_KERNEL32_WriteFile(X64Ctx* c) {
    FILE* f = file_from_handle(arg0(c));
    uint64_t buf = arg1(c);
    uint32_t want = (uint32_t)arg2(c);
    uint64_t got_ptr = arg3(c);
    size_t got = 0;
    if (f && buf && want) got = std::fwrite(guest_ptr_from_ctx(c, buf), 1, want, f);
    if (got_ptr) mem_write<uint32_t>(c, got_ptr, (uint32_t)got);
    ret0(c, 1);
}

void shim_KERNEL32_SetFilePointerEx(X64Ctx* c) {
    FILE* f = file_from_handle(arg0(c));
    int64_t dist = (int64_t)arg1(c);
    uint32_t method = (uint32_t)arg3(c);
    int whence = method == 1 ? SEEK_CUR : (method == 2 ? SEEK_END : SEEK_SET);
    int rc = f ? fseek(f, (long)dist, whence) : -1;
    ret0(c, rc == 0 ? 1 : 0);
}

void shim_KERNEL32_GetFileSizeEx(X64Ctx* c) {
    FILE* f = file_from_handle(arg0(c));
    long cur = f ? ftell(f) : 0;
    long size = 0;
    if (f) { fseek(f, 0, SEEK_END); size = ftell(f); fseek(f, cur, SEEK_SET); }
    if (arg1(c)) mem_write<int64_t>(c, arg1(c), (int64_t)size);
    ret0(c, f ? 1 : 0);
}

void shim_KERNEL32_CloseHandle(X64Ctx* c) {
    uint64_t h = arg0(c);
    FILE* f = file_from_handle(h);
    if (f) std::fclose(f);
    HandleTable::instance().erase(h);
    ret0(c, 1);
}

void shim_KERNEL32_FlushFileBuffers(X64Ctx* c) {
    FILE* f = file_from_handle(arg0(c));
    if (f) std::fflush(f);
    ret0(c, 1);
}

// ---------------- 线程/TLS/同步 ----------------
void shim_KERNEL32_TlsAlloc(X64Ctx* c) {
    std::lock_guard<std::mutex> lk(g_tls_mu);
    for (int i = 1; i < 1024; ++i) if (!g_tls_used[i]) { g_tls_used[i] = true; ret0(c, i); return; }
    ret0(c, (uint64_t)-1);
}

void shim_KERNEL32_TlsFree(X64Ctx* c) {
    uint32_t i = (uint32_t)arg0(c);
    if (i < 1024) g_tls_used[i] = false;
    ret0(c, 1);
}

// x64 Windows 上 TLS 只有**一份**真相：TEB+TlsSlots（`gs:[0x58 + 8*index]`）。
// `__declspec(thread)` 变量是编译器直接发 `mov rax, gs:[0x58 + 8*index]` 读的，
// 根本不经过 TlsGetValue。之前这里写的是宿主侧 thread_local g_tls[]，于是两条路
// 互不可见——线程局部变量在模拟器里永远是 0，CRT 拿它当对象指针就会崩
//（stage3 实测：0x140d6d140 里 `mov [rax],ebx` 写到 0xc06b57238）。
// 现在两个 API 直接读写伪 TEB 的 TlsSlots，和编译器生成的访问路径对齐；
// 索引 >=64 的仍然落在宿主数组里（Windows 那边是 TlsExpansionSlots）。
// TEB+0x58 = ThreadLocalStoragePointer → 指向 64 项指针数组；模块的 TLS 块挂在
// 数组[_tls_index] 上（和 MSVC 生成的 `mov rax,gs:[58h]; mov r14,[rax+idx*8]` 对齐）。
static uint64_t tls_slot_addr(X64Ctx* c, uint32_t idx) {
    uint64_t arr = mem_read<uint64_t>(c, c->gs_base + 0x58);
    if (!arr) return 0;
    return arr + (uint64_t)idx * 8;
}

void shim_KERNEL32_TlsGetValue(X64Ctx* c) {
    uint32_t i = (uint32_t)arg0(c) & 1023;
    uint64_t a = (i < 64) ? tls_slot_addr(c, i) : 0;
    if (a) { ret0(c, mem_read<uint64_t>(c, a)); return; }
    ret0(c, g_tls[i]);
}

void shim_KERNEL32_TlsSetValue(X64Ctx* c) {
    uint32_t i = (uint32_t)arg0(c) & 1023;
    uint64_t a = (i < 64) ? tls_slot_addr(c, i) : 0;
    if (a) mem_write<uint64_t>(c, a, arg1(c));
    else g_tls[i] = arg1(c);
    ret0(c, 1);
}

void shim_KERNEL32_InitializeCriticalSection(X64Ctx* c) {
    pthread_mutex_t* m = new pthread_mutex_t;
    // Windows 的 CRITICAL_SECTION 是可重入锁；pthread 默认互斥锁不可重入。
    // 用默认属性会让"同一执行流二次 EnterCriticalSection"永久自旋
    //（实测锁表下标 7：_lock(7) 之后再 _lock(7)，15 次采样栈完全不变）。
    pthread_mutexattr_t attr;
    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(m, &attr);
    pthread_mutexattr_destroy(&attr);
    if (arg0(c)) mem_write<uint64_t>(c, arg0(c), (uint64_t)((int64_t)(uintptr_t)m - c->mem_bias));
    ret0(c, 1);
}

// Windows 的 CRITICAL_SECTION 是可重入的。pthread 的 RECURSIVE 属性在部分构建里
// 没生效（实测同一 cs=0x1413bb298 二次进入直接堵死），所以这里自己记深度：
// 只在 0->1 时真正 lock，1->0 时 unlock，中间的重入只加计数。
std::mutex g_cs_mu;
std::unordered_map<uint64_t, int> g_cs_depth;

void shim_KERNEL32_EnterCriticalSection(X64Ctx* c) {
    uint64_t cs = arg0(c);
    uint64_t m = cs ? mem_read<uint64_t>(c, cs) : 0;
    int d = 0;
    {
        std::lock_guard<std::mutex> lk(g_cs_mu);
        d = ++g_cs_depth[cs];
    }
    static int logged = 0;
    if (logged++ < 40)
        std::fprintf(stderr, "[shim] EnterCS(cs=0x%llx mutex=0x%llx depth=%d)\n",
                     (unsigned long long)cs, (unsigned long long)m, d);
    if (d == 1 && m)
        pthread_mutex_lock((pthread_mutex_t*)(uintptr_t)((int64_t)m + c->mem_bias));
    ret0(c, 1);
}

void shim_KERNEL32_LeaveCriticalSection(X64Ctx* c) {
    uint64_t cs = arg0(c);
    uint64_t m = cs ? mem_read<uint64_t>(c, cs) : 0;
    int d = 0;
    {
        std::lock_guard<std::mutex> lk(g_cs_mu);
        auto it = g_cs_depth.find(cs);
        if (it != g_cs_depth.end() && it->second > 0) d = --it->second;
    }
    static int logged = 0;
    if (logged++ < 40)
        std::fprintf(stderr, "[shim] LeaveCS(cs=0x%llx mutex=0x%llx depth=%d)\n",
                     (unsigned long long)cs, (unsigned long long)m, d);
    if (d == 0 && m) pthread_mutex_unlock((pthread_mutex_t*)(uintptr_t)((int64_t)m + c->mem_bias));
    ret0(c, 1);
}

void shim_KERNEL32_DeleteCriticalSection(X64Ctx* c) { (void)c; ret0(c, 1); }

// ---------------- 时间 ----------------
void shim_KERNEL32_QueryPerformanceCounter(X64Ctx* c) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    int64_t v = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
    if (arg0(c)) mem_write<int64_t>(c, arg0(c), v);
    ret0(c, 1);
}

void shim_KERNEL32_QueryPerformanceFrequency(X64Ctx* c) {
    if (arg0(c)) mem_write<int64_t>(c, arg0(c), 1000000000LL);
    ret0(c, 1);
}

void shim_KERNEL32_Sleep(X64Ctx* c) { usleep((useconds_t)((uint32_t)arg0(c) * 1000u)); ret0(c, 0); }
void shim_KERNEL32_GetTickCount(X64Ctx* c) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    ret0(c, (uint32_t)(ts.tv_sec * 1000ull + ts.tv_nsec / 1000000ull));
}
void shim_KERNEL32_GetTickCount64(X64Ctx* c) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    ret0(c, (uint64_t)(ts.tv_sec * 1000ull + ts.tv_nsec / 1000000ull));
}

// ---------------- 模块/调试/杂项 ----------------
void shim_KERNEL32_GetLastError(X64Ctx* c) { ret0(c, (uint64_t)g_last_error); }
void shim_KERNEL32_SetLastError(X64Ctx* c) { g_last_error = (uint32_t)arg0(c); ret0(c, 0); }
void shim_KERNEL32_GetModuleHandleW(X64Ctx* c) { ret0(c, 0x140000000ULL); }
void shim_KERNEL32_GetModuleHandleA(X64Ctx* c) { ret0(c, 0x140000000ULL); }
void shim_KERNEL32_GetModuleFileNameW(X64Ctx* c) { ret0(c, 0); }
void shim_KERNEL32_IsDebuggerPresent(X64Ctx* c) { ret0(c, 0); }
void shim_KERNEL32_GetCurrentProcessId(X64Ctx* c) { ret0(c, (uint64_t)getpid()); }
void shim_KERNEL32_GetCurrentThreadId(X64Ctx* c) { ret0(c, (uint64_t)(uintptr_t)pthread_self()); }
void shim_KERNEL32_GetSystemInfo(X64Ctx* c) {
    // SYSTEM_INFO（x64 布局，48 字节）。旧实现把页大小写到了 p+20（那是
    // lpMaximumApplicationAddress 的中间），且把架构报成 x86；这里按 1 核 ARM64 填。
    const uint64_t p = arg0(c);
    if (p) {
        std::memset(guest_ptr_from_ctx(c, p), 0, 48);
        mem_write<uint16_t>(c, p + 0, 12);                 // PROCESSOR_ARCHITECTURE_ARM64
        mem_write<uint32_t>(c, p + 4, 0x4000);             // dwPageSize
        mem_write<uint64_t>(c, p + 8, 0x10000);            // lpMinimumApplicationAddress
        mem_write<uint64_t>(c, p + 16, 0x7FFFFFFEFFFFULL); // lpMaximumApplicationAddress
        mem_write<uint64_t>(c, p + 24, 1);                 // dwActiveProcessorMask
        mem_write<uint32_t>(c, p + 32, 1);                 // dwNumberOfProcessors
        mem_write<uint32_t>(c, p + 36, 1);                 // dwProcessorType
        mem_write<uint32_t>(c, p + 40, 0x10000);           // dwAllocationGranularity
        mem_write<uint16_t>(c, p + 44, 8);                 // wProcessorLevel
        mem_write<uint16_t>(c, p + 46, 0);                 // wProcessorRevision
    }
    ret0(c, 0);
}
void shim_KERNEL32_InitializeSListHead(X64Ctx* c) { if (arg0(c)) mem_write<uint64_t>(c, arg0(c), 0); ret0(c, 0); }
void shim_KERNEL32_SetUnhandledExceptionFilter(X64Ctx* c) { ret0(c, 0); }
void shim_KERNEL32_UnhandledExceptionFilter(X64Ctx* c) { ret0(c, 1); }

void shim_KERNEL32_MultiByteToWideChar(X64Ctx* c) {
    // (CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar)
    // **返回 0 就是失败**。旧实现是 `(void)c; ret0(c, 0);` —— 和 GetCurrentDirectoryW 同病：
    // MSVC 的 std::filesystem 做窄→宽（path::wstring / 错误消息）时会用它，拿到 0 就
    // 当失败，最终翻成一个没有任何数字的 error_code。
    // 按 UTF-8 解码成 UTF-16：游戏内路径与消息全是 ASCII，CP_ACP 在真机上也等价于
    // 当前 ANSI 代码页，这里统一按 UTF-8 处理（非 ASCII 遇到再按日志里的 cp 分支）。
    const uint32_t cp  = (uint32_t)arg0(c);
    const uint64_t src = arg2(c);
    const int      cb  = (int)arg3(c);
    const uint64_t dst = arg4(c);
    const int      cch = (int)arg5(c);
    if (!src) { mew_set_last_error(87); ret0(c, 0); return; }   // ERROR_INVALID_PARAMETER

    const bool nul_term = cb < 0;
    size_t nbytes = 0;
    if (nul_term) {
        const char* p = (const char*)guest_ptr_from_ctx(c, src);
        nbytes = p ? std::strlen(p) + 1 : 0;
    } else {
        nbytes = (size_t)cb;
    }

    std::vector<uint16_t> w;
    w.reserve(nbytes + 1);
    for (size_t i = 0; i < nbytes;) {
        const uint8_t b = mem_read<uint8_t>(c, src + i);
        if (b == 0) { w.push_back(0); ++i; if (nul_term) break; continue; }
        uint32_t cpv = b;
        size_t extra = 0;
        if (b >= 0xF0)      { cpv = b & 0x07u; extra = 3; }
        else if (b >= 0xE0) { cpv = b & 0x0Fu; extra = 2; }
        else if (b >= 0xC0) { cpv = b & 0x1Fu; extra = 1; }
        ++i;
        for (size_t k = 0; k < extra && i < nbytes; ++k, ++i)
            cpv = (cpv << 6) | (uint32_t)(mem_read<uint8_t>(c, src + i) & 0x3Fu);
        if (cpv < 0x10000u) {
            w.push_back((uint16_t)cpv);
        } else {
            cpv -= 0x10000u;
            w.push_back((uint16_t)(0xD800u + (cpv >> 10)));
            w.push_back((uint16_t)(0xDC00u + (cpv & 0x3FFu)));
        }
    }

    static int logged = 0;
    if (logged++ < 10)
        std::fprintf(stderr, "[shim] MultiByteToWideChar(cp=%u, cb=%d, cch=%d) = %zu caller=0x%llx\n",
                     cp, cb, cch, w.size(), (unsigned long long)cur_fn_va());

    if (!dst || cch == 0) { ret0(c, (uint64_t)w.size()); return; }   // 只问所需长度
    if ((size_t)cch < w.size()) { mew_set_last_error(122); ret0(c, 0); return; }  // INSUFFICIENT_BUFFER
    for (size_t i = 0; i < w.size(); ++i) mem_write<uint16_t>(c, dst + i * 2, w[i]);
    ret0(c, (uint64_t)w.size());
}
void shim_KERNEL32_lstrlenW(X64Ctx* c) {
    const uint16_t* p = (const uint16_t*)guest_ptr_from_ctx(c, arg0(c));
    size_t n = 0;
    while (p && p[n]) ++n;
    ret0(c, (uint64_t)n);
}

// ---------------- USER32（最小） ----------------
void shim_USER32_MessageBoxW(X64Ctx* c) {
    std::fprintf(stderr, "[shim] MessageBoxW: %s\n", guest_wstr(c, arg1(c)).c_str());
    ret0(c, 1);
}
void shim_USER32_GetSystemMetrics(X64Ctx* c) { mew_api_hit("GetSystemMetrics"); ret0(c, (uint32_t)arg0(c) == 0 ? 1920 : 1080); }
void shim_USER32_GetDesktopWindow(X64Ctx* c) { ret0(c, 1); }

// ---------------- CRT / 时间补充 ----------------
void shim_KERNEL32_GetSystemTimeAsFileTime(X64Ctx* c) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    // FILETIME: 100ns since 1601-01-01
    int64_t ft = ((int64_t)ts.tv_sec + 11644473600LL) * 10000000LL + ts.tv_nsec / 100;
    if (arg0(c)) { mem_write<uint32_t>(c, arg0(c), (uint32_t)ft); mem_write<uint32_t>(c, arg0(c) + 4, (uint32_t)(ft >> 32)); }
    ret0(c, 0);
}

void shim_KERNEL32_GetSystemTime(X64Ctx* c) { if (arg0(c)) std::memset(guest_ptr_from_ctx(c, arg0(c)), 0, 16); ret0(c, 0); }
void shim_KERNEL32_GetLocalTime(X64Ctx* c) { if (arg0(c)) std::memset(guest_ptr_from_ctx(c, arg0(c)), 0, 16); ret0(c, 0); }
void shim_KERNEL32_GetTimeZoneInformation(X64Ctx* c) { if (arg0(c)) std::memset(guest_ptr_from_ctx(c, arg0(c)), 0, 172); ret0(c, 0); }
void shim_KERNEL32_GetACP(X64Ctx* c) { ret0(c, 65001); }
void shim_KERNEL32_GetOEMCP(X64Ctx* c) { ret0(c, 65001); }
void shim_KERNEL32_GetCPInfo(X64Ctx* c) { ret0(c, 1); }
void shim_KERNEL32_GetStringTypeW(X64Ctx* c) { ret0(c, 0); }
void shim_KERNEL32_LCMapStringW(X64Ctx* c) { ret0(c, 0); }
void shim_KERNEL32_IsValidCodePage(X64Ctx* c) { ret0(c, 1); }
void shim_KERNEL32_IsValidLocale(X64Ctx* c) { ret0(c, 1); }
void shim_KERNEL32_GetUserDefaultLCID(X64Ctx* c) { ret0(c, 0x0409); }
void shim_KERNEL32_GetSystemDefaultLCID(X64Ctx* c) { ret0(c, 0x0409); }
void shim_KERNEL32_GetSystemTimePreciseAsFileTime(X64Ctx* c) { shim_KERNEL32_GetSystemTimeAsFileTime(c); }
void shim_KERNEL32_OutputDebugStringW(X64Ctx* c) {
    std::fprintf(stderr, "[game] %s\n", guest_wstr(c, arg0(c)).c_str());
    ret0(c, 0);
}
void shim_KERNEL32_TryEnterCriticalSection(X64Ctx* c) {
    shim_KERNEL32_EnterCriticalSection(c);
    ret0(c, 1);
}
// ---------------- 真线程 / 真事件（MEW_REAL_THREADS=1 开启） ----------------
// 背景（run 46061908947 的实测）：主线程在 0x140d1f7e4 上对镜像内 cv(0x1412f80a0)
// 反复 INFINITE 等待，而另一条路径在堆上的 cv(0x509355c0) 上反复唤醒 504 次——
// 两个对象永远不会相遇。根因是 CreateThread 一直是假句柄（ret0 0x1002），
// 没有任何 worker 线程能去满足那个等待。
// 这里按「每线程一份 X64Ctx」实现：4 MB 独立栈 + 4 KB 伪 TEB（gs:[0x30]=Self），
// 线程体 push 哨兵 0 后 dispatch_indirect(lpStartAddress)。
// 默认关闭（MEW_REAL_THREADS 未设时行为与以前完全一致），便于灰度与回归对照。
namespace {
bool real_threads() {
    static bool on = [] {
        const char* e = std::getenv("MEW_REAL_THREADS");
        return e && e[0] == '1';
    }();
    return on;
}

struct GuestThread {
    X64Ctx   ctx{};
    uint64_t entry = 0, param = 0;
    pthread_t tid{};
    bool     started = false, finished = false, joined = false;
    uint32_t exit_code = 0;
};

std::mutex g_thread_mu;
std::unordered_map<uint64_t, GuestThread*> g_threads;
uint64_t g_next_thread_handle = 0x2001;

// 等价的 init_guest_thread_ctx（垫片侧只有 mem_bias，没有 GuestImage）
bool init_thread_ctx(X64Ctx* ctx, uint64_t mem_bias) {
    constexpr size_t kStack = 4 * 1024 * 1024;
    void* stack = mmap(nullptr, kStack, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (stack == MAP_FAILED) return false;
    void* teb = mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (teb == MAP_FAILED) return false;
    std::memset(ctx, 0, sizeof(*ctx));
    std::memset(teb, 0, 4096);
    ctx->mem_bias = mem_bias;
    const uint64_t host_top = ((uint64_t)(uintptr_t)stack + kStack - 0x100) & ~0xFULL;
    ctx->rsp = (uint64_t)((int64_t)host_top - (int64_t)mem_bias);
    ctx->gs_base = (uint64_t)((int64_t)(uintptr_t)teb - (int64_t)mem_bias);
    ctx->fs_base = ctx->gs_base;
    *reinterpret_cast<uint64_t*>(reinterpret_cast<char*>(teb) + 0x30) = ctx->gs_base;
    register_guest_range(ctx->gs_base, 4096);
    register_guest_range((uint64_t)((int64_t)(uintptr_t)stack - (int64_t)mem_bias), kStack);
    return true;
}

void* guest_thread_main(void* arg) {
    GuestThread* t = static_cast<GuestThread*>(arg);
    cur_ctx_ptr() = &t->ctx;
    cur_fn_va() = t->entry;
    // 压哨兵：被调函数的 ret 会弹到 0，lifter 于是直接返回宿主
    t->ctx.rsp -= 8;
    mem_write<uint64_t>(&t->ctx, t->ctx.rsp, 0);
    t->ctx.rcx = t->param;   // lpParameter
    dispatch_indirect(t->entry, &t->ctx);
    t->exit_code = (uint32_t)t->ctx.rax;
    std::lock_guard<std::mutex> lk(g_thread_mu);
    t->finished = true;
    return nullptr;
}

GuestThread* find_thread(uint64_t h) {
    std::lock_guard<std::mutex> lk(g_thread_mu);
    auto it = g_threads.find(h);
    return it == g_threads.end() ? nullptr : it->second;
}

bool is_guest_worker_thread() {
    const pthread_t self = pthread_self();
    std::lock_guard<std::mutex> lk(g_thread_mu);
    for (const auto& kv : g_threads)
        if (kv.second && kv.second->started && pthread_equal(kv.second->tid, self)) return true;
    return false;
}

// ---- 事件：真 condvar，让跨线程信号真的能叫醒等待方 ----
struct GuestEvent {
    std::mutex mu;
    std::condition_variable cv;
    bool manual = false;
    bool signaled = false;
};
std::mutex g_event_mu;
std::unordered_map<uint64_t, GuestEvent*> g_events;
uint64_t g_next_event_handle = 0x1001;

GuestEvent* find_event(uint64_t h) {
    std::lock_guard<std::mutex> lk(g_event_mu);
    auto it = g_events.find(h);
    return it == g_events.end() ? nullptr : it->second;
}
}  // namespace

void shim_KERNEL32_CreateEventW(X64Ctx* c) { mew_api_hit("CreateEventW");
    if (!real_threads()) { ret0(c, 0x1001); return; }
    GuestEvent* e = new GuestEvent();
    e->manual = arg1(c) != 0;              // bManualReset
    e->signaled = arg2(c) != 0;            // bInitialState
    uint64_t h;
    {
        std::lock_guard<std::mutex> lk(g_event_mu);
        h = g_next_event_handle++;
        g_events[h] = e;
    }
    ret0(c, h);
}
void shim_KERNEL32_CreateEventA(X64Ctx* c) { shim_KERNEL32_CreateEventW(c); }

void shim_KERNEL32_SetEvent(X64Ctx* c) {
    if (real_threads()) {
        if (GuestEvent* e = find_event(arg0(c))) {
            std::lock_guard<std::mutex> lk(e->mu);
            e->signaled = true;
            e->cv.notify_all();
        }
    }
    ret0(c, 1);
}
void shim_KERNEL32_ResetEvent(X64Ctx* c) {
    if (real_threads()) {
        if (GuestEvent* e = find_event(arg0(c))) {
            std::lock_guard<std::mutex> lk(e->mu);
            e->signaled = false;
        }
    }
    ret0(c, 1);
}

void shim_KERNEL32_WaitForSingleObject(X64Ctx* c) { mew_api_hit("WaitForSingleObject");
    if (!real_threads()) { ret0(c, 0); return; }
    const uint64_t h = arg0(c);
    const uint32_t ms = (uint32_t)arg1(c);
    if (GuestThread* t = find_thread(h)) {          // 线程句柄 -> join
        if (t->started) {
            pthread_join(t->tid, nullptr);
            t->joined = true;
            t->finished = true;
        }
        ret0(c, 0);                                  // WAIT_OBJECT_0
        return;
    }
    if (GuestEvent* e = find_event(h)) {             // 事件句柄 -> 等信号
        std::unique_lock<std::mutex> lk(e->mu);
        if (ms == 0xFFFFFFFFu) e->cv.wait(lk, [&] { return e->signaled; });
        else e->cv.wait_for(lk, std::chrono::milliseconds(ms), [&] { return e->signaled; });
        const bool was = e->signaled;
        if (was && !e->manual) e->signaled = false;  // auto-reset
        ret0(c, was ? 0u : 258u);                    // WAIT_OBJECT_0 / WAIT_TIMEOUT
        return;
    }
    ret0(c, 0);
}
void shim_KERNEL32_WaitForMultipleObjects(X64Ctx* c) { ret0(c, 0); }

void shim_KERNEL32_CreateThread(X64Ctx* c) { mew_api_hit("CreateThread");
    if (!real_threads()) { ret0(c, 0x1002); return; }
    const uint64_t entry = arg2(c);                  // lpStartAddress
    const uint64_t param = arg3(c);                  // lpParameter
    const uint64_t tid_out = arg5(c);
    if (!entry) { ret0(c, 0); return; }
    GuestThread* t = new GuestThread();
    if (!init_thread_ctx(&t->ctx, c->mem_bias)) { delete t; ret0(c, 0); return; }
    t->entry = entry;
    t->param = param;
    uint64_t h;
    {
        std::lock_guard<std::mutex> lk(g_thread_mu);
        h = g_next_thread_handle++;
        g_threads[h] = t;
    }
    if (pthread_create(&t->tid, nullptr, guest_thread_main, t) != 0) {
        std::lock_guard<std::mutex> lk(g_thread_mu);
        g_threads.erase(h);
        delete t;
        ret0(c, 0);
        return;
    }
    t->started = true;
    std::fprintf(stderr, "[thread] CreateThread entry=0x%llx param=0x%llx handle=0x%llx\n",
                 (unsigned long long)entry, (unsigned long long)param, (unsigned long long)h);
    if (tid_out) mem_write<uint32_t>(c, tid_out, (uint32_t)h);
    ret0(c, h);
}
void shim_KERNEL32_GetExitCodeThread(X64Ctx* c) {
    uint32_t code = 0;
    if (real_threads()) {
        if (GuestThread* t = find_thread(arg0(c))) code = t->exit_code;
    }
    if (arg1(c)) mem_write<uint32_t>(c, arg1(c), code);
    ret0(c, 1);
}
void shim_KERNEL32_SetThreadPriority(X64Ctx* c) { ret0(c, 1); }
void shim_KERNEL32_SwitchToThread(X64Ctx* c) { ret0(c, 1); }
void shim_KERNEL32_GetCurrentThread(X64Ctx* c) { ret0(c, 1); }
void shim_KERNEL32_GetCurrentProcess(X64Ctx* c) { ret0(c, 2); }
void shim_KERNEL32_CreateMutexW(X64Ctx* c) { ret0(c, 0x1003); }
void shim_KERNEL32_ReleaseMutex(X64Ctx* c) { ret0(c, 1); }
void shim_KERNEL32_SetEndOfFile(X64Ctx* c) { ret0(c, 1); }
void shim_KERNEL32_GetFileAttributesW(X64Ctx* c) {
    mew_api_hit("GetFileAttributesW");
    const std::string raw  = guest_wstr(c, arg0(c));
    const std::string path = host_path_from_guest(c, arg0(c));
    struct stat st;
    if (!raw.empty() && !path.empty() && ::stat(path.c_str(), &st) == 0) {
        // 目录必须报 FILE_ATTRIBUTE_DIRECTORY(0x10)：以前只用 fopen 判「能不能打开」，
        // 目录会被报成 MISSING，于是 create_directories 永远认为目录建不出来。
        const uint32_t attr = S_ISDIR(st.st_mode) ? 0x10u : 0x80u;
        // 封顶：create_directories 会反复查同一路径，逐条打会把 runner.err 冲爆
        // （上一轮真线程轮才 635 KB，这里放开就没边了）。24 条足够看出第一段行为。
        static int traced = 0;
        if (traced++ < 24)
            std::fprintf(stderr, "[shim] GetFileAttributesW(\"%s\")=0x%x\n", path.c_str(), attr);
        ret0(c, attr);
        return;
    }
    mew_set_last_error(raw.empty() ? 3u : 2u);   // 3=PATH_NOT_FOUND / 2=FILE_NOT_FOUND
    ret0(c, (uint32_t)-1);
}
void shim_KERNEL32_GetCurrentDirectoryW(X64Ctx* c) {
    // GetCurrentDirectoryW(nBufferLength, lpBuffer)：返回写入的字符数（不含 NUL），
    // **返回 0 就是失败**。以前这里直接 ret0(c, 0)，等于对所有人宣称"拿不到当前目录"。
    // MSVC 的 std::filesystem::current_path / absolute 一旦拿到 0 就用 GetLastError()
    // 造 error_code，上游 create_directories 于是抛
    //   filesystem_error("create_directories: unknown error")
    // —— 这是那条异常唯一还没有解释的一环（FormatMessageW 只被调过一次，且 id=0，
    // 说明 MSVC 走的是 generic category，不是 Win32 错误码）。
    // 宿主侧所有 guest 相对路径都落在进程 CWD 下，host_path_from_guest 也把 "C:\" 映射成
    // "./"，所以这里统一回报根目录 "C:\"：与映射完全一致。
    const uint32_t cap = (uint32_t)arg0(c);
    const uint64_t buf = arg1(c);
    static int traced = 0;
    if (traced++ < 8)
        std::fprintf(stderr, "[shim] GetCurrentDirectoryW(cap=%u) -> \"C:\\\\\" caller=0x%llx\n",
                     cap, (unsigned long long)cur_fn_va());
    if (cap < 4) { ret0(c, 4); return; }   // 缓冲区不足：返回所需长度（含 NUL），不写
    if (buf) {
        mem_write<uint16_t>(c, buf + 0, (uint16_t)'C');
        mem_write<uint16_t>(c, buf + 2, (uint16_t)':');
        mem_write<uint16_t>(c, buf + 4, (uint16_t)'\\');
        mem_write<uint16_t>(c, buf + 6, (uint16_t)0);
    }
    ret0(c, 3);
}
void shim_KERNEL32_SetCurrentDirectoryW(X64Ctx* c) { ret0(c, 1); }
// 逐级 mkdir（含中间目录）。
// 为什么不能只调一次 ::mkdir：MSVC 的 create_directories 确实自己会递归，但它拆
// 路径用的是 **Windows 语义**，而我们 host_path_from_guest 把 "C:\Users\x\AppData
// \Roaming\Mewgenics" 压成了相对路径 "Users/x/AppData/Roaming/Mewgenics"（去盘符
// + 去前导斜杠 + 挂到 MEW_DATA_DIR 下，而 workflow 里 MEW_DATA_DIR 根本没设，默认
// "."）。于是第一层 "Users" 在宿主上并不存在，单次 mkdir 直接 ENOENT —— 修好的
// 垫片又会以同样的 filesystem_error 回到原点。这里自己把中间层补出来。
// 返回 true 只代表「每一级都建成功或已存在」，最终仍由调用方 stat 复核是不是目录。
static bool mew_mkpath(const std::string& path) {
    const bool abs = !path.empty() && path[0] == '/';
    std::string cur = abs ? "/" : "";
    size_t i = abs ? 1 : 0;
    for (;;) {
        const size_t nxt = path.find('/', i);
        const std::string seg =
            path.substr(i, nxt == std::string::npos ? std::string::npos : nxt - i);
        if (!seg.empty() && seg != ".") {
            if (seg == "..") {
                // 不建也不跳：host_path_from_guest 只剥前导点，正常情况下不会产生
                // ".."；真出现时按字面拼进去交给 mkdir 判失败，比静默走偏安全。
            } else {
                if (!cur.empty() && cur.back() != '/') cur += '/';
                cur += seg;
                if (::mkdir(cur.c_str(), 0777) != 0 && errno != EEXIST) return false;
            }
        }
        if (nxt == std::string::npos) break;
        i = nxt + 1;
    }
    return !cur.empty();
}

void shim_KERNEL32_CreateDirectoryW(X64Ctx* c) {
    mew_api_hit("CreateDirectoryW");
    const std::string path = host_path_from_guest(c, arg0(c));
    if (path.empty()) { ret0(c, 0); return; }
    // 必须真的落盘：std::filesystem::create_directories 建完会**再查一遍**是否
    // 存在，如果这里只返回 1 而不创建，第二次查询仍是「不存在」，MSVC 就抛
    //   filesystem_error("create_directories: unknown error")
    // 实测 run 46079343652 的 [cxx-eh] #2，throw_pc=0x14023e254，
    // handler=0x140d4014c —— 那就是引擎在建存档/配置目录时炸掉的。
    const bool built = mew_mkpath(path);
    // 建完必须**再 stat 复核一次是不是目录**：mkdir 返回 EEXIST 也可能是同名文件，
    // 那种情况下 create_directories 仍然会判失败，我们这里就得如实报 0。
    struct stat st;
    if (built && ::stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
        static int traced = 0;
        if (traced++ < 24)
            std::fprintf(stderr, "[shim] CreateDirectoryW(guest=\"%s\" host=\"%s\") -> ok\n",
                         guest_wstr(c, arg0(c)).c_str(), path.c_str());
        ret0(c, 1);
        return;
    }
    // 失败时必须把 last error 写对：MSVC 的 __std_fs_create_directory 是
    // 「GetLastError() → __std_win_error → error_code」这条路，last error 为 0
    // 就会翻成 error_code(0, system_category())，what() 里只剩 "unknown error"。
    uint32_t winerr = 5;                       // ERROR_ACCESS_DENIED
    if (errno == EEXIST) winerr = 183;         // ERROR_ALREADY_EXISTS
    else if (errno == ENOENT) winerr = 3;      // ERROR_PATH_NOT_FOUND
    else if (errno == ENOSPC) winerr = 112;    // ERROR_DISK_FULL
    mew_set_last_error(winerr);
    std::fprintf(stderr, "[shim] CreateDirectoryW(guest=\"%s\" host=\"%s\") 失败 errno=%d winerr=%u\n",
                 guest_wstr(c, arg0(c)).c_str(), path.c_str(), errno, winerr);
    ret0(c, 0);
}
void shim_KERNEL32_DeleteFileW(X64Ctx* c) { ret0(c, 1); }
namespace {
// ---- 目录枚举（FindFirstFileW / FindNextFileW / FindClose）----
// 为什么必须真实现：这三个以前是「返回 INVALID / FALSE」的静默桩，
// 引擎扫 saves/、找 *.gpak、列 audio/music/*.ogg 全都会拿到空列表，
// 然后在上游报一个和真实原因毫无关系的错（和 GetFileAttributesExW 同一个病：
// 返回值说"失败"，但从来没让它成功过）。
struct FindState {
    DIR* dir = nullptr;
    std::string dirpath;
    std::string pattern;
};

// Windows 通配匹配：大小写不敏感，支持 * 和 ?
static bool win_wild_match(const char* pat, const char* name) {
    while (*pat) {
        if (*pat == '*') {
            ++pat;
            if (!*pat) return true;
            for (const char* s = name;; ++s) {
                if (win_wild_match(pat, s)) return true;
                if (!*s) return false;
            }
        } else if (*pat == '?') {
            if (!*name) return false;
            ++pat; ++name;
        } else {
            if (!*name) return false;
            if (std::tolower((unsigned char)*pat) != std::tolower((unsigned char)*name)) return false;
            ++pat; ++name;
        }
    }
    return *name == 0;
}

// 填 WIN32_FIND_DATAW（x64 布局，592 字节）
//   +0   dwFileAttributes      DWORD
//   +4   ftCreationTime        FILETIME
//   +12  ftLastAccessTime      FILETIME
//   +20  ftLastWriteTime       FILETIME
//   +28  nFileSizeHigh         DWORD
//   +32  nFileSizeLow          DWORD
//   +36  dwReserved0           DWORD
//   +40  dwReserved1           DWORD
//   +44  cFileName             WCHAR[260]
//   +564 cAlternateFileName    WCHAR[14]
static void fill_find_data(X64Ctx* c, uint64_t out, const std::string& name, const struct stat& st) {
    if (!out) return;
    const uint32_t attr = S_ISDIR(st.st_mode) ? 0x10u : 0x80u;
    const uint64_t ft = ((uint64_t)st.st_mtime + 11644473600ULL) * 10000000ULL;
    const uint64_t at = ((uint64_t)st.st_atime + 11644473600ULL) * 10000000ULL;
    const uint64_t sz = (uint64_t)st.st_size;
    mem_write<uint32_t>(c, out + 0,  attr);
    mem_write<uint32_t>(c, out + 4,  (uint32_t)(ft & 0xFFFFFFFFu));
    mem_write<uint32_t>(c, out + 8,  (uint32_t)(ft >> 32));
    mem_write<uint32_t>(c, out + 12, (uint32_t)(at & 0xFFFFFFFFu));
    mem_write<uint32_t>(c, out + 16, (uint32_t)(at >> 32));
    mem_write<uint32_t>(c, out + 20, (uint32_t)(ft & 0xFFFFFFFFu));
    mem_write<uint32_t>(c, out + 24, (uint32_t)(ft >> 32));
    mem_write<uint32_t>(c, out + 28, (uint32_t)(sz >> 32));
    mem_write<uint32_t>(c, out + 32, (uint32_t)(sz & 0xFFFFFFFFu));
    mem_write<uint32_t>(c, out + 36, 0);   // dwReserved0（重解析点/符号链接标志）
    mem_write<uint32_t>(c, out + 40, 0);   // dwReserved1
    if (guest_mapped(out + 44, 520)) {
        uint16_t* p = (uint16_t*)guest_ptr_from_ctx(c, out + 44);
        std::memset(p, 0, 520);
        size_t i = 0;
        for (; i < 259 && i < name.size(); ++i) p[i] = (uint16_t)(unsigned char)name[i];
        p[i] = 0;
    }
    if (guest_mapped(out + 564, 28))
        std::memset(guest_ptr_from_ctx(c, out + 564), 0, 28);   // 8.3 名留空
}

// 从当前游标继续找下一个匹配项；成功则填 out 并返回 true
static bool find_take_next(X64Ctx* c, FindState* fs, uint64_t out) {
    if (!fs || !fs->dir || !out) return false;
    for (;;) {
        struct dirent* de = ::readdir(fs->dir);
        if (!de) return false;
        const std::string nm = de->d_name;
        if (nm == "." || nm == "..") continue;           // Windows 不返回这两个
        if (!win_wild_match(fs->pattern.c_str(), nm.c_str())) continue;
        const std::string full = fs->dirpath + "/" + nm;
        struct stat st;
        if (::stat(full.c_str(), &st) != 0) continue;
        fill_find_data(c, out, nm, st);
        return true;
    }
}
}  // namespace

void shim_KERNEL32_FindFirstFileW(X64Ctx* c) {
    const std::string full = host_path_from_guest(c, arg0(c));
    const uint64_t out = arg1(c);
    // 拆成「目录 + 通配模式」，最后一个 '/' 处切开
    std::string dir = ".";
    std::string pat = "*";
    const size_t slash = full.find_last_of('/');
    if (slash != std::string::npos) {
        dir = full.substr(0, slash);
        pat = full.substr(slash + 1);
        if (dir.empty()) dir = "/";
    } else if (!full.empty()) {
        pat = full;   // 没有目录部分，例如 "*.gpak"
    }
    if (pat.empty()) pat = "*";
    DIR* d = ::opendir(dir.c_str());
    static int traced = 0;
    if (!d) {
        const int e = errno;
        if (traced++ < 16)
            std::fprintf(stderr,
                         "[shim] FindFirstFileW(\"%s\") dir=\"%s\" pat=\"%s\" -> INVALID (opendir errno=%d)\n",
                         full.c_str(), dir.c_str(), pat.c_str(), e);
        ret0(c, (uint64_t)-1);
        return;
    }
    FindState* fs = new FindState();
    fs->dir = d;
    fs->dirpath = dir;
    fs->pattern = pat;
    if (!find_take_next(c, fs, out)) {
        ::closedir(d);
        delete fs;
        if (traced++ < 16)
            std::fprintf(stderr, "[shim] FindFirstFileW(\"%s\") -> INVALID (\"%s\" 里没有匹配 \"%s\")\n",
                         full.c_str(), dir.c_str(), pat.c_str());
        ret0(c, (uint64_t)-1);
        return;
    }
    const uint64_t h = HandleTable::instance().add(fs);
    if (traced++ < 16)
        std::fprintf(stderr, "[shim] FindFirstFileW(\"%s\") -> h=0x%llx caller=0x%llx\n",
                     full.c_str(), (unsigned long long)h, (unsigned long long)cur_fn_va());
    ret0(c, h);
}

void shim_KERNEL32_FindNextFileW(X64Ctx* c) {
    FindState* fs = (FindState*)(uintptr_t)HandleTable::instance().get(arg0(c));
    const uint64_t out = arg1(c);
    const bool ok = find_take_next(c, fs, out);
    ret0(c, ok ? 1u : 0u);
}
void shim_KERNEL32_FindClose(X64Ctx* c) {
    const uint64_t h = arg0(c);
    FindState* fs = (FindState*)(uintptr_t)HandleTable::instance().get(h);
    if (fs) {
        if (fs->dir) ::closedir(fs->dir);
        fs->dir = nullptr;
        delete fs;
        HandleTable::instance().erase(h);
    }
    ret0(c, 1);
}
void shim_KERNEL32_GetFileSize(X64Ctx* c) {
    FILE* f = file_from_handle(arg0(c));
    long cur = f ? ftell(f) : 0; long size = 0;
    if (f) { fseek(f, 0, SEEK_END); size = ftell(f); fseek(f, cur, SEEK_SET); }
    if (arg1(c)) mem_write<uint32_t>(c, arg1(c), (uint32_t)size);
    ret0(c, (uint32_t)size);
}
void shim_WINMM_timeGetTime(X64Ctx* c) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    ret0(c, (uint32_t)(ts.tv_sec * 1000ull + ts.tv_nsec / 1000000ull));
}

void shim_KERNEL32_OutputDebugStringA(X64Ctx* c) {
    const char* p = (const char*)guest_ptr_from_ctx(c, arg0(c));
    std::fprintf(stderr, "[game] %s\n", p ? p : "");
    ret0(c, 0);
}

// ---------------- SRW 锁 / 条件变量 / 一次性初始化 ----------------
// Windows 上 std::mutex / std::shared_mutex 底层就是 SRWLOCK；UCRT 的 locale、errno
// 初始化也走 InitOnce。这些对象在 guest 侧只是一个 8 字节不透明槽（静态初值 0），
// 所以宿主按「槽地址」建表，用真正的 pthread 原语实现，而不是返回成功骗过去。
namespace {
struct SrwSlot { pthread_rwlock_t rw; int shared; };
struct CvSlot  { pthread_cond_t cv; pthread_mutex_t mu; };

std::mutex& g_sync_mu() { static std::mutex m; return m; }
std::unordered_map<uint64_t, SrwSlot*>& srw_table() { static std::unordered_map<uint64_t, SrwSlot*> m; return m; }
std::unordered_map<uint64_t, CvSlot*>&  cv_table()  { static std::unordered_map<uint64_t, CvSlot*>  m; return m; }
std::unordered_map<uint64_t, int>&      once_table(){ static std::unordered_map<uint64_t, int>      m; return m; }

SrwSlot* srw_for(uint64_t addr, bool create) {
    if (!addr) return nullptr;
    std::lock_guard<std::mutex> lk(g_sync_mu());
    auto it = srw_table().find(addr);
    if (it != srw_table().end()) return it->second;
    if (!create) return nullptr;
    SrwSlot* s = new SrwSlot();
    pthread_rwlock_init(&s->rw, nullptr);
    s->shared = 0;
    srw_table()[addr] = s;
    return s;
}

CvSlot* cv_for(uint64_t addr, bool create) {
    if (!addr) return nullptr;
    std::lock_guard<std::mutex> lk(g_sync_mu());
    auto it = cv_table().find(addr);
    if (it != cv_table().end()) return it->second;
    if (!create) return nullptr;
    CvSlot* s = new CvSlot();
    pthread_cond_init(&s->cv, nullptr);
    pthread_mutex_init(&s->mu, nullptr);
    cv_table()[addr] = s;
    return s;
}
}  // namespace

// InitializeSRWLock / InitializeConditionVariable：Windows 语义是「把对象写成初始状态」，
// 返回 void。这两个以前**完全没实现**，于是 GetProcAddress("InitializeSRWLock") 返回 0，
// 调用方把 0 当函数指针直接 call -> SIGSEGV(fault=0xffffffffffffffff)，
// 实测 run 46084959550。我们的锁在首次 srw_for / cv_for 时懒创建，
// 这里提前建好，语义等价。
void shim_KERNEL32_InitializeSRWLock(X64Ctx* c) {
    (void)srw_for(arg0(c), true);
    ret0(c, 0);
}
void shim_KERNEL32_InitializeConditionVariable(X64Ctx* c) {
    (void)cv_for(arg0(c), true);
    ret0(c, 0);
}

void shim_KERNEL32_AcquireSRWLockExclusive(X64Ctx* c) {
    SrwSlot* s = srw_for(arg0(c), true);
    if (s) pthread_rwlock_wrlock(&s->rw);
    ret0(c, 0);
}
void shim_KERNEL32_AcquireSRWLockShared(X64Ctx* c) {
    SrwSlot* s = srw_for(arg0(c), true);
    if (s) {
        pthread_rwlock_rdlock(&s->rw);
        __atomic_add_fetch(&s->shared, 1, __ATOMIC_SEQ_CST);
    }
    ret0(c, 0);
}
void shim_KERNEL32_ReleaseSRWLockExclusive(X64Ctx* c) {
    SrwSlot* s = srw_for(arg0(c), false);
    if (s) pthread_rwlock_unlock(&s->rw);
    ret0(c, 0);
}
void shim_KERNEL32_ReleaseSRWLockShared(X64Ctx* c) {
    SrwSlot* s = srw_for(arg0(c), false);
    if (s) {
        __atomic_sub_fetch(&s->shared, 1, __ATOMIC_SEQ_CST);
        pthread_rwlock_unlock(&s->rw);
    }
    ret0(c, 0);
}
void shim_KERNEL32_TryAcquireSRWLockExclusive(X64Ctx* c) {
    // 单线程模型：任何 try-lock 都「成功」。用真 pthread trywrlock 时，同一线程重入会返回
    // EDEADLK，MSVC STL 把它翻成 std::system_error("resource deadlock would occur") ——
    // run 46047307348 的 [cxx-eh] #1 就是这个（type=.?AVsystem_error@std@@）。
    (void)srw_for(arg0(c), true);
    ret0(c, 1);
}
void shim_KERNEL32_TryAcquireSRWLockShared(X64Ctx* c) {
    // 同上：单线程模型下 try-lock 一律成功
    SrwSlot* s = srw_for(arg0(c), true);
    if (s) __atomic_add_fetch(&s->shared, 1, __ATOMIC_SEQ_CST);
    ret0(c, 1);
}

// SleepConditionVariableSRW：释放 srw → 等条件 → 重新加锁。
// pthread 的 rwlock 不会告诉你「当前是共享还是独占」，所以重新加锁的模式按
// 「等之前有没有人持共享锁」近似；单线程初始化路径下这是精确的。
void shim_KERNEL32_SleepConditionVariableSRW(X64Ctx* c) { mew_api_hit("SleepConditionVariableSRW");
    // **单线程模拟：没有别的线程会来 Wake，真等就是死锁。**
    // run 46023439342 的卡死（0x140d1f7e4，rsp 30 分钟不动）就是这条：
    // 原来这里走 pthread_cond_wait(INFINITE)，没人 signal，永远不返回。
    // 现在按「超时」立刻返回 0，并打一行日志让下一轮 artifact 能证实这条路径。
    const uint32_t ms = (uint32_t)arg2(c);
    // 关键：参数是 INFINITE(0xFFFFFFFF) 时**不可能超时**。上面那版一律返回 FALSE(0)，
    // 于是 CRT 的 _Cnd_wait 把它解释成「死锁」并抛
    //   std::system_error("resource deadlock would occur")
    // （run 46047307348 的 [cxx-eh] #1）。单线程模拟下没人会 signal，正确做法是
    // 「假装已被唤醒」——返回 TRUE，让等待方继续走，而不是抛异常把 main 打死。
    const uint64_t ret = (ms == 0xFFFFFFFFu) ? 1ull : 0ull;
    // 带上 caller：run 46055985114 里 485 次 wake 都是同一个 cv(0x509355c0)，
    // 只有 caller 能区分「SDL 事件队列在转」还是「引擎自己的 job 池在等不存在的线程」。
    // 参数顺序修正（run 46065844562 的日志误读）：SleepConditionVariableSRW(cv, srw, ms, flags)
    // 的第一个参数是 rcx=cv、第二个是 rdx=srw。这里一直把 arg1(rdx) 当 cv 打印，
    // 于是「0x1412f80a0 没人唤醒」是假象——0x1412f80a0 是 SRW 锁，真 cv 是 rcx 那个。
    // 实测对照：wait 的 rcx=0x1413c62e8，而 _Cnd_signal 打的 wake cv=0x1413c62e8 —— 同一个对象，
    // 所以那条「两个 cv 永不配对」的结论作废。
    static int wait_logged = 0;
    if (wait_logged++ < 20)
        std::fprintf(stderr, "[cond] wait cv=0x%llx srw=0x%llx ms=%u -> %s(%llu) caller=0x%llx\n",
                     (unsigned long long)arg0(c), (unsigned long long)arg1(c), ms,
                     ret ? "signaled" : "timeout",
                     (unsigned long long)ret, (unsigned long long)cur_fn_va());
    (void)cv_for; (void)srw_for;
    // **真正的语义：释放调用方持有的 SRW → 等待 → 重新获取。**
    // 以前这里只「假装已唤醒」就返回，SRW 一直攥在等待方手里；别的线程要改 predicate
    // 就必须先拿同一把 SRW，于是全都堵在 pthread_rwlock_wrlock 里进不来，
    // 结果没有任何线程能让 predicate 变化，等待方在 _Cnd_wait 里空转到超时
    // （run 46098382772 实测 216,779,760 次；adfd412 的 205,042,261 次是同一个死结，
    //  那次能推进只是抢锁顺序恰好对）。这才是「关检测 / 加退让都推不动」的真正原因。
    {
        SrwSlot* s = srw_for(arg1(c), false);   // false：调用方一定已经持有，不要新建
        const uint32_t flags = (uint32_t)arg3(c);
        const bool shared = (flags & 1u) != 0;  // CONDITION_VARIABLE_LOCKMODE_SHARED
        if (s) {
            pthread_rwlock_unlock(&s->rw);
            if (shared) __atomic_sub_fetch(&s->shared, 1, __ATOMIC_SEQ_CST);
            sched_yield();                      // 让抢锁的线程先跑，别自己立刻拿回来
            if (shared) {
                pthread_rwlock_rdlock(&s->rw);
                __atomic_add_fetch(&s->shared, 1, __ATOMIC_SEQ_CST);
            } else {
                pthread_rwlock_wrlock(&s->rw);
            }
        }
    }
    ret0(c, ret);
}
// 语义修正（run 46055985114 的实测）：x64 下 WakeConditionVariable /
// WakeAllConditionVariable 返回 **BOOL**（非 0 = 成功）。以前这里 ret0(c, 0)，
// 等于每次都告诉调用方「唤醒失败」——建窗到弹窗那 1365 条调用里有 485 条
// WakeAllConditionVariable（35%），就是被这个 0 引着反复重试。
void shim_KERNEL32_WakeConditionVariable(X64Ctx* c) {
    CvSlot* cv = cv_for(arg0(c), true);
    if (cv) pthread_cond_signal(&cv->cv);
    static int logged = 0;
    if (logged++ < 20)
        std::fprintf(stderr, "[cond] wake cv=0x%llx caller=0x%llx\n",
                     (unsigned long long)arg0(c), (unsigned long long)cur_fn_va());
    ret0(c, 1);
}
void shim_KERNEL32_WakeAllConditionVariable(X64Ctx* c) { mew_api_hit("WakeAllConditionVariable");
    CvSlot* cv = cv_for(arg0(c), true);
    if (cv) pthread_cond_broadcast(&cv->cv);
    static int logged = 0;
    if (logged++ < 20) {
        std::fprintf(stderr, "[cond] wakeall cv=0x%llx caller=0x%llx\n",
                     (unsigned long long)arg0(c), (unsigned long long)cur_fn_va());
        // run 46061908947 实测：WakeAll 504 次、SleepConditionVariableSRW 只有 1 次，
        // 说明是「没有等待者还反复唤醒」的空转。caller 落在 thunk 区（0x140bdd9c0）
        // 不可靠，所以前 3 次把调用环尾巴打出来，看真正的函数链。
        if (logged <= 3) call_trace().dump_tail(8);
    }
    ret0(c, 1);   // BOOL：非 0 = 成功（见上）
}

// InitOnce：0=未完成 1=已完成；INIT_ONCE_INIT_FAILED(0x4) 允许后续重试
void shim_KERNEL32_InitOnceBeginInitialize(X64Ctx* c) {
    const uint64_t addr = arg0(c);
    const uint64_t pending = arg2(c);
    const uint64_t ctx_out = arg3(c);
    int state = 0;
    {
        std::lock_guard<std::mutex> lk(g_sync_mu());
        state = once_table()[addr];
    }
    if (pending) mem_write<int32_t>(c, pending, state == 1 ? 0 : 1);
    if (state == 1 && ctx_out) mem_write<uint64_t>(c, ctx_out, 0);
    ret0(c, 1);
}
void shim_KERNEL32_InitOnceComplete(X64Ctx* c) {
    const uint64_t addr = arg0(c);
    const uint32_t flags = (uint32_t)arg1(c);
    std::lock_guard<std::mutex> lk(g_sync_mu());
    once_table()[addr] = (flags & 0x4u) ? 0 : 1;   // 失败 -> 回到可重试
    ret0(c, 1);
}

// ---------------- 线程池（单线程宿主：句柄是真的，任务不真排队） ----------------
// 与 CreateThread（当前返回假句柄、不真起线程）保持一致的语义：
// 只保证调用方拿到有效句柄、不会崩，不假装任务执行过。
namespace {
uint64_t& tp_next() { static uint64_t n = 0x710000000ULL; return n; }
}
void shim_KERNEL32_CreateThreadpoolWork(X64Ctx* c) {
    ret0(c, tp_next()++);
}
void shim_KERNEL32_SubmitThreadpoolWork(X64Ctx* c) {
    static int logged = 0;
    if (logged++ < 5)
        std::fprintf(stderr, "[shim] SubmitThreadpoolWork(0x%llx) 忽略（单线程宿主）\n",
                     (unsigned long long)arg0(c));
    ret0(c, 0);
}
void shim_KERNEL32_CloseThreadpoolWork(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_KERNEL32_WaitForThreadpoolWorkCallbacks(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_KERNEL32_FreeLibraryWhenCallbackReturns(X64Ctx* c) { (void)c; ret0(c, 0); }

// ---------------- Global*（Win16 时代的堆，很多库还在用） ----------------
void shim_KERNEL32_GlobalAlloc(X64Ctx* c) {
    const uint32_t flags = (uint32_t)arg0(c);
    const size_t n = (size_t)arg1(c);
    uint64_t g = g_guest_heap.alloc(n ? n : 1, (flags & 0x40u) != 0);  // GMEM_ZEROINIT=0x40
    ret0(c, g);
}
void shim_KERNEL32_GlobalFree(X64Ctx* c) {
    uint64_t a = arg0(c);
    if (a && g_guest_heap.owns(a)) g_guest_heap.free_block(a);
    ret0(c, 0);
}
void shim_KERNEL32_GlobalLock(X64Ctx* c) { ret0(c, arg0(c)); }   // 句柄即指针（GMEM_FIXED 语义）
void shim_KERNEL32_GlobalUnlock(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_KERNEL32_GlobalSize(X64Ctx* c) {
    uint64_t a = arg0(c);
    ret0(c, a ? (uint64_t)g_guest_heap.requested(a) : 0);
}

// ---------------- 等待 / 信号量 ----------------
void shim_KERNEL32_WaitForSingleObjectEx(X64Ctx* c) { (void)c; ret0(c, 0); }  // 无真线程：视为已满足
void shim_KERNEL32_CreateSemaphoreW(X64Ctx* c) {
    static uint64_t h = 0x720000000ULL;
    ret0(c, h++);
}
void shim_KERNEL32_ReleaseSemaphore(X64Ctx* c) {
    if (arg2(c)) mem_write<uint32_t>(c, arg2(c), 0);   // lpPreviousCount
    ret0(c, 1);
}

// ---------------- 系统信息 / 环境 ----------------
void shim_KERNEL32_IsWow64Process(X64Ctx* c) {
    if (arg1(c)) mem_write<int32_t>(c, arg1(c), 0);
    ret0(c, 1);
}
void shim_KERNEL32_GlobalMemoryStatusEx(X64Ctx* c) {
    // MEMORYSTATUSEX：dwLength(0) dwMemoryLoad(4) ullTotalPhys(8) ullAvailPhys(16)
    // ullTotalPageFile(24) ullAvailPageFile(32) ullTotalVirtual(40) ullAvailVirtual(48) ullAvailExtendedVirtual(56)
    const uint64_t p = arg0(c);
    if (p) {
        const uint64_t gb = 1024ULL * 1024 * 1024;
        mem_write<uint32_t>(c, p + 0, 64);
        mem_write<uint32_t>(c, p + 4, 40);                 // 40% 用量
        mem_write<uint64_t>(c, p + 8, 4 * gb);
        mem_write<uint64_t>(c, p + 16, 2 * gb);
        mem_write<uint64_t>(c, p + 24, 8 * gb);
        mem_write<uint64_t>(c, p + 32, 4 * gb);
        mem_write<uint64_t>(c, p + 40, 1ULL << 47);
        mem_write<uint64_t>(c, p + 48, 1ULL << 46);
        mem_write<uint64_t>(c, p + 56, 0);
    }
    ret0(c, 1);
}
void shim_KERNEL32_GetNativeSystemInfo(X64Ctx* c) { shim_KERNEL32_GetSystemInfo(c); }
void shim_KERNEL32_SetThreadExecutionState(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_KERNEL32_SetErrorMode(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_KERNEL32_GetLogicalDrives(X64Ctx* c) { (void)c; ret0(c, 1); }  // 只有 C:
void shim_KERNEL32_MulDiv(X64Ctx* c) {
    const int32_t a = (int32_t)arg0(c), b = (int32_t)arg1(c), d = (int32_t)arg2(c);
    if (d == 0) { ret0(c, (uint64_t)(int64_t)-1); return; }
    const long long v = ((long long)a * (long long)b + d / 2) / d;
    ret0(c, (uint64_t)(int64_t)v);
}
void shim_KERNEL32_AreFileApisANSI(X64Ctx* c) { (void)c; ret0(c, 1); }
// FormatMessageW/A：以前一律返回 0（"如实失败"），结果 SDL 的错误消息全是空串。
// 链路是：SDL 的 SetError(0x140c15800) 先 GetLastError() 拿码，再 FormatMessageW 取文本；
// 我们返回 0 -> 文本为空 -> SDL_GetError() 返回空串 ->
//   TaskDialog 的内容只剩前缀 `content="Could not create window: "`，
// 后半截（真正的失败原因）永久丢失。这条空串挡住了好几轮诊断，必须先打通。
//
// 注意 GetLastError 本身仍恒返回 0（ERROR_SUCCESS），所以这里能给出的是
// "no error" 一类文本 —— 那本身就是结论：**失败的 API 没有设过错误码**，
// 说明失败发生在我们自己的垫片里（它们不设 LastError），不是 Windows 语义的失败。
static const char* mew_format_windows_error(uint32_t id) {
    switch (id) {
        case 0:    return "no error (GetLastError()=0)";
        case 2:    return "The system cannot find the file specified.";
        case 3:    return "The system cannot find the path specified.";
        case 5:    return "Access is denied.";
        case 6:    return "The handle is invalid.";
        case 8:    return "Not enough memory resources are available.";
        case 14:   return "The system cannot find the drive specified.";
        case 87:   return "The parameter is incorrect.";
        case 126:  return "The specified module could not be found.";
        case 127:  return "The specified procedure could not be found.";
        case 1400: return "Invalid window handle.";
        case 1407: return "Cannot find window class.";
        case 1418: return "This hook procedure can only be set globally.";
        default:   break;
    }
    return nullptr;
}

void shim_KERNEL32_FormatMessageW(X64Ctx* c) {
    // FormatMessageW(dwFlags, lpSource, dwMessageId, dwLanguageId, lpBuffer, nSize, Arguments)
    const uint32_t flags = (uint32_t)arg0(c);
    const uint32_t msgid = (uint32_t)arg2(c);
    const uint64_t out   = arg4(c);   // 第 5 参：lpBuffer（栈上）
    const uint32_t cap   = (uint32_t)arg5(c);
    const bool allocate  = (flags & 0x100u) != 0;   // FORMAT_MESSAGE_ALLOCATE_BUFFER
    static int traced = 0;
    if (traced++ < 24)
        std::fprintf(stderr,
                     "[shim] FormatMessageW(flags=0x%x id=%u cap=%u alloc=%d) caller=0x%llx\n",
                     flags, msgid, cap, (int)allocate, (unsigned long long)cur_fn_va());

    // 组一条文本：已知码用系统原文，未知码给 "Unknown error (N)"，
    // 这样 SDL_GetError() 至少能带出错误码，不再是空串。
    char text[128];
    const char* known = mew_format_windows_error(msgid);
    if (known) std::snprintf(text, sizeof(text), "%s", known);
    else       std::snprintf(text, sizeof(text), "Unknown error (%u)", msgid);
    const size_t units = std::strlen(text) + 1;

    if (allocate) {
        // lpBuffer 是 `WCHAR**`：分配一块 guest 内存，把指针写回 *lpBuffer
        const uint64_t buf = guest_alloc(c, units * 2);
        if (!buf) { ret0(c, 0); return; }
        uint16_t* p = (uint16_t*)guest_ptr_from_ctx(c, buf);
        for (size_t i = 0; i < units; ++i) p[i] = (uint16_t)(unsigned char)text[i];
        if (out) mem_write<uint64_t>(c, out, buf);
        ret0(c, (uint64_t)(units - 1));
        return;
    }
    if (!out || cap < units) { ret0(c, 0); return; }
    uint16_t* p = (uint16_t*)guest_ptr_from_ctx(c, out);
    for (size_t i = 0; i < units; ++i) p[i] = (uint16_t)(unsigned char)text[i];
    ret0(c, (uint64_t)(units - 1));   // 返回写入的字符数，不含 NUL
}

void shim_KERNEL32_FormatMessageA(X64Ctx* c) {
    // ANSI 版：语义同上，只是按 char 写。
    const uint32_t msgid = (uint32_t)arg2(c);
    const uint64_t out   = arg4(c);
    const uint32_t cap   = (uint32_t)arg5(c);
    char text[128];
    const char* known = mew_format_windows_error(msgid);
    if (known) std::snprintf(text, sizeof(text), "%s", known);
    else       std::snprintf(text, sizeof(text), "Unknown error (%u)", msgid);
    const size_t n = std::strlen(text) + 1;
    if (!out || cap < n) { ret0(c, 0); return; }
    std::memcpy(guest_ptr_from_ctx(c, out), text, n);
    ret0(c, (uint64_t)(n - 1));
}
// 环境变量：只提供 SDL3 的 hint 系统需要的那一个 —— SDL_VIDEO_DRIVER。
// 为什么必须给：SDL_GetHint 最终走 SDL_getenv -> 这里；而每个 video driver 的
// CreateDevice 第一步（0x140c7d320）就是「读 SDL_VIDEO_DRIVER，判断是不是自己」，
// hint 不存在时它返回 0，调用方立刻 `test al,al; je 失败返回 0`。
// 结果就是**所有** driver 都被拒、_this 永远为 0、SDL_CreateWindow 永远失败。
// 指定 windows 让 SDL 直接选 Windows driver —— 三个 driver（windows/offscreen/
// dummy）里只有它带 WGL，引擎要的是 OpenGL。
// 其余变量保持「如实不存在」（引擎自己不读任何环境变量，前面已查证）。
void shim_KERNEL32_GetEnvironmentVariableW(X64Ctx* c) {
    const std::string name = guest_wstr(c, arg0(c));
    const uint64_t buf = arg1(c);
    const uint32_t cap = (uint32_t)arg2(c);
    const char* val = nullptr;
    if (name == "SDL_VIDEO_DRIVER") val = "windows";
    static int traced = 0;
    if (traced++ < 16)
        std::fprintf(stderr, "[shim] GetEnvironmentVariableW(\"%s\",cap=%u) -> %s\n",
                     name.c_str(), cap, val ? val : "<none>");
    if (!val) { ret0(c, 0); return; }
    const std::string v(val);
    const size_t need = v.size() + 1;
    if (buf && cap >= need && guest_mapped(buf, need * 2)) {
        uint16_t* p = (uint16_t*)guest_ptr_from_ctx(c, buf);
        for (size_t i = 0; i < v.size(); ++i) p[i] = (uint16_t)(unsigned char)v[i];
        p[v.size()] = 0;
        ret0(c, (uint64_t)v.size());
        return;
    }
    ret0(c, (uint64_t)need);
}
void shim_KERNEL32_GetEnvironmentVariableA(X64Ctx* c) {
    std::string name;
    if (arg0(c) && guest_mapped(arg0(c), 1)) {
        const char* p = (const char*)guest_ptr_from_ctx(c, arg0(c));
        for (size_t i = 0; i < 260 && p[i]; ++i) name.push_back(p[i]);
    }
    const uint64_t buf = arg1(c);
    const uint32_t cap = (uint32_t)arg2(c);
    const char* val = nullptr;
    if (name == "SDL_VIDEO_DRIVER") val = "windows";
    static int traced = 0;
    if (traced++ < 16)
        std::fprintf(stderr, "[shim] GetEnvironmentVariableA(\"%s\",cap=%u) -> %s\n",
                     name.c_str(), cap, val ? val : "<none>");
    if (!val) { ret0(c, 0); return; }
    const std::string v(val);
    const size_t need = v.size() + 1;
    if (buf && cap >= need && guest_mapped(buf, need)) {
        std::memcpy(guest_ptr_from_ctx(c, buf), v.c_str(), need);
        ret0(c, (uint64_t)v.size());
        return;
    }
    ret0(c, (uint64_t)need);
}

void shim_KERNEL32_SetEnvironmentVariableW(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_KERNEL32_SetEnvironmentVariableA(X64Ctx* c) { (void)c; ret0(c, 1); }

// ---------------- 控制台（失败要如实，不能假装写成功） ----------------
void shim_KERNEL32_WriteConsoleW(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_KERNEL32_GetConsoleMode(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_KERNEL32_SetStdHandle(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_KERNEL32_AttachConsole(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_KERNEL32_SetConsoleCtrlHandler(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_KERNEL32_ReadConsoleW(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_KERNEL32_GetConsoleOutputCP(X64Ctx* c) { (void)c; ret0(c, 65001); }

// ---------------- 杂项 ----------------
void shim_KERNEL32_InitializeCriticalSectionEx(X64Ctx* c) { shim_KERNEL32_InitializeCriticalSectionAndSpinCount(c); }
void shim_KERNEL32_ExitThread(X64Ctx* c) {
    std::fprintf(stderr, "[shim] ExitThread(%u)\n", (unsigned)arg0(c));
    // 真线程模式下只有「在 worker 线程里调用」才 pthread_exit；
    // 主线程上仍是老行为（把整个进程带走），避免改变既有路径。
    if (real_threads() && is_guest_worker_thread())
        pthread_exit(reinterpret_cast<void*>((uintptr_t)(uint32_t)arg0(c)));
    std::exit((int)arg0(c));
}
void shim_KERNEL32_AddVectoredExceptionHandler(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_KERNEL32_RemoveVectoredExceptionHandler(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_KERNEL32_RtlCaptureStackBackTrace(X64Ctx* c) { (void)c; ret0(c, 0); }

// ---------------- locale（初始化路径会调；给稳定的 en-US 子集） ----------------
namespace {
const char* locale_value(uint32_t type) {
    switch (type) {
        case 0x59:   return "ENG";                    // LOCALE_SISO639LANGNAME
        case 0x5A:   return "USA";                    // LOCALE_SISO3166CTRYNAME
        case 0x5C:   return "en-US";                  // LOCALE_SNAME
        case 0x0C:   return ",";                      // LOCALE_SLIST
        case 0x0D:   return "0";                      // LOCALE_IMEASURE（0=美制）
        case 0x0E:   return ".";                      // LOCALE_SDECIMAL
        case 0x0F:   return ",";                      // LOCALE_STHOUSAND
        case 0x11:   return "2";                      // LOCALE_IDIGITS
        case 0x12:   return "1";                      // LOCALE_ILZERO
        case 0x1D:   return "/";                      // LOCALE_SDATE
        case 0x1E:   return ":";                      // LOCALE_STIME
        case 0x1F:   return "M/d/yyyy";               // LOCALE_SSHORTDATE
        case 0x20:   return "dddd, MMMM d, yyyy";     // LOCALE_SLONGDATE
        case 0x31:   return "AM";                     // LOCALE_S1159
        case 0x32:   return "PM";                     // LOCALE_S2359
        case 0x50:   return "+";                      // LOCALE_SPOSITIVESIGN
        case 0x51:   return "-";                      // LOCALE_SNEGATIVESIGN
        case 0x1001: return "English";                // LOCALE_SENGLANGUAGE
        case 0x1002: return "United States";          // LOCALE_SENGCOUNTRY
        case 0x1003: return "h:mm:ss tt";             // LOCALE_STIMEFORMAT
        case 0x1004: return "MMMM d, yyyy";           // LOCALE_SLONGDATE（旧名）
        // 货币一族（run 45993665762 的 16 条 GetLocaleInfoEx 采样里出现过这些）
        case 0x14:   return "$";                      // LOCALE_SCURRENCY
        case 0x15:   return "USD";                    // LOCALE_SINTLSYMBOL
        case 0x16:   return ".";                      // LOCALE_SMONDECIMALSEP
        case 0x17:   return ",";                      // LOCALE_SMONTHOUSANDSEP
        case 0x18:   return "3;0";                    // LOCALE_SMONGROUPING
        default:     return "";
    }
}
// LOCALE_RETURN_NUMBER(0x20000000)：数值型 LCType 要往 lpLCData 写一个 **DWORD** 并返回 2，
// 不是写字符串。run 45993665762 里 CRT 问过 0x20001004 / 0x2000001a（各 1 次），
// 而旧实现一律走字符串路径：locale_value() 返回空串 → 写一个 NUL、返回 1，
// 调用方读出来的「货币小数位」永远是 0 而不是 2。
// 返回值取一组足以让 ucrt 正常工作的数：货币/整数小数位=2、前导零/公历=1、其余 0。
bool write_locale_number(X64Ctx* c, uint32_t type, uint64_t buf, int cch) {
    uint32_t v = 0;
    switch (type & ~0x20000000u) {
        case 0x11:   // LOCALE_IDIGITS
        case 0x19:   // LOCALE_ICURRDIGITS
        case 0x1A:   // LOCALE_IINTLCURRDIGITS
            v = 2;
            break;
        case 0x12:   // LOCALE_ILZERO
        case 0x1009: // LOCALE_ICALENDARTYPE（1 = 公历）
            v = 1;
            break;
        default:
            v = 0;
            break;
    }
    if (!buf || cch <= 0) return false;           // 只问长度：调用方看返回的 2
    if (cch < 2 || !guest_mapped(buf, 4)) return false;
    std::memcpy(guest_ptr_from_ctx(c, buf), &v, 4);
    return true;
}
void write_utf16(X64Ctx* c, uint64_t dst, const char* s) {
    uint16_t* p = (uint16_t*)guest_ptr_from_ctx(c, dst);
    size_t i = 0;
    for (; s[i]; ++i) p[i] = (uint16_t)(unsigned char)s[i];
    p[i] = 0;
}
}  // namespace

void shim_KERNEL32_GetLocaleInfoW(X64Ctx* c) {
    const uint32_t type = (uint32_t)arg1(c);
    const uint64_t buf = arg2(c);
    const int cch = (int)arg3(c);
    if (type & 0x20000000u) {   // LOCALE_RETURN_NUMBER
        write_locale_number(c, type, buf, cch);
        ret0(c, 2);
        return;
    }
    const char* v = locale_value(type);
    const int need = (int)std::strlen(v) + 1;
    if (!buf || cch == 0) { ret0(c, (uint64_t)need); return; }
    if (cch < need) { ret0(c, 0); return; }
    write_utf16(c, buf, v);
    ret0(c, (uint64_t)need);
}
void shim_KERNEL32_GetLocaleInfoA(X64Ctx* c) {
    const uint32_t type = (uint32_t)arg1(c);
    const uint64_t buf = arg2(c);
    const int cch = (int)arg3(c);
    if (type & 0x20000000u) {   // LOCALE_RETURN_NUMBER（A/W 一样返回 DWORD）
        write_locale_number(c, type, buf, cch);
        ret0(c, 2);
        return;
    }
    const char* v = locale_value(type);
    const int need = (int)std::strlen(v) + 1;
    if (!buf || cch == 0) { ret0(c, (uint64_t)need); return; }
    if (cch < need) { ret0(c, 0); return; }
    std::memcpy(guest_ptr_from_ctx(c, buf), v, (size_t)need);
    ret0(c, (uint64_t)need);
}
// GetLocaleInfoEx(lpLocaleName, LCType, lpLCData, cchData)：与 W 版只差第一个参数
// 是 locale **名字** 而不是 LCID，所以不能直接转调 GetLocaleInfoW（那会把一个指针
// 当 LCID 读，返回错的字符串）。按 arg2/arg3/arg4 取类型和缓冲区，复用 locale_value。
// 另外：这个函数以前**没有进 lookup_api**，所以 CRT 的 GetProcAddress("GetLocaleInfoEx")
// 一直返回 0（run 45985646254 的 unmapped 清单里就有它）。
void shim_KERNEL32_GetLocaleInfoEx(X64Ctx* c) {
    // 参数映射必须按 Win64 顺序：rcx=localeName, rdx=LCType, r8=lpLCData, r9=cchData。
    // 第一次实现把三个参数整体错位了一格（type 取 r8、buf 取 r9、cch 取栈上第 5 个），
    // 于是 buf 变成了 r9 的垃圾值，write_utf16 往地址 0x2 写 → SIGSEGV
    // （run 45993665762：`[CRASH] signal=11 fault=0x2` 落在这个垫片 +0xb4）。
    const uint32_t type = (uint32_t)arg1(c);
    const uint64_t buf = arg2(c);
    const int cch = (int)arg3(c);
    if (type & 0x20000000u) {   // LOCALE_RETURN_NUMBER
        write_locale_number(c, type, buf, cch);
        ret0(c, 2);
        return;
    }
    const char* v = locale_value(type);
    const int need = (int)std::strlen(v) + 1;
    if (!buf || cch <= 0) { ret0(c, (uint64_t)need); return; }   // 只问所需长度
    if (cch < need) { ret0(c, 0); return; }
    // 兜底：写之前确认目标确实可写。这个垫片以前没注册、调用方一直拿到 0 自己降级，
    // 一旦接上就会用它给的指针直接写，参数不对就是野写。
    if (!guest_mapped(buf, (uint64_t)need * 2)) {
        static int logged = 0;
        if (logged++ < 5)
            std::fprintf(stderr, "[shim] GetLocaleInfoEx 目标不可写 buf=0x%llx need=%d，返回失败\n",
                         (unsigned long long)buf, need);
        ret0(c, 0);
        return;
    }
    write_utf16(c, buf, v);
    ret0(c, (uint64_t)need);
}

// CompareString*：按码点序比较，返回 1/2/3（CSTR_LESS/EQUAL/GREATER）
namespace {
int compare_units(const uint16_t* a, int an, const uint16_t* b, int bn) {
    int i = 0;
    for (; i < an && i < bn; ++i) {
        if (a[i] != b[i]) return a[i] < b[i] ? 1 : 3;
    }
    if (an == bn) return 2;
    return an < bn ? 1 : 3;
}
}  // namespace
void shim_KERNEL32_CompareStringW(X64Ctx* c) {
    const uint64_t sa = arg2(c), sb = arg4(c);
    const int na = (int)arg3(c), nb = (int)arg5(c);
    if (!sa || !sb) { ret0(c, 0); return; }
    const uint16_t* a = (const uint16_t*)guest_ptr_from_ctx(c, sa);
    const uint16_t* b = (const uint16_t*)guest_ptr_from_ctx(c, sb);
    int an = na, bn = nb;
    if (an < 0) { an = 0; while (a[an]) ++an; }
    if (bn < 0) { bn = 0; while (b[bn]) ++bn; }
    ret0(c, (uint64_t)compare_units(a, an, b, bn));
}
void shim_KERNEL32_CompareStringEx(X64Ctx* c) {
    // (name, flags, s1, n1, s2, n2, version, reserved, param) —— 前 6 个参数位置一致
    const uint64_t sa = arg2(c), sb = arg4(c);
    const int na = (int)arg3(c), nb = (int)arg5(c);
    if (!sa || !sb) { ret0(c, 0); return; }
    const uint16_t* a = (const uint16_t*)guest_ptr_from_ctx(c, sa);
    const uint16_t* b = (const uint16_t*)guest_ptr_from_ctx(c, sb);
    int an = na, bn = nb;
    if (an < 0) { an = 0; while (a[an]) ++an; }
    if (bn < 0) { bn = 0; while (b[bn]) ++bn; }
    ret0(c, (uint64_t)compare_units(a, an, b, bn));
}
void shim_KERNEL32_CompareStringA(X64Ctx* c) {
    const uint64_t sa = arg2(c), sb = arg4(c);
    const int na = (int)arg3(c), nb = (int)arg5(c);
    if (!sa || !sb) { ret0(c, 0); return; }
    const char* a = (const char*)guest_ptr_from_ctx(c, sa);
    const char* b = (const char*)guest_ptr_from_ctx(c, sb);
    int an = na, bn = nb;
    if (an < 0) { an = 0; while (a[an]) ++an; }
    if (bn < 0) { bn = 0; while (b[bn]) ++bn; }
    const int n = an < bn ? an : bn;
    int cmp = 2;
    for (int i = 0; i < n; ++i) {
        if (a[i] != b[i]) { cmp = (a[i] < b[i]) ? 1 : 3; break; }
    }
    if (cmp == 2 && an != bn) cmp = an < bn ? 1 : 3;
    ret0(c, (uint64_t)cmp);
}
void shim_KERNEL32_LCMapStringEx(X64Ctx* c) { (void)c; ret0(c, 0); }   // 如实失败

// ---------------- USER32 / GDI32：假窗口 + 有界消息循环（阶段 A） ----------------
// 依据见 Mewgenics-方案二-窗口与GL垫片设计-2026-11-27.md：
//   * 导入表里没有 SDL3.dll —— SDL 静态链进游戏，窗口仍走 USER32；
//   * 没有 wglCreateContext —— GL 入口靠 LoadLibraryW("opengl32.dll") +
//     GetProcAddress("wglCreateContext") 动态取，所以 wgl 的接入点是 KERNEL32
//     的动态加载垫片，不是导入表。
// 阶段 A 只做「假窗口 + 有界消息循环」：让引擎初始化跑穿、跑到资源加载，
// 跑满 MEW_MAX_FRAMES（默认 60）后投递 WM_QUIT 让引擎自己退出，
// 这样能拿到退出路径的日志，不必再靠 timeout 杀进程。
namespace {
constexpr uint64_t kFakeHwnd = 0x10001;
constexpr uint64_t kFakeHdc  = 0x20001;
constexpr uint32_t WM_PAINT_  = 0x000F;
constexpr uint32_t WM_TIMER_  = 0x0113;
constexpr uint32_t WM_QUIT_   = 0x0012;
constexpr uint32_t WM_CLOSE_  = 0x0010;

struct WinState { int w; int h; int frames; bool quit_sent; const char* title; };
WinState& win() {
    static WinState s = {1280, 720, 0, false, ""};
    return s;
}
int max_frames() {
    static int v = -1;
    if (v < 0) {
        const char* e = std::getenv("MEW_MAX_FRAMES");
        v = e ? std::atoi(e) : 60;
        if (v <= 0) v = 60;
    }
    return v;
}
// MSG（x64，48 字节）：hwnd(0) message(8) wParam(16) lParam(24) time(32) pt(36,40) lPrivate(44)
void fill_msg(X64Ctx* c, uint64_t dst, uint32_t msg) {
    if (!dst) return;
    std::memset(guest_ptr_from_ctx(c, dst), 0, 48);
    mem_write<uint64_t>(c, dst + 0, kFakeHwnd);
    mem_write<uint32_t>(c, dst + 8, msg);
    mem_write<uint32_t>(c, dst + 32, (uint32_t)(win().frames * 16));
}
void fill_rect(X64Ctx* c, uint64_t dst, int l, int t, int r, int b) {
    if (!dst) return;
    mem_write<int32_t>(c, dst + 0, l);
    mem_write<int32_t>(c, dst + 4, t);
    mem_write<int32_t>(c, dst + 8, r);
    mem_write<int32_t>(c, dst + 12, b);
}
}  // namespace

void shim_USER32_CreateWindowExW(X64Ctx* c) { mew_api_hit("CreateWindowExW");
    const int w = (int)arg6(c), h = (int)arg7(c);
    if (w > 0) win().w = w;
    if (h > 0) win().h = h;
    win().title = (const char*)guest_ptr_from_ctx(c, arg2(c));
    // 带 caller：建窗失败时能立刻区分「SDL 在 WIN_CreateWindow 里建的」还是
    // 「引擎自己走动态表建的」（前者 caller 在 0x140c8xxxx 的 SDL 区，后者在 0x1409bxxxx）。
    std::fprintf(stderr, "[shim] CreateWindowExW(w=%d h=%d title=%s) -> hwnd=0x%llx caller=0x%llx\n",
                 win().w, win().h, win().title ? win().title : "(n/a)",
                 (unsigned long long)kFakeHwnd, (unsigned long long)cur_fn_va());
    ret0(c, kFakeHwnd);
}
void shim_USER32_CreateWindowExA(X64Ctx* c) { shim_USER32_CreateWindowExW(c); }
void shim_USER32_RegisterClassW(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_USER32_RegisterClassExW(X64Ctx* c) { mew_api_hit("RegisterClassExW"); (void)c; ret0(c, 1); }
void shim_USER32_RegisterClassA(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_USER32_DestroyWindow(X64Ctx* c) { mew_api_hit("DestroyWindow"); (void)c; ret0(c, 1); }
void shim_USER32_IsWindow(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_USER32_ShowWindow(X64Ctx* c) { mew_api_hit("ShowWindow"); (void)c; ret0(c, 1); }
void shim_USER32_SetWindowPos(X64Ctx* c) { mew_api_hit("SetWindowPos");
    // (hwnd, hWndInsertAfter, x, y, cx, cy, flags)：cx=第 5 个=arg4，cy=第 6 个=arg5
    const int cx = (int)arg4(c), cy = (int)arg5(c);
    if (cx > 0) win().w = cx;
    if (cy > 0) win().h = cy;
    ret0(c, 1);
}
void shim_USER32_GetClientRect(X64Ctx* c) { mew_api_hit("GetClientRect");
    fill_rect(c, arg1(c), 0, 0, win().w, win().h);
    ret0(c, 1);
}
void shim_USER32_GetWindowRect(X64Ctx* c) {
    fill_rect(c, arg1(c), 0, 0, win().w, win().h);
    ret0(c, 1);
}
void shim_USER32_GetDC(X64Ctx* c) { mew_api_hit("GetDC"); (void)c; ret0(c, kFakeHdc); }
void shim_USER32_ReleaseDC(X64Ctx* c) { mew_api_hit("ReleaseDC"); (void)c; ret0(c, 1); }
void shim_USER32_GetForegroundWindow(X64Ctx* c) { (void)c; ret0(c, kFakeHwnd); }
void shim_USER32_GetActiveWindow(X64Ctx* c) { (void)c; ret0(c, kFakeHwnd); }
void shim_USER32_SetForegroundWindow(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_USER32_SetActiveWindow(X64Ctx* c) { (void)c; ret0(c, kFakeHwnd); }
void shim_USER32_EnableWindow(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_USER32_GetWindowLongW(X64Ctx* c) {
    // GWL_STYLE(-16) 给个带 WS_VISIBLE 的普通风格，其余 0
    if ((int)arg1(c) == -16) { ret0(c, 0x10CF0000ULL); return; }
    ret0(c, 0);
}
void shim_USER32_GetWindowLongPtrW(X64Ctx* c) { shim_USER32_GetWindowLongW(c); }
void shim_USER32_SetWindowLongW(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_USER32_SetWindowLongPtrW(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_USER32_GetWindowThreadProcessId(X64Ctx* c) {
    if (arg1(c)) mem_write<uint32_t>(c, arg1(c), 1);
    ret0(c, kFakeHwnd);
}
void shim_USER32_GetWindowTextW(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_USER32_GetWindowTextA(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_USER32_GetWindowTextLengthW(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_USER32_SetWindowTextW(X64Ctx* c) { mew_api_hit("SetWindowTextW"); (void)c; ret0(c, 1); }
void shim_USER32_ScreenToClient(X64Ctx* c) { (void)c; ret0(c, 1); }   // 恒等变换
void shim_USER32_ClientToScreen(X64Ctx* c) { (void)c; ret0(c, 1); }

// ---- 消息循环：有界 ----
// PeekMessageW/GetMessageW 每调用一次推进一「帧」，跑满 MEW_MAX_FRAMES 后投 WM_QUIT
void shim_USER32_PeekMessageW(X64Ctx* c) { mew_api_hit("PeekMessageW");
    if (win().frames < max_frames()) {
        win().frames++;
        fill_msg(c, arg0(c), (win().frames % 16 == 0) ? WM_TIMER_ : WM_PAINT_);
        ret0(c, 1);
        return;
    }
    if (!win().quit_sent) {
        win().quit_sent = true;
        fill_msg(c, arg0(c), WM_QUIT_);
        std::fprintf(stderr, "[shim] 消息循环到达 MEW_MAX_FRAMES=%d，投递 WM_QUIT\n",
                     max_frames());
        ret0(c, 1);
        return;
    }
    ret0(c, 0);
}
void shim_USER32_GetMessageW(X64Ctx* c) { mew_api_hit("GetMessageW");
    if (win().frames < max_frames()) {
        win().frames++;
        fill_msg(c, arg0(c), (win().frames % 16 == 0) ? WM_TIMER_ : WM_PAINT_);
        ret0(c, 1);
        return;
    }
    if (!win().quit_sent) {
        win().quit_sent = true;
        fill_msg(c, arg0(c), WM_QUIT_);
        std::fprintf(stderr, "[shim] 消息循环到达 MEW_MAX_FRAMES=%d，投递 WM_QUIT\n",
                     max_frames());
        ret0(c, 1);
        return;
    }
    ret0(c, 0);   // GetMessageW 返回 0 = 收到 WM_QUIT，引擎退出主循环
}
void shim_USER32_DispatchMessageW(X64Ctx* c) { mew_api_hit("DispatchMessageW"); (void)c; ret0(c, 0); }
void shim_USER32_TranslateMessage(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_USER32_DefWindowProcW(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_USER32_DefWindowProcA(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_USER32_CallWindowProcW(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_USER32_PostMessageW(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_USER32_PostThreadMessageW(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_USER32_SendMessageW(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_USER32_SendMessageA(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_USER32_GetMessageExtraInfo(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_USER32_GetMessageTime(X64Ctx* c) { (void)c; ret0(c, (uint64_t)(win().frames * 16)); }
void shim_USER32_GetMessagePos(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_USER32_RegisterWindowMessageA(X64Ctx* c) {
    static uint32_t n = 0xC000;
    ret0(c, n++);
}
void shim_USER32_MessageBoxA(X64Ctx* c) {
    static int logged = 0;
    if (logged++ < 5)
        std::fprintf(stderr, "[shim] MessageBoxA: %s\n",
                     (const char*)guest_ptr_from_ctx(c, arg1(c)));
    ret0(c, 1);
}

// ---------------- COMCTL32：任务对话框（诊断用） ----------------
// SDL3 的 SDL_ShowSimpleMessageBox 在 Windows 上**优先**用 TaskDialogIndirect
// （comctl32 v6，动态 GetProcAddress 取），取不到才回落到自绘的旧消息框
// （WIN_ShowOldMessageBox：CreateCompatibleDC + 512KB 位图 + 模态循环）。
// 这个名字以前不在 lookup_api 里，于是 GetProcAddress 返回 0，SDL 走旧路径——
// run 46047307348 里连续三次 `LoadLibraryW(comctl32) -> GetProcAddress=0
// -> CreateCompatibleDC -> HeapAlloc(524319) -> SleepConditionVariableSRW(INFINITE)
// -> ExitProcess(3)`，就是三次「想弹错误框但弹不出来」，正文一条都没进日志。
//
// 这里给它一个真垫片：把 TASKDIALOGCONFIG 的标题/正文打出来，然后按「点了第一个按钮」
// 立刻返回 S_OK。SDL 因此走 SUCCEEDED 分支，不再进旧消息框、也不再阻塞。
//
// 布局注意（这条是硬事实，别按自然对齐写）：Windows SDK 的 commctrl.h 里
// TASKDIALOGCONFIG 被 `#include <pshpack1.h>` 包着（mingw-w64 的 commctrl.h
// 5168 行 pshpack1 -> 5262 行结构体 -> 5298 行 poppack），SDL3 自己也写了
// `#pragma pack(push, 1)`。所以 x64 下 cbSize = 0xA0（不是自然对齐的 0xB0），
// 字段偏移是：+0x1C pszWindowTitle / +0x2C pszMainInstruction / +0x34 pszContent
// / +0x3C cButtons / +0x64 pszExpandedInformation / +0x84 pszFooter。
// 0x20/0x30/0x38 是自然对齐的偏移，读出来是指针的高半截 + 图标资源 ID，全是垃圾。
// 这里按 cbSize 选布局，并对每个指针做 guest_mapped 校验、取不到就换另一种布局再试。
void shim_COMCTL32_TaskDialogIndirect(X64Ctx* c) {
    // run 46051381022：rcx 指向的是 UTF-16 "ERROR"，不是 TASKDIALOGCONFIG
    // （cbSize 读出来 0x520045 = 'E','R'），说明真正 config 不在 rcx。
    // 所以这里不再假设第一个参数：把 rcx/rdx/r8/r9 四个候选都看一遍，
    // 谁的前 4 字节是 0xA0（pshpack1）或 0xB0（自然对齐）就当 config；
    // 同时把每个候选的前 0x40 字节十六进制打出来，一轮定型。
    const uint64_t cand[4] = { c->rcx, c->rdx, c->r8, c->r9 };
    const char* names[4] = { "rcx", "rdx", "r8", "r9" };
    int best = -1;
    uint64_t cfg = 0;
    uint32_t cb = 0;
    bool packed = true;
    for (int i = 0; i < 4; ++i) {
        if (!cand[i] || !guest_mapped(cand[i], 4)) continue;
        const uint32_t v = mem_read<uint32_t>(c, cand[i]);
        if (v == 0xA0 || v == 0xB0) { best = i; cfg = cand[i]; cb = v; packed = (v == 0xA0); break; }
    }
    for (int i = 0; i < 4; ++i) {
        if (!cand[i] || !guest_mapped(cand[i], 0x40)) {
            std::fprintf(stderr, "[shim] TaskDialogIndirect cand %s=0x%llx <unmapped>\n",
                         names[i], (unsigned long long)cand[i]);
            continue;
        }
        std::fprintf(stderr, "[shim] TaskDialogIndirect cand %s=0x%llx:", names[i],
                     (unsigned long long)cand[i]);
        for (int k = 0; k < 0x40; k += 8)
            std::fprintf(stderr, " %016llx",
                         (unsigned long long)mem_read<uint64_t>(c, cand[i] + (uint64_t)k));
        std::fprintf(stderr, "\n");
    }
    if (best < 0) {
        // 四个都不像 config：仍然按 rcx 走一遍（可能它真是个小 cbSize 变体）
        cfg = cand[0];
        if (cfg && guest_mapped(cfg, 4)) cb = mem_read<uint32_t>(c, cfg);
        std::fprintf(stderr, "[shim] TaskDialogIndirect 未找到 cbSize=0xA0/0xB0 的候选，退回 rcx\n");
    }
    auto rd = [&](uint64_t off) -> uint64_t {
        if (!cfg || !guest_mapped(cfg + off, 8)) return 0;
        return mem_read<uint64_t>(c, cfg + off);
    };
    auto pick = [&](uint64_t poff, uint64_t noff) -> uint64_t {
        uint64_t v = packed ? rd(poff) : rd(noff);
        if (v && guest_mapped(v, 2)) return v;
        uint64_t w = packed ? rd(noff) : rd(poff);
        if (w && guest_mapped(w, 2)) return w;
        return 0;
    };
    const uint64_t title = pick(0x1C, 0x20);
    const uint64_t instr = pick(0x2C, 0x30);
    const uint64_t content = pick(0x34, 0x38);
    const uint64_t expanded = pick(0x64, 0x70);
    const uint64_t footer = pick(0x84, 0x90);
    uint32_t cbuttons = 0;
    if (cfg && guest_mapped(cfg + (packed ? 0x3C : 0x40), 4))
        cbuttons = mem_read<uint32_t>(c, cfg + (packed ? 0x3C : 0x40));
    std::fprintf(stderr,
                 "[shim] TaskDialogIndirect picked=%s cbSize=0x%x packed=%d buttons=%u"
                 " title=\"%s\" content=\"%s\" main=\"%s\" expanded=\"%s\" footer=\"%s\"\n",
                 (best >= 0 ? names[best] : "rcx(fallback)"), cb, (int)packed, cbuttons,
                 title ? guest_wstr(c, title).c_str() : "",
                 content ? guest_wstr(c, content).c_str() : "",
                 instr ? guest_wstr(c, instr).c_str() : "",
                 expanded ? guest_wstr(c, expanded).c_str() : "",
                 footer ? guest_wstr(c, footer).c_str() : "");
    // IDBUTTONINDEX0(=100)：SDL3 用 nButton-100 反查是第几个按钮。
    if (arg1(c)) mem_write<int32_t>(c, arg1(c), 100);
    if (arg2(c)) mem_write<int32_t>(c, arg2(c), 0);
    if (arg3(c)) mem_write<int32_t>(c, arg3(c), 0);
    ret0(c, 0);   // S_OK
}

// ---- 输入：一律「没有按键」 ----
void shim_USER32_GetAsyncKeyState(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_USER32_GetKeyState(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_USER32_GetKeyboardState(X64Ctx* c) {
    const uint64_t p = arg0(c);
    if (p) std::memset(guest_ptr_from_ctx(c, p), 0, 256);
    ret0(c, 1);
}
void shim_USER32_GetRawInputDeviceList(X64Ctx* c) {
    if (arg1(c)) mem_write<uint32_t>(c, arg1(c), 0);   // 0 个设备
    ret0(c, 0);
}
void shim_USER32_GetRawInputDeviceInfoA(X64Ctx* c) {
    if (arg2(c)) mem_write<uint32_t>(c, arg2(c), 0);
    ret0(c, (uint64_t)-1);
}
void shim_USER32_PtInRect(X64Ctx* c) {
    // BOOL PtInRect(const RECT *lprc, POINT pt) —— pt 是**按值**传的 8 字节（x 低 32、y 高 32）
    const uint64_t r = arg0(c);
    if (!r) { ret0(c, 0); return; }
    const int l = mem_read<int32_t>(c, r + 0), t = mem_read<int32_t>(c, r + 4);
    const int rr = mem_read<int32_t>(c, r + 8), bb = mem_read<int32_t>(c, r + 12);
    const int x = (int)(uint32_t)(arg1(c) & 0xFFFFFFFFu);
    const int y = (int)(uint32_t)(arg1(c) >> 32);
    ret0(c, (x >= l && x < rr && y >= t && y < bb) ? 1 : 0);
}
void shim_USER32_IntersectRect(X64Ctx* c) {
    const uint64_t d = arg0(c), a = arg1(c), b = arg2(c);
    if (!d || !a || !b) { ret0(c, 0); return; }
    int l = std::max(mem_read<int32_t>(c, a + 0), mem_read<int32_t>(c, b + 0));
    int t = std::max(mem_read<int32_t>(c, a + 4), mem_read<int32_t>(c, b + 4));
    int r = std::min(mem_read<int32_t>(c, a + 8), mem_read<int32_t>(c, b + 8));
    int bo = std::min(mem_read<int32_t>(c, a + 12), mem_read<int32_t>(c, b + 12));
    if (r <= l || bo <= t) { fill_rect(c, d, 0, 0, 0, 0); ret0(c, 0); return; }
    fill_rect(c, d, l, t, r, bo);
    ret0(c, 1);
}
void shim_USER32_ClipCursor(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_USER32_GetClipCursor(X64Ctx* c) { fill_rect(c, arg0(c), 0, 0, win().w, win().h); ret0(c, 1); }
void shim_USER32_SetCapture(X64Ctx* c) { (void)c; ret0(c, kFakeHwnd); }
void shim_USER32_ReleaseCapture(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_USER32_SetCursorPos(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_USER32_LockWorkStation(X64Ctx* c) { (void)c; ret0(c, 1); }

// ---- 显示 / 系统参数 ----
void shim_USER32_ChangeDisplaySettingsExW(X64Ctx* c) { (void)c; ret0(c, 0); }  // DISP_CHANGE_SUCCESSFUL
// ---- 显示枚举：必须报告「有一个 1920x1080 的主显示器」 ----
// 以前 EnumDisplayMonitors / EnumDisplayDevicesW 都直接 ret0，等于「这台机器没有任何显示器」。
// SDL3 的 WIN_InitModes 虽然恒返回 true（WIN_AddDisplays 找不到显示器也不报错），
// 但后续 SDL_GetPrimaryDisplay/SDL_GetDisplayBounds 会一路 "Invalid display index"，
// 引擎摆放窗口时就会失败——这条线不能再留空。
// 结构偏移按 mingw-w64 wingdi.h：
//   DEVMODEW: dmSize@68(220) dmFields@72 dmBitsPerPel@168 dmPelsWidth@172
//             dmPelsHeight@176 dmDisplayFrequency@184，sizeof=220
//   DISPLAY_DEVICEW: cb@0 DeviceName[32]@4 DeviceString[128]@68 StateFlags@324，sizeof=840
namespace {
constexpr uint64_t kFakeMonitor = 0x30001;
// 逐字符写 UTF-16LE（只处理 ASCII，够表示设备名）
void put_wascii(X64Ctx* c, uint64_t dst, const char* s, size_t units) {
    size_t i = 0;
    for (; s[i] && i + 1 < units; ++i)
        mem_write<uint16_t>(c, dst + i * 2, (uint16_t)(unsigned char)s[i]);
    if (i < units) mem_write<uint16_t>(c, dst + i * 2, 0);
}
}  // namespace

void shim_USER32_EnumDisplayDevicesW(X64Ctx* c) {
    const uint32_t idx = (uint32_t)arg1(c);
    const uint64_t out = arg2(c);
    if (idx != 0 || !out || !guest_mapped(out, 840)) { ret0(c, 0); return; }
    std::memset(guest_ptr_from_ctx(c, out), 0, 840);
    mem_write<uint32_t>(c, out + 0, 840);
    put_wascii(c, out + 4, "\\\\.\\DISPLAY1", 32);
    put_wascii(c, out + 68, "Fake Display", 128);
    mem_write<uint32_t>(c, out + 324, 0x1 | 0x4);   // ATTACHED_TO_DESKTOP | PRIMARY_DEVICE
    put_wascii(c, out + 328, "MONITOR\\FAKE1", 128);
    put_wascii(c, out + 584, "\\Registry\\Machine\\System\\Fake", 128);
    ret0(c, 1);
}

// BOOL EnumDisplayMonitors(HDC, LPCRECT, MONITORENUMPROC, LPARAM)
// 合成一次回调：回调是 guest 函数，调用方式与 runner 里 TLS 回调一致——
// 先在栈上压一个 0 作返回哨兵（lift 出来的 ret 就是 rsp+=8; return），再 dispatch。
void shim_USER32_EnumDisplayMonitors(X64Ctx* c) { mew_api_hit("EnumDisplayMonitors");
    const uint64_t cb = arg2(c);
    const uint64_t data = arg3(c);
    if (!cb) { ret0(c, 0); return; }
    static uint64_t rect_va = 0;
    if (!rect_va) rect_va = guest_alloc(c, 16);
    if (!rect_va) { ret0(c, 0); return; }
    fill_rect(c, rect_va, 0, 0, win().w, win().h);
    const uint64_t saved_rsp = c->rsp;
    c->rsp -= 8;
    mem_write<uint64_t>(c, c->rsp, 0);   // 返回哨兵：回到宿主
    c->rcx = kFakeMonitor;
    c->rdx = kFakeHdc;
    c->r8 = rect_va;
    c->r9 = data;
    dispatch_indirect(cb, c);
    c->rsp = saved_rsp;
    ret0(c, 1);
}

// BOOL EnumDisplaySettingsW(LPCWSTR, DWORD, DEVMODEW*)
void shim_USER32_EnumDisplaySettingsW(X64Ctx* c) {
    const uint32_t mode = (uint32_t)arg1(c);
    const uint64_t dm = arg2(c);
    if (!dm || !guest_mapped(dm, 220)) { ret0(c, 0); return; }
    // ENUM_CURRENT_SETTINGS = 0xFFFFFFFF，ENUM_REGISTRY_SETTINGS = 0xFFFFFFFE；
    // 只报一个模式，其余索引一律失败（SDL 靠这个判断枚举结束）。
    if (mode != 0xFFFFFFFFu && mode != 0xFFFFFFFEu) { ret0(c, 0); return; }
    std::memset(guest_ptr_from_ctx(c, dm), 0, 220);
    mem_write<uint16_t>(c, dm + 68, 220);                                   // dmSize
    mem_write<uint32_t>(c, dm + 72, 0x005C0000u);                           // BITS_PER_PEL|PELS_WIDTH|PELS_HEIGHT|DISPLAY_FREQUENCY
    mem_write<uint32_t>(c, dm + 168, 32);                                   // dmBitsPerPel
    mem_write<uint32_t>(c, dm + 172, (uint32_t)win().w);                     // dmPelsWidth
    mem_write<uint32_t>(c, dm + 176, (uint32_t)win().h);                     // dmPelsHeight
    mem_write<uint32_t>(c, dm + 184, 60);                                   // dmDisplayFrequency
    ret0(c, 1);
}
void shim_USER32_EnumDisplaySettingsExW(X64Ctx* c) { shim_USER32_EnumDisplaySettingsW(c); }
void shim_USER32_MonitorFromWindow(X64Ctx* c) { (void)c; ret0(c, kFakeHwnd); }
void shim_USER32_GetMonitorInfoW(X64Ctx* c) {
    const uint64_t p = arg1(c);
    if (p) {
        std::memset(guest_ptr_from_ctx(c, p), 0, 40);
        mem_write<uint32_t>(c, p + 0, 40);
        fill_rect(c, p + 4, 0, 0, win().w, win().h);
        fill_rect(c, p + 20, 0, 0, win().w, win().h);
        mem_write<uint32_t>(c, p + 36, 1);   // MONITORINFOF_PRIMARY
    }
    ret0(c, 1);
}
void shim_USER32_SystemParametersInfoW(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_USER32_SystemParametersInfoA(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_USER32_AdjustWindowRectEx(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_USER32_SetWindowRgn(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_USER32_SetLayeredWindowAttributes(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_USER32_FlashWindowEx(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_USER32_SetParent(X64Ctx* c) { ret0(c, kFakeHwnd); }
void shim_USER32_GetWindowPlacement(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_USER32_GetKeyboardLayout(X64Ctx* c) { (void)c; ret0(c, 0x0409); }
void shim_USER32_ToUnicode(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_USER32_LoadCursorW(X64Ctx* c) { (void)c; ret0(c, 0x30001); }
void shim_USER32_SetCursor(X64Ctx* c) { (void)c; ret0(c, 0x30001); }
void shim_USER32_SetWindowsHookExW(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_USER32_UnhookWindowsHookEx(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_USER32_DrawTextW(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_USER32_GetDlgItem(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_USER32_EndDialog(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_USER32_CreateIconFromResource(X64Ctx* c) { (void)c; ret0(c, 0); }

// ---- 剪贴板：一律「没有数据」 ----
void shim_USER32_OpenClipboard(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_USER32_CloseClipboard(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_USER32_EmptyClipboard(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_USER32_GetClipboardData(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_USER32_SetClipboardData(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_USER32_EnumClipboardFormats(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_USER32_IsClipboardFormatAvailable(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_USER32_GetClipboardSequenceNumber(X64Ctx* c) { (void)c; ret0(c, 0); }

// ---------------- 动态表剩余高频：绘制 / 输入 / 图标 / 注册表 / COM ----------------
// 这 30 个在引擎动态表里出现、我们此前**完全没有实现**（走 UNIMPL 弱占位，
// 一律 ret0 = 0）。对 Reg* 这类「0 = ERROR_SUCCESS」的 API 而言，返回 0 且不回填
// 出参比直接失败更糟（调用方会拿着未初始化的 hKey/value 继续跑），所以这里给真语义。
void shim_USER32_BeginPaint(X64Ctx* c) {                 // HDC BeginPaint(HWND, LPPAINTSTRUCT)
    const uint64_t ps = arg1(c);
    // PAINTSTRUCT(x64)：hdc@0(8) fErase@8(4) rcPaint@12(16) fRestore@28(4)
    //                    fIncUpdate@32(4) rgbReserved@36(32)  -> sizeof 68，按 8 对齐 72
    // 早先这里把 fErase 写到了 +32（那是 fIncUpdate），代码复查时纠正。
    if (ps && guest_mapped(ps, 72)) {
        std::memset(guest_ptr_from_ctx(c, ps), 0, 72);
        mem_write<uint64_t>(c, ps + 0, kFakeHdc);        // hdc
        mem_write<uint32_t>(c, ps + 8, 1);               // fErase = TRUE
    }
    ret0(c, kFakeHdc);
}
void shim_USER32_EndPaint(X64Ctx* c) { ret0(c, 1); }
void shim_USER32_GetUpdateRect(X64Ctx* c) {              // BOOL(HWND, LPRECT, BOOL)
    if (arg1(c)) fill_rect(c, arg1(c), 0, 0, 0, 0);
    ret0(c, 0);
}
void shim_USER32_InvalidateRect(X64Ctx* c) { ret0(c, 1); }
void shim_USER32_ValidateRect(X64Ctx* c) { ret0(c, 1); }
void shim_USER32_FillRect(X64Ctx* c) { ret0(c, 1); }
void shim_USER32_GetFocus(X64Ctx* c) { ret0(c, kFakeHwnd); }
void shim_USER32_SetFocus(X64Ctx* c) { ret0(c, kFakeHwnd); }
void shim_USER32_GetCursorPos(X64Ctx* c) {
    const uint64_t p = arg0(c);
    if (p && guest_mapped(p, 8)) { mem_write<int32_t>(c, p, 0); mem_write<int32_t>(c, p + 4, 0); }
    ret0(c, 1);
}
void shim_USER32_SetTimer(X64Ctx* c) { ret0(c, 1); }
void shim_USER32_KillTimer(X64Ctx* c) { ret0(c, 1); }
void shim_USER32_GetQueueStatus(X64Ctx* c) { ret0(c, 0); }
void shim_USER32_RegisterRawInputDevices(X64Ctx* c) { ret0(c, 1); }
void shim_USER32_GetRawInputData(X64Ctx* c) { ret0(c, 0); }
void shim_USER32_GetRawInputBuffer(X64Ctx* c) { ret0(c, 0); }
void shim_USER32_LoadIconW(X64Ctx* c) { ret0(c, 1); }
void shim_USER32_CreateIconIndirect(X64Ctx* c) { ret0(c, 1); }
void shim_USER32_DestroyIcon(X64Ctx* c) { ret0(c, 1); }
void shim_USER32_DestroyCursor(X64Ctx* c) { ret0(c, 1); }
void shim_USER32_TrackMouseEvent(X64Ctx* c) { ret0(c, 1); }
void shim_USER32_GetClassInfoExW(X64Ctx* c) { ret0(c, 0); }   // 0 = 类未注册（SDL 会去注册）
void shim_USER32_UnregisterClassW(X64Ctx* c) { ret0(c, 1); }
void shim_USER32_UnregisterClassA(X64Ctx* c) { ret0(c, 1); }
void shim_USER32_RegisterClassExA(X64Ctx* c) { ret0(c, 1); }
void shim_USER32_GetPropW(X64Ctx* c) { ret0(c, 0); }
void shim_USER32_SetPropW(X64Ctx* c) { ret0(c, 1); }
void shim_USER32_RemovePropW(X64Ctx* c) { ret0(c, 1); }
// MapVirtualKeyW(uCode, uMapType)：run 46061908947 里被调了 836 次且完全未实现
// （弱占位一律返回 0）。SDL/引擎在枚举键盘布局时会反复问，全 0 会让它一直扫。
// 这里按 Win32 语义给最小可用映射：
//   0=MAPVK_VK_TO_VSC  1=MAPVK_VSC_TO_VK  2=MAPVK_VK_TO_CHAR
//   3=MAPVK_VSC_TO_VK_EX  4=MAPVK_VK_TO_VSC_EX
void shim_USER32_MapVirtualKeyW(X64Ctx* c) { mew_api_hit("MapVirtualKeyW");
    const uint32_t code = (uint32_t)arg0(c);
    const uint32_t type = (uint32_t)arg1(c);
    uint32_t out = 0;
    switch (type) {
        case 0:   // VK -> VSC
        case 4:   // VK -> VSC_EX
            if (code >= 'A' && code <= 'Z') out = 0x1E + (code - 'A');
            else if (code >= '0' && code <= '9') out = 0x02 + (code - '0');
            else if (code == 0x20) out = 0x39;   // space
            else if (code >= 0x70 && code <= 0x87) out = 0x3B + (code - 0x70);  // F1..F24
            break;
        case 1:   // VSC -> VK
        case 3:   // VSC -> VK_EX
            if (code >= 0x1E && code <= 0x26) out = 'A' + (code - 0x1E);
            else if (code >= 0x02 && code <= 0x0B) out = '0' + (code - 0x02);
            else if (code == 0x39) out = 0x20;
            break;
        case 2:   // VK -> CHAR
            if (code >= 0x30 && code <= 0x5A) out = code;   // 数字与大写字母按 ASCII 回
            else if (code == 0x20) out = ' ';
            break;
        default:
            break;
    }
    ret0(c, out);
}
void shim_USER32_MapVirtualKeyA(X64Ctx* c) { shim_USER32_MapVirtualKeyW(c); }
void shim_USER32_GetDoubleClickTime(X64Ctx* c) { ret0(c, 500); }
void shim_USER32_MonitorFromPoint(X64Ctx* c) { ret0(c, 0x30001); }
void shim_USER32_SetRectEmpty(X64Ctx* c) {
    const uint64_t p = arg0(c);
    if (p) fill_rect(c, p, 0, 0, 0, 0);
    ret0(c, 1);
}
// 注册表：0 是 ERROR_SUCCESS，所以必须回真错误码，别让调用方拿着未初始化的 hKey 继续跑
void shim_ADVAPI32_RegOpenKeyExW(X64Ctx* c) {
    if (arg4(c)) mem_write<uint64_t>(c, arg4(c), 0);
    ret0(c, 2);   // ERROR_FILE_NOT_FOUND
}
void shim_ADVAPI32_RegQueryValueExW(X64Ctx* c) { ret0(c, 2); }
void shim_ADVAPI32_RegCloseKey(X64Ctx* c) { ret0(c, 0); }
// COM：S_OK；单线程模拟下不需要真初始化
void shim_OLE32_CoInitializeEx(X64Ctx* c) { ret0(c, 0); }
void shim_OLE32_OleInitialize(X64Ctx* c) { ret0(c, 0); }
void shim_OLE32_CoUninitialize(X64Ctx* c) { ret0(c, 0); }
void shim_OLE32_OleUninitialize(X64Ctx* c) { ret0(c, 0); }

// ---------------- GDI32 像素格式 + OPENGL32 / wgl：假 GL 3.3 上下文 ----------------
// 依据（run 46055985114 之后）：
//   * 引擎的动态表里有 ChoosePixelFormat/SetPixelFormat/DescribePixelFormat/
//     GetPixelFormat/SwapBuffers 这 5 个名字，我们**一个都没实现**；
//   * 同一张表里还有 27 个 gl*/wgl* 名字（glGetString/glGetIntegerv/glGenTextures/
//     glTexImage2D/glViewport/wglGetProcAddress/wglGetCurrentDC…），也全没实现；
//   * ApplicationBase::initGraphics 里写着 "This game requires OpenGL 3.2 or higher"，
//     所以窗口建起来之后 GL 就是下一关。
// 这一批按「最小可信」实现：上下文/像素格式一律成功，glGetString 报 3.3，
// glGenTextures 给真句柄，其余绘制类一律 no-op（不崩、不阻塞，够跑初始化）。
namespace {
constexpr uint64_t kFakeHglrc = 0x30001;
constexpr int32_t  kFakePixelFormat = 1;
uint32_t g_gl_tex_id = 0;

const char* gl_string_for(uint32_t name) {
    switch (name) {
        case 0x1F00: return "MewRecomp";                 // GL_VENDOR
        case 0x1F01: return "MewRecomp FakeGL";          // GL_RENDERER
        case 0x1F02: return "3.3.0 MewRecomp";           // GL_VERSION
        case 0x1F03: return "";                          // GL_EXTENSIONS
        case 0x8B8C: return "3.30";                      // GL_SHADING_LANGUAGE_VERSION
        default: return "";
    }
}

// 把 ASCII 写进一块新分配的 guest 内存并返回其地址（glGetString 用，调用次数很少）
uint64_t gl_new_cstr(X64Ctx* c, const char* s) {
    const size_t n = std::strlen(s) + 1;
    const uint64_t va = guest_alloc(c, n);
    if (!va) return 0;
    for (size_t i = 0; i < n; ++i) mem_write<uint8_t>(c, va + (uint64_t)i, (uint8_t)s[i]);
    return va;
}
}  // namespace

void shim_GDI32_ChoosePixelFormat(X64Ctx* c) { ret0(c, (uint64_t)kFakePixelFormat); }
void shim_GDI32_SetPixelFormat(X64Ctx* c) { mew_api_hit("SetPixelFormat"); ret0(c, 1); }
void shim_GDI32_GetPixelFormat(X64Ctx* c) { ret0(c, (uint64_t)kFakePixelFormat); }
// BOOL DescribePixelFormat(HDC, int, UINT nBytes, LPPIXELFORMATDESCRIPTOR)
void shim_GDI32_DescribePixelFormat(X64Ctx* c) {
    const uint64_t p = arg3(c);
    if (p && guest_mapped(p, 40)) {
        std::memset(guest_ptr_from_ctx(c, p), 0, 40);
        mem_write<uint16_t>(c, p + 0, 40);          // nSize
        mem_write<uint16_t>(c, p + 2, 1);           // nVersion
        mem_write<uint32_t>(c, p + 4, 0x25);        // DRAW_TO_WINDOW|SUPPORT_OPENGL|DOUBLEBUFFER
        mem_write<uint8_t>(c, p + 8, 0);            // PFD_TYPE_RGBA
        mem_write<uint8_t>(c, p + 9, 32);           // cColorBits
        mem_write<uint8_t>(c, p + 23, 24);          // cDepthBits
        mem_write<uint8_t>(c, p + 24, 8);           // cStencilBits
    }
    ret0(c, 1);
}
void shim_GDI32_SwapBuffers(X64Ctx* c) { ret0(c, 1); }

void shim_OPENGL32_wglCreateContext(X64Ctx* c) { mew_api_hit("wglCreateContext"); ret0(c, kFakeHglrc); }
void shim_OPENGL32_wglCreateContextAttribsARB(X64Ctx* c) { ret0(c, kFakeHglrc); }
void shim_OPENGL32_wglMakeCurrent(X64Ctx* c) { mew_api_hit("wglMakeCurrent"); ret0(c, 1); }
void shim_OPENGL32_wglDeleteContext(X64Ctx* c) { ret0(c, 1); }
void shim_OPENGL32_wglGetCurrentContext(X64Ctx* c) { ret0(c, kFakeHglrc); }
void shim_OPENGL32_wglGetCurrentDC(X64Ctx* c) { ret0(c, kFakeHdc); }
void shim_OPENGL32_wglSwapBuffers(X64Ctx* c) { ret0(c, 1); }
void shim_OPENGL32_wglSwapIntervalEXT(X64Ctx* c) { ret0(c, 1); }
void shim_OPENGL32_wglGetProcAddress(X64Ctx* c) { mew_api_hit("wglGetProcAddress");
    const char* name = (const char*)guest_ptr_from_ctx(c, arg0(c));
    ret0(c, (name && name[0]) ? shim_KERNEL32_LookupSynthetic(name) : 0);
}
// BOOL wglChoosePixelFormatARB(HDC, const int*, const FLOAT*, UINT, int*, UINT*)
void shim_OPENGL32_wglChoosePixelFormatARB(X64Ctx* c) {
    const uint64_t formats = arg4(c);
    const uint64_t nout = arg5(c);
    if (formats && guest_mapped(formats, 4)) mem_write<int32_t>(c, formats, kFakePixelFormat);
    if (nout) mem_write<uint32_t>(c, nout, 1);
    ret0(c, 1);
}

// BOOL wglGetPixelFormatAttribivARB(HDC, int iPixelFormat, int iLayerPlane,
//                                  UINT nAttributes, const int* piAttribs, int* piValues)
// 为什么必须实现：SDL 的 WIN_GL_SetupWindow 拿到 wglChoosePixelFormatARB 之后，
// 会再用本函数逐项核对属性；这个函数缺失时 wglGetProcAddress 返回 0，SDL 判
//   "No matching GL pixel format available"
// 并放弃建 GL 上下文（run 46105611557 实测这条 2 次，正好对应两轮建窗）。
void shim_OPENGL32_wglGetPixelFormatAttribivARB(X64Ctx* c) {
    const uint32_t n = (uint32_t)arg3(c);
    const uint64_t pattr = arg4(c);
    const uint64_t pval = arg5(c);
    if (!pattr || !pval || n == 0 || n > 64) { ret0(c, 0); return; }
    for (uint32_t i = 0; i < n; ++i) {
        const int32_t a = mem_read<int32_t>(c, pattr + (uint64_t)i * 4);
        int32_t v = 0;
        switch (a) {
            case 0x2001: v = 1; break;       // WGL_DRAW_TO_WINDOW_ARB
            case 0x2003: v = 0x2027; break;  // WGL_ACCELERATION_ARB = FULL
            case 0x200B: v = 1; break;       // WGL_SUPPORT_OPENGL_ARB
            case 0x2011: v = 1; break;       // WGL_DOUBLE_BUFFER_ARB
            case 0x2013: v = 0x202B; break;  // WGL_PIXEL_TYPE_ARB = RGBA
            case 0x2014: v = 32; break;      // WGL_COLOR_BITS_ARB
            case 0x2015: v = 8; break;       // WGL_RED_BITS_ARB
            case 0x2017: v = 8; break;       // WGL_GREEN_BITS_ARB
            case 0x2019: v = 8; break;       // WGL_BLUE_BITS_ARB
            case 0x201B: v = 8; break;       // WGL_ALPHA_BITS_ARB
            case 0x2022: v = 24; break;      // WGL_DEPTH_BITS_ARB
            case 0x2023: v = 8; break;       // WGL_STENCIL_BITS_ARB
            default:     v = 0; break;       // STEREO / SAMPLES / SAMPLE_BUFFERS = 0
        }
        mem_write<int32_t>(c, pval + (uint64_t)i * 4, v);
    }
    ret0(c, 1);
}

// BOOL wglGetPixelFormatAttribfvARB(HDC, int, int, UINT, const int*, FLOAT*)
void shim_OPENGL32_wglGetPixelFormatAttribfvARB(X64Ctx* c) {
    const uint32_t n = (uint32_t)arg3(c);
    const uint64_t pval = arg5(c);
    if (!pval || n == 0 || n > 64) { ret0(c, 0); return; }
    for (uint32_t i = 0; i < n; ++i) mem_write<float>(c, pval + (uint64_t)i * 4, 1.0f);
    ret0(c, 1);
}

void shim_OPENGL32_glGetString(X64Ctx* c) { mew_api_hit("glGetString");
    // 每个 pname 只分配一次：早先每次调用都 guest_alloc，长跑下来会持续泄漏 guest 堆。
    static uint64_t cache[6] = {0, 0, 0, 0, 0, 0};
    const uint32_t nm = (uint32_t)arg0(c);
    int ix = 5;
    switch (nm) {
        case 0x1F00: ix = 0; break;   // GL_VENDOR
        case 0x1F01: ix = 1; break;   // GL_RENDERER
        case 0x1F02: ix = 2; break;   // GL_VERSION
        case 0x1F03: ix = 3; break;   // GL_EXTENSIONS
        case 0x8B8C: ix = 4; break;   // GL_SHADING_LANGUAGE_VERSION
        default: ix = 5; break;
    }
    if (!cache[ix]) cache[ix] = gl_new_cstr(c, gl_string_for(nm));
    // 把 pname 和返回内容打出来：initGraphics 里的 "This game requires OpenGL 3.2
    // or higher" 就在这里判，GL_EXTENSIONS 现在返回空串，引擎只要 strstr 查扩展
    // 就会失败——到底是查版本还是查扩展，看这几行就知道。
    static int logged = 0;
    if (logged++ < 24)
        std::fprintf(stderr, "[shim] glGetString(0x%04x) -> \"%s\" caller=0x%llx\n",
                     nm, gl_string_for(nm), (unsigned long long)cur_fn_va());
    ret0(c, cache[ix]);
}
void shim_OPENGL32_glGetIntegerv(X64Ctx* c) { mew_api_hit("glGetIntegerv");
    const uint32_t pname = (uint32_t)arg0(c);
    const uint64_t out = arg1(c);
    if (!out) { ret0(c, 0); return; }
    int32_t v = 0;
    switch (pname) {
        case 0x0D33: v = 16384; break;   // GL_MAX_TEXTURE_SIZE
        case 0x8872: v = 16; break;      // GL_MAX_TEXTURE_IMAGE_UNITS
        case 0x8B4D: v = 32; break;      // GL_MAX_COMBINED_TEXTURE_IMAGE_UNITS
        case 0x8869: v = 16; break;      // GL_MAX_VERTEX_ATTRIBS
        case 0x8DFB: v = 1024; break;    // GL_MAX_VERTEX_UNIFORM_VECTORS
        case 0x8DFD: v = 1024; break;    // GL_MAX_FRAGMENT_UNIFORM_VECTORS
        case 0x8DFC: v = 32; break;      // GL_MAX_VARYING_VECTORS
        case 0x0BA2: {                   // GL_VIEWPORT -> 4 ints
            mem_write<int32_t>(c, out + 0, 0);
            mem_write<int32_t>(c, out + 4, 0);
            mem_write<int32_t>(c, out + 8, win().w);
            mem_write<int32_t>(c, out + 12, win().h);
            ret0(c, 0);
            return;
        }
        default: v = 0; break;
    }
    mem_write<int32_t>(c, out, v);
    ret0(c, 0);
}
void shim_OPENGL32_glGenTextures(X64Ctx* c) {
    const int32_t n = (int32_t)arg0(c);
    const uint64_t out = arg1(c);
    if (out) for (int32_t i = 0; i < n && i < 64; ++i)
        mem_write<uint32_t>(c, out + (uint64_t)i * 4, ++g_gl_tex_id);
    ret0(c, 0);
}

// 其余 GL 入口：绘制态一律 no-op（语义上是「设置成功」，不改任何宿主状态）
void shim_OPENGL32_glBindTexture(X64Ctx* c) { ret0(c, 0); }
void shim_OPENGL32_glBlendFunc(X64Ctx* c) { ret0(c, 0); }
void shim_OPENGL32_glClear(X64Ctx* c) { mew_api_hit("glClear"); ret0(c, 0); }
void shim_OPENGL32_glClearColor(X64Ctx* c) { ret0(c, 0); }
void shim_OPENGL32_glColorMask(X64Ctx* c) { ret0(c, 0); }
void shim_OPENGL32_glCopyTexSubImage2D(X64Ctx* c) { ret0(c, 0); }
void shim_OPENGL32_glDeleteTextures(X64Ctx* c) { ret0(c, 0); }
void shim_OPENGL32_glDepthMask(X64Ctx* c) { ret0(c, 0); }
void shim_OPENGL32_glDisable(X64Ctx* c) { mew_api_hit("glDisable"); ret0(c, 0); }
void shim_OPENGL32_glDrawArrays(X64Ctx* c) { mew_api_hit("glDrawArrays"); ret0(c, 0); }
void shim_OPENGL32_glEnable(X64Ctx* c) { mew_api_hit("glEnable"); ret0(c, 0); }
void shim_OPENGL32_glLineWidth(X64Ctx* c) { ret0(c, 0); }
void shim_OPENGL32_glPixelStorei(X64Ctx* c) { ret0(c, 0); }
void shim_OPENGL32_glPointSize(X64Ctx* c) { ret0(c, 0); }
void shim_OPENGL32_glPolygonMode(X64Ctx* c) { ret0(c, 0); }
void shim_OPENGL32_glScissor(X64Ctx* c) { ret0(c, 0); }
void shim_OPENGL32_glStencilFunc(X64Ctx* c) { ret0(c, 0); }
void shim_OPENGL32_glStencilMask(X64Ctx* c) { ret0(c, 0); }
void shim_OPENGL32_glStencilOp(X64Ctx* c) { ret0(c, 0); }
void shim_OPENGL32_glTexImage2D(X64Ctx* c) { ret0(c, 0); }
void shim_OPENGL32_glTexParameteri(X64Ctx* c) { ret0(c, 0); }
void shim_OPENGL32_glViewport(X64Ctx* c) { ret0(c, 0); }

// ---- 动态表登记的 159 个符号：定义散落在本文件各处，这里统一前置声明 ----
void shim_GDI32_CreateCompatibleDC(X64Ctx*);
void shim_GDI32_CreateDCW(X64Ctx*);
void shim_GDI32_CreateDCA(X64Ctx*);
void shim_GDI32_CreateFontIndirectW(X64Ctx*);
void shim_GDI32_DeleteDC(X64Ctx*);
void shim_GDI32_DeleteObject(X64Ctx*);
void shim_GDI32_GetDeviceCaps(X64Ctx*);
void shim_GDI32_GetTextExtentPoint32A(X64Ctx*);
void shim_GDI32_GetTextMetricsW(X64Ctx*);
void shim_GDI32_SelectObject(X64Ctx*);
void shim_KERNEL32_AddVectoredExceptionHandler(X64Ctx*);
void shim_KERNEL32_AttachConsole(X64Ctx*);
void shim_KERNEL32_CloseThreadpoolWork(X64Ctx*);
void shim_KERNEL32_CompareStringA(X64Ctx*);
void shim_KERNEL32_CompareStringW(X64Ctx*);
void shim_KERNEL32_CreateDirectoryW(X64Ctx*);
void shim_KERNEL32_CreateMutexW(X64Ctx*);
void shim_KERNEL32_CreateSemaphoreW(X64Ctx*);
void shim_KERNEL32_CreateThreadpoolWork(X64Ctx*);
void shim_KERNEL32_DeleteFileW(X64Ctx*);
void shim_KERNEL32_DeviceIoControl(X64Ctx*);
void shim_KERNEL32_EnumSystemLocalesW(X64Ctx*);
void shim_KERNEL32_ExitThread(X64Ctx*);
void shim_KERNEL32_FindClose(X64Ctx*);
void shim_KERNEL32_FindFirstFileW(X64Ctx*);
void shim_KERNEL32_FindNextFileW(X64Ctx*);
void shim_KERNEL32_FormatMessageA(X64Ctx*);
void shim_KERNEL32_FormatMessageW(X64Ctx*);
void shim_KERNEL32_FreeLibrary(X64Ctx*);
void shim_KERNEL32_FreeLibraryWhenCallbackReturns(X64Ctx*);
void shim_KERNEL32_GetConsoleMode(X64Ctx*);
void shim_KERNEL32_GetConsoleOutputCP(X64Ctx*);
void shim_KERNEL32_GetCurrentDirectoryW(X64Ctx*);
void shim_KERNEL32_GetEnvironmentVariableA(X64Ctx*);
void shim_KERNEL32_GetExitCodeThread(X64Ctx*);
void shim_KERNEL32_GetLocaleInfoA(X64Ctx*);
void shim_KERNEL32_GetLocaleInfoW(X64Ctx*);
void shim_KERNEL32_GetLogicalDrives(X64Ctx*);
void shim_KERNEL32_GetModuleFileNameA(X64Ctx*);
void shim_KERNEL32_GetNativeSystemInfo(X64Ctx*);
void shim_KERNEL32_GetProcAddress(X64Ctx*);
void shim_KERNEL32_GetSystemTime(X64Ctx*);
void shim_KERNEL32_GetTimeZoneInformation(X64Ctx*);
void shim_KERNEL32_GetUserDefaultLCID(X64Ctx*);
void shim_KERNEL32_GlobalAlloc(X64Ctx*);
void shim_KERNEL32_GlobalFree(X64Ctx*);
void shim_KERNEL32_GlobalLock(X64Ctx*);
void shim_KERNEL32_GlobalMemoryStatusEx(X64Ctx*);
void shim_KERNEL32_GlobalSize(X64Ctx*);
void shim_KERNEL32_GlobalUnlock(X64Ctx*);
void shim_KERNEL32_InitOnceBeginInitialize(X64Ctx*);
void shim_KERNEL32_InitOnceComplete(X64Ctx*);
void shim_KERNEL32_IsWow64Process(X64Ctx*);
void shim_KERNEL32_LoadLibraryA(X64Ctx*);
void shim_KERNEL32_LoadLibraryExW(X64Ctx*);
void shim_KERNEL32_LoadLibraryW(X64Ctx*);
void shim_KERNEL32_MulDiv(X64Ctx*);
void shim_KERNEL32_ReadConsoleW(X64Ctx*);
void shim_KERNEL32_ReleaseSemaphore(X64Ctx*);
void shim_KERNEL32_RemoveVectoredExceptionHandler(X64Ctx*);
void shim_KERNEL32_RtlCaptureStackBackTrace(X64Ctx*);
void shim_KERNEL32_RtlUnwindEx(X64Ctx*);
void shim_KERNEL32_SetConsoleCtrlHandler(X64Ctx*);
void shim_KERNEL32_SetEnvironmentVariableA(X64Ctx*);
void shim_KERNEL32_SetEnvironmentVariableW(X64Ctx*);
void shim_KERNEL32_SetErrorMode(X64Ctx*);
void shim_KERNEL32_SetStdHandle(X64Ctx*);
void shim_KERNEL32_SetThreadExecutionState(X64Ctx*);
void shim_KERNEL32_SubmitThreadpoolWork(X64Ctx*);
void shim_KERNEL32_TerminateProcess(X64Ctx*);
void shim_KERNEL32_WaitForSingleObjectEx(X64Ctx*);
void shim_KERNEL32_WaitForThreadpoolWorkCallbacks(X64Ctx*);
void shim_KERNEL32_WriteConsoleW(X64Ctx*);
void shim_SHELL32_SHGetFolderPathW(X64Ctx*);
void shim_USER32_AdjustWindowRectEx(X64Ctx*);
void shim_USER32_CallWindowProcW(X64Ctx*);
void shim_USER32_ChangeDisplaySettingsExW(X64Ctx*);
void shim_USER32_ClientToScreen(X64Ctx*);
void shim_USER32_ClipCursor(X64Ctx*);
void shim_USER32_CloseClipboard(X64Ctx*);
void shim_USER32_CreateIconFromResource(X64Ctx*);
void shim_USER32_CreateWindowExA(X64Ctx*);
void shim_USER32_CreateWindowExW(X64Ctx*);
void shim_USER32_DefWindowProcW(X64Ctx*);
void shim_USER32_DestroyWindow(X64Ctx*);
void shim_USER32_DialogBoxIndirectParamW(X64Ctx*);
void shim_USER32_DispatchMessageW(X64Ctx*);
void shim_USER32_DrawTextW(X64Ctx*);
void shim_USER32_EmptyClipboard(X64Ctx*);
void shim_USER32_EnableWindow(X64Ctx*);
void shim_USER32_EndDialog(X64Ctx*);
void shim_USER32_EnumClipboardFormats(X64Ctx*);
void shim_USER32_EnumDisplayDevicesW(X64Ctx*);
void shim_USER32_EnumDisplayMonitors(X64Ctx*);
void shim_USER32_EnumDisplaySettingsW(X64Ctx*);
void shim_USER32_FlashWindowEx(X64Ctx*);
void shim_USER32_GetAsyncKeyState(X64Ctx*);
void shim_USER32_GetClientRect(X64Ctx*);
void shim_USER32_GetClipCursor(X64Ctx*);
void shim_USER32_GetClipboardData(X64Ctx*);
void shim_USER32_GetClipboardSequenceNumber(X64Ctx*);
void shim_USER32_GetDC(X64Ctx*);
void shim_USER32_GetDesktopWindow(X64Ctx*);
void shim_USER32_GetDlgItem(X64Ctx*);
void shim_USER32_GetForegroundWindow(X64Ctx*);
void shim_USER32_GetKeyState(X64Ctx*);
void shim_USER32_GetKeyboardLayout(X64Ctx*);
void shim_USER32_GetKeyboardState(X64Ctx*);
void shim_USER32_GetMessageExtraInfo(X64Ctx*);
void shim_USER32_GetMessagePos(X64Ctx*);
void shim_USER32_GetMessageTime(X64Ctx*);
void shim_USER32_GetMessageW(X64Ctx*);
void shim_USER32_GetMonitorInfoW(X64Ctx*);
void shim_USER32_GetRawInputDeviceInfoA(X64Ctx*);
void shim_USER32_GetRawInputDeviceList(X64Ctx*);
void shim_USER32_GetSystemMetrics(X64Ctx*);
void shim_USER32_GetWindowLongPtrW(X64Ctx*);
void shim_USER32_GetWindowLongW(X64Ctx*);
void shim_USER32_GetWindowPlacement(X64Ctx*);
void shim_USER32_GetWindowRect(X64Ctx*);
void shim_USER32_GetWindowTextLengthW(X64Ctx*);
void shim_USER32_GetWindowTextW(X64Ctx*);
void shim_USER32_GetWindowThreadProcessId(X64Ctx*);
void shim_USER32_IntersectRect(X64Ctx*);
void shim_USER32_IsClipboardFormatAvailable(X64Ctx*);
void shim_USER32_IsWindow(X64Ctx*);
void shim_USER32_LoadCursorW(X64Ctx*);
void shim_USER32_MonitorFromWindow(X64Ctx*);
void shim_USER32_OpenClipboard(X64Ctx*);
void shim_USER32_PeekMessageW(X64Ctx*);
void shim_USER32_PostMessageW(X64Ctx*);
void shim_USER32_PostThreadMessageW(X64Ctx*);
void shim_USER32_PtInRect(X64Ctx*);
void shim_USER32_RegisterClassExW(X64Ctx*);
void shim_USER32_RegisterClassW(X64Ctx*);
void shim_USER32_RegisterWindowMessageA(X64Ctx*);
void shim_USER32_ReleaseCapture(X64Ctx*);
void shim_USER32_ReleaseDC(X64Ctx*);
void shim_USER32_ScreenToClient(X64Ctx*);
void shim_USER32_SendMessageA(X64Ctx*);
void shim_USER32_SendMessageW(X64Ctx*);
void shim_USER32_SetActiveWindow(X64Ctx*);
void shim_USER32_SetCapture(X64Ctx*);
void shim_USER32_SetClipboardData(X64Ctx*);
void shim_USER32_SetCursor(X64Ctx*);
void shim_USER32_SetCursorPos(X64Ctx*);
void shim_USER32_SetForegroundWindow(X64Ctx*);
void shim_USER32_SetLayeredWindowAttributes(X64Ctx*);
void shim_USER32_SetParent(X64Ctx*);
void shim_USER32_SetWindowLongPtrW(X64Ctx*);
void shim_USER32_SetWindowLongW(X64Ctx*);
void shim_USER32_SetWindowPos(X64Ctx*);
void shim_USER32_SetWindowRgn(X64Ctx*);
void shim_USER32_SetWindowTextW(X64Ctx*);
void shim_USER32_SetWindowsHookExW(X64Ctx*);
void shim_USER32_ShowWindow(X64Ctx*);
void shim_USER32_SystemParametersInfoA(X64Ctx*);
void shim_USER32_SystemParametersInfoW(X64Ctx*);
void shim_USER32_ToUnicode(X64Ctx*);
void shim_USER32_TranslateMessage(X64Ctx*);
void shim_USER32_UnhookWindowsHookEx(X64Ctx*);

// ---------------- 动态加载：伪造模块句柄 + 合成函数地址 -> 真垫片 ----------------
namespace {

struct DynApi { const char* name; RecompFn fn; };

uint64_t fake_module_handle() { return 0x7FFF00000000ULL; }


// 映射表：引擎/CRT 会 GetProcAddress 的常见入口
RecompFn lookup_api(const char* name) {
    static const DynApi kApis[] = {
        // 这四个早就实现了，但一直没进 lookup_api —— 于是 CRT 的
        // GetProcAddress("GetLocaleInfoEx"/"CompareStringEx"/"LCMapStringEx"/
        // "AreFileApisANSI") 全都返回 0（run 45985646254 的 unmapped 清单）。
        {"GetLocaleInfoEx", shim_KERNEL32_GetLocaleInfoEx},
        {"CompareStringEx", shim_KERNEL32_CompareStringEx},
        {"LCMapStringEx", shim_KERNEL32_LCMapStringEx},
        {"AreFileApisANSI", shim_KERNEL32_AreFileApisANSI},
        // steam_api64：GetProcAddress 也会问这三个名字（0x1409b5380 走的就是动态路径）
        {"SteamAPI_RestartAppIfNecessary", shim_STEAM_API64_SteamAPI_RestartAppIfNecessary},
        {"SteamInternal_SteamAPI_Init", shim_STEAM_API64_SteamInternal_SteamAPI_Init},
        {"SteamInternal_ContextInit", shim_STEAM_API64_SteamInternal_ContextInit},
        {"InitializeCriticalSectionAndSpinCount", shim_KERNEL32_InitializeCriticalSectionAndSpinCount},
        {"InitializeCriticalSection", shim_KERNEL32_InitializeCriticalSectionAndSpinCount},
        {"InitializeCriticalSectionEx", shim_KERNEL32_InitializeCriticalSectionAndSpinCount},
        {"EnterCriticalSection", shim_KERNEL32_EnterCriticalSection},
        {"LeaveCriticalSection", shim_KERNEL32_LeaveCriticalSection},
        {"DeleteCriticalSection", shim_KERNEL32_DeleteCriticalSection},
        {"TryEnterCriticalSection", shim_KERNEL32_TryEnterCriticalSection},
        {"GetSystemTimeAsFileTime", shim_KERNEL32_GetSystemTimeAsFileTime},
        {"GetSystemTimePreciseAsFileTime", shim_KERNEL32_GetSystemTimePreciseAsFileTime},
        {"QueryPerformanceCounter", shim_KERNEL32_QueryPerformanceCounter},
        {"QueryPerformanceFrequency", shim_KERNEL32_QueryPerformanceFrequency},
        {"GetCurrentThreadId", shim_KERNEL32_GetCurrentThreadId},
        {"GetCurrentProcessId", shim_KERNEL32_GetCurrentProcessId},
        {"GetCurrentThread", shim_KERNEL32_GetCurrentThread},
        {"GetCurrentProcess", shim_KERNEL32_GetCurrentProcess},
        // 条件变量 / SRW 锁：实现了但一直没登记（run 46023439342 卡死点的直接嫌疑）。
        // 现在 SleepConditionVariableSRW 按单线程语义立即超时返回，不再死等。
        {"SleepConditionVariableSRW", shim_KERNEL32_SleepConditionVariableSRW},
        {"WakeConditionVariable", shim_KERNEL32_WakeConditionVariable},
        {"WakeAllConditionVariable", shim_KERNEL32_WakeAllConditionVariable},
        {"InitializeSRWLock", shim_KERNEL32_InitializeSRWLock},
        {"InitializeConditionVariable", shim_KERNEL32_InitializeConditionVariable},
        {"AcquireSRWLockExclusive", shim_KERNEL32_AcquireSRWLockExclusive},
        {"AcquireSRWLockShared", shim_KERNEL32_AcquireSRWLockShared},
        {"ReleaseSRWLockExclusive", shim_KERNEL32_ReleaseSRWLockExclusive},
        {"ReleaseSRWLockShared", shim_KERNEL32_ReleaseSRWLockShared},
        {"TryAcquireSRWLockExclusive", shim_KERNEL32_TryAcquireSRWLockExclusive},
        {"TryAcquireSRWLockShared", shim_KERNEL32_TryAcquireSRWLockShared},
        {"Sleep", shim_KERNEL32_Sleep},
        {"SleepEx", shim_KERNEL32_Sleep},
        {"GetTickCount", shim_KERNEL32_GetTickCount},
        {"GetTickCount64", shim_KERNEL32_GetTickCount64},
        {"CreateEventW", shim_KERNEL32_CreateEventW},
        {"SetEvent", shim_KERNEL32_SetEvent},
        {"ResetEvent", shim_KERNEL32_ResetEvent},
        {"WaitForSingleObject", shim_KERNEL32_WaitForSingleObject},
        {"WaitForMultipleObjects", shim_KERNEL32_WaitForMultipleObjects},
        {"CreateThread", shim_KERNEL32_CreateThread},
        {"TlsAlloc", shim_KERNEL32_TlsAlloc},
        {"TlsFree", shim_KERNEL32_TlsFree},
        {"TlsGetValue", shim_KERNEL32_TlsGetValue},
        {"TlsSetValue", shim_KERNEL32_TlsSetValue},
        {"VirtualAlloc", shim_KERNEL32_VirtualAlloc},
        {"VirtualFree", shim_KERNEL32_VirtualFree},
        {"VirtualProtect", shim_KERNEL32_VirtualProtect},
        {"HeapAlloc", shim_KERNEL32_HeapAlloc},
        {"HeapFree", shim_KERNEL32_HeapFree},
        {"HeapReAlloc", shim_KERNEL32_HeapReAlloc},
        {"HeapSize", shim_KERNEL32_HeapSize},
        {"HeapValidate", shim_KERNEL32_HeapValidate},
        {"HeapCompact", shim_KERNEL32_HeapCompact},
        {"HeapCreate", shim_KERNEL32_HeapCreate},
        {"HeapDestroy", shim_KERNEL32_HeapDestroy},
        {"HeapSetInformation", shim_KERNEL32_HeapSetInformation},
        {"HeapQueryInformation", shim_KERNEL32_HeapQueryInformation},
        {"GetProcessHeap", shim_KERNEL32_GetProcessHeap},
        {"CloseHandle", shim_KERNEL32_CloseHandle},
        {"ReadFile", shim_KERNEL32_ReadFile},
        {"WriteFile", shim_KERNEL32_WriteFile},
        {"SetFilePointerEx", shim_KERNEL32_SetFilePointerEx},
        {"GetFileSizeEx", shim_KERNEL32_GetFileSizeEx},
        {"GetFileSize", shim_KERNEL32_GetFileSize},
        {"GetFileType", shim_KERNEL32_GetFileType},
        {"FlushFileBuffers", shim_KERNEL32_FlushFileBuffers},
        {"CreateFileW", shim_KERNEL32_CreateFileW},
        {"CreateFileA", shim_KERNEL32_CreateFileA},
        {"FindFirstFileExW", shim_KERNEL32_FindFirstFileExW},
        {"GetFileAttributesExW", shim_KERNEL32_GetFileAttributesExW},
        {"SetProcessDPIAware", shim_USER32_SetProcessDPIAware},
        {"SetProcessDpiAwarenessContext", shim_USER32_SetProcessDpiAwarenessContext},
        {"SetThreadDpiAwarenessContext", shim_USER32_SetThreadDpiAwarenessContext},
        {"GetThreadDpiAwarenessContext", shim_USER32_GetThreadDpiAwarenessContext},
        {"GetAwarenessFromDpiAwarenessContext", shim_USER32_GetAwarenessFromDpiAwarenessContext},
        {"AreDpiAwarenessContextsEqual", shim_USER32_AreDpiAwarenessContextsEqual},
        {"IsValidDpiAwarenessContext", shim_USER32_IsValidDpiAwarenessContext},
        {"RegisterTouchWindow", shim_USER32_RegisterTouchWindow},
        {"GetTouchInputInfo", shim_USER32_GetTouchInputInfo},
        {"CloseTouchInputHandle", shim_USER32_CloseTouchInputHandle},
        {"GetFullPathNameW", shim_KERNEL32_GetFullPathNameW},
        {"LocalAlloc", shim_KERNEL32_LocalAlloc},
        {"LocalFree", shim_KERNEL32_LocalFree},
        {"GetFileAttributesW", shim_KERNEL32_GetFileAttributesW},
        {"SetEndOfFile", shim_KERNEL32_SetEndOfFile},
        {"GetModuleHandleExW", shim_KERNEL32_GetModuleHandleExW},
        {"GetModuleHandleExA", shim_KERNEL32_GetModuleHandleExA},
        {"GetModuleHandleW", shim_KERNEL32_GetModuleHandleW},
        {"GetModuleHandleA", shim_KERNEL32_GetModuleHandleA},
        {"GetModuleFileNameW", shim_KERNEL32_GetModuleFileNameW},
        {"OutputDebugStringA", shim_KERNEL32_OutputDebugStringA},
        {"OutputDebugStringW", shim_KERNEL32_OutputDebugStringW},
        {"IsDebuggerPresent", shim_KERNEL32_IsDebuggerPresent},
        {"RaiseException", shim_KERNEL32_RaiseException},
        {"RtlUnwind", shim_KERNEL32_RtlUnwind},
        {"FlsAlloc", shim_KERNEL32_FlsAlloc},
        {"FlsFree", shim_KERNEL32_FlsFree},
        {"FlsGetValue", shim_KERNEL32_FlsGetValue},
        {"FlsSetValue", shim_KERNEL32_FlsSetValue},
        {"RtlCaptureContext", shim_KERNEL32_RtlCaptureContext},
        {"RtlLookupFunctionEntry", shim_KERNEL32_RtlLookupFunctionEntry},
        {"RtlVirtualUnwind", shim_KERNEL32_RtlVirtualUnwind},
        {"RtlPcToFileHeader", shim_KERNEL32_RtlPcToFileHeader},
        {"AppPolicyGetProcessTerminationMethod", shim_KERNEL32_AppPolicyGetProcessTerminationMethod},
        {"EncodePointer", shim_KERNEL32_EncodePointer},
        {"DecodePointer", shim_KERNEL32_DecodePointer},
        {"GetCommandLineA", shim_KERNEL32_GetCommandLineA},
        {"GetCommandLineW", shim_KERNEL32_GetCommandLineW},
        {"CommandLineToArgvW", shim_SHELL32_CommandLineToArgvW},
        {"GetEnvironmentStringsW", shim_KERNEL32_GetEnvironmentStringsW},
        {"FreeEnvironmentStringsW", shim_KERNEL32_FreeEnvironmentStringsW},
        {"GetStartupInfoW", shim_KERNEL32_GetStartupInfoW},
        {"IsProcessorFeaturePresent", shim_KERNEL32_IsProcessorFeaturePresent},
        {"GetStdHandle", shim_KERNEL32_GetStdHandle},
        {"GetFileType", shim_KERNEL32_GetFileType},
        {"GetSystemInfo", shim_KERNEL32_GetSystemInfo},
        {"InitializeSListHead", shim_KERNEL32_InitializeSListHead},
        {"SetUnhandledExceptionFilter", shim_KERNEL32_SetUnhandledExceptionFilter},
        {"UnhandledExceptionFilter", shim_KERNEL32_UnhandledExceptionFilter},
        {"IsProcessorFeaturePresent", shim_KERNEL32_IsProcessorFeaturePresent},
        {"ExitProcess", shim_KERNEL32_ExitProcess},
        {"GetLastError", shim_KERNEL32_GetLastError},
        {"SetLastError", shim_KERNEL32_SetLastError},
        {"SwitchToThread", shim_KERNEL32_SwitchToThread},
        {"SetThreadPriority", shim_KERNEL32_SetThreadPriority},
        {"GetACP", shim_KERNEL32_GetACP},
        {"SleepConditionVariableSRW", shim_KERNEL32_SleepConditionVariableSRW},
        {"SleepConditionVariableCS", shim_KERNEL32_SleepConditionVariableSRW},
        {"WakeConditionVariable", shim_KERNEL32_WakeConditionVariable},
        {"WakeAllConditionVariable", shim_KERNEL32_WakeAllConditionVariable},
        {"GetOEMCP", shim_KERNEL32_GetOEMCP},
        {"GetCPInfo", shim_KERNEL32_GetCPInfo},
        {"GetStringTypeW", shim_KERNEL32_GetStringTypeW},
        {"LCMapStringW", shim_KERNEL32_LCMapStringW},
        {"IsValidCodePage", shim_KERNEL32_IsValidCodePage},
        {"IsValidLocale", shim_KERNEL32_IsValidLocale},
        {"WideCharToMultiByte", shim_KERNEL32_WideCharToMultiByte},
        {"MultiByteToWideChar", shim_KERNEL32_MultiByteToWideChar},
        // 错误弹窗一族：SDL3 的 SDL_ShowSimpleMessageBox 优先走 TaskDialogIndirect，
        // 取不到才回落 MessageBoxW/A。三个名字都要登记，否则 SDL 只走自绘旧框。
        // 注意：9cde606 那次提交把这段定义连同登记一起删掉了（基于旧版文件打的补丁），
        // 这里按原样恢复。
        {"TaskDialogIndirect", shim_COMCTL32_TaskDialogIndirect},
        {"MessageBoxA", shim_USER32_MessageBoxA},
        {"MessageBoxW", shim_USER32_MessageBoxW},
        // ---- 像素格式 + 假 GL（引擎动态表要的 5 个 GDI32 + 27 个 gl*/wgl*）----
        {"ChoosePixelFormat", shim_GDI32_ChoosePixelFormat},
        {"SetPixelFormat", shim_GDI32_SetPixelFormat},
        {"GetPixelFormat", shim_GDI32_GetPixelFormat},
        {"DescribePixelFormat", shim_GDI32_DescribePixelFormat},
        {"SwapBuffers", shim_GDI32_SwapBuffers},
        {"wglCreateContext", shim_OPENGL32_wglCreateContext},
        {"wglCreateContextAttribsARB", shim_OPENGL32_wglCreateContextAttribsARB},
        {"wglMakeCurrent", shim_OPENGL32_wglMakeCurrent},
        {"wglDeleteContext", shim_OPENGL32_wglDeleteContext},
        {"wglGetCurrentContext", shim_OPENGL32_wglGetCurrentContext},
        {"wglGetCurrentDC", shim_OPENGL32_wglGetCurrentDC},
        {"wglSwapBuffers", shim_OPENGL32_wglSwapBuffers},
        {"wglSwapIntervalEXT", shim_OPENGL32_wglSwapIntervalEXT},
        {"wglGetProcAddress", shim_OPENGL32_wglGetProcAddress},
        {"wglChoosePixelFormatARB", shim_OPENGL32_wglChoosePixelFormatARB},
        {"wglGetPixelFormatAttribivARB", shim_OPENGL32_wglGetPixelFormatAttribivARB},
        {"wglGetPixelFormatAttribfvARB", shim_OPENGL32_wglGetPixelFormatAttribfvARB},
        {"glGetString", shim_OPENGL32_glGetString},
        {"glGetIntegerv", shim_OPENGL32_glGetIntegerv},
        {"glGenTextures", shim_OPENGL32_glGenTextures},
        {"glBindTexture", shim_OPENGL32_glBindTexture},
        {"glBlendFunc", shim_OPENGL32_glBlendFunc},
        {"glClear", shim_OPENGL32_glClear},
        {"glClearColor", shim_OPENGL32_glClearColor},
        {"glColorMask", shim_OPENGL32_glColorMask},
        {"glCopyTexSubImage2D", shim_OPENGL32_glCopyTexSubImage2D},
        {"glDeleteTextures", shim_OPENGL32_glDeleteTextures},
        {"glDepthMask", shim_OPENGL32_glDepthMask},
        {"glDisable", shim_OPENGL32_glDisable},
        {"glDrawArrays", shim_OPENGL32_glDrawArrays},
        {"glEnable", shim_OPENGL32_glEnable},
        {"glLineWidth", shim_OPENGL32_glLineWidth},
        {"glPixelStorei", shim_OPENGL32_glPixelStorei},
        {"glPointSize", shim_OPENGL32_glPointSize},
        {"glPolygonMode", shim_OPENGL32_glPolygonMode},
        {"glScissor", shim_OPENGL32_glScissor},
        {"glStencilFunc", shim_OPENGL32_glStencilFunc},
        {"glStencilMask", shim_OPENGL32_glStencilMask},
        {"glStencilOp", shim_OPENGL32_glStencilOp},
        {"glTexImage2D", shim_OPENGL32_glTexImage2D},
        {"glTexParameteri", shim_OPENGL32_glTexParameteri},
        {"glViewport", shim_OPENGL32_glViewport},
        // ---- 动态表剩余高频：绘制 / 输入 / 图标 / 注册表 / COM ----
        {"BeginPaint", shim_USER32_BeginPaint},
        {"EndPaint", shim_USER32_EndPaint},
        {"GetUpdateRect", shim_USER32_GetUpdateRect},
        {"InvalidateRect", shim_USER32_InvalidateRect},
        {"ValidateRect", shim_USER32_ValidateRect},
        {"FillRect", shim_USER32_FillRect},
        {"GetFocus", shim_USER32_GetFocus},
        {"SetFocus", shim_USER32_SetFocus},
        {"GetCursorPos", shim_USER32_GetCursorPos},
        {"SetTimer", shim_USER32_SetTimer},
        {"KillTimer", shim_USER32_KillTimer},
        {"GetQueueStatus", shim_USER32_GetQueueStatus},
        {"RegisterRawInputDevices", shim_USER32_RegisterRawInputDevices},
        {"GetRawInputData", shim_USER32_GetRawInputData},
        {"GetRawInputBuffer", shim_USER32_GetRawInputBuffer},
        {"LoadIconW", shim_USER32_LoadIconW},
        {"CreateIconIndirect", shim_USER32_CreateIconIndirect},
        {"DestroyIcon", shim_USER32_DestroyIcon},
        {"DestroyCursor", shim_USER32_DestroyCursor},
        {"TrackMouseEvent", shim_USER32_TrackMouseEvent},
        {"GetClassInfoExW", shim_USER32_GetClassInfoExW},
        {"UnregisterClassW", shim_USER32_UnregisterClassW},
        {"UnregisterClassA", shim_USER32_UnregisterClassA},
        {"RegisterClassExA", shim_USER32_RegisterClassExA},
        {"GetPropW", shim_USER32_GetPropW},
        {"SetPropW", shim_USER32_SetPropW},
        {"RemovePropW", shim_USER32_RemovePropW},
        {"GetDoubleClickTime", shim_USER32_GetDoubleClickTime},
        {"MapVirtualKeyW", shim_USER32_MapVirtualKeyW},
        {"MapVirtualKeyA", shim_USER32_MapVirtualKeyA},
        {"MonitorFromPoint", shim_USER32_MonitorFromPoint},
        {"SetRectEmpty", shim_USER32_SetRectEmpty},
        {"RegOpenKeyExW", shim_ADVAPI32_RegOpenKeyExW},
        {"RegQueryValueExW", shim_ADVAPI32_RegQueryValueExW},
        {"RegCloseKey", shim_ADVAPI32_RegCloseKey},
        {"CoInitializeEx", shim_OLE32_CoInitializeEx},
        {"OleInitialize", shim_OLE32_OleInitialize},
        {"CoUninitialize", shim_OLE32_CoUninitialize},
        {"OleUninitialize", shim_OLE32_OleUninitialize},
        // ---- 引擎自带动态 API 表（455 个名字）里「有强垫片但没登记」的 159 个 ----
        // 引擎不只用导入表，它还走自己的函数指针表：`jmp [.data 槽]` → 槽里是
        // 「{u16 id}{name}」描述符（0x140e3f000 起 910 项），解析失败就把 0 当函数调。
        // run 46055985114 的 `title="ERROR" content="Could not create window: "`
        // （SDL_GetError() 为空）就是这么来的：CreateWindowExW 在这里查到 0，
        // 引擎的建窗调用变成「返回 0」，而 SDL 侧根本没参与，所以没有错误串。
        // 这一批按「动态表 ∩ 强垫片 − 已登记」算出来，机械补齐。
        {"AddVectoredExceptionHandler", shim_KERNEL32_AddVectoredExceptionHandler},
        {"AdjustWindowRectEx", shim_USER32_AdjustWindowRectEx},
        {"AttachConsole", shim_KERNEL32_AttachConsole},
        {"CallWindowProcW", shim_USER32_CallWindowProcW},
        {"ChangeDisplaySettingsExW", shim_USER32_ChangeDisplaySettingsExW},
        {"ClientToScreen", shim_USER32_ClientToScreen},
        {"ClipCursor", shim_USER32_ClipCursor},
        {"CloseClipboard", shim_USER32_CloseClipboard},
        {"CloseThreadpoolWork", shim_KERNEL32_CloseThreadpoolWork},
        {"CompareStringA", shim_KERNEL32_CompareStringA},
        {"CompareStringW", shim_KERNEL32_CompareStringW},
        {"CreateCompatibleDC", shim_GDI32_CreateCompatibleDC},
        {"CreateDCW", shim_GDI32_CreateDCW},
        {"CreateDCA", shim_GDI32_CreateDCA},
        {"CreateDirectoryW", shim_KERNEL32_CreateDirectoryW},
        {"CreateFontIndirectW", shim_GDI32_CreateFontIndirectW},
        {"CreateIconFromResource", shim_USER32_CreateIconFromResource},
        {"CreateMutexW", shim_KERNEL32_CreateMutexW},
        {"CreateSemaphoreW", shim_KERNEL32_CreateSemaphoreW},
        {"CreateThreadpoolWork", shim_KERNEL32_CreateThreadpoolWork},
        {"CreateWindowExA", shim_USER32_CreateWindowExA},
        {"CreateWindowExW", shim_USER32_CreateWindowExW},
        {"DefWindowProcW", shim_USER32_DefWindowProcW},
        {"DeleteDC", shim_GDI32_DeleteDC},
        {"DeleteFileW", shim_KERNEL32_DeleteFileW},
        {"DeleteObject", shim_GDI32_DeleteObject},
        {"DestroyWindow", shim_USER32_DestroyWindow},
        {"DeviceIoControl", shim_KERNEL32_DeviceIoControl},
        {"DialogBoxIndirectParamW", shim_USER32_DialogBoxIndirectParamW},
        {"DispatchMessageW", shim_USER32_DispatchMessageW},
        {"DrawTextW", shim_USER32_DrawTextW},
        {"EmptyClipboard", shim_USER32_EmptyClipboard},
        {"EnableWindow", shim_USER32_EnableWindow},
        {"EndDialog", shim_USER32_EndDialog},
        {"EnumClipboardFormats", shim_USER32_EnumClipboardFormats},
        {"EnumDisplayDevicesW", shim_USER32_EnumDisplayDevicesW},
        {"EnumDisplayMonitors", shim_USER32_EnumDisplayMonitors},
        {"EnumDisplaySettingsW", shim_USER32_EnumDisplaySettingsW},
        {"EnumSystemLocalesW", shim_KERNEL32_EnumSystemLocalesW},
        {"ExitThread", shim_KERNEL32_ExitThread},
        {"FindClose", shim_KERNEL32_FindClose},
        {"FindFirstFileW", shim_KERNEL32_FindFirstFileW},
        {"FindNextFileW", shim_KERNEL32_FindNextFileW},
        {"FlashWindowEx", shim_USER32_FlashWindowEx},
        {"FormatMessageA", shim_KERNEL32_FormatMessageA},
        {"FormatMessageW", shim_KERNEL32_FormatMessageW},
        {"FreeLibrary", shim_KERNEL32_FreeLibrary},
        {"FreeLibraryWhenCallbackReturns", shim_KERNEL32_FreeLibraryWhenCallbackReturns},
        {"GetAsyncKeyState", shim_USER32_GetAsyncKeyState},
        {"GetClientRect", shim_USER32_GetClientRect},
        {"GetClipCursor", shim_USER32_GetClipCursor},
        {"GetClipboardData", shim_USER32_GetClipboardData},
        {"GetClipboardSequenceNumber", shim_USER32_GetClipboardSequenceNumber},
        {"GetConsoleMode", shim_KERNEL32_GetConsoleMode},
        {"GetConsoleOutputCP", shim_KERNEL32_GetConsoleOutputCP},
        {"GetCurrentDirectoryW", shim_KERNEL32_GetCurrentDirectoryW},
        {"GetDC", shim_USER32_GetDC},
        {"GetDesktopWindow", shim_USER32_GetDesktopWindow},
        {"GetDeviceCaps", shim_GDI32_GetDeviceCaps},
        {"GetDlgItem", shim_USER32_GetDlgItem},
        {"GetEnvironmentVariableA", shim_KERNEL32_GetEnvironmentVariableA},
        {"GetExitCodeThread", shim_KERNEL32_GetExitCodeThread},
        {"GetForegroundWindow", shim_USER32_GetForegroundWindow},
        {"GetKeyState", shim_USER32_GetKeyState},
        {"GetKeyboardLayout", shim_USER32_GetKeyboardLayout},
        {"GetKeyboardState", shim_USER32_GetKeyboardState},
        {"GetLocaleInfoA", shim_KERNEL32_GetLocaleInfoA},
        {"GetLocaleInfoW", shim_KERNEL32_GetLocaleInfoW},
        {"GetLogicalDrives", shim_KERNEL32_GetLogicalDrives},
        {"GetMessageExtraInfo", shim_USER32_GetMessageExtraInfo},
        {"GetMessagePos", shim_USER32_GetMessagePos},
        {"GetMessageTime", shim_USER32_GetMessageTime},
        {"GetMessageW", shim_USER32_GetMessageW},
        {"GetModuleFileNameA", shim_KERNEL32_GetModuleFileNameA},
        {"GetMonitorInfoW", shim_USER32_GetMonitorInfoW},
        {"GetNativeSystemInfo", shim_KERNEL32_GetNativeSystemInfo},
        {"GetProcAddress", shim_KERNEL32_GetProcAddress},
        {"GetRawInputDeviceInfoA", shim_USER32_GetRawInputDeviceInfoA},
        {"GetRawInputDeviceList", shim_USER32_GetRawInputDeviceList},
        {"GetSystemMetrics", shim_USER32_GetSystemMetrics},
        {"GetSystemTime", shim_KERNEL32_GetSystemTime},
        {"GetTextExtentPoint32A", shim_GDI32_GetTextExtentPoint32A},
        {"GetTextMetricsW", shim_GDI32_GetTextMetricsW},
        {"GetTimeZoneInformation", shim_KERNEL32_GetTimeZoneInformation},
        {"GetUserDefaultLCID", shim_KERNEL32_GetUserDefaultLCID},
        {"GetWindowLongPtrW", shim_USER32_GetWindowLongPtrW},
        {"GetWindowLongW", shim_USER32_GetWindowLongW},
        {"GetWindowPlacement", shim_USER32_GetWindowPlacement},
        {"GetWindowRect", shim_USER32_GetWindowRect},
        {"GetWindowTextLengthW", shim_USER32_GetWindowTextLengthW},
        {"GetWindowTextW", shim_USER32_GetWindowTextW},
        {"GetWindowThreadProcessId", shim_USER32_GetWindowThreadProcessId},
        {"GlobalAlloc", shim_KERNEL32_GlobalAlloc},
        {"GlobalFree", shim_KERNEL32_GlobalFree},
        {"GlobalLock", shim_KERNEL32_GlobalLock},
        {"GlobalMemoryStatusEx", shim_KERNEL32_GlobalMemoryStatusEx},
        {"GlobalSize", shim_KERNEL32_GlobalSize},
        {"GlobalUnlock", shim_KERNEL32_GlobalUnlock},
        {"InitOnceBeginInitialize", shim_KERNEL32_InitOnceBeginInitialize},
        {"InitOnceComplete", shim_KERNEL32_InitOnceComplete},
        {"IntersectRect", shim_USER32_IntersectRect},
        {"IsClipboardFormatAvailable", shim_USER32_IsClipboardFormatAvailable},
        {"IsWindow", shim_USER32_IsWindow},
        {"IsWow64Process", shim_KERNEL32_IsWow64Process},
        {"LoadCursorW", shim_USER32_LoadCursorW},
        {"LoadLibraryA", shim_KERNEL32_LoadLibraryA},
        {"LoadLibraryExW", shim_KERNEL32_LoadLibraryExW},
        {"LoadLibraryW", shim_KERNEL32_LoadLibraryW},
        {"MonitorFromWindow", shim_USER32_MonitorFromWindow},
        {"MulDiv", shim_KERNEL32_MulDiv},
        {"OpenClipboard", shim_USER32_OpenClipboard},
        {"PeekMessageW", shim_USER32_PeekMessageW},
        {"PostMessageW", shim_USER32_PostMessageW},
        {"PostThreadMessageW", shim_USER32_PostThreadMessageW},
        {"PtInRect", shim_USER32_PtInRect},
        {"ReadConsoleW", shim_KERNEL32_ReadConsoleW},
        {"RegisterClassExW", shim_USER32_RegisterClassExW},
        {"RegisterClassW", shim_USER32_RegisterClassW},
        {"RegisterWindowMessageA", shim_USER32_RegisterWindowMessageA},
        {"ReleaseCapture", shim_USER32_ReleaseCapture},
        {"ReleaseDC", shim_USER32_ReleaseDC},
        {"ReleaseSemaphore", shim_KERNEL32_ReleaseSemaphore},
        {"RemoveVectoredExceptionHandler", shim_KERNEL32_RemoveVectoredExceptionHandler},
        {"RtlCaptureStackBackTrace", shim_KERNEL32_RtlCaptureStackBackTrace},
        {"RtlUnwindEx", shim_KERNEL32_RtlUnwindEx},
        {"SHGetFolderPathW", shim_SHELL32_SHGetFolderPathW},
        {"ScreenToClient", shim_USER32_ScreenToClient},
        {"SelectObject", shim_GDI32_SelectObject},
        {"SendMessageA", shim_USER32_SendMessageA},
        {"SendMessageW", shim_USER32_SendMessageW},
        {"SetActiveWindow", shim_USER32_SetActiveWindow},
        {"SetCapture", shim_USER32_SetCapture},
        {"SetClipboardData", shim_USER32_SetClipboardData},
        {"SetConsoleCtrlHandler", shim_KERNEL32_SetConsoleCtrlHandler},
        {"SetCursor", shim_USER32_SetCursor},
        {"SetCursorPos", shim_USER32_SetCursorPos},
        {"SetEnvironmentVariableA", shim_KERNEL32_SetEnvironmentVariableA},
        {"SetEnvironmentVariableW", shim_KERNEL32_SetEnvironmentVariableW},
        {"SetErrorMode", shim_KERNEL32_SetErrorMode},
        {"SetForegroundWindow", shim_USER32_SetForegroundWindow},
        {"SetLayeredWindowAttributes", shim_USER32_SetLayeredWindowAttributes},
        {"SetParent", shim_USER32_SetParent},
        {"SetStdHandle", shim_KERNEL32_SetStdHandle},
        {"SetThreadExecutionState", shim_KERNEL32_SetThreadExecutionState},
        {"SetWindowLongPtrW", shim_USER32_SetWindowLongPtrW},
        {"SetWindowLongW", shim_USER32_SetWindowLongW},
        {"SetWindowPos", shim_USER32_SetWindowPos},
        {"SetWindowRgn", shim_USER32_SetWindowRgn},
        {"SetWindowTextW", shim_USER32_SetWindowTextW},
        {"SetWindowsHookExW", shim_USER32_SetWindowsHookExW},
        {"ShowWindow", shim_USER32_ShowWindow},
        {"SubmitThreadpoolWork", shim_KERNEL32_SubmitThreadpoolWork},
        {"SystemParametersInfoA", shim_USER32_SystemParametersInfoA},
        {"SystemParametersInfoW", shim_USER32_SystemParametersInfoW},
        {"TerminateProcess", shim_KERNEL32_TerminateProcess},
        {"ToUnicode", shim_USER32_ToUnicode},
        {"TranslateMessage", shim_USER32_TranslateMessage},
        {"UnhookWindowsHookEx", shim_USER32_UnhookWindowsHookEx},
        {"WaitForSingleObjectEx", shim_KERNEL32_WaitForSingleObjectEx},
        {"WaitForThreadpoolWorkCallbacks", shim_KERNEL32_WaitForThreadpoolWorkCallbacks},
        {"WriteConsoleW", shim_KERNEL32_WriteConsoleW},
    };
    for (const auto& e : kApis)
        if (std::strcmp(e.name, name) == 0) return e.fn;
    return nullptr;
}

}  // namespace

// 运行时兜底桥：dispatch_indirect 遇到「未绑定的 IAT 槽」时，把槽里的
// IMAGE_IMPORT_BY_NAME 解成 API 名，再经这里直接执行对应垫片。
// 返回 1 表示已执行（调用方负责弹掉模拟返回地址），0 表示没有实现。
extern "C" int mew_call_api_by_name(const char* name, X64Ctx* ctx) {
    if (!name || !ctx) return 0;
    RecompFn fn = lookup_api(name);
    if (!fn) {
        const char* bang = std::strchr(name, '!');
        if (bang) fn = lookup_api(bang + 1);
    }
    if (!fn) return 0;
    fn(ctx);
    return 1;
}

// 合成地址反查表（0x5000000xx 是哪个 API）+ 追踪开关。
// 打开后，每一次经合成地址进入的垫片都会打印 (名称, rcx, rdx, r8 -> rax)。
std::unordered_map<uint64_t, std::string>& g_synth_names() {
    static std::unordered_map<uint64_t, std::string> m;
    return m;
}
bool& g_api_trace() { static bool on = false; return on; }

void mew_api_trace_impl(uint64_t va, X64Ctx* c, int post) {
    const std::string* nm = nullptr;
    auto& m = g_synth_names();
    auto it = m.find(va);
    if (it != m.end()) nm = &it->second;
    if (!nm) return;
    bool fls = nm->rfind("Fls", 0) == 0;
    if (!post) {
        if (!fls && !g_api_trace()) return;
        std::fprintf(stderr, "[api] -> %s(rcx=0x%llx rdx=0x%llx r8=0x%llx)\n",
                     nm->c_str(), (unsigned long long)c->rcx,
                     (unsigned long long)c->rdx, (unsigned long long)c->r8);
    } else {
        if (!fls && !g_api_trace()) return;
        std::fprintf(stderr, "[api] <- %s rax=0x%llx\n", nm->c_str(),
                     (unsigned long long)c->rax);
    }
}

struct ApiTraceInstaller {
    ApiTraceInstaller() { api_trace_hook() = &mew_api_trace_impl; }
};
ApiTraceInstaller g_api_trace_installer;

uint64_t shim_KERNEL32_LookupSynthetic(const char* name) {
    static std::unordered_map<std::string, uint64_t> cache;
    auto it = cache.find(name);
    if (it != cache.end()) return it->second;
    RecompFn fn = lookup_api(name);
    if (!fn) return 0;
    uint64_t va = 0x500000000ULL + 0x10 * (uint64_t)(cache.size() + 1);
    register_recomp_fn(va, fn);
    cache[name] = va;
    g_synth_names()[va] = name;
    return va;
}

void shim_KERNEL32_LoadLibraryW(X64Ctx* c) {
    std::fprintf(stderr, "[shim] LoadLibraryW(\"%s\") -> fake module\n", guest_wstr(c, arg0(c)).c_str());
    ret0(c, fake_module_handle());
}
void shim_KERNEL32_LoadLibraryA(X64Ctx* c) {
    const char* p = (const char*)guest_ptr_from_ctx(c, arg0(c));
    std::fprintf(stderr, "[shim] LoadLibraryA(\"%s\") -> fake module\n", p ? p : "");
    ret0(c, fake_module_handle());
}
void shim_KERNEL32_LoadLibraryExW(X64Ctx* c) {
    std::fprintf(stderr, "[shim] LoadLibraryExW(\"%s\") -> fake module\n", guest_wstr(c, arg0(c)).c_str());
    ret0(c, fake_module_handle());
}
void shim_KERNEL32_GetProcAddress(X64Ctx* c) {
    // 注意：GetProcAddress 第二个参数是窄字符 LPCSTR
    std::string name;
    if (arg1(c) && guest_mapped(arg1(c), 1)) {
        const char* p = (const char*)guest_ptr_from_ctx(c, arg1(c));
        name = p;
    }
    uint64_t va = shim_KERNEL32_LookupSynthetic(name.c_str());
    std::fprintf(stderr, "[shim] GetProcAddress(\"%s\") -> 0x%llx%s\n", name.c_str(),
                 (unsigned long long)va, va ? "" : " (unmapped)");
    ret0(c, va);
}
void shim_KERNEL32_FreeLibrary(X64Ctx* c) { ret0(c, 1); }

// ---------------- FLs(纤程局部存储) / 异常上下文 / 其它启动 API ----------------
void shim_KERNEL32_FlsAlloc(X64Ctx* c) {
    std::lock_guard<std::mutex> lk(g_tls_mu);
    for (int i = 1; i < 1024; ++i) if (!g_tls_used[i]) {   // 从 1 起：0 留给"未分配"
        g_tls_used[i] = true;
        std::fprintf(stderr, "[shim] FlsAlloc()=%d caller=0x%llx\n", i, (unsigned long long)cur_fn_va());
        ret0(c, i);
        return;
    }
    std::fprintf(stderr, "[shim] FlsAlloc()=FLS_OUT_OF_INDEXES\n");
    ret0(c, (uint64_t)-1);
}
void shim_KERNEL32_FlsFree(X64Ctx* c) {
    uint32_t i = (uint32_t)arg0(c);
    static int logged = 0;
    if (logged++ < 30)
        std::fprintf(stderr, "[shim] FlsFree(%u) caller=0x%llx\n", i, (unsigned long long)cur_fn_va());
    if (i < 1024) g_tls_used[i] = false;
    ret0(c, 1);
}
void shim_KERNEL32_FlsGetValue(X64Ctx* c) {
    uint32_t i = (uint32_t)arg0(c);
    uint64_t v = (i < 1024) ? g_tls[i] : 0;
    static int logged = 0;
    if (logged++ < 10) std::fprintf(stderr, "[shim] FlsGetValue(%u)=0x%llx\n", i, (unsigned long long)v);
    ret0(c, v);
}
void shim_KERNEL32_FlsSetValue(X64Ctx* c) {
    uint32_t i = (uint32_t)arg0(c);
    static int logged = 0;
    if (logged++ < 20)
        std::fprintf(stderr, "[shim] FlsSetValue(%u, 0x%llx) caller=0x%llx\n", i,
                     (unsigned long long)arg1(c), (unsigned long long)cur_fn_va());
    g_api_trace() = true;   // 从这里开始逐 API 打印，直到 fastfail 现场
    if (i < 1024) g_tls[i] = arg1(c);
    ret0(c, 1);
}

void shim_KERNEL32_RtlCaptureContext(X64Ctx* c) {
    uint64_t dst = arg0(c);
    if (!dst) { ret0(c, 0); return; }
    std::memset(reinterpret_cast<void*>(uintptr_t(dst)), 0, seh::kContextSize);
    seh::Ctx64 w;
    seh::ctx_to_win(c, &w);
    w.Rip = 0;
    std::memcpy(&w.Rip, reinterpret_cast<const void*>(uintptr_t(c->rsp)), 8);  // 返回地址
    w.Rsp = c->rsp + 8;
    std::memcpy(reinterpret_cast<void*>(uintptr_t(dst)), &w, sizeof(w));
    ret0(c, 0);
}

void shim_KERNEL32_RtlLookupFunctionEntry(X64Ctx* c) {
    seh::ensure_ready();
    uint64_t pc = arg0(c);
    seh::FuncEntry fe;
    if (!seh::lookup_function_entry(pc, &fe)) { ret0(c, 0); return; }
    if (arg1(c)) std::memcpy(reinterpret_cast<void*>(uintptr_t(arg1(c))), &seh::image().base, 8);
    ret0(c, fe.entry_va);
}

void shim_KERNEL32_RtlVirtualUnwind(X64Ctx* c) {
    // (HandlerType, ImageBase, ControlPc, FunctionEntry, ContextRecord, HandlerData)
    const uint64_t control_pc = arg2(c);
    const uint64_t context_va = arg4(c);
    const uint64_t handler_data = arg5(c);
    seh::ensure_ready();
    if (!context_va) { ret0(c, 0); return; }
    seh::Ctx64 w;
    std::memcpy(&w, reinterpret_cast<const void*>(uintptr_t(context_va)), sizeof(w));
    uint64_t handler = 0, estab = 0;
    seh::virtual_unwind(control_pc, &w, &handler, &estab, false);
    std::memcpy(reinterpret_cast<void*>(uintptr_t(context_va)), &w, sizeof(w));
    if (handler_data) std::memcpy(reinterpret_cast<void*>(uintptr_t(handler_data)), &estab, 8);
    ret0(c, handler);
}

void shim_KERNEL32_RtlUnwindEx(X64Ctx* c) {
    // (TargetFrame, TargetIp, ExceptionRecord, ReturnValue, ContextRecord, HistoryTable)
    const uint64_t target_frame = arg0(c);
    const uint64_t target_ip = arg1(c);
    std::fprintf(stderr, "[shim] RtlUnwindEx(frame=0x%llx ip=0x%llx)\n",
                 (unsigned long long)target_frame, (unsigned long long)target_ip);
    if (target_ip && seh::seh_dispatch_enabled()) {
        // 和 RtlUnwind 一样要跑第二阶段：MSVC 的 C++ EH（__CxxFrameHandler3）
        // 多半走的是 RtlUnwindEx 而不是 RtlUnwind，这里不接就等于 __finally 依旧不跑。
        const uint64_t rec = arg2(c) ? arg2(c) : seh::last_record_va();
        seh::unwind_phase2(c, target_frame, target_ip, rec);
        seh::Ctx64 w;
        seh::ctx_to_win(c, &w);
        w.Rsp = target_frame;
        w.Rax = arg3(c);
        seh::resume_at(target_ip, w);
    }
    ret0(c, 0);
}
void shim_KERNEL32_RtlPcToFileHeader(X64Ctx* c) { ret0(c, 0x140000000ULL); }
void shim_KERNEL32_TerminateProcess(X64Ctx* c) {
    std::fprintf(stderr, "[shim] TerminateProcess(code=%u)\n", (unsigned)arg1(c));
    std::exit((int)arg1(c));
}
void shim_KERNEL32_GetModuleFileNameA(X64Ctx* c) { ret0(c, 0); }
void shim_KERNEL32_VirtualQuery(X64Ctx* c) { ret0(c, 0); }
void shim_KERNEL32_GetProcessTimes(X64Ctx* c) { ret0(c, 1); }
void shim_KERNEL32_QueryFullProcessImageNameW(X64Ctx* c) { ret0(c, 0); }
void shim_KERNEL32_GetFileInformationByHandle(X64Ctx* c) { ret0(c, 1); }
void shim_KERNEL32_DeviceIoControl(X64Ctx* c) { ret0(c, 0); }
void shim_KERNEL32_GetVolumeInformationW(X64Ctx* c) { ret0(c, 0); }
void shim_KERNEL32_GetDriveTypeW(X64Ctx* c) { ret0(c, 2); }

// ---------------- CRT P0：必须返回有效值的 9 个 API ----------------
namespace {
uint64_t g_cmdline_a = 0;
uint64_t g_cmdline_w = 0;
uint64_t g_env_w = 0;
}

void shim_KERNEL32_GetCommandLineA(X64Ctx* c) {
    if (!g_cmdline_a) {
        g_cmdline_a = guest_alloc(c, 64);
        std::memcpy(guest_ptr_from_ctx(c, g_cmdline_a), "Mewgenics.exe", 14);
    }
    ret0(c, g_cmdline_a);
}

void shim_KERNEL32_GetCommandLineW(X64Ctx* c) {
    if (!g_cmdline_w) {
        g_cmdline_w = guest_alloc(c, 128);
        uint16_t* p = (uint16_t*)guest_ptr_from_ctx(c, g_cmdline_w);
        const char* s = "Mewgenics.exe";
        size_t i = 0;
        for (; s[i]; ++i) p[i] = (uint16_t)s[i];
        p[i] = 0;
    }
    ret0(c, g_cmdline_w);
}

// CommandLineToArgvW(lpCmdLine, pNumArgs) —— 之前是 UNIMPL（返回 0）。
// 这个 API 由 shell32 导出，但我们的垫片表只按函数名索引，所以放这里即可。
// 它的返回是**宽字符指针数组**，调用方一般拿着 argv[0] 当 exe 路径用；
// 返回 0 的话上层可能直接解引用空指针，或者把命令行解析成 0 个参数。
// 这里和 GetCommandLineW 保持同一口径：1 个参数，argv[0] = "Mewgenics.exe"。
void shim_SHELL32_CommandLineToArgvW(X64Ctx* c) {
    uint64_t nargs_out = arg1(c);
    uint64_t wbuf = guest_alloc(c, 64);
    if (!wbuf) { if (nargs_out) mem_write<int32_t>(c, nargs_out, 0); ret0(c, 0); return; }
    {
        uint16_t* p = (uint16_t*)guest_ptr_from_ctx(c, wbuf);
        const char* s = "Mewgenics.exe";
        size_t i = 0;
        for (; s[i]; ++i) p[i] = (uint16_t)s[i];
        p[i] = 0;
    }
    uint64_t argv = guest_alloc(c, 16);
    if (!argv) { if (nargs_out) mem_write<int32_t>(c, nargs_out, 0); ret0(c, 0); return; }
    mem_write<uint64_t>(c, argv, wbuf);
    mem_write<uint64_t>(c, argv + 8, 0);
    if (nargs_out) mem_write<int32_t>(c, nargs_out, 1);
    std::fprintf(stderr, "[shim] CommandLineToArgvW -> 1 arg (argv=0x%llx)\n",
                 (unsigned long long)argv);
    ret0(c, argv);
}

void shim_KERNEL32_GetEnvironmentStringsW(X64Ctx* c) {
    if (!g_env_w) {
        g_env_w = guest_alloc(c, 256);
        uint16_t* p = (uint16_t*)guest_ptr_from_ctx(c, g_env_w);
        std::memset(p, 0, 256);
        const char* s = "PATH=C:\\";
        size_t i = 0;
        for (; s[i]; ++i) p[i] = (uint16_t)s[i];
        p[i] = 0;      // 第一个字符串结束
        p[i + 1] = 0;  // 块结束（双 NUL）
    }
    ret0(c, g_env_w);
}

void shim_KERNEL32_GetStartupInfoW(X64Ctx* c) {
    MEW_TRACE_API(c, "KERNEL32!GetStartupInfoW");
    if (arg0(c)) {
        uint8_t* p = (uint8_t*)guest_ptr_from_ctx(c, arg0(c));
        std::memset(p, 0, 104);
        *(uint32_t*)(p + 0) = 104;  // cb = sizeof(STARTUPINFOW)
    }
    ret0(c, 0);
}

void shim_KERNEL32_EncodePointer(X64Ctx* c) { ret0(c, arg0(c)); }
void shim_KERNEL32_DecodePointer(X64Ctx* c) { ret0(c, arg0(c)); }
void shim_KERNEL32_EncodeSystemPointer(X64Ctx* c) { ret0(c, arg0(c)); }
void shim_KERNEL32_DecodeSystemPointer(X64Ctx* c) { ret0(c, arg0(c)); }

void shim_KERNEL32_AppPolicyGetProcessTerminationMethod(X64Ctx* c) {
    if (arg1(c)) mem_write<uint32_t>(c, arg1(c), 0);  // 0 = ExitProcess
    ret0(c, 0);  // ERROR_SUCCESS
}

void shim_KERNEL32_IsProcessorFeaturePresent(X64Ctx* c) {
    uint32_t f = (uint32_t)arg0(c);
    // 6=SSE, 10=SSE2, 23=FASTFAIL ; 这些必须为 1 否则 CRT 直接 __fastfail
    if (f == 6 || f == 10 || f == 23 || f == 12 || f == 13) { ret0(c, 1); return; }
    ret0(c, 0);
}

void shim_KERNEL32_GetStdHandle(X64Ctx* c) {
    uint32_t n = (uint32_t)arg0(c);
    if (n == (uint32_t)-10) { ret0(c, 0x1000); return; }
    if (n == (uint32_t)-11) { ret0(c, 0x1001); return; }
    if (n == (uint32_t)-12) { ret0(c, 0x1002); return; }
    ret0(c, (uint64_t)-1);
}

void shim_KERNEL32_GetFileType(X64Ctx* c) {
    uint64_t h = arg0(c);
    if (h == 0x1000 || h == 0x1001 || h == 0x1002) { ret0(c, 2); return; }  // FILE_TYPE_CHAR
    ret0(c, 0);
}

// ---------------- 归属补充 ----------------
void shim_KERNEL32_GetModuleHandleExW(X64Ctx* c) {
    if (arg2(c)) mem_write<uint64_t>(c, arg2(c), 0x140000000ULL);
    ret0(c, 1);
}
void shim_KERNEL32_GetModuleHandleExA(X64Ctx* c) {
    if (arg2(c)) mem_write<uint64_t>(c, arg2(c), 0x140000000ULL);
    ret0(c, 1);
}

// ---------------- 被误删的强定义（补回，避免弱占位顶替） ----------------
void shim_KERNEL32_ExitProcess(X64Ctx* c) {
    std::fprintf(stderr, "[shim] ExitProcess(%u)\n", (unsigned) arg0(c));
    call_trace().dump("ExitProcess");
    // 真线程下不能用 std::exit：它会去析构静态对象（计数表/互斥量），
    // 而 worker 线程此刻还在调 WakeAllConditionVariable -> mew_api_hit，
    // 于是崩在 std::map 插入里（run 46068371903：
    // [CRASH] signal=11 fault=0x0，栈 _Rb_tree_decrement <- std::map::operator[] <- mew_api_hit）。
    // 正确收尾：① 先关计数闸门，worker 之后直接返回不再插入；
    //           ② 等一小会让已经在锁里的插入跑完；
    //           ③ 把 UNIMPL / API 两张表打出来（这是整轮唯一的出口，不能丢）；
    //           ④ _exit 直接终止宿主进程，绕开所有静态析构。
    mew_api_counting().store(false, std::memory_order_relaxed);
    usleep(50000);
    mew_unimpl_dump("exitprocess");
    std::fflush(stderr);
    _exit((int)(uint32_t)arg0(c));
}

void shim_KERNEL32_InitializeCriticalSectionAndSpinCount(X64Ctx* c) {
    pthread_mutex_t* m = new pthread_mutex_t;
    pthread_mutex_init(m, nullptr);
    if (arg0(c)) mem_write<uint64_t>(c, arg0(c), (uint64_t)((int64_t)(uintptr_t)m - c->mem_bias));
    ret0(c, 1);
}

// ---- P0-B：MSVC C++ 异常飞行记录器 --------------------------------------
// 0xE06D7363 = MSVC C++ 异常。RaiseException 的参数里已经带了
// magic / pExceptionObject / pThrowInfo / ImageBase，但旧日志只打了三个裸指针，
// 看不出「抛的是哪个类、what() 是什么」，5 次异常里哪一次打死 main 就无从判断。
// 这里按 x64 RTTI 布局把类型名和 what() 解出来（结构见 MSVC CRT 的 ThrowInfo）。
namespace {
struct MsvcThrowInfo {
    uint32_t attributes, pmfnUnwind, pForwardCompat, pCatchableTypeArray;
};
struct MsvcCatchableTypeArray { int32_t n; uint32_t rva[1]; };
struct MsvcCatchableType {
    uint32_t properties, pType;
    int32_t mdisp, pdisp, vdisp, sizeOrOffset;
    uint32_t copyFunction;
};

std::string read_cstr(X64Ctx* c, uint64_t va, size_t cap = 96) {
    std::string out;
    if (!va || !guest_mapped(va, 1)) return out;
    const char* p = (const char*)guest_ptr_from_ctx(c, va);
    for (size_t i = 0; i < cap && p && p[i]; ++i) out.push_back(p[i]);
    return out;
}

void dump_cxx_throw(X64Ctx* c, const uint64_t* p, uint32_t n) {
    static int logged = 0;
    if (logged++ >= 8) return;
    const uint64_t obj = p[1], ti = p[2];
    const uint64_t base = (n >= 4 && p[3]) ? p[3] : 0;
    std::string type = "<unknown>";
    if (guest_mapped(ti, sizeof(MsvcThrowInfo))) {
        const MsvcThrowInfo* ti_p = (const MsvcThrowInfo*)guest_ptr_from_ctx(c, ti);
        const uint64_t cta_va = base + ti_p->pCatchableTypeArray;
        if (guest_mapped(cta_va, sizeof(MsvcCatchableTypeArray))) {
            const MsvcCatchableTypeArray* cta = (const MsvcCatchableTypeArray*)guest_ptr_from_ctx(c, cta_va);
            if (cta->n > 0) {
                const uint64_t ct_va = base + cta->rva[0];
                if (guest_mapped(ct_va, sizeof(MsvcCatchableType))) {
                    const MsvcCatchableType* ct = (const MsvcCatchableType*)guest_ptr_from_ctx(c, ct_va);
                    const uint64_t td_va = base + ct->pType;
                    // TypeDescriptor: 前 16 字节两个指针，随后是修饰名
                    if (guest_mapped(td_va + 16, 1)) {
                        std::string nm = read_cstr(c, td_va + 16);
                        if (!nm.empty()) type = nm;
                    }
                }
            }
        }
    }
    std::string what;
    if (guest_mapped(obj + 8, 8)) {
        const uint64_t w = mem_read<uint64_t>(c, obj + 8);   // std::exception::_What
        what = read_cstr(c, w, 120);
    }
    std::fprintf(stderr, "[cxx-eh] #%d type=%s what=\"%.120s\" obj=0x%llx ti=0x%llx base=0x%llx\n",
                 logged, type.c_str(), what.empty() ? "<n/a>" : what.c_str(),
                 (unsigned long long)obj, (unsigned long long)ti, (unsigned long long)base);
}
}  // namespace

void shim_KERNEL32_RaiseException(X64Ctx* c) {
    // RaiseException(Code, Flags, NumberParameters, lpExceptionInformation)
    const uint32_t code = (uint32_t)arg0(c);
    const uint32_t flags = (uint32_t)arg1(c);
    const uint32_t nparams = (uint32_t)arg2(c);
    {
        const uint64_t p0 = arg3(c) ? *reinterpret_cast<const uint64_t*>((uintptr_t)arg3(c)) : 0;
        const uint64_t p1 = arg3(c) ? *reinterpret_cast<const uint64_t*>((uintptr_t)arg3(c) + 8) : 0;
        const uint64_t p2 = arg3(c) ? *reinterpret_cast<const uint64_t*>((uintptr_t)arg3(c) + 16) : 0;
        std::fprintf(stderr, "[shim]   params=%u [0]=0x%llx [1]=0x%llx [2]=0x%llx\n",
                     nparams, (unsigned long long)p0, (unsigned long long)p1, (unsigned long long)p2);
    }
    std::fprintf(stderr, "[shim] RaiseException(code=0x%x, flags=0x%x, n=%u)\n",
                 code, flags, nparams);
    if (code == 0xE06D7363u && nparams >= 3 && arg3(c))
        dump_cxx_throw(c, reinterpret_cast<const uint64_t*>((uintptr_t)arg3(c)), nparams);
    // C++ EH 依赖真正的两阶段派发：先走 .pdata 链条问 personality routine。
    // MEW_SEH_DISPATCH=1 时才真的调用 handler；否则只打印帧链（观测模式）。
    const uint64_t* params = nullptr;
    if (arg3(c)) params = reinterpret_cast<const uint64_t*>((uintptr_t)arg3(c));
    if (seh::raise_exception_dispatch(c, code, flags, nparams, params)) return;  // 已接管
    ret0(c, 0);
}

void shim_KERNEL32_RtlUnwind(X64Ctx* c) {
    // RtlUnwind(TargetFrame, TargetIp, ExceptionRecord, ReturnValue)
    const uint64_t target_frame = arg0(c);
    const uint64_t target_ip = arg1(c);
    std::fprintf(stderr, "[shim] RtlUnwind(frame=0x%llx ip=0x%llx)\n",
                 (unsigned long long)target_frame, (unsigned long long)target_ip);
    if (target_ip && seh::seh_dispatch_enabled()) {
        // 第二阶段：从当前帧一路 unwind 到 target_frame，沿途把 __finally 跑掉。
        // arg2 是 EXCEPTION_RECORD，MSVC 常传 NULL —— 那就用最近一次 raise 的那份。
        const uint64_t rec = arg2(c) ? arg2(c) : seh::last_record_va();
        seh::unwind_phase2(c, target_frame, target_ip, rec);
        seh::Ctx64 w;
        seh::ctx_to_win(c, &w);
        w.Rsp = target_frame;
        ret0(c, arg3(c));
        seh::resume_at(target_ip, w);
    }
    ret0(c, 0);
}

void shim_KERNEL32_WideCharToMultiByte(X64Ctx* c) {
    // (CodePage, dwFlags, lpWideCharStr, cchWideChar,
    //  lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar)
    // 旧实现只返回 len+1、从不住缓冲区，真正拿它填路径的调用方会读到空串（P2-5）。
    const uint32_t cp   = (uint32_t)arg0(c);
    const uint64_t src  = arg2(c);
    const int      in_cch = (int)arg3(c);
    const uint64_t dst  = arg4(c);
    const int      cb   = (int)arg5(c);
    if (arg7(c)) mem_write<int32_t>(c, arg7(c), 0);   // lpUsedDefaultChar = FALSE
    if (!src) { ret0(c, 0); return; }

    const bool nul_term = in_cch < 0;
    size_t units = 0;
    if (nul_term) {
        const uint16_t* p = (const uint16_t*)guest_ptr_from_ctx(c, src);
        while (p && p[units]) ++units;
        ++units;                                      // 长度含结尾 NUL
    } else {
        units = (size_t)in_cch;
    }
    // 注意：这里恒按 UTF-8 输出。游戏内路径/设置全是 ASCII，CP_ACP 与 UTF-8 同结果；
    // 若将来出现非 ASCII 的 ANSI 调用，日志里会看到 cp 与长度，再按代码页分支。
    std::string s = utf16_to_utf8((const uint16_t*)guest_ptr_from_ctx(c, src), units);
    if (nul_term) s.push_back('\0');
    const int need = (int)s.size();
    static int logged = 0;
    if (logged++ < 10)
        std::fprintf(stderr, "[shim] WideCharToMultiByte(cp=%u, cch=%d, cb=%d) = %d caller=0x%llx\n",
                     cp, in_cch, cb, need, (unsigned long long)cur_fn_va());
    if (!dst || cb == 0) { ret0(c, (uint64_t)need); return; }   // 只问所需长度
    if (need <= cb) {
        std::memcpy(guest_ptr_from_ctx(c, dst), s.data(), (size_t)need);
        ret0(c, (uint64_t)need);
    } else {
        std::memcpy(guest_ptr_from_ctx(c, dst), s.data(), (size_t)cb);  // 满额拷贝后按失败返回
        ret0(c, 0);
    }
}

// ---------------- steam_api64（游戏静态导入，见 run 45991101871 的 UNIMPL API 表）--------
// 这三个名字在 import 表里是 **静态**导入（不是 LoadLibrary 动态取），所以自动生成的
// 弱占位会把它们打成 UNIMPL_API 然后返回 0。返回 0 恰好是「没有 Steam」的正确语义，
// 但我们需要**明确**写出来，理由有两条：
//   1) `SteamAPI_RestartAppIfNecessary` 返回 0 是「别重启进程」，绝不能被后来的改动
//      改成别的值（真机上这条一旦非 0，游戏会直接退出）；
//   2) 后面要接离线模式时，只有强符号能覆盖 `shims_auto.cpp` 的弱占位。
// 现阶段刻意保持「没有 Steam」：`SteamInternal_ContextInit` 返回 0，调用方必须自己判空
// （0x1409b5380 里那次调用已经确认会走 target=0 的降级路径，不会崩）。
void shim_STEAM_API64_SteamAPI_RestartAppIfNecessary(X64Ctx* c) {
    static int logged = 0;
    if (logged++ < 3) std::fprintf(stderr, "[shim] SteamAPI_RestartAppIfNecessary -> 0（不重启）\n");
    ret0(c, 0);
}
void shim_STEAM_API64_SteamInternal_SteamAPI_Init(X64Ctx* c) {
    static int logged = 0;
    if (logged++ < 3) std::fprintf(stderr, "[shim] SteamInternal_SteamAPI_Init -> 0（没有 Steam）\n");
    ret0(c, 0);
}
void shim_STEAM_API64_SteamInternal_ContextInit(X64Ctx* c) {
    static int logged = 0;
    if (logged++ < 3) std::fprintf(stderr, "[shim] SteamInternal_ContextInit -> 0（没有上下文）\n");
    ret0(c, 0);
}

// ---------------- GDI32 字体/文本度量（游戏 UI 布局用，不需要真渲染）----------------
// run 46005752715 第一次跑到这里（[UNIMPL API] GDI32!CreateCompatibleDC / CreateFontIndirectW /
// SelectObject / GetDeviceCaps / GetTextMetricsW / GetTextExtentPoint32A / DeleteDC）。
// 这条链是「建内存 DC → 建字体 → 选入 → 取文本度量/尺寸」的纯布局代码，不涉及像素输出，
// 所以给合理的假值就够：句柄用固定的非空假值，度量按 96 DPI、19px 行高的等宽近似。
namespace {
constexpr uint64_t kFakeDC = 0x7FFE0001E000ULL;
constexpr uint64_t kFakeFont = 0x7FFE0002F000ULL;
inline void put_i32(X64Ctx* c, uint64_t addr, int32_t v) { std::memcpy(guest_ptr_from_ctx(c, addr), &v, 4); }
}  // namespace

// run 46070229625 的 UNIMPL API TABLE 里，真线程轮唯一被调到的图形相关缺项就是
// GDI32!CreateDCW（1 次，返回 0）。initGraphics 在建 GL 上下文之前要先拿设备 DC，
// 拿不到就等于图形初始化第一步就失败——而 appmain 的返回值正是 3。
// 这里返回一个假 HDC（和 kFakeHdc 一致），让 GetDeviceCaps / wgl 那条链能继续走。
void shim_GDI32_CreateDCW(X64Ctx* c) {
    mew_api_hit("CreateDCW");
    std::fprintf(stderr, "[shim] CreateDCW(...) -> fake hdc=0x%llx caller=0x%llx\n",
                 (unsigned long long)kFakeHdc, (unsigned long long)cur_fn_va());
    ret0(c, kFakeHdc);
}
void shim_GDI32_CreateDCA(X64Ctx* c) { mew_api_hit("CreateDCA"); ret0(c, kFakeHdc); }

void shim_GDI32_CreateCompatibleDC(X64Ctx* c) {
    static int logged = 0;
    if (logged++ < 3) std::fprintf(stderr, "[shim] CreateCompatibleDC -> 假 DC\n");
    ret0(c, kFakeDC);
}
void shim_GDI32_CreateFontIndirectW(X64Ctx* c) { ret0(c, kFakeFont); }
void shim_GDI32_SelectObject(X64Ctx* c) { ret0(c, kFakeFont); }   // 返回「旧对象」，非空即可
void shim_GDI32_DeleteDC(X64Ctx* c) { ret0(c, 1); }
void shim_GDI32_DeleteObject(X64Ctx* c) { ret0(c, 1); }
void shim_GDI32_GetDeviceCaps(X64Ctx* c) {
    const int idx = (int)arg1(c);
    int v = 0;
    switch (idx) {
        case 88:  v = 96; break;      // LOGPIXELSY
        case 90:  v = 96; break;      // LOGPIXELSX
        case 12:  v = 32; break;      // BITSPIXEL
        case 14:  v = 1; break;       // PLANES
        case 8:   v = 1920; break;    // HORZRES
        case 10:  v = 1080; break;    // VERTRES
        case 118: v = 1920; break;    // DESKTOPHORZRES
        case 117: v = 1080; break;    // DESKTOPVERTRES
        default:  v = 0; break;
    }
    ret0(c, (uint64_t)v);
}
void shim_GDI32_GetTextMetricsW(X64Ctx* c) {
    const uint64_t tm = arg1(c);
    if (!tm || !guest_mapped(tm, 0x3C)) { ret0(c, 0); return; }
    uint8_t buf[0x3C];
    std::memset(buf, 0, sizeof(buf));
    auto put32 = [&](int off, int32_t v) { std::memcpy(buf + off, &v, 4); };
    put32(0, 19);    // tmHeight
    put32(4, 15);    // tmAscent
    put32(8, 4);     // tmDescent
    put32(12, 4);    // tmInternalLeading
    put32(16, 0);    // tmExternalLeading
    put32(20, 9);    // tmAveCharWidth
    put32(24, 16);   // tmMaxCharWidth
    put32(28, 400);  // tmWeight
    put32(36, 96);   // tmDigitizedAspectX
    put32(40, 96);   // tmDigitizedAspectY
    const uint16_t first = ' ', last = '~', def = '?', brk = ' ';
    std::memcpy(buf + 44, &first, 2);
    std::memcpy(buf + 46, &last, 2);
    std::memcpy(buf + 48, &def, 2);
    std::memcpy(buf + 50, &brk, 2);
    buf[56] = 1;     // tmPitchAndFamily（fixed pitch）
    buf[57] = 0;     // tmCharSet（ANSI_CHARSET）
    std::memcpy(guest_ptr_from_ctx(c, tm), buf, sizeof(buf));
    ret0(c, 1);
}
void shim_GDI32_GetTextExtentPoint32A(X64Ctx* c) {
    const uint64_t s = arg1(c);
    const int n = (int)arg2(c);
    const uint64_t psize = arg3(c);
    (void)s;
    if (!psize || !guest_mapped(psize, 8)) { ret0(c, 0); return; }
    const int32_t cx = (n > 0 ? n : 0) * 9;   // 与 tmAveCharWidth 一致的等宽近似
    const int32_t cy = 19;
    put_i32(c, psize, cx);
    put_i32(c, psize + 4, cy);
    ret0(c, 1);
}

// ---------------- 同一轮里撞到的其余三个 ----------------
// S_HELL32!SHGetFolderPathW(csidl, ...)：游戏用来定位存档目录，给一个固定路径即可。
void shim_SHELL32_SHGetFolderPathW(X64Ctx* c) {
    const uint64_t buf = arg4(c);
    if (!buf) return;
    const uint16_t path[] = {'C', ':', '\\', 'M', 'e', 'w', 'g', 'e', 'n', 'i', 'c', 's', 0};
    if (!guest_mapped(buf, sizeof(path))) { ret0(c, (uint64_t)0x80004005); return; }  // E_FAIL
    std::memcpy(guest_ptr_from_ctx(c, buf), path, sizeof(path));
    static int logged = 0;
    if (logged++ < 3) std::fprintf(stderr, "[shim] SHGetFolderPathW -> C:\\Mewgenics\n");
    ret0(c, 0);   // S_OK
}
// 枚举系统 locale：不回调、直接返 0（FALSE = 一项都没有）。ucrt 会退回默认 locale。
void shim_KERNEL32_EnumSystemLocalesW(X64Ctx* c) { (void)c; ret0(c, 0); }
// 模态对话框：不实现界面，直接返 0（相当于「没弹出来/被取消」）。
void shim_USER32_DialogBoxIndirectParamW(X64Ctx* c) { (void)c; ret0(c, 0); }
