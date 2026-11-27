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
#include <unordered_set>
#include <unordered_map>
#include <malloc.h>
#include <dirent.h>
#include <cctype>
#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include "x64_runtime.h"
#include "win32_common.h"
#include "seh_x64.h"

// ---- 前向声明：动态加载表可能在定义之前引用 ----
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
    std::fprintf(stderr, "[shim] HeapAlloc(%zu, flags=0x%x)=0x%llx caller=0x%llx%s\n", n, flags,
                 (unsigned long long)g, (unsigned long long)cur_fn_va(), g ? "" : " (NULL: refused)");
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
void shim_KERNEL32_CreateFileW(X64Ctx* c) {
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
void shim_KERNEL32_FindFirstFileExW(X64Ctx* c) {
    const std::string pattern = host_path_from_guest(c, arg0(c));
    std::fprintf(stderr, "[shim] FindFirstFileExW(\"%s\", info=0x%llx) -> INVALID (stub) caller=0x%llx\n",
                 pattern.c_str(), (unsigned long long)arg1(c), (unsigned long long)cur_fn_va());
    static int traced = 0;
    if (traced++ < 3) call_trace().dump("FindFirstFileExW stub");
    ret0(c, (uint64_t)-1);
}

// GetFileAttributesExW：拿不到时返回 FALSE 并置 last error。
// 同样先出声，避免「文件存在但游戏以为不存在」被静默吞掉。
void shim_KERNEL32_GetFileAttributesExW(X64Ctx* c) {
    const std::string path = find_case_insensitive(host_path_from_guest(c, arg0(c)));
    FILE* f = std::fopen(path.c_str(), "rb");
    const bool ok = f != nullptr;
    if (f) std::fclose(f);
    std::fprintf(stderr, "[shim] GetFileAttributesExW(\"%s\")=%s caller=0x%llx\n",
                 path.c_str(), ok ? "TRUE" : "FALSE", (unsigned long long)cur_fn_va());
    ret0(c, ok ? 1u : 0u);
}

void shim_KERNEL32_ReadFile(X64Ctx* c) {
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
void shim_KERNEL32_GetLastError(X64Ctx* c) { ret0(c, 0); }
void shim_KERNEL32_SetLastError(X64Ctx* c) { (void)c; ret0(c, 0); }
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

void shim_KERNEL32_MultiByteToWideChar(X64Ctx* c) { (void)c; ret0(c, 0); }
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
void shim_USER32_GetSystemMetrics(X64Ctx* c) { ret0(c, (uint32_t)arg0(c) == 0 ? 1920 : 1080); }
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
void shim_KERNEL32_CreateEventW(X64Ctx* c) { ret0(c, 0x1001); }
void shim_KERNEL32_CreateEventA(X64Ctx* c) { ret0(c, 0x1001); }
void shim_KERNEL32_SetEvent(X64Ctx* c) { ret0(c, 1); }
void shim_KERNEL32_ResetEvent(X64Ctx* c) { ret0(c, 1); }
void shim_KERNEL32_WaitForSingleObject(X64Ctx* c) { ret0(c, 0); }
void shim_KERNEL32_WaitForMultipleObjects(X64Ctx* c) { ret0(c, 0); }
void shim_KERNEL32_CreateThread(X64Ctx* c) { ret0(c, 0x1002); }
void shim_KERNEL32_GetExitCodeThread(X64Ctx* c) { if (arg1(c)) mem_write<uint32_t>(c, arg1(c), 0); ret0(c, 1); }
void shim_KERNEL32_SetThreadPriority(X64Ctx* c) { ret0(c, 1); }
void shim_KERNEL32_SwitchToThread(X64Ctx* c) { ret0(c, 1); }
void shim_KERNEL32_GetCurrentThread(X64Ctx* c) { ret0(c, 1); }
void shim_KERNEL32_GetCurrentProcess(X64Ctx* c) { ret0(c, 2); }
void shim_KERNEL32_CreateMutexW(X64Ctx* c) { ret0(c, 0x1003); }
void shim_KERNEL32_ReleaseMutex(X64Ctx* c) { ret0(c, 1); }
void shim_KERNEL32_SetEndOfFile(X64Ctx* c) { ret0(c, 1); }
void shim_KERNEL32_GetFileAttributesW(X64Ctx* c) {
    std::string path = host_path_from_guest(c, arg0(c));
    FILE* f = std::fopen(path.c_str(), "rb");
    std::fprintf(stderr, "[shim] GetFileAttributesW(\"%s\")=%s\n", path.c_str(), f ? "FILE" : "MISSING");
    if (f) std::fclose(f);
    ret0(c, f ? 0x80 : (uint32_t)-1);
}
void shim_KERNEL32_GetCurrentDirectoryW(X64Ctx* c) { ret0(c, 0); }
void shim_KERNEL32_SetCurrentDirectoryW(X64Ctx* c) { ret0(c, 1); }
void shim_KERNEL32_CreateDirectoryW(X64Ctx* c) { ret0(c, 1); }
void shim_KERNEL32_DeleteFileW(X64Ctx* c) { ret0(c, 1); }
void shim_KERNEL32_FindFirstFileW(X64Ctx* c) {
    // 这原本是个静默返回 INVALID_HANDLE_VALUE 的桩：如果游戏是靠目录枚举
    // 去找 *.gpak / 资源目录，它会在这里静默失败，日志里连一条痕迹都没有，
    // 于是「阶段 5 没进展」看起来像「还没走到文件 IO」。
    // 先让它出声（pattern 与调用环），再决定要不要真实现枚举。
    const std::string pattern = host_path_from_guest(c, arg0(c));
    if (!pattern.empty())
        std::fprintf(stderr, "[shim] FindFirstFileW(\"%s\") -> INVALID (stub) caller=0x%llx\n",
                     pattern.c_str(), (unsigned long long)cur_fn_va());
    static int traced = 0;
    if (traced++ < 3) call_trace().dump("FindFirstFileW stub");
    ret0(c, (uint64_t)-1);
}

void shim_KERNEL32_FindNextFileW(X64Ctx* c) {
    std::fprintf(stderr, "[shim] FindNextFileW(h=0x%llx) -> FALSE (stub) caller=0x%llx\n",
                 (unsigned long long)arg0(c), (unsigned long long)cur_fn_va());
    ret0(c, 0);
}
void shim_KERNEL32_FindClose(X64Ctx* c) { ret0(c, 1); }
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
void shim_KERNEL32_SleepConditionVariableSRW(X64Ctx* c) {
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
    std::fprintf(stderr, "[shim] SleepConditionVariableSRW(srw=0x%llx cv=0x%llx ms=%u) -> %s(%llu)\n",
                 (unsigned long long)arg0(c), (unsigned long long)arg1(c), ms,
                 ret ? "signaled" : "timeout", (unsigned long long)ret);
    (void)cv_for; (void)srw_for;
    ret0(c, ret);
}
void shim_KERNEL32_WakeConditionVariable(X64Ctx* c) {
    CvSlot* cv = cv_for(arg0(c), true);
    if (cv) pthread_cond_signal(&cv->cv);
    ret0(c, 0);
}
void shim_KERNEL32_WakeAllConditionVariable(X64Ctx* c) {
    CvSlot* cv = cv_for(arg0(c), true);
    if (cv) pthread_cond_broadcast(&cv->cv);
    ret0(c, 0);
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
void shim_KERNEL32_FormatMessageW(X64Ctx* c) { (void)c; ret0(c, 0); }   // 如实失败
void shim_KERNEL32_FormatMessageA(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_KERNEL32_GetEnvironmentVariableW(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_KERNEL32_GetEnvironmentVariableA(X64Ctx* c) { (void)c; ret0(c, 0); }
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

void shim_USER32_CreateWindowExW(X64Ctx* c) {
    const int w = (int)arg6(c), h = (int)arg7(c);
    if (w > 0) win().w = w;
    if (h > 0) win().h = h;
    win().title = (const char*)guest_ptr_from_ctx(c, arg2(c));
    std::fprintf(stderr, "[shim] CreateWindowExW(w=%d h=%d title=%s) -> hwnd=0x%llx\n",
                 win().w, win().h, win().title ? win().title : "(n/a)",
                 (unsigned long long)kFakeHwnd);
    ret0(c, kFakeHwnd);
}
void shim_USER32_CreateWindowExA(X64Ctx* c) { shim_USER32_CreateWindowExW(c); }
void shim_USER32_RegisterClassW(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_USER32_RegisterClassExW(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_USER32_RegisterClassA(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_USER32_DestroyWindow(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_USER32_IsWindow(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_USER32_ShowWindow(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_USER32_SetWindowPos(X64Ctx* c) {
    // (hwnd, hWndInsertAfter, x, y, cx, cy, flags)：cx=第 5 个=arg4，cy=第 6 个=arg5
    const int cx = (int)arg4(c), cy = (int)arg5(c);
    if (cx > 0) win().w = cx;
    if (cy > 0) win().h = cy;
    ret0(c, 1);
}
void shim_USER32_GetClientRect(X64Ctx* c) {
    fill_rect(c, arg1(c), 0, 0, win().w, win().h);
    ret0(c, 1);
}
void shim_USER32_GetWindowRect(X64Ctx* c) {
    fill_rect(c, arg1(c), 0, 0, win().w, win().h);
    ret0(c, 1);
}
void shim_USER32_GetDC(X64Ctx* c) { (void)c; ret0(c, kFakeHdc); }
void shim_USER32_ReleaseDC(X64Ctx* c) { (void)c; ret0(c, 1); }
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
void shim_USER32_SetWindowTextW(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_USER32_ScreenToClient(X64Ctx* c) { (void)c; ret0(c, 1); }   // 恒等变换
void shim_USER32_ClientToScreen(X64Ctx* c) { (void)c; ret0(c, 1); }

// ---- 消息循环：有界 ----
// PeekMessageW/GetMessageW 每调用一次推进一「帧」，跑满 MEW_MAX_FRAMES 后投 WM_QUIT
void shim_USER32_PeekMessageW(X64Ctx* c) {
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
void shim_USER32_GetMessageW(X64Ctx* c) {
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
void shim_USER32_DispatchMessageW(X64Ctx* c) { (void)c; ret0(c, 0); }
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
void shim_USER32_EnumDisplayDevicesW(X64Ctx* c) { (void)c; ret0(c, 0); }
void shim_USER32_EnumDisplayMonitors(X64Ctx* c) { (void)c; ret0(c, 0); }
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

// ---------------- 动态加载：伪造模块句柄 + 合成函数地址 -> 真垫片 ----------------
namespace {

struct DynApi { const char* name; RecompFn fn; };

uint64_t fake_module_handle() { return 0x7FFF00000000ULL; }

uint64_t synth_va_for(const char* name);

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
    std::exit((int)arg0(c));
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
