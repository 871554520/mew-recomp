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
#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include "x64_runtime.h"
#include "win32_common.h"

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
void shim_KERNEL32_CreateThread(X64Ctx*);
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

std::string host_path_from_guest(X64Ctx* c, uint64_t wpath) {
    std::string s = guest_wstr(c, wpath);
    for (char& ch : s) if (ch == '\\') ch = '/';
    return s;
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
    uint32_t prot = (uint32_t)arg3(c);
    size_t n = size ? (size_t)size : 0x1000;
    int flags = MAP_PRIVATE | MAP_ANON;
    int p = (prot & 0x40) ? (PROT_READ | PROT_WRITE | PROT_EXEC) : (PROT_READ | PROT_WRITE);
    void* m = mmap(nullptr, n, p, flags, -1, 0);
    if (m == MAP_FAILED) { ret0(c, 0); return; }
    {
        std::lock_guard<std::mutex> lk(g_virt_mu);
        g_virt_ranges[m] = n;
    }
    uint64_t g = (uint64_t)((int64_t)(uintptr_t)m - c->mem_bias);
    register_guest_range(g, n);
    ret0(c, g);
}

void shim_KERNEL32_VirtualFree(X64Ctx* c) {
    uint64_t addr = arg0(c);
    void* p = (void*)(uintptr_t)((int64_t)addr + c->mem_bias);
    if (!p) { ret0(c, 1); return; }
    size_t n = 0;
    {
        std::lock_guard<std::mutex> lk(g_virt_mu);
        auto it = g_virt_ranges.find(p);
        if (it != g_virt_ranges.end()) { n = it->second; g_virt_ranges.erase(it); }
    }
    if (n) {
        munmap(p, n);
        ret0(c, 1);
    } else {
        std::fprintf(stderr, "[shim] VirtualFree(0x%llx) ignored: not a range we mapped\n",
                     (unsigned long long)addr);
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
    void* p = std::malloc(n ? n : 1);
    if (p) { std::lock_guard<std::mutex> lk(g_heap_mu); g_heap_blocks.insert(p); }
    std::fprintf(stderr, "[shim] HeapAlloc(%zu)=%p\n", n, p);
    uint64_t g = p ? (uint64_t)((int64_t)(uintptr_t)p - c->mem_bias) : 0;
    if (g) {
        // 按真实可用大小登记：CRT 拿到 HeapAlloc(1) 之后常常往里写整个结构体，
        // 只登记 1 字节会让 MEW_SAFE_MEM 误报 unmapped write（实测 0x140d6cb90）。
        size_t usable = n ? n : 1;
#if defined(__GLIBC__)
        usable = malloc_usable_size(p);
#endif
        if (usable > (1u << 20)) usable = 1u << 20;
        register_guest_range(g, usable);
    }
    ret0(c, g);
}

void shim_KERNEL32_HeapFree(X64Ctx* c) {
    void* p = (void*)(uintptr_t)((int64_t)arg2(c) + c->mem_bias);
    if (!p) { ret0(c, 1); return; }
    bool known = false;
    {
        std::lock_guard<std::mutex> lk(g_heap_mu);
        auto it = g_heap_blocks.find(p);
        if (it != g_heap_blocks.end()) { g_heap_blocks.erase(it); known = true; }
    }
    if (known) {
        std::free(p);
        ret0(c, 1);
    } else {
        std::fprintf(stderr, "[shim] HeapFree(0x%llx) ignored: not a block we allocated\n",
                     (unsigned long long)arg2(c));
        ret0(c, 0);
    }
}

// ---------------- 文件 ----------------
void shim_KERNEL32_CreateFileW(X64Ctx* c) {
    std::string path = host_path_from_guest(c, arg0(c));
    uint32_t access = (uint32_t)arg1(c);
    const char* mode = (access & 0x40000000u) ? "wb+" : ((access & 0x80000000u) ? "rb" : "rb");
    FILE* f = std::fopen(path.c_str(), mode);
    std::fprintf(stderr, "[shim] CreateFileW(\"%s\", 0x%x) = %p\n", path.c_str(), access, (void*)f);
    if (!f) { ret0(c, (uint64_t)-1); return; }
    ret0(c, HandleTable::instance().add(f));
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

void shim_KERNEL32_TlsGetValue(X64Ctx* c) { ret0(c, g_tls[(uint32_t)arg0(c) & 1023]); }
void shim_KERNEL32_TlsSetValue(X64Ctx* c) {
    g_tls[(uint32_t)arg0(c) & 1023] = arg1(c);
    ret0(c, 1);
}

void shim_KERNEL32_InitializeCriticalSection(X64Ctx* c) {
    pthread_mutex_t* m = new pthread_mutex_t;
    pthread_mutex_init(m, nullptr);
    if (arg0(c)) mem_write<uint64_t>(c, arg0(c), (uint64_t)((int64_t)(uintptr_t)m - c->mem_bias));
    ret0(c, 1);
}

void shim_KERNEL32_EnterCriticalSection(X64Ctx* c) {
    uint64_t m = arg0(c) ? mem_read<uint64_t>(c, arg0(c)) : 0;
    if (m) pthread_mutex_lock((pthread_mutex_t*)(uintptr_t)((int64_t)m + c->mem_bias));
    ret0(c, 1);
}

void shim_KERNEL32_LeaveCriticalSection(X64Ctx* c) {
    uint64_t m = arg0(c) ? mem_read<uint64_t>(c, arg0(c)) : 0;
    if (m) pthread_mutex_unlock((pthread_mutex_t*)(uintptr_t)((int64_t)m + c->mem_bias));
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
    if (arg0(c)) {
        uint8_t* p = (uint8_t*)guest_ptr_from_ctx(c, arg0(c));
        std::memset(p, 0, 48);
        *(uint32_t*)(p + 0) = 0;       // 架构 x86
        *(uint32_t*)(p + 20) = 4096;   // 页大小
        *(uint32_t*)(p + 24) = 0x10000;
        *(uint32_t*)(p + 32) = 4;      // 处理器数
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
void shim_KERNEL32_FindFirstFileW(X64Ctx* c) { ret0(c, (uint64_t)-1); }
void shim_KERNEL32_FindNextFileW(X64Ctx* c) { ret0(c, 0); }
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

// ---------------- 动态加载：伪造模块句柄 + 合成函数地址 -> 真垫片 ----------------
namespace {

struct DynApi { const char* name; RecompFn fn; };

uint64_t fake_module_handle() { return 0x7FFF00000000ULL; }

uint64_t synth_va_for(const char* name);

// 映射表：引擎/CRT 会 GetProcAddress 的常见入口
RecompFn lookup_api(const char* name) {
    static const DynApi kApis[] = {
        {"InitializeCriticalSectionAndSpinCount", shim_KERNEL32_InitializeCriticalSectionAndSpinCount},
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
        {"GetEnvironmentStringsW", shim_KERNEL32_GetEnvironmentStringsW},
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
        std::fprintf(stderr, "[shim] FlsAlloc()=%d\n", i);
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
        std::fprintf(stderr, "[shim] FlsFree(%u)\n", i);
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
        std::fprintf(stderr, "[shim] FlsSetValue(%u, 0x%llx)\n", i, (unsigned long long)arg1(c));
    g_api_trace() = true;   // 从这里开始逐 API 打印，直到 fastfail 现场
    if (i < 1024) g_tls[i] = arg1(c);
    ret0(c, 1);
}

void shim_KERNEL32_RtlCaptureContext(X64Ctx* c) {
    if (arg0(c)) std::memset(guest_ptr_from_ctx(c, arg0(c)), 0, 0x4d0);
    ret0(c, 0);
}
void shim_KERNEL32_RtlLookupFunctionEntry(X64Ctx* c) { ret0(c, 0); }
void shim_KERNEL32_RtlVirtualUnwind(X64Ctx* c) { ret0(c, 0); }
void shim_KERNEL32_RtlUnwindEx(X64Ctx* c) { ret0(c, 0); }
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

void shim_KERNEL32_RaiseException(X64Ctx* c) {
    std::fprintf(stderr, "[shim] RaiseException(code=0x%x, flags=0x%x)\n",
                 (unsigned)arg0(c), (unsigned)arg2(c));
    ret0(c, 0);
}

void shim_KERNEL32_RtlUnwind(X64Ctx* c) { (void)c; }

void shim_KERNEL32_WideCharToMultiByte(X64Ctx* c) {
    // (cp, dwFlags, lpWide, cchWide, lpMulti, cbMulti, lpDefault, pfUsed)
    uint64_t src = arg2(c);
    int cch = (int)arg3(c);
    uint64_t dst = 0;
    int cbMulti = 0;
    if (cch < 0) {
        const uint16_t* p = (const uint16_t*)guest_ptr_from_ctx(c, src);
        size_t n = 0;
        while (p && p[n]) ++n;
        cch = (int)n;
    }
    std::string s = utf16_to_utf8((const uint16_t*)guest_ptr_from_ctx(c, src), (size_t)(cch < 0 ? 0 : cch));
    // 第 5/6 个参数在栈上，这里简化：若目标指针为 0 只返回所需长度
    (void)dst; (void)cbMulti;
    ret0(c, (uint64_t)s.size() + 1);
}
