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
#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include "x64_runtime.h"
#include "win32_common.h"

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
void shim_KERNEL32_VirtualAlloc(X64Ctx* c) {
    uint64_t size = arg1(c);
    uint32_t prot = (uint32_t)arg3(c);
    int flags = MAP_PRIVATE | MAP_ANON;
    int p = (prot & 0x40) ? (PROT_READ | PROT_WRITE | PROT_EXEC) : (PROT_READ | PROT_WRITE);
    void* m = mmap(nullptr, size ? size : 0x1000, p, flags, -1, 0);
    if (m == MAP_FAILED) { ret0(c, 0); return; }
    uint64_t g = (uint64_t)((int64_t)(uintptr_t)m - c->mem_bias);
    register_guest_range(g, size ? size : 0x1000);
    ret0(c, g);
}

void shim_KERNEL32_VirtualFree(X64Ctx* c) {
    uint64_t addr = arg0(c);
    uint64_t size = arg1(c);
    if (addr) munmap((void*)(uintptr_t)((int64_t)addr + c->mem_bias), size ? size : 0x1000);
    ret0(c, 1);
}

void shim_KERNEL32_VirtualProtect(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_KERNEL32_GetProcessHeap(X64Ctx* c) { ret0(c, 1); }

void shim_KERNEL32_HeapAlloc(X64Ctx* c) {
    void* p = std::malloc((size_t)arg2(c));
    std::fprintf(stderr, "[shim] HeapAlloc(%zu)=%p\n", (size_t)arg2(c), p);
    uint64_t g = p ? (uint64_t)((int64_t)(uintptr_t)p - c->mem_bias) : 0;
    if (g) register_guest_range(g, (size_t)arg2(c));
    ret0(c, g);
}

void shim_KERNEL32_HeapFree(X64Ctx* c) {
    if (arg2(c)) std::free((void*)(uintptr_t)((int64_t)arg2(c) + c->mem_bias));
    ret0(c, 1);
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
    for (int i = 0; i < 1024; ++i) if (!g_tls_used[i]) { g_tls_used[i] = true; ret0(c, i); return; }
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
void shim_KERNEL32_IsProcessorFeaturePresent(X64Ctx* c) { ret0(c, 1); }
void shim_KERNEL32_ExitProcess(X64Ctx* c) {
    std::fprintf(stderr, "[shim] ExitProcess(%u)\n", (unsigned) arg0(c));
    std::exit((int)arg0(c));
}
void shim_KERNEL32_GetCommandLineW(X64Ctx* c) { ret0(c, 0); }
void shim_KERNEL32_GetCommandLineA(X64Ctx* c) { ret0(c, 0); }
void shim_KERNEL32_GetEnvironmentVariableW(X64Ctx* c) { ret0(c, 0); }
void shim_KERNEL32_GetStartupInfoW(X64Ctx* c) { if (arg0(c)) std::memset(guest_ptr_from_ctx(c, arg0(c)), 0, 104); ret0(c, 0); }

void shim_KERNEL32_WideCharToMultiByte(X64Ctx* c) {
    uint32_t cp = (uint32_t)arg0(c);
    uint64_t src = arg2(c);
    int srclen = (int)arg3(c);
    uint64_t dst = 0, dstlen = 0;
    // 后两个参数在栈上（Win64 第 5/6 参数）
    (void)cp;
    if (srclen < 0) {
        size_t n = 0;
        const uint16_t* p = (const uint16_t*)guest_ptr_from_ctx(c, src);
        while (p[n]) ++n;
        srclen = (int)n;
    }
    std::string s = utf16_to_utf8((const uint16_t*)guest_ptr_from_ctx(c, src), (size_t)srclen);
    (void)dst; (void)dstlen;
    ret0(c, (uint64_t)s.size());
}

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
void shim_KERNEL32_GetStdHandle(X64Ctx* c) {
    uint32_t n = (uint32_t)arg0(c);
    ret0(c, n == (uint32_t)-10 ? 0x101 : (n == (uint32_t)-11 ? 0x102 : 0x103));
}
void shim_KERNEL32_GetFileType(X64Ctx* c) { ret0(c, 1); }
void shim_KERNEL32_SetHandleCount(X64Ctx* c) { ret0(c, (uint32_t)arg0(c)); }
void shim_KERNEL32_RtlUnwind(X64Ctx* c) { (void)c; }

// ---------------- 补充：库加载与错误 ----------------
void shim_KERNEL32_GetModuleHandleExW(X64Ctx* c) { (void)c; ret0(c, 1); }
void shim_KERNEL32_FreeLibraryAndExitThread(X64Ctx* c) { std::exit(0); }
void shim_KERNEL32_RaiseException(X64Ctx* c) {
    std::fprintf(stderr, "[shim] RaiseException code=0x%x\n", (unsigned)arg0(c));
    ret0(c, 0);
}
void shim_KERNEL32_GetSystemTimePreciseAsFileTime(X64Ctx* c) { shim_KERNEL32_GetSystemTimeAsFileTime(c); }
void shim_KERNEL32_OutputDebugStringW(X64Ctx* c) {
    std::fprintf(stderr, "[game] %s\n", guest_wstr(c, arg0(c)).c_str());
    ret0(c, 0);
}
void shim_KERNEL32_GetEnvironmentStringsW(X64Ctx* c) { ret0(c, 0); }
void shim_KERNEL32_FreeEnvironmentStringsW(X64Ctx* c) { ret0(c, 1); }

// ---------------- 临界区/事件/线程补充 ----------------
void shim_KERNEL32_InitializeCriticalSectionAndSpinCount(X64Ctx* c) {
    shim_KERNEL32_InitializeCriticalSection(c);
    ret0(c, 1);
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

uint64_t shim_KERNEL32_LookupSynthetic(const char* name) {
    static std::unordered_map<std::string, uint64_t> cache;
    auto it = cache.find(name);
    if (it != cache.end()) return it->second;
    RecompFn fn = lookup_api(name);
    if (!fn) return 0;
    uint64_t va = 0x500000000ULL + 0x10 * (uint64_t)(cache.size() + 1);
    register_recomp_fn(va, fn);
    cache[name] = va;
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
    for (int i = 0; i < 1024; ++i) if (!g_tls_used[i]) { g_tls_used[i] = true; ret0(c, i); return; }
    ret0(c, (uint64_t)-1);
}
void shim_KERNEL32_FlsFree(X64Ctx* c) {
    uint32_t i = (uint32_t)arg0(c);
    if (i < 1024) g_tls_used[i] = false;
    ret0(c, 1);
}
void shim_KERNEL32_FlsGetValue(X64Ctx* c) { ret0(c, g_tls[(uint32_t)arg0(c) & 1023]); }
void shim_KERNEL32_FlsSetValue(X64Ctx* c) { g_tls[(uint32_t)arg0(c) & 1023] = arg1(c); ret0(c, 1); }

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
