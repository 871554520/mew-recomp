// MewHost（无 SDK 版）：不 include 任何 Apple 头文件，所有 libSystem 原型自己声明，
// 因此可以在 Ubuntu 上 `clang -target arm64-apple-ios15.0 -nostdlibinc` 编译，
// 再用 ld64.lld 链接成 ios arm64 可执行文件 —— 不需要 Xcode / iPhoneOS.sdk。
//
// 与带 SDK 版等价的行为：
//   1) main 进来第一件事：建 Documents/ 与 Documents/game/，把 fd 1/2 dup2 到
//      Documents/mew.log（append），之后所有输出（宿主、shim、游戏自己的
//      __android_log_print）都落盘
//   2) 首次启动写低内存 settings.txt（埋点用，两处各一份）
//   3) 检查 Documents/game/resources.gpak；缺了就弹窗 + 正常退出
//   4) 分库 dlopen：SDL3 → libbionic_shim → libmew_relinked（每步记 dlerror）
//   5) dlsym("SDL_main")，失败退到 mach_header + 0x4075e60
//   6) **通过 dlsym 拿 SDL_RunApp 并由它接管 UIApplicationMain**（iOS 不这么做就白屏）
#include <stdarg.h>
#include <stddef.h>

// ---------------- 自己声明的最小 libSystem 接口 ----------------
typedef unsigned long size_t;
typedef long off_t;
typedef long ssize_t;

extern void* dlopen(const char*, int);
extern void* dlsym(void*, const char*);
extern char* dlerror(void);
extern char* getenv(const char*);
extern int open(const char*, int, ...);
extern off_t lseek(int, off_t, int);
extern int close(int);
extern ssize_t write(int, const void*, size_t);
extern ssize_t read(int, void*, size_t);
extern int dup2(int, int);
extern int mkdir(const char*, unsigned);
extern int chdir(const char*);
extern char* getcwd(char*, size_t);
extern int access(const char*, int);
extern int unlink(const char*);
extern int rename(const char*, const char*);
extern int snprintf(char*, size_t, const char*, ...);
extern int vsnprintf(char*, size_t, const char*, va_list);
extern void exit(int);
extern int _NSGetExecutablePath(char*, unsigned*);
extern unsigned _dyld_image_count(void);
extern const char* _dyld_get_image_name(unsigned);
extern const void* _dyld_get_image_header(unsigned);

#define RTLD_NOW 2
#define RTLD_GLOBAL 8
#define O_WRONLY 1
#define O_CREAT 0x200
#define O_APPEND 8
#define O_RDONLY 0
#define F_OK 0

#define MEW_SDL_MAIN_OFFSET 0x4075e60ULL
#define MEW_DYLIB_NAME "libmew_relinked.dylib"
#define LOG_MAX 8388608L

static char g_exe_dir[4096];
static char g_docs[1024], g_game[1200], g_gpak[1400], g_log[1400];
static int g_logfd = -1;

static size_t mew_strlen(const char* s) { size_t n = 0; while (s && s[n]) n++; return n; }
static int mew_has(const char* hay, const char* needle) {
    if (!hay || !needle) return 0;
    size_t n = mew_strlen(needle);
    for (; *hay; hay++) {
        size_t i = 0;
        while (i < n && hay[i] == needle[i]) i++;
        if (i == n) return 1;
    }
    return 0;
}

// 统一日志：先格式化，再写 fd（dup2 之后就是 mew.log）
static void say(const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n >= sizeof buf) n = (int)sizeof buf - 1;
    if (g_logfd >= 0) { (void)write(g_logfd, buf, (size_t)n); }
    (void)write(2, buf, (size_t)n);
}

static const char* exe_dir(void) {
    unsigned sz = sizeof g_exe_dir;
    if (_NSGetExecutablePath(g_exe_dir, &sz) != 0) return ".";
    size_t n = mew_strlen(g_exe_dir);
    while (n > 0 && g_exe_dir[n - 1] != '/') n--;
    if (n > 0) g_exe_dir[n - 1] = '\0';
    return g_exe_dir;
}

static long file_size(const char* p) {
    int fd = open(p, O_RDONLY);
    if (fd < 0) return -1;
    long sz = (long)lseek(fd, 0, 2);
    close(fd);
    return sz;
}

static void rotate_log(const char* log) {
    long sz = file_size(log);
    if (sz < LOG_MAX) return;
    char old[1500];
    snprintf(old, sizeof old, "%s.1", log);
    unlink(old);
    rename(log, old);
}

static int logs_setup(void) {
    const char* home = getenv("HOME");
    if (!home || !*home) return -1;
    snprintf(g_docs, sizeof g_docs, "%s/Documents", home);
    snprintf(g_game, sizeof g_game, "%s/game", g_docs);
    snprintf(g_gpak, sizeof g_gpak, "%s/resources.gpak", g_game);
    snprintf(g_log,  sizeof g_log,  "%s/mew.log", g_docs);
    (void)mkdir(g_docs, 0755);
    (void)mkdir(g_game, 0755);
    rotate_log(g_log);
    int fd = open(g_log, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return -1;
    g_logfd = fd;
    dup2(fd, 1);
    dup2(fd, 2);
    return 0;
}

static void write_lowmem_once(const char* base) {
    char cfg[1500];
    snprintf(cfg, sizeof cfg, "%s/settings.txt", base);
    if (access(cfg, F_OK) == 0) return;
    int fd = open(cfg, O_WRONLY | O_CREAT, 0644);
    if (fd < 0) { say("[host] WARN: 写 %s 失败\n", cfg); return; }
    static const char body[] =
        "texture_scale_big 0.5\ncurve_resolution 2.5\n"
        "soundeffect_cache_size_mb 64\nantialias 0\n";
    (void)write(fd, body, sizeof body - 1);
    close(fd);
    say("[host] 已写入低内存配置：%s\n", cfg);
}

// dlerror() 是会「清空」的：连续调两次，第二次返回 NULL。
// 之前日志里 dlopen shim -> 0x0 (null) 就是这么来的 —— 明明有错误信息却打成 (null)。
static const char* get_dlerror(void) {
    const char* e = dlerror();
    return e ? e : "unknown";
}

// gpak 可能被放到 Documents/ 或 Documents/game/（iOS「文件」App 里很容易放错层级）。
// 这里把所有候选都探一遍并逐条记日志，然后用**实际找到的那个目录**当工作目录。
static const char* find_gpak_dir(void) {
    static char cand[6][1500];
    const char* home = getenv("HOME");
    if (!home) return 0;
    snprintf(cand[0], sizeof cand[0], "%s/Documents/game/resources.gpak", home);
    snprintf(cand[1], sizeof cand[1], "%s/Documents/resources.gpak", home);
    snprintf(cand[2], sizeof cand[2], "%s/Documents/game/game/resources.gpak", home);
    snprintf(cand[3], sizeof cand[3], "%s/Documents/Resources/resources.gpak", home);
    static const char* tag[4] = { "Documents/game", "Documents", "Documents/game/game", "Documents/Resources" };
    for (int i = 0; i < 4; i++) {
        long sz = file_size(cand[i]);
        say("[host] 探测 %-22s -> %s%s%ld\n", tag[i], sz >= 0 ? "存在 size=" : "不存在",
            sz >= 0 ? "" : "", sz);
        if (sz >= 0) {
            // 顺便把 gpak 头 16 字节打出来，确认是容器而不是空文件/占位文件
            int fd = open(cand[i], O_RDONLY);
            if (fd >= 0) {
                unsigned char hd[16];
                long got = (long)read(fd, hd, 16);
                close(fd);
                if (got > 0) {
                    char hex[64];
                    int n = 0;
                    for (long k = 0; k < got && n < 48; k++)
                        n += snprintf(hex + n, sizeof hex - n, "%02x", hd[k]);
                    say("[host] gpak 头 16 字节：%s\n", hex);
                }
            }
            return tag[i];
        }
    }
    return 0;
}

static void* find_mew_header(void) {
    unsigned n = _dyld_image_count();
    for (unsigned i = 0; i < n; i++) {
        const char* nm = _dyld_get_image_name(i);
        if (nm && mew_has(nm, MEW_DYLIB_NAME)) return (void*)_dyld_get_image_header(i);
    }
    return 0;
}

// ---------------- 真正的 App 主逻辑（由 SDL_RunApp 回调进来） ----------------
static int app_main(int argc, char** argv) {
    (void)argc; (void)argv;
    const char* dir = exe_dir();
    say("\n[host 1] enter app main: docs=%s game=%s\n", g_docs, g_game);

    write_lowmem_once(g_docs);
    write_lowmem_once(g_game);

    long gsz = file_size(g_gpak);
    const char* found = (gsz >= 0) ? "Documents/game" : find_gpak_dir();
    say("[host 2] gpak exists=%s size=%ld dir=%s\n",
        gsz >= 0 ? "yes" : (found ? "yes(其他目录)" : "no"), gsz,
        found ? found : "-");
    if (gsz < 0 && found) {
        // 找到了但不在 game/ 下：把工作目录切到它所在的目录
        const char* home = getenv("HOME");
        if (home) {
            if (found[0] == 'D' && mew_has(found, "Documents/game/game")) {
                snprintf(g_game, sizeof g_game, "%s/Documents/game/game", home);
            } else if (mew_has(found, "Documents/game")) {
                snprintf(g_game, sizeof g_game, "%s/Documents/game", home);
            } else if (mew_has(found, "Documents/Resources")) {
                snprintf(g_game, sizeof g_game, "%s/Documents/Resources", home);
            } else {
                snprintf(g_game, sizeof g_game, "%s/Documents", home);
            }
            say("[host 2b] 改用数据目录：%s\n", g_game);
            gsz = file_size(g_gpak) >= 0 ? file_size(g_gpak) : 0;
        }
    }

    // 每个库都先试 @rpath，失败再试绝对路径（Linux 编出来的 MewHost 没有 LC_RPATH，
    // 所以绝对路径这条路是必须的，不能省）。
    char alt[4300];
    void* h_sdl = dlopen("@rpath/SDL3.framework/SDL3", RTLD_NOW | RTLD_GLOBAL);
    if (!h_sdl) {
        snprintf(alt, sizeof alt, "%s/Frameworks/SDL3.framework/SDL3", dir);
        say("[host] @rpath/SDL3 失败：%s，改试 %s\n", get_dlerror(), alt);
        h_sdl = dlopen(alt, RTLD_NOW | RTLD_GLOBAL);
    }
    say("[host] dlopen SDL3 -> %p %s\n", h_sdl, h_sdl ? "ok" : get_dlerror());

    void* h_shim = dlopen("@rpath/libbionic_shim.dylib", RTLD_NOW | RTLD_GLOBAL);
    if (!h_shim) {
        snprintf(alt, sizeof alt, "%s/Frameworks/libbionic_shim.dylib", dir);
        say("[host] @rpath/shim 失败：%s，改试 %s\n", get_dlerror(), alt);
        h_shim = dlopen(alt, RTLD_NOW | RTLD_GLOBAL);
    }
    say("[host] dlopen shim -> %p %s\n", h_shim, h_shim ? "ok" : get_dlerror());

    // 兼容库必须显式加载：它是 libmew_relinked 的第 4 个依赖，但主 dylib 是按**绝对路径**
    // dlopen 的，dyld 解析它里面的 @rpath/libmewcompat.dylib 时要靠可执行文件的 LC_RPATH；
    // 显式先加载一份，dyld 就会按 install name 复用，不必赌 rpath 回溯。
    // 顺序必须在 SDL3 之后（compat 自己依赖 SDL3 的 SDL_BlitSurfaceScaled）。
    void* h_compat = dlopen("@rpath/libmewcompat.dylib", RTLD_NOW | RTLD_GLOBAL);
    if (!h_compat) {
        snprintf(alt, sizeof alt, "%s/Frameworks/libmewcompat.dylib", dir);
        say("[host] @rpath/compat 失败：%s，改试 %s\n", get_dlerror(), alt);
        h_compat = dlopen(alt, RTLD_NOW | RTLD_GLOBAL);
    }
    say("[host] dlopen compat -> %p %s\n", h_compat, h_compat ? "ok" : get_dlerror());
    if (!h_compat) say("[host] 警告：compat 库没加载，主 dylib 大概率会报 "
                       "symbol not found: _bionic_tlsdesc_resolver\n");
    if (gsz < 0) {
        if (!h_sdl) h_sdl = dlopen("@rpath/SDL3.framework/SDL3", RTLD_NOW | RTLD_GLOBAL);
        typedef int (*mb_fn)(unsigned, const char*, const char*, void*);
        mb_fn mb = h_sdl ? (mb_fn)dlsym(h_sdl, "SDL_ShowSimpleMessageBox") : 0;
        if (mb) mb(0x10, "缺少游戏数据",
                   "请将 resources.gpak 放入「文件 → 我的 iPhone → MewRelink → game」后重新打开。"
                   "\n\n详细日志：文件 → 我的 iPhone → MewRelink → mew.log", 0);
        say("[host] 已提示用户，正常退出\n");
        return 0;
    }

    if (chdir(g_game) != 0) chdir(dir);
    char cwd[4096];
    if (getcwd(cwd, sizeof cwd)) say("[host] cwd = %s\n", cwd);

    say("[host 3] before dlopen(%s)\n", MEW_DYLIB_NAME);
    char p3[4200];
    void* h = 0;
    snprintf(p3, sizeof p3, "%s/Frameworks/%s", dir, MEW_DYLIB_NAME);
    h = dlopen(p3, RTLD_NOW | RTLD_GLOBAL);
    if (!h) {
        say("[host] dlopen %s 失败：%s\n", p3, dlerror() ? dlerror() : "?");
        h = dlopen(MEW_DYLIB_NAME, RTLD_NOW | RTLD_GLOBAL);
    }
    say("[host 3b] dlopen result h=%p %s\n", h, h ? "ok" : get_dlerror());
    if (!h) return 2;

    void* hdr = find_mew_header();
    typedef void (*set_base_fn)(unsigned long);
    set_base_fn set_base = (set_base_fn)dlsym((void*)-2 /*RTLD_DEFAULT*/, "mew_eh_register_image");
    say("[host 3c] mew_base=%p set_base=%p\n", hdr, (void*)set_base);
    if (set_base && hdr) set_base((unsigned long)hdr);

    void* entry = dlsym(h, "SDL_main");
    if (!entry && hdr) {
        entry = (void*)((char*)hdr + MEW_SDL_MAIN_OFFSET);
        say("[host 4] dlsym 失败，退到 header+0x%llx = %p\n",
            (unsigned long long)MEW_SDL_MAIN_OFFSET, entry);
    } else {
        say("[host 4] calling target _SDL_main at %p\n", entry);
    }
    if (!entry) return 3;

    typedef int (*sdl_main_fn)(int, char**);
    int rc = ((sdl_main_fn)entry)(0, (char**)0);
    say("[host 5] target _SDL_main returned rc=%d\n", rc);
    return rc;
}

// ---------------- 入口：必须走 SDL_RunApp（iOS 靠它进 UIApplicationMain） ----------------
int main(int argc, char** argv) {
    int logged = logs_setup();
    say("\n[host 0] main() entered, logs_setup=%d\n", logged);

    // 先用 dlopen 把 SDL3 拉进来，再 dlsym 取 SDL_RunApp：
    // 这样 MewHost 不需要在链接期依赖 SDL3.framework（Ubuntu 上没有 .tbd 也能链）。
    void* h_sdl = dlopen("@rpath/SDL3.framework/SDL3", RTLD_NOW | RTLD_GLOBAL);
    if (!h_sdl) {
        char alt[4200];
        snprintf(alt, sizeof alt, "%s/Frameworks/SDL3.framework/SDL3", exe_dir());
        h_sdl = dlopen(alt, RTLD_NOW | RTLD_GLOBAL);
    }
    typedef int (*run_app_fn)(int, char**, int (*)(int, char**), void*);
    run_app_fn run = h_sdl ? (run_app_fn)dlsym(h_sdl, "SDL_RunApp") : 0;
    say("[host 0b] SDL3=%p SDL_RunApp=%p\n", h_sdl, (void*)run);
    if (run) {
        int rc = run(argc, argv, app_main, 0);
        say("[host 9] SDL_RunApp returned %d\n", rc);
        return rc;
    }
    say("[host 0c] 没有 SDL_RunApp，退回裸跑（iOS 上会白屏）\n");
    return app_main(argc, argv);
}
