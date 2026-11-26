// iOS 宿主：dlopen 构建期重链接出来的 libmew_relinked.dylib，然后调 SDL_main。
//
// 为什么还要宿主：重链接产物是一个 dylib（代码页全在 __TEXT，可签名、可映射），
// 真机上「谁去 mmap 它、谁去调入口」必须由 App 本体负责。App 本体只做四件事：
//   1) 找到随包分发的那几个 dylib（同目录 / Frameworks）
//   2) dlopen（RTLD_NOW，符号缺失当场炸，不要 RTLD_LAZY 拖到运行中途）
//   3) 把工作目录切到 Documents/game，游戏自己会相对路径找 resources.gpak 与资源
//   4) 调 SDL_main(0, NULL)，之后一切交给引擎
//
// 注意：不用 registerGNU_EH_FRAME。那条是 Linux 侧 ELF 加载器的活；Mach-O 的
// __eh_frame 节点由 dyld 直接登记，我们只要保证它被放在 __TEXT 且 __TEXT 段
// fileoff/vmaddr 从 0 起覆盖 header（converter 已经保证）。

#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char g_exe_dir[4096];

static const char *exe_dir(void) {
    uint32_t sz = sizeof g_exe_dir;
    if (_NSGetExecutablePath(g_exe_dir, &sz) != 0) return ".";
    char *s = strrchr(g_exe_dir, '/');
    if (s) *s = '\0';
    return g_exe_dir;
}

static void log_images(void) {
    uint32_t n = _dyld_image_count();
    fprintf(stderr, "[host] dyld images = %u\n", n);
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (nm && (strstr(nm, "mew") || strstr(nm, "bionic") || strstr(nm, "SDL")))
            fprintf(stderr, "[host]   [%u] %s @ %p\n", i, nm, (void *)_dyld_get_image_header(i));
    }
}

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    log_images();
    const char *dir = exe_dir();
    fprintf(stderr, "[host] exe dir = %s\n", dir);

    const char *cand[] = {
        "libmew_relinked.dylib",
        "Frameworks/libmew_relinked.dylib",
        "../Frameworks/libmew_relinked.dylib",
    };
    char path[4096];
    void *h = NULL;
    for (size_t i = 0; i < sizeof cand / sizeof cand[0]; i++) {
        snprintf(path, sizeof path, "%s/%s", dir, cand[i]);
        h = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
        if (h) {
            fprintf(stderr, "[host] dlopen OK: %s\n", path);
            break;
        }
        fprintf(stderr, "[host] dlopen miss %s: %s\n", path, dlerror());
    }
    if (!h) {
        fprintf(stderr, "[host] FATAL: 找不到 libmew_relinked.dylib\n");
        return 2;
    }

    int (*SDL_main)(int, char **) = (int (*)(int, char **))dlsym(h, "SDL_main");
    if (!SDL_main) {
        fprintf(stderr, "[host] FATAL: dlsym(SDL_main) 失败: %s\n", dlerror());
        return 3;
    }
    fprintf(stderr, "[host] SDL_main = %p\n", (void *)SDL_main);

    // 游戏用相对路径打开 resources.gpak / 资源，宿主负责把工作目录摆好
    char cwd[4096];
    snprintf(cwd, sizeof cwd, "%s/../Documents/game", dir);
    if (mkdir(cwd, 0755) == 0)
        fprintf(stderr, "[host] created %s\n", cwd);
    if (chdir(cwd) != 0) {
        // 退回包内目录，至少让缺资源的失败信息落在明确位置
        if (chdir(dir) != 0) fprintf(stderr, "[host] chdir failed: %s\n", dir);
        else fprintf(stderr, "[host] WARN: Documents/game 不可用，退回合包目录\n");
    }
    char real[4096];
    if (getcwd(real, sizeof real)) fprintf(stderr, "[host] cwd = %s\n", real);

    log_images();
    fprintf(stderr, "[host] entering SDL_main\n");
    fflush(stderr);
    int rc = SDL_main(0, NULL);
    fprintf(stderr, "[host] SDL_main returned %d\n", rc);
    return rc;
}
