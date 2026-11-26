// P0 体检：加载安卓版 libmain.so，报告重定位/符号解析情况
// 用法: p0_report <libmain.so> [--run-init]
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "elf_loader.h"

// P0 阶段我们的 shim 表还是空的；P1 起往里加 bionic 专有实现
static void* shim_lookup(const char* name) {
    (void)name;
    return NULL;
}

#define MAX_UNRES 500
static char* g_unres[MAX_UNRES];
static size_t g_unres_n = 0;

static int collect(const char* name, void* ud) {
    (void)ud;
    if (g_unres_n < MAX_UNRES) g_unres[g_unres_n++] = (char*)name;
    return 0;
}

static int cmpstr(const void* a, const void* b) {
    return strcmp(*(char* const*)a, *(char* const*)b);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <libmain.so> [--run-init]\n", argv[0]);
        return 2;
    }
    int do_init = 0;
    for (int i = 2; i < argc; ++i)
        if (!strcmp(argv[i], "--run-init")) do_init = 1;

    uint64_t base_hint = 0x700000000000ULL;
    elf_image* img = NULL;
    struct elf_stats st;
    if (elf_load(argv[1], &base_hint, shim_lookup, &img, &st) != 0) {
        fprintf(stderr, "elf_load failed\n");
        return 1;
    }
    printf("\n===== elf stats =====\n");
    printf("load_segments   = %d\n", st.load_segments);
    printf("mapped_bytes    = %zu (%.1f MB)\n", st.mapped_bytes, st.mapped_bytes / 1048576.0);
    printf("relocs relative = %d\n", st.relocs_relative);
    printf("relocs symbolic = %d\n", st.relocs_symbolic);
    printf("resolved shim   = %d\n", st.resolved_shim);
    printf("resolved dlsym  = %d\n", st.resolved_dlsym);
    printf("unresolved      = %d\n", st.unresolved);

    elf_each_unresolved(img, collect, NULL);
    qsort(g_unres, g_unres_n, sizeof(char*), cmpstr);

    int n_sdl = 0, n_other = 0;
    for (size_t i = 0; i < g_unres_n; ++i)
        if (!strncmp(g_unres[i], "SDL_", 4)) n_sdl++; else n_other++;
    printf("unresolved SDL_ = %d, other = %d\n", n_sdl, n_other);
    printf("\n--- unresolved (non-SDL, up to 200) ---\n");
    int shown = 0;
    for (size_t i = 0; i < g_unres_n && shown < 200; ++i) {
        if (!strncmp(g_unres[i], "SDL_", 4)) continue;
        printf("  %s\n", g_unres[i]);
        shown++;
    }
    printf("--- SDL sample (up to 10) ---\n");
    shown = 0;
    for (size_t i = 0; i < g_unres_n && shown < 10; ++i) {
        if (strncmp(g_unres[i], "SDL_", 4)) continue;
        printf("  %s\n", g_unres[i]);
        shown++;
    }

    printf("\nentry=0x%llx\n", (unsigned long long)(uintptr_t)elf_entry(img));
    if (do_init) {
        printf("running init_array ...\n");
        fflush(stdout);
        int n = elf_run_init_array(img);
        printf("init_array done (%d ctors)\n", n);
    }
    return 0;
}
