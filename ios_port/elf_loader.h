// ELF64 (AArch64) 加载器 —— 用于在 Apple 平台上跑安卓 arm64 的 .so
// 设计目标：
//   1) 把 PT_LOAD 段映射进来并处理 .bss
//   2) 应用 R_AARCH64_* 重定位（RELATIVE / ABS64 / GLOB_DAT / JUMP_SLOT / PREL32）
//   3) 符号解析走三级：我方 shim 表 -> dlsym(RTLD_DEFAULT) -> 记录未解析
//   4) 提供 init_array / 入口调用
//
// P0 阶段只用它做"能不能加载 + 能解析多少符号"的体检。
#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct elf_image elf_image;
typedef void* (*elf_resolver)(const char* name);

struct elf_stats {
    int    load_segments;
    int    relocs_relative;
    int    relocs_symbolic;
    int    resolved_dlsym;
    int    resolved_shim;
    int    unresolved;
    size_t mapped_bytes;
};

// 加载并重定位；成功返回 0
int elf_load(const char* path, const uint64_t* preferred_base, elf_resolver shim_lookup,
             elf_image** out, struct elf_stats* stats);

// 按名字查符号地址（用于 dlsym 模拟）
void* elf_lookup(elf_image* img, const char* name);

// 遍历未解析符号名（回调返回非 0 则停止）
void elf_each_unresolved(elf_image* img, int (*cb)(const char* name, void* ud), void* ud);

// 入口相关
void* elf_entry(elf_image* img);
int   elf_run_init_array(elf_image* img);

#ifdef __cplusplus
}
#endif
