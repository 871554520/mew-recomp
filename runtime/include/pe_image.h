#pragma once
// 阶段 4：PE 原始段镜像加载 + .reloc 修正 + 独立模拟栈
#include <cstdint>
#include "x64_runtime.h"
#include <cstddef>
#include <vector>
#include <string>

struct PeSectionInfo {
    uint32_t rva = 0, vsize = 0, raw_off = 0, raw_size = 0;
};

struct GuestImage {
    uint64_t orig_image_base = 0;
    uint8_t* host_base = nullptr;
    size_t image_size = 0;
    int64_t mem_bias = 0;   // host_addr = guest_addr + mem_bias
    uint64_t pdata_va = 0;      // .pdata（异常目录）在镜像里的 VA
    uint32_t pdata_bytes = 0;   // 字节数（/12 = RUNTIME_FUNCTION 个数）
};

// 把 PE 全部节按原 RVA 映射到一块连续匿名内存，并应用 .reloc（DIR64/HIGHLOW）
bool load_pe_image(const char* exe_path, GuestImage* out, std::string* err);

// 释放镜像（仅用于测试）
void unload_pe_image(GuestImage* img);

// 为 ctx 分配 4MB 模拟栈（16 字节对齐），栈指针换算到 guest 虚拟地址空间
void init_guest_thread_ctx(X64Ctx* ctx, const GuestImage& img);

// 便捷：guest 地址 -> 宿主指针
inline void* guest_ptr(const GuestImage& img, uint64_t guest_addr) {
    return const_cast<void*>(reinterpret_cast<const void*>(guest_addr + img.mem_bias));
}
