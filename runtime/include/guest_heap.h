#pragma once
// 固定 Guest 堆池：把所有 guest 可见的堆内存放进一个固定虚拟区间，
// 让 MEW_SAFE_MEM 变成几次整数比较，同时让 Linux / macOS / iOS 三端地址行为一致。
//
// 布局（bias=0，guest 地址即宿主地址）：
//   0x140000000 - 0x142000000   PE 镜像
//   0x200000000 - 0x220000000   本堆池（512 MB，按需提交物理页）
//   0x300000000 - 0x304000000   模拟栈区
//   0x500000000 - 0x500100000   合成 Win32 垫片表
//   0x600000000 - 0x600100000   合成 OpenGL 垫片表（阶段 6）
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <sys/mman.h>

struct GuestHeapPool {
    static constexpr uint64_t BASE_HINT = 0x200000000ULL;
    static constexpr size_t   POOL_SIZE = 512ULL * 1024 * 1024;

    uint8_t* base = nullptr;
    size_t   cursor = 0;
    std::mutex mtx;
    std::unordered_map<uint64_t, size_t> alloc_sizes;

    void init() {
        if (base) return;
        void* p = mmap(reinterpret_cast<void*>(BASE_HINT), POOL_SIZE,
                       PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#ifdef MAP_FIXED_NOREPLACE
        if (p == MAP_FAILED) {
            // 地址被占：退回系统挑选，但依然登记在 alloc_sizes 里，SAFE_MEM 靠 owns() 放行
            p = mmap(nullptr, POOL_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        } else if (p != reinterpret_cast<void*>(BASE_HINT)) {
            // 内核没有按提示放置：接受（仍能工作，只是基址不是 0x200000000）
            munmap(p, POOL_SIZE);
            p = mmap(nullptr, POOL_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        }
#else
        if (p == MAP_FAILED) {
            p = mmap(nullptr, POOL_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        }
#endif
        if (p == MAP_FAILED) {
            std::fprintf(stderr, "[FATAL] GuestHeapPool mmap 512MB failed\n");
            std::abort();
        }
        base = static_cast<uint8_t*>(p);
        cursor = 0x1000;  // 留空首页，防低偏移误碰
        std::fprintf(stderr, "[heap] pool base=0x%llx size=%zuMB\n",
                     (unsigned long long)(uintptr_t)base, (size_t)(POOL_SIZE >> 20));
    }

    uint64_t alloc(size_t sz, bool zero_init) {
        std::lock_guard<std::mutex> lk(mtx);
        if (!base) init();
        size_t aligned = (sz + 15ULL) & ~static_cast<size_t>(15ULL);
        if (aligned == 0) aligned = 16;
        if (cursor + aligned > POOL_SIZE) {
            std::fprintf(stderr, "[FATAL] GuestHeapPool OOM! cursor=%zu need=%zu\n", cursor, aligned);
            std::abort();
        }
        uint8_t* ptr = base + cursor;
        cursor += aligned;
        if (zero_init) std::memset(ptr, 0, aligned);
        uint64_t addr = reinterpret_cast<uint64_t>(ptr);
        alloc_sizes[addr] = aligned;
        return addr;
    }

    bool owns(uint64_t addr) const {
        if (!base) return false;
        uint64_t b = reinterpret_cast<uint64_t>(base);
        return addr >= b && addr < b + cursor;
    }

    bool contains(uint64_t addr, size_t n) const {
        if (!base) return false;
        uint64_t b = reinterpret_cast<uint64_t>(base);
        return addr >= b && addr + n <= b + cursor;
    }

    size_t size_of(uint64_t addr) {
        std::lock_guard<std::mutex> lk(mtx);
        auto it = alloc_sizes.find(addr);
        return it == alloc_sizes.end() ? 0 : it->second;
    }

    // 阶段 5 调试期只从登记表移除，不真正回收：彻底杜绝 use-after-free 与野指针崩。
    void free_block(uint64_t addr) {
        std::lock_guard<std::mutex> lk(mtx);
        alloc_sizes.erase(addr);
    }

    size_t used() const { return cursor; }
};

inline GuestHeapPool g_guest_heap;
