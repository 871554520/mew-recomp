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
#include <vector>
#include <algorithm>
#include <sys/mman.h>

struct GuestHeapPool {
    // 基址必须落在 **4GB 以下**。原因：这个 exe 的 CRT 路径里存在把指针截成 32 位的
    // 写法（手工解 0x140d7a31c/calloc 时看到 `8b f0` = mov esi,eax，最后 `mov rax,rsi`
    // 返回）。堆放在 0x200000000（8GB）时，这种截断会直接把指针毁掉，调用方拿到就是
    // 0xc06b57xxx 这类垃圾，最终崩在 `mov [r9],rdx`。Windows 上堆通常也在 4GB 内，
    // 所以把堆挪到 0x10000000（256MB）既安全又符合真实环境。
    static constexpr uint64_t BASE_HINT = 0x10000000ULL;
    // 512MB → 2.5GB：实测游戏会申请 **1 GiB** 的整块（调用环
    // sub_0x1409da1d0(rcx=0x40000000)），512MB 池直接拒成 NULL，随后那条路径
    // 一路降级到「invalid hash bucket count」C++ 异常 + NULL 间接跳转。
    // 上界约束仍然是「结尾必须 < 4GB」：0x10000000 + 0xA0000000 = 0xB0000000 ✓
    // 匿名 mmap 是惰性提交，只有真正写到的页才占物理内存。
    static constexpr size_t   POOL_SIZE = 2560ULL * 1024 * 1024;

    uint8_t* base = nullptr;
    size_t   cursor = 0;
    size_t   pool_size = POOL_SIZE;   // 实际拿到的池大小（mmap 失败会逐级缩小）
    std::mutex mtx;
    std::unordered_map<uint64_t, size_t> alloc_sizes;
    std::unordered_map<uint64_t, size_t> alloc_req;   // 调用方请求的字节数（诊断用）
    std::vector<std::pair<uint64_t, size_t>> live;     // 已分配区间（升序），查重叠

    void init() {
        if (base) return;
        // 大池拿不到就逐级退：CI 上偶尔会遇到地址空间/ulimit 限制，
        // 那时宁可用小池跑（会打印实际大小），也不要 abort 把整轮日志毁掉。
        for (size_t want : {POOL_SIZE, (size_t)(512ULL << 20), (size_t)(256ULL << 20)}) {
            pool_size = want;
            void* q = mmap(reinterpret_cast<void*>(BASE_HINT), want,
                           PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (q != MAP_FAILED) {
                base = static_cast<uint8_t*>(q);
                cursor = 0x1000;
                std::fprintf(stderr, "[heap] pool base=0x%llx size=%zuMB (requested %zuMB)\n",
                             (unsigned long long)(uintptr_t)base, want >> 20, POOL_SIZE >> 20);
                return;
            }
        }
        void* p = reinterpret_cast<void*>(MAP_FAILED);
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
            std::fprintf(stderr, "[FATAL] GuestHeapPool mmap failed for every size\n");
            std::abort();
        }
        base = static_cast<uint8_t*>(p);
        pool_size = POOL_SIZE;
        cursor = 0x1000;  // 留空首页，防低偏移误碰
        std::fprintf(stderr, "[heap] pool base=0x%llx size=%zuMB\n",
                     (unsigned long long)(uintptr_t)base, (size_t)(pool_size >> 20));
    }

    uint64_t alloc(size_t sz, bool zero_init) {
        std::lock_guard<std::mutex> lk(mtx);
        if (!base) init();
        size_t aligned = (sz + 15ULL) & ~static_cast<size_t>(15ULL);
        if (aligned == 0) aligned = 16;
        // 申请不到就返回 0，**不 abort**：Windows 的 HeapAlloc/VirtualAlloc 语义就是
        // 失败返回 NULL，让 guest 自己走错误路径。实测有 4.76 GiB 的请求
        // （GuestHeapPool OOM need=5114261360），当时直接 abort 把一整轮日志废掉，
        // 而 abort 之前的现场才是我们要看的。
        if (aligned > pool_size || cursor + aligned > pool_size) {
            static int refused = 0;
            if (refused++ < 20)
                std::fprintf(stderr,
                             "[heap] alloc(%zu) refused (cursor=%zu pool=%zuMB) -> NULL\n",
                             sz, cursor, (size_t)(pool_size >> 20));
            return 0;
        }
        uint8_t* ptr = base + cursor;
        cursor += aligned;
        if (zero_init) std::memset(ptr, 0, aligned);
        uint64_t addr = reinterpret_cast<uint64_t>(ptr);
        // 不变量：新块不能和任何存活块重叠。重叠说明"请求的 size 是错的"，
        // 后续对这个块的写入会踩烂邻居（实测 0x3c8 的 PTD 只申请到 1 字节）。
        {
            auto it = std::lower_bound(live.begin(), live.end(), std::make_pair(addr, (size_t)0));
            bool bad = false;
            if (it != live.end() && it->first < addr + aligned) bad = true;
            if (it != live.begin()) {
                auto pv = it - 1;
                if (pv->first + pv->second > addr) bad = true;
            }
            if (bad) {
                static int logged = 0;
                if (logged++ < 20)
                    std::fprintf(stderr,
                                 "[heap] OVERLAP new=0x%llx size=%zu req=%zu conflicts live=%zu\n",
                                 (unsigned long long)addr, aligned, sz, live.size());
            } else {
                live.insert(it, std::make_pair(addr, aligned));
            }
        }
        alloc_sizes[addr] = aligned;
        alloc_req[addr] = sz;
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

    // 调用方当初请求的字节数（HeapSize 用；块的实际物理大小是 size_of）
    size_t requested(uint64_t addr) {
        std::lock_guard<std::mutex> lk(mtx);
        auto it = alloc_req.find(addr);
        return it == alloc_req.end() ? 0 : it->second;
    }

    // 尝试原地扩容：只有「最新一块」才有资格（游标就在它尾巴上）。
    // 成功返回 true；失败不动任何状态，调用方自行决定退化路线。
    bool grow_in_place(uint64_t addr, size_t new_aligned, bool zero_new) {
        std::lock_guard<std::mutex> lk(mtx);
        auto it = alloc_sizes.find(addr);
        if (it == alloc_sizes.end()) return false;
        size_t old = it->second;
        if (new_aligned <= old) return true;                       // 够大，不缩
        if (addr + old != reinterpret_cast<uint64_t>(base) + cursor) return false;  // 不是最新块
        size_t need = new_aligned - old;
        if (cursor + need > pool_size) return false;
        if (zero_new) std::memset(base + cursor, 0, need);
        cursor += need;
        it->second = new_aligned;
        for (auto& e : live)
            if (e.first == addr) { e.second = new_aligned; break; }
        return true;
    }

    // 原地扩容后修正「请求字节数」，让后续 HeapSize 拿到新值
    void set_requested(uint64_t addr, size_t n) {
        std::lock_guard<std::mutex> lk(mtx);
        if (alloc_sizes.count(addr)) alloc_req[addr] = n;
    }

    // 阶段 5 调试期只从登记表移除，不真正回收：彻底杜绝 use-after-free 与野指针崩。
    void free_block(uint64_t addr) {
        std::lock_guard<std::mutex> lk(mtx);
        auto it = alloc_sizes.find(addr);
        if (it != alloc_sizes.end()) {
            auto r = std::lower_bound(live.begin(), live.end(), std::make_pair(addr, (size_t)0));
            if (r != live.end() && r->first == addr) live.erase(r);
            alloc_req.erase(addr);
            alloc_sizes.erase(it);
        }
    }

    size_t used() const { return cursor; }
};

inline GuestHeapPool g_guest_heap;
