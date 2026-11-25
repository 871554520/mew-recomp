#pragma once
// 垫片公用设施：参数读取、句柄表、UTF-16 <-> UTF-8、guest 指针换算
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <mutex>

#include "x64_runtime.h"

// guest 地址 -> 宿主指针（ctx 里带 mem_bias）
static inline void* guest_ptr_from_ctx(X64Ctx* c, uint64_t guest_addr) {
    return reinterpret_cast<void*>((int64_t)guest_addr + c->mem_bias);
}

// Win64 参数寄存器
static inline uint64_t arg0(X64Ctx* c) { return c->rcx; }
static inline uint64_t arg1(X64Ctx* c) { return c->rdx; }
static inline uint64_t arg2(X64Ctx* c) { return c->r8; }
static inline uint64_t arg3(X64Ctx* c) { return c->r9; }
static inline void ret0(X64Ctx* c, uint64_t v) { c->rax = v; }

template <typename T>
static inline T g_read(X64Ctx* c, uint64_t addr) { return mem_read<T>(c, addr); }

static inline std::string utf16_to_utf8(const uint16_t* w, size_t maxUnits) {
    std::string out;
    size_t i = 0;
    while (i < maxUnits && w[i]) {
        uint32_t cp = w[i++];
        if (cp >= 0xD800 && cp <= 0xDBFF && i < maxUnits && w[i] >= 0xDC00 && w[i] <= 0xDFFF)
            cp = 0x10000 + ((cp - 0xD800) << 10) + (w[i++] - 0xDC00);
        if (cp < 0x80) out += (char)cp;
        else if (cp < 0x800) { out += (char)(0xC0 | (cp >> 6)); out += (char)(0x80 | (cp & 0x3F)); }
        else if (cp < 0x10000) {
            out += (char)(0xE0 | (cp >> 12));
            out += (char)(0x80 | ((cp >> 6) & 0x3F));
            out += (char)(0x80 | (cp & 0x3F));
        } else {
            out += (char)(0xF0 | (cp >> 18));
            out += (char)(0x80 | ((cp >> 12) & 0x3F));
            out += (char)(0x80 | ((cp >> 6) & 0x3F));
            out += (char)(0x80 | (cp & 0x3F));
        }
    }
    return out;
}

static inline std::string guest_wstr(X64Ctx* c, uint64_t addr, size_t maxUnits = 4096) {
    if (!addr || !guest_mapped(addr, 2)) return std::string("<badptr>");
    const uint16_t* p = (const uint16_t*)guest_ptr_from_ctx(c, addr);
    return utf16_to_utf8(p, maxUnits);
}

// 在 guest 地址空间分配一块（mmap 后登记，返回 guest 地址）
static inline uint64_t guest_alloc(X64Ctx* c, size_t n) {
    extern void* mmap(void*, size_t, int, int, int, long);
    void* p = mmap(nullptr, (n + 4095) & ~size_t(4095), 3 /*RW*/, 0x22 /*PRIVATE|ANON*/, -1, 0);
    if (p == (void*)-1) return 0;
    uint64_t g = (uint64_t)((int64_t)(uintptr_t)p - c->mem_bias);
    register_guest_range(g, n);
    return g;
}

// 句柄表：宿主对象 -> guest 句柄值
class HandleTable {
public:
    static HandleTable& instance() { static HandleTable t; return t; }
    uint64_t add(void* p) {
        std::lock_guard<std::mutex> lk(mu_);
        uint64_t h = next_++;
        map_[h] = p;
        return h;
    }
    void* get(uint64_t h) {
        std::lock_guard<std::mutex> lk(mu_);
        auto it = map_.find(h);
        return it == map_.end() ? nullptr : it->second;
    }
    bool erase(uint64_t h) {
        std::lock_guard<std::mutex> lk(mu_);
        return map_.erase(h) != 0;
    }
private:
    std::mutex mu_;
    uint64_t next_ = 0x100;
    std::unordered_map<uint64_t, void*> map_;
};
