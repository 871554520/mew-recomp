#include "pe_image.h"
#include "x64_runtime.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/mman.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

namespace {

uint32_t rd32(const uint8_t* p) { uint32_t v; std::memcpy(&v, p, 4); return v; }
uint64_t rd64(const uint8_t* p) { uint64_t v; std::memcpy(&v, p, 8); return v; }

}  // namespace

bool load_pe_image(const char* exe_path, GuestImage* out, std::string* err) {
    FILE* f = std::fopen(exe_path, "rb");
    if (!f) { if (err) *err = "open failed"; return false; }
    std::fseek(f, 0, SEEK_END);
    long n = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> file((size_t)n);
    if (std::fread(file.data(), 1, file.size(), f) != file.size()) {
        std::fclose(f); if (err) *err = "short read"; return false;
    }
    std::fclose(f);

    const uint32_t peOff = rd32(file.data() + 0x3c);
    if (std::memcmp(file.data() + peOff, "PE\0\0", 4) != 0) { if (err) *err = "not PE"; return false; }
    const uint16_t nsec = *(uint16_t*)(file.data() + peOff + 6);
    const uint16_t optSize = *(uint16_t*)(file.data() + peOff + 20);
    const uint8_t* opt = file.data() + peOff + 24;
    const uint64_t imageBase = rd64(opt + 24);
    const uint32_t sizeOfImage = rd32(opt + 56);
    const size_t secTab = peOff + 24 + optSize;
    // 注意：映射时只拷贝节，PE 头（RVA 0）不落地，所以 .pdata 目录必须在这里从文件头取
    const uint32_t excRva = rd32(opt + 112 + 3 * 8);
    const uint32_t excBytes = rd32(opt + 112 + 3 * 8 + 4);

    // 优先映射到原始基址：bias=0 时镜像内所有绝对指针天然有效，无需 .reloc 修正
    void* want = (void*)(uintptr_t)imageBase;
    void* mem = mmap(want, sizeOfImage, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANON | MAP_FIXED_NOREPLACE, -1, 0);
    bool pinned = (mem != MAP_FAILED && mem == want);
    if (!pinned) {
        if (mem != MAP_FAILED) munmap(mem, sizeOfImage);
        mem = mmap(nullptr, sizeOfImage, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON, -1, 0);
    }
    if (mem == MAP_FAILED) { if (err) *err = "mmap failed"; return false; }
    std::memset(mem, 0, sizeOfImage);

    struct Sec { uint32_t rva, vsize, raw, rawsize; };
    std::vector<Sec> secs;
    for (uint16_t i = 0; i < nsec; ++i) {
        const uint8_t* p = file.data() + secTab + i * 40;
        Sec s;
        std::memcpy(&s.vsize, p + 8, 4);
        std::memcpy(&s.rva, p + 12, 4);
        std::memcpy(&s.rawsize, p + 16, 4);
        std::memcpy(&s.raw, p + 20, 4);
        secs.push_back(s);
        if (s.raw && s.rawsize && s.raw + s.rawsize <= file.size() && s.rva < sizeOfImage) {
            size_t cp = s.rawsize;
            if (s.rva + cp > sizeOfImage) cp = sizeOfImage - s.rva;
            std::memcpy((uint8_t*)mem + s.rva, file.data() + s.raw, cp);
        }
    }

    int64_t bias = (int64_t)(uintptr_t)mem - (int64_t)imageBase;
    std::fprintf(stderr, "[loader] pinned_at_base=%d bias=%lld\n", (int)pinned, (long long)bias);

    // ---- .reloc：仅在没能钉在原始基址时才需要 ----
    for (uint16_t i = 0; i < nsec && bias != 0; ++i) {
        const uint8_t* p = file.data() + secTab + i * 40;
        char name[9] = {0};
        std::memcpy(name, p, 8);
        if (std::strncmp(name, ".reloc", 6) != 0) continue;
        uint32_t rva = rd32(p + 12), rawsize = rd32(p + 16), raw = rd32(p + 20);
        if (!raw || !rawsize) break;
        const uint8_t* r = file.data() + raw;
        uint32_t off = 0;
        while (off + 8 <= rawsize) {
            uint32_t pageRva = rd32(r + off);
            uint32_t blockSize = rd32(r + off + 4);
            if (blockSize < 8 || off + blockSize > rawsize) break;
            for (uint32_t e = 8; e + 2 <= blockSize; e += 2) {
                uint16_t ent = *(const uint16_t*)(r + off + e);
                uint32_t type = ent >> 12;
                uint32_t ofs = ent & 0xFFF;
                if (type == 0) continue;  // IMAGE_REL_BASED_ABSOLUTE
                uint32_t rvaSlot = pageRva + ofs;
                if (rvaSlot + 8 > sizeOfImage) continue;
                uint8_t* slot = (uint8_t*)mem + rvaSlot;
                if (type == 10 /* DIR64 */) {
                    uint64_t v = rd64(slot);
                    v = (uint64_t)((int64_t)v + bias);
                    std::memcpy(slot, &v, 8);
                } else if (type == 3 /* HIGHLOW */) {
                    uint32_t v = rd32(slot);
                    v = (uint32_t)((int32_t)v + (int32_t)bias);
                    std::memcpy(slot, &v, 4);
                }
            }
            off += blockSize;
        }
        (void)rva;
    }

    register_guest_range(imageBase, sizeOfImage);
    out->orig_image_base = imageBase;
    out->host_base = (uint8_t*)mem;
    out->image_size = sizeOfImage;
    out->mem_bias = bias;
    out->pdata_va = excRva ? imageBase + excRva : 0;
    out->pdata_bytes = excBytes;
    std::fprintf(stderr, "[loader] pdata va=0x%llx bytes=0x%x (%u entries)\n",
                 (unsigned long long)out->pdata_va, excBytes, excBytes / 12);
    return true;
}

void unload_pe_image(GuestImage* img) {
    if (img && img->host_base) {
        munmap(img->host_base, img->image_size);
        img->host_base = nullptr;
    }
}

void init_guest_thread_ctx(X64Ctx* ctx, const GuestImage& img) {
    constexpr size_t kStack = 4 * 1024 * 1024;
    void* stack = mmap(nullptr, kStack, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (stack == MAP_FAILED) std::abort();
    std::memset(stack, 0, 0x100);
    std::memset(ctx, 0, sizeof(*ctx));
    ctx->mem_bias = img.mem_bias;
    uint64_t host_top = ((uint64_t)(uintptr_t)stack + kStack - 0x100) & ~0xFULL;
    ctx->rsp = (uint64_t)((int64_t)host_top - img.mem_bias);
    // 4KB 伪 TEB：gs:[0x30]=Self, gs:[0x58]=TLS 数组
    void* teb = mmap(nullptr, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (teb == MAP_FAILED) std::abort();
    std::memset(teb, 0, 4096);
    ctx->gs_base = (uint64_t)((int64_t)(uintptr_t)teb - img.mem_bias);
    register_guest_range(ctx->gs_base, 4096);
    register_guest_range((uint64_t)((int64_t)(uintptr_t)stack - img.mem_bias), kStack);
    ctx->fs_base = ctx->gs_base;
    // gs:[0x30] = TEB.Self：CRT 里一堆 `mov rax, gs:[0x30]` 之后按偏移取字段的写法，
    // 这一格是 0 的话立刻在 NULL 上翻车（注释早就说有，代码一直没写）。
    *reinterpret_cast<uint64_t*>(teb) = 0;  // 先确保清零
    *reinterpret_cast<uint64_t*>(reinterpret_cast<char*>(teb) + 0x30) = ctx->gs_base;
    ctx->rbx = 0; ctx->rbp = 0; ctx->rsi = 0; ctx->rdi = 0;
    ctx->r12 = ctx->r13 = ctx->r14 = ctx->r15 = 0;
}
