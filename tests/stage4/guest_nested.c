/* 阶段 4 对照 harness（Wine 侧）：映射原版 PE + 应用 .reloc，调用嵌套调用根函数 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 0x20000
#define BUF_BIAS 0x8000

static unsigned long long parse_hex(const char* s) { return strtoull(s, 0, 16); }

static unsigned long long fnv1a(const unsigned char* p, size_t n) {
    unsigned long long h = 1469598103934665603ULL;
    size_t i;
    for (i = 0; i < n; ++i) { h ^= p[i]; h *= 1099511628211ULL; }
    return h;
}

int main(int argc, char** argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: guest_nested <exe> <va-hex> <mask-hex> [a0 a1 a2 a3]\n");
        return 2;
    }
    const char* path = argv[1];
    unsigned long long va = parse_hex(argv[2]);
    unsigned int mask = (unsigned int)parse_hex(argv[3]);
    unsigned long long args[4] = {0, 0, 0, 0};
    for (int i = 0; i < 4 && i + 4 < argc; ++i) args[i] = parse_hex(argv[i + 4]);

    FILE* f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "open failed\n"); return 1; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char* img = (unsigned char*)malloc((size_t)n);
    if (fread(img, 1, (size_t)n, f) != (size_t)n) { fprintf(stderr, "read failed\n"); return 1; }
    fclose(f);

    unsigned int peOff = *(unsigned int*)(img + 0x3c);
    unsigned short nsec = *(unsigned short*)(img + peOff + 6);
    unsigned short optSize = *(unsigned short*)(img + peOff + 20);
    unsigned char* opt = img + peOff + 24;
    unsigned long long imageBase = *(unsigned long long*)(opt + 24);
    unsigned int sizeOfImage = *(unsigned int*)(opt + 56);
    size_t secTab = peOff + 24 + optSize;

    unsigned char* mem = (unsigned char*)VirtualAlloc(NULL, sizeOfImage,
                                                      MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!mem) { fprintf(stderr, "VirtualAlloc failed\n"); return 1; }
    memset(mem, 0, sizeOfImage);
    unsigned long long delta = (unsigned long long)(uintptr_t)mem - imageBase;

    unsigned short i;
    for (i = 0; i < nsec; ++i) {
        unsigned char* p = img + secTab + i * 40;
        unsigned int vsize = *(unsigned int*)(p + 8);
        unsigned int vaddr = *(unsigned int*)(p + 12);
        unsigned int rawsize = *(unsigned int*)(p + 16);
        unsigned int raw = *(unsigned int*)(p + 20);
        if (raw && rawsize) memcpy(mem + vaddr, img + raw, rawsize < vsize ? rawsize : vsize);
    }

    /* 应用 .reloc（DIR64 / HIGHLOW） */
    unsigned long long relocApplied = 0;
    for (i = 0; i < nsec; ++i) {
        unsigned char* p = img + secTab + i * 40;
        if (memcmp(p, ".reloc", 6) != 0) continue;
        unsigned int rawsize = *(unsigned int*)(p + 16);
        unsigned int raw = *(unsigned int*)(p + 20);
        if (!raw || !rawsize) break;
        unsigned char* r = img + raw;
        unsigned int off = 0;
        while (off + 8 <= rawsize) {
            unsigned int pageRva = *(unsigned int*)(r + off);
            unsigned int blockSize = *(unsigned int*)(r + off + 4);
            unsigned int e;
            if (blockSize < 8 || off + blockSize > rawsize) break;
            for (e = 8; e + 2 <= blockSize; e += 2) {
                unsigned short ent = *(unsigned short*)(r + off + e);
                unsigned int type = ent >> 12;
                unsigned int ofs = ent & 0xFFF;
                unsigned char* slot;
                if (type == 0) continue;
                if (pageRva + ofs + 8 > sizeOfImage) continue;
                slot = mem + pageRva + ofs;
                if (type == 10) {
                    unsigned long long v = *(unsigned long long*)slot;
                    v += delta;
                    *(unsigned long long*)slot = v;
                    relocApplied++;
                } else if (type == 3) {
                    unsigned int v = *(unsigned int*)slot;
                    v += (unsigned int)delta;
                    *(unsigned int*)slot = v;
                    relocApplied++;
                }
            }
            off += blockSize;
        }
        break;
    }

    unsigned char* buf = (unsigned char*)VirtualAlloc(NULL, BUF_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!buf) { fprintf(stderr, "buf alloc failed\n"); return 1; }
    memset(buf, 0, BUF_SIZE);
    unsigned long long bufp = (unsigned long long)(uintptr_t)(buf + BUF_BIAS);
    for (i = 0; i < 4; ++i)
        if (mask & (1u << i)) args[i] = bufp;

    typedef unsigned long long (*fn_t)(unsigned long long, unsigned long long,
                                       unsigned long long, unsigned long long);
    fn_t fn = (fn_t)(uintptr_t)(va + delta);
    fprintf(stderr, "stage: base=%llx delta=%llx va=%llx relocs=%llu\n",
            imageBase, delta, va, relocApplied);
    fflush(stderr);

    unsigned long long rax = fn(args[0], args[1], args[2], args[3]);
    fprintf(stderr, "stage: returned rax=%llu\n", rax);
    fflush(stderr);
    printf("{\"rax\": %llu, \"h\": %llu}\n", rax, fnv1a(buf, BUF_SIZE));
    return 0;
}
