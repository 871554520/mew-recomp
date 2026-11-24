/* 阶段 2 对照 harness（Wine 侧）：映射原版 PE，调用指定函数，返回 rax + 缓冲区哈希 */
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
        fprintf(stderr, "usage: guest_harness <exe> <va-hex> <ptr_mask-hex> [a0 a1 a2 a3]\n");
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
    size_t secTab = peOff + 24 + optSize;

    unsigned char* mem = (unsigned char*)VirtualAlloc(NULL, 0x2000000,
                                                      MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!mem) { fprintf(stderr, "VirtualAlloc failed\n"); return 1; }
    unsigned long long delta = (unsigned long long)(uintptr_t)mem - imageBase;
    for (unsigned short i = 0; i < nsec; ++i) {
        unsigned char* p = img + secTab + i * 40;
        unsigned int vsize = *(unsigned int*)(p + 8);
        unsigned int vaddr = *(unsigned int*)(p + 12);
        unsigned int rawsize = *(unsigned int*)(p + 16);
        unsigned int raw = *(unsigned int*)(p + 20);
        if (raw && rawsize) memcpy(mem + vaddr, img + raw, rawsize < vsize ? rawsize : vsize);
    }

    unsigned char* buf = (unsigned char*)VirtualAlloc(NULL, BUF_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!buf) { fprintf(stderr, "buf alloc failed\n"); return 1; }
    memset(buf, 0, BUF_SIZE);
    unsigned long long bufp = (unsigned long long)(uintptr_t)(buf + BUF_BIAS);
    for (int i = 0; i < 4; ++i)
        if (mask & (1u << i)) args[i] = bufp;

    typedef unsigned long long (*fn_t)(unsigned long long, unsigned long long,
                                       unsigned long long, unsigned long long);
    fn_t fn = (fn_t)(uintptr_t)(va + delta);
    fprintf(stderr, "stage: base=%llx delta=%llx va=%llx mask=%x\n", imageBase, delta, va, mask);
    fflush(stderr);

    unsigned long long rax = fn(args[0], args[1], args[2], args[3]);
    fprintf(stderr, "stage: returned rax=%llu\n", rax);
    fflush(stderr);

    printf("{\"rax\": %llu, \"h\": %llu}\n", rax, fnv1a(buf, BUF_SIZE));
    return 0;
}
