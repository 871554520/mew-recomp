/* 阶段 2 对照 harness（Wine 侧）：把原版 PE 映射到 ImageBase，直接调用指定函数 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned long long parse_hex(const char* s) { return strtoull(s, 0, 16); }

int main(int argc, char** argv) {
    if (argc < 3) { fprintf(stderr, "usage: guest_harness <exe> <va-hex> [a0 a1 a2 a3]\n"); return 2; }
    const char* path = argv[1];
    unsigned long long va = parse_hex(argv[2]);
    unsigned long long args[4] = {0, 0, 0, 0};
    for (int i = 0; i < 4 && i + 3 < argc; ++i) args[i] = parse_hex(argv[i + 3]);

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

    /* 模拟栈 */
    unsigned char* stk = (unsigned char*)VirtualAlloc(NULL, 1 << 20, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    unsigned long long top = (unsigned long long)(uintptr_t)(stk + (1 << 20) - 64);

    typedef unsigned long long (*fn_t)(unsigned long long, unsigned long long, unsigned long long, unsigned long long);
    fn_t fn = (fn_t)(uintptr_t)(va + delta);
    unsigned long long rax = fn(args[0], args[1], args[2], args[3]);
    (void)top;

    printf("{\"rax\": %llu, \"va\": %llu, \"delta\": %llu}\n", rax, va, delta);
    return 0;
}
