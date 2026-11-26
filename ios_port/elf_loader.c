#include "elf_loader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <errno.h>

// ---- ELF64 结构（只定义需要的部分） ----
typedef struct {
    unsigned char e_ident[16];
    uint16_t e_type, e_machine;
    uint32_t e_version;
    uint64_t e_entry, e_phoff, e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx;
} Ehdr64;

typedef struct {
    uint32_t p_type, p_flags;
    uint64_t p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align;
} Phdr64;

typedef struct {
    int64_t  d_tag;
    uint64_t d_val;
} Dyn64;

typedef struct {
    uint32_t st_name;
    uint8_t  st_info, st_other;
    uint16_t st_shndx;
    uint64_t st_value, st_size;
} Sym64;

typedef struct {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t  r_addend;
} Rela64;

#define PT_LOAD_   1
#define PT_DYNAMIC_ 2
#define DT_NULL_   0
#define DT_NEEDED_ 1
#define DT_INIT_   12
#define DT_STRTAB_ 5
#define DT_SYMTAB_ 6
#define DT_RELA_   7
#define DT_RELASZ_ 8
#define DT_RELAENT_ 9
#define DT_INIT_ARRAY_ 25
#define DT_INIT_ARRAYSZ_ 27
#define DT_SYMENT_ 11
#define DT_JMPREL_ 23
#define DT_PLTRELSZ_ 2
#define DT_PLTREL_ 20

#define R_AARCH64_ABS64_    257
#define R_AARCH64_PREL32_   261
#define R_AARCH64_GLOB_DAT_ 1025
#define R_AARCH64_JUMP_SLOT_ 1026
#define R_AARCH64_RELATIVE_ 1027

typedef struct {
    char*      name;
    void*      addr;
} NameEnt;

struct elf_image {
    uint8_t*     base;
    size_t       span;
    Ehdr64       eh;
    Phdr64*      ph;
    Dyn64*       dyn;
    Sym64*       symtab;
    const char*  strtab;
    size_t       symcount;
    void*        init_array;   // 绝对地址
    size_t       init_array_sz;
    void*        init_fn;
    void*        entry;
    NameEnt*     unresolved;
    size_t       unresolved_n, unresolved_cap;
    int          dirty;
};

static int add_unresolved(elf_image* img, const char* name) {
    for (size_t i = 0; i < img->unresolved_n; ++i)
        if (!strcmp(img->unresolved[i].name, name)) return 0;
    if (img->unresolved_n == img->unresolved_cap) {
        size_t cap = img->unresolved_cap ? img->unresolved_cap * 2 : 64;
        NameEnt* p = (NameEnt*)realloc(img->unresolved, cap * sizeof(NameEnt));
        if (!p) return -1;
        img->unresolved = p;
        img->unresolved_cap = cap;
    }
    img->unresolved[img->unresolved_n].name = strdup(name);
    img->unresolved[img->unresolved_n].addr = 0;
    img->unresolved_n++;
    return 0;
}

static uint64_t page_down(uint64_t v) { return v & ~(uint64_t)0xfff; }
static uint64_t page_up(uint64_t v) { return (v + 0xfff) & ~(uint64_t)0xfff; }

int elf_load(const char* path, const uint64_t* preferred_base, elf_resolver shim_lookup,
             elf_image** out, struct elf_stats* st) {
    if (!path || !out) return -1;
    memset(st, 0, sizeof(*st));

    int fd = open(path, O_RDONLY);
    if (fd < 0) { fprintf(stderr, "[elf] open %s: %s\n", path, strerror(errno)); return -1; }
    off_t fsz = lseek(fd, 0, SEEK_END);
    if (fsz <= 0) { close(fd); return -1; }
    void* fmap = mmap(NULL, (size_t)fsz, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (fmap == MAP_FAILED) { fprintf(stderr, "[elf] mmap file failed\n"); return -1; }

    elf_image* img = (elf_image*)calloc(1, sizeof(elf_image));
    if (!img) { munmap(fmap, (size_t)fsz); return -1; }
    memcpy(&img->eh, fmap, sizeof(Ehdr64));

    if (memcmp(img->eh.e_ident, "\177ELF", 4) != 0 || img->eh.e_ident[4] != 2) {
        fprintf(stderr, "[elf] not ELF64\n"); goto fail;
    }
    if (img->eh.e_machine != 183) {  // EM_AARCH64
        fprintf(stderr, "[elf] machine=%u (want 183/AArch64)\n", img->eh.e_machine); goto fail;
    }
    img->ph = (Phdr64*)calloc(img->eh.e_phnum, sizeof(Phdr64));
    memcpy(img->ph, (uint8_t*)fmap + img->eh.e_phoff, img->eh.e_phnum * sizeof(Phdr64));

    // 计算跨度
    uint64_t lo = ~0ULL, hi = 0;
    for (int i = 0; i < img->eh.e_phnum; ++i) {
        Phdr64* p = &img->ph[i];
        if (p->p_type != PT_LOAD_) continue;
        if (p->p_vaddr < lo) lo = page_down(p->p_vaddr);
        if (p->p_vaddr + p->p_memsz > hi) hi = page_up(p->p_vaddr + p->p_memsz);
        st->load_segments++;
    }
    if (lo >= hi) { fprintf(stderr, "[elf] no PT_LOAD\n"); goto fail; }
    img->span = (size_t)(hi - lo);

    uint64_t want = preferred_base ? *preferred_base : 0;
    void* mem = NULL;
    if (want) {
        mem = mmap((void*)(uintptr_t)want, img->span, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
        if (mem == MAP_FAILED) {
            fprintf(stderr, "[elf] fixed mmap 0x%llx failed, fallback\n", (unsigned long long)want);
            mem = NULL;
        }
    }
    if (!mem) {
        mem = mmap(NULL, img->span, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    }
    if (mem == MAP_FAILED) { fprintf(stderr, "[elf] mmap %zu failed\n", img->span); goto fail; }
    img->base = (uint8_t*)mem;
    st->mapped_bytes = img->span;
    fprintf(stderr, "[elf] base=0x%llx span=0x%zx lo=0x%llx\n",
            (unsigned long long)(uintptr_t)img->base, img->span, (unsigned long long)lo);

    // 拷贝段
    for (int i = 0; i < img->eh.e_phnum; ++i) {
        Phdr64* p = &img->ph[i];
        if (p->p_type != PT_LOAD_) continue;
        uint8_t* dst = img->base + (p->p_vaddr - lo);
        if (p->p_filesz) memcpy(dst, (uint8_t*)fmap + p->p_offset, (size_t)p->p_filesz);
        if (p->p_memsz > p->p_filesz)
            memset(dst + p->p_filesz, 0, (size_t)(p->p_memsz - p->p_filesz));
    }
    // 段基址修正量：ELF 里符号值都是相对 lo 的（vaddr 是 link-time）
    img->entry = img->base + (img->eh.e_entry - lo);

    // PT_DYNAMIC
    for (int i = 0; i < img->eh.e_phnum; ++i) {
        Phdr64* p = &img->ph[i];
        if (p->p_type != PT_DYNAMIC_) continue;
        img->dyn = (Dyn64*)(img->base + (p->p_vaddr - lo));
    }
    if (!img->dyn) { fprintf(stderr, "[elf] no PT_DYNAMIC\n"); goto fail; }

    uint64_t stra = 0, syma = 0, rela = 0, relasz = 0, jmprel = 0, pltsz = 0;
    int pltrel = 0;
    for (Dyn64* d = img->dyn; d->d_tag != DT_NULL_; ++d) {
        switch (d->d_tag) {
            case DT_STRTAB_: stra = d->d_val; break;
            case DT_SYMTAB_: syma = d->d_val; break;
            case DT_RELA_: rela = d->d_val; break;
            case DT_RELASZ_: relasz = d->d_val; break;
            case DT_JMPREL_: jmprel = d->d_val; break;
            case DT_PLTRELSZ_: pltsz = d->d_val; break;
            case DT_PLTREL_: pltrel = (int)d->d_val; break;
            case DT_INIT_ARRAY_: img->init_array = img->base + (d->d_val - lo); break;
            case DT_INIT_ARRAYSZ_: img->init_array_sz = (size_t)d->d_val; break;
            case DT_INIT_: img->init_fn = img->base + (d->d_val - lo); break;
            default: break;
        }
    }
    img->strtab = (const char*)(img->base + (stra - lo));
    img->symtab = (Sym64*)(img->base + (syma - lo));
    // 符号个数：用 .rela 里最大符号索引估算（无 hash 也够用）
    size_t maxsym = 0;
    uint64_t all_rela[2] = {rela, jmprel};
    uint64_t all_size[2] = {relasz, pltsz};
    for (int k = 0; k < 2; ++k) {
        if (!all_rela[k]) continue;
        Rela64* r = (Rela64*)(img->base + (all_rela[k] - lo));
        size_t cnt = (size_t)(all_size[k] / sizeof(Rela64));
        for (size_t i = 0; i < cnt; ++i) {
            size_t si = (size_t)(r[i].r_info >> 32);
            if (si > maxsym) maxsym = si;
        }
    }
    img->symcount = maxsym + 1;
    fprintf(stderr, "[elf] dynsym≈%zu strtab=0x%llx rela=0x%llx jmprel=0x%llx\n",
            img->symcount, (unsigned long long)stra, (unsigned long long)rela,
            (unsigned long long)jmprel);

    // 解析未定义符号
    void** symcache = (void**)calloc(img->symcount, sizeof(void*));
    for (size_t i = 0; i < img->symcount; ++i) {
        Sym64* s = &img->symtab[i];
        if (s->st_shndx != 0 || s->st_name == 0) continue;
        const char* name = img->strtab + s->st_name;
        void* a = shim_lookup ? shim_lookup(name) : NULL;
        if (a) { st->resolved_shim++; }
        if (!a) { a = dlsym(RTLD_DEFAULT, name); if (a) st->resolved_dlsym++; }
        if (!a) { st->unresolved++; add_unresolved(img, name); }
        symcache[i] = a;
    }

    // 应用重定位
    for (int k = 0; k < 2; ++k) {
        if (!all_rela[k]) continue;
        if (k == 1 && pltrel != 7) { /* 非 RELA 的 PLT 不处理 */ }
        Rela64* r = (Rela64*)(img->base + (all_rela[k] - lo));
        size_t cnt = (size_t)(all_size[k] / sizeof(Rela64));
        for (size_t i = 0; i < cnt; ++i) {
            uint32_t type = (uint32_t)(r[i].r_info & 0xffffffffu);
            uint32_t sym = (uint32_t)(r[i].r_info >> 32);
            uint8_t* place = img->base + ((r[i].r_offset) - lo);
            uint64_t val = 0;
            switch (type) {
                case R_AARCH64_RELATIVE_:
                    val = (uint64_t)(uintptr_t)img->base + (uint64_t)r[i].r_addend;
                    st->relocs_relative++;
                    break;
                case R_AARCH64_ABS64_:
                case R_AARCH64_GLOB_DAT_:
                case R_AARCH64_JUMP_SLOT_:
                    val = (uint64_t)(uintptr_t)(sym < img->symcount ? symcache[sym] : NULL);
                    if (!val) { st->unresolved++; add_unresolved(img, "(slot)"); }
                    val += (uint64_t)r[i].r_addend;
                    st->relocs_symbolic++;
                    break;
                case R_AARCH64_PREL32_: {
                    uint64_t t = (uint64_t)(uintptr_t)(sym < img->symcount ? symcache[sym] : NULL);
                    int32_t v32 = (int32_t)((int64_t)(t + (uint64_t)r[i].r_addend) - (int64_t)(uintptr_t)place);
                    memcpy(place, &v32, 4);
                    st->relocs_symbolic++;
                    continue;
                }
                default:
                    continue;  // TLS 等一律跳过
            }
            memcpy(place, &val, 8);
        }
    }
    free(symcache);

    // 代码段设为 RX
    for (int i = 0; i < img->eh.e_phnum; ++i) {
        Phdr64* p = &img->ph[i];
        if (p->p_type != PT_LOAD_) continue;
        if (!(p->p_flags & 1)) continue;  // 非 PF_X
        uint8_t* s = img->base + page_down(p->p_vaddr - lo);
        size_t len = (size_t)(page_up(p->p_vaddr + p->p_memsz) - page_down(p->p_vaddr));
        if (mprotect(s, len, PROT_READ | PROT_EXEC) != 0) {
            fprintf(stderr, "[elf] mprotect RX failed (ok on iOS without JIT)\n");
        }
    }
    munmap(fmap, (size_t)fsz);
    *out = img;
    return 0;

fail:
    munmap(fmap, (size_t)fsz);
    free(img);
    return -1;
}

void* elf_lookup(elf_image* img, const char* name) {
    if (!img || !name) return NULL;
    for (size_t i = 0; i < img->symcount; ++i) {
        Sym64* s = &img->symtab[i];
        if (!s->st_name || s->st_shndx == 0) continue;
        if (!strcmp(img->strtab + s->st_name, name))
            return img->base + (s->st_value);
    }
    return NULL;
}

void elf_each_unresolved(elf_image* img, int (*cb)(const char*, void*), void* ud) {
    if (!img) return;
    for (size_t i = 0; i < img->unresolved_n; ++i)
        if (cb(img->unresolved[i].name, ud)) return;
}

void* elf_entry(elf_image* img) { return img ? img->entry : NULL; }

int elf_run_init_array(elf_image* img) {
    if (!img) return -1;
    int n = 0;
    if (img->init_fn) {
        ((void (*)(void))img->init_fn)();
        n++;
    }
    if (img->init_array && img->init_array_sz) {
        size_t cnt = img->init_array_sz / sizeof(void*);
        void** a = (void**)img->init_array;
        for (size_t i = 0; i < cnt; ++i) {
            if (!a[i]) continue;
            ((void (*)(void))a[i])();
            n++;
        }
    }
    return n;
}
