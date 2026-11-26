// libmewcompat：补齐两个「游戏确实要、现有库却没有」的符号。
//
// 为什么需要这个库（两条都是**加载期强绑定**，缺一个 dyld 就直接
// "symbol not found"，dlopen 返回 0，真机表现就是卡在 [host 3b]）：
//
//   1) _bionic_tlsdesc_resolver
//      libmain.so 有 14 条 R_AARCH64_TLSDESC，转换器把它们写成绑定到
//      @rpath/libbionic_shim.dylib 的这个符号。仓库源码（ios_port/shim/
//      bionic_tlsdesc.S）里是有的，但 Release 资产 mac-products-v1 里的 shim
//      是更早的构建，导出表/符号表里都查不到它（实测 symtab 318 条里只有
//      _bionic_tlsdesc_get_offset）。所以把这一段搬到本库来，不依赖 shim 重建。
//      寄存器保全在 asm 侧（直接复用 ios_port/shim/bionic_tlsdesc.S），
//      这里只做「槽偏移 + 线程块基址 - tpidr_el0」的地址换算。
//
//   2) _SDL_StretchSurface
//      游戏自带的安卓 SDL3 是 3.2.12 开发版（有它），我们打的 iOS SDL3 是
//      release-3.2.0（没有）。SDL 官方实现（src/video/SDL_stretch.c）就是
//      「校验矩形 + 加锁 + 按 scaleMode 缩放 blit」，而 3.2.0 已经有等价入口
//      SDL_BlitSurfaceScaled()，所以这里如实转调，不假装成功。
//
// 约定：不用任何 Apple 头（无 SDK 构建），原型全部自己声明——和 host_nosdk.c 同一套做法。
// 构建：ios_port/build_compat_linux.sh（clang -target arm64-apple-ios15.0 + ld64.lld）

// ---------------- libSystem（Darwin）原型 ----------------
typedef unsigned long pthread_key_t;    // Darwin: unsigned long（8 字节）
typedef unsigned long pthread_once_t;   // Darwin: long，PTHREAD_ONCE_INIT = 0

extern int pthread_once(pthread_once_t *once_control, void (*init_routine)(void));
extern int pthread_key_create(pthread_key_t *key, void (*destructor)(void *));
extern void *pthread_getspecific(pthread_key_t key);
extern int pthread_setspecific(pthread_key_t key, const void *value);
extern void *calloc(unsigned long count, unsigned long size);
extern void free(void *ptr);

// ---------------- 1) TLSDESC 槽地址换算 ----------------
// libmain.so 的 .tbss 只有 0x501 字节且全零初始化，所以给每个线程一块固定块即可。
static pthread_key_t g_tls_key;
static pthread_once_t g_tls_once = 0;

static void mew_tls_key_init(void) {
    pthread_key_create(&g_tls_key, free);
}

// 返回「目标地址 - tpidr_el0」：ELF AArch64 TLSDESC 的返回约定。
// slot_offset 取自描述符 [slot+8]（转换器写入的 .tbss 内偏移）。
unsigned long bionic_tlsdesc_get_offset(unsigned long slot_offset, unsigned long cur_tpidr) {
    pthread_once(&g_tls_once, mew_tls_key_init);
    unsigned char *blk = (unsigned char *)pthread_getspecific(g_tls_key);
    if (!blk) {
        blk = (unsigned char *)calloc(1, 0x1000);
        if (!blk) {
            return 0;   // 分配失败：返回 0 会让调用方算出 tpidr 本身，属于显式失败
        }
        pthread_setspecific(g_tls_key, blk);
    }
    return (unsigned long)(blk + slot_offset) - cur_tpidr;
}

// ---------------- 2) SDL_StretchSurface ----------------
typedef struct SDL_Surface SDL_Surface;
typedef struct SDL_Rect { int x, y, w, h; } SDL_Rect;
typedef int SDL_ScaleMode;   // SDL_SCALEMODE_NEAREST=0, SDL_SCALEMODE_LINEAR=1

extern _Bool SDL_BlitSurfaceScaled(SDL_Surface *src, const SDL_Rect *srcrect,
                                   SDL_Surface *dst, const SDL_Rect *dstrect,
                                   SDL_ScaleMode scaleMode);

// SDL 3.4 的 SDL_StretchSurface：带缩放模式的拉伸 blit。
// 3.2.0 的 SDL_BlitSurfaceScaled 做的是同一件事（同样的 5 个参数、同样校验矩形）。
_Bool SDL_StretchSurface(SDL_Surface *src, const SDL_Rect *srcrect,
                         SDL_Surface *dst, const SDL_Rect *dstrect,
                         SDL_ScaleMode scaleMode) {
    return SDL_BlitSurfaceScaled(src, srcrect, dst, dstrect, scaleMode);
}
