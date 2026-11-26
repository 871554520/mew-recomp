// TLSDESC：libmain.so 的 .tbss 只有 0x501 字节且全零初始化。
// ELF 的 TLSDESC resolver 约定：返回 目标地址 - tpidr_el0。
#include "bionic_shim.h"
#include <pthread.h>
#include <stdlib.h>

static pthread_key_t g_key;
static pthread_once_t g_once = PTHREAD_ONCE_INIT;
static void init_key(void) { pthread_key_create(&g_key, free); }

uint64_t bionic_tlsdesc_get_offset(uint64_t slot_offset, uint64_t cur_tpidr) {
    pthread_once(&g_once, init_key);
    unsigned char* blk = (unsigned char*)pthread_getspecific(g_key);
    if (!blk) { blk = (unsigned char*)calloc(1, 0x1000); pthread_setspecific(g_key, blk); }
    return (uint64_t)(blk + slot_offset) - cur_tpidr;
}
