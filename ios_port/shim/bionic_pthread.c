// Bionic pthread (40B mutex) -> Darwin pthread（64B）的安全间接层
// 关键点：不能把 Bionic 的 40 字节块直接当 Darwin 的 64 字节对象用，否则会踩爆相邻 24 字节。
// 做法：在调用方给的那 40 字节里放 {magic, real_ptr}，真对象 malloc 在堆上。
#include "bionic_shim.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <stdio.h>

#define KIND_MUTEX 0x4D58u   // 'MX'
#define KIND_COND  0x4344u   // 'CD'
#define KIND_RW    0x5257u   // 'RW'
#define MAGIC(k)   (0x4D45570000000000ULL | (uint64_t)(k))

typedef struct {
    uint64_t magic;
    void*    real;     // 指向堆上的 Darwin pthread_*_t
} bionic_slot;

static pthread_mutex_t g_guard = PTHREAD_MUTEX_INITIALIZER;

static void* slot_ensure(void* bionic_obj, unsigned kind, size_t real_size, int* created) {
    bionic_slot* s = (bionic_slot*)bionic_obj;
    const uint64_t want = MAGIC(kind);
    if (__builtin_expect(s->magic == want && s->real != NULL, 1)) {
        if (created) *created = 0;
        return s->real;
    }
    pthread_mutex_lock(&g_guard);
    if (s->magic != want || s->real == NULL) {
        void* real = calloc(1, real_size);
        s->real = real;
        atomic_thread_fence(memory_order_release);
        s->magic = want;
        if (created) *created = 1;
    } else if (created) {
        *created = 0;
    }
    pthread_mutex_unlock(&g_guard);
    return s->real;
}

static void slot_destroy(void* bionic_obj, unsigned kind) {
    bionic_slot* s = (bionic_slot*)bionic_obj;
    if (s->magic == MAGIC(kind) && s->real) {
        free(s->real);
        s->real = NULL;
        s->magic = 0;
    }
}

// ---------------- mutex ----------------
int bionic_pthread_mutex_init(void* m, const void* attr) {
    (void)attr;
    if (!m) return 22;
    memset(m, 0, BIONIC_MUTEX_SIZE);
    int created = 0;
    pthread_mutex_t* real = (pthread_mutex_t*)slot_ensure(m, KIND_MUTEX, sizeof(pthread_mutex_t), &created);
    if (!real) return 12;
    if (created) {
        pthread_mutexattr_t a;
        pthread_mutexattr_init(&a);
        // Bionic 静态初始化常见递归语义，统一给递归锁最安全
        pthread_mutexattr_settype(&a, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(real, &a);
        pthread_mutexattr_destroy(&a);
    }
    return 0;
}
int bionic_pthread_mutex_lock(void* m) {
    pthread_mutex_t* real = (pthread_mutex_t*)slot_ensure(m, KIND_MUTEX, sizeof(pthread_mutex_t), NULL);
    if (!real) return 22;
    return pthread_mutex_lock(real) == 0 ? 0 : 22;
}
int bionic_pthread_mutex_trylock(void* m) {
    pthread_mutex_t* real = (pthread_mutex_t*)slot_ensure(m, KIND_MUTEX, sizeof(pthread_mutex_t), NULL);
    if (!real) return 22;
    return pthread_mutex_trylock(real) == 0 ? 0 : 11;   // EBUSY(bionic 16)->EAGAIN? 这里给 bionic EBUSY=16
}
int bionic_pthread_mutex_unlock(void* m) {
    pthread_mutex_t* real = (pthread_mutex_t*)slot_ensure(m, KIND_MUTEX, sizeof(pthread_mutex_t), NULL);
    if (!real) return 22;
    return pthread_mutex_unlock(real) == 0 ? 0 : 22;
}
int bionic_pthread_mutex_destroy(void* m) {
    if (!m) return 22;
    pthread_mutex_t* real = (pthread_mutex_t*)slot_ensure(m, KIND_MUTEX, sizeof(pthread_mutex_t), NULL);
    if (real) pthread_mutex_destroy(real);
    slot_destroy(m, KIND_MUTEX);
    return 0;
}

// ---------------- cond ----------------
int bionic_pthread_cond_init(void* c, const void* attr) {
    (void)attr;
    if (!c) return 22;
    memset(c, 0, BIONIC_COND_SIZE);
    int created = 0;
    pthread_cond_t* real = (pthread_cond_t*)slot_ensure(c, KIND_COND, sizeof(pthread_cond_t), &created);
    if (!real) return 12;
    if (created) pthread_cond_init(real, NULL);
    return 0;
}
int bionic_pthread_cond_destroy(void* c) {
    pthread_cond_t* real = (pthread_cond_t*)slot_ensure(c, KIND_COND, sizeof(pthread_cond_t), NULL);
    if (real) pthread_cond_destroy(real);
    slot_destroy(c, KIND_COND);
    return 0;
}
int bionic_pthread_cond_signal(void* c) {
    pthread_cond_t* real = (pthread_cond_t*)slot_ensure(c, KIND_COND, sizeof(pthread_cond_t), NULL);
    return real ? pthread_cond_signal(real) : 22;
}
int bionic_pthread_cond_broadcast(void* c) {
    pthread_cond_t* real = (pthread_cond_t*)slot_ensure(c, KIND_COND, sizeof(pthread_cond_t), NULL);
    return real ? pthread_cond_broadcast(real) : 22;
}
int bionic_pthread_cond_wait(void* c, void* m) {
    pthread_cond_t* rc = (pthread_cond_t*)slot_ensure(c, KIND_COND, sizeof(pthread_cond_t), NULL);
    pthread_mutex_t* rm = (pthread_mutex_t*)slot_ensure(m, KIND_MUTEX, sizeof(pthread_mutex_t), NULL);
    if (!rc || !rm) return 22;
    return pthread_cond_wait(rc, rm) == 0 ? 0 : 22;
}
int bionic_pthread_cond_timedwait(void* c, void* m, const struct timespec* abstime) {
    pthread_cond_t* rc = (pthread_cond_t*)slot_ensure(c, KIND_COND, sizeof(pthread_cond_t), NULL);
    pthread_mutex_t* rm = (pthread_mutex_t*)slot_ensure(m, KIND_MUTEX, sizeof(pthread_mutex_t), NULL);
    if (!rc || !rm) return 22;
    // 注意：Linux 的 CLOCK_MONOTONIC 与 Darwin 的 CLOCK_REALTIME 不同，这里直接透传，P2 再校时基
    int r = pthread_cond_timedwait(rc, rm, abstime);
    return r == 0 ? 0 : (r == ETIMEDOUT ? 110 : 22);
}

// ---------------- rwlock ----------------
int bionic_pthread_rwlock_rdlock(void* l) {
    pthread_rwlock_t* real = (pthread_rwlock_t*)slot_ensure(l, KIND_RW, sizeof(pthread_rwlock_t), NULL);
    return real ? pthread_rwlock_rdlock(real) : 22;
}
int bionic_pthread_rwlock_wrlock(void* l) {
    pthread_rwlock_t* real = (pthread_rwlock_t*)slot_ensure(l, KIND_RW, sizeof(pthread_rwlock_t), NULL);
    return real ? pthread_rwlock_wrlock(real) : 22;
}
int bionic_pthread_rwlock_unlock(void* l) {
    pthread_rwlock_t* real = (pthread_rwlock_t*)slot_ensure(l, KIND_RW, sizeof(pthread_rwlock_t), NULL);
    return real ? pthread_rwlock_unlock(real) : 22;
}

// ---------------- 直接透传的那些（签名/AArch64 约定一致） ----------------
int bionic_pthread_create(pthread_t* t, const void* attr, void* (*fn)(void*), void* arg) {
    return pthread_create(t, (const pthread_attr_t*)attr, fn, arg);
}
int bionic_pthread_join(pthread_t t, void** r) { return pthread_join(t, r); }
int bionic_pthread_detach(pthread_t t) { return pthread_detach(t); }
void bionic_pthread_exit(void* r) { pthread_exit(r); }
pthread_t bionic_pthread_self(void) { return pthread_self(); }
int bionic_pthread_once(void* once, void (*fn)(void)) { return pthread_once((pthread_once_t*)once, fn); }
int bionic_pthread_key_create(unsigned* k, void (*dtor)(void*)) { return pthread_key_create(k, dtor); }
int bionic_pthread_key_delete(unsigned k) { return pthread_key_delete(k); }
void* bionic_pthread_getspecific(unsigned k) { return pthread_getspecific(k); }
int bionic_pthread_setspecific(unsigned k, const void* v) { return pthread_setspecific(k, v); }

int bionic_pthread_attr_init(void* a) {
    memset(a, 0, BIONIC_ATTR_SIZE);
    return pthread_attr_init((pthread_attr_t*)a) == 0 ? 0 : 22;
}
int bionic_pthread_attr_destroy(void* a) { return pthread_attr_destroy((pthread_attr_t*)a); }
int bionic_pthread_attr_setdetachstate(void* a, int s) {
    return pthread_attr_setdetachstate((pthread_attr_t*)a, s) == 0 ? 0 : 22;
}
int bionic_pthread_attr_setstacksize(void* a, size_t s) {
    return pthread_attr_setstacksize((pthread_attr_t*)a, s) == 0 ? 0 : 22;
}
int bionic_pthread_mutexattr_init(void* a) { return pthread_mutexattr_init((pthread_mutexattr_t*)a); }
int bionic_pthread_mutexattr_destroy(void* a) { return pthread_mutexattr_destroy((pthread_mutexattr_t*)a); }
int bionic_pthread_mutexattr_settype(void* a, int t) {
    // Bionic 的 PTHREAD_MUTEX_RECURSIVE 与 Darwin 数值不同（bionic 1 / darwin 2）
    int dt = (t == 1) ? PTHREAD_MUTEX_RECURSIVE : PTHREAD_MUTEX_NORMAL;
    return pthread_mutexattr_settype((pthread_mutexattr_t*)a, dt);
}
