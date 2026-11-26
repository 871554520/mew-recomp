// libbionic_shim —— Android NDK (Bionic) ABI 到 Apple Darwin 的适配层
// 只覆盖 libmew_relinked.dylib 里「非 SDL3 / 非直连」的 132 个符号。
#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------- Bionic 结构体尺寸（AArch64 Android） ----------------
// pthread_mutex_t 40B / pthread_cond_t 48B / pthread_rwlock_t 56B / pthread_attr_t 56B
#define BIONIC_MUTEX_SIZE   40
#define BIONIC_COND_SIZE    48
#define BIONIC_RWLOCK_SIZE  56
#define BIONIC_ATTR_SIZE    56
#define BIONIC_MUTEX_INIT   0x40000000u   // Bionic PTHREAD_MUTEX_INITIALIZER 首个 word

// ---------------- Bionic errno 数值（与 Darwin 不同的那几个） ----------------
// Darwin:  EAGAIN 35, EDEADLK 11, ETIMEDOUT 60, ENOTSUP 45, EOPNOTSUPP 102
// Linux:   EAGAIN 11, EDEADLK 35, ETIMEDOUT 110, ENOTSUP 95, EOPNOTSUPP 95
int *bionic_errno_slot(void);            // 返回线程局部 int*（Bionic 语义）
int  darwin_to_bionic_errno(int d);
int  bionic_to_darwin_errno(int b);

// ---------------- Bionic 结构体（只列用到的字段布局） ----------------
// Linux arm64 struct stat（132B）
struct bionic_stat {
    uint64_t st_dev;
    uint64_t st_ino;
    uint32_t st_mode;
    uint32_t st_nlink;
    uint32_t st_uid;
    uint32_t st_gid;
    uint64_t st_rdev;
    uint64_t __pad1;
    int64_t  st_size;
    int32_t  st_blksize;
    int32_t  __pad2;
    int64_t  st_blocks;
    int64_t  st_atime;
    uint64_t st_atime_nsec;
    int64_t  st_mtime;
    uint64_t st_mtime_nsec;
    int64_t  st_ctime;
    uint64_t st_ctime_nsec;
    uint32_t __unused4;
    uint32_t __unused5;
};

// Linux arm64 struct dirent（d_name 256B）
struct bionic_dirent {
    uint64_t d_ino;
    int64_t  d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[256];
};

// Linux arm64 statvfs
struct bionic_statvfs {
    uint64_t f_bsize, f_frsize, f_blocks, f_bfree, f_bavail;
    uint64_t f_files, f_ffree, f_favail, f_fsid, f_flag, f_namemax;
    uint32_t __f_spare[6];
};

#ifdef __cplusplus
}
#endif
