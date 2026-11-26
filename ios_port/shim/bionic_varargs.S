// 变参函数桥：Bionic(ELF, AAPCS64) -> Darwin
// 问题：AAPCS64 变参走 x0..x7，Darwin arm64 变参全在栈上且 va_list 是 char*。
// 计法：调用方按 AAPCS64 传参 → 我们把 x1..x7 溢写到栈上的连续 8 字节槽，
//       再把这块内存当作 Darwin 的 va_list 交给 C 侧转发。
// TODO(P2)：浮点变参需要额外保存 q0..q7，先留位置。
    .text
    .p2align 2

// void mew_vararg_thunk(struct Spill* s, void* fn, uint64_t x0, x1..x7)
.macro VARARG_THUNK name, target
    .globl _bionic_\name
_bionic_\name:
    sub  sp, sp, #0x60
    stp  x0, x1, [sp, #0x00]
    stp  x2, x3, [sp, #0x10]
    stp  x4, x5, [sp, #0x20]
    stp  x6, x7, [sp, #0x30]
    mov  x0, sp              // args 数组首地址
    bl   _\target
    add  sp, sp, #0x60
    ret
.endm

// 先只落两个最常用的骨架（其余同步照抄即可）
VARARG_THUNK snprintf, mew_vararg_snprintf
VARARG_THUNK __android_log_print, mew_vararg_android_log_print
