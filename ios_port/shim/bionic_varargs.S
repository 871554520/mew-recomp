// 变参桥：Bionic(ELF, AAPCS64) -> Darwin
//   AAPCS64 : 整数 x0..x7，浮点 d0..d7
//   Darwin  : va_list 是扁平 char*，所有参数按格式串顺序连续排 8 字节槽
// 做法：把 x0..x7 / d0..d7 各溢写到栈上两块槽，交给 C 侧的 mew_vararg_build 重排。
    .text
    .p2align 2

.macro VARARG_THUNK name, target
    .globl _bionic_\name
_bionic_\name:
    sub  sp, sp, #0x120
    stp  x0, x1, [sp, #0x00]
    stp  x2, x3, [sp, #0x10]
    stp  x4, x5, [sp, #0x20]
    stp  x6, x7, [sp, #0x30]
    stp  d0, d1, [sp, #0x80]
    stp  d2, d3, [sp, #0x90]
    stp  d4, d5, [sp, #0xa0]
    stp  d6, d7, [sp, #0xb0]
    add  x0, sp, #0x00      // x_slots
    add  x1, sp, #0x80      // d_slots
    bl   _\target
    add  sp, sp, #0x120
    ret
.endm

VARARG_THUNK snprintf, mew_vararg_snprintf
VARARG_THUNK __android_log_print, mew_vararg_android_log_print
