"""ff25 型 import thunk 的形状判定（可单测，不依赖 lief / PE）。

背景（run 45999239672）：0x140bf4fc0/4fd0/4fe0/4ff0 是四个 16 字节一格的
import thunk，`.text` 内、没有 .pdata。旧的挖掘规则只认 `48 85 /r` 开头的守卫形态，
于是同一串里有的收、有的漏；漏掉的那个在运行期就是一次
`[FATAL] Unmapped indirect target`。这里把判定抽成纯函数并覆盖三种实测形态。
"""
from __future__ import annotations


def import_thunk_shape(buf, p: int, size: int = 16) -> bool:
    """buf[p:p+size] 是否是 ff25 型 import thunk。

    实测形状：
      A) `48 ff 25 <rel32>` + `c3`                    纯尾跳
      B) `48 85 /r` + `74 07` + `48 ff 25 <rel32>` + `c3`
         test r,r / je 跳过尾跳 / jmp qword [rip+rel32] / ret —— 空指针守卫
      C) 同 B 但条件是 `75`（jne）—— 反向守卫，少见但一并认
    精度靠调用方再查 16 对齐 + 不在已知函数内 + 槽尾落在终止符上。
    """
    slot = buf[p:p + size]
    if len(slot) < 8:
        return False
    for off in (0, 5):
        if len(slot) < off + 7:
            continue
        if slot[off:off + 3] != b'\x48\xff\x25':
            continue
        if off == 5:                       # 守卫形态：test r,r / jcc
            if slot[0] != 0x48 or slot[1] != 0x85:
                continue
            if slot[3] not in (0x74, 0x75):
                continue
            tgt = 7 + slot[4]              # jcc 后下一条在 offset 5，再加 imm8
            if tgt < size and slot[tgt] not in (0xC3, 0xCC):
                continue
        end = off + 7
        if end < size and slot[end] not in (0xC3, 0xCC, 0x00):
            continue
        return True
    return False
