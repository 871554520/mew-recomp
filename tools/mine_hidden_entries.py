#!/usr/bin/env python3
"""手册 Prompt 2：从 .reloc(DIR64) + CFG GFIDS 静态挖出指向 .text 的隐藏入口"""
import bisect
import json
import struct
import sys

import lief

pe_path = sys.argv[1]
meta_path = sys.argv[2] if len(sys.argv) > 2 else None
out_path = sys.argv[3] if len(sys.argv) > 3 else 'generated/extra_seeds.txt'

binary = lief.PE.parse(pe_path)
image_base = binary.optional_header.imagebase
text_sec = binary.get_section('.text')
text_start = image_base + text_sec.virtual_address
text_end = text_start + text_sec.virtual_size

known = set()
if meta_path:
    try:
        meta = json.load(open(meta_path, encoding='utf-8'))
        known = {int(f['va']) if isinstance(f, dict) else int(f) for f in meta.get('functions', [])}
    except Exception as e:
        print('meta load failed:', e)

seeds = set()

# GFIDS
try:
    lc = binary.load_configuration if binary.has_configuration else None
    if lc is not None:
        for rva in getattr(lc, 'guard_cf_functions', []) or []:
            va = image_base + int(rva)
            if text_start <= va < text_end and va not in known:
                seeds.add(va)
except Exception:
    pass

# .reloc DIR64 槽位里的 64 位值
n_reloc = 0
for reloc in binary.relocations:
    page = reloc.virtual_address
    for entry in reloc.entries:
        typ = int(getattr(entry, 'type', 0))
        if typ != int(lief.PE.RelocationEntry.BASE_TYPES.DIR64):
            continue
        n_reloc += 1
        slot = page + int(getattr(entry, 'position', 0))
        raw = binary.get_content_from_virtual_address(slot, 8)
        if len(raw) != 8:
            continue
        val = struct.unpack('<Q', bytes(raw))[0]
        if text_start <= val < text_end and val not in known:
            seeds.add(val)

# 对齐填充后的隐藏入口：MSVC 会用 `cc` 拉起对齐，紧随其后的代码常常是
# 没有 .pdata 登记的 thunk（例如 0x140d578c0: xor r8d,r8d; xor edx,edx; jmp ...）。
# 这类入口纯 .pdata/.reloc 都挖不到，但占位率与运行期 miss 主要就来自它们。
n_pad = 0
# 已登记函数的区间：填充候选如果落在某个 .pdata 区间内部，那它只是函数体内的
# 对齐填充，不是新入口（误收会让生成器对同一 VA 生成两种长度）。
pdata_ranges = []
try:
    pd_sec = binary.get_section('.pdata')
    if pd_sec is not None:
        pd_raw = bytes(binary.get_content_from_virtual_address(
            image_base + pd_sec.virtual_address, pd_sec.virtual_size or pd_sec.sizeof_raw_data))
        for k in range(0, len(pd_raw) - 11, 12):
            b, e, _u = struct.unpack_from('<III', pd_raw, k)
            if b or e:
                pdata_ranges.append((image_base + b, image_base + e))
        pdata_ranges.sort()
except Exception as exc:  # noqa: BLE001
    print('pdata range scan failed:', exc)

# 注意：这个判定在 thunk 那一步里会被调用近百万次（.text 按 16 字节步进），
# 用线性扫 5.5 万条 .pdata 会直接跑成几十分钟（真踩过：stage3 的
# 「Mine hidden entries」一步挂住 11 分钟没动）。所以改成二分。
_pd_starts = [lo for lo, _hi in pdata_ranges]


def _inside_known(va):
    if not pdata_ranges:
        return False
    i = bisect.bisect_right(_pd_starts, va) - 1
    return i >= 0 and pdata_ranges[i][0] <= va < pdata_ranges[i][1]


try:
    text_bytes = bytes(binary.get_content_from_virtual_address(text_start, len_range := text_end - text_start))
    i = 0
    limit = len(text_bytes)
    while i < limit:
        if text_bytes[i] != 0xCC:
            i += 1
            continue
        j = i
        while j < limit and text_bytes[j] == 0xCC:
            j += 1
        run = j - i
        if run >= 3 and j < limit and n_pad < 30000:
            va = text_start + j
            # 8 对齐就够了：MSVC 的「跳转 thunk 表」每项只有 8 字节
            # （`e9 rel32` + 3 个 cc），表内第 2、3 项是 8 对齐但**不是** 16 对齐。
            # run 45991101871 的三条 FATAL 里有两条正是这种中间项：
            #   0x140d4cb38 (nearest_lo=0x140d4cb30 delta=8)
            #   0x140d3eee8 (nearest_lo=0x140d3eee0 delta=8)
            # 只认 16 对齐就会把它们漏掉，vtable 里换个槽位就是一次 FATAL。
            if va % 8 == 0 and va not in known and va not in seeds and not _inside_known(va):
                seeds.add(va)
                n_pad += 1
        i = j
except Exception as exc:  # noqa: BLE001
    print('padding scan failed:', exc)

# 背靠背对齐 thunk：MSVC 的 C++ 调整器 thunk
# （`lea rcx,[rdx+off]` / `mov rcx,[rdx+off]` / `lea rcx,[rip+off]` + `add rcx,imm` + `jmp rel32`）
# 会按 16 字节对齐**紧挨着排成一串**，段与段之间没有 `cc` 填充——上面那条「≥3 个 cc」的
# 规则正好漏掉它们，只有每串最后一个才会被挖到。
#
# 运行期证据（stage3 run 45985646254，head e412712）：init 链推进到 index=2339 时
#   [FATAL] Unmapped indirect target: 0x140e39c20 (nearest_lo=0x140e39b90 delta=144)
#           in_fn=0x140d4c580
#   同族还有 0x140e39c10 / 0x140e39c00 —— 三个都是这种 thunk（`.text` 内、无 .pdata、
#   16 对齐），而 vtable 里存的就是它们的地址，所以换一个就是一次 FATAL。
# 本地按下面这个形状扫全镜像：7,507 个候选，其中 599 个是现有 seed 没覆盖的。
n_thunk = 0


def _thunk_shape(buf, p):
    """从 p 起按 thunk 形状走，走到 `jmp rel32` 返回其结束偏移，否则 None。"""
    for _ in range(5):
        if p + 1 >= len(buf):
            return None
        b0, b1 = buf[p], buf[p + 1]
        if b0 == 0xE9 and p + 5 <= len(buf):
            return p + 5
        if b0 == 0x48 and b1 in (0x8D, 0x8B) and p + 7 <= len(buf):
            modrm = buf[p + 2]
            if (modrm & 0xC0) == 0x80 or (modrm & 0xC7) == 0x05:
                p += 7
                continue
            return None
        if b0 == 0x48 and b1 == 0x83 and buf[p + 2] in (0xC1, 0xC0) and p + 4 <= len(buf):
            p += 4
            continue
        if b0 == 0x48 and b1 == 0x81 and buf[p + 2] in (0xC1, 0xC0) and p + 7 <= len(buf):
            p += 7
            continue
        return None
    return None


try:
    for k in range(0, len(text_bytes) - 21, 16):
        va = text_start + k
        if va % 16 or va in known or va in seeds or _inside_known(va):
            continue
        if _thunk_shape(text_bytes, k) is not None:
            seeds.add(va)
            n_thunk += 1
except Exception as exc:  # noqa: BLE001
    print('thunk scan failed:', exc)
print('back-to-back thunk-entry candidates:', n_thunk)

# 纯跳转 thunk 表：`e9 rel32` + 3 个 cc，每项 8 字节，表项之间**没有** cc 填充
# （上一项末尾的 3 个 cc 就是下一项的「前置填充」，但如果表项是 5 字节紧凑排布，
#  上一项后面就没有 cc 了）。这条规则按「e9 + 紧随 3 个 cc」精确匹配，8 对齐。
n_jmp = 0
try:
    limit = len(text_bytes) - 8
    for k in range(0, limit):
        if text_bytes[k] != 0xE9:
            continue
        if text_bytes[k + 5:k + 8] != b'\xcc\xcc\xcc':
            continue
        va = text_start + k
        if va % 8 or va in known or va in seeds or _inside_known(va):
            continue
        seeds.add(va)
        n_jmp += 1
except Exception as exc:  # noqa: BLE001
    print('jmp-thunk scan failed:', exc)
print('jmp-thunk (e9+ccc) candidates:', n_jmp)

# 「空指针守卫 + 尾跳函数指针」桩（import/内部指针表 thunk），16 字节一个、16 对齐：
#   48 85 c9           test rcx,rcx          （也有 test rdx/rbx/... 的变体）
#   74 07              je  +7（跳过 jmp，空指针时直接返回）
#   48 ff 25 <rel32>   jmp qword [rip+rel32]
# 关键：尾跳是 **ff 25** 不是 **e9**，所以上面那条 e9 规则看不见它们；
# 而且相邻两个桩之间往往只有 1 个 cc，`>=3 个 cc` 的填充规则也挖不到。
# 运行期证据（run 45999239672）：
#   [FATAL] Unmapped indirect target: 0x140bf4ff0 (nearest_lo=0x140bf4fe0 delta=16)
#   而 manifest 里 0x140bf4fe0=32 —— 长度按「下一个 seed（0x140bf5000）」算，
#   把兄弟桩 0x140bf4ff0 一起吞了，于是调用 0x140bf4ff0 就 miss。
n_ithunk = 0
try:
    for k in range(0, len(text_bytes) - 16):
        if text_bytes[k] != 0x48 or text_bytes[k + 1] != 0x85:
            continue
        if text_bytes[k + 3] != 0x74:
            continue
        if text_bytes[k + 5:k + 8] != b'\x48\xff\x25':
            continue
        va = text_start + k
        if va % 16 or va in known or va in seeds or _inside_known(va):
            continue
        seeds.add(va)
        n_ithunk += 1
except Exception as exc:  # noqa: BLE001
    print('import-thunk scan failed:', exc)
print('import-thunk (test/je/jmp[rip]) candidates:', n_ithunk)

print('padding-entry candidates:', n_pad, 'pdata_ranges:', len(pdata_ranges))
print('total seeds:', len(seeds))

with open(out_path, 'w', encoding='utf-8') as f:
    for va in sorted(seeds):
        f.write('0x%x\n' % va)

print('dir64_relocs=%d known_funcs=%d mined_seeds=%d -> %s'
      % (n_reloc, len(known), len(seeds), out_path))
