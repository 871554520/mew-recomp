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


from thunk_shapes import import_thunk_shape as _import_thunk_shape  # noqa: E402


try:
    # 槽按 16 对齐整段扫（比逐字节快，且入口本来就要求 16 对齐）
    for k in range(0, len(text_bytes) - 16, 16):
        if not _import_thunk_shape(text_bytes, k):
            continue
        va = text_start + k
        if va in known or va in seeds or _inside_known(va):
            continue
        seeds.add(va)
        n_ithunk += 1
except Exception as exc:  # noqa: BLE001
    print('import-thunk scan failed:', exc)
print('import-thunk (test/je/jmp[rip]) candidates:', n_ithunk)

# 第二批：**任意短前缀** + `jmp qword [rip+rel32]` + 终止符/填充铺满 16 字节。
# 上面那条规则只认「槽首」或「槽 5 的 test/jcc 守卫」，于是同一类桩换个前缀就漏：
#   0x140a9b490  48 8b ca              mov rcx,rdx        （被 .data 引用 4 次）
#   0x14097a1e0  b9 11 0c 00 00        mov ecx,0xc11      （被 .rdata 引用 2 次）
#   0x140a29cf0  33 d2 b9 40 8d 00 00  xor edx,edx; mov ecx,…
#   0x140bf7f90  48 85 c9 74 0a f0 ff 01  test/lock inc（空指针路径不是裸 ret）
#   0x140a91290  48 85 c9 74 07 … 33 c0 c3 守卫 + `xor eax,eax; ret`
#   0x140a55370  4c 8b c2 ba 01 00 00 00  mov r8,rdx; mov edx,1（12 连排）
# 全 .text 扫下来旧规则收 1206 个、新规则收 1236 个，多出的 30 个里 4 个是
# 被数据段当函数指针引用的活桩 —— 漏一个就是运行期一次未映射目标。
#
# **必须再加一道 `prev ∈ {cc,00}` 过滤**（这是拿真镜像全量对过才定下来的）：
# 不加过滤会多收 12 个「16 对齐、无 .pdata、尾跳正好铺满槽」的假阳性，
# 它们的前一个字节是 8b/48/41/c5/e6/d2 这种指令中段字节，实测都是**函数体内**
# 的 16 对齐落点（例如 0x140d51fa0 前一字是 VEX 前缀 c5、0x140d6ae20 前一字
# 是 e6），一旦当成入口就会把真正的宿主函数切碎。真 thunk 一定坐在填充/对齐
# 空隙里，所以前置字节必然是 cc 或 00。
# 反过来，前置字节非填充但**确实**是活桩的那种（如 0x140a9b490 prev=e0），
# 早已被上面 .reloc 那条规则当作函数指针值收进 seeds 了，这里跳过不会漏。
# 打磨后：新规则净增 18 个种子（11 个 0x140a55380..0x140a55420 的连排桩 + 7 个分散桩）。
# 形状判定在 tools/thunk_shapes.py::tail_jump_thunk_shape，单测见 test_thunk_shapes.py。
n_tjthunk = 0
try:
    from thunk_shapes import tail_jump_thunk_shape as _tail_jump_thunk_shape  # noqa: E402

    for k in range(0, len(text_bytes) - 16, 16):
        if _tail_jump_thunk_shape(text_bytes, k) < 0:
            continue
        if k == 0 or text_bytes[k - 1] not in (0xCC, 0x00):
            continue
        va = text_start + k
        if va in known or va in seeds or _inside_known(va):
            continue
        seeds.add(va)
        n_tjthunk += 1
except Exception as exc:  # noqa: BLE001
    print('tail-jump-thunk scan failed:', exc)
print('tail-jump-thunk (任意前缀 + jmp[rip], 前置填充) candidates:', n_tjthunk)

# 运行期实证过的漏网入口：既没有 .pdata，前面又不到 3 个 cc 填充，所以上面三条
# 静态规则一条都收不到；但镜像里确实有**直接 call** 指向它们，运行期表现就是
#   [FATAL] Unmapped indirect target: 0x… (nearest_lo=…, delta=…)
# 每一条都必须来自真实 run 的日志（不是猜），加的时候写清 run id + 反汇编形态。
RUNTIME_PROVEN_ENTRIES = [
    # run 46080964765 (339c746, 基线轮)：
    #   [FATAL] Unmapped indirect target: 0x140bf9d80 (nearest_lo=0x140bf9d60 delta=32)
    #   in_fn=0x140bf9ab0 hits=1/2/3
    # 0x140bf9ab0(352B,有 .pdata) 里 0x140bf9ac3 处是 `e8 b8 02 00 00` = call 0x140bf9d80；
    # 目标形态 `0f bd c1 74 1a 48 63 c8 85 c0 78 13 48 8d 05 … 80 3c 01 00` 是位图检查，
    # 和 0x140bf9d60 是同源内联对（后者前面有 10 个 cc，已被 padding 规则收到）。
    # 它前面只有 2 个 cc（0x140bf9d7e/7f），阈值 3 所以漏掉。
    0x140bf9d80,
    # run 46104754966 (f52777c, MEW_TRACE_N=400)：
    #   [fn] 0x140bb0720 rcx=0x140e63b80 ×2（runner.err 第 52462 / 53391 行），
    #   rdx=0x0  r8=0x141135198("windows" 字符串)  r9=0x1fff0000
    #   → 'No dynamic %s support in current SDL video driver (%s)'
    #   两次都紧跟在 SDL_CreateWindowWithProperties 的 +0x20 调用之后、建窗之前。
    # 0x140be8190 没有 .pdata（padding-entry 形态，同 0x140bf9d80 / 0x140bea300 / 0x1409db940）：
    #   mov rcx,[0x1413b45e0]; test rcx,rcx; je; cmp byte [rcx+0x30a],0; je +3;
    #   mov al,1; ret / mov rax,[rcx+0x240]; mov byte [rcx+0x30a],1;
    #   test rax,rax; je +3; jmp rax   = SDL_GL_LoadLibrary 快路。
    # 0x140be81d0 是紧跟其后的另一个 padding-entry（0x140be81cc 起是 cc cc 补齐）：
    #   mov r8,[rip+…]; mov rdx,rcx; lea rcx,['No dynamic %s support…'];
    #   mov r8,[r8]; jmp SDL_SetError(0x140bb0720)。
    0x140be8190,
    0x140be81d0,
    # run 46115661940 (9526b92, 像素格式日志轮)：
    #   探测函数 0x140c8a550(452B,有 .pdata) 在 +0x094 处 `call 0x140c8b0c0`，
    #   时机正好夹在 ChoosePixelFormat(+0x0a1 实际是 +0x0a1 之后的 +0x0b1 SetPixelFormat)
    #   与 ReleaseDC(+0x18f) 之间 —— 就是“验证这个像素格式真能建 GL 上下文”那一步。
    #   日志里 10x10 探测窗 → ChoosePixelFormat -> 1 → wglCreateContext -> 0x30001
    #   → wglMakeCurrent/WakeDeleteContext 全成功，随后才报 0x140e806e8，
    #   和这个函数返回 false 的位置吻合。
    # 0x140c8b0c0 没有 .pdata（padding-entry 形态，同 0x140be8190 / 0x140bf9d80）：
    #   前填充 0x140c8b0b8..0x140c8b0bf，后填充 0x140c8b1a6..0x140c8b1af，
    #   即 [0x140c8b0c0, 0x140c8b1b0) ≈ 240 字节。
    #   同圈 0x140c8a720/0x140c8aaf0/0x140c8ab20/0x140c8ae40/0x140c8afc0/
    #   0x140c8b050/0x140c8b1b0/0x140c8b220/0x140c8b510/0x140c8b5d0 全有 .pdata，
    #   只有它没有 —— 与 0x140be8190 当初同一个孤例形态。
    0x140c8b0c0,
]
_n_rt = 0
for _va in RUNTIME_PROVEN_ENTRIES:
    if _va not in seeds and not _inside_known(_va):
        seeds.add(_va)
        _n_rt += 1
print('runtime-proven entries added:', _n_rt)

print('padding-entry candidates:', n_pad, 'pdata_ranges:', len(pdata_ranges))
print('total seeds:', len(seeds))

with open(out_path, 'w', encoding='utf-8') as f:
    for va in sorted(seeds):
        f.write('0x%x\n' % va)

print('dir64_relocs=%d known_funcs=%d mined_seeds=%d -> %s'
      % (n_reloc, len(known), len(seeds), out_path))
