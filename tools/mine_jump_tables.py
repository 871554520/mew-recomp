#!/usr/bin/env python3
"""静态挖出「跳转表 case 标签」，写进 tools/known_internal_labels.txt 用的种子文件。

背景
----
MSVC 把 memcpy / memset 这类长度分派例程编成：

    lea  r10, [__ImageBase]              ; 4c 8d 15 <disp32>
    cmp  r8, 0xf
    ja   big
    mov  r?d, [r10 + r?*4 + <disp32>]    ; 47 8b 8c 82 <disp32>
    add  r?, r10
    jmp  r?                              ; 跳进本函数内部的 case 标签

这些 case 标签不是函数入口，只有跳到它们才执行那几字节的搬运/填充代码，
所以我们的 dispatcher（只认函数入口）命中不了。命中不了就记 miss 并当场
return，被调函数走不到自己的 ret，返回地址滞留在栈上，上层收尾寄存器整体
错位一格（详见 d286ae3 / run 45937873457）。

运行时能发现这些标签（discovered_entries.txt），但只能反馈到**下一轮 build**，
同一轮里新走到的路径追不上——实测二次构建仍在 0x140dab860 内部空转 93 万次。

跳转表是静态数据，直接解析出来即可。表项是**相对 ImageBase** 的 32 位偏移
（编码处 `mov r?d,[...]` 取 32 位零扩展 + `add r?,r10`），表基址 = ImageBase + disp32。

用法
----
    ./tools/mine_jump_tables.py Mewgenics.exe generated/jump_table_labels.txt

输出每行一个 `0x<va>`，可直接 `cat >> generated/extra_seeds.txt`。
"""
import struct
import sys


def parse_pe(data):
    """极简 PE 解析：返回 (image_base, size_of_image, [(name, va, raw_off, vsize, rsize)])。"""
    if data[:2] != b'MZ':
        raise SystemExit('not a PE: missing MZ')
    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b'PE\0\0':
        raise SystemExit('not a PE: missing PE signature')
    coff = e_lfanew + 4
    nsec = struct.unpack_from('<H', data, coff + 2)[0]
    size_opt = struct.unpack_from('<H', data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from('<H', data, opt)[0]
    if magic == 0x20B:                        # PE32+
        image_base = struct.unpack_from('<Q', data, opt + 0x18)[0]
        size_image = struct.unpack_from('<I', data, opt + 0x38)[0]
    elif magic == 0x10B:                      # PE32
        image_base = struct.unpack_from('<I', data, opt + 0x1C)[0]
        size_image = struct.unpack_from('<I', data, opt + 0x38)[0]
    else:
        raise SystemExit('unknown optional header magic 0x%x' % magic)
    secs = []
    sh = opt + size_opt
    for i in range(nsec):
        base = sh + i * 40
        name = data[base:base + 8].rstrip(b'\0').decode('ascii', 'replace')
        vsize, va, rsize, roff = struct.unpack_from('<IIII', data, base + 8)
        secs.append((name, image_base + va, roff, vsize, rsize))
    return image_base, size_image, secs


def main():
    if len(sys.argv) < 2:
        raise SystemExit('usage: mine_jump_tables.py <exe> [out.txt]')
    exe = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else 'generated/jump_table_labels.txt'
    data = open(exe, 'rb').read()
    image_base, size_image, secs = parse_pe(data)
    image_end = image_base + size_image

    # 只扫 .text：跳转表本身通常在 .rdata，但编码指令一定在 .text。
    text = next((s for s in secs if s[0] == '.text'), None)
    if text is None:
        raise SystemExit('.text section not found')
    _, text_va, text_off, text_vsize, text_rsize = text
    body = data[text_off:text_off + text_rsize]

    # 匹配 `mov r32, [r10 + r?*4 + disp32]`：
    #   [REX 40..4f] 8b ModRM(10 rrr 100) SIB(10 iii 010) disp32
    # 其中 SIB.base=010 配 REX.B 才是 r10，scale=10 是 *4；index/reg 位不固定，
    # 因为不同例程把结果放进 r9d / eax / edx 都出现过。
    labels = {}
    n = len(body)
    for i in range(n - 8):
        b0 = body[i]
        if not (0x40 <= b0 <= 0x4F) or body[i + 1] != 0x8B:
            continue
        modrm = body[i + 2]
        if (modrm & 0xC7) != 0x84:          # mod=10, rm=100(SIB)
            continue
        sib = body[i + 3]
        if (sib & 0xC7) != 0x82:            # scale=*4, base=010(r10)
            continue
        site_va = text_va + i
        disp = struct.unpack_from('<i', body, i + 4)[0]
        table_va = (image_base + disp) & 0xFFFFFFFFFFFFFFFF
        if not (image_base <= table_va < image_end):
            continue
        # 表项：16 条（长度 0..15 的分派表），相对 ImageBase 的 32 位偏移。
        for k in range(16):
            ent_va = table_va + k * 4
            sec = next((s for s in secs if s[1] <= ent_va < s[1] + max(s[3], s[4])), None)
            if sec is None:
                break
            _, s_va, s_off, _, s_rsize = sec
            foff = s_off + (ent_va - s_va)
            if foff + 4 > len(data):
                break
            rel = struct.unpack_from('<I', data, foff)[0]
            target = image_base + rel
            if not (text_va <= target < text_va + text_vsize):
                break
            labels.setdefault(target, site_va)

    if not labels:
        print('no jump-table case labels found')
        return
    lines = ['# 由 tools/mine_jump_tables.py 从跳转表静态挖出（每行一个 VA）']
    for va in sorted(labels):
        lines.append('0x%x' % va)
    payload = '\n'.join(lines) + '\n'
    try:
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(payload)
        print('wrote %s (%d labels)' % (out_path, len(labels)))
    except OSError as e:
        print('write %s failed: %s' % (out_path, e), file=sys.stderr)
    for va in sorted(labels):
        print('  0x%x  (load site 0x%x)' % (va, labels[va]))


if __name__ == '__main__':
    main()
