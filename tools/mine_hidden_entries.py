#!/usr/bin/env python3
"""手册 Prompt 2：从 .reloc(DIR64) + CFG GFIDS 静态挖出指向 .text 的隐藏入口"""
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
            if va % 16 == 0 and va not in known and va not in seeds:
                seeds.add(va)
                n_pad += 1
        i = j
except Exception as exc:  # noqa: BLE001
    print('padding scan failed:', exc)

print('padding-entry candidates:', n_pad)
print('total seeds:', len(seeds))

with open(out_path, 'w', encoding='utf-8') as f:
    for va in sorted(seeds):
        f.write('0x%x\n' % va)

print('dir64_relocs=%d known_funcs=%d mined_seeds=%d -> %s'
      % (n_reloc, len(known), len(seeds), out_path))
