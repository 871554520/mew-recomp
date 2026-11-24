#!/usr/bin/env python3
"""阶段 1：PE 元数据 + IAT 导入表导出（方案书里的 scan_pe_and_isa.py）

用法：python3 tools/scan_pe_and_isa.py Mewgenics.exe generated/pe_meta.json
依赖：pip install lief
"""
import json
import os
import sys

import lief


def main():
    pe_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else 'generated/pe_meta.json'
    binary = lief.PE.parse(pe_path)
    meta = {
        "image_base": binary.optional_header.imagebase,
        "entry_rva": binary.optional_header.addressof_entrypoint,
        "sections": [],
        "imports": [],
        "functions": [],
    }
    for s in binary.sections:
        meta["sections"].append({
            "name": s.name,
            "rva": s.virtual_address,
            "vsize": s.virtual_size,
            "raw_offset": s.pointerto_raw_data,
            "raw_size": s.sizeof_raw_data,
            "exec": bool(s.characteristics & 0x20000000),
        })
    for imp in binary.imports:
        for entry in imp.entries:
            meta["imports"].append({
                "dll": imp.name.upper(),
                "name": entry.name or ("ORD_%d" % entry.ordinal),
                "iat_va": binary.optional_header.imagebase + entry.iat_address,
            })

    # .pdata: RUNTIME_FUNCTION = BeginRVA, EndRVA, UnwindRVA（每项 12 字节）
    pdata = binary.get_section(".pdata")
    if pdata:
        raw = bytes(pdata.content)
        for off in range(0, len(raw) - 11, 12):
            b = int.from_bytes(raw[off:off + 4], "little")
            e = int.from_bytes(raw[off + 4:off + 8], "little")
            if b and e > b:
                meta["functions"].append({
                    "va": binary.optional_header.imagebase + b,
                    "size": e - b,
                })

    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    by_dll = {}
    for imp in meta["imports"]:
        by_dll[imp["dll"]] = by_dll.get(imp["dll"], 0) + 1
    print("functions:", len(meta["functions"]))
    print("imports:", len(meta["imports"]))
    for dll, n in sorted(by_dll.items(), key=lambda kv: -kv[1]):
        print("  %-16s %d" % (dll, n))
    print("sections:", [(s["name"], s["vsize"], s["exec"]) for s in meta["sections"]])


if __name__ == '__main__':
    main()
