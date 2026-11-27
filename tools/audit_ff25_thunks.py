#!/usr/bin/env python3
"""扫 PE .text 里所有 `FF 25 disp32`（jmp qword [rip+disp]）与 `FF 15 disp32`（call …），
核对哪些间接跳转的槽位落在 .rdata/.idata 里、却不在重编译入口表里。

用途：`1dec451` 之后仍有漏网 ff25 thunk 时，一次扫全表就能列出候选，
不必等运行期 `[FATAL] Unmapped indirect target` 一条条冒。

用法：
  python3 tools/audit_ff25_thunks.py Mewgenics.exe generated/pe_meta.json
（第二个参数可选；给了就按它的 functions/seeds 列表判断「已收录」。）
"""
import json
import struct
import sys


def parse_pe(data: bytes):
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    num_sec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    opt_sz = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    img_base = struct.unpack_from("<Q", data, e_lfanew + 24 + 24)[0]
    sec_off = e_lfanew + 24 + opt_sz
    secs = []
    for i in range(num_sec):
        off = sec_off + i * 40
        name = data[off:off + 8].rstrip(b"\x00").decode("latin1")
        vsize, rva, rsize, roff = struct.unpack_from("<IIII", data, off + 8)
        secs.append((name, rva, vsize, roff, rsize))
    return img_base, secs


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    data = open(sys.argv[1], "rb").read()
    img_base, secs = parse_pe(data)

    data_ranges = [(img_base + rva, img_base + rva + max(vsize, rsize))
                   for name, rva, vsize, _roff, rsize in secs
                   if name in (".rdata", ".idata", ".data")]

    known = set()
    if len(sys.argv) > 2:
        try:
            meta = json.load(open(sys.argv[2]))
            for f in meta.get("functions", []):
                known.add(int(f["va"]) if isinstance(f, dict) else int(f))
        except Exception as exc:  # noqa: BLE001
            print("WARN: 读 pe_meta 失败，按「无已知表」处理:", exc)

    hits = []
    for name, rva, _vsize, roff, rsize in secs:
        if name != ".text":
            continue
        blob = data[roff:roff + rsize]
        for op, label in ((b"\xff\x25", "jmp"), (b"\xff\x15", "call")):
            pos = 0
            while True:
                idx = blob.find(op, pos)
                if idx < 0 or idx + 6 > len(blob):
                    break
                disp = struct.unpack_from("<i", blob, idx + 2)[0]
                va = img_base + rva + idx
                target = va + 6 + disp
                if any(lo <= target < hi for lo, hi in data_ranges):
                    hits.append((label, va, target))
                pos = idx + 1

    missing = [h for h in hits if h[1] not in known] if known else []
    print(f"FF25/FF15 -> 数据段槽位：{len(hits)} 条"
          + (f"，不在入口表里：{len(missing)} 条" if known else "（未给 pe_meta，跳过收录比对）"))
    for label, va, tgt in (missing or hits)[:80]:
        print(f"  {label}  va=0x{va:x}  slot=0x{tgt:x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
