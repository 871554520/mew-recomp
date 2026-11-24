#!/usr/bin/env python3
"""按 VA 打印 PE 内原始字节 + 对应的 .pdata 条目（诊断用）"""
import struct, sys

def load(path):
    d = open(path, 'rb').read()
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    nsec = struct.unpack_from('<H', d, pe + 6)[0]
    optsz = struct.unpack_from('<H', d, pe + 20)[0]
    opt = pe + 24
    base = struct.unpack_from('<Q', d, opt + 24)[0]
    secs = []
    st = opt + optsz
    for i in range(nsec):
        p = st + i * 40
        name = d[p:p + 8].rstrip(b'\0').decode('latin1')
        vsize, vaddr, rawsize, raw = struct.unpack_from('<IIII', d, p + 8)
        secs.append((name, vaddr, vsize, raw, rawsize))
    return d, base, secs

def rva_to_off(secs, rva):
    for name, vaddr, vsize, raw, rawsize in secs:
        if vaddr <= rva < vaddr + max(vsize, rawsize):
            return raw + (rva - vaddr)
    return None

d, base, secs = load(sys.argv[1])
print('image_base=0x%x sections=%s' % (base, [s[0] for s in secs]))
pdata = next((s for s in secs if s[0] == '.pdata'), None)
for a in sys.argv[2:]:
    va = int(a, 16)
    rva = va - base
    off = rva_to_off(secs, rva)
    print('\n== va=0x%x rva=0x%x off=%s' % (va, rva, off))
    if off is not None:
        b = d[off:off + 80]
        print('bytes:', ' '.join('%02x' % x for x in b))
    if pdata:
        n = pdata[2] // 12
        for i in range(n):
            p = pdata[3] + i * 12
            if p + 12 > len(d): break
            b0, b1 = struct.unpack_from('<II', d, p)
            if b0 == rva:
                print('pdata[%d] begin=0x%x end=0x%x size=%d unwind=0x%x' % (i, b0, b1, b1 - b0, struct.unpack_from('<I', d, p + 8)[0]))
                break
        else:
            print('pdata: no entry begin==rva')
