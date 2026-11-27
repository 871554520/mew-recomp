#!/usr/bin/env python3
"""扫出「一个真实函数被 MSVC 拆成好几条 .pdata」的全部家族，并标出真正会坏的那批。

背景（run 45978138365 定案）：MSVC 会把一个函数拆成若干条 .pdata，
**后续几条的 UNWIND_INFO flags 带 UNW_FLAG_CHAININFO(0x4)**，其链式
RUNTIME_FUNCTION 指回第一段（BeginAddress/EndAddress/UnwindData）。
如果按 .pdata 逐条 lift，第一段末尾一旦不是 ret/jmp（而是 fall-through
落进第二段），lifter 就会在段尾直接返回宿主：函数体一次都没执行，而且
`push rsi; sub rsp,0x20` 的帧撤不掉。0x14004ba20（vector::assign）就是这样，
它让 rehash 的 _Vec 没扩容、重链循环写穿 guest 堆，表现为「调用环 idx 冻结、
600/1800 秒停在同一处」的静默卡死。

所以判据不是「含 chaininfo 就坏」，而是：
  1. 家族的各段在 VA 上**连续**（中间没有塞进别的函数的字节）；
  2. 第一段最后一个字节**不是** ret(0xc3) / jmp(0xeb,0xe9) / int3(0xcc) /
     ret imm16(0xc2) / ud2(0f 0b) —— 即真的 fall-through 进了第二段。
同时满足这两条的家族，就是必须补长（或按家族合并 lift）的那批。

用法：
    python3 tools/scan_split_functions.py /path/to/Mewgenics.exe          # 概要
    python3 tools/scan_split_functions.py /path/to/Mewgenics.exe --list   # 逐条列候选
    python3 tools/scan_split_functions.py /path/to/Mewgenics.exe --tsv > split.tsv

输出只读 PE，不写任何文件（--tsv 走 stdout，便于 diff）。
"""
import struct
import sys

# UNWIND_INFO 的 UnwindInfo.Flags 位（winnt.h）
UNW_FLAG_EHANDLER = 0x1
UNW_FLAG_UHANDLER = 0x2
UNW_FLAG_CHAININFO = 0x4


class Pe:
    def __init__(self, path):
        self.data = open(path, 'rb').read()
        d = self.data
        pe = struct.unpack_from('<I', d, 0x3c)[0]
        nsec = struct.unpack_from('<H', d, pe + 6)[0]
        optsz = struct.unpack_from('<H', d, pe + 20)[0]
        opt = pe + 24
        self.image_base = struct.unpack_from('<Q', d, opt + 24)[0]
        self.sections = []
        sec = opt + optsz
        for i in range(nsec):
            o = sec + i * 40
            name = d[o:o + 8].rstrip(b'\0').decode('latin1')
            vsz, va, rsz, ro = struct.unpack_from('<IIII', d, o + 8)
            self.sections.append((name, va, vsz, ro, rsz))
        # DataDirectory[3] = ExceptionTable（.pdata）
        nrva, nsz = struct.unpack_from('<II', d, opt + 112 + 8 * 3)
        self.functions = []
        off = self.rva_to_off(nrva)
        if off is not None:
            for k in range(nsz // 12):
                self.functions.append(struct.unpack_from('<III', d, off + k * 12))
            self.functions.sort()

    def rva_to_off(self, rva):
        for _name, va, vsz, ro, rsz in self.sections:
            if va <= rva < va + vsz and rva - va < rsz:
                return ro + (rva - va)
        return None

    def byte(self, rva):
        o = self.rva_to_off(rva)
        return None if o is None else self.data[o]

    def unwind(self, unw_rva):
        """-> (flags, chain or None)。chain = (begin, end, unw) RVA。"""
        p = self.rva_to_off(unw_rva)
        if p is None:
            return 0, None
        ver_flags = self.data[p]
        flags = (ver_flags >> 3) & 0x1f
        count = self.data[p + 2]
        q = (p + 4 + 2 * count + 3) & ~3
        chain = None
        if flags & UNW_FLAG_CHAININFO:
            if q + 12 <= len(self.data):
                chain = struct.unpack_from('<III', self.data, q)
        return flags, chain


def ends_with_terminator(pe, end_rva):
    """end_rva 是 .pdata 的 EndAddress（exclusive）。判断最后一条指令是否收尾。

    没有反汇编器时的近似：只在段尾这几个字节上找 ret/jmp/int3 的编码。
    位置是精确的（段尾 = 最后一条指令的末尾），所以不会误判成「收尾」。
    """
    b1 = pe.byte(end_rva - 1)
    b2 = pe.byte(end_rva - 2)
    b3 = pe.byte(end_rva - 3)
    b5 = pe.byte(end_rva - 5)
    if b1 is None:
        return None
    if b1 == 0xc3:
        return 'ret'
    if b1 == 0xcc:
        return 'int3'
    if b2 == 0xeb:
        return 'jmp8'
    if b2 == 0x0b and b3 == 0x0f:
        return 'ud2'
    if b3 == 0xc2:
        return 'retimm'
    if b5 == 0xe9:
        return 'jmp32'
    return None


def families(pe):
    """按链式 RUNTIME_FUNCTION 的 BeginAddress 归组 -> {begin: {'prim':(...), 'pieces':[...]}}"""
    fam = {}
    for begin, end, unw in pe.functions:
        flags, chain = pe.unwind(unw)
        if chain is None:
            continue
        fam.setdefault(chain[0], {'prim': (chain[0], chain[1], chain[2]), 'pieces': []})
        fam[chain[0]]['pieces'].append((begin, end))
    return fam


def classify(pe, fam):
    rows = []
    for start in sorted(fam):
        v = fam[start]
        allp = sorted([(v['prim'][0], v['prim'][1])] + v['pieces'])
        contiguous = all(a[1] == b[0] for a, b in zip(allp, allp[1:]))
        term = ends_with_terminator(pe, v['prim'][1])
        rows.append({
            'va': pe.image_base + start,
            'size': allp[-1][1] - start,
            'pieces': len(allp),
            'contiguous': contiguous,
            'term': term,
            'broken': contiguous and term is None,
        })
    return rows


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    pe = Pe(argv[1])
    rows = classify(pe, families(pe))
    broken = [r for r in rows if r['broken']]
    gap = [r for r in rows if not r['contiguous']]
    print('# .pdata 条目 %d，含 chaininfo 的家族 %d，段数 %d'
          % (len(pe.functions), len(rows), sum(r['pieces'] for r in rows)))
    print('# 段连续 %d（其中 fall-through 会坏 %d），段不连续 %d'
          % (len(rows) - len(gap), len(broken), len(gap)))
    print('# 坏家族合计补长字节 %d（最大 0x%x）'
          % (sum(r['size'] for r in broken), max([r['size'] for r in broken] or [0])))
    if '--tsv' in argv:
        print('va\tsize\tpieces\tcontiguous\tterm')
        for r in rows:
            print('0x%x\t0x%x\t%d\t%d\t%s'
                  % (r['va'], r['size'], r['pieces'], r['contiguous'], r['term'] or '-'))
    elif '--list' in argv:
        for r in broken:
            print('0x%x  size=0x%x  pieces=%d' % (r['va'], r['size'], r['pieces']))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
