#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""verify_macho.py —— 纯 Python 校验 elf2macho_dylib.py 的产物（不需要 lief / macOS）。
   等价于 otool -l + dyld_info -exports 的关键几项：
     1) 12 条 load command 逐条解析、sizeofcmds 自洽
     2) 段 16 KB 对齐、__TEXT 覆盖 Mach-O header
     3) rebase/bind 流条数、bind 符号是否带前导 _
     4) symtab 导出名全部能在 export trie 里查到（并抽验 SDL_main）
用法: python3 verify_macho.py libmew_relinked.dylib
"""
import struct
import sys

PAGE = 0x4000
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYLD_INFO_ONLY = 0x80000022


def uleb(d, p):
    v = 0
    s = 0
    while True:
        b = d[p]
        p += 1
        v |= (b & 0x7F) << s
        if not b & 0x80:
            return v, p
        s += 7


def main(path):
    d = open(path, 'rb').read()
    magic, cputype, sub, ft, ncmds, szcmds = struct.unpack_from('<IIIIII', d, 0)
    fail = []
    if magic != 0xFEEDFACF:
        fail.append('magic')
    if ft != 6:
        fail.append('filetype != MH_DYLIB')
    o = 32
    segs, sects, sy, di = [], [], None, None
    for i in range(ncmds):
        cmd, sz = struct.unpack_from('<II', d, o)
        if cmd == LC_SEGMENT_64:
            name = d[o + 8:o + 24].rstrip(b'\0').decode()
            vm, vs, fo, fs = struct.unpack_from('<QQQQ', d, o + 24)
            maxp, initp, ns = struct.unpack_from('<III', d, o + 56)
            segs.append((name, vm, vs, fo, fs, initp, ns))
            so = o + 72
            for _k in range(ns):
                sn = d[so:so + 16].rstrip(b'\0').decode()
                sa, ssz = struct.unpack_from('<QQ', d, so + 32)
                sects.append((name, sn, sa, ssz))
                so += 80
        elif cmd == LC_SYMTAB:
            sy = struct.unpack_from('<IIIIII', d, o)
        elif cmd == LC_DYLD_INFO_ONLY:
            di = struct.unpack_from('<IIIIIIIIIIII', d, o)
        o += sz
    print('ncmds=%d sizeofcmds=%d  解析后 offset=%d  %s'
          % (ncmds, szcmds, o - 32, 'OK' if o - 32 == szcmds else 'MISMATCH'))
    if o - 32 != szcmds:
        fail.append('sizeofcmds')

    t = [s for s in segs if s[0] == '__TEXT']
    if not t:
        fail.append('no __TEXT')
    else:
        n, vm, vs, fo, fs, initp, ns = t[0]
        cov = (vm == 0 and fo == 0 and fs >= 32 + szcmds)
        print('__TEXT vm=0x%x vmsize=0x%x fileoff=0x%x filesize=0x%x initprot=%d nsects=%d  覆盖 header=%s'
              % (vm, vs, fo, fs, initp, ns, cov))
        if not cov:
            fail.append('__TEXT 未覆盖 header')
    for n, vm, vs, fo, fs, initp, ns in segs:
        if vm % PAGE or fo % PAGE or vs % PAGE:
            fail.append('段 %s 未 16KB 对齐' % n)
    print('段数量=%d 全部 16KB 对齐=%s' % (len(segs), not any('对齐' in f for f in fail)))

    # __LINKEDIT 必须覆盖 rebase/bind/export trie —— 真机 dyld 报的就是这条
    le = [x for x in segs if x[0] == '__LINKEDIT']
    if le and di:
        _n, _vm, _vs, le_fo, le_fs, _ip, _ns = le[0]
        _ex_off, _ex_sz = di[10], di[11]
        _rb_off, _rb_sz, _bd_off, _bd_sz = di[2], di[3], di[4], di[5]
        end = max(_ex_off + _ex_sz, _rb_off + _rb_sz, _bd_off + _bd_sz)
        print('__LINKEDIT fileoff=0x%x filesize=0x%x end=0x%x；内容最远到 0x%x'
              % (le_fo, le_fs, le_fo + le_fs, end))
        if end > le_fo + le_fs:
            fail.append('__LINKEDIT 未覆盖 dyld 内容（超出 %d 字节）' % (end - (le_fo + le_fs)))

    if di:
        rb_off, rb_sz, bd_off, bd_sz = di[2], di[3], di[4], di[5]
        trie_off, trie_sz = di[10], di[11]
        def in_section(segidx, addr):
            """addr 是否落在该段某个节的 [addr, addr+size) 里。"""
            segname = segs[segidx][0]
            for sn_seg, sn, sa, ssz in sects:
                if sn_seg == segname and sa <= addr < sa + ssz:
                    return True
            return False

        def count_rebase(off, size):
            p, end, n = off, off + size, 0
            seg = soff = None
            while p < end:
                b = d[p]; p += 1
                op, imm = b & 0xF0, b & 0x0F
                if b == 0:
                    if p != end:
                        fail.append('rebase 流提前 DONE，剩 %d 字节' % (end - p))
                    break
                if op == 0x20:            # SET_SEGMENT_AND_OFFSET_ULEB
                    soff, p = uleb(d, p)
                    seg = imm
                elif op == 0x30:          # ADD_ADDR_ULEB
                    v, p = uleb(d, p); soff += v
                elif op == 0x40:          # ADD_ADDR_IMM_SCALED
                    soff += imm * 8
                elif op == 0x50:          # DO_REBASE_IMM_TIMES
                    cnt = imm if imm else 1
                    n += cnt
                    if seg is None or not in_section(seg, segs[seg][1] + soff):
                        fail.append('rebase 落点无节覆盖 seg=%s off=0x%x' % (seg, soff or 0))
                    soff += 8 * cnt
                elif op == 0x60:          # DO_REBASE_ULEB_TIMES
                    v, p = uleb(d, p); n += v
                    if seg is None or not in_section(seg, segs[seg][1] + soff):
                        fail.append('rebase 落点无节覆盖 seg=%s off=0x%x' % (seg, soff or 0))
                    soff += 8 * v
                elif op == 0x70:          # DO_REBASE_ADD_ADDR_ULEB
                    v, p = uleb(d, p); n += 1
                    if seg is None or not in_section(seg, segs[seg][1] + soff):
                        fail.append('rebase 落点无节覆盖 seg=%s off=0x%x' % (seg, soff or 0))
                    soff += 8 + v
                elif op == 0x80:          # DO_REBASE_ULEB_TIMES_SKIPPING_ULEB
                    v, p = uleb(d, p); sk, p = uleb(d, p); n += v
                    if seg is None or not in_section(seg, segs[seg][1] + soff):
                        fail.append('rebase 落点无节覆盖 seg=%s off=0x%x' % (seg, soff or 0))
                    soff += v * (8 + sk)
            return n

        bind_syms, bind_ords = [], set()
        def count_bind(off, size):
            """严格状态机式 bind 解码：DO_BIND 缺符号/段、落点没有节覆盖、
            或流中出现多余字节导致提前 DONE，都算结构错误。"""
            p, end, n = off, off + size, 0
            seg = soff = sym = ordv = None
            while p < end:
                b = d[p]; p += 1
                op, imm = b & 0xF0, b & 0x0F
                if op == 0x00:            # DONE
                    if p != end:
                        fail.append('bind 流在 +%d 就 DONE，后面还剩 %d 字节（多半是 opcode 多写了字节）'
                                    % (p - off, end - p))
                    break
                if op == 0x10:            # SET_DYLIB_ORDINAL_IMM
                    if imm == 0:
                        fail.append('bind 里出现序号 0')
                    ordv = imm
                elif op == 0x20:          # SET_DYLIB_ORDINAL_ULEB
                    ordv, p = uleb(d, p)
                elif op == 0x30:          # SET_DYLIB_SPECIAL_IMM
                    ordv = imm - 16 if imm else 0
                elif op == 0x40:          # SET_SYMBOL_TRAILING_FLAGS_IMM + cstring
                    e = d.index(b'\0', p); sym = d[p:e].decode(); p = e + 1
                elif op == 0x50:          # SET_TYPE_IMM
                    pass
                elif op == 0x60:          # SET_ADDEND_SLEB
                    while d[p] & 0x80:
                        p += 1
                    p += 1
                elif op == 0x70:          # SET_SEGMENT_AND_OFFSET_ULEB
                    soff, p = uleb(d, p)
                    seg = imm             # 段号在 opcode 低 4 位
                elif op == 0x80:          # ADD_ADDR_ULEB
                    v, p = uleb(d, p); soff += v
                elif op in (0x90, 0xA0, 0xC0):
                    if sym is None or seg is None or soff is None:
                        fail.append('bind DO_BIND 缺符号或段（+%d）' % (p - off))
                    else:
                        if seg >= len(segs):
                            fail.append('bind 段号越界 %d' % seg)
                        elif not in_section(seg, segs[seg][1] + soff):
                            fail.append('bind 落点 0x%x 没有任何节覆盖'
                                        % (segs[seg][1] + soff))
                        bind_syms.append(sym)
                        bind_ords.add(ordv)
                    if op == 0x90:
                        n += imm if imm else 1
                    elif op == 0xA0:
                        v, p = uleb(d, p); soff += v; n += 1
                    else:
                        v, p = uleb(d, p); _, p = uleb(d, p); soff += v; n += v
            return n

        # dyld4 的 rebase()/bind() 里 type 初值是 0，流中没 SET_TYPE 就会报
        # "unknown rebase type 0" / "unknown bind type 0"。这里直接卡住开头几个字节。
        if d[rb_off] != 0x11:
            fail.append('rebase 流首字节不是 0x11（SET_TYPE_IMM|POINTER=1）')
        if d[rb_off + rb_sz - 1] != 0x00:
            fail.append('rebase 流末字节不是 DONE(0x00)')
        if d[bd_off] not in (0x51, 0x11):
            fail.append('bind 流首字节不是 SET_TYPE/SET_ORDINAL（0x%02x）' % d[bd_off])
        if d[bd_off + bd_sz - 1] != 0x00:
            fail.append('bind 流末字节不是 DONE(0x00)')
        print('rebase 首字节=0x%02x 末=0x%02x；bind 首字节=0x%02x 末=0x%02x'
              % (d[rb_off], d[rb_off+rb_sz-1], d[bd_off], d[bd_off+bd_sz-1]))

        n_rb = count_rebase(rb_off, rb_sz)
        n_bd = count_bind(bd_off, bd_sz)
        print('rebase 流 %d 字节 -> %d 条；bind 流 %d 字节 -> %d 条；trie %d 字节'
              % (rb_sz, n_rb, bd_sz, n_bd, trie_sz))
        blob = d[bd_off:bd_off + bd_sz]
        if b'\x00memcpy\x00' in blob:
            fail.append('bind 里出现无下划线的 memcpy')
        print('bind 含 _memcpy=%s  含无下划线 memcpy=%s'
              % (b'_memcpy\x00' in blob, b'\x00memcpy\x00' in blob))
        print('bind 序号集合=%s  前 3 个符号=%s'
              % (sorted(x for x in bind_ords if x is not None), bind_syms[:3]))
    else:
        fail.append('no LC_DYLD_INFO_ONLY')

    # trie 走查（标准布局：terminal_size → payload → child_count → 边名字/偏移）
    def node(q):
        tsz, p = uleb(d, q)
        addr = None
        if tsz:
            end = p + tsz
            _, p = uleb(d, p)
            addr, p = uleb(d, p)
            if p != end:
                fail.append('trie terminal 长度不符 @0x%x' % q)
        nc = d[p]
        p += 1
        kids, offs = [], []
        for _ in range(nc):          # 每个子节点：边名字紧接它自己的偏移
            e = d.index(b'\0', p)
            kids.append(d[p:e])
            p = e + 1
            v, p = uleb(d, p)
            offs.append(v)
            if trie_off + v >= trie_off + trie_sz:
                fail.append('trie 子节点偏移越界 @0x%x -> 0x%x' % (q - trie_off, v))
        return tsz, addr, kids, offs, p

    def find(name):
        q = trie_off
        for i in range(len(name)):
            tsz, addr, kids, offs, _ = node(q)
            c = name[i:i + 1]
            if c not in kids:
                return None
            q = trie_off + offs[kids.index(c)]
        tsz, addr, kids, offs, p = node(q)
        return addr if tsz else None

    a = find(b'_SDL_main')
    print('trie 走查 _SDL_main -> %s' % (hex(a) if a else None))
    if not a:
        fail.append('trie 找不到 _SDL_main')
    if find(b'SDL_main') is not None:
        fail.append('trie 里存在无下划线的 SDL_main')
    # 全量走查：节点数、导出名数、精确占满 trie_sz（LLVM 就是这么判 inconsistent 的）
    seen, stack, nnames, maxend = set(), [(0, b'')], 0, 0
    while stack:
        off, pre = stack.pop()
        if off in seen:
            fail.append('trie 节点被重复引用 0x%x' % off)
            break
        seen.add(off)
        tsz, addr, kids, offs, p = node(trie_off + off)
        maxend = max(maxend, p - trie_off)
        if tsz and pre:
            nnames += 1
        for nm, v in zip(kids, offs):
            stack.append((v, pre + nm))
    print('trie 节点 %d 个，导出名 %d 个，占用 %d / %d 字节'
          % (len(seen), nnames, maxend, trie_sz))
    if maxend != trie_sz:
        fail.append('trie 未精确占满（%d != %d）' % (maxend, trie_sz))
    if sy:
        symoff, nsyms, stroff = sy[2], sy[3], sy[4]
        ok = 0
        for i in range(nsyms):
            e = struct.unpack_from('<IBBHQ', d, symoff + i * 16)
            nm = d[stroff + e[0]:d.index(b'\0', stroff + e[0])]
            if find(nm) is not None:
                ok += 1
        print('symtab 名字在 trie 中可解析: %d / %d' % (ok, nsyms))
        if ok != nsyms:
            fail.append('trie 未覆盖全部 symtab')
    print()
    if fail:
        print('FAIL:', fail)
        return 1
    print('ALL CHECKS PASSED')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else 'libmew_relinked.dylib'))
