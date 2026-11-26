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
    segs, sy, di = [], None, None
    for i in range(ncmds):
        cmd, sz = struct.unpack_from('<II', d, o)
        if cmd == LC_SEGMENT_64:
            name = d[o + 8:o + 24].rstrip(b'\0').decode()
            vm, vs, fo, fs = struct.unpack_from('<QQQQ', d, o + 24)
            maxp, initp, ns = struct.unpack_from('<III', d, o + 56)
            segs.append((name, vm, vs, fo, fs, initp, ns))
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

    if di:
        rb_off, rb_sz, bd_off, bd_sz = di[2], di[3], di[4], di[5]
        trie_off, trie_sz = di[10], di[11]
        def count_rebase(off, size):
            p, end, n = off, off + size, 0
            while p < end:
                b = d[p]; p += 1
                op, imm = b & 0xF0, b & 0x0F
                if b == 0:
                    break
                if op == 0x20:            # SET_SEGMENT_AND_OFFSET_ULEB
                    _, p = uleb(d, p)
                elif op == 0x30:          # ADD_ADDR_ULEB
                    _, p = uleb(d, p)
                elif op == 0x40:          # ADD_ADDR_IMM_SCALED
                    pass
                elif op == 0x50:          # DO_REBASE_IMM_TIMES
                    n += imm if imm else 1
                elif op == 0x60:          # DO_REBASE_ULEB_TIMES
                    v, p = uleb(d, p); n += v
                elif op == 0x70:          # DO_REBASE_ADD_ADDR_ULEB
                    _, p = uleb(d, p); n += 1
                elif op == 0x80:          # DO_REBASE_ULEB_TIMES_SKIPPING_ULEB
                    v, p = uleb(d, p); _, p = uleb(d, p); n += v
            return n

        def count_bind(off, size):
            p, end, n = off, off + size, 0
            while p < end:
                b = d[p]; p += 1
                op, imm = b & 0xF0, b & 0x0F
                if b == 0:
                    break
                if op == 0x20:            # SET_DYLIB_ORDINAL_ULEB
                    _, p = uleb(d, p)
                elif op == 0x40:          # SET_SYMBOL_TRAILING_FLAGS_IMM + cstring
                    e = d.index(b'\0', p); p = e + 1
                elif op == 0x60:          # SET_ADDEND_SLEB
                    while d[p] & 0x80:
                        p += 1
                    p += 1
                elif op == 0x70:          # SET_SEGMENT_AND_OFFSET_ULEB
                    _, p = uleb(d, p)
                elif op == 0x80:          # ADD_ADDR_ULEB
                    _, p = uleb(d, p)
                elif op == 0x90:          # DO_BIND
                    n += imm if imm else 1
                elif op == 0xA0:          # DO_BIND_ADD_ADDR_ULEB
                    _, p = uleb(d, p); n += 1
                elif op == 0xC0:
                    v, p = uleb(d, p); _, p = uleb(d, p); n += v
            return n

        n_rb = count_rebase(rb_off, rb_sz)
        n_bd = count_bind(bd_off, bd_sz)
        print('rebase 流 %d 字节 -> %d 条；bind 流 %d 字节 -> %d 条；trie %d 字节'
              % (rb_sz, n_rb, bd_sz, n_bd, trie_sz))
        blob = d[bd_off:bd_off + bd_sz]
        if b'\x00memcpy\x00' in blob:
            fail.append('bind 里出现无下划线的 memcpy')
        print('bind 含 _memcpy=%s  含无下划线 memcpy=%s'
              % (b'_memcpy\x00' in blob, b'\x00memcpy\x00' in blob))
    else:
        fail.append('no LC_DYLD_INFO_ONLY')

    # trie 走查
    def node(q):
        tsz, p = uleb(d, q)
        nc = d[p]
        p += 1
        kids = []
        for _ in range(nc):
            e = d.index(b'\0', p)
            kids.append(d[p:e])
            p = e + 1
        offs = []
        for _ in range(nc):
            v, p = uleb(d, p)
            offs.append(v)
        return tsz, kids, offs, p

    def find(name):
        q = trie_off
        for i in range(len(name)):
            tsz, kids, offs, _ = node(q)
            c = name[i:i + 1]
            if c not in kids:
                return None
            q = trie_off + offs[kids.index(c)]
        tsz, kids, offs, p = node(q)
        if not tsz:
            return None
        fl, p = uleb(d, p)
        addr, p = uleb(d, p)
        return addr

    a = find(b'_SDL_main')
    print('trie 走查 _SDL_main -> %s' % (hex(a) if a else None))
    if not a:
        fail.append('trie 找不到 _SDL_main')
    if find(b'SDL_main') is not None:
        fail.append('trie 里存在无下划线的 SDL_main')
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
