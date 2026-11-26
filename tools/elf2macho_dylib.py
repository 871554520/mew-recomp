#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""elf2macho_dylib.py —— 把 AArch64 Android ELF 共享库无损封装成 Mach-O MH_DYLIB。

设计要点（对应《Mewgenics ELF转MachO iOS 重链接完整方案》）：
  * 三个 PT_LOAD 段原样搬到 __TEXT / __DATA_CONST / __DATA，
    段的 vmaddr 按页对齐，但**内容**仍落在 ELF 的原始相对偏移上，
    因此 .so 内部所有 b/bl、adrp+add 相对引用天然有效，不需要改指令。
  * R_AARCH64_RELATIVE  -> LC_DYLD_INFO_ONLY rebase（槽里写 addend，dyld 再加 slide）
  * JUMP_SLOT/ABS64/GLOB_DAT -> bind
        SDL_*                 -> SDL3.framework
        PASSTHROUGH（数学/内存/字符串）-> /usr/lib/libSystem.B.dylib
        其余 bionic/POSIX/Android -> @rpath/libbionic_shim.dylib（符号名加 _bionic_ 前缀）
  * TLSDESC -> 绑定到 libbionic_shim 的 _bionic_tlsdesc_resolver
  * 导出表（export trie）里放上所有已定义全局符号，保证 dlsym(SDL_main) 可用。

用法:
    python3 tools/elf2macho_dylib.py libmain.so -o libmew_relinked.dylib \
        --platform ios|macos [--fixups classic|chained] [--verbose]
"""
import argparse
import struct
import sys

# ---------------- ELF 常量 ----------------
PT_LOAD, PT_DYNAMIC, PT_TLS, PT_GNU_EH_FRAME = 1, 2, 7, 0x6474E550
DT_NULL, DT_NEEDED, DT_INIT, DT_FINI = 0, 1, 12, 13
DT_INIT_ARRAY, DT_INIT_ARRAYSZ = 25, 27
DT_STRTAB, DT_SYMTAB, DT_RELA, DT_RELASZ = 5, 6, 7, 8
DT_RELAENT, DT_SYMENT = 9, 11
DT_JMPREL, DT_PLTRELSZ, DT_PLTREL = 23, 2, 20
DT_HASH, DT_GNU_HASH = 4, 0x6FFFFEF5

R_AARCH64_ABS64 = 257
R_AARCH64_PREL32 = 261
R_AARCH64_GLOB_DAT = 1025
R_AARCH64_JUMP_SLOT = 1026
R_AARCH64_RELATIVE = 1027
R_AARCH64_TLSDESC = 1031

# ---------------- Mach-O 常量 ----------------
MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
CPU_SUBTYPE_ARM64_ALL = 0
MH_DYLIB = 6
MH_TWOLEVEL = 0x80
MH_DYLDLINK = 0x4
MH_NOUNDEFS = 0x1
MH_NO_REEXPORTED_DYLIBS = 0x00200000

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_LOAD_DYLIB = 0xC
LC_ID_DYLIB = 0xD
LC_DYLD_INFO_ONLY = 0x80000022
LC_BUILD_VERSION = 0x32
LC_LOAD_DYLINKER = 0xE
LC_UUID = 0x1B

PLATFORM_MACOS, PLATFORM_IOS = 1, 2
S_ZEROFILL = 0x1
S_ATTR_PURE_INSTRUCTIONS = 0x80000000
S_ATTR_SOME_INSTRUCTIONS = 0x00000400
S_REGULAR, S_CSTRING_LITERALS, S_4BYTE_LITERALS = 0x0, 0x2, 0x3

# 可以直接 1:1 绑定 Darwin 的数学/内存/字符串/时间函数（方案 §8）
PASSTHROUGH = set("""
_exit abort acos asin atan atan2 atof atoi atoll btowc calloc closelog cos exp exp2
fchmod fchmodat free freelocale frexp getenv getpid iswalpha_l iswblank_l iswcntrl_l
iswdigit_l iswlower_l iswprint_l iswpunct_l iswspace_l iswupper_l iswxdigit_l link
localeconv log log2 malloc mbrlen mbrtowc mbsnrtowcs mbsrtowcs mbtowc memchr memcmp
memcpy memmove memset newlocale nl_langinfo pathconf posix_memalign pow realloc remove
sched_yield setenv setlocale sin sleep strcasecmp strchr strcmp strcoll_l strdup
strftime_l strlen strncasecmp strncmp strrchr strstr strtod strtof strtok_r strtol
strtoll strtoll_l strtoul strtoull strtoull_l strxfrm_l symlink tan time timegm
towlower towlower_l towupper towupper_l unlinkat uselocale usleep wcrtomb wcscoll_l
wcslen wcsnrtombs wcstod wcstof wcstol wcstoll wcstoul wcstoull wcsxfrm_l wctob
wmemchr wmemcmp
""".split())


def align(v, a):
    return (v + a - 1) & ~(a - 1)


def uleb(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def sleb(v):
    out = bytearray()
    more = True
    while more:
        b = v & 0x7F
        v >>= 7
        if (v == 0 and not (b & 0x40)) or (v == -1 and (b & 0x40)):
            more = False
        else:
            b |= 0x80
        out.append(b)
    return bytes(out)


class Elf:
    def __init__(self, data):
        self.d = data
        if data[:4] != b'\x7fELF' or data[4] != 2:
            raise SystemExit('not ELF64')
        (self.e_type, self.e_machine, self.e_version, self.e_entry, self.e_phoff,
         self.e_shoff, self.e_flags, self.e_ehsize, self.e_phentsize, self.e_phnum,
         self.e_shentsize, self.e_shnum, self.e_shstrndx) = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
        if self.e_machine != 183:
            raise SystemExit('not AArch64 (machine=%d)' % self.e_machine)
        self.ph = []
        for i in range(self.e_phnum):
            o = self.e_phoff + i * 56
            t, fl, off, va, pa, fsz, msz, al = struct.unpack_from('<IIQQQQQQ', data, o)
            self.ph.append(dict(type=t, flags=fl, off=off, va=va, fsz=fsz, msz=msz, align=al))
        self.loads = [p for p in self.ph if p['type'] == PT_LOAD]
        self.tls = next((p for p in self.ph if p['type'] == PT_TLS), None)
        self.ehframe = next((p for p in self.ph if p['type'] == PT_GNU_EH_FRAME), None)
        self.sections = self._sections()
        self.dyn = self._dynamic()
        self._symbols()
        self._relocs()

    # ---- 节 ----
    def _sections(self):
        if not self.e_shoff:
            return []
        raw = []
        for i in range(self.e_shnum):
            o = self.e_shoff + i * 64
            name, typ, flags, addr, off, size, link, info, al, ent = struct.unpack_from('<IIQQQQIIQQ', self.d, o)
            raw.append(dict(name_off=name, type=typ, flags=flags, addr=addr, off=off,
                            size=size, link=link, ent=ent))
        stro = raw[self.e_shstrndx]['off']
        for s in raw:
            n = self.d[stro + s['name_off']:]
            s['name'] = n[:n.index(b'\0')].decode('latin1')
        return raw

    def sect(self, name):
        for s in self.sections:
            if s['name'] == name:
                return s
        return None

    def _dynamic(self):
        self.dynv = {}
        seg = next((p for p in self.ph if p['type'] == PT_DYNAMIC), None)
        if not seg:
            return
        o = seg['off']
        while True:
            tag, val = struct.unpack_from('<qQ', self.d, o)
            if tag == DT_NULL:
                break
            self.dynv.setdefault(tag, val)
            o += 16

    def vaddr_to_off(self, va):
        for p in self.loads:
            if p['va'] <= va < p['va'] + p['msz']:
                return p['off'] + (va - p['va'])
        return None

    def _symbols(self):
        self.symtab = []
        syma = self.dynv.get(DT_SYMTAB)
        stra = self.dynv.get(DT_STRTAB)
        if not syma or not stra:
            return
        so = self.vaddr_to_off(stra)
        self.strtab_off = so
        # 符号个数：用 hash 表或 rela 最大索引推断
        count = 0
        if DT_HASH in self.dynv:
            ho = self.vaddr_to_off(self.dynv[DT_HASH])
            count = struct.unpack_from('<I', self.d, ho + 4)[0]
        if not count:
            maxs = 0
            for rel_off, rel_sz in self._rela_ranges():
                for i in range(0, rel_sz, 24):
                    info = struct.unpack_from('<Q', self.d, rel_off + i + 8)[0]
                    maxs = max(maxs, info >> 32)
            count = maxs + 1
        to = self.vaddr_to_off(syma)
        for i in range(count):
            o = to + i * 24
            name, info, other, shndx, value, size = struct.unpack_from('<IBBHQQ', self.d, o)
            s = self.d[so + name:]
            nm = s[:s.index(b'\0')].decode('latin1') if name else ''
            self.symtab.append(dict(name=nm, info=info, shndx=shndx, value=value, size=size))

    def _rela_ranges(self):
        out = []
        r = self.dynv.get(DT_RELA)
        if r:
            sz = self.dynv.get(DT_RELASZ, 0)
            o = self.vaddr_to_off(r)
            if o is not None and sz:
                out.append((o, sz))
        j = self.dynv.get(DT_JMPREL)
        if j and self.dynv.get(DT_PLTREL, 0) == 7:
            sz = self.dynv.get(DT_PLTRELSZ, 0)
            o = self.vaddr_to_off(j)
            if o is not None and sz:
                out.append((o, sz))
        return out

    def _relocs(self):
        self.relocs = []
        for off, sz in self._rela_ranges():
            for i in range(0, sz, 24):
                r_off, r_info, r_add = struct.unpack_from('<QQq', self.d, off + i)
                self.relocs.append(dict(off=r_off, type=(r_info & 0xffffffff), sym=r_info >> 32, add=r_add))


# ---------------- 符号路由 ----------------
def route(name):
    if name.startswith('SDL_'):
        return 'sdl'
    if name in PASSTHROUGH:
        return 'system'
    return 'shim'


def shim_name(name):
    if name.startswith('__'):
        return '_bionic' + name          # __errno -> _bionic__errno
    return '_bionic_' + name             # stat    -> _bionic_stat


class MachO:
    PAGE = 0x4000

    def __init__(self, elf, platform, verbose=False):
        self.elf = elf
        self.platform = platform
        self.verbose = verbose
        self.base = 0
        self.dlls = []          # 依赖库名（按序）
        self.ordinal = {}       # name -> ordinal
        self.segments = []
        self.exports = []       # (name, addr)
        self.rebases = []       # (seg_index_section_off, addr_offset_value)
        self.binds = []         # (slot_va, symbol, addend, kind)

    # ---- 段规划 ----
    def plan(self):
        elf = self.elf
        segs = []
        for p in elf.loads:
            page_va = p['va'] & ~(self.PAGE - 1)
            lead = p['va'] - page_va
            segs.append(dict(elf=p, page_va=page_va, lead=lead,
                             vm=page_va, fsz=p['fsz'], msz=p['msz']))
        self.segments = segs
        # 文件名
        self.seg_names = ['__TEXT', '__DATA_CONST', '__DATA']
        # 依赖库
        self.dlls = ['/usr/lib/libSystem.B.dylib',
                     '@rpath/SDL3.framework/SDL3',
                     '@rpath/libbionic_shim.dylib']
        for i, n in enumerate(self.dlls):
            self.ordinal[n] = i + 1

    # ---- 收集 export / rebase / bind ----
    def collect(self):
        elf = self.elf
        for s in elf.symtab:
            if not s['name'] or s['shndx'] == 0:
                continue
            if s['info'] & 0x0f not in (1, 2, 10):   # GLOBAL/WEAK/IFUNC
                continue
            self.exports.append((s['name'], s['value'], s['info'] & 0xf))
        for r in elf.relocs:
            t = r['type']
            if t == R_AARCH64_RELATIVE:
                self.rebases.append((r['off'], r['add']))
            elif t in (R_AARCH64_JUMP_SLOT, R_AARCH64_ABS64, R_AARCH64_GLOB_DAT):
                if r['sym'] < len(elf.symtab):
                    se = elf.symtab[r['sym']]
                    if se['shndx'] != 0:
                        # 本 DSO 内部符号：目标 = st_value + addend（按镜像整体平移修正）
                        self.rebases.append((r['off'], se['value'] + r['add']))
                    else:
                        self.binds.append((r['off'], se['name'], r['add'], t))
                self.internal_relocs = getattr(self, 'internal_relocs', 0) + 1
            elif t == R_AARCH64_TLSDESC:
                self.binds.append((r['off'], '__tlsdesc__', r['add'], t))
            elif t == R_AARCH64_PREL32:
                continue  # 段内相对，布局保留即天然正确
            else:
                if self.verbose:
                    sys.stderr.write('[warn] 未处理重定位类型 %d @0x%x\n' % (t, r['off']))

    # ---- 生成 Mach-O ----
    def emit(self, init_array_hook=True):
        elf = self.elf
        segs = self.segments
        page = self.PAGE
        # 文件布局：header 页 + 各段（段起点文件偏移 = 段 page_va）
        # 段内容保持在 ELF 的精确相对偏移上：文件偏移 = 段 page_va + lead + (段内偏移)
        filesz_total = max(s['page_va'] + s['lead'] + s['msz'] for s in segs)
        # __LINKEDIT 放最后
        ncmds_est = 8 + 3 + 1
        cmds_size_est = 72 * 4 + 24 * ncmds_est + 0x400 + 0x400
        header_room = align(cmds_size_est, page)
        seg0_shift = header_room
        # 因为 header 占一个 page，所有段整体后移 seg0_shift，保持相对布局
        # 这样 code 段从 seg0_shift 开始；相对引用不变。
        self._shift = seg0_shift
        # 数据：拷贝各段
        buf = bytearray(seg0_shift)
        placed = []
        for i, s in enumerate(segs):
            start = seg0_shift + s['page_va']          # 段页起点（文件偏移）
            content = start + s['lead']                 # 内容起点
            need = content + s['fsz'] - len(buf)
            if need > 0:
                buf.extend(b'\0' * need)
            src = elf.d[elf.loads[i]['off']: elf.loads[i]['off'] + s['fsz']]
            buf[content:content + len(src)] = src
            # bss 补到 memsz
            tail = content + s['msz']
            if tail > len(buf):
                buf.extend(b'\0' * (tail - len(buf)))
            placed.append(dict(vm=s['page_va'] + seg0_shift, fileoff=start,
                               content_off=content, lead=s['lead'], fsz=s['fsz'], msz=s['msz']))
        # 虚拟地址 = 文件偏移（因为整体放在 base 0 + slide）
        for p_ in placed:
            p_['vm'] = p_['fileoff']
        image_end = len(buf)
        linkedit_off = align(image_end, page)
        if linkedit_off > len(buf):
            buf.extend(b'\0' * (linkedit_off - len(buf)))

        def seg_of_va(va):
            for i, p_ in enumerate(placed):
                if p_['vm'] <= va < p_['vm'] + p_['msz']:
                    return i, va - p_['vm']
            return None, None

        # ---- rebase / bind 字节流 ----
        # 简化：所有 rebase 都用 SET_SEGMENT_AND_OFFSET_ULEB + DO_REBASE_IMM_TIMES
        rebase_blob = bytearray()
        for va, add in sorted(self.rebases):
            si, so = seg_of_va(va)
            if si is None or si == 0:
                struct.pack_into('<Q', buf, va, (add + self._shift) & 0xFFFFFFFFFFFFFFFF)
                continue
            rebase_blob += bytes([0x21]) + uleb(si) + uleb(so) + bytes([0x51])
            struct.pack_into('<Q', buf, va, (add + self._shift) & 0xFFFFFFFFFFFFFFFF)


        # 修正上面 bind 流里多写的占位字节（保持简单：重建一份干净流）
        bind_blob = bytearray()
        shim_syms = []
        for va, sym, add, kind in sorted(self.binds):
            if kind == R_AARCH64_TLSDESC:
                dll, sym_out = '@rpath/libbionic_shim.dylib', '_bionic_tlsdesc_resolver'
            elif not sym:
                continue
            else:
                k = route(sym)
                if k == 'sdl':
                    dll, sym_out = '@rpath/SDL3.framework/SDL3', sym
                elif k == 'system':
                    dll, sym_out = '/usr/lib/libSystem.B.dylib', sym
                else:
                    dll, sym_out = '@rpath/libbionic_shim.dylib', shim_name(sym)
                    shim_syms.append(sym)
            bind_blob += bytes([0x11, self.ordinal[dll]])
            if add:
                bind_blob += bytes([0x60]) + sleb(add)
            bind_blob += bytes([0x40, 0]) + sym_out.encode() + b'\0'
            bind_blob += bytes([0x51])
            si2, so2 = None, None
            for i, p_ in enumerate(placed):
                if p_['vm'] <= va < p_['vm'] + p_['msz']:
                    si2, so2 = i, va - p_['vm']
                    break
            if si2 is None:
                self.skipped_binds = getattr(self, 'skipped_binds', 0) + 1
                continue
            bind_blob += bytes([0x21]) + uleb(si2) + uleb(so2)
            bind_blob += bytes([0x90])
            struct.pack_into('<Q', buf, va, 0)

        # ---- 符号表（__LINKEDIT） ----
        strtab = bytearray(b'\0')
        symtab = bytearray()

        def add_str(s):
            off = len(strtab)
            strtab.extend(s.encode() + b'\0')
            return off

        for name, addr, typ in sorted(self.exports):
            n = add_str('_' + name)
            n_type = 0x0f if typ == 2 else 0x0f   # N_SECT|N_EXT
            symtab += struct.pack('<IBBHQ', n, n_type, 1, 1, addr)

        symoff = linkedit_off
        buf.extend(symtab)
        stroff = len(buf)
        buf.extend(strtab)
        end = align(len(buf), page)
        buf.extend(b'\0' * (end - len(buf)))

        # ---- export trie ----
        trie_off = align(len(buf), 8)
        trie = _build_trie(sorted(set(self.exports)))
        buf.extend(trie)
        buf.extend(b'\0' * (align(len(buf), page) - len(buf)))

        # 重新排布 linkedit（简单：把 symtab/strtab/trie 都放在最终位置）
        # （上面已经 append，故此处 linkedit_off 指向 symoff）
        # ---- load commands ----
        seg_cmds = bytearray()
        for i, p_ in enumerate(placed):
            name = self.seg_names[i] if i < len(self.seg_names) else '__SEG%d' % i
            nsec = 0
            secs = b''
            if i == 0:
                # __TEXT 里给 .eh_frame 单独建节，供 Darwin unwinder 找到
                eh = self.elf.ehframe
                if eh:
                    secs += struct.pack('<16s16sQQIIIIIIII', b'__text', b'__TEXT',
                                        p_['content_off'], align(self.elf.sect('.text')['size'] if self.elf.sect('.text') else 0, 4),
                                        p_['fileoff'], 4, 0, 0, S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS, 0, 0, 0)
                    nsec += 1
                    # .eh_frame 节（在 __TEXT 内，地址就是 ELF 的绝对偏移）
                    eho = p_['fileoff'] + (eh['va'] - (p_['vm'] - p_['fileoff']))
                    secs += struct.pack('<16s16sQQIIIIIIII', b'__eh_frame', b'__TEXT',
                                        eho, eh['fsz'], eho, 3, 0, 0, S_REGULAR, 0, 0, 0)
                    nsec += 1
            ncmds = 72 + nsec * 80
            seg_cmds += struct.pack('<II16sQQQQIIII',
                                    LC_SEGMENT_64, ncmds, name.encode(),
                                    p_['vm'], p_['msz'], p_['fileoff'], p_['fsz'],
                                    7 if i == 0 else (3 if i == 1 else 3),
                                    5 if i == 0 else 3, nsec, 0)
            seg_cmds += secs

        def filetime_body(s, ln):
            # LC_LOAD_DYLIB 结构: cmd, cmdsize, name_offset(24), timestamp, current, compat
            body = struct.pack('<IIII', 24, 2, 0x10000, 0x10000)
            out = body + s
            return out + b'\0' * (ln - 24 - len(out))

        cmds = bytearray()
        ncmd = 0
        cmds += seg_cmds
        ncmd += len(placed)
        # LC_ID_DYLIB
        idn = '@rpath/libmew_relinked.dylib'
        idb = filetime_body(idn.encode() + b'\0', align(24 + len(idn) + 1, 8))
        cmds += struct.pack('<III', LC_ID_DYLIB, align(24 + len(idn) + 1, 8), 24) + idb
        ncmd += 1
        for d in self.dlls:
            b = filetime_body(d.encode() + b'\0', align(24 + len(d) + 1, 8))
            cmds += struct.pack('<III', LC_LOAD_DYLIB, align(24 + len(d) + 1, 8), 24) + b
            ncmd += 1
        # LC_DYLD_INFO_ONLY
        rb_off = len(buf)
        buf.extend(rebase_blob)
        bd_off = len(buf)
        buf.extend(bind_blob)
        buf.extend(b'\0' * (align(len(buf), 8) - len(buf)))
        cmds += struct.pack('<IIIIIIIIII', LC_DYLD_INFO_ONLY, 48, rb_off, len(rebase_blob),
                            bd_off, len(bind_blob), 0, 0, 0, 0)
        ncmd += 1
        # LC_SYMTAB
        cmds += struct.pack('<IIIIII', LC_SYMTAB, 24, symoff, len(symtab) // 16, stroff, len(strtab))
        ncmd += 1
        # LC_UUID
        cmds += struct.pack('<II', LC_UUID, 24) + bytes(range(16))
        ncmd += 1
        # LC_BUILD_VERSION
        plat = PLATFORM_IOS if self.platform == 'ios' else PLATFORM_MACOS
        cmds += struct.pack('<IIIIII', LC_BUILD_VERSION, 24, plat, 0x000F0000, 0, 0)
        ncmd += 1
        # __LINKEDIT 段
        le_start = align(min([symoff, bd_off]), page)
        le_end = align(len(buf), page)
        cmds += struct.pack('<II16sQQQQIIII', LC_SEGMENT_64, 72, b'__LINKEDIT',
                            le_start, le_end - le_start, le_start, le_end - le_start, 7, 5, 0, 0)
        ncmd += 1

        if len(cmds) > self._shift:
            raise SystemExit('load commands 超出预留 header 空间: %d > %d' % (len(cmds), self._shift))

        # ---- header ----
        hdr = struct.pack('<IIIIIIII', MH_MAGIC_64, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL,
                          MH_DYLIB, ncmd, len(cmds),
                          MH_DYLDLINK | MH_TWOLEVEL | MH_NO_REEXPORTED_DYLIBS, 0)
        buf[0:len(hdr)] = hdr
        buf[len(hdr):len(hdr) + len(cmds)] = cmds
        return bytes(buf), dict(placed=placed, symoff=symoff, strtab=len(strtab),
                                trie_off=trie_off, trie_len=len(trie),
                                rebases=len(self.rebases), binds=len(self.binds),
                                exports=len(self.exports), shim=len(set(shim_syms)))

def _build_trie(entries):
    """标准前缀压缩 export trie（entries: [(name, addr, type)]）。"""
    root = {}
    for name, addr, typ in entries:
        if not name:
            continue
        cur = root
        for ch in name:
            cur = cur.setdefault(ch, {})
        cur[''] = (addr, typ)
    out = bytearray()
    pos = {}

    def emit(node):
        kids = sorted(k for k in node if k != '')
        for k in kids:
            emit(node[k])
        pos[id(node)] = len(out)
        term = node.get('')
        tb = b''
        if term:
            addr, typ = term
            payload = uleb(0) + uleb(addr)
            tb = uleb(len(payload)) + payload
        out.extend(uleb(len(tb)))
        out.append(len(kids))
        for k in kids:
            out.extend(k.encode() + b'\0')
        for k in kids:
            out.extend(uleb(pos[id(node[k])]))
        out.extend(tb)

    emit(root)
    return bytes(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('elf')
    ap.add_argument('-o', '--out', required=True)
    ap.add_argument('--platform', choices=['ios', 'macos'], default='ios')
    ap.add_argument('--fixups', choices=['classic', 'chained'], default='classic')
    ap.add_argument('--verbose', action='store_true')
    a = ap.parse_args()
    data = open(a.elf, 'rb').read()
    elf = Elf(data)
    if len(elf.loads) != 3:
        print('[warn] PT_LOAD 数量 = %d（预期 3）' % len(elf.loads))
    m = MachO(elf, a.platform, a.verbose)
    m.plan()
    m.collect()
    blob, info = m.emit()
    open(a.out, 'wb').write(blob)
    print('wrote %s  %.1f MB' % (a.out, len(blob) / 1048576.0))
    print('  segments : %d' % len(info['placed']))
    for i, p in enumerate(info['placed']):
        print('   [%d] vm=0x%-9x off=0x%-9x filesz=0x%-8x memsz=0x%-8x'
              % (i, p['vm'], p['fileoff'], p['fsz'], p['msz']))
    print('  rebases  : %d' % info['rebases'])
    print('  binds    : %d (distinct shim syms %d)' % (info['binds'], info['shim']))
    print('  exports  : %d' % info['exports'])


if __name__ == '__main__':
    main()
