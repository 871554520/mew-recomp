#!/usr/bin/env python3
"""装机前静态门禁：检查一个 .app 目录 / .ipa 里的 Mach-O 依赖闭合性。

三个检查（任何一条不过就让 CI 红）：
  1. 每个 Mach-O 的 LC_LOAD_DYLIB 里 @rpath/... 的依赖，包内必须能找到文件；
  2. 每个 Mach-O 的 bind 流里每条强绑定（flags & WEAK_IMPORT == 0）的符号，
     必须在其所属依赖库的 export trie 里存在——否则真机 dyld 报
     "symbol not found: _XXX"，dlopen 直接失败（v0.9.0 就是这么回事）；
  3. 每个库的 __LINKEDIT 里 export trie 不能越界（dyld 会拒绝加载）。

用法：
  python3 ios_port/verify_bundle.py Mewgenics.app
  python3 ios_port/verify_bundle.py Mewgenics-v0.10.0-unsigned.ipa

只用标准库，直接在 Ubuntu runner / 本机都能跑。
"""
import os
import struct
import sys
import zipfile

LC_LOAD_DYLIB = 0xC
LC_ID_DYLIB = 0xD
LC_LOAD_WEAK = 0x80000018
LC_REEXPORT = 0x8000001F
LC_LOAD_UPWARD = 0x80000023
LC_LAZY_LOAD = 0x20
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYLD_INFO_ONLY = 0x80000022
LC_DYLD_EXPORTS_TRIE = 0x80000033
DEP_CMDS = {LC_LOAD_DYLIB, LC_LOAD_WEAK, LC_REEXPORT, LC_LOAD_UPWARD, LC_LAZY_LOAD}

BIND_WEAK_IMPORT = 0x1


def uleb(b, p):
    v = 0
    s = 0
    while True:
        x = b[p]
        p += 1
        v |= (x & 0x7F) << s
        s += 7
        if not x & 0x80:
            return v, p


def sleb(b, p):
    v = 0
    s = 0
    while True:
        x = b[p]
        p += 1
        v |= (x & 0x7F) << s
        s += 7
        if not x & 0x80:
            if x & 0x40:
                v -= 1 << s
            return v, p


class MachO:
    def __init__(self, data, name):
        self.raw = data
        self.name = name
        self.deps = []          # 按依赖序号（1 基）排列的 install name
        self.exports = set()    # 导出符号（带前导下划线）
        self.binds = []         # (ordinal, symbol, flags) —— ordinal 0 表示 SPECIAL
        self.self_name = None
        self.problems = []
        self._parse()

    def _parse(self):
        d = self.raw
        magic = struct.unpack_from('<I', d, 0)[0]
        if magic != 0xFEEDFACF:
            raise ValueError('不是 64 位 Mach-O（magic=0x%x）' % magic)
        ncmds = struct.unpack_from('<I', d, 16)[0]
        o = 32
        dyld_info = None
        exports_trie = None
        linkedit = None
        for _ in range(ncmds):
            cmd, csz = struct.unpack_from('<II', d, o)
            if cmd in DEP_CMDS:
                strx = struct.unpack_from('<I', d, o + 8)[0]
                s = d[o + strx:].split(b'\0')[0].decode('utf-8', 'replace')
                self.deps.append(s)
            elif cmd == LC_ID_DYLIB:
                strx = struct.unpack_from('<I', d, o + 8)[0]
                self.self_name = d[o + strx:].split(b'\0')[0].decode('utf-8', 'replace')
            elif cmd == LC_SEGMENT_64:
                nm = d[o + 8:o + 24].rstrip(b'\0').decode('utf-8', 'replace')
                vm, vs, fo, fs = struct.unpack_from('<QQQQ', d, o + 24)
                if nm == '__LINKEDIT':
                    linkedit = (fo, fs)
            elif cmd == LC_DYLD_INFO_ONLY:
                f = struct.unpack_from('<10I', d, o + 8)
                dyld_info = f
            elif cmd == LC_DYLD_EXPORTS_TRIE:
                exports_trie = struct.unpack_from('<II', d, o + 8)
            o += csz

        # 导出表
        if exports_trie is None and dyld_info and dyld_info[8] and dyld_info[9]:
            exports_trie = (dyld_info[8], dyld_info[9])
        if exports_trie:
            self.exports = self._read_exports(exports_trie[0])
            if linkedit and exports_trie[0] + exports_trie[1] > linkedit[0] + linkedit[1]:
                self.problems.append(
                    'export trie [0x%x,0x%x) 超出 __LINKEDIT [0x%x,0x%x)'
                    % (exports_trie[0], exports_trie[0] + exports_trie[1],
                       linkedit[0], linkedit[0] + linkedit[1]))
        else:
            self.problems.append('找不到 export trie')

        # bind 流
        if dyld_info and dyld_info[1] and dyld_info[2]:
            self.binds = self._read_binds(dyld_info[2], dyld_info[3])

    def _read_exports(self, base):
        d = self.raw
        out = set()

        def rec(off, prefix):
            p = base + off
            v, p = uleb(d, p)
            term = v
            if term:
                out.add(prefix)
                p += term
            nch = d[p]
            p += 1
            for _ in range(nch):
                e = p
                while d[e]:
                    e += 1
                nm = d[p:e].decode('utf-8', 'replace')
                p = e + 1
                v, p = uleb(d, p)
                rec(v, prefix + nm)

        rec(0, '')
        return out

    def _read_binds(self, off, size):
        d = self.raw
        p, end = off, off + size
        ordinal = 0
        sym = None
        flags = 0
        binds = []
        while p < end:
            op = d[p]
            p += 1
            imm = op & 0x0F
            code = op & 0xF0
            if code == 0x00:
                break
            elif code == 0x10:
                ordinal = imm
            elif code == 0x20:
                ordinal, p = uleb(d, p)
            elif code == 0x30:
                ordinal = (imm | 0xF0) - 0x100 if imm else 0
            elif code == 0x40:
                flags = imm
                e = p
                while d[e]:
                    e += 1
                sym = d[p:e].decode('utf-8', 'replace')
                p = e + 1
            elif code == 0x50:
                pass
            elif code == 0x60:
                _, p = sleb(d, p)
            elif code == 0x70:
                _, p = uleb(d, p)
            elif code == 0x80:
                _, p = uleb(d, p)
            elif code == 0x90:
                binds.append((ordinal, sym, flags))
            elif code == 0xA0:
                binds.append((ordinal, sym, flags))
                _, p = uleb(d, p)
            elif code == 0xB0:
                binds.append((ordinal, sym, flags))
            elif code == 0xC0:
                n, p = uleb(d, p)
                _, p = uleb(d, p)
                for _ in range(n):
                    binds.append((ordinal, sym, flags))
            else:
                break
        return binds


def load_bundle(path):
    """返回 {包内相对路径: bytes}，只收 Mach-O 候选。"""
    files = {}
    if os.path.isdir(path):
        for root, _dirs, names in os.walk(path):
            for n in names:
                full = os.path.join(root, n)
                rel = os.path.relpath(full, path)
                with open(full, 'rb') as f:
                    files[rel] = f.read()
    elif zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for n in z.namelist():
                if n.endswith('/'):
                    continue
                rel = n.split('Payload/', 1)[-1] if 'Payload/' in n else n
                files[rel] = z.read(n)
    else:
        raise SystemExit('既不是目录也不是 zip：%s' % path)
    return files


def is_macho(b):
    return len(b) >= 4 and struct.unpack_from('<I', b, 0)[0] == 0xFEEDFACF


def resolve_dep(rel_self, install_name, files):
    """把 @rpath/xxx、@loader_path/xxx、@executable_path/xxx 解析成包内路径。"""
    if install_name.startswith('@rpath/'):
        want = install_name[len('@rpath/'):]
        for rel in files:
            if rel.endswith(want):
                return rel
        base = os.path.basename(want)
        for rel in files:
            if os.path.basename(rel) == base:
                return rel
        return None
    if install_name.startswith('@loader_path/') or install_name.startswith('@executable_path/'):
        base = os.path.basename(install_name)
        for rel in files:
            if os.path.basename(rel) == base:
                return rel
        return None
    if install_name.startswith('/usr/lib/') or install_name.startswith('/System/'):
        return 'SYSTEM'
    return None


def main(argv):
    if len(argv) < 2:
        print('用法: verify_bundle.py <app 目录或 .ipa>')
        return 2
    path = argv[1]
    files = load_bundle(path)
    binfiles = {rel: b for rel, b in files.items() if is_macho(b)}
    print('包内文件 %d 个，其中 Mach-O %d 个：' % (len(files), len(binfiles)))
    for rel in sorted(binfiles):
        print('  %-58s %d B' % (rel, len(binfiles[rel])))

    errors = []
    machos = {}
    for rel in sorted(binfiles):
        m = MachO(binfiles[rel], rel)
        machos[rel] = m
        print('\n[%s]' % rel)
        print('  LC_ID         %s' % (m.self_name or '-'))
        print('  依赖          %s' % (', '.join(m.deps) or '-'))
        print('  导出 %d 个，bind %d 条' % (len(m.exports), len(m.binds)))
        for pr in m.problems:
            errors.append('%s: %s' % (rel, pr))

    # 检查 1：依赖闭合
    print('\n===== 检查 1：依赖闭合 =====')
    for rel, m in machos.items():
        for inst in m.deps:
            tgt = resolve_dep(rel, inst, files)
            if tgt is None:
                print('  ✗ %s 依赖 %s 在包内找不到' % (rel, inst))
                errors.append('%s: 依赖 %s 找不到' % (rel, inst))

    # 检查 2：bind 符号必须在所属依赖的导出表里（libSystem 跳过，包内无法核）
    print('===== 检查 2：bind 符号解析 =====')
    total = 0
    skipped_system = 0
    checked = 0
    for rel, m in machos.items():
        for ordinal, sym, flags in m.binds:
            total += 1
            if not sym:
                continue
            if ordinal <= 0 or ordinal >= 0xF0:
                continue  # SPECIAL（self / flat lookup / weak lookup）：运行时再查
            if ordinal > len(m.deps):
                print('  ✗ %s bind 序号 %d 超出依赖数 %d（%s）' % (rel, ordinal, len(m.deps), sym))
                errors.append('%s: bind 序号越界 %d (%s)' % (rel, ordinal, sym))
                continue
            inst = m.deps[ordinal - 1]
            tgt = resolve_dep(rel, inst, files)
            if tgt == 'SYSTEM':
                skipped_system += 1
                continue
            if tgt is None or tgt not in machos:
                print('  ✗ %s bind %s 指向 %s，包内没有该库' % (rel, sym, inst))
                errors.append('%s: bind 目标缺失 %s' % (rel, sym))
                continue
            checked += 1
            if sym not in machos[tgt].exports:
                weak = '(弱绑定，可缺)' if flags & BIND_WEAK_IMPORT else '(强绑定，必崩)'
                print('  ✗ %s bind 的 %s 在 %s 的导出表里没有 %s' % (rel, sym, tgt, weak))
                if not flags & BIND_WEAK_IMPORT:
                    errors.append('%s: %s 未被 %s 导出' % (rel, sym, tgt))

    print('  bind 总数 %d（可核 %d，libSystem %d）' % (total, checked, skipped_system))
    if skipped_system:
        print('  注：/usr/lib/libSystem.B.dylib 的符号这里不核（iOS 版本相关，真机才能定）')

    print('\n===== 结论 =====')
    if errors:
        counted = {}
        for e in errors:
            counted[e] = counted.get(e, 0) + 1
        for e, n in counted.items():
            print('  FAIL %s%s' % (e, ('  ×%d' % n) if n > 1 else ''))
        print('\n共 %d 处问题（去重后 %d 类）：这只包装到真机必然加载失败或行为异常。'
              % (len(errors), len(counted)))
        return 1
    print('  全部通过：依赖闭合、%d 条可核 bind 全部能在所属库里找到。' % checked)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
