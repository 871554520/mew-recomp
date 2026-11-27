#!/usr/bin/env python3
"""本地校验「手工维护的三个清单」是否和 PE 一致——省一轮 CI。

清单：
  1. `lifter/src/lifter_core.cpp` 里 `lookup_size_override` 的白名单（VA, 补长后大小）
  2. `tools/known_internal_labels.txt`（函数体内标签，走 --seeds-inside）
  3. 上面白名单的补长区间是否**段连续**（跨进别的函数就说明算错了）

用法：python3 tools/verify_lists.py /path/to/Mewgenics.exe
退出码 1 表示有问题。
"""
import re
import struct
import sys


def load_pe(path):
    data = open(path, 'rb').read()
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    nsec = struct.unpack_from('<H', data, pe + 6)[0]
    optsz = struct.unpack_from('<H', data, pe + 20)[0]
    opt = pe + 24
    image_base = struct.unpack_from('<Q', data, opt + 24)[0]
    secs = []
    sec = opt + optsz
    for i in range(nsec):
        o = sec + i * 40
        name = data[o:o + 8].rstrip(b'\0').decode('latin1')
        vsz, va, rsz, ro = struct.unpack_from('<IIII', data, o + 8)
        secs.append((name, va, vsz, ro, rsz))
    nrva, nsz = struct.unpack_from('<II', data, opt + 112 + 8 * 3)
    off = None
    for name, va, vsz, ro, rsz in secs:
        if va <= nrva < va + vsz:
            off = ro + (nrva - va)
            break
    funcs = []
    raw_ents = []
    if off is not None:
        for k in range(nsz // 12):
            b, e, u = struct.unpack_from('<III', data, off + k * 12)
            if b and e > b:
                funcs.append((image_base + b, image_base + e))
                raw_ents.append((b, e, u))
    funcs.sort()
    return data, image_base, secs, funcs, raw_ents


def rva_off(secs, rva):
    for _name, va, vsz, ro, rsz in secs:
        if va <= rva < va + vsz and rva - va < rsz:
            return ro + (rva - va)
    return None


def chain_primary(data, secs, raw_ents):
    """-> {begin_rva: 所属家族首段 rva}，只对带 UNW_FLAG_CHAININFO 的条目。"""
    out = {}
    for b, _e, u in raw_ents:
        p = rva_off(secs, u)
        if p is None:
            continue
        flags = (data[p] >> 3) & 0x1F
        if not (flags & 0x4):
            continue
        cnt = data[p + 2]
        q = (u + 4 + 2 * cnt + 3) & ~3
        qp = rva_off(secs, q)
        if qp is None:
            continue
        out[b] = struct.unpack_from('<I', data, qp)[0]   # chain.BeginAddress
    return out


# 手工逐字节核过、**允许**跨「非本家族」入口的两条（其余一律报错）：
#   0x1403862d0：rehash 主体跨 3 条 .pdata，但中间那条是独立子函数、不带 chaininfo；
#   0x140386180：同上，并且它把 0x1403862d0 整个并进来（`jmp 0x1403862d0` 尾跳）。
# 两条都在 lifter_core.cpp 的注释里逐字节说明过。
KNOWN_SPAN_EXCEPTIONS = {
    0x1403862d0,
    0x140386180,
    # 0x140062450：五条 .pdata 首尾相接，但**全都没有 CHAININFO**（flags=1 EHANDLER），
    # 首段 `ja` 直接跳到第 5 段，所以必须整段补长（逐段核过，见 lifter_core.cpp 注释）。
    0x140062450,
}


def main(argv):
    exe = argv[1] if len(argv) > 1 else '/tmp/Mewgenics.exe'
    data, image_base, secs, funcs, raw_ents = load_pe(exe)
    chained = chain_primary(data, secs, raw_ents)
    starts = {b for b, _e in funcs}
    # 注意：section.va 是 **RVA**，比较时统一换成 VA（这个坑本轮刚踩过）
    exec_ranges = [(image_base + va, image_base + va + vsz)
                   for name, va, vsz, _ro, _rsz in secs if name == '.text']
    lo = exec_ranges[0][0] if exec_ranges else 0
    hi = exec_ranges[0][1] if exec_ranges else 0
    bad = 0

    def in_text(va):
        return lo <= va < hi

    def next_start(va):
        for b, _e in funcs:
            if b > va:
                return b
        return None

    src = open('lifter/src/lifter_core.cpp', encoding='utf-8').read()
    i = src.index('lookup_size_override')
    j = src.index('};', i)
    table = re.findall(r'\{(0x[0-9a-fA-F]+)ULL,\s*(0x[0-9a-fA-F]+)\}', src[i:j])
    print('== 1. lookup_size_override 白名单 %d 条（图片基址 0x%x）' % (len(table), image_base))
    for va_s, sz_s in table:
        va = int(va_s, 16)
        size = int(sz_s, 16)
        end = va + size
        problems = []
        if not in_text(va):
            problems.append('不在 .text')
        # 补长区间不能越过「下一个函数起点」太多——除非那些段是 chaininfo 家族
        # （这里只做一个粗检查：区间内每 16 字节处不应出现 0xCC 长填充后紧跟别的函数起点）
        crossing = [b for b, _e in funcs if va < b < end]
        # 跨过的条目必须都属于**同一个 chaininfo 家族**（链式 RUNTIME_FUNCTION 指回本 VA）。
        # 不属于任何家族的条目被圈进来 = 把别的函数并进了本函数体，必须报错。
        # 家族完整性：chaininfo 家族的续段如果落在补长区间之外，就会留成「独立函数」，
        # 运行期被单独调用时 rsp 语义不成立（续段依赖外层已压的帧）。
        # run 46010953943 实测：0x140c11370 补到 0x876、家族实际到 0x8ec，
        # 尾巴 0x140c11be6 被单独调用 → [ABI VIOLATION] → SIGSEGV。
        fam_end = va
        tail_at_boundary = None
        for b, e in funcs:
            if b < va or b > va + size:
                continue
            if chained.get(b - image_base) != va - image_base:
                continue
            if b == va + size:
                # 续段正好从补长边界开始：可能是**故意**只补到收尾之前
                # （例 0x14004ba20 末尾那个 call+int3 冷桩，并进来会让 int3 进预扫、
                # 把整函数判成 UNIMPL），也可能是**漏掉**（例 0x140c11370 那次 SIGSEGV）。
                # 这里只提示，交给人判断。
                tail_at_boundary = (b, e)
                continue
            fam_end = max(fam_end, e)
        if tail_at_boundary is not None:
            print('   ℹ️ 0x%x + 0x%x 之后紧跟 0x%x 的 chaininfo 续段（至 0x%x）——'
                  '确认是故意还是漏掉' % (va, size, tail_at_boundary[0], tail_at_boundary[1]))
        if fam_end > va + size:
            bad += 1
            print('   ⚠️ 0x%x + 0x%x 会截断 chaininfo 家族（家族到 0x%x，少 0x%x 字节）'
                  % (va, size, fam_end, fam_end - (va + size)))
            continue
        alien = [b for b in crossing if chained.get(b - image_base) != va - image_base]
        if va in KNOWN_SPAN_EXCEPTIONS:
            print('   OK 0x%x + 0x%x -> 0x%x （手核例外：跨 %d 个非本家族入口）'
                  % (va, size, end, len(alien)))
            continue
        if alien:
            problems.append('圈进了 %d 个**非本家族**的 .pdata 入口（首个 0x%x）'
                            % (len(alien), alien[0]))
        if problems:
            bad += 1
            print('   ⚠️ 0x%x + 0x%x -> 0x%x  %s' % (va, size, end, '; '.join(problems)))
        else:
            tag = '（含 %d 个 chaininfo 段）' % len(crossing) if crossing else '（单段）'
            print('   OK 0x%x + 0x%x -> 0x%x %s' % (va, size, end, tag))

    print('\n== 2. tools/known_internal_labels.txt')
    n_in = 0
    for line in open('tools/known_internal_labels.txt', encoding='utf-8'):
        line = line.strip()
        if not line.startswith('0x'):
            continue
        va = int(line, 16)
        n_in += 1
        inside = any(b <= va < e for b, e in funcs)
        if not in_text(va):
            print('   ❌ 0x%x 不在 .text' % va)
            bad += 1
        elif not inside:
            # 不在函数体内 = 走 --seeds-inside 没有意义（应该进 extra_seeds）
            print('   ⚠️ 0x%x 不在任何 .pdata 区间内（应改走 extra_seeds 而不是 seeds-inside）' % va)
    print('   共 %d 条' % n_in)

    print('\n== 3. 结论')
    print('   %s' % ('全部通过' if bad == 0 else '有 %d 条硬错误' % bad))
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
