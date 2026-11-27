#!/usr/bin/env python3
"""一轮 stage3 artifact 的七条判据一键汇总。

用法：  python3 tools/check_run.py <解包后的 artifact 目录>
目录里应有 generated/runner*.err（没有 generated/ 就直接读当前目录）。

为什么要脚本：每轮判据都在换，靠手 grep 容易漏项、也容易把"预期内的 0"
当成"没跑到"。这里把"该出现什么"和"不该出现什么"分开列。
"""
import os
import re
import sys
from collections import Counter

def load(d, name):
    for cand in (os.path.join(d, 'generated', name), os.path.join(d, name)):
        if os.path.exists(cand):
            with open(cand, 'r', errors='replace') as f:
                return f.read()
    return ''

def count(pat, text, flags=0):
    return len(re.findall(pat, text, flags))

def main():
    d = sys.argv[1] if len(sys.argv) > 1 else '.'
    err = load(d, 'runner.err')
    out = load(d, 'runner.out')
    nosafe = load(d, 'runner_nosafe.err')
    hot = load(d, 'hot_functions.txt')
    # [merge]/[extend] 是 **lifter 阶段**打的，落在 shards.log（stage3 那一步
    # `--shards 64 ... 2>&1 | tee generated/shards.log`），不在 runner.err 里。
    shards = load(d, 'shards.log')
    # manifest 是「lift 之后」的权威视图：每条形如 `0x<va>\t<size>\t<shard>`。
    manifest = load(d, os.path.join('stage3', 'manifest.tsv'))
    print(f'== artifact: {d}')
    print(f'   runner.err {len(err)}B  runner_nosafe.err {len(nosafe)}B  runner.out {len(out)}B  hot_functions {len(hot)}B  shards.log {len(shards)}B')

    print('\n== 1. 该出现的（推进证据）')
    print(f'   RESUME                 {count(r"\[seh\] RESUME", err)}')
    print(f'   跳过当前初始化器        {count(r"跳过当前初始化器", err)}')
    print(f'   entry returned         {count(r"entry returned", err)}')
    print(f'   [main] 补调/已进过      {count(r"\[main\]", err)}')
    print(f'   [fn] 0x140385f80       {count(r"\[fn\] 0x140385f80", err)}   (走到容器插入才 >0)')
    print(f'   [extend] 0x1403862d0   {count(r"\[extend\] 0x1403862d0", shards)}   (白名单补长 43 -> 443，在 shards.log)')
    print(f'   [merge] 共享序言合并    {count(r"\[merge\]", shards)}   (在 shards.log)')
    for m in re.findall(r'\[merge\] .*', shards)[:8]:
        print(f'       {m.strip()}')
    for m in re.findall(r'\[extend\] .*', shards)[:4]:
        print(f'       {m.strip()}')
    print(f'   [watch] 行              {count(r"\[watch\]", err)}')
    print(f'   RaiseException         {count(r"RaiseException", err)}')
    for k in ('gpak', 'CreateFileW', 'FindFirstFileW', 'FindNextFileW'):
        print(f'   {k:22s} {count(k, err)}')

    print('\n== 2. 该消失的（回归信号）')
    fat = Counter(re.findall(r'Unmapped indirect target: (0x[0-9a-f]+)', err))
    print(f'   dispatch miss 目标：', dict(fat.most_common(8)) if fat else '无')
    for t in ('0x140d6aedd', '0x7f16895ffdc8'):
        print(f'      {t}: {fat.get(t, 0)}')
    reps = Counter(re.findall(r'\[rsp-repair\].*delta=(-?\d+)', err))
    print(f'   [rsp-repair] delta 分布：', dict(reps) if reps else '无')
    abr = Counter(re.findall(r'\[abi-repair\] target=(0x[0-9a-f]+) caller=(0x[0-9a-f]+)', err))
    print(f'   [abi-repair] 共 {sum(abr.values())} 条', dict(abr.most_common(5)) if abr else '')
    unimpl = Counter(re.findall(r'\[UNIMPL (?:API|FUNC)\] (\S+)', err))
    print(f'   UNIMPL distinct={len(unimpl)}', dict(unimpl.most_common(8)) if unimpl else '')
    print(f'   prefetchw              {count("prefetchw", err)}')
    print(f'   ABI VIOLATION          {count(r"ABI VIOLATION", err)}')
    print(f'   CRASH                  {count(r"\[CRASH\]", err)}   TIMEOUT {count(r"\[TIMEOUT\]", err)}   LIVELOCK {count("LIVELOCK", err)}')
    # ExitProcess 是"进程被 guest 主动结束"的信号（rc=255 常来自这里，而不是 main 返回）。
    # 它后面紧跟一个 CALL RING TRACE，第一条 FUNC 就是"谁叫的 abort"。
    print(f'   ExitProcess            {count("ExitProcess", err)}')
    m = re.search(r'\[shim\] ExitProcess\((\d+)\)\s*\n=+ CALL RING TRACE[^\n]*\n(?:\s+\[(\d+)\] FUNC (\S+)[^\n]*\n)?', err)
    if m:
        print(f'      code={m.group(1)}  第一个调用帧={m.group(3) or "?"}')

    # 容器插入循环是否正确收敛：那个初始化器只有 13 个键，
    # 所以 size 应停在小数字并继续跑下一个初始化器。
    # 之前 158d946 涨到 65 是 caller 循环指针被毁后的无限插入（到超时为止），不是成功。
    seq = [int(v, 16) for v in re.findall(r'\[watch\] W addr=0x1413c60c0 size=8 val=0x([0-9a-f]+)', err)]
    if seq:
        print(f'\n== 容器插入轨迹：共 {len(seq)} 次 ++，size {seq[0]} -> {seq[-1]}（最大 {max(seq)}）')
        print('   判定：' + ('✅ 收敛（<=20，符合 13 个键的初始化器）' if max(seq) <= 20
                          else '❌ 不收敛（>20，大概率又是循环指针被毁后无限插入）'))
        rh = re.findall(r'\[watch\] W addr=0x1413c60(e0|e8) size=8 val=0x([0-9a-f]+)', err)
        if rh:
            print('   rehash 写回: ' + ', '.join(f'0x{a}{v}' for a, v in rh))

    print('\n== 3. manifest 尺寸抽查（lift 之后的权威长度）')
    if manifest:
        size = {}
        for line in manifest.splitlines():
            parts = line.split('\t')
            if len(parts) >= 2 and parts[0].startswith('0x'):
                try:
                    size[parts[0].lower()] = int(parts[1])
                except ValueError:
                    pass
        # 期望值写在注释里，方便一眼对照
        want = {
            '0x1409b5230': '21   main 包装器（要进派发表，MEW_CALL_MAIN 才调得动）',
            '0x1403862d0': '443  白名单补长后 0x1bb（旧 43）',
            '0x140be0a60': '120  合并后 0x78（旧 0x23=35）',
            '0x140386180': '336  rehash 算桶数',
            '0x140385f80': '503  insert(range) 本体',
            '0x140d6aef5': '?     SEH 恢复点 fragment',
            '0x140d6aedd': '?     _initterm 循环头 fragment',
        }
        for va, note in want.items():
            got = size.get(va)
            print(f'   {va} = {got if got is not None else "缺"}   ({note})')
    else:
        print('   manifest.tsv 不在 artifact 里')

    print('\n== 4. 最后停在哪（快速定位，不用翻 20 万行）')
    for pat, label in ((r'\[shim\] .*', 'shim'),
                       (r'\[api\] <- \S+', 'api'),
                       (r'\[fn\] 0x[0-9a-f]+', 'fn'),
                       (r'\[merge\] .*', 'merge(在 shards.log)')):
        src = shards if 'merge' in label else err
        lines = re.findall(pat, src)
        if lines:
            print(f'   最后 3 条 {label}:')
            for ln in lines[-3:]:
                print('     ', ln.strip()[:120])
    # 最后一条 CRASH/超时/致命行，通常就是结局
    tail = re.findall(r'(?:\[CRASH\].*|\[TIMEOUT\].*|\[FATAL\].*|\[LIVELOCK\].*|Unhandled.*)', err)
    if tail:
        print('   最后一条致命/异常行:', tail[-1].strip()[:160])
    ro = out.strip().splitlines()
    if ro:
        print('   runner.out 尾部:', ro[-1][:120])

    print('\n== 5. lifted C++ 抽查（hot_functions.txt）')
    if hot:
        for va in ('140385f80', '140386180', '140386250', '1403862d0'):
            print(f'   sub_{va}: {"有" if ("void sub_"+va) in hot else "缺"}')
        print(f'   x64_bsr                {count("x64_bsr", hot)}   x64_clz {count("x64_clz", hot)}')
        fill = re.search(r'void sub_1403862d0.*?(?=\nvoid |\Z)', hot, re.S)
        if fill:
            n = len(re.findall(r'add rsp', fill.group(0)))
            print(f'   0x1403862d0 里 add rsp 次数 {n}（补长生效应 >=1，否则整函数被截断）')
    else:
        print('   hot_functions.txt 不在 artifact 里')

if __name__ == '__main__':
    main()
