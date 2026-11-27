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
    unimpl = Counter(re.findall(r'\[UNIMPL (?:API|FUNC)\] (\S+)', err))
    print(f'   UNIMPL distinct={len(unimpl)}', dict(unimpl.most_common(8)) if unimpl else '')
    print(f'   prefetchw              {count("prefetchw", err)}')
    print(f'   ABI VIOLATION          {count(r"ABI VIOLATION", err)}')
    print(f'   CRASH                  {count(r"\[CRASH\]", err)}   TIMEOUT {count(r"\[TIMEOUT\]", err)}   LIVELOCK {count(r"LIVELOCK", err)}')

    print('\n== 3. lifted C++ 抽查（hot_functions.txt）')
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
