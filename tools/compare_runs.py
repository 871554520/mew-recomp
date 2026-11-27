#!/usr/bin/env python3
"""两轮 artifact 的判据数字对照（当前 vs 基线），只看"变了什么"。

用法：python3 tools/compare_runs.py <当前目录> [基线目录]
默认基线 = 环境变量 MEW_BASE，否则只打当前值。

为什么单独一个脚本：迭代期每轮都在动同一批数字（FATAL、rsp-repair、ABI、UNIMPL、
watch 轨迹、manifest 尺寸），并排看才看得出"这轮到底推进了没有"。
"""
import os
import re
import sys

def load(d, *names):
    for n in names:
        # 先看 generated/：artifact 里根目录也可能有同名文件（二次构建的产物），
        # 主跑日志一定在 generated/ 下。之前顺序反了，导致拿错文件分析了一轮。
        for cand in (os.path.join(d, 'generated', n), os.path.join(d, n)):
            if os.path.exists(cand):
                with open(cand, 'r', errors='replace') as f:
                    return f.read()
    return ''

def metrics(d):
    err = load(d, 'runner.err')
    out = load(d, 'runner.out')
    shards = load(d, 'shards.log')
    manifest = load(d, os.path.join('stage3', 'manifest.tsv'))
    m = {}
    def c(pat, text):
        return len(re.findall(pat, text))
    m['FATAL'] = c(r'\[FATAL\]', err)
    m['dispatch_miss'] = c(r'Unmapped indirect target', err)
    m['ABI_VIOLATION'] = c(r'ABI VIOLATION', err)
    m['rsp_repair'] = c(r'\[rsp-repair\]', err)
    m['abi_repair'] = c(r'\[abi-repair\]', err)
    m['SAFE'] = c(r'\[SAFE\]', err)
    # nosafe 趟的 fault 点是最灵敏的"真崩在哪"信号（safe 趟会把非法访问吞掉）
    nosafe = load(d, 'runner_nosafe.err')
    fm = re.search(r'\[CRASH\][^\n]*fault=(0x[0-9a-f]+)', nosafe)
    m['nosafe_fault'] = int(fm.group(1), 16) if fm else 0
    m['RaiseException'] = c(r'RaiseException', err)
    m['ExitProcess'] = c(r'ExitProcess', err)
    m['TIMEOUT'] = c(r'\[TIMEOUT\]', err)
    m['CRASH'] = c(r'\[CRASH\]', err)
    m['LIVELOCK'] = c(r'LIVELOCK', err)
    m['watch'] = c(r'\[watch\]', err)
    m['fn_140385f80'] = c(r'\[fn\] 0x140385f80', err)
    m['merge'] = c(r'\[merge\]', shards)
    m['extend'] = c(r'\[extend\]', shards)
    m['merge_in_err'] = c(r'\[merge\]', err)
    m['unimpl_distinct'] = len(set(re.findall(r'\[UNIMPL (?:API|FUNC)\] (\S+)', err)))
    m['prefetchw'] = c('prefetchw', err)
    m['gpak'] = c('gpak', err)
    m['CreateFileW'] = c('CreateFileW', err)
    m['FindFirstFileW'] = c('FindFirstFileW', err)
    m['RESUME'] = c(r'\[seh\] RESUME', err)
    m['entry_returned'] = c('entry returned', out + err)
    m['main'] = c(r'\[main\]', err)
    # 容器轨迹：size 最大值 / rehash 写 mask 的次数
    sizes = [int(v, 16) for v in re.findall(r'\[watch\] W addr=0x1413c60c0 size=8 val=0x([0-9a-f]+)', err)]
    m['map_size_max'] = max(sizes) if sizes else 0
    m['map_rehash_writes'] = len(re.findall(r'\[watch\] W addr=0x1413c60(e0|e8)', err)) - 2  # 减去初始化器自己那两条
    for va, key in (('0x1403862d0', 'sz_1403862d0'), ('0x140be0a60', 'sz_140be0a60'),
                    ('0x140d6aedd', 'sz_140d6aedd'), ('0x1409b5230', 'sz_main')):
        hit = re.search(r'^' + va + r'\t(\d+)', manifest, re.M)
        m[key] = int(hit.group(1)) if hit else 0
    return m

def main():
    cur = sys.argv[1] if len(sys.argv) > 1 else '.'
    base = sys.argv[2] if len(sys.argv) > 2 else os.environ.get('MEW_BASE', '')
    a = metrics(cur)
    b = metrics(base) if base else None
    w = max(len(k) for k in a)
    if b:
        print(f'{"metric":{w}}  {"baseline":>10} {"current":>10}   delta')
        for k in a:
            d = a[k] - b.get(k, 0)
            flag = '' if d == 0 else ('  ↑' if d > 0 else '  ↓')
            print(f'{k:{w}}  {b.get(k,0):>10} {a[k]:>10}   {d:+d}{flag}')
    else:
        for k, v in a.items():
            print(f'{k:{w}}  {v}')

if __name__ == '__main__':
    main()
