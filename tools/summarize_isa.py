#!/usr/bin/env python3
"""阶段 1：指令直方图汇总（Top-N 覆盖率）"""
import json
import sys

path = sys.argv[1] if len(sys.argv) > 1 else 'generated/isa_histogram.json'
d = json.load(open(path))
mn = d['mnemonics']
total = d['instructions']
print('total instructions', total, 'mnemonics', len(mn), 'decode_failures', d.get('decode_failures'))
top = sorted(mn.items(), key=lambda kv: -kv[1])
acc = 0
for i, (k, v) in enumerate(top[:30], 1):
    acc += v
    print('%2d. %-10s %8d  %5.2f%%  cum %5.2f%%' % (i, k, v, 100 * v / total, 100 * acc / total))
for n in (60, 100, 120, 150, 200):
    acc = sum(v for _, v in top[:n])
    print('top %d -> %.2f%% coverage' % (n, 100 * acc / total))
