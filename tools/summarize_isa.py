#!/usr/bin/env python3
"""阶段 1/3：指令直方图汇总（Top-N 覆盖率 + TSV）"""
import json
import sys

path = sys.argv[1] if len(sys.argv) > 1 else 'generated/isa_histogram.json'
out_tsv = sys.argv[2] if len(sys.argv) > 2 else 'generated/isa_freq.tsv'
d = json.load(open(path))
mn = d['mnemonics']
total = d['instructions']
top = sorted(mn.items(), key=lambda kv: -kv[1])
print('total instructions %d  mnemonics %d  decode_failures %d' %
      (total, len(mn), d.get('decode_failures', 0)))

acc = 0
print('\n--- Top 50 ---')
for i, (k, v) in enumerate(top[:50], 1):
    acc += v
    print('%2d. %-12s %9d  %6.3f%%  cum %6.3f%%' % (i, k, v, 100 * v / total, 100 * acc / total))

print('\n--- 累计覆盖率 ---')
for n in (30, 50, 60, 100, 120, 150, 200):
    a = sum(v for _, v in top[:n])
    print('top %-3d -> %6.3f%%' % (n, 100 * a / total))

with open(out_tsv, 'w') as f:
    f.write('rank\tmnemonic\tcount\tpct\tcum_pct\n')
    acc = 0
    for i, (k, v) in enumerate(top, 1):
        acc += v
        f.write('%d\t%s\t%d\t%.4f\t%.4f\n' % (i, k, v, 100 * v / total, 100 * acc / total))
print('\nwrote', out_tsv)
