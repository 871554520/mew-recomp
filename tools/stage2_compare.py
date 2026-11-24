#!/usr/bin/env python3
"""阶段 2：比对 Wine 侧与原生侧的返回值。"""
import json
import sys

g = json.loads(open(sys.argv[1]).read().strip().splitlines()[-1])
n = json.loads(open(sys.argv[2]).read().strip().splitlines()[-1])
print('guest ', g)
print('native', n)
if g['rax'] == n['rax']:
    print('RESULT PASS  rax =', g['rax'])
    sys.exit(0)
print('RESULT FAIL  guest=%s native=%s' % (g['rax'], n['rax']))
sys.exit(1)
