#!/usr/bin/env python3
"""阶段 2：比对 Wine 侧与原生侧的 rax 与缓冲区哈希。"""
import json
import sys


def load(path):
    try:
        lines = [l for l in open(path).read().strip().splitlines() if l.strip().startswith('{')]
        if not lines:
            return None
        return json.loads(lines[-1])
    except Exception:
        return None


g = load(sys.argv[1])
n = load(sys.argv[2])
if g is None or n is None:
    print('RESULT FAIL  missing output  guest=%r native=%r' % (g, n))
    sys.exit(1)
ok = g.get('rax') == n.get('rax') and g.get('h') == n.get('h')
print('guest  %s' % g)
print('native %s' % n)
if ok:
    print('RESULT PASS  rax = %s  hash = %s' % (g['rax'], g['h']))
    sys.exit(0)
print('RESULT FAIL  rax g=%s n=%s | hash g=%s n=%s'
      % (g.get('rax'), n.get('rax'), g.get('h'), n.get('h')))
sys.exit(1)
