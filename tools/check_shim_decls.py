#!/usr/bin/env python3
"""推送前自检：kApis 表里引用的每个垫片函数，必须在表**之前**可见
（有前置声明，或者定义写在表前面）。"""
import re, sys
path = sys.argv[1] if len(sys.argv) > 1 else 'shims/win32_kernel32.cpp'
src = open(path, encoding='utf-8').read()
m = re.search(r'static const DynApi kApis\[\]\s*=\s*\{', src)
tbl_start = m.start()
tail = src.find('\n    };', tbl_start)
table, prefix = src[tbl_start:tail], src[:tbl_start]
names = sorted(set(re.findall(r'\b(shim_[A-Za-z0-9_]+)\b', table)))
missing = []
for n in names:
    if re.search(r'void\s+' + re.escape(n) + r'\s*\(\s*X64Ctx\s*\*\s*\)\s*;', prefix): continue
    if re.search(r'void\s+' + re.escape(n) + r'\s*\(\s*X64Ctx\s*\*\s*[A-Za-z_]\w*\s*\)\s*\{', prefix): continue
    missing.append(n)
print('kApis 引用 %d 个垫片函数；表前可见 %d 个' % (len(names), len(names) - len(missing)))
if missing:
    print('\n缺失前置声明（照抄到声明区即可）：')
    for n in missing: print('void %s(X64Ctx*);' % n)
    sys.exit(1)
print('OK：全部可见')
