#!/usr/bin/env python3
"""阶段 2：为转译出的 sub_<va> 生成 lifted_entry 包装。"""
import sys

va = sys.argv[1]
out = sys.argv[2]
with open(out, 'w') as f:
    f.write('#include "x64_runtime.h"\n')
    f.write('void sub_%s(X64Ctx* ctx);\n' % va)
    f.write('void lifted_entry(X64Ctx* ctx) { sub_%s(ctx); }\n' % va)
print('wrapper for', va)
