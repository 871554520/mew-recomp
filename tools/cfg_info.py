#!/usr/bin/env python3
"""从 PE Load Config 提取 CFG 槽位与 GFIDS（手册代码 1 第 1 步）"""
import json
import sys

import lief

binary = lief.PE.parse(sys.argv[1])
meta_path = sys.argv[2] if len(sys.argv) > 2 else None
cfg = {"guard_check_va": 0, "guard_dispatch_va": 0, "gfids": []}
if binary.has_configuration:
    lc = binary.load_configuration
    cfg["guard_check_va"] = int(getattr(lc, "guard_cf_check_function_pointer", 0) or 0)
    cfg["guard_dispatch_va"] = int(getattr(lc, "guard_cf_dispatch_function_pointer", 0) or 0)
    for rva in getattr(lc, "guard_cf_functions", []):
        cfg["gfids"].append(binary.optional_header.imagebase + int(rva))
print("guard_check_va=0x%x guard_dispatch_va=0x%x gfids=%d"
      % (cfg["guard_check_va"], cfg["guard_dispatch_va"], len(cfg["gfids"])))
if meta_path:
    json.dump(cfg, open(meta_path, "w"), indent=1)
    print("wrote", meta_path)
