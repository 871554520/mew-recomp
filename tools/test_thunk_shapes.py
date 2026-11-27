"""ff25 thunk 形状判定的本地单测（不需要 PE / lief）。

用法：python3 tools/test_thunk_shapes.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from thunk_shapes import import_thunk_shape  # noqa: E402

CASES = [
    # (名字, 16 字节, 期望)
    ("0x140bf4ff0 实拍（test rcx / je +7 / jmp[rip] / ret）",
     "4885c9740748ff25f4f67b00c3cccccc", True),
    ("纯尾跳（无守卫）", "48ff2511223344c3cccccccccccccc", True),
    ("jne 反向守卫", "4885c9750748ff25f4f67b00c3cccccc", True),
    ("test rdx 变体", "4885d2740748ff25f4f67b00c3cccccc", True),
    ("守卫跳出了槽（不是 thunk）", "4885c97410488b01c3cccccccccccccc", False),
    ("尾跳后面接的不是终止符", "48ff25112233448b01cccccccccccccc", False),
    ("尾跳不在槽首/槽 5（偏移 3）", "90909048ff2511223344c3cccccccccc", False),
    ("普通函数体（test+条件跳+mov）", "4885c97405488b01c3cccccccccccccc", False),
]


def main() -> int:
    bad = 0
    for name, hexs, want in CASES:
        # 真机上槽内不足 16 字节的部分一律是 cc 填充，这里同样补齐
        buf = (bytes.fromhex(hexs) + b"\xcc" * 16)[:16]
        got = import_thunk_shape(buf, 0)
        ok = (got == want)
        print(("PASS " if ok else "FAIL ") + name + f"  got={got} want={want}")
        if not ok:
            bad += 1
    print(f"\n{len(CASES) - bad}/{len(CASES)} 通过")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
