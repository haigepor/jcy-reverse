# -*- coding: utf-8 -*-
"""tmp_trace.py — 动态插桩 E 管线：看每个块调用 0x2d9ed0 时寄存器怎么变。

目的：搞清 CONST_b 是「怎么按块号生成的」。
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.join(HERE, "captures", "rsa_scan"),
           os.path.join(HERE, "deliverables"),
           os.path.join(HERE, "toolchain"),
           os.path.join(HERE, "..", "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import unicorn  # noqa: E402
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1,  # noqa: E402
                                 UC_ARM64_REG_X2, UC_ARM64_REG_X3)
from authgen import DEV_BASE  # noqa: E402
from e_oracle import EOracle  # noqa: E402

TARGETS = {
    0x2D7440: "block_loop",
    0x2D9014: "const_reader",
    0x2D9AD4: "extract",
    0x2D9ED0: "neon",
    0x2DA1C8: "reorder",
    0x2DA498: "round_driver",
}


def main():
    o = EOracle()
    e = o.s.e
    uc = e.uc
    logs = []

    def hook(uc_, addr, size, ud):
        nm = TARGETS.get(addr - DEV_BASE)
        if nm:
            logs.append((nm, uc_.reg_read(UC_ARM64_REG_X0), uc_.reg_read(UC_ARM64_REG_X1),
                         uc_.reg_read(UC_ARM64_REG_X2), uc_.reg_read(UC_ARM64_REG_X3)))

    for off in TARGETS:
        uc.hook_add(unicorn.UC_HOOK_CODE, hook, begin=DEV_BASE + off, end=DEV_BASE + off + 4)

    KEY = bytes(range(16))
    IV = KEY[::-1]
    pt = b"\x00" * 48                      # 3 块
    raw = o.enc(pt, KEY, IV)
    print("密文 %d 字节: %s" % (len(raw), raw.hex()))

    print("\n常量 @0x1e0120 (32B):", e.rd(DEV_BASE + 0x1E0120, 32).hex())

    print("\n=== 调用序列（按时间）共 %d 条 ===" % len(logs))
    for i, (nm, x0, x1, x2, x3) in enumerate(logs[:400]):
        print("  %3d %-12s x0=0x%x x1=0x%x x2=0x%x x3=0x%x"
              % (i, nm, x0, x1, x2, x3))

    # 每个函数被调了几次
    from collections import Counter
    print("\n调用次数:", dict(Counter(n for n, *_ in logs)))


if __name__ == "__main__":
    main()
