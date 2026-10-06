# -*- coding: utf-8 -*-
"""tmp_neontrace.py — 观测有状态生成器 0x2d9ed0 的输入/输出内存演化。

0x2d9ed0 每次调用参数恒定(x1,x2,x3)，说明它靠内存里的状态推进。
在入口 hook，dump 三个指针处的内存，跨调用对比即可看出「状态」与「输出」。
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.join(HERE, "captures", "rsa_scan"),
           os.path.join(HERE, "deliverables"), os.path.join(HERE, "toolchain"),
           os.path.join(HERE, "..", "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import unicorn  # noqa: E402
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1,  # noqa: E402
                                 UC_ARM64_REG_X2, UC_ARM64_REG_X3)
from authgen import DEV_BASE  # noqa: E402
from e_oracle import EOracle  # noqa: E402

OFF = 0x2D9ED0
snaps = []


def main():
    o = EOracle()
    e = o.s.e
    uc = e.uc

    def hook(uc_, addr, size, ud):
        x0 = uc_.reg_read(UC_ARM64_REG_X0)
        x1 = uc_.reg_read(UC_ARM64_REG_X1)
        x2 = uc_.reg_read(UC_ARM64_REG_X2)
        x3 = uc_.reg_read(UC_ARM64_REG_X3)
        rec = {"regs": (x0, x1, x2, x3), "mem": {}}
        for nm, p in (("x0", x0), ("x1", x1), ("x2", x2), ("x3", x3)):
            if p > 0x10000:
                try:
                    rec["mem"][nm] = e.rd(p, 32).hex()
                except Exception:
                    rec["mem"][nm] = "?"
        snaps.append(rec)

    uc.hook_add(unicorn.UC_HOOK_CODE, hook, begin=DEV_BASE + OFF, end=DEV_BASE + OFF + 4)

    KEY = bytes(range(16))
    IV = KEY[::-1]
    pt = b"\x00" * 32
    raw = o.enc(pt, KEY, IV)
    print("密文 %d 字节: %s" % (len(raw), raw.hex()))
    print("\n0x2d9ed0 调用 %d 次" % len(snaps))
    for i, r in enumerate(snaps):
        x0, x1, x2, x3 = r["regs"]
        print("\n--- 调用 %d ---" % i)
        print("  regs x0=%#x x1=%#x x2=%#x x3=%#x" % (x0, x1, x2, x3))
        for nm, v in r["mem"].items():
            print("    [%s] %s" % (nm, v))


if __name__ == "__main__":
    main()
