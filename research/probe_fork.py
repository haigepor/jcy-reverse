# -*- coding: utf-8 -*-
"""probe_fork.py — 在 C 引擎首个发散点 (idx 252879, br x8 计算跳转表) 取
Unicorn 侧真值, 与 C 引擎现场逐寄存器对拍.

只读: 不修改 golden / 镜像 / trace, 只打印.
"""
import os
import sys
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from unicorn.arm64_const import (  # noqa: E402
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X8, UC_ARM64_REG_X9,
    UC_ARM64_REG_X10, UC_ARM64_REG_X20, UC_ARM64_REG_X21,
    UC_ARM64_REG_X25, UC_ARM64_REG_X30)
from decrypt_e import EDecryptor, _b64len  # noqa: E402
from authgen import DEV_BASE, OFF_PIPE  # noqa: E402

DB = DEV_BASE
# C 侧插桩点 (so 内偏移)
PROBES = [0x2e2ebc, 0x2e2ecc, 0x2e2ed0, 0x2e2ed4, 0x2e2ee4, 0x2e2ee8]
# 只关心第一次经过 (C 侧 idx 252879 前的那次)
NFIELDS = [("X0", UC_ARM64_REG_X0), ("X1", UC_ARM64_REG_X1),
           ("X8", UC_ARM64_REG_X8),
           ("X9", UC_ARM64_REG_X9), ("X10", UC_ARM64_REG_X10),
           ("X20", UC_ARM64_REG_X20), ("X21", UC_ARM64_REG_X21),
           ("X25", UC_ARM64_REG_X25), ("X30", UC_ARM64_REG_X30)]


def main():
    d = EDecryptor()
    d._oracle()
    o = d._o
    s = o.s
    e = s.e
    uc = e.uc

    K = bytes(range(0x05, 0x15))
    iv = K[::-1]
    PT = bytes(16 * 1)  # NBLK=1, 与 golden1 一致

    e.fix_long_string(0x688130, K)
    e.fix_long_string(0x688148, iv)
    L = next(c for c in range(1, len(PT) + 1) if _b64len(c) == len(PT))
    s._cur[0] = PT
    s._out.clear()
    inp = e.mkstr(b"\x00" * L)
    sret = s.sret

    hit = [0]
    recs = []

    def on_probe(u_, addr, sz, ud):
        off = addr - DB
        if off not in PROBES:
            return
        vals = {n: u_.reg_read(r) for n, r in NFIELDS}
        vals["pc"] = off
        recs.append(vals)
        hit[0] += 1

    for p in PROBES:
        uc.hook_add(unicorn.UC_HOOK_CODE, on_probe,
                    begin=DB + p, end=DB + p + 4)

    e.call(DEV_BASE + OFF_PIPE,
           (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148),
           sret=sret, timeout=600_000_000)

    print("=== Unicorn 侧分叉链逐条现场 (每次经过一组) ===")
    if not recs:
        print("未命中任何探针!")
        return
    # 按经过顺序分组: 每组从 0x2d8820 (链首) 到 0x2d8870 (链尾)
    groups = []
    cur = []
    for r in recs:
        if r["pc"] == 0x2d8820 and cur:
            groups.append(cur)
            cur = []
        cur.append(r)
        if r["pc"] == 0x2d8870 and cur:
            groups.append(cur)
            cur = []
    if cur:
        groups.append(cur)

    print("=== Unicorn 侧分叉链 (共 %d 组完整经过) ===" % len(groups))
    for gi, g in enumerate(groups[:3]):
        print("[组%d]" % gi)
        for r in g:
            print("   0x%x: X0=0x%-8x x8=0x%-18x x9=0x%-18x x10=0x%-18x x20=0x%-6x x25=0x%x"
                  % (r["pc"], r["X0"], r["X8"], r["X9"], r["X10"], r["X20"], r["X25"]))
    r0 = recs[0]
    print("\n首次进入: x0=0x%x x25=0x%x" % (r0["X0"], r0["X25"]))
    print("提示: msub x8,x8,x25,x0 => X8 = X8 - X25*X0 (无符号回绕)")


if __name__ == "__main__":
    main()
