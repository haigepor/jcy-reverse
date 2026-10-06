# -*- coding: utf-8 -*-
"""trace_py_1blk.py — Unicorn 侧 1 块运行 PC trace (与 C 引擎 trace 对比定位首发散点)."""
import os
import sys
import struct

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from decrypt_e import EDecryptor, _b64len  # noqa: E402
from authgen import DEV_BASE, OFF_PIPE  # noqa: E402

LIM = 5_000_000

d = EDecryptor()
d._oracle()
o = d._o
s = o.s
e = s.e
uc = e.uc

K = bytes(range(0x05, 0x15))
iv = K[::-1]
PT = bytes(16)

pcs = []


def cb(u_, a, sz, ud):
    if len(pcs) < LIM:
        pcs.append(a - DEV_BASE)


h = uc.hook_add(unicorn.UC_HOOK_CODE, cb, begin=DEV_BASE, end=DEV_BASE + 0x800000)

def dbg(u_, a, sz, ud):
    from unicorn.arm64_const import UC_ARM64_REG_X8, UC_ARM64_REG_X9, UC_ARM64_REG_X20, UC_ARM64_REG_SP
    x8 = u_.reg_read(UC_ARM64_REG_X8); x9 = u_.reg_read(UC_ARM64_REG_X9)
    x20 = u_.reg_read(UC_ARM64_REG_X20); sp = u_.reg_read(UC_ARM64_REG_SP)
    m8 = e.rd(x20 + 0x28, 8) if x20 else b""
    print("PY 0x2ce638 X8=0x%x X9=0x%x X20=0x%x [X20+28]=%s [SP+8]=%s"
          % (x8, x9, x20, m8.hex(), e.rd(sp + 8, 8).hex()))


h2 = uc.hook_add(unicorn.UC_HOOK_CODE, dbg, begin=DEV_BASE + 0x2ce638, end=DEV_BASE + 0x2ce638 + 4)

e.fix_long_string(0x688130, K)
e.fix_long_string(0x688148, iv)
L = next(c for c in range(1, len(PT) + 1) if _b64len(c) == len(PT))
s._cur[0] = PT
s._out.clear()
inp = e.mkstr(b"\x00" * L)
e.call(DEV_BASE + OFF_PIPE, (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148),
       sret=s.sret, timeout=600_000_000)
body = s._out.get("body", b"")
print("body 前32:", body[:32].hex(), "trace:", len(pcs))
with open(os.path.join(HERE, "reports", "trace_py_1blk.txt"), "w") as f:
    f.write("\n".join(hex(p) for p in pcs))
print("→ reports/trace_py_1blk.txt")
