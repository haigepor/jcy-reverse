# -*- coding: utf-8 -*-
"""tmp_dbg_vals.py — Python 侧关键 PC 寄存器现场 (与 C 引擎 AT 打印对照)."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
sys.path.insert(0, os.path.join(HERE, "toolchain"))

import unicorn  # noqa: E402
from decrypt_e import EDecryptor, _b64len  # noqa: E402
from authgen import DEV_BASE, OFF_PIPE  # noqa: E402

WATCH = (0x2e2ddc, 0x2e2e10, 0x2e2e70, 0x60c838, 0x60c848, 0x60c84c, 0x2e49dc)

d = EDecryptor()
d._oracle()
o = d._o
s = o.s
e = s.e
uc = e.uc


def dbg(u_, a, sz, ud):
    from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X19,
                                    UC_ARM64_REG_X29, UC_ARM64_REG_X30, UC_ARM64_REG_SP)
    x0 = u_.reg_read(UC_ARM64_REG_X0)
    x19 = u_.reg_read(UC_ARM64_REG_X19)
    sp = u_.reg_read(UC_ARM64_REG_SP)
    lr = u_.reg_read(UC_ARM64_REG_X30)
    fp = u_.reg_read(UC_ARM64_REG_X29)
    try:
        m0 = e.rd(sp, 8).hex()
        m8 = e.rd(sp + 8, 8).hex()
    except Exception:
        m0 = m8 = "?"
    print("PY 0x%x X30=0x%x X29=0x%x SP=0x%x X0=0x%x X19=0x%x [SP]=%s [SP+8]=%s"
          % (a - DEV_BASE, lr, fp, sp, x0, x19, m0, m8), flush=True)


for pc in WATCH:
    uc.hook_add(unicorn.UC_HOOK_CODE, dbg, begin=DEV_BASE + pc, end=DEV_BASE + pc + 4)

K = bytes(range(0x05, 0x15))
iv = K[::-1]
PT = bytes(16)

L = next(c for c in range(1, len(PT) + 1) if _b64len(c) == len(PT))
s._cur[0] = PT
s._out.clear()
inp = e.mkstr(b"\x00" * L)
print("inp obj @0x%x len=%d" % (inp, L), flush=True)
e.call(DEV_BASE + OFF_PIPE, (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148),
       sret=s.sret, timeout=600_000_000)
print("done")
