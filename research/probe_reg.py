# -*- coding: utf-8 -*-
"""probe_reg.py — 在 idx 1085 之前的最后 13 条指令上, 输出**全寄存器快照**,
与 C 引擎 (gen_engine.py 里的 "R 0x..." 插桩) 逐条 diff, 定位第一个不同的寄存器.

用法: py -3.12 probe_reg.py > reports/reg_ref.txt 2>&1
      然后与 C 侧 run*.log 里 grep '^R ' 的部分对拍.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from unicorn.arm64_const import (  # noqa: E402
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
    UC_ARM64_REG_X8, UC_ARM64_REG_X9, UC_ARM64_REG_X11,
    UC_ARM64_REG_X12, UC_ARM64_REG_X19, UC_ARM64_REG_X20,
    UC_ARM64_REG_X21, UC_ARM64_REG_X22, UC_ARM64_REG_X25,
    UC_ARM64_REG_X26, UC_ARM64_REG_X27, UC_ARM64_REG_X28,
    UC_ARM64_REG_X30, UC_ARM64_REG_SP)
from decrypt_e import EDecryptor, _b64len  # noqa: E402
from authgen import DEV_BASE, OFF_PIPE  # noqa: E402

DB = DEV_BASE
PROBES = [0x2d8820, 0x2d8824, 0x2d882c, 0x2d8830, 0x2d8834,
          0x2d8838, 0x2d883c, 0x2d8840, 0x2d8844, 0x2d8858,
          0x2d886c, 0x2d8870]
FIELDS = [("X0", UC_ARM64_REG_X0), ("X1", UC_ARM64_REG_X1),
          ("X2", UC_ARM64_REG_X2), ("X8", UC_ARM64_REG_X8),
          ("X9", UC_ARM64_REG_X9), ("X11", UC_ARM64_REG_X11),
          ("X12", UC_ARM64_REG_X12),
          ("X19", UC_ARM64_REG_X19), ("X20", UC_ARM64_REG_X20),
          ("X21", UC_ARM64_REG_X21), ("X22", UC_ARM64_REG_X22),
          ("X25", UC_ARM64_REG_X25), ("X26", UC_ARM64_REG_X26),
          ("X27", UC_ARM64_REG_X27), ("X28", UC_ARM64_REG_X28),
          ("X30", UC_ARM64_REG_X30)]
MAXGROUPS = 400


def main():
    d = EDecryptor()
    d._oracle()
    o = d._o
    s = o.s
    e = s.e
    uc = e.uc

    K = bytes(range(0x05, 0x15))
    iv = K[::-1]
    PT = bytes(16 * 1)
    e.fix_long_string(0x688130, K)
    e.fix_long_string(0x688148, iv)
    L = next(c for c in range(1, len(PT) + 1) if _b64len(c) == len(PT))
    s._cur[0] = PT
    s._out.clear()
    inp = e.mkstr(b"\x00" * L)
    sret = s.sret

    ngroups = [0]

    def on_probe(u_, addr, sz, ud):
        off = addr - DB
        if off not in PROBES:
            return
        if ngroups[0] >= MAXGROUPS:
            return
        sp = u_.reg_read(UC_ARM64_REG_SP)
        parts = []
        for nm, r in FIELDS:
            parts.append("%s=0x%x" % (nm, u_.reg_read(r)))
        try:
            m0 = int.from_bytes(u_.mem_read(sp, 8), "little")
            m8 = int.from_bytes(u_.mem_read(sp + 8, 8), "little")
        except Exception:
            m0 = m8 = 0
        print("R 0x%x SP=0x%x %s [SP]=0x%x [SP+8]=0x%x"
              % (off, sp, " ".join(parts), m0, m8))
        if off == 0x2d8870:
            ngroups[0] += 1

    for p in PROBES:
        uc.hook_add(unicorn.UC_HOOK_CODE, on_probe, begin=DB + p, end=DB + p + 4)

    e.call(DEV_BASE + OFF_PIPE,
           (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148),
           sret=sret, timeout=900_000_000)
    print("# 共 %d 组" % ngroups[0], file=sys.stderr)


if __name__ == "__main__":
    main()
