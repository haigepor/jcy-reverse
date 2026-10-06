# -*- coding: utf-8 -*-
"""tmp_g1_step4l.py — 从仿真内存 dump 字节函数 f (0x2d2e78 起至返回) 的完整反汇编。"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402
from decrypt_e import EDecryptor  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

K = bytes(range(0x30, 0x40))
d = EDecryptor()
d._oracle()
d._enc_big(bytes(32), K, K[::-1])
uc = d._uc

code = bytes(uc.mem_read(DEV_BASE + 0x2D2E78, 0x400))
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
n = 0
for ins in md.disasm(code, DEV_BASE + 0x2D2E78):
    print("+%#08x  %-8s %s" % (ins.address - DEV_BASE, ins.mnemonic, ins.op_str))
    n += 1
    if n >= 120:
        break
