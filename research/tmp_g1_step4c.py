# -*- coding: utf-8 -*-
"""tmp_g1_step4c.py — dump churn 热读的 .bss 常量区 DEV+0x66e000~0x672000。"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

from decrypt_e import EDecryptor  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

K = bytes(range(0x30, 0x40))
d = EDecryptor()
d.calibrate(K, 2)
d._o = None
d._uc = None
d._oracle()
uc = d._uc

data = bytes(uc.mem_read(DEV_BASE + 0x66E000, 0x4000))
HOT = [0x66E020, 0x66E060, 0x66E0C0, 0x66F200, 0x66F250,
       0x670DD0, 0x670DE0, 0x670DF0, 0x6714E0, 0x671500,
       0x671510, 0x671520, 0x671540, 0x671BE0, 0x671C00,
       0x671C10, 0x671C30]

print("=== 热单元内容（各 64B） ===")
for off in HOT:
    chunk = data[off - 0x66E000: off - 0x66E000 + 64]
    print("DEV+%#x: %s" % (off, chunk.hex()))

print("\n=== 非零段概览（64B 步进，跳过全零） ===")
run = None
for i in range(0, 0x4000, 64):
    chunk = data[i:i + 64]
    if any(chunk):
        print("DEV+%#x: %s" % (0x66E000 + i, chunk.hex()))
