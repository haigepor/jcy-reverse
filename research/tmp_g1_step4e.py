# -*- coding: utf-8 -*-
"""tmp_g1_step4e.py — .bss churn 材料是否 K 相关？两把 K 各 dump 一次并 diff。
顺带：材料与 expand(K)/F(K) 的关系离线比对。
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

from decrypt_e import EDecryptor, expand, F  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

REG = (0x66E000, 0x4000)


def dump_for_key(K):
    d = EDecryptor()
    d._oracle()
    # 触发一次真实运行让材料就位
    d._enc_big(bytes(32), K, K[::-1])
    uc = d._uc
    lo, sz = REG
    return bytes(uc.mem_read(DEV_BASE + lo, sz))


K1 = bytes(range(0x30, 0x40))
K2 = b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv"[:16]  # 真实风格 K16

m1 = dump_for_key(K1)
m2 = dump_for_key(K2)
same = m1 == m2
print("两 K 的 .bss[%#x,%#x) 完全相同? %s" % (REG[0], REG[0] + REG[1], same))
if not same:
    diffs = sum(1 for a, b in zip(m1, m2) if a != b)
    print("差异字节数: %d / %d" % (diffs, len(m1)))

# 热单元对照
HOT = [0x66E020, 0x66F200, 0x670DD0, 0x671500, 0x671C00]
for off in HOT:
    i = off - REG[0]
    print("DEV+%#x K1: %s" % (off, m1[i:i + 32].hex()))
    print("DEV+%#x K2: %s" % (off, m2[i:i + 32].hex()))

# 离线比对：rk 展开 / F 单块 是否出现在材料里
rk1 = expand(K1)
rk_bytes = b"".join(bytes(r) for r in rk1)
print("\nrk(K1) 176B 在 K1 材料中? %s" % (rk_bytes[:16] in m1 or rk_bytes[16:32] in m1))
ct1 = F(bytes(16), rk1)
print("F(0,rk1) 在材料中? %s" % (ct1 in m1))

# 保存两份 dump 供后续
open(os.path.join(HERE, "reports", "bss_dump_K1.bin"), "wb").write(m1)
open(os.path.join(HERE, "reports", "bss_dump_K2.bin"), "wb").write(m2)
print("已存 reports/bss_dump_K1.bin / K2.bin")
