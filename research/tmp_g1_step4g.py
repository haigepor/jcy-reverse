# -*- coding: utf-8 -*-
"""tmp_g1_step4g.py — .bss 表线性性检验。
假设：dump 区 = 若干 2048B 表（256 项 × 8B LE），每表是 GF(2) 线性映射 x→T[x]。
检验 T[0]==0 与 T[a]^T[b]==T[a^b]；若成立，抽基向量。
"""
import os
import struct

here = os.path.dirname(os.path.abspath(__file__))
data = open(os.path.join(here, "reports", "bss_dump_K1.bin"), "rb").read()

N = len(data)
print("dump 大小: %d B = %d 个 2048B 表" % (N, N // 2048))

for t_off in range(0, N, 2048):
    tab = [struct.unpack_from("<Q", data, t_off + i * 8)[0] for i in range(256)]
    t0_zero = tab[0] == 0
    lin_ok = 0
    lin_bad = 0
    for _ in range(4096):
        a = int.from_bytes(__import__("os").urandom(1), "little")
        b = int.from_bytes(__import__("os").urandom(1), "little")
        if tab[a] ^ tab[b] == tab[a ^ b]:
            lin_ok += 1
        else:
            lin_bad += 1
    if t0_zero and lin_bad == 0:
        basis = [hex(tab[1 << i]) for i in range(8)]
        print("表 @+0x%x: ✅ 线性 T[0]=0; 基 = %s" % (t_off, basis))
    else:
        nz = sum(1 for v in tab if v)
        print("表 @+0x%x: T[0]==0? %s; 线性 ok=%d bad=%d; 非零项=%d/256" % (
            t_off, t0_zero, lin_ok, lin_bad, nz))
