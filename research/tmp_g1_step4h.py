# -*- coding: utf-8 -*-
"""tmp_g1_step4h.py — .bss 表结构分析：零项分布、周期性、字节熵。"""
import os
import struct
from collections import Counter

here = os.path.dirname(os.path.abspath(__file__))
data = open(os.path.join(here, "reports", "bss_dump_K1.bin"), "rb").read()

qwords = [struct.unpack_from("<Q", data, i)[0] for i in range(0, len(data), 8)]
print("qword 总数=%d, 零项=%d" % (len(qwords), sum(1 for q in qwords if q == 0)))

# 零项位置（相对 dump 起点，8B 单位）
zeros = [i for i, q in enumerate(qwords) if q == 0]
print("零项位置(前40): %s" % zeros[:40])
if len(zeros) > 2:
    gaps = [b - a for a, b in zip(zeros, zeros[1:])]
    print("零项间距分布: %s" % Counter(gaps).most_common(8))

# 高 24 位直方图（看共享模式规模）
hi = Counter(q >> 40 for q in qwords if q)
print("\n高 24 位 top10: %s" % [(hex(h), c) for h, c in hi.most_common(10)])

# 低 8 位直方图 top10
lo = Counter(q & 0xFF for q in qwords if q)
print("低 8 位 top10: %s" % [(hex(h), c) for h, c in lo.most_common(10)])

# 16B 重复检测：相邻 qword 相同？
same_pairs = sum(1 for a, b in zip(qwords, qwords[1:]) if a == b and a)
print("相邻相同 qword 对=%d" % same_pairs)

# dump 前 128 qword 的 (高16,低16) 视图
print("\n前 64 qword 视图 (hi24|lo16，按 2 qword/行):")
for i in range(0, 64, 2):
    a, b = qwords[i], qwords[i + 1]
    print("  [%3d] %06x_%04x  %06x_%04x" % (
        i, a >> 40, a & 0xFFFF, b >> 40, b & 0xFFFF))
