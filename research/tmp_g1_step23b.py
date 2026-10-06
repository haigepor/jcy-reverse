# -*- coding: utf-8 -*-
"""tmp_g1_step23b.py — 正确分段的跨块差分：找每块重复计算的 K 常量。

分段基准：
  - 0x2DA498 触发 2 次/真实块（decrypt_e 取偶数位），fire_idx//2 = 真实块号
  - 生成器入口 0x2d9ed0 每块调用 2 次（观察到成对出现）
对比两个相邻真实块的：
  1) 生成器区 PC 直方图是否逐 PC 相同（确定性流）
  2) 写内存 (addr,size,value) 的跨块相同值占比（可裁剪 setup）
  3) 堆工作区每块增量与内容差分
  4) top 热点 PC（后续反汇编目标）
"""
import os
import sys
import time
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import struct  # noqa: E402
import unicorn  # noqa: E402
from unicorn.arm64_const import UC_ARM64_REG_X1, UC_ARM64_REG_X4  # noqa: E402
from decrypt_e import EDecryptor  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

GEN = DEV_BASE + 0x2D9ED0
BOUND = DEV_BASE + 0x2DA498
GLO, GHI = DEV_BASE + 0x2CD000, DEV_BASE + 0x2EF600

K = bytes(range(0x30, 0x40))
NBLK = 4

d = EDecryptor()
d._oracle()
uc = d._uc
e = d._o.s.e

fire = [0]            # 0x2DA498 触发序号
gseg = [0]            # 生成器段号
ins = defaultdict(int)          # seg -> 生成器区指令数
pch = defaultdict(Counter)      # seg -> Counter(pc_off)
wr = defaultdict(list)          # seg -> [(addr,size,value)]
x4s = []                        # (seg, x4)
seg_of_fire = {}                # fire_idx -> seg（对齐用）


def on_bound(uc_, address, size, ud):
    fire[0] += 1


def on_gen(uc_, address, size, ud):
    gseg[0] += 1
    x4s.append((gseg[0], uc_.reg_read(UC_ARM64_REG_X4)))


def on_code(uc_, address, size, ud):
    if GLO <= address <= GHI:
        s = gseg[0]
        ins[s] += 1
        pch[s][address - DEV_BASE] += 1


def on_write(uc_, access, address, size, value, ud):
    if gseg[0] > 0:
        wr[gseg[0]].append((address, size, value & ((1 << (size * 8)) - 1)))


uc.hook_add(unicorn.UC_HOOK_CODE, on_bound, begin=BOUND, end=BOUND + 4)
uc.hook_add(unicorn.UC_HOOK_CODE, on_gen, begin=GEN, end=GEN + 4)
uc.hook_add(unicorn.UC_HOOK_CODE, on_code, begin=DEV_BASE, end=DEV_BASE + 0x800000)
uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, on_write)

t0 = time.time()
C, rk, CONST, Cb = d.calibrate(K, NBLK)
print("标定 %.1fs, 生成器段数=%d, fires=%d" % (time.time() - t0, gseg[0], fire[0]))
print("段指令数:", {s: ins[s] for s in sorted(ins)})
print("段 x4:", [(s, hex(x - 0x50000000 if x > 0x50000000 else x)) for s, x in x4s])

# 选两个指令量相近的连续段（真实相邻块的生成器体）
segs = [s for s in sorted(ins) if ins[s] > 100000]
if len(segs) >= 3:
    sa, sb = segs[-3], segs[-2]      # 倒数第二、第三段（避开首段 setup）
else:
    sa, sb = segs[0], segs[1]

print("\n=== 1) PC 直方图对比 段%d vs 段%d ===" % (sa, sb))
h1, h2 = pch[sa], pch[sb]
inter = set(h1) & set(h2)
same_cnt = sum(1 for p in inter if h1[p] == h2[p])
tot = sum(h1.values())
print("  不同 PC: %d vs %d, 交集 %d, 执行次数完全相同 %d (%.1f%%)" % (
    len(h1), len(h2), len(inter), same_cnt, 100.0 * same_cnt / max(1, len(inter))))
print("  指令数: %d vs %d, 交集指令数占比 %.1f%%" % (
    tot, sum(h2.values()), 100.0 * sum(min(h1[p], h2[p]) for p in inter) / max(1, tot)))

print("\n=== 2) 写内存跨块相同值 段%d vs 段%d ===" % (sa, sb))
def wmap(seg):
    m = {}
    for a, s, v in wr[seg]:
        m.setdefault((a, s), []).append(v)
    return m
w1, w2 = wmap(sa), wmap(sb)
keys1, keys2 = set(w1), set(w2)
common = keys1 & keys2
same_last = [k for k in common if w1[k][-1] == w2[k][-1]]
b_same = sum(s * len(w1[k]) for k in same_last for s in [k[1]])
b_all = sum(s for (a, s) in keys1)
print("  段%d: %d 次写/%d (addr,size)；与段%d 共同 addr %.1f%%；末值相同 %.1f%%" % (
    sa, len(wr[sa]), len(keys1), sb, 100.0 * len(common) / max(1, len(keys1)),
    100.0 * len(same_last) / max(1, len(common))))
print("  按字节数（含重复次数）：末值相同 %.0f / 全部 %.0f = %.1f%%" % (
    b_same, b_all, 100.0 * b_same / max(1, b_all)))

print("\n=== 3) top 热点 PC（段%d） ===" % sa)
for pc, n in h1.most_common(15):
    print("  +%#x  %d 次" % (pc, n))

# 保存段写入供后续分析
import json
json.dump({
    "segs": {str(s): ins[s] for s in sorted(ins)},
    "writes_sample": {str(s): [(hex(a), sz, hex(v)) for a, sz, v in wr[s][:2000]]
                       for s in (sa, sb)},
}, open(os.path.join(HERE, "reports", "g1_step23b.json"), "w"))
print("\n已存 reports/g1_step23b.json")
