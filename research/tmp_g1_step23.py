# -*- coding: utf-8 -*-
"""tmp_g1_step23.py — 生成器 0x2d9ed0 ABI 发现 + 每块重复计算剖析（STEP2+3）。

在一次 3 块标定运行中同时挂四类钩子：
  A. 0x2DA498      块边界（x_b 捕获，与 decrypt_e 相同）→ 分块
  B. 0x2d9ed0 入口 x0-x7/LR + 指针内存快照 → ABI
  C. 全域代码计数   总指令/生成器区(0x2cd000-0x2ef600)占比、PC 直方图（分块）
  D. 内存写入       (addr,size,value) 分块记录 → 跨块相同值 = 可裁剪 setup
"""
import os
import sys
import time
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import struct  # noqa: E402
import unicorn  # noqa: E402
from unicorn.arm64_const import (  # noqa: E402
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7,
    UC_ARM64_REG_LR, UC_ARM64_REG_PC,
)
from decrypt_e import EDecryptor  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

GEN = DEV_BASE + 0x2D9ED0          # 生成器入口
BOUND = DEV_BASE + 0x2DA498        # 块边界
GLO, GHI = DEV_BASE + 0x2CD000, DEV_BASE + 0x2EF600   # 生成器机械区

K = bytes(range(0x30, 0x40))       # 任意固定 K
NBLK = 3

d = EDecryptor()
d._oracle()
uc = d._uc
e = d._o.s.e

blk = [0]                # 当前块号（在边界钩子里递增前先记当前）
cur_blk = [0]
ins_total = [0]
ins_gen = [0]
pc_hist = defaultdict(Counter)     # blk -> Counter(pc_off)
calls = []                         # 生成器入口实参
writes = defaultdict(list)         # blk -> [(addr, size, value)]
wmap_cache = {}
caps = []                          # 块边界 x_b（对照 decrypt_e._cap）


def rd_ptr_mem(addr, n=48):
    try:
        return bytes(e.rd(addr, n)).hex()
    except Exception:
        return None


def on_bound(uc_, address, size, ud):
    # 与 decrypt_e 相同的 x_b 捕获 + 分块推进
    from unicorn.arm64_const import UC_ARM64_REG_X1
    x1 = uc_.reg_read(UC_ARM64_REG_X1)
    b = struct.unpack("<Q", e.rd(x1, 8))[0]
    val = b"".join(e.rd(struct.unpack("<Q", e.rd(b + i * 24, 8))[0], 4) for i in range(4))
    caps.append(val.hex())
    cur_blk[0] += 1


def on_gen(uc_, address, size, ud):
    regs = [uc_.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                      UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5,
                                      UC_ARM64_REG_X6, UC_ARM64_REG_X7)]
    lr = uc_.reg_read(UC_ARM64_REG_LR)
    calls.append({
        "blk": cur_blk[0],
        "x0": regs[0], "x1": regs[1], "x2": regs[2], "x3": regs[3],
        "x4": regs[4], "x5": regs[5], "x6": regs[6], "x7": regs[7],
        "lr": lr - DEV_BASE,
        "m_x0": rd_ptr_mem(regs[0]) if regs[0] > 0x1000 else None,
        "m_x1": rd_ptr_mem(regs[1]) if regs[1] > 0x1000 else None,
        "m_x2": rd_ptr_mem(regs[2]) if regs[2] > 0x1000 else None,
    })


def on_code(uc_, address, size, ud):
    ins_total[0] += 1
    off = address - DEV_BASE
    if GLO <= address <= GHI:
        ins_gen[0] += 1
        pc_hist[cur_blk[0]][off] += 1


def on_write(uc_, access, address, size, value, ud):
    writes[cur_blk[0]].append((address, size, value & ((1 << (size * 8)) - 1)))


uc.hook_add(unicorn.UC_HOOK_CODE, on_bound, begin=BOUND, end=BOUND + 4)
uc.hook_add(unicorn.UC_HOOK_CODE, on_gen, begin=GEN, end=GEN + 4)
uc.hook_add(unicorn.UC_HOOK_CODE, on_code, begin=DEV_BASE, end=DEV_BASE + 0x800000)
uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, on_write)

t0 = time.time()
C, rk, CONST, Cb = d.calibrate(K, NBLK)
dt = time.time() - t0
print("标定 %d 块 %.1fs（含钩子开销）" % (NBLK, dt))
print("x_b 捕获:", len(caps), " CONST[1]=", bytes(CONST[1]).hex()[:32])

print("\n=== B. 生成器入口实参（共 %d 次调用） ===" % len(calls))
for i, c in enumerate(calls[:12]):
    print("[%d] blk=%d lr=%#x x0=%#x x1=%#x x2=%#x x3=%#x x4=%#x x5=%#x" % (
        i, c["blk"], c["lr"], c["x0"], c["x1"], c["x2"], c["x3"], c["x4"], c["x5"]))
    if c["m_x1"]:
        print("     [x1]=%s" % c["m_x1"][:64])
    if c["m_x2"]:
        print("     [x2]=%s" % c["m_x2"][:64])
if len(calls) > 12:
    per_blk = Counter(c["blk"] for c in calls)
    print("  ... 每块调用次数:", dict(per_blk))

print("\n=== C. 指令分布 ===")
print("总指令 %d，生成器区 %d (%.1f%%)" % (ins_total[0], ins_gen[0],
      100.0 * ins_gen[0] / max(1, ins_total[0])))
for b in sorted(pc_hist):
    print("  块%d: 生成器区指令 %d, 不同 PC %d" % (b, sum(pc_hist[b].values()), len(pc_hist[b])))
if 1 in pc_hist and 2 in pc_hist:
    h1, h2 = pc_hist[1], pc_hist[2]
    same = sum(min(h1[p], h2.get(p, 0)) for p in h1)
    only1 = sum(h1[p] for p in h1 if p not in h2)
    diff = sum(abs(h1[p] - h2.get(p, 0)) for p in set(h1) | set(h2))
    print("  块1 vs 块2 直方图: 完全一致部分 %.1f%%, 仅块1有 %d, 直方图总偏差 %d" % (
        100.0 * same / max(1, sum(h1.values())), only1, diff))

print("\n=== D. 内存写入分析 ===")
for b in sorted(writes):
    ws = writes[b]
    uniq_addr = len(set(w[0] for w in ws))
    print("  块%d: %d 次写, %d 个不同地址" % (b, len(ws), uniq_addr))
if 1 in writes and 2 in writes:
    w1 = {}
    for a, s, v in writes[1]:
        w1.setdefault((a, s), []).append(v)
    w2 = {}
    for a, s, v in writes[2]:
        w2.setdefault((a, s), []).append(v)
    same_av = [k for k in w1 if k in w2 and w1[k][-1] == w2[k][-1]]
    tot1 = len(w1)
    print("  块1 唯一(addr,size)=%d，其中块2 写了完全相同值 = %d (%.1f%%)" % (
        tot1, len(same_av), 100.0 * len(same_av) / max(1, tot1)))
    # 相同值写的字节数体量
    sz_same = sum(s for (a, s) in same_av for _ in range(1))
    sz_all = sum(s for (a, s) in w1)
    print("  按字节数：相同 %d / 全部 %d (%.1f%%)" % (sz_same, sz_all, 100.0 * sz_same / max(1, sz_all)))
    for k in same_av[:10]:
        print("    例: addr=%#x size=%d val=%#x" % (k[0] - DEV_BASE, k[1], w1[k][-1]))
