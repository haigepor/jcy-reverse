# -*- coding: utf-8 -*-
"""tmp_g1_step3.py — 决定性实验：块间是否独立？

在 0x2d9ad4（块链第一调用）入口抓 x0-x3 / w22 / [x29-0x48]（疑似 K 调度），
对比相邻块：
  - w22 是否 = 块计数器（递增）
  - [x29-0x48] 是否跨块完全相同（每消息一次的调度，块输入不含前块状态）
若两者成立 → 块间独立 → 多进程并行路线成立（每 worker 直接算任意 b）。
附带：反汇编 0x2d7440 向后找外层函数入口与块循环结构。
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from unicorn.arm64_const import (  # noqa: E402
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X22, UC_ARM64_REG_X29,
)
from decrypt_e import EDecryptor  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

PREP = DEV_BASE + 0x2D9AD4
K = bytes(range(0x30, 0x40))

d = EDecryptor()
d._oracle()
uc = d._uc
e = d._o.s.e

snaps = []


def on_prep(uc_, address, size, ud):
    x29 = uc_.reg_read(UC_ARM64_REG_X29)
    sched = bytes(e.rd(x29 - 0x48, 48)) if x29 > 0x1000 else None
    snaps.append({
        "x0": uc_.reg_read(UC_ARM64_REG_X0), "x1": uc_.reg_read(UC_ARM64_REG_X1),
        "x2": uc_.reg_read(UC_ARM64_REG_X2), "x3": uc_.reg_read(UC_ARM64_REG_X3),
        "w22": uc_.reg_read(UC_ARM64_REG_X22) & 0xFFFFFFFF,
        "sched": sched.hex() if sched else None,
    })


uc.hook_add(unicorn.UC_HOOK_CODE, on_prep, begin=PREP, end=PREP + 4)

t0 = time.time()
C, rk, CONST, Cb = d.calibrate(K, 4)
print("标定 %.1fs, prep 调用 %d 次" % (time.time() - t0, len(snaps)))

print("\n=== prep(0x2d9ad4) 入口快照 ===")
for i, s in enumerate(snaps[:10]):
    print("[%2d] w22=%-10d x0=%#x x1=%#x x2=%#x x3=%#x" % (
        i, s["w22"], s["x0"], s["x1"], s["x2"], s["x3"]))
    print("     [x29-0x48]=%s" % (s["sched"][:64] if s["sched"] else None))

# 独立性判定
if len(snaps) >= 4:
    s1, s2, s3 = snaps[1], snaps[2], snaps[3]
    print("\n=== 判定 ===")
    print("w22 序列:", [s["w22"] for s in snaps[:8]], "→ 递增=%s" % (
        all(snaps[i]["w22"] < snaps[i + 1]["w22"] for i in range(min(6, len(snaps) - 1)))))
    same12 = s1["sched"] == s2["sched"]
    same13 = s1["sched"] == s3["sched"]
    print("[x29-0x48] 块1==块2: %s, 块1==块3: %s" % (same12, same13))
    if s1["sched"] and not same12:
        # 找第一个差异偏移
        a, b = bytes.fromhex(s1["sched"]), bytes.fromhex(s2["sched"])
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        print("  前 48B 内差异偏移:", diff[:20])
    indep = same12 and same13
    print("\n结论: 块间独立 = %s" % indep)
    if indep:
        print("  → 多进程并行路线成立：prep 一次(K)，各 worker 独立算任意 b！")
