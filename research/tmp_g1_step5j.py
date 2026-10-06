# -*- coding: utf-8 -*-
"""tmp_g1_step5j.py — 线性选择子求解 + 第三组检验."""
import os
import json
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

br = json.load(open(os.path.join(HERE, "reports", "gen_branches.json")))
grpA = set(br["grpA"])
grpB = set(br["grpB"]) - {"72aff4a0fa5b1c2d3e4f5a6b7c8d9e0f"[:16]}  # 占位
grpB = [k for k in br["grpB"]]
outl = {"72aff4a0", "aff25760"}
Bc = [k for k in grpB if not any(k.startswith(o) for o in outl)]
Cc = [k for k in grpB if any(k.startswith(o) for o in outl)]
print("A=%d B=%d C=%d" % (len(grpA), len(Bc), len(Cc)))

# 线性选择子: 找 mask m 使 parity(K & m) = 0 for A, = 1 for B
# 方程: <m, K_i> = y_i over GF(2), 260 方程 128 未知 → 高斯消元
def bits(v):
    return [(v >> i) & 1 for i in range(128)]


rows = []
for kh in grpA:
    rows.append((bits(int.from_bytes(bytes.fromhex(kh), "big")), 0))
for kh in Bc:
    rows.append((bits(int.from_bytes(bytes.fromhex(kh), "big")), 1))

# 高斯消元 (增广)
aug = [r[:] + [y] for r, y in rows]
pivots = {}
n = len(aug)
for i in range(n):
    cur = aug[i]
    for pb, prow in pivots.items():
        if cur[pb]:
            cur = [a ^ b for a, b in zip(cur, prow)]
    nz = next((j for j in range(128) if cur[j]), None)
    if nz is None:
        if cur[128] == 1:
            print("选择子: 线性不可行 (矛盾方程)")
            break
        continue
    pivots[nz] = cur
else:
    print("选择子: 线性可行! 秩", len(pivots))
    # 回代得一个解 (自由变量取0)
    m = [0] * 128
    for pb in sorted(pivots, reverse=True):
        row = pivots[pb]
        s = row[128]
        for j in range(pb + 1, 128):
            if row[j] and m[j]:
                s ^= 1
        m[pb] = s
    mask = sum(b << i for i, b in enumerate(m))
    print("mask =", format(mask, "x"))
    # 全量验证
    okA = all(bin(int.from_bytes(bytes.fromhex(k), "big") & mask).count("1") % 2 == 0
              for k in grpA)
    okB = all(bin(int.from_bytes(bytes.fromhex(k), "big") & mask).count("1") % 2 == 1
              for k in Bc)
    okC = [bin(int.from_bytes(bytes.fromhex(k), "big") & mask).count("1") % 2 for k in Cc]
    print("A 组验证:", okA, " B 组验证:", okB, " C 组 parity:", okC)
    json.dump({"mask": format(mask, "x")},
              open(os.path.join(HERE, "reports", "gen_selector.json"), "w"))
