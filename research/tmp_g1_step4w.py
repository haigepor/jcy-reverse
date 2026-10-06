# -*- coding: utf-8 -*-
"""tmp_g1_step4w.py — 从 gen_rks.json 离线破解调度（不再跑 emu）。"""
import os
import json
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
from decrypt_e import xr, SBOX, ISBOX  # noqa: E402

data = json.load(open(os.path.join(HERE, "reports", "gen_rks.json")))
K0 = bytes(range(0x30, 0x40))
if K0.hex() not in data:  # 兼容
    pass

samples = []
for Kh, rks in data.items():
    for r in range(1, 8):
        if str(r + 1) not in rks:
            continue
        a = bytes.fromhex(rks[str(r)])
        b = bytes.fromhex(rks[str(r + 1)])
        t0 = xr(b[:4], a[:4])
        samples.append({"K": Kh, "r": r, "a": a, "b": b, "t0": t0})
print("样本数", len(samples))

# --- 假设族: t0 = F(a 的某个 4B 投影) ^ rc
def words(v, mode):
    if mode == "w":          # 行词 w[i] = v[4i:4i+4]
        return [v[4 * i:4 * i + 4] for i in range(4)]
    if mode == "c":          # 列词 w[i] = v[i], v[i+4], v[i+8], v[i+12]
        return [bytes(v[4 * j + i] for j in range(4)) for i in range(4)]
    if mode == "cT":         # 列词但倒序字节
        return [bytes(v[4 * j + i] for j in range(3, -1, -1)) for i in range(4)]

def rot(w, m):
    if m == "l1":
        return w[1:] + w[:1]
    if m == "r1":
        return w[-1:] + w[:-1]
    return w

def sbm(w, m):
    if m == "s":
        return bytes(SBOX[x] for x in w)
    if m == "i":
        return bytes(ISBOX[x] for x in w)
    return w

RC = [1]
for _ in range(15):
    RC.append((RC[-1] << 1) ^ 0x1B if RC[-1] & 0x80 else RC[-1] << 1)

hits = []
for wm in ("w", "c", "cT"):
    for rm in ("l1", "r1", "none"):
        for sm in ("s", "i", "none"):
            # 检验: t0 = sbm(rot(word_j)) ^ (rc@pos0)  对某个 j 与 rc 偏移
            for j in range(4):
                for rcp in range(4):
                    ok = True
                    for s in samples:
                        wj = words(s["a"], wm)[j]
                        exp = sbm(rot(wj, rm), sm)
                        rc = RC[s["r"]] if rcp == 0 else (
                            RC[s["r"]] >> (8 * rcp) | 0) if rcp < 4 else 0
                        if rcp == 0:
                            e = bytes([exp[0] ^ RC[s["r"]]]) + exp[1:]
                        else:
                            e = exp
                        if e != s["t0"]:
                            ok = False
                            break
                    if ok:
                        hits.append((wm, rm, sm, j, rcp))
print("精确命中:", hits or "无")

# --- 逐字节一致性(允许逐位置独立σ): 统计 (输入字节,输出字节) 是否函数
from collections import defaultdict
for wm in ("w", "c"):
    for rm in ("l1", "r1", "none"):
        for sm in ("s", "i", "none"):
            m = [defaultdict(set) for _ in range(4)]
            for s in samples:
                wj = words(s["a"], wm)[2]  # 试 word2/3 都看
                pass
# 直接检验: 输出字节是否为某固定 S 盒作用于输入某字节(任意对齐)
print("\n=== 字节级函数性搜索: t0[p] = σ(a[q]) ? ===")
for q in range(16):
    for p in range(4):
        m = {}
        ok = True
        for s in samples:
            iv_, ov = s["a"][q], s["t0"][p]
            if iv_ in m and m[iv_] != ov:
                ok = False
                break
            m[iv_] = ov
        if ok and len(m) > 8:
            print("  t0[%d] = σ(a[%d]) 一致 (映射 %d 项)" % (p, q, len(m)))

# --- 仿射检验: t0 = L·w + c (GF(2)), w = a[12:16]
print("\n=== 仿射检验 g(w)=L·w^c ===")
import itertools
ws = [s["a"][12:16] for s in samples]
ts = [s["t0"] for s in samples]
# 建 32x32 线性方程组解 L 的每一输出位 — 用样本差分
# 取一批样本, 检验 g(x)^g(y) 是否只依赖 x^y (线性必充)
by_out = {}
consistent = True
for i in range(len(samples)):
    for j_ in range(i + 1, len(samples)):
        d_in = xr(ws[i], ws[j_])
        d_out = xr(ts[i], ts[j_])
        if d_in in by_out and by_out[d_in] != d_out:
            consistent = False
            break
        by_out[d_in] = d_out
    if not consistent:
        break
print("差分一致性(线性必要条件):", consistent, "(检验对数超限时提前停)")

# --- 是否 t0 与 a 无关而只与 r 有关? ---
print("\n=== t0 是否只依赖 r ===")
byr = {}
ok = True
for s in samples:
    if s["r"] in byr and byr[s["r"]] != s["t0"]:
        ok = False
    byr.setdefault(s["r"], s["t0"])
print("t0 只依赖 r?", ok)
if ok:
    for r in sorted(byr):
        print("  r=%d t0=%s" % (r, byr[r].hex()))
