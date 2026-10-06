# -*- coding: utf-8 -*-
"""tmp_g1_step5y.py — u=rk0? 调度=expand(u)? 多变体测试."""
import os
import json
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
from decrypt_e import xr, expand, SBOX, ISBOX, T, _gmul  # noqa: E402

MJ = json.load(open(os.path.join(HERE, "reports", "gen_M.json")))
emapM = {int(k): int(v, 16) for k, v in MJ["emap"].items()}


def Mmap(v_int):
    out, vv, j = 0, vv_int if False else v_int, 0
    while v_int:
        if v_int & 1:
            out ^= emapM.get(j, 0)
        v_int >>= 1
        j += 1
    return out


data = json.load(open(os.path.join(HERE, "reports", "gen_rks3.json")))

us = {}
for kh, rec in data.items():
    K = bytes.fromhex(kh)
    iv = K[::-1]
    u = xr(bytes.fromhex(rec["preSB0"]),
           Mmap(int.from_bytes(iv, "big")).to_bytes(16, "big"))
    us[kh] = u

# 变体
def variants(u):
    yield "u", u
    yield "T(u)", bytes(T(list(u)))
    yield "SB(u)", bytes(SBOX[x] for x in u)
    yield "iSB(u)", bytes(ISBOX[x] for x in u)
    yield "rev(u)", u[::-1]
    yield "T(SB(u))", bytes(T(list(bytes(SBOX[x] for x in u))))


best = {}
for kh, rec in data.items():
    u = us[kh]
    rks = {int(r): bytes.fromhex(v) for r, v in rec["rks"].items()}
    for name, seed in variants(u):
        try:
            sch = expand(seed)
        except Exception:
            continue
        # expand 返回 list[round keys]? 每轮 16B
        n_ok = 0
        for r in range(1, 9):
            if r < len(sch) and sch[r] == rks[r]:
                n_ok += 1
        best.setdefault(name, 0)
        best[name] = max(best[name], n_ok)
print("expand 变体最大匹配轮数 (of 8):", best)

# u[j] 是否只依赖 K[0]? 功能依赖
dep = [dict() for _ in range(16)]
nonfunc = []
for kh, u in us.items():
    K0 = int(kh[0:2], 16)
    for j in range(16):
        d = dep[j]
        if K0 in d and d[K0] != u[j]:
            nonfunc.append(j)
        d[K0] = u[j]
print("u[j] 只依赖 K[0] 的字节:", [j for j in range(16) if j not in set(nonfunc)])

# u[j] vs K 字节功能依赖
import collections
for j in range(16):
    for p in range(16):
        d = {}
        bad = False
        for kh, u in us.items():
            Kb = bytes.fromhex(kh)
            key = Kb[p]
            if key in d and d[key] != u[j]:
                bad = True
                break
            d[key] = u[j]
        if not bad:
            print("u[%d] = f(K[%d]) 功能成立 (映射 %d 项)" % (j, p, len(d)))
            break
