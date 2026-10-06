# -*- coding: utf-8 -*-
"""tmp_g1_step5x.py — 模加模型: u=K[0]+C? rk_r=(M·K)⊞C?"""
import os
import json
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
from decrypt_e import xr  # noqa: E402

MJ = json.load(open(os.path.join(HERE, "reports", "gen_M.json")))
emapM = {int(k): int(v, 16) for k, v in MJ["emap"].items()}


def Mmap(v_int, emap):
    out, vv, j = 0, v_int, 0
    while vv:
        if vv & 1:
            out ^= emap.get(j, 0)
        vv >>= 1
        j += 1
    return out


def Mi(vb, emap=emapM):
    return Mmap(int.from_bytes(vb, "big"), emap).to_bytes(16, "big")


data = json.load(open(os.path.join(HERE, "reports", "gen_rks3.json")))

# --- 1) u(K) = K[0] + C_u (byte-wise mod 256)? ---
us = {}
for kh, rec in data.items():
    K = bytes.fromhex(kh)
    u = xr(bytes.fromhex(rec["preSB0"]), Mi(K[::-1]))
    us[kh] = u
Cs = {}
ok = True
for kh, u in us.items():
    K0 = int(kh[0:2], 16)
    for j in range(16):
        c = (u[j] - K0) & 0xFF
        if j in Cs and Cs[j] != c:
            ok = False
            print("u[%d] 常数不符 K=%s: %02x vs %02x" % (j, kh[:8], c, Cs[j]))
            break
        Cs[j] = c
    if not ok:
        break
print("u(K) = K[0]+C_u 模型:", "成立" if ok else "失败")
if ok:
    Cu = bytes(Cs[j] for j in range(16))
    print("C_u =", Cu.hex())
    bad = sum(1 for kh, u in us.items()
              if bytes((int(kh[0:2], 16) + Cu[j]) & 0xFF for j in range(16)) != u)
    print("u 全量验证失败:", bad, "/", len(us))

# --- 2) rk_r = (M_A·K) ⊞ C_r (byte mod-256)? ---
br = json.load(open(os.path.join(HERE, "reports", "gen_branches.json")))


def mk_M(rec):
    e = {int(k): int(v, 16) for k, v in rec["emap"].items()}

    def Mf(v_int):
        out, vv, j = 0, v_int, 0
        while vv:
            if vv & 1:
                out ^= e.get(j, 0)
            vv >>= 1
            j += 1
        return out
    return Mf


for r in ("1", "2", "8"):
    MA = mk_M(br["A"][r])
    cA = int(br["A"][r]["c"], 16)
    cols = [dict() for _ in range(16)]
    consistent = True
    for kh, drec in data.items():
        K = bytes.fromhex(kh)
        rk = bytes.fromhex(drec["rks"][r])
        lin = (MA(int.from_bytes(K, "big")) ^ cA).to_bytes(16, "big")
        for j in range(16):
            c = (rk[j] - lin[j]) & 0xFF
            if j in cols[j] and cols[j][j] if False else False:
                pass
            if j in cols[j]:
                if cols[j][j] != c:
                    consistent = False
            cols[j][j] = c
    # 上面的 dict 用法错了, 重来
    colvals = [set() for _ in range(16)]
    for kh, drec in data.items():
        K = bytes.fromhex(kh)
        rk = bytes.fromhex(drec["rks"][r])
        lin = (MA(int.from_bytes(K, "big")) ^ cA).to_bytes(16, "big")
        for j in range(16):
            colvals[j].add((rk[j] - lin[j]) & 0xFF)
    sizes = [len(s) for s in colvals]
    print("rk%s: 每字节 (rk-lin) mod256 取值数 %s %s"
          % (r, sizes, "←全1即模加常数成立" if all(s == 1 for s in sizes) else ""))
