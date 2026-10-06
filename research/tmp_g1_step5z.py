# -*- coding: utf-8 -*-
"""tmp_g1_step5z.py — u = P5(K) 全量验证 + u 空间调度重测."""
import os
import json
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
from decrypt_e import xr, expand, SBOX, ISBOX, T  # noqa: E402

MJ = json.load(open(os.path.join(HERE, "reports", "gen_M.json")))
emapM = {int(k): int(v, 16) for k, v in MJ["emap"].items()}


def Mmap(v_int):
    out, vv, j = 0, v_int, 0
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

# P5 验证
bad = 0
for kh, u in us.items():
    K = bytes.fromhex(kh)
    p5 = bytes(K[(5 * j) % 16] for j in range(16))
    if p5 != u:
        bad += 1
        if bad <= 3:
            print("不符 K=%s u=%s p5=%s" % (kh[:8], u.hex(), p5.hex()))
print("u = P5(K) 验证失败:", bad, "/", len(us))

# u 空间: rk1 仿射? (差分一致性)
pairs = [(int.from_bytes(u, "big"),
          int.from_bytes(bytes.fromhex(data[kh]["rks"]["1"]), "big"))
         for kh, u in us.items()]
chk = {}
lin = True
for i in range(len(pairs)):
    for j in range(i + 1, len(pairs)):
        v = pairs[i][0] ^ pairs[j][0]
        if v == 0:
            continue
        o = pairs[i][1] ^ pairs[j][1]
        if v in chk and chk[v] != o:
            lin = False
            break
        chk[v] = o
    if not lin:
        break
print("rk1 = affine(u)? 差分一致:", lin, "唯一差分:", len(chk))

# expand 变体 (对 u)
def variants(u):
    yield "u", u
    yield "T(u)", bytes(T(list(u)))
    yield "SB(u)", bytes(SBOX[x] for x in u)
    yield "iSB(u)", bytes(ISBOX[x] for x in u)
    yield "rev(u)", u[::-1]


for kh in list(us)[:2]:
    u = us[kh]
    rks = {int(r): bytes.fromhex(v) for r, v in data[kh]["rks"].items()}
    for name, seed in variants(u):
        sch = expand(seed)
        n_ok = sum(1 for r in range(1, 9) if r < len(sch) and sch[r] == rks[r])
        print("K=%s seed=%s: expand 匹配 %d/8" % (kh[:8], name, n_ok))
