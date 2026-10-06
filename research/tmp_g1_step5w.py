# -*- coding: utf-8 -*-
"""tmp_g1_step5w.py — u=rk0? + 调度跨块稳定性检验."""
import os
import sys
import json

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
from decrypt_e import xr, SBOX, ISBOX, _gmul, T  # noqa: E402

MJ = json.load(open(os.path.join(HERE, "reports", "gen_M.json")))
emap = {int(k): int(v, 16) for k, v in MJ["emap"].items()}


def M(v_int):
    out, vv, j = 0, v_int, 0
    while vv:
        if vv & 1:
            out ^= emap.get(j, 0)
        vv >>= 1
        j += 1
    return out


def Mi(vb):
    return M(int.from_bytes(vb, "big")).to_bytes(16, "big")


br = json.load(open(os.path.join(HERE, "reports", "gen_branches.json")))
data = json.load(open(os.path.join(HERE, "reports", "gen_rks3.json")))
Aset = set(br["grpA"])


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


def apply(rec, Kint):
    return mk_M(rec)(Kint) ^ int(rec["c"], 16)


print("=== u vs rk0: A(u)^c == rk1 ? ===")
nA = nB = okA = okB = 0
for kh, rec in data.items():
    K = bytes.fromhex(kh)
    u = int.from_bytes(xr(bytes.fromhex(rec["preSB0"]), Mi(K[::-1])), "big")
    rk1 = int.from_bytes(bytes.fromhex(rec["rks"]["1"]), "big")
    grp = br["A"] if kh in Aset else br["B"]
    pred = apply(br["A" if kh in Aset else "B"]["1"], u)
    if kh in Aset:
        nA += 1
        okA += (pred == rk1)
    else:
        nB += 1
        okB += (pred == rk1)
print("A 组: %d/%d   B 组: %d/%d" % (okA, nA, okB, nB))

# u == 某个已知量的检验: u vs preSB0^M(iv) 已经是定义; 看 u 与 expand(K) 词头
print("\n=== u 形态 (前 4 键) ===")
for kh in list(data)[:4]:
    K = bytes.fromhex(kh)
    u = xr(bytes.fromhex(data[kh]["preSB0"]), Mi(K[::-1]))
    print("K=%s u=%s" % (kh[:8], u.hex()))
