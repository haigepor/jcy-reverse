# -*- coding: utf-8 -*-
"""tmp_g1_step5q.py — 失败键残差形态: XOR 差 vs 模加差."""
import os
import json
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

br = json.load(open(os.path.join(HERE, "reports", "gen_branches.json")))
data = json.load(open(os.path.join(HERE, "reports", "gen_rks3.json")))
Aset = set(br["grpA"])


def mk_M(rec):
    emap = {int(k): int(v, 16) for k, v in rec["emap"].items()}

    def M(v_int):
        out, vv, j = 0, v_int, 0
        while vv:
            if vv & 1:
                out ^= emap.get(j, 0)
            vv >>= 1
            j += 1
        return out
    return M


M1 = mk_M(br["A"]["1"])
c1 = int(br["A"]["1"]["c"], 16)

print("=== B 组键: predA ^ actual (rk1) ===")
for kh in br["grpB"][:10]:
    K = int.from_bytes(bytes.fromhex(kh), "big")
    actual = int.from_bytes(bytes.fromhex(data[kh]["rks"]["1"]), "big")
    pred = M1(K) ^ c1
    x = pred ^ actual
    s = (actual - pred) % (1 << 128)
    print("K=%s xor=%s add=%s" % (kh[:8], format(x, "x")[:34], format(s, "x")[:34]))

print("\n=== A 组键残差 (应全 0) ===")
n = 0
for kh in list(Aset)[:10]:
    K = int.from_bytes(bytes.fromhex(kh), "big")
    actual = int.from_bytes(bytes.fromhex(data[kh]["rks"]["1"]), "big")
    pred = M1(K) ^ c1
    if pred != actual:
        n += 1
        print("K=%s xor=%s" % (kh[:8], format(pred ^ actual, "x")))
print("A 组失败:", n)

# 检验: B 组 actual 是否 = (predA + Δ) mod 2^128 常数 Δ?
deltas = set()
for kh in br["grpB"]:
    K = int.from_bytes(bytes.fromhex(kh), "big")
    actual = int.from_bytes(bytes.fromhex(data[kh]["rks"]["1"]), "big")
    deltas.add((actual - (M1(K) ^ c1)) % (1 << 128))
print("B 组 mod-add 常数差个数:", len(deltas))
xors = set()
for kh in br["grpB"]:
    K = int.from_bytes(bytes.fromhex(kh), "big")
    actual = int.from_bytes(bytes.fromhex(data[kh]["rks"]["1"]), "big")
    xors.add(actual ^ (M1(K) ^ c1))
print("B 组 xor 常数差个数:", len(xors))
