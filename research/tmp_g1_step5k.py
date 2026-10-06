# -*- coding: utf-8 -*-
"""tmp_g1_step5k.py — A/B 矩阵对比 + 单字节非线性谓词扫描."""
import os
import json
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
from decrypt_e import SBOX, ISBOX  # noqa: E402

br = json.load(open(os.path.join(HERE, "reports", "gen_branches.json")))
data = json.load(open(os.path.join(HERE, "reports", "gen_rks3.json")))


def get_emap(rec):
    return {int(k): int(v, 16) for k, v in rec["emap"].items()}


print("=== A vs B emap 对比 ===")
for key in ("preSB0", "1", "8", "W"):
    ra = br["A"].get(key)
    rb = br["B"].get(key)
    if not ra or not rb or "emap" not in ra or "emap" not in rb:
        print(key, "缺")
        continue
    ea, eb = get_emap(ra), get_emap(rb)
    same = all(ea.get(j, 0) == eb.get(j, 0) for j in range(128))
    print(key, "矩阵相同?", same)
    if not same:
        diff = [j for j in range(128) if ea.get(j, 0) != eb.get(j, 0)]
        print("  不同的列:", len(diff), diff[:10])
    ca = int(ra["c"], 16)
    cb = int(rb["c"], 16)
    print("  常数异或:", format(ca ^ cb, "x"))

# ---- 单字节非线性谓词扫描 ----
grpA = br["grpA"]
grpB = [k for k in br["grpB"] if not any(k.startswith(o) for o in ("72aff4a0", "aff25760"))]
print("\n=== 谓词扫描 (需 A/B 组完全分离) ===")


def test_pred(fn, name):
    va = {fn(bytes.fromhex(k)) for k in grpA}
    vb = {fn(bytes.fromhex(k)) for k in grpB}
    if not (va & vb):
        print("命中:", name, "A→", va, "B→", vb)
        return True
    return False


hits = 0
for p in range(16):
    for i in range(8):
        if test_pred(lambda K, p=p, i=i: (SBOX[K[p]] >> i) & 1,
                     "bit%d(SBOX(K[%d]))" % (i, p)):
            hits += 1
        if test_pred(lambda K, p=p, i=i: (ISBOX[K[p]] >> i) & 1,
                     "bit%d(ISBOX(K[%d]))" % (i, p)):
            hits += 1
    if test_pred(lambda K, p=p: K[p] == 0, "K[%d]==0" % p):
        hits += 1
    if test_pred(lambda K, p=p: bin(K[p]).count("1") > 4,
                 "pop(K[%d])>4" % p):
        hits += 1
# 双字节 XOR 高位
for p in range(16):
    for q in range(p + 1, 16):
        if test_pred(lambda K, p=p, q=q: ((K[p] ^ K[q]) >> 7) & 1,
                     "hi(K[%d]^K[%d])" % (p, q)):
            hits += 1
print("命中数:", hits)
