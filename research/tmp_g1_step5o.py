# -*- coding: utf-8 -*-
"""tmp_g1_step5o.py — 选择子 s(K) 函数依赖搜索."""
import os
import json
import sys
from itertools import combinations

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
from decrypt_e import SBOX, ISBOX, _gmul  # noqa: E402

br = json.load(open(os.path.join(HERE, "reports", "gen_branches.json")))
Aset = set(br["grpA"])
data = json.load(open(os.path.join(HERE, "reports", "gen_rks3.json")))

labels = {}
for kh in data:
    labels[kh] = 0 if kh in Aset else 1
# C 组两键按 1 处理 (属 B 侧残差) — 先排除
Cc = [k for k in br["grpB"] if any(k.startswith(o) for o in ("72aff4a0", "aff25760"))]
items = [(bytes.fromhex(kh), labels[kh]) for kh in data
         if not any(kh.startswith(o) for o in ("72aff4a0", "aff25760"))]
print("样本: %d (0:%d, 1:%d)" % (len(items),
      sum(1 for _, y in items if y == 0), sum(1 for _, y in items if y == 1)))

X = [K for K, _ in items]
Y = [y for _, y in items]


def functional(feats, name):
    m = {}
    for K, y in zip(X, Y):
        key = feats(K)
        if key in m and m[key] != y:
            return False
        m[key] = y
    return len(m) > 1


hits = []
for p in range(16):
    if functional(lambda K, p=p: K[p], "K[%d]" % p):
        hits.append(("byte", (p,)))
for p, q in combinations(range(16), 2):
    if functional(lambda K, p=p, q=q: (K[p], K[q]), "K[%d],K[%d]" % (p, q)):
        hits.append(("pair", (p, q)))
print("字节依赖命中:", hits)

# 派生单字节特征
feats1 = []
for p in range(16):
    feats1.append(("SBOX(K[%d])" % p, lambda K, p=p: SBOX[K[p]]))
    feats1.append(("ISBOX(K[%d])" % p, lambda K, p=p: ISBOX[K[p]]))
    feats1.append(("xtime(K[%d])" % p, lambda K, p=p: _gmul(K[p], 2)))
    feats1.append(("3*K[%d]" % p, lambda K, p=p: _gmul(K[p], 3)))
    feats1.append(("pop(K[%d])" % p, lambda K, p=p: bin(K[p]).count("1")))
    feats1.append(("K[%d]<0x80" % p, lambda K, p=p: K[p] < 0x80))
print("单字节派生特征:")
for name, f in feats1:
    if functional(f, name):
        print("  命中:", name)

# 双字节 XOR/GF 乘特征
print("双字节特征:")
found = False
for p, q in combinations(range(16), 2):
    for nm, f in (("xor", lambda K, p=p, q=q: K[p] ^ K[q]),
                  ("gf", lambda K, p=p, q=q: _gmul(K[p], K[q])),
                  ("add", lambda K, p=p, q=q: (K[p] + K[q]) & 0xFF)):
        if functional(f, "%s(%d,%d)" % (nm, p, q)):
            print("  命中: %s(K[%d],K[%d])" % (nm, p, q))
            found = True
if not found:
    print("  无")
