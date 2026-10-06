# -*- coding: utf-8 -*-
"""tmp_chain3.py — 暴力搜索块1的链式: 找 f 使 ct1 == E(f)。"""
import os, sys, itertools
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from e_oracle import EOracle  # noqa
sys.path.insert(0, HERE)
import tmp_verify_decrypt as V  # noqa

K = b'X8TEUA3DEXZNW2TN'
Z = bytes(16)
o = EOracle()
C = V.determine_C(o, K)
P = bytes(range(32))
ct = o.enc(P, K, Z)
ct0, ct1 = ct[0:16], ct[16:32]
P0, P1 = P[0:16], P[16:32]
print('ct1 =', ct1.hex())
print('E(P1^ct0) =', V.E(V.xr(P1, ct0), K, C).hex())

T = lambda b: bytes(V.T(list(b)))
def X(a, b):
    return V.xr(a, b)

# 候选链式值 f (进入 E 的输入)
cands = {}
base = {'P1': P1, 'ct0': ct0, 'Tct0': T(ct0), 'C': C, 'TC': T(C), 'P0': P0,
        'iv': Z, 'Tiv': Z, 'ct1': ct1}
# 单元素
for n, v in base.items():
    cands['P1^%s' % n] = X(P1, v)
    cands['T(P1^%s)' % n] = T(X(P1, v))
    cands['%s' % n] = v
# 组合
keys = list(base)
for a, b in itertools.combinations(keys, 2):
    cands['%s^%s' % (a, b)] = X(base[a], base[b])
for a, b, c in itertools.combinations(keys, 3):
    cands['%s^%s^%s' % (a, b, c)] = X(X(base[a], base[b]), base[c])

hits = []
for name, f in cands.items():
    if len(f) != 16:
        continue
    if V.E(f, K, C) == ct1:
        hits.append(name)
print('命中 f:', hits)

# 若 ct1 = E(P1)^g, 找 g
g = X(ct1, V.E(P1, K, C))
print('ct1^E(P1) =', g.hex())
for name, v in cands.items():
    if len(v) == 16 and v == g:
        print('  g 命中:', name)
