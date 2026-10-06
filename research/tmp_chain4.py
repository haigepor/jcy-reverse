# -*- coding: utf-8 -*-
"""tmp_chain4.py — 扩大链式候选搜索 (含转置组合、S盒、E派生)。"""
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
T = lambda b: bytes(V.T(list(b)))
SB = lambda b: bytes(V.SB(list(b)))
ISB = lambda b: bytes(V.ISB(list(b)))
X = V.xr

print('ct0', ct0.hex())
print('ct1', ct1.hex())
print('f=E_inv(ct1)', V.E_inv(ct1, K, C).hex())

# 目标: ct1 == E(f) 中的 f
f_t = V.E_inv(ct1, K, C)
# 候选 base
base = {
    'P0': P0, 'P1': P1, 'ct0': ct0, 'C': C, 'iv': Z,
    'T(P0)': T(P0), 'T(P1)': T(P1), 'T(ct0)': T(ct0), 'T(C)': T(C),
    'ct0^C': X(ct0, C), 'T(ct0^C)': T(X(ct0, C)),
    'E(P0)': V.E(P0, K, C), 'E(ct0)': V.E(ct0, K, C),
    'SB(ct0)': SB(ct0), 'ISB(ct0)': ISB(ct0),
    'T(SB(ct0))': T(SB(ct0)), 'SB(T(ct0))': SB(T(ct0)),
}
# 检查 f_t 是否等于某候选
for n, v in base.items():
    if v == f_t:
        print('f_t ==', n)
# 组合 (f_t ^ P1 或 f_t ^ T(P1) 与候选比较)
gt = X(f_t, P1)
gtT = X(f_t, T(P1))
print('f_t^P1 =', gt.hex())
print('f_t^T(P1) =', gtT.hex())
for n, v in base.items():
    if v == gt:
        print('f_t^P1 ==', n)
    if v == gtT:
        print('f_t^T(P1) ==', n)

# 直接测 ct1 == E(P1 ^ c)  c 为 base 元素及两两
hits = []
for n, v in base.items():
    if len(v) == 16 and V.E(X(P1, v), K, C) == ct1:
        hits.append('P1^%s' % n)
    if len(v) == 16 and V.E(v, K, C) == ct1:
        hits.append(n)
ks = list(base)
for a, b in itertools.combinations(ks, 2):
    c = X(base[a], base[b])
    if V.E(X(P1, c), K, C) == ct1:
        hits.append('P1^(%s^%s)' % (a, b))
print('ct1==E(P1^c) 命中:', hits)
