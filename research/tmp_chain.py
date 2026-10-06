# -*- coding: utf-8 -*-
"""tmp_chain.py — 反解 CBC 链式: X1 = E_inv(ct1) 应等于 pt1 ^ f(ct0)。求 f。"""
import os, sys
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
print('ct len', len(ct))
ct0, ct1 = ct[0:16], ct[16:32]
X0 = V.E_inv(ct0, K, C)
X1 = V.E_inv(ct1, K, C)
print('X0 == P0:', X0 == P[0:16])
print('X0^P0 =', V.xr(X0, P[0:16]).hex(), '(iv=0 -> 应为0)')
print('X1 =', X1.hex())
print('P1 =', P[16:32].hex())
d = V.xr(X1, P[16:32])
print('X1^P1 =', d.hex())
print('ct0    =', ct0.hex(), ' 相等?', d == ct0)
print('T(ct0) =', V.T(list(ct0)).hex(), ' 相等?', d == V.T(list(ct0)))
print('iv     =', Z.hex())
# 备选: ct1 = E(pt1) ^ ct0 ?
alt = V.xr(V.E(P[16:32], K, C), ct0)
print('E(pt1)^ct0 == ct1:', alt == ct1)
alt2 = V.xr(V.E(P[16:32], K, C), V.T(list(ct0)))
print('E(pt1)^T(ct0) == ct1:', alt2 == ct1)
# 备选: ct1 = T(E_inv_alt) ... 试 ct1 = E(pt1 ^ T(ct0))
print('E(pt1^T(ct0)) == ct1:', V.E(V.xr(P[16:32], V.T(list(ct0))), K, C) == ct1)
