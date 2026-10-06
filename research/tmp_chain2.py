# -*- coding: utf-8 -*-
"""tmp_chain2.py — 判定预言机是否标准 CBC: 比较 ct1 与 enc(P1^ct0)。"""
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
ct0, ct1 = ct[0:16], ct[16:32]
print('ct len', len(ct))
print('ct0', ct0.hex())
print('ct1', ct1.hex())
e = o.enc(V.xr(P[16:32], ct0), K, Z)
print('enc(P1^ct0)[0:16]', e[0:16].hex(), ' == ct1?', e[0:16] == ct1)
# 也试 enc(P1) 前16
e2 = o.enc(P[16:32], K, Z)
print('enc(P1)[0:16]   ', e2[0:16].hex(), ' == ct1?', e2[0:16] == ct1)
print('enc(P1)[0:16] ^ ct0 == ct1?', V.xr(e2[0:16], ct0) == ct1)
# 单块对照: enc(P0)[0:16] == ct0?
e0 = o.enc(P[0:16], K, Z)
print('enc(P0)[0:16] == ct0?', e0[0:16] == ct0)
# 试 X1 与 ct0 的各种关系
X1 = V.E_inv(ct1, K, C)
print('X1', X1.hex())
print('X1 ^ ct0  ', V.xr(X1, ct0).hex())
print('X1 ^ T(ct0)', V.xr(X1, bytes(V.T(list(ct0)))).hex())
print('P1        ', P[16:32].hex())
print('X1^P1     ', V.xr(X1, P[16:32]).hex())
