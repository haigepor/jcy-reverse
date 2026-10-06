# -*- coding: utf-8 -*-
"""tmp_multiblk.py — 判定预言机多块行为: 依赖性与确定性。"""
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

A = bytes([0x11]*16)
B = bytes([0x22]*16)
P1 = bytes([0xaa]*16)
P1b = bytes([0xbb]*16)

c1 = o.enc(A + P1, K, Z)
c2 = o.enc(A + P1, K, Z)          # 确定性
c3 = o.enc(B + P1, K, Z)          # 依赖 P0
c4 = o.enc(A + P1b, K, Z)         # 依赖 P1
print('c1', c1.hex())
print('确定性 (c1==c2):', c1 == c2)
print('依赖P0 (ct1 变):', c1[16:32] != c3[16:32], ' ct0 变:', c1[0:16] != c3[0:16])
print('依赖P1 (ct1 变):', c1[16:32] != c4[16:32])
# 单块对照
s = o.enc(A, K, Z)
print('enc(A)[0:16] == c1[0:16]:', s[0:16] == c1[0:16])
# g = E_inv(ct1) ^ P1
for nm, cc in (('c1', c1), ('c3', c3)):
    g = V.xr(V.E_inv(cc[16:32], K, C), P1)
    print('%s: ct0=%s  g=E_inv(ct1)^P1=%s  g^ct0=%s' % (
        nm, cc[0:16].hex(), g.hex(), V.xr(g, cc[0:16]).hex()))
