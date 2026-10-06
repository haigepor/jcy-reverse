# -*- coding: utf-8 -*-
"""tmp_blkfunc.py — 判定块1函数是否为 E(shifted input): 固定ct0, 变P1。"""
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
Ps = [bytes([0xaa]*16), bytes([0xbb]*16), bytes([0xcc]*16)]
res = []
for P1 in Ps:
    cc = o.enc(A + P1, K, Z)
    res.append((P1, cc[0:16], cc[16:32]))
for P1, ct0, ct1 in res:
    print('P1=%s ct0=%s ct1=%s' % (P1.hex()[:8], ct0.hex(), ct1.hex()))
print()
print('ct0 恒定:', all(r[1] == res[0][1] for r in res))
# g = E_inv(ct1) ^ P1 应恒定, 若块函数为 E(P1^g)
gs = [V.xr(V.E_inv(ct1, K, C), P1) for P1, ct0, ct1 in res]
for g in gs:
    print('g =', g.hex())
print('g 恒定:', all(g == gs[0] for g in gs))
# 交叉: E_inv(ct1_i) ^ E_inv(ct1_j) == P1_i ^ P1_j ?
for i in range(len(res)):
    for j in range(i+1, len(res)):
        lhs = V.xr(V.E_inv(res[i][2], K, C), V.E_inv(res[j][2], K, C))
        rhs = V.xr(res[i][0], res[j][0])
        print('i%d j%d  E_inv差==P1差: %s' % (i, j, lhs == rhs))
