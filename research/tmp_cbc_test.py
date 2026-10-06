# -*- coding: utf-8 -*-
"""tmp_cbc_test.py — 验证 2 块 CBC 模型 与 E_inv 正确性。"""
import os, sys, json
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
print('C =', C.hex())

# 1) E_inv 正确性
import os as _os
x = _os.urandom(16)
y = V.E(x, K, C)
print('E_inv(E(x))==x:', V.E_inv(y, K, C) == x)

# 2) 2 块模型
pt = bytes(range(32))
ct = o.enc(pt, K, Z)
ct0_m = V.E(pt[0:16], K, C)
ct1_m = V.E(V.xr(pt[16:32], ct0_m), K, C)
print('block0 match:', ct[0:16] == ct0_m)
print('block1 match:', ct[16:32] == ct1_m)
print(' oracle b1:', ct[16:32].hex())
print(' model  b1:', ct1_m.hex())
# 备选: 链式用 T(ct0)
ct1_alt = V.E(V.xr(pt[16:32], V.T(list(ct[0:16]))), K, C)
print('block1 (chained with T(ct0)):', ct[16:32] == ct1_alt)

# 3) 锚点全量复现
pl = json.load(open(os.path.join(HERE, 'tmp_plains.json')))
pairs = json.load(open(os.path.join(HERE, 'tmp_pairs.json')))
plain = pl[5]['text'].encode('utf-8')
h21 = [bytes.fromhex(e['p1_hex']) for e in pairs if e.get('hit') == 21][0]
# 用 oracle 加密 plain(208B, 已是16倍数) 与 h21 比
enc = o.enc(plain, K, K[::-1])
print('enc(plain,K,revK) len', len(enc), 'vs h21', len(h21))
same = 0
for i in range(0, min(len(enc), len(h21)), 16):
    if enc[i:i+16] == h21[i:i+16]:
        same += 1
    else:
        break
print('相同前缀块数:', same, '/', len(h21)//16)
