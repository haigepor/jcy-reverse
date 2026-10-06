# -*- coding: utf-8 -*-
"""tmp_feistel.py — 黑盒结构探测: 检验 16B 分组密码是否为 Feistel。

Feistel 性质: 固定右半 R0, 左半 L0 -> L1 满足 L1 ^ L0 = F(R0) = 常数。
"""
import sys
sys.path.insert(0, 'research/captures/rsa_scan')
from e_oracle import EOracle  # noqa

K = b'X8TEUA3DEXZNW2TN'
Z = b'\x00' * 16
o = EOracle()


def E(pt16):
    return o.enc(pt16, K, Z)[:16]


print('--- 固定 R0=0, 变 L0 ---')
res = []
for L0 in (0, 1, 2, 0x0102030405060708, 0xFFFFFFFFFFFFFFFF):
    pt = L0.to_bytes(8, 'big') + b'\x00' * 8
    out = E(pt)
    l1 = int.from_bytes(out[:8], 'big')
    r1 = int.from_bytes(out[8:], 'big')
    res.append((L0, l1 ^ L0, l1, r1))
    print('L0=%016x  L1=%016x  L1^L0=%016x  R1=%016x' % (L0, l1, l1 ^ L0, r1))
print('L1^L0 常数?', len(set(r[1] for r in res)) == 1)

print('--- 固定 L0=0, 变 R0 ---')
for R0 in (0, 1, 0x0102030405060708):
    pt = b'\x00' * 8 + R0.to_bytes(8, 'big')
    out = E(pt)
    print('R0=%016x  out=%s' % (R0, out.hex()))
