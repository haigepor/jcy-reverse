# -*- coding: utf-8 -*-
"""tmp_affine.py - 判定 E_b 是否仿射/可分. 若仿射则 D 可闭式求逆."""
import os
import random
import sys

sys.path.insert(0, 'research/captures/rsa_scan')
from e_oracle import EOracle  # noqa

K = b'X8TEUA3DEXZNW2TN'
IV = b'\x00' * 16


def E(o, x):
    out = o.enc(x, K, IV)
    return bytes(a ^ b for a, b in zip(out[:8], IV[:8]))


o = EOracle()
e0 = E(o, b'\x00' * 8)
print('E(0) =', e0.hex())

random.seed(1)
ok = 0
for t in range(3):
    a = bytes(random.randrange(256) for _ in range(8))
    b = bytes(random.randrange(256) for _ in range(8))
    x = bytes(p ^ q for p, q in zip(a, b))
    lhs = bytes(p ^ q ^ r for p, q, r in zip(E(o, a), E(o, b), E(o, x)))
    hit = (lhs == e0)
    ok += hit
    print('affine test %d: a=%s b=%s -> %s' % (t, a.hex(), b.hex(), 'LINEAR' if hit else 'nonlinear'))

# 单字节变化 -> 输出差分是否只影响固定位置(可分性)
base = b'\x00' * 8
eb = E(o, base)
for i in range(8):
    d = bytearray(8)
    d[i] = 1
    e1 = E(o, bytes(d))
    diff = bytes(p ^ q for p, q in zip(e1, eb))
    nz = [j for j in range(8) if diff[j]]
    print('bit(i=%d) -> 输出差分活跃字节 %s' % (i, nz))
print('affine hits %d/3' % ok)
