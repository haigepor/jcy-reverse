# -*- coding: utf-8 -*-
"""tmp_blkfunc2.py — 测块1函数是否为 core 相同/末轮常量不同等。"""
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
rk = V.expand(K)
T = lambda b: bytes(V.T(list(b)))
X = V.xr

A = bytes([0x11]*16)
Ps = [bytes([0xaa]*16), bytes([0xbb]*16), bytes([0xcc]*16)]
data = []
for P1 in Ps:
    cc = o.enc(A + P1, K, Z)
    data.append((P1, cc[0:16], cc[16:32]))
ct0 = data[0][1]


def core(x):
    """T(core(T(x)^K)) 前的 T(...) 值, 即 E(x) ^ C."""
    s = [a ^ b for a, b in zip(T(list(x)), rk[0])]
    for r in range(1, 10):
        s = V.MC(V.SR(V.SB(s)))
        s = [a ^ b for a, b in zip(s, rk[r])]
    return bytes(T(V.SR(V.SB(s))))


def test(name, fn):
    vals = [X(ct1, fn(P1)) for P1, c0, ct1 in data]
    print('%-32s 恒定=%s  val0=%s' % (name, all(v == vals[0] for v in vals), vals[0].hex()))


# 假设: ct1 = T(core(T(P1^ct0))) ^ const  <=> ct1 ^ core(P1^ct0) 恒定
test('ct1 ^ core(P1^ct0)', lambda P1: core(X(P1, ct0)))
test('ct1 ^ core(P1)', lambda P1: core(P1))
test('ct1 ^ core(P1^T(ct0))', lambda P1: core(X(P1, T(ct0))))
test('ct1 ^ core(P1^ct0^C)', lambda P1: core(X(X(P1, ct0), C)))
test('ct1 ^ core(T(P1)^ct0)', lambda P1: core(X(T(P1), ct0)))
# 假设: ct1 = E(P1) ^ const
test('ct1 ^ E(P1)', lambda P1: V.E(P1, K, C))
test('ct1 ^ E(P1^ct0)', lambda P1: V.E(X(P1, ct0), K, C))
# 假设: ct1 = T(core2(...)) — 试 core 少一轮/多一轮
def core_r(x, nrounds):
    s = [a ^ b for a, b in zip(T(list(x)), rk[0])]
    for r in range(1, nrounds+1):
        s = V.MC(V.SR(V.SB(s)))
        s = [a ^ b for a, b in zip(s, rk[r])]
    return bytes(T(V.SR(V.SB(s))))
for nr in (8, 9, 10):
    test('ct1 ^ core_r%d(P1^ct0)' % nr, lambda P1, nr=nr: core_r(X(P1, ct0), nr))
