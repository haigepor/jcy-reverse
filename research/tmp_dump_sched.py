# -*- coding: utf-8 -*-
"""tmp_dump_sched.py — dump 密钥调度内存区域, 看每轮密钥的两份副本布局。"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from e_oracle import EOracle  # noqa

K = b'X8TEUA3DEXZNW2TN'
Z = bytes(16)
SO = open(os.path.join(HERE, 'artifacts', 'libcore.so'), 'rb').read()
SBOX = SO[0x1dfc00:0x1dfc00 + 256]


def xt(a):
    a <<= 1
    return (a ^ 0x1b) & 0xff if a & 0x100 else a


def expand(key, nr=14):
    w = [list(key[i*4:i*4+4]) for i in range(4)]
    rc = 1
    for i in range(4, 4*(nr+1)):
        t = list(w[i-1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[x] for x in t]
            t[0] ^= rc
            rc = xt(rc)
        w.append([w[i-4][j] ^ t[j] for j in range(4)])
    return [bytes(sum(w[4*r:4*r+4], [])) for r in range(nr+1)]


def T(s):
    o = [0]*16
    for r in range(4):
        for c in range(4):
            o[4*r+c] = s[4*c+r]
    return bytes(o)


o = EOracle()
uc = o.s.e.uc
o.enc(bytes(16), K, Z)
rk = expand(K)
C1 = bytes.fromhex('922d5b80f9d4790db030dbf4bf190190')

for i in range(11):
    print('rk%-2d=%s  T=%s' % (i, rk[i].hex(), T(rk[i]).hex()))
print('C1 =', C1.hex())
print('T(C1)=', T(C1).hex())
print()

# dump 0x50001700..0x50002f00
base = 0x50001700
data = bytes(uc.mem_read(base, 0x1800))
for off in range(0, len(data), 16):
    chunk = data[off:off+16]
    if chunk == bytes(16):
        continue
    tag = ''
    for i in range(11):
        if chunk == rk[i]:
            tag = 'rk%d' % i
        elif chunk == T(rk[i]):
            tag = 'T(rk%d)' % i
        elif chunk == bytes(rk[i][::-1]):
            tag = 'rev(rk%d)' % i
    if chunk == C1:
        tag = 'C1'
    if chunk == T(C1):
        tag = 'T(C1)'
    print('%#x  %s  %s' % (base + off, chunk.hex(), tag))
