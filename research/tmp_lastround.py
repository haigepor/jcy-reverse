# -*- coding: utf-8 -*-
"""tmp_lastround.py — 确定末轮变换: 对 block0/block1 分别求 rk10, 取一致的候选。"""
import os
HERE = os.path.dirname(os.path.abspath(__file__))
SO = open(os.path.join(HERE, 'artifacts', 'libcore.so'), 'rb').read()
SBOX = SO[0x1dfc00:0x1dfc00 + 256]


def xt(a):
    a <<= 1
    return (a ^ 0x1b) & 0xff if a & 0x100 else a


def gmul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        a = xt(a)
        b >>= 1
    return r


def sub(s):
    return [SBOX[x] for x in s]


def shift(s):
    o = [0]*16
    for c in range(4):
        for r in range(4):
            o[4*c+r] = s[4*((c+r) % 4)+r]
    return o


def mix(s):
    o = [0]*16
    for c in range(4):
        a = s[4*c:4*c+4]
        o[4*c+0] = gmul(a[0], 2) ^ gmul(a[1], 3) ^ a[2] ^ a[3]
        o[4*c+1] = a[0] ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ a[3]
        o[4*c+2] = a[0] ^ a[1] ^ gmul(a[2], 2) ^ gmul(a[3], 3)
        o[4*c+3] = gmul(a[0], 3) ^ a[1] ^ a[2] ^ gmul(a[3], 2)
    return o


def expand(key):
    w = [list(key[i*4:i*4+4]) for i in range(4)]
    rc = 1
    for i in range(4, 44):
        t = list(w[i-1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[x] for x in t]
            t[0] ^= rc
            rc = xt(rc)
        w.append([w[i-4][j] ^ t[j] for j in range(4)])
    return [bytes(sum(w[4*r:4*r+4], [])) for r in range(11)]


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


grp09 = bytes.fromhex('043b03b522c082c4990ae3312635757 1'.replace(' ', ''))
grp19 = bytes.fromhex('0a4147eb351b1eae4cbdf9c03820b17c')
ct0 = bytes.fromhex('60beb57743b3efefa1ada0e71ccc1d57')
ct1 = bytes.fromhex('baff63e71c19fe053763b8e831ae7b48')
K = b'X8TEUA3DEXZNW2TN'
rk = expand(K)
print('rk10(标准) =', rk[10].hex())

cands = {
    'SR(SB(x))': lambda s: shift(sub(s)),
    'MC(SR(SB(x)))': lambda s: mix(shift(sub(s))),
    'SB(x)': lambda s: sub(s),
    'x(恒等)': lambda s: list(s),
    'MC(SB(x))': lambda s: mix(sub(s)),
    'SR(x)': lambda s: shift(list(s)),
}
for name, L in cands.items():
    r0 = xor(bytes(L(list(grp09))), ct0)
    r1 = xor(bytes(L(list(grp19))), ct1)
    ok = r0 == r1
    print('%-16s blk0_rk=%s blk1_rk=%s 一致=%s ==rk10标准?%s' %
          (name, r0.hex(), r1.hex(), ok, r0 == rk[10]))
