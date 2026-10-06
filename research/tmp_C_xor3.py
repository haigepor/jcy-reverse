# -*- coding: utf-8 -*-
"""tmp_C_xor3.py — C 的 1..3 元素 XOR 组合搜索 (K1 命中, K2 复核)。"""
import os, itertools
HERE = os.path.dirname(os.path.abspath(__file__))
SO = open(os.path.join(HERE, 'artifacts', 'libcore.so'), 'rb').read()
SBOX = SO[0x1dfc00:0x1dfc00 + 256]
ISBOX = bytes(SBOX.index(i) for i in range(256))


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


def sub(s, box=SBOX):
    return bytes(box[x] for x in s)


def SR(s):
    o = [0]*16
    for c in range(4):
        for r in range(4):
            o[4*c+r] = s[4*((c+r) % 4)+r]
    return bytes(o)


def ISR(s):
    o = [0]*16
    for c in range(4):
        for r in range(4):
            o[4*c+r] = s[4*((c-r) % 4)+r]
    return bytes(o)


def MC(s):
    o = [0]*16
    for c in range(4):
        a = s[4*c:4*c+4]
        o[4*c+0] = gmul(a[0], 2) ^ gmul(a[1], 3) ^ a[2] ^ a[3]
        o[4*c+1] = a[0] ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ a[3]
        o[4*c+2] = a[0] ^ a[1] ^ gmul(a[2], 2) ^ gmul(a[3], 3)
        o[4*c+3] = gmul(a[0], 3) ^ a[1] ^ a[2] ^ gmul(a[3], 2)
    return bytes(o)


def T(s):
    o = [0]*16
    for r in range(4):
        for c in range(4):
            o[4*r+c] = s[4*c+r]
    return bytes(o)


def xr(*vs):
    r = vs[0]
    for v in vs[1:]:
        r = bytes(a ^ b for a, b in zip(r, v))
    return r


K1 = b'X8TEUA3DEXZNW2TN'
K2 = b'ABCDEFGHIJKLMNOP'
C1 = bytes.fromhex('922d5b80f9d4790db030dbf4bf190190')
C2 = bytes.fromhex('ddb620bf286bdeb737406233b533ad92')


def build(K):
    S = {'K': K, 'TK': T(K), 'RK': bytes(K[::-1]), 'SK': SR(K),
         'IK': ISR(K), 'MK': MC(K)}
    for i in range(15):
        r = expand(K)[i]
        S['r%d' % i] = r
        S['T%d' % i] = T(r)
        S['S%d' % i] = SR(r)
        S['I%d' % i] = ISR(r)
        S['M%d' % i] = MC(r)
        S['B%d' % i] = sub(r)
    return S


S1 = build(K1)
S2 = build(K2)
names = list(S1)
print('|S| =', len(names))

hits = []
for depth in (1, 2, 3):
    for combo in itertools.combinations_with_replacement(names, depth):
        v = xr(*[S1[c] for c in combo])
        if v == C1:
            hits.append(combo)
    if hits:
        print('depth%d hits: %d' % (depth, len(hits)))
        for c in hits[:20]:
            v2 = xr(*[S2[x] for x in c])
            print('   ', c, ' K2复核:', v2 == C2)
        break
if not hits:
    print('无命中 (1..3 元素)')
