# -*- coding: utf-8 -*-
"""tmp_final_search.py — 搜索末轮变换 f: G9 -> ct (深度1..3 算子组合)。"""
import os, json, itertools
HERE = os.path.dirname(os.path.abspath(__file__))
SO = open(os.path.join(HERE, 'artifacts', 'libcore.so'), 'rb').read()
SBOX = SO[0x1dfc00:0x1dfc00 + 256]
ISBOX = bytes(SBOX.index(i) for i in range(256))
K = b'X8TEUA3DEXZNW2TN'


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


def sub(s):
    return [SBOX[x] for x in s]


def isub(s):
    return [ISBOX[x] for x in s]


def SR(s):
    o = [0]*16
    for c in range(4):
        for r in range(4):
            o[4*c+r] = s[4*((c+r) % 4)+r]
    return o


def ISR(s):
    o = [0]*16
    for c in range(4):
        for r in range(4):
            o[4*c+r] = s[4*((c-r) % 4)+r]
    return o


def MC(s):
    o = [0]*16
    for c in range(4):
        a = s[4*c:4*c+4]
        o[4*c+0] = gmul(a[0], 2) ^ gmul(a[1], 3) ^ a[2] ^ a[3]
        o[4*c+1] = a[0] ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ a[3]
        o[4*c+2] = a[0] ^ a[1] ^ gmul(a[2], 2) ^ gmul(a[3], 3)
        o[4*c+3] = gmul(a[0], 3) ^ a[1] ^ a[2] ^ gmul(a[3], 2)
    return o


def IMC(s):
    o = [0]*16
    for c in range(4):
        a = s[4*c:4*c+4]
        o[4*c+0] = gmul(a[0], 14) ^ gmul(a[1], 11) ^ gmul(a[2], 13) ^ gmul(a[3], 9)
        o[4*c+1] = gmul(a[0], 9) ^ gmul(a[1], 14) ^ gmul(a[2], 11) ^ gmul(a[3], 13)
        o[4*c+2] = gmul(a[0], 13) ^ gmul(a[1], 9) ^ gmul(a[2], 14) ^ gmul(a[3], 11)
        o[4*c+3] = gmul(a[0], 11) ^ gmul(a[1], 13) ^ gmul(a[2], 9) ^ gmul(a[3], 14)
    return o


def T(s):
    o = [0]*16
    for r in range(4):
        for c in range(4):
            o[4*r+c] = s[4*c+r]
    return o


def REV(s):
    return list(s)[::-1]


OPS = {'SB': sub, 'ISB': isub, 'SR': SR, 'ISR': ISR, 'MC': MC, 'IMC': IMC,
       'T': T, 'REV': REV, 'I': lambda s: list(s)}
rk = expand(K)
recs = json.load(open(os.path.join(HERE, 'tmp_full_caps.json')))


def g9_of(rec):
    idx = rec['idx']
    return bytes(idx[40+9*16:40+10*16])


def A0_of(pt):
    return [a ^ b for a, b in zip(T(list(pt)), rk[0])]


def state9(A0):
    s = list(A0)
    for r in range(1, 10):
        s = MC(SR(sub(s)))
        s = [x ^ y for x, y in zip(s, rk[r])]
    return bytes(s)


data = [(state9(A0_of(bytes.fromhex(r['pt']))), bytes.fromhex(r['ct'])) for r in recs]
print('n samples', len(data))
# 确认 g9 一致
for rec, (s9, ct) in zip(recs, data):
    if g9_of(rec) != s9:
        print('WARN g9 mismatch', rec['pt'])

names = list(OPS)
hits = []
for depth in (1, 2, 3):
    for combo in itertools.product(names, repeat=depth):
        if combo[-1] == 'I':
            pass
        def F(s, combo=combo):
            for nm in combo:
                s = OPS[nm](s)
            return s
        Ds = [bytes(x ^ y for x, y in zip(ct, F(list(s9)))) for s9, ct in data]
        if all(d == Ds[0] for d in Ds):
            hits.append((combo, Ds[0]))
            print('HIT depth%d %s const=%s' % (depth, '->'.join(combo), Ds[0].hex()))
print('total hits', len(hits))
