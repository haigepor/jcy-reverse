# -*- coding: utf-8 -*-
"""tmp_find_C.py — 反推末轮常量 C 的密钥公式 (K1/K2 双约束)。"""
import os, sys
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


def xr(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


K1 = b'X8TEUA3DEXZNW2TN'
K2 = b'ABCDEFGHIJKLMNOP'
C1 = bytes.fromhex('922d5b80f9d4790db030dbf4bf190190')
C2 = bytes.fromhex('ddb620bf286bdeb737406233b533ad92')

for name, K, C in (('K1', K1, C1), ('K2', K2, C2)):
    rk = expand(K)
    print('=== %s ===' % name)
    print('  C          =', C.hex())
    print('  T(C)       =', T(C).hex())
    for i in range(15):
        if rk[i] == C:
            print('  C == rk%d' % i)
        if T(rk[i]) == C:
            print('  C == T(rk%d)' % i)
        if xr(rk[i], C) == bytes(16):
            print('  C == rk%d (xor0)' % i)
    # 常见派生
    cands = {}
    for i in range(15):
        cands['rk%d' % i] = rk[i]
        cands['T(rk%d)' % i] = T(rk[i])
        cands['SR(rk%d)' % i] = SR(rk[i])
        cands['MC(rk%d)' % i] = MC(rk[i])
        cands['SB(rk%d)' % i] = sub(rk[i])
        cands['T(SR(rk%d))' % i] = T(SR(rk[i]))
        cands['SR(T(rk%d))' % i] = SR(T(rk[i]))
        cands['MC(T(rk%d))' % i] = MC(T(rk[i]))
        cands['T(MC(rk%d))' % i] = T(MC(rk[i]))
    cands['T(K)'] = T(K)
    cands['K'] = K
    cands['SR(K)'] = SR(K)
    cands['MC(K)'] = MC(K)
    hits = [n for n, v in cands.items() if v == C]
    print('  direct hits:', hits)

# 差分法: 找 f(K) 使 C = f(rk10) 且两密钥一致
rk1 = expand(K1)
rk2 = expand(K2)
print('\n=== 差分 (rk10 ^ C) ===')
d1 = xr(rk1[10], C1)
d2 = xr(rk2[10], C2)
print('K1 rk10^C =', d1.hex())
print('K2 rk10^C =', d2.hex())
print('相同?', d1 == d2)
print('\n=== 差分 (T(rk10) ^ C) ===')
e1 = xr(T(rk1[10]), C1)
e2 = xr(T(rk2[10]), C2)
print('K1', e1.hex())
print('K2', e2.hex())
print('相同?', e1 == e2)
print('\n=== 差分 (rk11 ^ C) ===')
f1 = xr(rk1[11], C1)
f2 = xr(rk2[11], C2)
print('K1', f1.hex())
print('K2', f2.hex())
print('相同?', f1 == f2)
