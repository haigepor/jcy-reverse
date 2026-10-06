# -*- coding: utf-8 -*-
"""tmp_C_combo.py — C 的组合搜索: C ∈ S 或 C = a^b (a,b ∈ S), S=各种密钥派生。"""
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


def rev(s):
    return bytes(s[::-1])


K1 = b'X8TEUA3DEXZNW2TN'
K2 = b'ABCDEFGHIJKLMNOP'
C1 = bytes.fromhex('922d5b80f9d4790db030dbf4bf190190')
C2 = bytes.fromhex('ddb620bf286bdeb737406233b533ad92')


def build_S(K):
    S = {}
    for kname, k in (('K', K), ('T(K)', T(K)), ('rev(K)', rev(K)), ('SR(K)', SR(K))):
        S[kname] = k
        rk = expand(k)
        for i in range(15):
            S['%s.rk%d' % (kname, i)] = rk[i]
            S['%s.T(rk%d)' % (kname, i)] = T(rk[i])
            S['%s.SR(rk%d)' % (kname, i)] = SR(rk[i])
            S['%s.MC(rk%d)' % (kname, i)] = MC(rk[i])
            S['%s.SB(rk%d)' % (kname, i)] = sub(rk[i])
            S['%s.T(SR(rk%d))' % (kname, i)] = T(SR(rk[i]))
            S['%s.SR(T(rk%d))' % (kname, i)] = SR(T(rk[i]))
    return S


for label, K, C in (('K1', K1, C1), ('K2', K2, C2)):
    S = build_S(K)
    print('=== %s  |S|=%d ===' % (label, len(S)))
    singles = [n for n, v in S.items() if v == C]
    print('  单元素命中:', singles)
    # 两两 XOR
    names = list(S)
    pairhits = []
    for i in range(len(names)):
        vi = S[names[i]]
        for j in range(i+1, len(names)):
            vj = S[names[j]]
            if bytes(a ^ b for a, b in zip(vi, vj)) == C:
                pairhits.append((names[i], names[j]))
    print('  两两XOR命中数:', len(pairhits))
    for p in pairhits[:12]:
        print('    ', p)
    # 也找 C 与某个单元素的 XOR 恒定(跨密钥)
print('\n=== 跨密钥: C1^C2 ===')
print((bytes(a ^ b for a, b in zip(C1, C2))).hex())
rk1 = expand(K1)
rk2 = expand(K2)
for i in range(15):
    for nm, f in (('rk', lambda r: r), ('T(rk)', T), ('SR(rk)', SR), ('MC(rk)', MC)):
        d1 = bytes(a ^ b for a, b in zip(C1, f(rk1[i])))
        d2 = bytes(a ^ b for a, b in zip(C2, f(rk2[i])))
        if d1 == d2:
            print('  C ^ %s%d 跨密钥恒定 = %s' % (nm, i, d1.hex()))
