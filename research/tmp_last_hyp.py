# -*- coding: utf-8 -*-
"""tmp_last_hyp.py — 用 tmp_last_samples.json 枚举末轮结构假设 (纯 Python)。"""
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


def sub(s, box):
    return [box[x] for x in s]


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


rk = expand(K)
samples = json.load(open(os.path.join(HERE, 'tmp_last_samples.json')))
pairs = [(bytes.fromhex(s['A']), bytes.fromhex(s['ct']), bytes.fromhex(s['pt'])) for s in samples
         if s.get('A')]


def std_state9(pt):
    s = list(bytes(a ^ b for a, b in zip(pt, rk[0])))
    for r in range(1, 10):
        s = MC(SR(sub(s, SBOX)))
        s = [x ^ y for x, y in zip(s, rk[r])]
    return bytes(s)


print('=== 校验: 抓到的 A(grp9) == 标准 state9? ===')
for A, ct, pt in pairs:
    print('  match=%s' % (A == std_state9(pt)))

# 假设空间: ct = P(T(A)) ^ rk10'  (rk10' 未知 -> 检查 P(T(A)) ^ ct 恒定)
Ts = {'SB': lambda s: sub(s, SBOX), 'ISB': lambda s: sub(s, ISBOX), 'I': lambda s: list(s)}
Ps = {'I': lambda s: list(s), 'SR': SR, 'ISR': ISR, 'MC': MC, 'IMC': IMC,
      'MC.SR': lambda s: MC(SR(s)), 'SR.MC': lambda s: SR(MC(s)),
      'MC.ISR': lambda s: MC(ISR(s)), 'IMC.SR': lambda s: IMC(SR(s))}

print('\n=== 单层假设 ct = P(T(A)) ^ const ===')
hits = []
for tn, T in Ts.items():
    for pn, P in Ps.items():
        Ds = [bytes(x ^ y for x, y in zip(ct, P(T(list(A))))) for A, ct, pt in pairs]
        if all(d == Ds[0] for d in Ds):
            hits.append((tn, pn, Ds[0]))
            print('  HIT  T=%s P=%s const=%s' % (tn, pn, Ds[0].hex()))
print('hits:', len(hits))

print('\n=== 双层假设 ct = P2(T2(P1(T1(A)))) ^ const (子集) ===')
# 只用 SR/SB 组合的两层
layer1 = {'SB': lambda s: sub(s, SBOX), 'ISB': lambda s: sub(s, ISBOX), 'I': lambda s: list(s),
          'SR': SR, 'ISR': ISR, 'MC': MC, 'IMC': IMC,
          'SR.SB': lambda s: SR(sub(s, SBOX)), 'SB.SR': lambda s: sub(SR(s), SBOX)}
layer2 = {'SB': lambda s: sub(s, SBOX), 'ISB': lambda s: sub(s, ISBOX), 'I': lambda s: list(s),
          'SR': SR, 'ISR': ISR, 'MC': MC, 'IMC': IMC}
h2 = []
for n1, L1 in layer1.items():
    for n2, L2 in layer2.items():
        Ds = [bytes(x ^ y for x, y in zip(ct, L2(L1(list(A))))) for A, ct, pt in pairs]
        if all(d == Ds[0] for d in Ds):
            h2.append((n1, n2, Ds[0]))
            print('  HIT  %s -> %s const=%s' % (n1, n2, Ds[0].hex()))
print('hits2:', len(h2))
