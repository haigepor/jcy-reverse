# -*- coding: utf-8 -*-
"""tmp_model_verify.py — 验证 E(x) = T(SR(SB(AES9(T(x)^K)))) ^ C, 并查 C 的密钥依赖。"""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from e_oracle import EOracle  # noqa

SO = open(os.path.join(HERE, 'artifacts', 'libcore.so'), 'rb').read()
SBOX = SO[0x1dfc00:0x1dfc00 + 256]
ISBOX = bytes(SBOX.index(i) for i in range(256))
BASE = 0x737e41c38960


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


def sub(s):
    return [SBOX[x] for x in s]


def SR(s):
    o = [0]*16
    for c in range(4):
        for r in range(4):
            o[4*c+r] = s[4*((c+r) % 4)+r]
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


def T(s):
    o = [0]*16
    for r in range(4):
        for c in range(4):
            o[4*r+c] = s[4*c+r]
    return o


def E_model(x, K, C):
    rk = expand(K)
    A0 = [a ^ b for a, b in zip(T(list(x)), rk[0])]
    s = list(A0)
    for r in range(1, 10):
        s = MC(SR(sub(s)))
        s = [a ^ b for a, b in zip(s, rk[r])]
    st10 = SR(sub(s))
    return bytes(a ^ b for a, b in zip(T(st10), C))


def g9_of(idx):
    return bytes(idx[40+9*16:40+10*16])


o = EOracle()
uc = o.s.e.uc
cur = {'idx': []}


def mem_cb(uc_, access, address, size, value, ud):
    if access == unicorn.UC_MEM_READ and BASE <= address <= BASE + 255:
        cur['idx'].append(address - BASE)


uc.hook_add(unicorn.UC_HOOK_MEM_READ, mem_cb, begin=BASE, end=BASE + 255)

K1 = b'X8TEUA3DEXZNW2TN'
C1 = bytes.fromhex('922d5b80f9d4790db030dbf4bf190190')
K2 = b'ABCDEFGHIJKLMNOP'
Z = bytes(16)

print('=== 1) 同密钥 K1, 新明文验证 C1 ===')
for pt in [bytes([0x11]*16), bytes(range(16, 32)), bytes([0xaa]*16)]:
    cur['idx'] = []
    out = o.enc(pt, K1, Z)
    G9 = g9_of(cur['idx'])
    ct = out[:16]
    rk = expand(K1)
    st10 = SR(sub(list(G9)))
    C_obs = bytes(a ^ b for a, b in zip(ct, T(st10)))
    print('pt=%s C_obs=%s  ==C1? %s' % (pt.hex(), C_obs.hex(), C_obs == C1))
    print('   model_eq=%s' % (E_model(pt, K1, C1) == ct))

print('\n=== 2) 新密钥 K2, 拟合 C2 ===')
Cs = []
for pt in [Z, bytes([0x10]*16), bytes(range(16))]:
    cur['idx'] = []
    out = o.enc(pt, K2, Z)
    G9 = g9_of(cur['idx'])
    ct = out[:16]
    st10 = SR(sub(list(G9)))
    C_obs = bytes(a ^ b for a, b in zip(ct, T(st10)))
    Cs.append(C_obs)
    print('pt=%s C_obs=%s' % (pt.hex(), C_obs.hex()))
print('C2 const?', all(c == Cs[0] for c in Cs))
if Cs:
    C2 = Cs[0]
    print('C2 =', C2.hex())
    rk = expand(K2)
    for i, r in enumerate(rk[:15]):
        if C2 == r:
            print('  C2 == rk%d' % i)
        if T(C2) == r:
            print('  T(C2) == rk%d' % i)
    rk1 = expand(K1)
    print('C2 vs K1 schedule:')
    for i, r in enumerate(rk1[:15]):
        if C2 == r:
            print('  C2 == rk%d(K1)' % i)
        if T(C2) == r:
            print('  T(C2) == rk%d(K1)' % i)
    print('--- K1: C1 与调度比对 ---')
    for i, r in enumerate(rk1[:15]):
        if C1 == r:
            print('  C1 == rk%d(K1)' % i)
        if T(C1) == r:
            print('  T(C1) == rk%d(K1)' % i)
