# -*- coding: utf-8 -*-
"""tmp_crack_last.py — 暴力枚举末轮变换(要求两组明文 rk10 一致)。"""
import os, sys, itertools
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from e_oracle import EOracle  # noqa

K = b'X8TEUA3DEXZNW2TN'
Z = b'\x00' * 16
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


def SB(s):
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


OPS = {'SB': SB, 'SR': SR, 'MC': MC, 'I': lambda s: list(s)}
rk = expand(K)


def grab(pt):
    o = EOracle()
    uc = o.s.e.uc
    idx = []

    def mem_cb(uc_, access, address, size, value, ud):
        if access == unicorn.UC_MEM_READ:
            idx.append(address - 0x737e41c38960)

    uc.hook_add(unicorn.UC_HOOK_MEM_READ, mem_cb, begin=0x737e41c38960, end=0x737e41c38960 + 255)
    out = o.enc(pt, K, Z)
    sub = idx[40:]
    grp = [bytes(sub[g*16:(g+1)*16]) for g in range(len(sub)//16)]
    return out, grp


samples = []
for pt in (bytes(16), bytes([1])*16, bytes(range(16))):
    out, grp = grab(pt)
    samples.append((grp[9], out[:16]))  # (round-10 SubBytes input, ct block0)
    print('pt=%s -> ct0=%s grp09=%s' % (pt.hex()[:16], out[:16].hex(), grp[9].hex()))

print('\n--- 枚举末轮 (op1..opN, ARK) 要求 3 组 rk10 一致 ---')
found = []
for L in range(1, 5):
    for combo in itertools.product(['SB', 'SR', 'MC'], repeat=L):
        def T(s, combo=combo):
            x = list(s)
            for op in combo:
                x = OPS[op](x)
            return bytes(x)
        rks = [xor(T(list(g)), ct) for g, ct in samples]
        if all(r == rks[0] for r in rks):
            found.append((combo, rks[0]))
            print('HIT combo=%s rk10=%s  ==std?%s' % ('-'.join(combo), rks[0].hex(), rks[0] == rk[10]))
if not found:
    print('无命中(单 ARK 模型) — 尝试 末轮=组合 + 额外 ⊕rk10_std 之外的固定量')
