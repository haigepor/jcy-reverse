# -*- coding: utf-8 -*-
"""tmp_rounds.py — 计算标准 AES-128 各轮状态, 与 emu 抓到的 SubBytes 输入逐轮比对, 找分叉点。"""
import os, sys, json
from collections import Counter
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


def aes_states(pt, key, last_mix=False):
    """返回 [state0, after_r1, ..., after_r10, ciphertext]; SubBytes 输入 = 各 state。"""
    rk = expand(key)
    s = list(bytes(a ^ b for a, b in zip(pt, rk[0])))
    states = [bytes(s)]
    for r in range(1, 10):
        s = mix(shift(sub(s)))
        s = [x ^ y for x, y in zip(s, rk[r])]
        states.append(bytes(s))
    s = shift(sub(s))
    if last_mix:
        s = mix(s)
    s = [x ^ y for x, y in zip(s, rk[10])]
    states.append(bytes(s))
    return states, rk


# 抓 emu SubBytes 输入
o = EOracle()
uc = o.s.e.uc
idx = []


def mem_cb(uc_, access, address, size, value, ud):
    if access == unicorn.UC_MEM_READ:
        idx.append(address - 0x737e41c38960)


uc.hook_add(unicorn.UC_HOOK_MEM_READ, mem_cb, begin=0x737e41c38960, end=0x737e41c38960 + 255)
out = o.enc(Z, K, Z)
print('out', out.hex())
sub_idx = idx[40:]
grp = [bytes(sub_idx[g*16:(g+1)*16]) for g in range(len(sub_idx)//16)]

# block0: grp[0:10] 是 10 轮 SubBytes 输入
states, rk = aes_states(bytes(16), K, last_mix=False)
states_lm, _ = aes_states(bytes(16), K, last_mix=True)
print('--- 逐轮比对 block0 (grp[r] vs 标准AES round r SubBytes输入) ---')
for r in range(10):
    g = grp[r] if r < len(grp) else b''
    std = states[r]
    print('r%d  match=%s' % (r, g == std))
    if g != std:
        print('   emu %s' % g.hex())
        print('   std %s' % std.hex())
print('--- block0 密文 ---')
print('emu out[0:16]      ', out[:16].hex())
print('std AES(0)         ', states[10].hex())
print('std AES(0)+lastMC  ', states_lm[10].hex())
