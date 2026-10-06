# -*- coding: utf-8 -*-
"""tmp_lastround2.py — 单次自洽捕获: 运行时S盒表 + 索引序列 + 密文, 判定末轮变换。
不依赖任何硬编码旧值。"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from e_oracle import EOracle  # noqa

K = b'X8TEUA3DEXZNW2TN'
Z = b'\x00' * 16
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


def expand(key, nk=4, nr=10):
    w = [list(key[i*4:i*4+4]) for i in range(nk)]
    rc = 1
    for i in range(nk, 4*(nr+1)):
        t = list(w[i-1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [SBOX[x] for x in t]
            t[0] ^= rc
            rc = xt(rc)
        w.append([w[i-nk][j] ^ t[j] for j in range(4)])
    return [bytes(sum(w[4*r:4*r+4], [])) for r in range(nr+1)]


def sub(s, box=SBOX):
    return [box[x] for x in s]


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


o = EOracle()
uc = o.s.e.uc
idx = []
reads = []


def mem_cb(uc_, access, address, size, value, ud):
    if access == unicorn.UC_MEM_READ and BASE <= address <= BASE + 255:
        idx.append(address - BASE)


uc.hook_add(unicorn.UC_HOOK_MEM_READ, mem_cb, begin=BASE, end=BASE + 255)
out = o.enc(Z, K, Z)
runtime_box = bytes(uc.mem_read(BASE, 256))
print('out', out.hex(), 'len', len(out))
print('runtime S-box == standard AES S-box?', runtime_box == SBOX)
print('runtime S-box == inv AES S-box?', runtime_box == ISBOX)
print('runtime distinct', len(set(runtime_box)))
print('runtime box', runtime_box.hex())
print('idx count', len(idx))
print('idx[0:64]', idx[:64])
sub_idx = idx[40:]
print('after-40 count', len(sub_idx), 'groups', len(sub_idx)//16)
grp = [bytes(sub_idx[g*16:(g+1)*16]) for g in range(len(sub_idx)//16)]
for r, g in enumerate(grp):
    print('grp%d %s' % (r, g.hex()))

# 标准 AES 逐轮状态 (S-box 用文件标准表)
rk = expand(K)


def aes_states(pt, box=SBOX):
    s = list(bytes(a ^ b for a, b in zip(pt, rk[0])))
    states = [bytes(s)]
    for r in range(1, 10):
        s = mix(shift(sub(s, box)))
        s = [x ^ y for x, y in zip(s, rk[r])]
        states.append(bytes(s))
    s = shift(sub(s, box))
    states.append(bytes(s))  # = SR(SB(state9))
    return states


st = aes_states(Z)
print('--- 逐轮比对 ---')
for r in range(min(10, len(grp))):
    print('r%d match_std=%s' % (r, grp[r] == st[r]))
print('SR(SB(state9)) [std] =', st[10].hex())
print('rk10 std            =', rk[10].hex())
print('ct0                 =', out[:16].hex())
print('ct0 ^ rk10          =', bytes(a ^ b for a, b in zip(out[:16], rk[10])).hex())
print('ct0 ^ st[10]        =', bytes(a ^ b for a, b in zip(out[:16], st[10])).hex())
