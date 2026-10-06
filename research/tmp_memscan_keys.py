# -*- coding: utf-8 -*-
"""tmp_memscan_keys.py — 跑一次加密后扫描模拟器内存, 定位密钥调度与末轮常量 C。"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from e_oracle import EOracle  # noqa

K = b'X8TEUA3DEXZNW2TN'
Z = bytes(16)
SO = open(os.path.join(HERE, 'artifacts', 'libcore.so'), 'rb').read()
SBOX = SO[0x1dfc00:0x1dfc00 + 256]


def xt(a):
    a <<= 1
    return (a ^ 0x1b) & 0xff if a & 0x100 else a


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


def T(s):
    o = [0]*16
    for r in range(4):
        for c in range(4):
            o[4*r+c] = s[4*c+r]
    return bytes(o)


def rev(s):
    return bytes(s[::-1])


o = EOracle()
uc = o.s.e.uc
out = o.enc(bytes(16), K, Z)
print('out =', out.hex())

rk = expand(K)
C1 = bytes.fromhex('922d5b80f9d4790db030dbf4bf190190')
pats = {}
for i in range(15):
    pats['rk%d' % i] = rk[i]
    pats['T(rk%d)' % i] = T(rk[i])
    pats['rev(rk%d)' % i] = rev(rk[i])
pats['K'] = K
pats['T(K)'] = T(K)
pats['C1'] = C1
pats['T(C1)'] = T(C1)
pats['outblk0'] = bytes.fromhex(out[:16].hex())
pats['outblk1'] = bytes.fromhex(out[16:32].hex())
# 反序(4字节字内反转)版本
pats['rk10_wrev'] = b''.join(rk[10][4*i:4*i+4][::-1] for i in range(4))
pats['C1_wrev'] = b''.join(C1[4*i:4*i+4][::-1] for i in range(4))

regions = list(uc.mem_regions())
print('regions', len(regions))
found = {k: [] for k in pats}
for (base, end, perm) in regions:
    try:
        data = bytes(uc.mem_read(base, end - base))
    except Exception:
        continue
    for name, pat in pats.items():
        idx = 0
        while True:
            j = data.find(pat, idx)
            if j < 0:
                break
            found[name].append(base + j)
            idx = j + 1

for name in pats:
    locs = found[name]
    if locs:
        print('%-12s -> %s' % (name, [hex(x) for x in locs[:6]]))
