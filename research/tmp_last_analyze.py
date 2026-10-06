# -*- coding: utf-8 -*-
"""tmp_last_analyze.py — 采集多组 (state9, ct) 反解末轮函数 f。
前 9 轮已确证标准 AES, 只需反解 state9 -> ct 的映射。"""
import os, sys, json
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


def sub(s, box=SBOX):
    return [box[x] for x in s]


def shift(s):
    o = [0]*16
    for c in range(4):
        for r in range(4):
            o[4*c+r] = s[4*((c+r) % 4)+r]
    return o


def ishift(s):
    o = [0]*16
    for c in range(4):
        for r in range(4):
            o[4*c+r] = s[4*((c-r) % 4)+r]
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


rk = expand(K)


def std_state9(pt):
    s = list(bytes(a ^ b for a, b in zip(pt, rk[0])))
    for r in range(1, 10):
        s = mix(shift(sub(s)))
        s = [x ^ y for x, y in zip(s, rk[r])]
    return bytes(s)


o = EOracle()
uc = o.s.e.uc
cur = {'idx': []}


def mem_cb(uc_, access, address, size, value, ud):
    if access == unicorn.UC_MEM_READ and BASE <= address <= BASE + 255:
        cur['idx'].append(address - BASE)


uc.hook_add(unicorn.UC_HOOK_MEM_READ, mem_cb, begin=BASE, end=BASE + 255)

samples = []
pts = [bytes(16), bytes([0x10]*16), bytes(range(16)), bytes([0xff]*16),
       bytes([0x5a]*16), bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])]
for pt in pts:
    cur['idx'] = []
    out = o.enc(pt, K, Z)
    idx = cur['idx'][:]
    grp = [bytes(idx[40+g*16:40+(g+1)*16]) for g in range((len(idx)-40)//16)]
    a = grp[9] if len(grp) > 9 else None
    samples.append({'pt': pt.hex(), 'ct': out[:16].hex(), 'A': a.hex() if a else None,
                    'ngroups': len(grp)})
    print('pt=%s ct0=%s A=%s ng=%d' % (pt.hex(), out[:16].hex(), a.hex() if a else '-', len(grp)))

json.dump(samples, open(os.path.join(HERE, 'tmp_last_samples.json'), 'w'), indent=1)

# 分析: 对每个候选末轮 L, 检查 ct ^ L(A) 是否恒定
cands = {
    'SR(SB)': lambda s: shift(sub(s)),
    'MC(SR(SB))': lambda s: mix(shift(sub(s))),
    'SB': lambda s: sub(s),
    'I': lambda s: list(s),
    'MC(SB)': lambda s: mix(sub(s)),
    'SR': lambda s: shift(list(s)),
    'MC(SR)': lambda s: mix(shift(list(s))),
    'SR^-1(SB)': lambda s: ishift(sub(s)),
    'SB(SR)': lambda s: sub(shift(list(s))),
    'SR(SB(MC))': lambda s: shift(sub(mix(list(s)))),
}
print('\n--- 恒定 XOR 检测 ---')
for name, L in cands.items():
    xs = []
    for sm in samples:
        if sm['A'] is None:
            continue
        a = bytes.fromhex(sm['A'])
        ct = bytes.fromhex(sm['ct'])
        xs.append(bytes(x ^ y for x, y in zip(ct, L(list(a)))))
    const = all(x == xs[0] for x in xs) if xs else False
    print('%-12s const=%s  x0=%s' % (name, const, xs[0].hex() if xs else '-'))

print('\n--- 与标准 AES 末轮的差值 (ct ^ ct_std) 是否恒定 ---')
ds = []
for sm in samples:
    pt = bytes.fromhex(sm['pt'])
    s9 = std_state9(pt)
    ct_std = bytes(a ^ b for a, b in zip(shift(sub(s9)), rk[10]))
    ct = bytes.fromhex(sm['ct'])
    ds.append(bytes(x ^ y for x, y in zip(ct, ct_std)))
print('all const?', all(d == ds[0] for d in ds))
for i, d in enumerate(ds):
    print('  %s' % d.hex())
