# -*- coding: utf-8 -*-
"""tmp_rowmajor.py — 用完整捕获验证: E(pt) = StdAES(T(pt)) 且末轮被改。
T = 状态矩阵转置 (row-major 序列化)。"""
import os, json
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


def T(s):  # 转置: out[4r+c] = in[4c+r]
    o = [0]*16
    for r in range(4):
        for c in range(4):
            o[4*r+c] = s[4*c+r]
    return o


rk = expand(K)
recs = json.load(open(os.path.join(HERE, 'tmp_full_caps.json')))


def states_from_A0(A0):
    s = list(A0)
    st = [bytes(s)]
    for r in range(1, 10):
        s = MC(SR(sub(s)))
        s = [x ^ y for x, y in zip(s, rk[r])]
        st.append(bytes(s))
    s = SR(sub(s))
    st.append(bytes(s))  # SR(SB(state9))
    return st


print('=== 假设: A0 = T(pt) ^ rk0, 之后标准 AES 轮 ===')
for rec in recs:
    pt = bytes.fromhex(rec['pt'])
    idx = rec['idx']
    grp = [bytes(idx[40+g*16:40+(g+1)*16]) for g in range(10)]
    A0 = [a ^ b for a, b in zip(T(list(pt)), rk[0])]
    st = states_from_A0(A0)
    ok = all(grp[r] == st[r] for r in range(10))
    print('pt=%s all10_match=%s' % (pt.hex(), ok))
    if not ok:
        for r in range(10):
            if grp[r] != st[r]:
                print('   r%d emu=%s std=%s' % (r, grp[r].hex(), st[r].hex()))

print('\n=== 假设: A0 = pt ^ rk0 (纯标准, 无转置) ===')
for rec in recs[:3]:
    pt = bytes.fromhex(rec['pt'])
    idx = rec['idx']
    grp = [bytes(idx[40+g*16:40+(g+1)*16]) for g in range(10)]
    A0 = [a ^ b for a, b in zip(pt, rk[0])]
    st = states_from_A0(A0)
    ok = all(grp[r] == st[r] for r in range(10))
    print('pt=%s all10_match=%s' % (pt.hex(), ok))
