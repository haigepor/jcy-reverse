# -*- coding: utf-8 -*-
"""tmp_hyp5.py — 测试 CONST_b 是否为 E(nonce ^ ctr_b) 形式 (CTR 型 keystream)。"""
import os, sys, struct, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from unicorn.arm64_const import UC_ARM64_REG_X1  # noqa
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa
sys.path.insert(0, HERE)
import tmp_verify_decrypt as V  # noqa

A_DRV = DEV_BASE + 0x2da498
Z = bytes(16)
o = EOracle()
uc = o.s.e.uc
rd = o.s.e.rd
u64 = lambda a: struct.unpack('<Q', rd(a, 8))[0]
X = V.xr
Tb = lambda b: bytes(V.T(list(b)))
cap = []


def rows24(x):
    b = u64(x)
    return b''.join(rd(u64(b + i * 24), 4) for i in range(4))


def cb(uc_, address, size, ud):
    cap.append(rows24(uc_.reg_read(UC_ARM64_REG_X1)))


uc.hook_add(unicorn.UC_HOOK_CODE, cb, begin=A_DRV, end=A_DRV + 4)


def F(x, rk):
    s = [a ^ b for a, b in zip(V.T(list(x)), rk[0])]
    for r in range(1, 10):
        s = V.MC(V.SR(V.SB(s)))
        s = [a ^ b for a, b in zip(s, rk[r])]
    return bytes(V.T(V.SR(V.SB(s))))


def measure(K, nblk=12):
    C = V.determine_C(o, K)
    rk = V.expand(K)
    pt = bytes([0x10 + i for i in range(nblk) for _ in range(16)])
    cap.clear()
    ct = o.enc(pt, K, Z)
    xs = [Tb(cap[i]) for i in range(0, len(cap), 2)]
    CONST = []
    for b in range(nblk):
        prev = ct[b*16-16:b*16] if b else Z
        CONST.append(X(X(xs[b], pt[b*16:(b+1)*16]), prev))
    return C, rk, CONST, ct


def nonces(K, C, rk, ct):
    d = {'0': Z, 'iv': K[::-1], 'K': K, 'C': C, 'T(C)': Tb(C),
         'F0': F(Z, rk), 'E0': X(F(Z, rk), C), 'T(F0)': Tb(F(Z, rk)),
         'ct0': ct[0:16], 'F(ct0)': F(ct[0:16], rk), 'T(ct0)': Tb(ct[0:16])}
    for j in range(0, 11):
        d['rk%d' % j] = rk[j]
        d['T(rk%d)' % j] = Tb(rk[j])
        d['F(rk%d)' % j] = F(rk[j], rk)
    return d


def ctrs(b):
    return {'le_last': bytes(15) + bytes([b & 0xff]),
            'be_last': bytes(15) + bytes([b & 0xff]),
            'le_first': bytes([b & 0xff]) + bytes(15),
            'be8': struct.pack('>Q', b) + bytes(8),
            'le8': struct.pack('<Q', b) + bytes(8)}


KEYS = [b'X8TEUA3DEXZNW2TN', b'ABCDEFGHIJKLMNOP', b'T9Z19J7NCY9S9X58']
agg = None
for K in KEYS:
    C, rk, CONST, ct = measure(K)
    ns = nonces(K, C, rk, ct)
    hits = set()
    for nm, N in ns.items():
        for cn, c in ctrs(1).items():
            # 假设 CONST_b = E(N ^ ctr_b)
            good = all(X(F(X(N, ctrs(b)[cn]), rk), C) == CONST[b] for b in range(1, len(CONST)))
            if good:
                hits.add('E(%s ^ %s)' % (nm, cn))
            # 假设 CONST_b = F(N ^ ctr_b)
            good2 = all(F(X(N, ctrs(b)[cn]), rk) == CONST[b] for b in range(1, len(CONST)))
            if good2:
                hits.add('F(%s ^ %s)' % (nm, cn))
    print('K=%s hits: %s' % (K.decode(), sorted(hits)))
    agg = hits if agg is None else (agg & hits)
print('多键一致:', sorted(agg))
