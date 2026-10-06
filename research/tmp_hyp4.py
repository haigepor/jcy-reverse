# -*- coding: utf-8 -*-
"""tmp_hyp4.py — CONST 序列递推公式搜索 (多密钥一致命中才算)。"""
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


def fam(v, rk, C, K, iv):
    d = {}
    d['F(v)'] = F(v, rk)
    d['E(v)'] = X(F(v, rk), C)
    d['T(F(v))'] = Tb(F(v, rk))
    d['v^F(v)'] = X(v, F(v, rk))
    d['v^E(v)'] = X(v, X(F(v, rk), C))
    d['F(v^K)'] = F(X(v, K), rk)
    d['E(v^K)'] = X(F(X(v, K), rk), C)
    d['F(v^iv)'] = F(X(v, iv), rk)
    d['E(v^iv)'] = X(F(X(v, iv), rk), C)
    d['F(v)^K'] = X(F(v, rk), K)
    d['F(v)^iv'] = X(F(v, rk), iv)
    d['F(v)^C'] = X(F(v, rk), C)
    d['T(v)^F(v)'] = X(Tb(v), F(v, rk))
    return d


KEYS = [b'X8TEUA3DEXZNW2TN', b'ABCDEFGHIJKLMNOP', b'T9Z19J7NCY9S9X58']
agg = None
for K in KEYS:
    C, rk, CONST, ct = measure(K)
    iv = K[::-1]
    hits = set()
    for b in range(1, len(CONST) - 1):
        d = fam(CONST[b], rk, C, K, iv)
        for nm, v in d.items():
            if v == CONST[b + 1]:
                hits.add(nm)
    print('K=%s 单键命中 CONST_b->CONST_b+1: %s' % (K.decode(), sorted(hits)))
    agg = hits if agg is None else (agg & hits)
print('多键一致:', sorted(agg))
