# -*- coding: utf-8 -*-
"""tmp_hyp2.py — 大范围候选搜索：CONST_1 / Cb_1 是否等于某候选表达式（多密钥一致命中才算）。"""
import os, sys, struct, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from unicorn.arm64_const import UC_ARM64_REG_X1
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
captured = []


def rows24(x):
    b = u64(x)
    return b''.join(rd(u64(b + i * 24), 4) for i in range(4))


def cb(uc_, address, size, ud):
    captured.append(rows24(uc_.reg_read(UC_ARM64_REG_X1)))


uc.hook_add(unicorn.UC_HOOK_CODE, cb, begin=A_DRV, end=A_DRV + 4)


def F(x, rk):
    s = [a ^ b for a, b in zip(V.T(list(x)), rk[0])]
    for r in range(1, 10):
        s = V.MC(V.SR(V.SB(s)))
        s = [a ^ b for a, b in zip(s, rk[r])]
    return bytes(V.T(V.SR(V.SB(s))))


def ext_sched(K, n=44):
    w = [list(K[i*4:i*4+4]) for i in range(4)]
    rc = 1
    for i in range(4, 4*(n+1)):
        t = list(w[i-1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [V.SBOX[x] for x in t]
            t[0] ^= rc
            rc = V.xt(rc)
        w.append([w[i-4][j] ^ t[j] for j in range(4)])
    return [bytes(sum(w[4*r:4*r+4], [])) for r in range(n+1)]


def measure1(K):
    C = V.determine_C(o, K)
    rk = V.expand(K)
    pt = bytes([0x10]*32)
    captured.clear()
    ct = o.enc(pt, K, Z)
    xs = [captured[i] for i in range(0, len(captured), 2)]
    x1 = Tb(xs[1])
    const1 = X(X(x1, pt[16:32]), ct[0:16])
    Cb1 = X(ct[16:32], X(F(x1, rk), C))
    return const1, Cb1, C, rk


def candidates(K):
    c1, w1, C, rk = measure1(K)
    iv = K[::-1]
    es = ext_sched(K, 44)
    ins = {}
    ins['iv'] = iv
    ins['K'] = K
    ins['iv^K'] = X(iv, K)
    ins['0'] = Z
    ins['1'] = bytes([0]*15 + [1])
    ins['iv^1'] = X(iv, bytes([0]*15 + [1]))
    ins['K^1'] = X(K, bytes([0]*15 + [1]))
    for j in range(0, 45):
        ins['rk%d' % j] = es[j]
        ins['T(rk%d)' % j] = Tb(es[j])
    outs = {}
    for nm, v in ins.items():
        outs['F(' + nm + ')'] = F(v, rk)
        outs['E(' + nm + ')'] = X(F(v, rk), C)
        outs['T(F(' + nm + '))'] = Tb(F(v, rk))
        outs['F(' + nm + ')^' + nm] = X(F(v, rk), v)
        outs['E(' + nm + ')^' + nm] = X(X(F(v, rk), C), v)
    return c1, w1, outs


KEYS = [b'X8TEUA3DEXZNW2TN', b'ABCDEFGHIJKLMNOP', b'T9Z19J7NCY9S9X58',
        b'0000000000000000', b'0123456789abcdef']
hits_c = None
hits_w = None
for K in KEYS:
    c1, w1, outs = candidates(K)
    sc = {nm for nm, v in outs.items() if v == c1}
    sw = {nm for nm, v in outs.items() if v == w1}
    hits_c = sc if hits_c is None else (hits_c & sc)
    hits_w = sw if hits_w is None else (hits_w & sw)
    print('K=%s CONST1=%s Cb1=%s  单键命中(CONST)=%s' % (K.decode(errors='replace'), c1.hex(), w1.hex(), sorted(sc)))
print()
print('多键一致命中 CONST_1:', sorted(hits_c))
print('多键一致命中 Cb_1   :', sorted(hits_w))
