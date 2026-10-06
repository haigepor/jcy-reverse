# -*- coding: utf-8 -*-
"""tmp_tweak_table.py — 对给定 K, 用预言机+轮驱动 hook 测出每块的 (CONST_b, C_b) 表。
CONST_b = x_b ^ pt_b ^ ct_{b-1};  C_b = ct_b ^ H(x_b)
"""
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
T = lambda b: bytes(V.T(list(b)))
X = V.xr


def rows24(x):
    b = u64(x)
    return b''.join(rd(u64(b + i * 24), 4) for i in range(4))


captured = []


def cb(uc_, address, size, ud):
    captured.append(rows24(uc_.reg_read(UC_ARM64_REG_X1)))


uc.hook_add(unicorn.UC_HOOK_CODE, cb, begin=A_DRV, end=A_DRV + 4)


def measure(K, nblk=10):
    """返回 {b: (CONST_b, C_b, x_b)}。"""
    C = V.determine_C(o, K)
    rk = V.expand(K)

    def H(x):
        s = [a ^ b for a, b in zip(T(list(x)), rk[0])]
        for r in range(1, 10):
            s = V.MC(V.SR(V.SB(s)))
            s = [a ^ b for a, b in zip(s, rk[r])]
        return bytes(X(T(V.SR(V.SB(s))), C))

    pt = bytes([(0x10 + i) for i in range(nblk) for _ in range(16)])
    captured.clear()
    ct = o.enc(pt, K, Z)
    xs = [captured[i] for i in range(0, len(captured), 2)]
    out = {}
    for b in range(nblk):
        xb = T(xs[b])          # 驱动里存的是 T(x)
        prev = ct[b * 16 - 16:b * 16] if b else Z
        const = X(X(xb, pt[b * 16:(b + 1) * 16]), prev)
        Cb = X(ct[b * 16:(b + 1) * 16], H(xb))
        out[b] = (const, Cb, xb)
    return C, out


for K in (b'X8TEUA3DEXZNW2TN', b'ABCDEFGHIJKLMNOP', b'T9Z19J7NCY9S9X58'):
    C, tab = measure(K)
    print('=== K = %s   C = %s' % (K.decode(), C.hex()))
    for b in sorted(tab):
        const, Cb, xb = tab[b]
        print('  b=%d CONST=%s  C_b=%s  C_b^C=%s' % (b, const.hex(), Cb.hex(), X(Cb, C).hex()))
    json.dump({str(b): [tab[b][0].hex(), tab[b][1].hex()] for b in tab},
              open(os.path.join(HERE, 'tmp_tweak_%s.json' % K.decode()), 'w'))
