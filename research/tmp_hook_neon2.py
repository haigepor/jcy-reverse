# -*- coding: utf-8 -*-
"""tmp_hook_neon2.py — 跟随 string 指针, dump 各阶段真实数据, 定位 tweak。"""
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_X29  # noqa
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa
sys.path.insert(0, HERE)
import tmp_verify_decrypt as V  # noqa

o = EOracle()
uc = o.s.e.uc
rd = o.s.e.rd
u64 = lambda a: struct.unpack('<Q', rd(a, 8))[0]
X = lambda a, b: bytes(x ^ y for x, y in zip(a, b))
Tb = lambda b: bytes(V.T(list(b)))
Z = bytes(16)


def deref(a):
    """尝试把 a 当成 string 头: 若 u64(a) 是堆指针则读其 16B, 否则读 a 自身 16B。"""
    try:
        p = u64(a)
        if 0x50000000 <= p < 0x50200000:
            return rd(p, 16).hex()
    except Exception:
        pass
    try:
        return rd(a, 16).hex()
    except Exception:
        return '??'


recs = []
POINTS = {0x2d7450: 'after-extract', 0x2d7464: 'after-neon', 0x2d7468: 'before-drv', 0x2d7478: 'after-drv'}


def cb(uc_, address, size, ud):
    off = address - DEV_BASE
    if off not in POINTS:
        return
    sp = uc_.reg_read(UC_ARM64_REG_SP)
    x29 = uc_.reg_read(UC_ARM64_REG_X29)
    recs.append((POINTS[off], deref(sp + 0x78), deref(sp + 0x60), deref(sp + 0x90)))


uc.hook_add(unicorn.UC_HOOK_CODE, cb, begin=DEV_BASE + 0x2d7450, end=DEV_BASE + 0x2d7478)
K = b'X8TEUA3DEXZNW2TN'
pt = bytes([0x10 + i for i in range(2) for _ in range(16)])
ct = o.enc(pt, K, Z)
print('ct', ct.hex())
print('pt0', pt[0:16].hex(), ' pt1', pt[16:32].hex())
print('iv ', K[::-1].hex())
print('x0  (T)', Tb(X(pt[0:16], K[::-1])).hex())
print('ct0', ct[0:16].hex())
CONST1 = bytes.fromhex('52f4c36b5f665eaafdb1cb79065d7df5')
x1 = X(X(pt[16:32], ct[0:16]), CONST1)
print('x1  (T)', Tb(x1).hex())
print()
for i, (nm, a, b, c) in enumerate(recs[:24]):
    print('#%-2d %-14s sp78=%s sp60=%s sp90=%s' % (i, nm, a, b, c))
