# -*- coding: utf-8 -*-
"""tmp_hook_neon.py — hook 块循环各阶段, dump 栈缓冲, 定位 tweak 注入。"""
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from unicorn.arm64_const import (UC_ARM64_REG_SP, UC_ARM64_REG_X29, UC_ARM64_REG_X0,  # noqa
                                 UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                                 UC_ARM64_REG_W2)
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa

PTS = [0x2d7440, 0x2d7450, 0x2d7468, 0x2d7478, 0x2d7484]
o = EOracle()
uc = o.s.e.uc
rd = o.s.e.rd
u64 = lambda a: struct.unpack('<Q', rd(a, 8))[0]


def rd16(a):
    try:
        return rd(a, 16).hex()
    except Exception:
        return '??'


recs = []


def cb(uc_, address, size, ud):
    off = address - DEV_BASE
    sp = uc_.reg_read(UC_ARM64_REG_SP)
    x29 = uc_.reg_read(UC_ARM64_REG_X29)
    recs.append((off, rd16(sp + 0x78), rd16(sp + 0x60), rd16(x29 - 0x48),
                 rd16(x29 - 0x78), rd16(sp + 0x90)))


uc.hook_add(unicorn.UC_HOOK_CODE, cb, begin=DEV_BASE + 0x2d7440, end=DEV_BASE + 0x2d7484)
K = b'X8TEUA3DEXZNW2TN'
pt = bytes([0x10 + i for i in range(2) for _ in range(16)])
ct = o.enc(pt, K, bytes(16))
print('ct', ct.hex())
for i, (off, a, b, c, d, e) in enumerate(recs[:40]):
    print('#%-2d pc=%#x  sp78=%s  sp60=%s  x29m48=%s  x29m78=%s  sp90=%s' % (i, off, a, b, c, d, e))
