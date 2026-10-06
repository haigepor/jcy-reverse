# -*- coding: utf-8 -*-
"""tmp_hook_stage.py — hook E 体块循环中间步骤 (0x2d9ad4 / 0x2d9ed0 / 0x2da1c8 / 0x2da6c4),
dump 参数与缓冲, 定位链式值来源。"""
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                 UC_ARM64_REG_X3, UC_ARM64_REG_W2, UC_ARM64_REG_LR)
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa

TARGETS = {0x2d9ad4: 'extract', 0x2d9ed0: 'neon', 0x2da1c8: 'reorder',
           0x2da6c4: 'outreorder', 0x2d19ec: 'link'}
Z = bytes(16)
o = EOracle()
uc = o.s.e.uc
rd = o.s.e.rd
u64 = lambda a: struct.unpack('<Q', rd(a, 8))[0]

log = []


def show(x):
    if x is None:
        return '?'
    parts = []
    try:
        parts.append('raw=%s' % rd(x, 16).hex())
    except Exception:
        parts.append('raw=?')
    try:
        p = u64(x)
        if 0x40000000 < p < 0x80000000:
            try:
                parts.append('p1=%s' % rd(p, 16).hex())
            except Exception:
                parts.append('p1=?')
    except Exception:
        pass
    return ' '.join(parts)


def cb(uc_, address, size, ud):
    off = address - DEV_BASE
    if off not in TARGETS:
        return
    name = TARGETS[off]
    x0 = uc_.reg_read(UC_ARM64_REG_X0)
    x1 = uc_.reg_read(UC_ARM64_REG_X1)
    x2 = uc_.reg_read(UC_ARM64_REG_X2)
    x3 = uc_.reg_read(UC_ARM64_REG_X3)
    w2 = uc_.reg_read(UC_ARM64_REG_W2)
    log.append('%s w2=%#x\n   x0 %s\n   x1 %s\n   x2 %s\n   x3 %s' % (
        name, w2, show(x0), show(x1), show(x2), show(x3)))


for a, n in TARGETS.items():
    uc.hook_add(unicorn.UC_HOOK_CODE, cb, begin=DEV_BASE + a, end=DEV_BASE + a + 4)

K = b'X8TEUA3DEXZNW2TN'
ct = o.enc(bytes([0x11] * 16) + bytes([0x22] * 16) + bytes([0x33] * 16), K, Z)
print('ct', ct.hex())
for i, l in enumerate(log):
    print('#%d %s' % (i, l))
