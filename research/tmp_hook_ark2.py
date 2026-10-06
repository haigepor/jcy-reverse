# -*- coding: utf-8 -*-
"""tmp_hook_ark2.py — dump ARK(0x2d52e0) 的 x0/x1 原始结构, 定位 state 与 rk。"""
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_LR
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa

ADDR_ARK = DEV_BASE + 0x2d52e0
Z = bytes(16)
o = EOracle()
uc = o.s.e.uc
rd = o.s.e.rd
u64 = lambda a: struct.unpack('<Q', rd(a, 8))[0]

calls = []


def cb(uc_, address, size, ud):
    x0 = uc_.reg_read(UC_ARM64_REG_X0)
    x1 = uc_.reg_read(UC_ARM64_REG_X1)
    x2 = uc_.reg_read(UC_ARM64_REG_X2)
    lr = uc_.reg_read(UC_ARM64_REG_LR) - DEV_BASE
    calls.append((lr, x0, x1, x2, rd(x0, 32), rd(x1, 32)))


uc.hook_add(unicorn.UC_HOOK_CODE, cb, begin=ADDR_ARK, end=ADDR_ARK + 4)

K = b'X8TEUA3DEXZNW2TN'
P = bytes([0x11] * 16)
Q = bytes([0x22] * 16)
calls.clear()
ct = o.enc(P + Q, K, Z)
print('ct', ct.hex())
print('n calls', len(calls))
for i, (lr, x0, x1, x2, m0, m1) in enumerate(calls[:14]):
    print('#%d lr=%#x x0=%#x x1=%#x x2=%#x' % (i, lr, x0, x1, x2))
    print('    [x0]=%s' % m0.hex())
    print('    [x1]=%s' % m1.hex())
    try:
        p = u64(x1)
        print('    *x1=%#x  [*x1]=%s' % (p, rd(p, 32).hex()))
    except Exception as ex:
        print('    *x1 fail', ex)
print()
print('A0_0 期望 = 492945544450225554494b5f4623455f')
print('rk0 = K = 583854455541334445585a4e5732544e')
