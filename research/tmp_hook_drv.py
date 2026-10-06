# -*- coding: utf-8 -*-
"""tmp_hook_drv.py — hook 轮驱动 0x2da498, 用多种指针解释读 x1 (密码输入)。"""
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_LR
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa

A_DRV = DEV_BASE + 0x2da498
Z = bytes(16)
o = EOracle()
uc = o.s.e.uc
rd = o.s.e.rd
u64 = lambda a: struct.unpack('<Q', rd(a, 8))[0]


def interps(x):
    out = {}
    try:
        out['raw'] = rd(x, 16).hex()
    except Exception:
        pass
    try:
        out['p1'] = rd(u64(x), 16).hex()
    except Exception:
        pass
    try:
        b = u64(x)
        out['rows8'] = b''.join(rd(u64(b + i * 8), 4) for i in range(4)).hex()
    except Exception:
        pass
    try:
        b = u64(x)
        out['rows24'] = b''.join(rd(u64(b + i * 24), 4) for i in range(4)).hex()
    except Exception:
        pass
    try:
        b = u64(x)
        out['rows8x2'] = b''.join(rd(u64(u64(b + i * 8)), 4) for i in range(4)).hex()
    except Exception:
        pass
    return out


recs = []


def cb(uc_, address, size, ud):
    recs.append((uc_.reg_read(UC_ARM64_REG_LR) - DEV_BASE,
                 interps(uc_.reg_read(UC_ARM64_REG_X0)),
                 interps(uc_.reg_read(UC_ARM64_REG_X1))))


uc.hook_add(unicorn.UC_HOOK_CODE, cb, begin=A_DRV, end=A_DRV + 4)

K = b'X8TEUA3DEXZNW2TN'
P = bytes([0x11] * 16)
Q = bytes([0x22] * 16)
R = bytes([0x33] * 16)
recs.clear()
ct = o.enc(P + Q + R, K, Z)
print('n', len(recs))
for i, (lr, a, b) in enumerate(recs):
    print('#%d lr=%#x' % (i, lr))
    print('   x0:', a)
    print('   x1:', b)
print()
print('目标: 块1输入应为 fd108518c0f4193bef50ae58f026d793')
print('      块2输入应为 b04ab77f1bed53b62f65552c44c7d49e')
print('      (或 Q^ct0=afe446739f92479112e16521f67baa66 若为纯CBC)')
