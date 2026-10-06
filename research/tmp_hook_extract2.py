# -*- coding: utf-8 -*-
"""tmp_hook_extract2.py — 跟随指针读取块提取结果与密码输入。"""
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from unicorn.arm64_const import UC_ARM64_REG_SP
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa
sys.path.insert(0, HERE)
import tmp_verify_decrypt as V  # noqa

A_EXT = DEV_BASE + 0x2d7450
A_DRV = DEV_BASE + 0x2d7468
Z = bytes(16)
o = EOracle()
uc = o.s.e.uc
rd = o.s.e.rd
u64 = lambda a: struct.unpack('<Q', rd(a, 8))[0]

rec = []


def dump(x):
    """尝试多种解释, 返回可读表示。"""
    outs = []
    raw = rd(x, 16)
    outs.append(('raw', raw.hex()))
    p = u64(x)
    if 0x40000000 < p < 0x80000000:
        outs.append(('ptr', rd(p, 16).hex()))
    return outs


def cb_ext(uc_, address, size, ud):
    sp = uc_.reg_read(UC_ARM64_REG_SP)
    rec.append(('ext', dump(sp + 0x78)))


def cb_drv(uc_, address, size, ud):
    sp = uc_.reg_read(UC_ARM64_REG_SP)
    rec.append(('drv', dump(sp + 0x60)))


uc.hook_add(unicorn.UC_HOOK_CODE, cb_ext, begin=A_EXT, end=A_EXT + 4)
uc.hook_add(unicorn.UC_HOOK_CODE, cb_drv, begin=A_DRV, end=A_DRV + 4)

K = b'X8TEUA3DEXZNW2TN'
P = bytes([0x11] * 16)
Q = bytes([0x22] * 16)
R = bytes([0x33] * 16)
rec.clear()
ct = o.enc(P + Q + R, K, Z)
print('ct', ct.hex())
for i, (t, outs) in enumerate(rec):
    if i % 2:
        continue
    print('#%2d %s %s' % (i, t, ' | '.join('%s=%s' % (a, b) for a, b in outs)))
print()
print('P=%s' % P.hex())
print('Q=%s' % Q.hex())
print('R=%s' % R.hex())
print('ct0=%s ct1=%s ct2=%s' % (ct[0:16].hex(), ct[16:32].hex(), ct[32:48].hex()))
print('P^iv      =%s' % P.hex())
print('Q^ct0     =%s' % V.xr(Q, ct[0:16]).hex())
print('R^ct1     =%s' % V.xr(R, ct[16:32]).hex())
print('input1(SB) =fd108518c0f4193bef50ae58f026d793')
print('input2(SB) =b04ab77f1bed53b62f65552c44c7d49e')
