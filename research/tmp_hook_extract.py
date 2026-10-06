# -*- coding: utf-8 -*-
"""tmp_hook_extract.py — hook E 体块循环:
  0x2d7450 (extract 之后) 读 sp+0x78 = 提取出的原始块
  0x2d7468 (轮驱动之前) 读 sp+0x60 = 送入密码的输入
"""
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from unicorn.arm64_const import UC_ARM64_REG_SP, UC_ARM64_REG_W2, UC_ARM64_REG_X2
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

rec = []


def cb_ext(uc_, address, size, ud):
    sp = uc_.reg_read(UC_ARM64_REG_SP)
    rec.append(('ext', rd(sp + 0x78, 16).hex()))


def cb_drv(uc_, address, size, ud):
    sp = uc_.reg_read(UC_ARM64_REG_SP)
    rec.append(('drv', rd(sp + 0x60, 16).hex()))


uc.hook_add(unicorn.UC_HOOK_CODE, cb_ext, begin=A_EXT, end=A_EXT + 4)
uc.hook_add(unicorn.UC_HOOK_CODE, cb_drv, begin=A_DRV, end=A_DRV + 4)

K = b'X8TEUA3DEXZNW2TN'
P = bytes([0x11] * 16)
Q = bytes([0x22] * 16)
R = bytes([0x33] * 16)
rec.clear()
ct = o.enc(P + Q + R, K, Z)
print('ct', ct.hex())
print('n events', len(rec))
for i, (t, v) in enumerate(rec):
    print('#%2d %s %s' % (i, t, v))
print()
print('P=%s Q=%s R=%s' % (P.hex(), Q.hex(), R.hex()))
print('ct0=%s ct1=%s ct2=%s' % (ct[0:16].hex(), ct[16:32].hex(), ct[32:48].hex()))
print('P^ct_prev:  b1=%s  b2=%s' % (V.xr(Q, ct[0:16]).hex(), V.xr(R, ct[16:32]).hex()))
