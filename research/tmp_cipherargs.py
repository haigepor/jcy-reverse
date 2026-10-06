# -*- coding: utf-8 -*-
"""tmp_cipherargs.py — 捕获密码函数 0x2d6f78 的入参(找模式位/密钥指针)。"""
import sys
sys.path.insert(0, 'research/captures/rsa_scan')
import unicorn  # noqa
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                 UC_ARM64_REG_X3, UC_ARM64_REG_X4, UC_ARM64_REG_X5,
                                 UC_ARM64_REG_LR, UC_ARM64_REG_SP)
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa

K = b'X8TEUA3DEXZNW2TN'
IV = K[::-1]
PT = bytes.fromhex('00000000000000000000000000000000')

o = EOracle()
uc = o.s.e.uc
calls = []
TGT = 0x2d6f78
RETS = set()


def code_cb(uc_, addr, size, ud):
    off = addr - DEV_BASE
    if off == TGT and len(calls) < 40:
        a = tuple(uc_.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                            UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                                            UC_ARM64_REG_X4, UC_ARM64_REG_X5,
                                            UC_ARM64_REG_LR))
        calls.append(a)


uc.hook_add(unicorn.UC_HOOK_CODE, code_cb, begin=DEV_BASE + TGT, end=DEV_BASE + TGT + 4)
out = o.enc(PT, K, IV)
print('out', out.hex())
print('0x2d6f78 calls:', len(calls))
for i, a in enumerate(calls[:12]):
    print('#%d x0=%#x x1=%#x x2=%#x x3=%#x x4=%#x x5=%#x lr=%#x' %
          (i, a[0], a[1], a[2], a[3], a[4], a[5], a[6] - DEV_BASE))
    for nm, ad in (('x0', a[0]), ('x1', a[1])):
        try:
            d = bytes(uc.mem_read(ad, 32))
            print('    %s@%#x = %s' % (nm, ad, d.hex()))
        except Exception as ex:
            print('    %s read err %s' % (nm, ex))
