# -*- coding: utf-8 -*-
"""tmp_tbl.py — 提取 0x2cd8b0 构造器的入参/输出表。"""
import sys
sys.path.insert(0, 'research/captures/rsa_scan')
import unicorn  # noqa
from unicorn.arm64_const import (UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2,
                                 UC_ARM64_REG_X3, UC_ARM64_REG_LR)
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa

K = b'X8TEUA3DEXZNW2TN'
IV = K[::-1]
PT = bytes.fromhex('00000000000000000000000000000000')

o = EOracle()
uc = o.s.e.uc

TBL = 0x2cd8b0
ent = []
RETS = {}


def code_cb(uc_, addr, size, ud):
    off = addr - DEV_BASE
    if off == TBL and len(ent) < 64:
        ent.append(tuple(uc_.reg_read(r) for r in (UC_ARM64_REG_X0, UC_ARM64_REG_X1,
                                                   UC_ARM64_REG_X2, UC_ARM64_REG_X3,
                                                   UC_ARM64_REG_LR)))


uc.hook_add(unicorn.UC_HOOK_CODE, code_cb, begin=DEV_BASE + TBL, end=DEV_BASE + TBL + 4)
out = o.enc(PT, K, IV)
print('out', out.hex())
print('0x2cd8b0 entries:', len(ent))
seen = set()
for i, (x0, x1, x2, x3, lr) in enumerate(ent):
    print('#%d x0=%#x x1=%#x x2=%#x x3=%#x lr=%#x' % (i, x0, x1, x2, x3, lr - DEV_BASE))
    for nm, a in (('x0', x0), ('x1', x1)):
        if a not in seen:
            seen.add(a)
            try:
                d = bytes(uc.mem_read(a, 256))
                print('   %s@%#x = %s' % (nm, a, d.hex()))
            except Exception as ex:
                print('   %s read err %s' % (nm, ex))
