# -*- coding: utf-8 -*-
"""tmp_stateptr.py — 钩 0x2d213c(strb 回写), 找到 16 字节状态缓冲地址与写序。"""
import sys
sys.path.insert(0, 'research/captures/rsa_scan')
import unicorn  # noqa
from unicorn.arm64_const import UC_ARM64_REG_X0
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa

K = b'X8TEUA3DEXZNW2TN'
IV = K[::-1]
PT = bytes.fromhex('00000000000000000000000000000000')

o = EOracle()
uc = o.s.e.uc
stores = []


def code_cb(uc_, addr, size, ud):
    stores.append(uc_.reg_read(UC_ARM64_REG_X0))


uc.hook_add(unicorn.UC_HOOK_CODE, code_cb, begin=DEV_BASE + 0x2d213c, end=DEV_BASE + 0x2d213c + 4)
out = o.enc(PT, K, IV)
print('out', out.hex())
print('stores:', len(stores))
# 分组: 每 16 个一组(一轮)
print('--- 前 4 组的写地址 (低 4 位 hex) ---')
for g in range(4):
    grp = stores[g*16:(g+1)*16]
    print('grp%d base~%#x offs=%s' % (g, grp[0] if grp else 0,
          ' '.join('%x' % (a - min(grp)) for a in grp)))
# 找出公共基址
if stores:
    bases = sorted(set(a & ~0xf for a in stores))
    print('distinct 16B-aligned bases:', ['%#x' % b for b in bases[:8]], '... total', len(bases))
