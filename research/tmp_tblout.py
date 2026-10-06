# -*- coding: utf-8 -*-
"""tmp_tblout.py — 在 0x2cd8b0 返回点转储其输出缓冲(自研 S-box 候选)。"""
import sys
sys.path.insert(0, 'research/captures/rsa_scan')
import unicorn  # noqa
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa

K = b'X8TEUA3DEXZNW2TN'
IV = K[::-1]
PT = bytes.fromhex('00000000000000000000000000000000')

AES = bytes.fromhex(
    '637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0'
    'b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275'
    '09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf'
    'd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2'
    'cd0c13ec5f974417c4a77e3e5d645d197360814fdc222a908846eeb814de5e0bd'
    'be0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08'
    'ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee'
    '1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16')

o = EOracle()
uc = o.s.e.uc
state = {'x1': None}
dumps = []

TBL = 0x2cd8b0
RET = 0x2cdf54


def code_cb(uc_, addr, size, ud):
    off = addr - DEV_BASE
    if off == TBL:
        state['x1'] = uc_.reg_read(UC_ARM64_REG_X1)
    elif off == RET and state['x1'] is not None:
        a = state['x1']
        try:
            d = bytes(uc_.mem_read(a, 256))
            dumps.append((a, d))
        except Exception as ex:
            dumps.append((a, b'ERR:%s' % str(ex).encode()))


uc.hook_add(unicorn.UC_HOOK_CODE, code_cb, begin=DEV_BASE + TBL, end=DEV_BASE + TBL + 4)
uc.hook_add(unicorn.UC_HOOK_CODE, code_cb, begin=DEV_BASE + RET, end=DEV_BASE + RET + 4)
out = o.enc(PT, K, IV)
print('out', out.hex())
print('dumps:', len(dumps))
for a, d in dumps[:6]:
    tag = 'AES' if d == AES else ('PERM' if len(set(d)) == 256 else 'np')
    print('@%#x %s' % (a, tag))
    print('   ', d.hex())
