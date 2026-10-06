# -*- coding: utf-8 -*-
"""tmp_idx_analyze.py — 全部 S 盒索引序列, 按 16 分组, 多重集对比标准 AES 轮状态。"""
import sys
sys.path.insert(0, 'research/captures/rsa_scan')
import unicorn  # noqa
from unicorn.arm64_const import UC_ARM64_REG_PC
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa

K = b'X8TEUA3DEXZNW2TN'
IV = K[::-1]
PT = bytes.fromhex('00000000000000000000000000000000')
SO = open('research/artifacts/libcore.so', 'rb').read()
SBOX = SO[0x1dfc00:0x1dfc00 + 256]

o = EOracle()
uc = o.s.e.uc
idx = []


def mem_cb(uc_, access, address, size, value, ud):
    if access == unicorn.UC_MEM_READ:
        idx.append(address - 0x737e41c38960)


uc.hook_add(unicorn.UC_HOOK_MEM_READ, mem_cb, begin=0x737e41c38960, end=0x737e41c38960 + 255)
out = o.enc(PT, K, IV)
print('out', out.hex())
print('total idx reads:', len(idx))
# 标准 AES: state0 = IV ^ K (AddRoundKey first)
st0 = bytes(a ^ b for a, b in zip(IV, K))
print('state0(IV^K):', st0.hex())
from collections import Counter
c0 = Counter(st0)
# 打印前 40 组
for g in range(0, min(len(idx) // 16, 40)):
    grp = idx[g*16:(g+1)*16]
    cg = Counter(grp)
    mark = ' == state0!' if cg == c0 else ''
    print('grp%02d %s%s' % (g, ' '.join('%02x' % x for x in grp), mark))
