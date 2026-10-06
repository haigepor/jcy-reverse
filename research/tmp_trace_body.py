# -*- coding: utf-8 -*-
"""tmp_trace_body.py — 记录 E 体 (0x2d6f78..0x2d7700) 实际执行的指令地址序列。"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa

LO, HI = 0x2d6f78, 0x2d7720
Z = bytes(16)
o = EOracle()
uc = o.s.e.uc
seq = []


def cb(uc_, address, size, ud):
    seq.append(address - DEV_BASE)


uc.hook_add(unicorn.UC_HOOK_CODE, cb, begin=DEV_BASE + LO, end=DEV_BASE + HI)

K = b'X8TEUA3DEXZNW2TN'
ct = o.enc(bytes([0x11] * 16) + bytes([0x22] * 16), K, Z)
print('ct', ct.hex())
print('executed instrs in E body:', len(seq))

# 压缩成 runs
runs = []
for a in seq:
    if runs and a == runs[-1][1] + 4:
        runs[-1][1] = a
    else:
        runs.append([a, a])
print('runs:', len(runs))
for i, (a, b) in enumerate(runs):
    print('#%3d  %#x - %#x  (%d)' % (i, a, b, (b - a) // 4 + 1))
