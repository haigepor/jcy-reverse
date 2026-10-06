# -*- coding: utf-8 -*-
"""tmp_watch4.py — 在每次驱动调用点打印状态缓冲内容，判定 x_b 是否为 T 变换后的形式。"""
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_LR  # noqa
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa
sys.path.insert(0, HERE)
import tmp_verify_decrypt as V  # noqa

A_DRV = DEV_BASE + 0x2da498
LO, HI = 0x50004f00, 0x50005200
o = EOracle()
uc = o.s.e.uc
rd = o.s.e.rd
X = lambda a, b: bytes(x ^ y for x, y in zip(a, b))
Tb = lambda b: bytes(V.T(list(b)))

ROWS = [0x50005030, 0x50005070, 0x500050b0, 0x500050f0]
base = 0x50005030
buf = bytearray(0x200)
events = []
drv = {'n': 0}


def on_code(uc_, address, size, ud):
    drv['n'] += 1
    events.append(('drv', uc_.reg_read(UC_ARM64_REG_LR) - DEV_BASE, drv['n']))


def on_wr(uc_, access, address, size, value, ud):
    if LO <= address <= HI:
        events.append(('wr', uc_.reg_read(UC_ARM64_REG_PC) - DEV_BASE, address, size, value))


uc.hook_add(unicorn.UC_HOOK_CODE, on_code, begin=A_DRV, end=A_DRV + 4)
uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, on_wr)

K = b'X8TEUA3DEXZNW2TN'
pt = bytes([0x10 + i for i in range(3) for _ in range(16)])
ct = o.enc(pt, K, bytes(16))
print('ct', ct.hex())
CONST1 = bytes.fromhex('52f4c36b5f665eaafdb1cb79065d7df5')
pt1, ct0 = pt[16:32], ct[0:16]
x1 = X(X(pt1, ct0), CONST1)
tgt = {'T(x1)': Tb(x1), 'x1': x1, 'T(CONST1)': Tb(CONST1), 'CONST1': CONST1,
       'T(pt1^ct0)': Tb(X(pt1, ct0))}


def snap():
    return b''.join(bytes(buf[r - base:r - base + 4]) for r in ROWS)


for i, e in enumerate(events):
    if e[0] == 'drv':
        s = snap()
        marks = [k for k, v in tgt.items() if v == s]
        print('#%-3d DRV n=%d lr=%#x  snap=%s %s' % (i, e[2], e[1], s.hex(), marks))
    else:
        off = e[2] - base
        if 0 <= off and off + e[3] <= len(buf):
            buf[off:off + e[3]] = e[4].to_bytes(e[3], 'little')
