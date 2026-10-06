# -*- coding: utf-8 -*-
"""tmp_watch3.py — 记录状态缓冲写事件，重建缓冲内容，定位 x_b / CONST_b 形成点。"""
import os, sys, struct, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from unicorn.arm64_const import UC_ARM64_REG_X1, UC_ARM64_REG_PC, UC_ARM64_REG_LR  # noqa
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa

A_DRV = DEV_BASE + 0x2da498
LO, HI = 0x50004f00, 0x50005200
o = EOracle()
uc = o.s.e.uc
rd = o.s.e.rd
u64 = lambda a: struct.unpack('<Q', rd(a, 8))[0]
X = lambda a, b: bytes(x ^ y for x, y in zip(a, b))

ROWS = [0x50005030, 0x50005070, 0x500050b0, 0x500050f0]
events = []
drv = {'n': 0}


def on_code(uc_, address, size, ud):
    drv['n'] += 1
    events.append(['drv', uc_.reg_read(UC_ARM64_REG_LR) - DEV_BASE, drv['n']])


def on_wr(uc_, access, address, size, value, ud):
    if LO <= address <= HI:
        events.append(['wr', uc_.reg_read(UC_ARM64_REG_PC) - DEV_BASE, address, size, value])


uc.hook_add(unicorn.UC_HOOK_CODE, on_code, begin=A_DRV, end=A_DRV + 4)
uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, on_wr)

K = b'X8TEUA3DEXZNW2TN'
pt = bytes([0x10 + i for i in range(3) for _ in range(16)])
ct = o.enc(pt, K, bytes(16))
print('ct', ct.hex())

# 已知值
CONST1 = bytes.fromhex('52f4c36b5f665eaafdb1cb79065d7df5')
pt1 = pt[16:32]
ct0 = ct[0:16]
x1 = X(X(pt1, ct0), CONST1)
print('pt1^ct0', X(pt1, ct0).hex())
print('x1     ', x1.hex())
print('CONST1 ', CONST1.hex())

# 重建
buf = bytearray(0x200 - 0x30)  # 覆盖 0x50005030..0x50005230
base = 0x50005030


def snap():
    return bytes(buf[r - base:r - base + 4] for r in ROWS) if False else \
        b''.join(bytes(buf[r - base:r - base + 4]) for r in ROWS)


def find(target, label):
    hits = []
    buf[:] = bytes(len(buf))
    for i, e in enumerate(events):
        if e[0] != 'wr':
            continue
        off = e[2] - base
        if off < 0 or off + e[3] > len(buf):
            continue
        buf[off:off + e[3]] = e[4].to_bytes(e[3], 'little')
        if snap() == target:
            hits.append((i, e[1]))
    return hits


for tgt, lab in [(X(pt1, ct0), 'pt1^ct0'), (CONST1, 'CONST1'), (x1, 'x1')]:
    print(lab, 'hits:', find(tgt, lab)[:10])
