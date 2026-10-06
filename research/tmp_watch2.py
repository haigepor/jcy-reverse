# -*- coding: utf-8 -*-
"""tmp_watch2.py — 从头记录状态缓冲的所有写，并标注驱动调用，定位 tweak 注入。"""
import os, sys, struct
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

events = []   # ('wr', pc, addr, size, val) / ('drv', lr, n)
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
print('events', len(events))
for e in events[:400]:
    if e[0] == 'drv':
        print('---- DRV call #%d  lr=%#x' % (e[2], e[1]))
    else:
        print('   wr pc=%#x addr=%#x sz=%d val=%#x' % (e[1], e[2], e[3], e[4]))
