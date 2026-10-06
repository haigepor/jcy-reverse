# -*- coding: utf-8 -*-
"""tmp_watch.py — 追踪轮驱动输入缓冲(x_b)的内存写序列，定位 tweak 注入点。"""
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from unicorn.arm64_const import UC_ARM64_REG_X1, UC_ARM64_REG_PC  # noqa
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa

A_DRV = DEV_BASE + 0x2da498
o = EOracle()
uc = o.s.e.uc
rd = o.s.e.rd
u64 = lambda a: struct.unpack('<Q', rd(a, 8))[0]

st = {'rows': [], 'seen0': False, 'log': [], 'n': 0}


def on_drv(uc_, address, size, ud):
    st['n'] += 1
    if st['n'] == 1:
        x1 = uc_.reg_read(UC_ARM64_REG_X1)
        b = u64(x1)
        st['rows'] = [u64(b + i * 24) for i in range(4)]
        st['lo'] = min(st['rows']) - 64
        st['hi'] = max(st['rows']) + 64
        print('rows=', [hex(r) for r in st['rows']], 'win=[%#x,%#x]' % (st['lo'], st['hi']))


def on_wr(uc_, access, address, size, value, ud):
    if st['rows'] and st['lo'] <= address <= st['hi']:
        st['log'].append((uc_.reg_read(UC_ARM64_REG_PC) - DEV_BASE, address, size, value))


uc.hook_add(unicorn.UC_HOOK_CODE, on_drv, begin=A_DRV, end=A_DRV + 4)
uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, on_wr)

K = b'X8TEUA3DEXZNW2TN'
pt = bytes([0x10 + i for i in range(3) for _ in range(16)])
ct = o.enc(pt, K, bytes(16))
print('ct', ct.hex())
print('driver calls:', st['n'], ' writes logged:', len(st['log']))
for pc, addr, size, val in st['log'][:200]:
    print('pc=%#x  wr %#x sz=%d val=%#x' % (pc, addr, size, val))
