# -*- coding: utf-8 -*-
"""tmp_tail_pc.py — 记录最后一次 S 盒读之后的 PC 序列 (末轮收尾代码)。"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from e_oracle import EOracle  # noqa

K = b'X8TEUA3DEXZNW2TN'
Z = bytes(16)
BASE = 0x737e41c38960

o = EOracle()
uc = o.s.e.uc
st = {'nread': 0, 'rec': False, 'pcs': [], 'last_read_pc': 0}


def rcb(uc_, access, address, size, value, ud):
    if access == unicorn.UC_MEM_READ and BASE <= address <= BASE + 255:
        st['nread'] += 1
        st['last_read_pc'] = uc_.reg_read(unicorn.arm64_const.UC_ARM64_REG_PC)
        if st['nread'] >= 360:
            st['rec'] = True
            st['pcs'] = []


def ccb(uc_, address, size, ud):
    if st['rec'] and len(st['pcs']) < 400:
        st['pcs'].append(address)


uc.hook_add(unicorn.UC_HOOK_MEM_READ, rcb, begin=BASE, end=BASE + 255)
uc.hook_add(unicorn.UC_HOOK_CODE, ccb)
out = o.enc(bytes(16), K, Z)
print('out =', out.hex())
print('total reads', st['nread'], 'last_read_pc', hex(st['last_read_pc']))
print('--- 末轮收尾 PC 序列 (前 200) ---')
for a in st['pcs'][:200]:
    print('  %#x' % a)
