# -*- coding: utf-8 -*-
"""tmp_sbox_pc.py — 记录 S 盒读的 PC, 定位末轮后处理代码; 并记录输出区写。"""
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
reads = []
writes = []


def rcb(uc_, access, address, size, value, ud):
    if access == unicorn.UC_MEM_READ and BASE <= address <= BASE + 255:
        reads.append((uc_.reg_read(unicorn.arm64_const.UC_ARM64_REG_PC), address - BASE))


def wcb(uc_, access, address, size, value, ud):
    if 0x50005000 <= address < 0x50006000:
        writes.append((uc_.reg_read(unicorn.arm64_const.UC_ARM64_REG_PC), address, size))


uc.hook_add(unicorn.UC_HOOK_MEM_READ, rcb, begin=BASE, end=BASE + 255)
uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, wcb, begin=0x50005000, end=0x50006000)
out = o.enc(bytes(16), K, Z)
print('out =', out.hex())
print('S盒读总数', len(reads))
# 打印每 16 个一组的 PC 代表
print('--- 每 16 读一组 (轮) 的 PC 集合 ---')
for g in range(len(reads)//16):
    pcs = sorted(set(hex(p) for p, i in reads[g*16:(g+1)*16]))
    print('  g%-2d %s' % (g, pcs[:4]))
print('--- 输出区写 ---')
for w in writes[:30]:
    print('  pc=%#x addr=%#x size=%d' % w)
