# -*- coding: utf-8 -*-
"""tmp_outwrite.py — 钩堆区写, 定位密文写入 PC; 并钩轮密钥区读, 看末轮读哪个密钥。"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from e_oracle import EOracle  # noqa

K = b'X8TEUA3DEXZNW2TN'
Z = bytes(16)
CT0 = bytes.fromhex('60beb57743b3efefa1ada0e71ccc1d57')

o = EOracle()
uc = o.s.e.uc
writes = []
kreads = []


def wcb(uc_, access, address, size, value, ud):
    if 0x50000000 <= address < 0x50010000 and size >= 4:
        try:
            data = bytes(uc_.mem_read(address, size))
        except Exception:
            return
        if CT0[:4] in data or CT0[8:12] in data or CT0[4:8] in data:
            writes.append((uc_.reg_read(unicorn.arm64_const.UC_ARM64_REG_PC), address, size, data[:16].hex()))


def rcb(uc_, access, address, size, value, ud):
    if 0x50001700 <= address < 0x50003000:
        kreads.append((uc_.reg_read(unicorn.arm64_const.UC_ARM64_REG_PC), address, size))


uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, wcb)
uc.hook_add(unicorn.UC_HOOK_MEM_READ, rcb, begin=0x50001700, end=0x50003000)
out = o.enc(bytes(16), K, Z)
print('out =', out.hex())
print('--- 命中密文的写 ---')
for w in writes[:20]:
    print('  pc=%#x addr=%#x size=%d %s' % w)
print('--- 轮密钥区读 (前40) ---')
seen = set()
for r in kreads:
    key = (r[0], r[1])
    if key in seen:
        continue
    seen.add(key)
    print('  pc=%#x addr=%#x size=%d' % r)
    if len(seen) > 40:
        break
