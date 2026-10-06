# -*- coding: utf-8 -*-
"""tmp_sbox_reads.py — 钩 AES S 盒读, 定位 SubBytes 函数与代换模式。"""
import sys
from collections import Counter
sys.path.insert(0, 'research/captures/rsa_scan')
import unicorn  # noqa
from unicorn.arm64_const import UC_ARM64_REG_PC
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa

K = b'X8TEUA3DEXZNW2TN'
IV = K[::-1]
PT = bytes.fromhex('00000000000000000000000000000000')

o = EOracle()
uc = o.s.e.uc

TABLES = [(0x6ff99394, 'T1'), (0x737e41c38960, 'T2')]
reads = []
pcc = Counter()


def mem_cb(uc_, access, address, size, value, ud):
    if access != unicorn.UC_MEM_READ:
        return
    for base, nm in TABLES:
        if base <= address < base + 256:
            pc = uc_.reg_read(UC_ARM64_REG_PC) - DEV_BASE
            reads.append((nm, pc, address - base, value))
            pcc[pc] += 1
            return


for base, _ in TABLES:
    uc.hook_add(unicorn.UC_HOOK_MEM_READ, mem_cb, begin=base, end=base + 255)
out = o.enc(PT, K, IV)
print('out', out.hex())
print('sbox reads total:', len(reads))
print('distinct pcs:', len(pcc))
print('--- pc counts ---')
for pc, n in pcc.most_common(20):
    print('  0x%06x  %d' % (pc, n))
print('--- first 50 reads (tbl, pc, idx, val) ---')
for nm, pc, idx, val in reads[:50]:
    print('  %s pc=0x%06x idx=%3d(0x%02x) val=0x%02x' % (nm, pc, idx, idx, val))
