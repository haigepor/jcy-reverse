# -*- coding: utf-8 -*-
"""tmp_trace_pc.py - 单块 E_b 加密的 PC 热力图 + 序列, 定位密码核心循环."""
import sys
from collections import Counter

sys.path.insert(0, 'research/captures/rsa_scan')
import unicorn  # noqa
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa

K = b'X8TEUA3DEXZNW2TN'
IV = K[::-1]
PT = bytes.fromhex('00000000000000000000000000000000')

o = EOracle()
uc = o.s.e.uc

hist = Counter()
seq = []
LO, HI = 0x2b0000, 0x320000


def cb(uc_, addr, size, ud):
    off = addr - DEV_BASE
    hist[off] += 1
    if len(seq) < 40000:
        seq.append(off)


uc.hook_add(unicorn.UC_HOOK_CODE, cb, begin=DEV_BASE + LO, end=DEV_BASE + HI)
out = o.enc(PT, K, IV)
print('out', out.hex())
print('total instr in [0x%x,0x%x): %d' % (LO, HI, sum(hist.values())))
print('distinct PCs:', len(hist))
print('--- top 40 hot PCs ---')
for off, n in hist.most_common(40):
    print('  0x%06x  %d' % (off, n))
print('--- first 120 PCs ---')
print(' '.join('%x' % a for a in seq[:120]))
