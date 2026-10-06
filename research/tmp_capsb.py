# -*- coding: utf-8 -*-
"""tmp_capsb.py — 批量采集 SubBytes 状态序列 (多组测试向量), 落盘离线分析。"""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from unicorn.arm64_const import UC_ARM64_REG_X0
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa

PC_RD = DEV_BASE + 0x2d20a8
K = b'X8TEUA3DEXZNW2TN'
Z = bytes(16)

o = EOracle()
uc = o.s.e.uc
rd = o.s.e.rd
seq = []


def cb(uc_, address, size, ud):
    seq.append(rd(uc_.reg_read(UC_ARM64_REG_X0), 1)[0])


uc.hook_add(unicorn.UC_HOOK_CODE, cb, begin=PC_RD, end=PC_RD + 4)

vecs = [
    ('zero2', bytes(32)),
    ('P11Q00', bytes([0x11] * 16) + bytes(16)),
    ('P00Q22', bytes(16) + bytes([0x22] * 16)),
    ('P11Q22', bytes([0x11] * 16) + bytes([0x22] * 16)),
    ('P11Q33', bytes([0x11] * 16) + bytes([0x33] * 16)),
    ('PaaQbb', bytes([0xaa] * 16) + bytes([0xbb] * 16)),
    ('P11Q22R33', bytes([0x11] * 16) + bytes([0x22] * 16) + bytes([0x33] * 16)),
    ('seq012', bytes(range(32))),
]
recs = []
for name, pt in vecs:
    seq.clear()
    ct = o.enc(pt, K, Z)
    sb = [bytes(seq[i:i + 32][0::2]) for i in range(0, len(seq) - len(seq) % 32, 32)]
    recs.append({'name': name, 'pt': pt.hex(), 'ct': ct.hex(),
                 'sb': [b.hex() for b in sb]})
    print('%s pt=%dB ct=%dB nsb=%d' % (name, len(pt), len(ct), len(sb)))
json.dump(recs, open(os.path.join(HERE, 'tmp_sbcaps.json'), 'w'))
print('saved tmp_sbcaps.json')
