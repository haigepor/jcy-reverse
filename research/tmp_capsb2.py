# -*- coding: utf-8 -*-
"""tmp_capsb2.py — 采集 3-4 块多组向量 (含第二密钥) 的 SB 轨迹, 提取每块的 prev_i。"""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from unicorn.arm64_const import UC_ARM64_REG_X0
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa

PC_RD = DEV_BASE + 0x2d20a8
Z = bytes(16)
K1 = b'X8TEUA3DEXZNW2TN'
K2 = b'ABCDEFGHIJKLMNOP'

o = EOracle()
uc = o.s.e.uc
rd = o.s.e.rd
seq = []


def cb(uc_, address, size, ud):
    seq.append(rd(uc_.reg_read(UC_ARM64_REG_X0), 1)[0])


uc.hook_add(unicorn.UC_HOOK_CODE, cb, begin=PC_RD, end=PC_RD + 4)

V = []
V.append(('K1_A', K1, bytes([0x11] * 16) + bytes([0x22] * 16) + bytes([0x33] * 16) + bytes([0x44] * 16)))
V.append(('K1_B', K1, bytes([0x11] * 16) + bytes([0xaa] * 16) + bytes([0xbb] * 16) + bytes([0xcc] * 16)))
V.append(('K1_C', K1, bytes(64)))
V.append(('K1_D', K1, bytes(range(64))))
V.append(('K1_E', K1, bytes([0x5a] * 16) + bytes(16) + bytes([0xff] * 16) + bytes([0x77] * 16)))
V.append(('K2_A', K2, bytes([0x11] * 16) + bytes([0x22] * 16) + bytes([0x33] * 16) + bytes([0x44] * 16)))
V.append(('K2_B', K2, bytes(64)))
V.append(('K2_C', K2, bytes(range(64))))

recs = []
for name, K, pt in V:
    seq.clear()
    ct = o.enc(pt, K, Z)
    sb = [bytes(seq[i:i + 32][0::2]) for i in range(0, len(seq) - len(seq) % 32, 32)]
    recs.append({'name': name, 'K': K.hex(), 'pt': pt.hex(), 'ct': ct.hex(),
                 'sb': [b.hex() for b in sb]})
    print('%s K=%s ct=%dB nsb=%d' % (name, K.decode(), len(ct), len(sb)))
json.dump(recs, open(os.path.join(HERE, 'tmp_sbcaps2.json'), 'w'))
print('saved')
