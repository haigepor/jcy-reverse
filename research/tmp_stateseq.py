# -*- coding: utf-8 -*-
"""tmp_stateseq.py — 采集 SubBytes 读点 0x2d20a8 的状态字节序列 (每字节读两次),
按 SubBytes 调用(32 读)切分, 去交错得到 16 字节 state, 落盘供离线分析。
"""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from unicorn.arm64_const import UC_ARM64_REG_X0
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa
sys.path.insert(0, HERE)
import tmp_verify_decrypt as V  # noqa

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

P = bytes([0x11] * 16)
Q = bytes([0x22] * 16)
R = bytes([0x33] * 16)
seq.clear()
ct = o.enc(P + Q + R, K, Z)
json.dump({'seq': seq, 'ct': ct.hex(), 'P': P.hex(), 'Q': Q.hex(), 'R': R.hex()},
          open(os.path.join(HERE, 'tmp_stateseq.json'), 'w'))
print('nreads', len(seq), 'ct', ct.hex())

# 去交错: 每个 SubBytes 调用 32 读 = 16 字节 × 2
sb = [bytes(seq[i:i + 32][0::2]) for i in range(0, len(seq) - len(seq) % 32, 32)]
print('n SubBytes calls =', len(sb))
for i, g in enumerate(sb):
    print('  SB[%2d] = %s' % (i, g.hex()))

T = lambda b: bytes(V.T(list(b)))
X = V.xr
print()
print('T(P)^K =', X(T(P), K).hex())
print('T(Q)^K =', X(T(Q), K).hex())
print('T(R)^K =', X(T(R), K).hex())
print('ct0=%s ct1=%s ct2=%s' % (ct[0:16].hex(), ct[16:32].hex(), ct[32:48].hex()))
for i, g in enumerate(sb):
    for nm, v in (('T(P)^K', X(T(P), K)), ('T(Q)^K', X(T(Q), K)),
                  ('T(R)^K', X(T(R), K)), ('ct0', ct[0:16]), ('ct1', ct[16:32])):
        if g == v:
            print('  命中 SB[%d] == %s' % (i, nm))
