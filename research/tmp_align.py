# -*- coding: utf-8 -*-
"""tmp_align.py — iv=0 隔离单块, 确定 SubBytes 分组与 E 输入。"""
import sys
from collections import Counter
sys.path.insert(0, 'research/captures/rsa_scan')
import unicorn  # noqa
from e_oracle import EOracle  # noqa

K = b'X8TEUA3DEXZNW2TN'
PT = bytes.fromhex('00000000000000000000000000000000')
Z = b'\x00' * 16

o = EOracle()
uc = o.s.e.uc
idx = []


def mem_cb(uc_, access, address, size, value, ud):
    if access == unicorn.UC_MEM_READ:
        idx.append(address - 0x737e41c38960)


uc.hook_add(unicorn.UC_HOOK_MEM_READ, mem_cb, begin=0x737e41c38960, end=0x737e41c38960 + 255)
out = o.enc(PT, K, Z)
print('out', out.hex())
print('total idx:', len(idx))
ck = Counter(K)
c0 = Counter(bytes(16))
sub = idx[40:]
print('subbytes reads:', len(sub))
for g in range(len(sub) // 16):
    grp = sub[g*16:(g+1)*16]
    cg = Counter(grp)
    tag = ''
    if cg == ck:
        tag = ' == K16'
    elif cg == c0:
        tag = ' == ZERO'
    print('grp%02d %s%s' % (g, ' '.join('%02x' % x for x in grp), tag))
