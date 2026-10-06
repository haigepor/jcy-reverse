# -*- coding: utf-8 -*-
"""tmp_cap_full.py — 采集完整 S 盒索引序列并落盘 (含 grp0 校验)。"""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from e_oracle import EOracle  # noqa

K = b'X8TEUA3DEXZNW2TN'
Z = b'\x00' * 16
BASE = 0x737e41c38960

o = EOracle()
uc = o.s.e.uc
cur = {'idx': []}


def mem_cb(uc_, access, address, size, value, ud):
    if access == unicorn.UC_MEM_READ and BASE <= address <= BASE + 255:
        cur['idx'].append(address - BASE)


uc.hook_add(unicorn.UC_HOOK_MEM_READ, mem_cb, begin=BASE, end=BASE + 255)

pts = [bytes(16), bytes([0x10]*16), bytes(range(16)), bytes([0xff]*16),
       bytes([0x5a]*16), bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])]
recs = []
for pt in pts:
    cur['idx'] = []
    out = o.enc(pt, K, Z)
    idx = cur['idx'][:]
    recs.append({'pt': pt.hex(), 'ct': out.hex(), 'idx': idx})
    grp0 = bytes(idx[40:56])
    print('pt=%s nidx=%d grp0^K=%s  ==pt?%s' % (
        pt.hex(), len(idx),
        bytes(a ^ b for a, b in zip(grp0, K)).hex(),
        bytes(a ^ b for a, b in zip(grp0, K)) == pt))
json.dump(recs, open(os.path.join(HERE, 'tmp_full_caps.json'), 'w'))
print('saved tmp_full_caps.json')
