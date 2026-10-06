# -*- coding: utf-8 -*-
"""tmp_watch5.py — 全局内存写追踪，搜索 x_1 / T(x_1) / CONST_1 等目标的落点。"""
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from unicorn.arm64_const import UC_ARM64_REG_PC  # noqa
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa
sys.path.insert(0, HERE)
import tmp_verify_decrypt as V  # noqa

o = EOracle()
uc = o.s.e.uc
X = lambda a, b: bytes(x ^ y for x, y in zip(a, b))
Tb = lambda b: bytes(V.T(list(b)))
mem = {}
writes = []          # (pc, addr, size, value)
CAP = 400000


def on_wr(uc_, access, address, size, value, ud):
    if 0x50000000 <= address < 0x50200000:
        mem[address] = value
        for k in range(size):
            mem[address + k] = (value >> (8 * k)) & 0xff
        if len(writes) < CAP:
            writes.append((uc_.reg_read(UC_ARM64_REG_PC) - DEV_BASE, address, size, value))


def rd16(a):
    out = bytearray(16)
    for i in range(16):
        out[i] = mem.get(a + i, 0)
    return bytes(out)


uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, on_wr)

K = b'X8TEUA3DEXZNW2TN'
pt = bytes([0x10 + i for i in range(3) for _ in range(16)])
ct = o.enc(pt, K, bytes(16))
print('ct', ct.hex())
CONST1 = bytes.fromhex('52f4c36b5f665eaafdb1cb79065d7df5')
pt1, ct0 = pt[16:32], ct[0:16]
x0 = X(pt[0:16], K[::-1])
x1 = X(X(pt1, ct0), CONST1)
targets = {'x0': x0, 'T(x0)': Tb(x0), 'pt1^ct0': X(pt1, ct0), 'T(pt1^ct0)': Tb(X(pt1, ct0)),
           'x1': x1, 'T(x1)': Tb(x1), 'CONST1': CONST1, 'T(CONST1)': Tb(CONST1),
           'ct0': ct0, 'T(ct0)': Tb(ct0)}
tvals = {v: k for k, v in targets.items()}
hits = []
for pc, addr, size, val in writes:
    for a in (addr, addr - 4, addr - 8, addr - 12, addr - 16):
        w = rd16(a)
        if w in tvals:
            hits.append((pc, a, tvals[w], w.hex()))
print('hits', len(hits))
for pc, a, nm, hx in hits[:60]:
    print('  pc=%#x addr=%#x  %s  %s' % (pc, a, nm, hx))
