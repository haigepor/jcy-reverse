# -*- coding: utf-8 -*-
"""tmp_hook_ark4.py — 正确访问器读 ARK 的 (state, rk):
  obj → 4 个行对象指针(8B步长) → 每个行对象的 data 指针 → 4 字节
"""
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_LR
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa
sys.path.insert(0, HERE)
import tmp_verify_decrypt as V  # noqa

A_ARK = DEV_BASE + 0x2d52e0
Z = bytes(16)
o = EOracle()
uc = o.s.e.uc
rd = o.s.e.rd
u64 = lambda a: struct.unpack('<Q', rd(a, 8))[0]


def rows(x):
    out = bytearray()
    for i in range(4):
        out += rd(u64(u64(x + i * 8)), 4)
    return bytes(out)


recs = []


def cb(uc_, address, size, ud):
    x0 = uc_.reg_read(UC_ARM64_REG_X0)
    x1 = uc_.reg_read(UC_ARM64_REG_X1)
    lr = uc_.reg_read(UC_ARM64_REG_LR) - DEV_BASE
    try:
        s = rows(x0)
    except Exception:
        s = b'?'
    try:
        k = rows(x1)
    except Exception:
        k = b'?'
    recs.append((lr, s, k))


uc.hook_add(unicorn.UC_HOOK_CODE, cb, begin=A_ARK, end=A_ARK + 4)

K = b'X8TEUA3DEXZNW2TN'
P = bytes([0x11] * 16)
Q = bytes([0x22] * 16)
R = bytes([0x33] * 16)
recs.clear()
ct = o.enc(P + Q + R, K, Z)
print('ct', ct.hex())
print('K =', K.hex())
print('n', len(recs))
seen = 0
for i, (lr, s, k) in enumerate(recs):
    if i % 2:
        continue
    print('#%2d lr=%#x state=%s rk=%s' % (i, lr, s.hex(), k.hex()))
    seen += 1
    if seen >= 16:
        break
