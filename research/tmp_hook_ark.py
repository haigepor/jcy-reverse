# -*- coding: utf-8 -*-
"""tmp_hook_ark.py — hook AddRoundKey 0x2d52e0, dump (state, rk) 每次调用。
state 容器: base=rd_u64(x0); row_i=rd_u64(base+i*24); byte=rd(row_i,4)
rk 对象: data=rd_u64(x1); 16 字节。
"""
import os, sys, json, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_LR
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa
sys.path.insert(0, HERE)
import tmp_verify_decrypt as V  # noqa

ADDR_ARK = DEV_BASE + 0x2d52e0
Z = bytes(16)
o = EOracle()
uc = o.s.e.uc
rd = o.s.e.rd


def u64(a):
    return struct.unpack('<Q', rd(a, 8))[0]


def st16(c):
    out = bytearray()
    base = u64(c)
    for i in range(4):
        row = u64(base + i * 24)
        out += rd(row, 4)
    return bytes(out)


calls = []


def cb(uc_, address, size, ud):
    x0 = uc_.reg_read(UC_ARM64_REG_X0)
    x1 = uc_.reg_read(UC_ARM64_REG_X1)
    lr = uc_.reg_read(UC_ARM64_REG_LR)
    try:
        s = st16(x0)
    except Exception:
        s = b'?'
    try:
        k = rd(u64(x1), 16)
    except Exception:
        k = b'?'
    calls.append((lr - DEV_BASE, s, k))


uc.hook_add(unicorn.UC_HOOK_CODE, cb, begin=ADDR_ARK, end=ADDR_ARK + 4)

K = b'X8TEUA3DEXZNW2TN'
P = bytes([0x11] * 16)
Q = bytes([0x22] * 16)
R = bytes([0x33] * 16)
calls.clear()
ct = o.enc(P + Q + R, K, Z)
print('ct', ct.hex())
print('n calls', len(calls))
for i, (lr, s, k) in enumerate(calls):
    print('#%2d lr=%#x state=%s rk=%s' % (i, lr, s.hex(), k.hex()))
