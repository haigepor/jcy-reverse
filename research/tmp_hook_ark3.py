# -*- coding: utf-8 -*-
"""tmp_hook_ark3.py — 正确访问器: 4 行 × 4 字节 (行指针数组, 8B 步长)。
dump 每次 ARK 的 (state_before, rk)。"""
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_LR
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa

ADDR_ARK = DEV_BASE + 0x2d52e0
Z = bytes(16)
o = EOracle()
uc = o.s.e.uc
rd = o.s.e.rd
u64 = lambda a: struct.unpack('<Q', rd(a, 8))[0]


def rows(x):
    out = bytearray()
    for i in range(4):
        p = u64(x + i * 8)
        out += rd(p, 4)
    return bytes(out)


calls = []


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
    calls.append((lr, s, k))


uc.hook_add(unicorn.UC_HOOK_CODE, cb, begin=ADDR_ARK, end=ADDR_ARK + 4)

K = b'X8TEUA3DEXZNW2TN'
P = bytes([0x11] * 16)
Q = bytes([0x22] * 16)
R = bytes([0x33] * 16)
calls.clear()
ct = o.enc(P + Q + R, K, Z)
print('ct', ct.hex())
print('n calls', len(calls))
seen = 0
for i, (lr, s, k) in enumerate(calls):
    if i % 2 == 0:      # 每次 ARK 触发两次, 取第一次
        print('#%2d lr=%#x state=%s rk=%s' % (i, lr, s.hex(), k.hex()))
        seen += 1
    if seen > 14:
        break
print()
print('期望块0: T(P)=11111111111111111111111111111111  rk0=K=583854455541334445585a4e5732544e')
