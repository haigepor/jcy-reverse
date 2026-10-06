# -*- coding: utf-8 -*-
"""tmp_hookstate.py — 直接 hook 轮驱动 0x2da498, dump 每块进入 ARK0 前的 16 字节状态。

目的: 判定"块1的加密输入"到底是什么 (CBC 的 pt^ct0? 还是别的)。
"""
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from unicorn.arm64_const import UC_ARM64_REG_X0, UC_ARM64_REG_LR
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa
sys.path.insert(0, HERE)
import tmp_verify_decrypt as V  # noqa

ADDR_ROUNDDRV = DEV_BASE + 0x2da498
K = b'X8TEUA3DEXZNW2TN'
Z = bytes(16)

o = EOracle()
uc = o.s.e.uc


def rd_u64(a):
    return struct.unpack('<Q', o.s.e.rd(a, 8))[0]


def state_bytes(container):
    out = bytearray()
    base = rd_u64(container)
    for i in range(4):
        row = rd_u64(base + i * 24)
        out += o.s.e.rd(row, 4)
    return bytes(out)


calls = []


def cb(uc_, address, size, ud):
    x0 = uc_.reg_read(UC_ARM64_REG_X0)
    lr = uc_.reg_read(UC_ARM64_REG_LR)
    try:
        st = state_bytes(x0)
    except Exception as ex:
        st = b'ERR:' + str(ex).encode()
    calls.append((x0, lr, st))


uc.hook_add(unicorn.UC_HOOK_CODE, cb, begin=ADDR_ROUNDDRV, end=ADDR_ROUNDDRV + 4)

P = bytes([0x11] * 16)
Q = bytes([0x22] * 16)
R = bytes([0x33] * 16)
calls.clear()
ct = o.enc(P + Q + R, K, Z)
print('ct len', len(ct))
print('ct', ct.hex())
print('nrounddrv calls =', len(calls))
for i, (x0, lr, st) in enumerate(calls):
    print('  #%d x0=%#x lr=%#x state=%s' % (i, x0, lr - DEV_BASE, st.hex()))

T = lambda b: bytes(V.T(list(b)))
X = V.xr
print()
print('T(P)      =', T(P).hex())
print('T(P)^K    =', X(T(P), K).hex())
print('T(Q)      =', T(Q).hex())
print('T(Q)^K    =', X(T(Q), K).hex())
print('ct0       =', ct[0:16].hex())
print('T(Q^ct0)  =', T(X(Q, ct[0:16])).hex())
print('T(Q^ct0)^K=', X(T(X(Q, ct[0:16])), K).hex())
print('T(R)      =', T(R).hex())
print('ct1       =', ct[16:32].hex())
print('T(R^ct1)  =', T(X(R, ct[16:32])).hex())
print('T(R^ct1)^K=', X(T(X(R, ct[16:32])), K).hex())
