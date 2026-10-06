# -*- coding: utf-8 -*-
"""tmp_count.py — 诊断: 不同块数下轮驱动被调用次数。"""
import os, sys, struct, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from unicorn.arm64_const import UC_ARM64_REG_X1  # noqa
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa

A_DRV = DEV_BASE + 0x2da498
o = EOracle()
uc = o.s.e.uc
u64 = lambda a: struct.unpack('<Q', o.s.e.rd(a, 8))[0]
cap = []


def rows24(x):
    b = u64(x)
    return b''.join(o.s.e.rd(u64(b + i * 24), 4) for i in range(4))


def cb(uc_, address, size, ud):
    cap.append(rows24(uc_.reg_read(UC_ARM64_REG_X1)))


uc.hook_add(unicorn.UC_HOOK_CODE, cb, begin=A_DRV, end=A_DRV + 4)
K = b'X8TEUA3DEXZNW2TN'
for nblk in (1, 2, 3, 4, 5, 8, 13, 20, 40, 80):
    cap.clear()
    t = time.time()
    try:
        ct = o.enc(bytes(16 * nblk), K, K[::-1])
        print('nblk=%-4d captured=%-5d ratio=%.2f  ct_len=%d  %.1fs' % (
            nblk, len(cap), len(cap) / nblk, len(ct), time.time() - t))
    except Exception as ex:
        print('nblk=%d ERR %s' % (nblk, ex))
