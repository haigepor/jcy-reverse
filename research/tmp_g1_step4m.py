# -*- coding: utf-8 -*-
"""tmp_g1_step4m.py — 收割 GF 乘法调用：hook 0x2d2f20 入口/出口，验证 GF(2^8) 乘法假设。"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from unicorn.arm64_const import (  # noqa: E402
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X30, UC_ARM64_REG_PC,
)
from decrypt_e import EDecryptor  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

MUL = DEV_BASE + 0x2D2F20
PREP = DEV_BASE + 0x2D9AD4
K = bytes(range(0x30, 0x40))
NBLK = 2

d = EDecryptor()
d.calibrate(K, NBLK)
d._o = None
d._uc = None
d._oracle()
uc = d._uc

ctx = [None]
mem0 = []


def on_snap(uc_, address, size, ud):
    if ctx[0] is not None:
        return
    ctx[0] = uc_.context_save()
    for rbase, rend, _perms in uc_.mem_regions():
        sz = rend - rbase
        if sz > 64 * 1024 * 1024:
            continue
        try:
            mem0.append((rbase, sz, bytes(uc_.mem_read(rbase, sz))))
        except Exception:
            pass


h = uc.hook_add(unicorn.UC_HOOK_CODE, on_snap, begin=PREP, end=PREP + 3)
d._cap.clear()
d._enc_big(bytes(16 * NBLK), K, K[::-1])
uc.hook_del(h)

uc.context_restore(ctx[0])
for base, size, data in mem0:
    try:
        uc.mem_write(base, data)
    except Exception:
        pass
uc.ctl_flush_tb()

calls = []          # [(x0, w1, w2, lr_off)]
pending = [None]
N = [0]


def on_mul(uc_, address, size, ud):
    x0 = uc_.reg_read(UC_ARM64_REG_X0)
    x1 = uc_.reg_read(UC_ARM64_REG_X1)
    x2 = uc_.reg_read(UC_ARM64_REG_X2)
    x3 = uc_.reg_read(UC_ARM64_REG_X3)
    lr = uc_.reg_read(UC_ARM64_REG_X30)
    pending[0] = (x0, x1 & 0xFFFFFFFF, x2 & 0xFFFFFFFF, x3 & 0xFFFFFFFF, lr)
    calls.append(pending[0])
    N[0] += 1
    if N[0] >= 40:
        uc_.emu_stop()


h_mul = uc.hook_add(unicorn.UC_HOOK_CODE, lambda u, a, s, ud: on_mul(u, a, s, ud),
                    begin=MUL, end=MUL + 3)

d._cap.clear()
try:
    uc.emu_start(uc.reg_read(UC_ARM64_REG_PC), 0, timeout=120 * 1000000,
                 count=3_000_000)
except Exception:
    pass

print("收割 %d 次乘法调用" % len(calls))
for i, (x0, x1, x2, x3, lr) in enumerate(calls[:40]):
    print("  #%02d x0=%#x w1=%#x w2=%#x w3=%#x ret_to=+%#x" % (
        i, x0, x1 & 0xFF, x2 & 0xFF, x3 & 0xFF, lr - DEV_BASE))


# GF(2^8) 乘法（AES 多项式 0x11b）
def gf_mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


print("\nGF 乘法假设检验 (w0 = gf(w1, w2)) — 需出口 w0；先看入口参数模式")
