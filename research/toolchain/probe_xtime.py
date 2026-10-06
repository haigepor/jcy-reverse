# -*- coding: utf-8 -*-
"""probe_xtime.py — 定位 AES 轮函数：hook xtime 并记录调用者 LR。"""
import os, sys, struct, base64
from collections import Counter
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from unicorn import *
from unicorn.arm64_const import *
from v13 import Emu3, DEV_BASE
from emu_v14 import Emu4 as _Engine

ALPHA = '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
FWD = str.maketrans(STD, ALPHA)
S = "3.0.0.8-1790618586109-Android-1.5.8.0-16613a7076284a15bc723d018bcd67e1-default"
A1B = base64.b64encode(S.encode()).decode().translate(FWD).encode()

AFTER_A1 = DEV_BASE + 0x304fb8
AFTER_E = DEV_BASE + 0x3050fc
HOOKS = [0x2d2f0c, 0x2d2f18, 0x2d2f20, 0x2cd8b0]

LR = Counter()
ARG = Counter()
ENABLED = [False]


def on_code(uc, address, size, ud):
    e = ud
    if address == AFTER_A1:
        x29 = uc.reg_read(UC_ARM64_REG_X29)
        b, en, cap = struct.unpack("<QQQ", e.rd(x29 - 0x38, 24))
        if en - b == len(A1B):
            e.wr(b, A1B)
        return
    if address == DEV_BASE + 0x2d6f78:
        ENABLED[0] = True
    elif address == AFTER_E:
        ENABLED[0] = False
        return
    off = address - DEV_BASE
    if off in HOOKS and ENABLED[0]:
        lr = uc.reg_read(UC_ARM64_REG_LR)
        LR[(off, lr - DEV_BASE)] += 1
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        x2 = uc.reg_read(UC_ARM64_REG_X2)
        ARG[(off, x1 & 0xffffffff, x2 & 0xffff)] += 1


def main():
    e = _Engine()
    e.fix_long_string(0x688130, b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv")
    for a in (AFTER_A1, DEV_BASE + 0x2d6f78, AFTER_E):
        e.uc.hook_add(UC_HOOK_CODE, on_code, user_data=e, begin=a, end=a + 4)
    for h in HOOKS:
        e.uc.hook_add(UC_HOOK_CODE, on_code, user_data=e, begin=DEV_BASE + h, end=DEV_BASE + h + 4)
    sret = e.alloc(0x40)
    e.wr(sret, b"\0" * 0x40)
    inp = e.mkstr(S)
    try:
        e.call(DEV_BASE + 0x304eb0, (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148),
               sret=sret, timeout=300_000_000)
    except Exception as ex:
        print("err", repr(ex))
    print("--- xtime/相关函数的调用者 (func, LR) ---")
    for (f, lr), c in LR.most_common(30):
        print("   func=%#08x  caller LR=%#08x  x%d" % (f, lr, c))
    print()
    print("--- 实参分布 (func, x1, x2) 前 20 ---")
    for (f, a1, a2), c in ARG.most_common(20):
        print("   func=%#08x x1=%#x x2=%#x x%d" % (f, a1, a2, c))


if __name__ == "__main__":
    main()
