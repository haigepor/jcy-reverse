# -*- coding: utf-8 -*-
# trace_sbox.py — 监视 S-box 内存读取, 定位密码核心函数
import os, sys, struct, base64
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

# S-box 的 vaddr (文件偏移 == vaddr, 第一段 vaddr=0)
REGIONS = {
    "AES_S": (DEV_BASE + 0x1dfc00, 0x100),
    "AES_INV": (DEV_BASE + 0x1e03b0, 0x100),
    "AES_Td0": (DEV_BASE + 0x1e8db0, 0x400),
    "SM4_S": (DEV_BASE + 0x20b630, 0x100),
}
hits = {}
enabled = [False]


def on_read(uc, access, address, size, value, ud):
    if not enabled[0]:
        return
    for nm, (lo, sz) in REGIONS.items():
        if lo <= address < lo + sz:
            pc = uc.reg_read(UC_ARM64_REG_PC)
            hits.setdefault(nm, {}).setdefault(pc - DEV_BASE, 0)
            hits[nm][pc - DEV_BASE] += 1


def on_code(uc, address, size, ud):
    e = ud
    if address == AFTER_A1:
        x29 = uc.reg_read(UC_ARM64_REG_X29)
        b, en, cap = struct.unpack("<QQQ", e.rd(x29 - 0x38, 24))
        if en - b == len(A1B):
            e.wr(b, A1B)
    elif address == DEV_BASE + 0x2d6f78:
        enabled[0] = True
    elif address == AFTER_E:
        enabled[0] = False


def main():
    e = _Engine()
    e.fix_long_string(0x688130, b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv")
    for a in (AFTER_A1, DEV_BASE + 0x2d6f78, AFTER_E):
        e.uc.hook_add(UC_HOOK_CODE, on_code, user_data=e, begin=a, end=a + 4)
    for nm, (lo, sz) in REGIONS.items():
        e.uc.hook_add(UC_HOOK_MEM_READ, on_read, begin=lo, end=lo + sz)
    sret = e.alloc(0x40)
    e.wr(sret, b"\0" * 0x40)
    inp = e.mkstr(S)
    err = None
    try:
        e.call(DEV_BASE + 0x304eb0, (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148),
               sret=sret, timeout=300_000_000)
    except Exception as ex:
        err = repr(ex)
    print("err:", err)
    for nm, d in hits.items():
        print("%-8s 读次数=%d  引用PC:" % (nm, sum(d.values())))
        for pc, c in sorted(d.items(), key=lambda x: -x[1])[:15]:
            print("    pc=%#08x x%d" % (pc, c))
    if not hits:
        print("未捕获任何 S-box 读取")


if __name__ == "__main__":
    main()
