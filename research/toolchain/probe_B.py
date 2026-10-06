# -*- coding: utf-8 -*-
# probe_B.py — 强制修正 A1 输出为已知正确 base64, 观察 E 的产出能否对上真实语料
#   MODE=std|custom  选择 A1 用标准/自定义字母表
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

CALL_A1 = DEV_BASE + 0x304fb4
AFTER_A1 = DEV_BASE + 0x304fb8
CALL_E = DEV_BASE + 0x3050f8
AFTER_E = DEV_BASE + 0x3050fc
CALL_A2 = DEV_BASE + 0x3051b4
AFTER_A2 = DEV_BASE + 0x3051b8

MODE = os.environ.get("MODE", "custom")
S = os.environ.get("INPUT", "3.0.0.8-1790618586109-Android-1.5.8.0-16613a7076284a15bc723d018bcd67e1-default")
A1 = base64.b64encode(S.encode()).decode()
if MODE == "custom":
    A1 = A1.translate(FWD)
A1B = A1.encode()

# 真实语料 (ts=1790618586109, norm)  std-decode 后
REAL_STD = bytes.fromhex(
    "e8cb1f120ef5a42c59e22a4d00279e9f"
    "f54b2e0d8df438db5ed9da7bc6fa778b4cee15a8fa0a90a2bd953328d08c4134"
    "09ec4ccaf72d6143e50398d8")
REAL_CUSTOM = bytes.fromhex("23754ae9d0cbe749f5441e769b45143e")


def show_vec(e, addr, label):
    try:
        b, en, cap = struct.unpack("<QQQ", e.rd(addr, 24))
        if 0x40000000 <= b < 0x70000000 and en >= b and (en - b) < 0x4000:
            print("    %-8s b=%#x len=%d data=%s" % (label, b, en - b, e.rd(b, en - b).hex()))
        else:
            print("    %-8s b=%#x e=%#x cap=%#x (非法)" % (label, b, en, cap))
    except Exception as ex:
        print("    %-8s err %r" % (label, ex))


def on_code(uc, address, size, ud):
    e = ud
    if address == AFTER_A1:
        x29 = uc.reg_read(UC_ARM64_REG_X29)
        addr = x29 - 0x38
        b, en, cap = struct.unpack("<QQQ", e.rd(addr, 24))
        print("\n=== AFTER_A1: 原始 A1 输出 len=%d ===" % (en - b))
        if en - b == len(A1B):
            e.wr(b, A1B)
            print("    -> 已覆写为 %s b64 (%d 字节): %s" % (MODE, len(A1B), A1B.decode()))
        else:
            print("    !! 长度不匹配 (%d vs %d), 不覆写" % (en - b, len(A1B)))
    elif address == CALL_E:
        x29 = uc.reg_read(UC_ARM64_REG_X29)
        print("=== E 调用 x0=%#x x1=%#x x2=%#x x3=%#x" %
              (uc.reg_read(UC_ARM64_REG_X0), uc.reg_read(UC_ARM64_REG_X1),
               uc.reg_read(UC_ARM64_REG_X2), uc.reg_read(UC_ARM64_REG_X3)))
        show_vec(e, uc.reg_read(UC_ARM64_REG_X1), "E.in")
        for nm, a in (("E.x2", uc.reg_read(UC_ARM64_REG_X2)), ("E.x3", uc.reg_read(UC_ARM64_REG_X3))):
            try:
                print("    %s raw48=%s" % (nm, e.rd(a, 48).hex()))
            except Exception as ex:
                print("    %s err %r" % (nm, ex))
    elif address == AFTER_E:
        x29 = uc.reg_read(UC_ARM64_REG_X29)
        show_vec(e, x29 - 0x38, "E.out")
    elif address == AFTER_A2:
        x29 = uc.reg_read(UC_ARM64_REG_X29)
        show_vec(e, x29 - 0x38, "A2.out")


def main():
    print("MODE=%s  A1 = %s" % (MODE, A1))
    print("真实体(std-decode) =", REAL_STD.hex())
    print("  -> 前16B", REAL_STD[:16].hex(), " O[0:64]", REAL_STD[16:80].hex())
    e = _Engine()
    print("regions loaded=%d skipped=%d" % (e.all_loaded, e.all_skipped))
    e.fix_long_string(0x688130, b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv")
    for a in (AFTER_A1, CALL_E, AFTER_E, AFTER_A2):
        e.uc.hook_add(UC_HOOK_CODE, on_code, user_data=e, begin=a, end=a + 4)
    sret = e.alloc(0x40)
    e.wr(sret, b"\0" * 0x40)
    inp = e.mkstr(S)
    err = None
    try:
        e.call(DEV_BASE + 0x304eb0, (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148),
               sret=sret, timeout=300_000_000)
    except Exception as ex:
        err = repr(ex)
    print("\nerr:", err)
    try:
        t, ln, ptr = struct.unpack("<QQQ", e.rd(sret, 24))
        print("final: tag=%#x len=%#x" % (t, ln))
        if 0x40000000 <= ptr < 0x70000000 and ln < 0x1000:
            data = e.rd(ptr, ln)
            print("final data hex:", data.hex())
            print("final data raw:", data[:200])
    except Exception as ex:
        print("final err", ex)


if __name__ == "__main__":
    main()
