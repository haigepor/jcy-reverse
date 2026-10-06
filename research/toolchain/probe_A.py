# -*- coding: utf-8 -*-
# probe_A.py — 在真实 304eb0 上下文里 dump A 编码器的输入/中间量
import os, sys, struct, base64
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from unicorn import *
from unicorn.arm64_const import *
from v13 import Emu3, DEV_BASE
if os.environ.get("ALL", "1") == "1":
    from emu_v14 import Emu4 as _Engine
else:
    _Engine = Emu3

AWRAP = DEV_BASE + 0x2dbf9c
ACORE = DEV_BASE + 0x2dc524
LOOPB = DEV_BASE + 0x2dc7bc      # bl 0x2dd3bc (extract)
LOOPA = DEV_BASE + 0x2dc7c0      # extract 返回后
CALL_A1 = DEV_BASE + 0x304fb4    # 304eb0 内 bl A wrapper
AFTER_A1 = DEV_BASE + 0x304fb8
CALL_E = DEV_BASE + 0x3050f8
AFTER_E = DEV_BASE + 0x3050fc
CALL_A2 = DEV_BASE + 0x3051b4
AFTER_A2 = DEV_BASE + 0x3051b8
ALPHA_HK = DEV_BASE + 0x2dc730      # A core 内字母表已构建, 循环初始化处

ALPHA = '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'


def show_obj(e, addr, n=0x60, label=""):
    try:
        raw = e.rd(addr, n)
    except Exception as ex:
        print("    %s @%#x read err %r" % (label, addr, ex)); return
    print("    %s @%#x raw=%s" % (label, addr, raw.hex()))
    for off in range(0, n, 8):
        v = struct.unpack_from("<Q", raw, off)[0]
        print("       +%#04x: %#018x" % (off, v))


def show_str(e, addr, label=""):
    try:
        s, kind = e.str_obj(addr)
        print("    %s str(%s)=%r" % (label, kind, s[:120]))
        return s
    except Exception as ex:
        print("    %s str err %r" % (label, ex))
        return None


def show_vec(e, addr, label=""):
    """vector<T> {begin,end,cap} 三连"""
    try:
        b, en, cap = struct.unpack("<QQQ", e.rd(addr, 24))
    except Exception as ex:
        print("    %s vec err %r" % (label, ex)); return
    txt = ""
    if 0x40000000 <= b < 0x70000000 and en >= b and (en - b) < 0x2000:
        try:
            txt = repr(e.rd(b, min(en - b, 256))[:256])
        except Exception as ex:
            txt = "dberr %r" % ex
    print("    %s vec @%#x b=%#x e=%#x cap=%#x len=%d %s" % (label, addr, b, en, cap, en - b if en >= b else -1, txt))


N = [0]
MAXP = 4


def on_code(uc, address, size, ud):
    e = ud
    x = lambda r: uc.reg_read(r)
    if address == CALL_A1:
        N[0] += 1
        print("\n### [%d] A1 wrapper 调用 (0x304fb4) x0=%#x x1=%#x x8=%#x" % (N[0], x(UC_ARM64_REG_X0), x(UC_ARM64_REG_X1), x(UC_ARM64_REG_X8)))
        x29 = x(UC_ARM64_REG_X29)
        show_obj(e, x(UC_ARM64_REG_X1), 0x60, "input_obj")
        for off in (0, 0x18, 0x30, 0x48):
            show_str(e, (x(UC_ARM64_REG_X1) + off) & ((1 << 64) - 1), "in+%#x" % off)
        show_obj(e, x(UC_ARM64_REG_X0), 0x60, "singleton")
        for off in (0, 0x18, 0x30, 0x48):
            show_str(e, (x(UC_ARM64_REG_X0) + off) & ((1 << 64) - 1), "sg+%#x" % off)
    elif address == AFTER_A1:
        x29 = x(UC_ARM64_REG_X29)
        show_vec(e, x29 - 0x38, "A1 out")
    elif address == ALPHA_HK:
        x29 = x(UC_ARM64_REG_X29)
        show_vec(e, x29 - 0x60, "alpha")
        show_vec(e, x29 - 0x48, "alpha_src")
        show_vec(e, x29 - 0x30, "tmp3")
    elif address == ACORE:
        print("  -- A core x0(sg)=%#x x1(obj)=%#x x8(sret)=%#x" % (x(UC_ARM64_REG_X0), x(UC_ARM64_REG_X1), x(UC_ARM64_REG_X8)))
        show_obj(e, x(UC_ARM64_REG_X1), 0x40, "A core input")
    elif address == LOOPB:
        if N[0] <= MAXP:
            print("    [loop] extract(obj=%#x, idx=%d)" % (x(UC_ARM64_REG_X20), x(UC_ARM64_REG_X21)))
    elif address == LOOPA:
        if N[0] <= MAXP:
            x29 = x(UC_ARM64_REG_X29)
            try:
                raw = e.rd(x29 - 0x30, 0x18)
                b, en, cap = struct.unpack("<QQQ", raw)
                pay = e.rd(b, min(en - b, 0x60)) if en > b else b""
                print("       -> sret b=%#x e=%#x cap=%#x len=%d pay=%s" % (b, en, cap, en - b, pay.hex()))
            except Exception as ex:
                print("       -> err %r" % ex)
    elif address == CALL_E:
        x29 = x(UC_ARM64_REG_X29)
        print("\n### E 调用 (0x3050f8) x0=%#x x1=%#x x2=%#x x3=%#x" % (x(UC_ARM64_REG_X0), x(UC_ARM64_REG_X1), x(UC_ARM64_REG_X2), x(UC_ARM64_REG_X3)))
        show_vec(e, x29 - 0x20, "E arg(in)")
        show_vec(e, x29 - 0x38, "E sret")
    elif address == AFTER_E:
        x29 = x(UC_ARM64_REG_X29)
        show_vec(e, x29 - 0x38, "E out")
    elif address == CALL_A2:
        x29 = x(UC_ARM64_REG_X29)
        print("\n### A2 wrapper 调用 (0x3051b4) x0=%#x x1=%#x" % (x(UC_ARM64_REG_X0), x(UC_ARM64_REG_X1)))
        show_obj(e, x(UC_ARM64_REG_X1), 0x60, "A2 input_obj")
        for off in (0, 0x18, 0x30, 0x48):
            show_str(e, (x(UC_ARM64_REG_X1) + off) & ((1 << 64) - 1), "in+%#x" % off)
    elif address == AFTER_A2:
        x29 = x(UC_ARM64_REG_X29)
        show_vec(e, x29 - 0x38, "A2 out")


S = os.environ.get("INPUT", "3.0.0.8-1790618586109-Android-1.5.8.0-16613a7076284a15bc723d018bcd67e1-default")


def main():
    tbl = str.maketrans(STD, ALPHA)
    print("expect A1 = custom_b64(input) =")
    print("  ", base64.b64encode(S.encode()).decode().translate(tbl))
    e = _Engine()
    if hasattr(e, "all_loaded"):
        print("all regions loaded=%d skipped=%d" % (e.all_loaded, e.all_skipped))
    e.fix_long_string(0x688130, b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv")
    for a in (CALL_A1, AFTER_A1, ACORE, ALPHA_HK, LOOPB, LOOPA, CALL_E, AFTER_E, CALL_A2, AFTER_A2):
        e.uc.hook_add(UC_HOOK_CODE, on_code, user_data=e, begin=a, end=a + 4)
    sret = e.alloc(0x40)
    e.wr(sret, b"\0" * 0x40)
    inp = e.mkstr(S)
    err = None
    try:
        e.call(DEV_BASE + 0x304eb0, (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148),
               sret=sret, timeout=200_000_000)
    except Exception as ex:
        err = repr(ex)
    print("\nerr:", err)
    try:
        print("final sret raw:", e.rd(sret, 0x30).hex())
    except Exception as ex:
        print("final sret err", ex)


if __name__ == "__main__":
    main()
