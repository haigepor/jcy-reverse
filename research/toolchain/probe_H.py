# -*- coding: utf-8 -*-
# probe_H.py — 从真正的入口 305d94 跑起, 抓 304eb0 实际收到的输入串
import os, sys, struct, base64
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from unicorn import *
from unicorn.arm64_const import *
from v13 import Emu3, DEV_BASE
from emu_v14 import Emu4 as _Engine

ENTRY = DEV_BASE + 0x305d94
PIPE = DEV_BASE + 0x304eb0
AFTER_E = DEV_BASE + 0x3050fc

CAP = {}


def dumpstr(e, addr):
    try:
        s, kind = e.str_obj(addr)
        return "str(%s,%d)=%r" % (kind, len(s), s[:160])
    except Exception as ex:
        return "err %r" % ex


def dumpvec(e, addr):
    try:
        b, en, cap = struct.unpack("<QQQ", e.rd(addr, 24))
        if 0x40000000 <= b < 0x70000000 and 0 <= en - b < 0x4000:
            return "vec len=%d %r" % (en - b, e.rd(b, min(en - b, 200)))
        return "raw=%s" % e.rd(addr, 24).hex()
    except Exception as ex:
        return "err %r" % ex


def on_code(uc, address, size, ud):
    e = ud
    if address == PIPE:
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        x2 = uc.reg_read(UC_ARM64_REG_X2)
        print("### 304eb0 入口 x0=%#x x1=%#x x2=%#x" % (x0, x1, x2))
        print("    x0 obj :", dumpstr(e, x0))
        print("    x0 raw :", dumpvec(e, x0))
        try:
            print("    x0+0x18:", dumpstr(e, x0 + 0x18))
        except Exception:
            pass
        CAP["x0"] = x0
    elif address == AFTER_E:
        x29 = uc.reg_read(UC_ARM64_REG_X29)
        b, en, cap = struct.unpack("<QQQ", e.rd(x29 - 0x38, 24))
        if 0x40000000 <= b < 0x70000000:
            CAP["eout"] = e.rd(b, en - b)
            print("### E.out len=%d %s" % (en - b, CAP["eout"].hex()))


def main():
    e = _Engine()
    e.fix_long_string(0x688130, b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv")
    for a in (PIPE, AFTER_E):
        e.uc.hook_add(UC_HOOK_CODE, on_code, user_data=e, begin=a, end=a + 4)
    sret = e.alloc(0x40)
    e.wr(sret, b"\0" * 0x40)
    arg = e.mkstr(os.environ.get("ARG1", "default"))
    err = None
    try:
        e.call(ENTRY, (int(os.environ.get("TS", "1790618586109")), arg), sret=sret, timeout=300_000_000)
    except Exception as ex:
        err = repr(ex)
    print("err:", err)
    print("vsnprintf 产出:")
    for s in e.vsnprintf_calls:
        print("   ", repr(s))
    try:
        t, ln, ptr = struct.unpack("<QQQ", e.rd(sret, 24))
        print("final tag=%#x len=%#x" % (t, ln))
        if 0x40000000 <= ptr < 0x70000000 and ln < 0x1000:
            print("final:", e.rd(ptr, ln).hex())
    except Exception as ex:
        print("final err", ex)


if __name__ == "__main__":
    main()
