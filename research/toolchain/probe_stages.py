# -*- coding: utf-8 -*-
# probe_stages.py — 在 304eb0 各阶段 dump 中间串, 定位在哪一步变成垃圾
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from unicorn import *
from unicorn.arm64_const import *
from v13 import Emu3, DEV_BASE, IMG_SIZE

S = os.environ.get("INPUT", "3.0.0.8-1790618586109-Android-1.5.8.0-16613a7076284a15bc723d018bcd67e1-default")

STAGES = [
    (0x304fb8, "after A1", [("in", -0x20), ("A1", -0x38)]),
    (0x3050e4, "before E", [("in", -0x20)]),
    (0x305138, "after E", [("in", -0x20), ("E", -0x38)]),
    (0x3051b8, "after A2", [("in", -0x20), ("A2", -0x38)]),
    (0x305218, "before final", [("in", -0x20)]),
    (0x3052a4, "at E5804", [("in", -0x20)]),
    (0x3052d4, "at E587C", [("in", -0x20)]),
]
HOOKS = {DEV_BASE + a: (label, vars_) for a, label, vars_ in STAGES}


def show(e, addr, name):
    try:
        w = struct.unpack("<QQQ", e.rd(addr, 24))
    except Exception as ex:
        print("      %-6s err %r" % (name, ex))
        return
    txt = ""
    b0, b1, b2 = w
    # vector<char> {begin,end,cap}
    if 0x50000000 <= b0 < 0x54000000 and b1 >= b0 and (b1 - b0) < 0x1000:
        try:
            txt = "vec len=%d data=%r" % (b1 - b0, e.rd(b0, b1 - b0)[:160].hex())
        except Exception as ex:
            txt = "vec err %r" % ex
    # libc++ string
    else:
        try:
            s, kind = e.str_obj(addr)
            txt = "str(%s)=%r" % (kind, s[:80])
        except Exception as ex:
            txt = "strerr %r" % ex
    print("      %-6s @%#x w=%s %s" % (name, addr, ",".join(hex(x) for x in w), txt))


def on_code(uc, address, size, ud):
    e = ud
    if address not in HOOKS:
        return
    label, vars_ = HOOKS[address]
    x29 = uc.reg_read(UC_ARM64_REG_X29)
    print("=== %s (pc=%#x) ===" % (label, address - DEV_BASE))
    for nm, off in vars_:
        show(e, (x29 + off) & ((1 << 64) - 1), nm)


def main():
    e = Emu3()
    e.fix_long_string(0x688130, b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv")
    for a in HOOKS:
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
    print("err:", err)
    t, ln, ptr = struct.unpack("<QQQ", e.rd(sret, 24))
    print("final view: tag=%#x len=%#x" % (t, ln))
    print("final data:", e.rd(ptr, ln).decode("latin1"))


if __name__ == "__main__":
    main()
