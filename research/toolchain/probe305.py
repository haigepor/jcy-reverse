# -*- coding: utf-8 -*-
# probe305.py — 在 0x306478 (bl 306a3c) 处 dump 真实实参, 并跑完 0x305d94
import os, sys, json, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from unicorn import *
from unicorn.arm64_const import *
from v13 import Emu3, DEV_BASE, IMG_SIZE

HOOK = DEV_BASE + 0x306478
seen = []


def on_code(uc, address, size, ud):
    if address != HOOK:
        return
    regs = [uc.reg_read(UC_ARM64_REG_X0 + i) for i in range(8)]
    sp = uc.reg_read(UC_ARM64_REG_SP)
    stack = []
    for i in range(4):
        try:
            stack.append(struct.unpack("<Q", uc.mem_read(sp + i * 8, 8))[0])
        except UcError:
            stack.append(None)
    x29 = uc.reg_read(UC_ARM64_REG_X29)
    rec = {"regs": [hex(r) for r in regs], "stack": [hex(s) if s is not None else None for s in stack],
           "x29": hex(x29)}
    # 尝试解引用可疑指针为字符串
    e = ud
    deref = {}
    for i, r in enumerate(regs):
        if r and DEV_BASE <= r < DEV_BASE + IMG_SIZE:
            try:
                deref["x%d" % i] = e.cstr(r, 128)
            except UcError:
                pass
        elif r and 0x40000000 <= r < 0x80000000:
            try:
                deref["x%d" % i] = e.cstr(r, 128)
            except UcError:
                pass
    rec["deref"] = {k: v.decode("latin1") for k, v in deref.items()}
    seen.append(rec)
    print("== @0x306478 ==")
    for k, v in rec.items():
        print("   %s: %s" % (k, v))


TARGET = os.environ.get("TARGET", "305")
ARG1 = os.environ.get("ARG1", "default")
TS = int(os.environ.get("TS", "1790618586109"))


def main():
    e = Emu3()
    e.fix_long_string(0x688130, b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv")
    e.uc.hook_add(UC_HOOK_CODE, on_code, user_data=e, begin=HOOK, end=HOOK + 4)
    sret = e.alloc(0x40)
    e.wr(sret, b"\0" * 0x40)
    err = None
    try:
        if TARGET == "305":
            arg = e.mkstr(ARG1)
            e.call(DEV_BASE + 0x305d94, (TS, arg), sret=sret, timeout=200_000_000)
        else:
            inp = e.mkstr(ARG1)
            e.call(DEV_BASE + 0x304eb0, (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148),
                   sret=sret, timeout=200_000_000)
    except Exception as ex:
        err = "%r args=%r errno=%r addr=%r" % (ex, getattr(ex, "args", None),
                                               getattr(ex, "errno", None), getattr(ex, "address", None))
    print("err:", err)
    print("faults:", len(e.faults))
    print("vsnprintf:", e.vsnprintf_calls)
    print("sret raw:", e.rd(sret, 0x30).hex())
    try:
        print("sret str:", e.str_obj(sret))
    except Exception as ex:
        print("sret str err:", ex)
    print("logs:", e.logs[-12:])


if __name__ == "__main__":
    main()
