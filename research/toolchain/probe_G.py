# -*- coding: utf-8 -*-
# probe_G.py — 不补 A1, 直接看 304eb0 内部 vsnprintf 拼出的字符串
#   X0ENV: 传给 304eb0 的 x0 内容 (字符串形式); 默认 "1790618586109"
import os, sys, struct, base64
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from unicorn import *
from unicorn.arm64_const import *
from v13 import Emu3, DEV_BASE
from emu_v14 import Emu4 as _Engine

X0 = os.environ.get("X0ENV", "1790618586109")


def main():
    e = _Engine()
    e.fix_long_string(0x688130, b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv")
    sret = e.alloc(0x40)
    e.wr(sret, b"\0" * 0x40)
    inp = e.mkstr(X0)
    err = None
    try:
        e.call(DEV_BASE + 0x304eb0, (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148),
               sret=sret, timeout=300_000_000)
    except Exception as ex:
        err = repr(ex)
    print("x0 =", repr(X0))
    print("err:", err)
    print("vsnprintf 产出 (%d 条):" % len(e.vsnprintf_calls))
    for s in e.vsnprintf_calls:
        if isinstance(s, bytes):
            print("   ", repr(s))
        else:
            print("   ", repr(s))
    print("logs tail:", e.logs[-5:])


if __name__ == "__main__":
    main()
