# -*- coding: utf-8 -*-
# probe_caller.py — 直接调用 0x305d94(调用者), 抓 vsnprintf 产物与 auth 输出
import os, sys, json, struct
from unicorn import *
from unicorn.arm64_const import *
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from v13 import Emu3, DEV_BASE, run_once
from emu_v11 import IMG_SIZE

ALPHA = "5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVMow9BHCZNMDpEaJRLj"
STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def custom_b64_decode(s):
    tbl = {c: i for i, c in enumerate(ALPHA)}
    s = s.rstrip("=")
    bits = 0
    nbits = 0
    out = bytearray()
    for ch in s:
        v = tbl.get(ch)
        if v is None:
            continue
        bits = (bits << 6) | v
        nbits += 6
        if nbits >= 8:
            nbits -= 8
            out.append((bits >> nbits) & 0xFF)
    return bytes(out)


def main():
    ts = int(sys.argv[1]) if len(sys.argv) > 1 else 1790618586109
    e = Emu3()
    e.fix_long_string(0x688130, b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv")
    empty = e.mkstr("")
    sret = e.alloc(0x80)
    e.wr(sret, b"\0" * 0x80)
    err = None
    for x1 in (empty, 0):
        e.wr(sret, b"\0" * 0x80)
        e.vsnprintf_calls.clear()
        e.logs.clear()
        try:
            e.call(DEV_BASE + 0x305d94, (ts, x1), sret=sret, timeout=120_000_000)
        except Exception as ex:
            err = repr(ex)
        print("=== x1=%s err=%s" % (hex(x1), err))
        print("  vsnprintf:", e.vsnprintf_calls)
        try:
            print("  sret:", e.str_obj(sret))
        except Exception:
            pass
        print("  raw:", e.rd(sret, 0x60).hex())
        print("  logs:", e.logs[-8:])
        if x1 == empty:
            break


main()
