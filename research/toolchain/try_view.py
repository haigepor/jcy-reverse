# -*- coding: utf-8 -*-
# try_view.py — 用不同 tag 构造 view 传入 304eb0, 比较输出
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from unicorn import *
from unicorn.arm64_const import *
from v13 import Emu3, DEV_BASE, IMG_SIZE

S = os.environ.get("INPUT", "3.0.0.8-1790618586109-Android-1.5.8.0-16613a7076284a15bc723d018bcd67e1-default")
AL = "5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj"


def mkview(e, s, tag, addr=None):
    b = s if isinstance(s, bytes) else s.encode()
    if addr is None:
        addr = e.alloc(0x40)
    buf = e.alloc(len(b) + 1)
    e.wr(buf, b + b"\x00")
    e.wr(addr, struct.pack("<QQQ", tag, len(b), buf))
    return addr


def run(tag):
    e = Emu3()
    e.fix_long_string(0x688130, b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv")
    sret = e.alloc(0x40)
    e.wr(sret, b"\0" * 0x40)
    inp = mkview(e, S, tag)
    err = None
    try:
        e.call(DEV_BASE + 0x304eb0, (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148),
               sret=sret, timeout=200_000_000)
    except Exception as ex:
        err = repr(ex)[:120]
    try:
        t, ln, ptr = struct.unpack("<QQQ", e.rd(sret, 24))
        data = e.rd(ptr, ln) if ln < 0x1000 else b""
    except Exception as ex:
        t = ln = ptr = None
        data = b""
    return err, t, ln, ptr, data


for tag in [0x31, 0xa1, 0x21, 0x41, 0x11, 0x01, 0x20, 0x30, 0x35]:
    err, t, ln, ptr, data = run(tag)
    print("tag=%#04x err=%s view(tag=%s,len=%s,ptr=%s)" % (tag, err, hex(t) if t else t, hex(ln) if ln else ln, hex(ptr) if ptr else ptr))
    if data:
        print("   out:", data.decode("latin1"))
