# -*- coding: utf-8 -*-
# test_E.py — 验证 E 原语: E(singleton, s1, s2, s3) 是否复现已知向量
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from unicorn import *
from unicorn.arm64_const import *
from v13 import Emu3, DEV_BASE

VEC = {
    "=": "43711e316a3bb0e35ac6d811ec65b3f6",
    "==": "90a178f857b9d6f69e0c8b38099e4737",
}


def mkview(e, b, tag=0x31):
    if isinstance(b, str):
        b = b.encode()
    a = e.alloc(0x40)
    buf = e.alloc(len(b) + 1)
    e.wr(buf, b + b"\0")
    e.wr(a, struct.pack("<QQQ", tag, len(b), buf))
    return a


def main():
    e = Emu3()
    e.fix_long_string(0x688130, b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv")
    # x0 用 304eb0 里 E 的 x0: [0x67c000+0xa90] + K  -> 先直接试 singleton 0x689640
    cand = [DEV_BASE + 0x689640]
    try:
        g = (e.rd_u64(DEV_BASE + 0x67ca90) + 0x1fc39ef4ba094005) & ((1 << 64) - 1)
        cand.append(g)
    except Exception:
        pass
    for s1, exp in VEC.items():
        for g in cand:
            sret = e.alloc(0x40)
            e.wr(sret, b"\0" * 0x40)
            v1 = mkview(e, s1)
            err = None
            try:
                e.call(DEV_BASE + 0x2d6f78, (g, v1, DEV_BASE + 0x688130, DEV_BASE + 0x688148),
                       sret=sret, timeout=60_000_000)
            except Exception as ex:
                err = repr(ex)[:100]
            try:
                t, ln, ptr = struct.unpack("<QQQ", e.rd(sret, 24))
                data = e.rd(ptr, ln).hex() if ln < 0x1000 else "<%d>" % ln
            except Exception as ex:
                t = ln = ptr = None
                data = "<%r>" % ex
            print("s1=%-3r g=%#x err=%s out(%s)=%s exp=%s %s" %
                  (s1, g, err, ln, data, exp, "OK" if data == exp else ""))


if __name__ == "__main__":
    main()
