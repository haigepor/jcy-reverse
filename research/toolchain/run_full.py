# -*- coding: utf-8 -*-
# run_full.py — 用全量设备内存跑 304eb0, 与语料对比
import os, sys, json, struct, base64
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from unicorn import *
from unicorn.arm64_const import *
from emu_v14 import Emu4
from v13 import DEV_BASE, IMG_SIZE

AL = "5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj"
STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
ENC = str.maketrans(STD, AL)

TS = int(os.environ.get("TS", "1790618586109"))
S = os.environ.get("INPUT",
                   "3.0.0.8-%d-Android-1.5.8.0-16613a7076284a15bc723d018bcd67e1-default" % TS)


def expected():
    p = os.path.join(HERE, "..", "v9", "brute", "O_true_corpus.json")
    d = json.load(open(p, encoding="utf-8"))
    for r in d:
        if r["ts"] == TS and r["family"] == "normal":
            raw = bytes.fromhex("23754ae9d0cbe749f5441e769b4514") + bytes([62]) + bytes.fromhex(r["O"])
            return base64.b64encode(raw).decode().translate(ENC), r["O"]
    return None, None


def main():
    e = Emu4()
    print("loaded:", e.all_loaded, "skipped:", e.all_skipped)
    e.fix_long_string(0x688130, b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv")
    sret = e.alloc(0x40)
    e.wr(sret, b"\0" * 0x40)
    inp = e.mkstr(S)
    err = None
    try:
        e.call(DEV_BASE + 0x304eb0, (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148),
               sret=sret, timeout=300_000_000)
    except Exception as ex:
        err = "%r errno=%r addr=%r" % (ex, getattr(ex, "errno", None), getattr(ex, "address", None))
    print("err:", err, "faults:", len(e.faults))
    try:
        t, ln, ptr = struct.unpack("<QQQ", e.rd(sret, 24))
        got = e.rd(ptr, ln).decode("latin1")
    except Exception as ex:
        got = "<err %r>" % (ex,)
        t = ln = 0
    exp, O = expected()
    print("got(%d): %s" % (ln, got))
    print("exp     : %s" % exp)
    if exp:
        print("MATCH:", got == exp)
        if O:
            # 反向: 用 custom 表解码 got 得到 raw, 对比 O
            try:
                tr = str.maketrans(AL, STD)
                raw = base64.b64decode(got.translate(tr))
                print("decoded raw[0:16]:", raw[:16].hex())
                print("decoded O[:32]   :", raw[16:48].hex())
                print("expected O[:32]  :", O[:64])
            except Exception as ex:
                print("decode err", ex)
    print("logs:", e.logs[-8:])


if __name__ == "__main__":
    main()
