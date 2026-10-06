# -*- coding: utf-8 -*-
# probe_D.py — 受控实验: 用不同 A1 输入观察 E 的输出变化 (判断是否分组/流式/含随机)
#   A1HEX=<hex>  指定 A1 的 104 字节内容; 默认用正确的 custom_b64
import os, sys, struct, base64, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from unicorn import *
from unicorn.arm64_const import *
from v13 import Emu3, DEV_BASE
from emu_v14 import Emu4 as _Engine

ALPHA = '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
FWD = str.maketrans(STD, ALPHA)

AFTER_A1 = DEV_BASE + 0x304fb8
AFTER_E = DEV_BASE + 0x3050fc

S = "3.0.0.8-1790618586109-Android-1.5.8.0-16613a7076284a15bc723d018bcd67e1-default"
DEFAULT_A1 = base64.b64encode(S.encode()).decode().translate(FWD).encode()
A1B = bytes.fromhex(os.environ["A1HEX"]) if os.environ.get("A1HEX") else DEFAULT_A1
TAG = os.environ.get("TAG", "base")

OUT = {}


def on_code(uc, address, size, ud):
    e = ud
    if address == AFTER_A1:
        x29 = uc.reg_read(UC_ARM64_REG_X29)
        b, en, cap = struct.unpack("<QQQ", e.rd(x29 - 0x38, 24))
        if en - b == len(A1B):
            e.wr(b, A1B)
        else:
            OUT["patchfail"] = (en - b, len(A1B))
    elif address == AFTER_E:
        x29 = uc.reg_read(UC_ARM64_REG_X29)
        b, en, cap = struct.unpack("<QQQ", e.rd(x29 - 0x38, 24))
        OUT["out"] = e.rd(b, en - b) if 0x40000000 <= b < 0x70000000 else b""


def main():
    t0 = time.time()
    e = _Engine()
    KEY = bytes.fromhex(os.environ["KEYHEX"]) if os.environ.get("KEYHEX") else b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv"
    e.fix_long_string(0x688130, KEY)
    if os.environ.get("IVHEX"):
        e.fix_long_string(0x688148, bytes.fromhex(os.environ["IVHEX"]))
    print("KEY=%r" % KEY)
    for a in (AFTER_A1, AFTER_E):
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
    dt = time.time() - t0
    o = OUT.get("out", b"")
    print("TAG=%s err=%s patchfail=%s dt=%.1fs" % (TAG, err, OUT.get("patchfail"), dt))
    print("A1   =", A1B.decode("latin1"))
    print("Eout len=%d" % len(o))
    if o:
        print("  head16 =", o[:16].hex())
        print("  O[0:64]=", o[16:80].hex())
        print("  O[64:] =", o[80:].hex())
        print("  md5    =", __import__("hashlib").md5(o).hexdigest())


if __name__ == "__main__":
    main()
