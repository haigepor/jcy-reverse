# -*- coding: utf-8 -*-
"""probe_ksa.py — 抓取 0x2cd8b0（密钥相关 S 盒构造）的实参与产物。

目标：确定
  1. dest / key 分别是什么、长度多少
  2. 生成的 256 字节表内容
  3. 该表随后被谁读取（定位真正的分组函数）
"""
import os, sys, struct, base64
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from unicorn import *
from unicorn.arm64_const import *
from v13 import Emu3, DEV_BASE
from emu_v14 import Emu4 as _Engine

ALPHA = '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
FWD = str.maketrans(STD, ALPHA)
S = "3.0.0.8-1790618586109-Android-1.5.8.0-16613a7076284a15bc723d018bcd67e1-default"
A1B = base64.b64encode(S.encode()).decode().translate(FWD).encode()

AFTER_A1 = DEV_BASE + 0x304fb8
KSA = DEV_BASE + 0x2cd8b0
AFTER_E = DEV_BASE + 0x3050fc

CALLS = []
READS = {}


def vec(e, addr):
    try:
        b, en, cap = struct.unpack("<QQQ", e.rd(addr, 24))
        if 0x40000000 <= b < 0x80000000 and 0 <= en - b < 0x10000:
            return b, en - b, e.rd(b, en - b)
    except Exception:
        pass
    return None


def on_code(uc, address, size, ud):
    e = ud
    if address == AFTER_A1:
        x29 = uc.reg_read(UC_ARM64_REG_X29)
        b, en, cap = struct.unpack("<QQQ", e.rd(x29 - 0x38, 24))
        if en - b == len(A1B):
            e.wr(b, A1B)
    elif address == KSA:
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        x2 = uc.reg_read(UC_ARM64_REG_X2)
        rec = {"x0": x0, "dest": x1, "keyptr": x2}
        v = vec(e, x2)
        rec["key"] = v[2] if v else None
        rec["keylen"] = v[1] if v else None
        CALLS.append(rec)
        print("### KSA 进入 x0=%#x dest=%#x keyptr=%#x keylen=%s" % (x0, x1, x2, rec["keylen"]))
        if rec["key"]:
            print("    key =", rec["key"][:80])
        # 监视该表的读取
        try:
            e.uc.hook_add(UC_HOOK_MEM_READ, on_read, begin=x1, end=x1 + 0x100)
        except Exception:
            pass
    elif address == AFTER_E:
        for i, rec in enumerate(CALLS):
            try:
                rec["table"] = e.rd(rec["dest"], 0x100)
            except Exception:
                rec["table"] = None


def on_read(uc, access, address, size, value, ud):
    pc = uc.reg_read(UC_ARM64_REG_PC) - DEV_BASE
    READS[pc] = READS.get(pc, 0) + 1


def main():
    e = _Engine()
    e.fix_long_string(0x688130, b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv")
    for a in (AFTER_A1, KSA, AFTER_E):
        e.uc.hook_add(UC_HOOK_CODE, on_code, user_data=e, begin=a, end=a + 4)
    sret = e.alloc(0x40)
    e.wr(sret, b"\0" * 0x40)
    inp = e.mkstr(S)
    try:
        e.call(DEV_BASE + 0x304eb0, (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148),
               sret=sret, timeout=300_000_000)
    except Exception as ex:
        print("err", repr(ex))
    print()
    for i, rec in enumerate(CALLS):
        t = rec.get("table")
        print("--- KSA 调用 #%d ---" % i)
        print("    dest = %#x" % rec["dest"])
        print("    key  = %r (%s 字节)" % ((rec["key"] or b"")[:40], rec["keylen"]))
        print("    表   =", t.hex() if t else None)
        if t:
            print("    是否等于 AES S-box:", t == AES_SBOX)
    print()
    print("--- 读取该表最频繁的 PC（前 20） ---")
    for pc, c in sorted(READS.items(), key=lambda x: -x[1])[:20]:
        print("   pc=%#08x x%d" % (pc, c))


AES_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16")

if __name__ == "__main__":
    main()
