# -*- coding: utf-8 -*-
# probe_I.py — 抓住"密钥相关 S 盒"的落地点, 监视谁在读它 => 分组函数
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
KSAB = DEV_BASE + 0x2cd8b0
AFTER_E = DEV_BASE + 0x3050fc

ST = {"dest": None, "key": None, "table": None}
READS = {}


def on_code(uc, address, size, ud):
    e = ud
    if address == AFTER_A1:
        x29 = uc.reg_read(UC_ARM64_REG_X29)
        b, en, cap = struct.unpack("<QQQ", e.rd(x29 - 0x38, 24))
        if en - b == len(A1B):
            e.wr(b, A1B)
    elif address == KSAB:
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        x2 = uc.reg_read(UC_ARM64_REG_X2)
        x0 = uc.reg_read(UC_ARM64_REG_X0)
        print("### KSA 进入 x0=%#x x1(dest)=%#x x2(key)=%#x" % (x0, x1, x2))
        try:
            print("    key bytes:", e.rd(x2, 0x30).hex())
        except Exception as ex:
            print("    key err", ex)
        ST["dest"] = x1
        ST["key"] = x2
        try:
            e.uc.hook_add(UC_HOOK_MEM_READ, on_read, begin=x1, end=x1 + 0x100)
        except Exception as ex:
            print("    hook err", ex)
    elif address == AFTER_E:
        try:
            ST["table"] = e.rd(ST["dest"], 0x100)
            print("### 生成的 S 盒:", ST["table"].hex())
        except Exception as ex:
            print("### table err", ex)


def on_read(uc, access, address, size, value, ud):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    off = address - ST["dest"]
    READS.setdefault(pc - DEV_BASE, {}).setdefault(off, 0)
    READS[pc - DEV_BASE][off] += 1


def main():
    e = _Engine()
    e.fix_long_string(0x688130, b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv")
    for a in (AFTER_A1, KSAB, AFTER_E):
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
    print("err:", err)
    print("--- 读该 S 盒的 PC 及偏移分布 ---")
    for pc, d in sorted(READS.items(), key=lambda x: -sum(x[1].values())):
        offs = sorted(d.keys())
        print("  pc=%#08x  读次数=%d  偏移范围=%d..%d 唯一偏移=%d" %
              (pc, sum(d.values()), offs[0], offs[-1], len(offs)))


if __name__ == "__main__":
    main()
