# -*- coding: utf-8 -*-
"""probe_regions.py — 统计 304eb0 管线实际读到的设备内存区域。

目的：把 authgen 的依赖从 813 个区域（424 MB）压缩到真正被读取的子集，
      使交付脚本更快、更易迁移。
输出：research/artifacts/regions_used.json
"""
import os, sys, json, struct, base64
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from unicorn import *
from unicorn.arm64_const import *
from v13 import Emu3, DEV_BASE
from emu_v14 import Emu4 as _Engine
import paths as _P

ALPHA = '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
FWD = str.maketrans(STD, ALPHA)
S = "3.0.0.8-1790618586109-Android-1.5.8.0-16613a7076284a15bc723d018bcd67e1-default"
A1B = base64.b64encode(S.encode()).decode().translate(FWD).encode()

AFTER_A1 = DEV_BASE + 0x304fb8
AFTER_E = DEV_BASE + 0x3050fc

REGIONS = []          # (lo, hi, file)
USED = {}
ENABLED = [False]


def on_read(uc, access, address, size, value, ud):
    if not ENABLED[0]:
        return
    for lo, hi, fn in REGIONS:
        if lo <= address < hi:
            USED[fn] = USED.get(fn, 0) + 1
            return


def on_code(uc, address, size, ud):
    e = ud
    if address == AFTER_A1:
        x29 = uc.reg_read(UC_ARM64_REG_X29)
        b, en, cap = struct.unpack("<QQQ", e.rd(x29 - 0x38, 24))
        if en - b == len(A1B):
            e.wr(b, A1B)
    elif address == DEV_BASE + 0x304eb0:
        ENABLED[0] = True
    elif address == AFTER_E:
        ENABLED[0] = False


def main():
    regs = json.load(open(_P.REGIONS_ALL_JSON, encoding="utf-8"))
    for r in regs:
        REGIONS.append((r["base"], r["base"] + r["size"], r["file"]))
    print("已登记区域 %d 个" % len(REGIONS))

    e = _Engine()
    e.fix_long_string(0x688130, b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv")
    for a in (AFTER_A1, DEV_BASE + 0x304eb0, AFTER_E):
        e.uc.hook_add(UC_HOOK_CODE, on_code, user_data=e, begin=a, end=a + 4)
    e.uc.hook_add(UC_HOOK_MEM_READ, on_read)
    sret = e.alloc(0x40)
    e.wr(sret, b"\0" * 0x40)
    inp = e.mkstr(S)
    try:
        e.call(DEV_BASE + 0x304eb0, (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148),
               sret=sret, timeout=300_000_000)
    except Exception as ex:
        print("err", repr(ex))

    used = {fn: c for fn, c in USED.items()}
    total = 0
    keep = []
    byfile = {r["file"]: r for r in regs}
    for fn, c in sorted(used.items(), key=lambda x: -x[1]):
        r = byfile.get(fn)
        if not r:
            continue
        total += r["size"]
        keep.append(r)
    print("\n被读取的区域: %d / %d" % (len(keep), len(regs)))
    print("被读取体积: %.1f MB / %.1f MB" % (total / 1048576, sum(r["size"] for r in regs) / 1048576))
    print("\n前 20 个热点区域:")
    for r in sorted(keep, key=lambda x: -used[x["file"]])[:20]:
        print("   %-12s base=%#x size=%#x 读 %d 次" % (r["file"], r["base"], r["size"], used[r["file"]]))

    out = os.path.join(_P.ARTIFACTS, "regions_used.json")
    json.dump(keep, open(out, "w", encoding="utf-8"), indent=1)
    print("\n已写出 %s（%d 条）" % (out, len(keep)))


if __name__ == "__main__":
    main()
