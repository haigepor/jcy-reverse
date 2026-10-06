# -*- coding: utf-8 -*-
# trace304.py — 追踪 304eb0 内部调用序列 (运行时逐指令反汇编, 避免 ELF 头卡住)
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from capstone import *
from unicorn import *
from unicorn.arm64_const import *
from v13 import Emu3, DEV_BASE, IMG_SIZE
from emu_v11 import HEAP, HEAP_SIZE

import paths as _P
SO = _P.SO
D = open(SO, "rb").read()
e_phoff = struct.unpack_from("<Q", D, 0x20)[0]
e_phentsize = struct.unpack_from("<H", D, 0x36)[0]
e_phnum = struct.unpack_from("<H", D, 0x38)[0]
SEGS = []
for i in range(e_phnum):
    o = e_phoff + i * e_phentsize
    t, fl = struct.unpack_from("<II", D, o)
    po, va, pa, fs, ms, al = struct.unpack_from("<QQQQQQ", D, o + 8)
    SEGS.append((t, po, va, fs))


def va2off(va):
    for t, po, v, fs in SEGS:
        if t == 1 and v <= va < v + fs:
            return po + (va - v)
    return None


md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
CACHE = {}
depth = [0]
log = []
MAXLOG = 400000


def ins_at(va):
    r = CACHE.get(va)
    if r is not None:
        return r
    o = va2off(va)
    if o is None:
        CACHE[va] = None
        return None
    lst = list(md.disasm(D[o:o + 4], va))
    r = (lst[0].mnemonic, lst[0].op_str) if lst else None
    CACHE[va] = r
    return r


def on_code(uc, address, size, ud):
    off = address - DEV_BASE
    if off < 0 or off >= IMG_SIZE:
        return
    ins = ins_at(off)
    if ins is None:
        return
    m, ops = ins
    if m == "ret":
        depth[0] = max(0, depth[0] - 1)
        return
    if m in ("bl", "blr"):
        if m == "bl":
            tgt = int(ops.replace("#", ""), 16)
        else:
            tgt = 0
            rn = ops.strip().lower()
            try:
                if rn.startswith("x") and rn[1:].isdigit():
                    tgt = uc.reg_read(UC_ARM64_REG_X0 + int(rn[1:]))
                elif rn.startswith("w") and rn[1:].isdigit():
                    tgt = uc.reg_read(UC_ARM64_REG_X0 + int(rn[1:])) & 0xFFFFFFFF
                else:
                    log.append((depth[0], off, "ERR:" + ops, 0))
            except Exception:
                log.append((depth[0], off, "ERR:" + ops, 0))
        if len(log) < MAXLOG:
            log.append((depth[0], off, m, tgt))
        depth[0] += 1


INPUT = os.environ.get("INPUT", "3.0.0.8-1790618586109-Android-1.5.8.0-16613a7076284a15bc723d018bcd67e1-default")
ONLY = os.environ.get("ONLY")


def main():
    e = Emu3()
    e.fix_long_string(0x688130, b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv")
    e.uc.hook_add(UC_HOOK_CODE, on_code, begin=DEV_BASE, end=DEV_BASE + IMG_SIZE)
    sret = e.alloc(0x40)
    e.wr(sret, b"\0" * 0x40)
    inp = e.mkstr(INPUT)
    err = None
    try:
        e.call(DEV_BASE + 0x304eb0, (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148),
               sret=sret, timeout=200_000_000)
    except Exception as ex:
        err = repr(ex)
    print("err:", err, "calls:", len(log))
    for d, a, k, t in log:
        to = (t - DEV_BASE) if (t and DEV_BASE <= t < DEV_BASE + IMG_SIZE) else t
        if ONLY and ONLY not in hex(to or 0):
            continue
        print("%s%s %-3s -> %s" % ("  " * min(d, 24), hex(a), k, hex(to or 0)))
    print("sret raw:", e.rd(sret, 0x18).hex())


if __name__ == "__main__":
    main()
