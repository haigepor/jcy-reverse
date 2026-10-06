# -*- coding: utf-8 -*-
# trace_E.py — 只跟踪 E(0x2d6f78) 内部的调用树, 找密码原语
import os, sys, struct, base64
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from capstone import *
from unicorn import *
from unicorn.arm64_const import *
from v13 import Emu3, DEV_BASE, IMG_SIZE
from emu_v14 import Emu4 as _Engine

import paths as _P
SO = _P.SO
D = open(SO, "rb").read()
e_phoff = struct.unpack_from("<Q", D, 0x20)[0]
e_phnum = struct.unpack_from("<H", D, 0x38)[0]
SEGS = []
for i in range(e_phnum):
    o = e_phoff + i * 0x38
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
ALPHA = '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BMDpEaJRLj'
STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
FWD = str.maketrans(STD, '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj')
S = "3.0.0.8-1790618586109-Android-1.5.8.0-16613a7076284a15bc723d018bcd67e1-default"
A1B = base64.b64encode(S.encode()).decode().translate(FWD).encode()

AFTER_A1 = DEV_BASE + 0x304fb8
E_ENT = DEV_BASE + 0x2d6f78


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


depth = [0]
state = {"in": 0, "d0": None}
LOG = []
MAX = 4000


def on_code(uc, address, size, ud):
    e = ud
    off = address - DEV_BASE
    if off < 0 or off >= IMG_SIZE:
        return
    if address == AFTER_A1:
        x29 = uc.reg_read(UC_ARM64_REG_X29)
        b, en, cap = struct.unpack("<QQQ", e.rd(x29 - 0x38, 24))
        if en - b == len(A1B):
            e.wr(b, A1B)
        return
    ins = ins_at(off)
    if ins is None:
        return
    if address == E_ENT:
        state["in"] = 1
        state["d0"] = depth[0]
    m, ops = ins
    if m == "ret":
        if state["in"] and depth[0] <= state["d0"]:
            state["in"] = 0
        depth[0] = max(0, depth[0] - 1)
        return
    if m in ("bl", "blr"):
        if m == "bl":
            tgt = int(ops.replace("#", ""), 16)
        else:
            tgt = 0
            rn = ops.strip().lower()
            if rn.startswith("x") and rn[1:].isdigit():
                tgt = uc.reg_read(UC_ARM64_REG_X0 + int(rn[1:]))
        if address == E_ENT:
            state["in"] = 1
            state["d0"] = depth[0]
        if address == E_ENT:
            state["in"] = 1
            state["d0"] = depth[0]
        if state["in"] and len(LOG) < MAX:
            x = [uc.reg_read(UC_ARM64_REG_X0 + i) for i in range(4)]
            LOG.append((depth[0] - state["d0"], off, m, tgt, x))
        depth[0] += 1


def main():
    e = _Engine()
    e.fix_long_string(0x688130, b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv")
    e.uc.hook_add(UC_HOOK_CODE, on_code, user_data=e, begin=DEV_BASE, end=DEV_BASE + IMG_SIZE)
    sret = e.alloc(0x40)
    e.wr(sret, b"\0" * 0x40)
    inp = e.mkstr(S)
    err = None
    try:
        e.call(DEV_BASE + 0x304eb0, (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148),
               sret=sret, timeout=300_000_000)
    except Exception as ex:
        err = repr(ex)
    print("err:", err, "calls:", len(LOG))
    from collections import Counter
    c = Counter()
    for d, a, m, t, x in LOG:
        if DEV_BASE <= t < DEV_BASE + IMG_SIZE:
            c[t - DEV_BASE] += 1
    print("--- 热点(被调用次数最多的目标) ---")
    for k, v in c.most_common(25):
        print("  %#08x x%d" % (k, v))
    print("--- 调用树(深度<=8) ---")
    for d, a, m, t, x in LOG:
        if d > 8:
            continue
        to = (t - DEV_BASE) if (t and DEV_BASE <= t < DEV_BASE + IMG_SIZE) else t
        print("%s%#08x %-3s -> %s   x0=%#x x1=%#x x2=%#x x3=%#x" %
              ("  " * d, a, m, hex(to or 0), x[0], x[1], x[2], x[3]))


if __name__ == "__main__":
    main()
