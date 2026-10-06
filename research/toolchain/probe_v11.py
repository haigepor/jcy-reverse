# -*- coding: utf-8 -*-
# probe_v11.py — 在真机镜像模拟器上调用 304eb0
import struct, sys, traceback
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.arm64_const import UC_ARM64_REG_PC
from emu_v11 import Emu, DEV_BASE, IMG_SIZE

e = Emu()
e.fix_long_string(0x688130, b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv")

# 记录执行路径 (粗粒度)
VISIT = []
def hook_code(uc, address, size, ud):
    if len(VISIT) < 200000:
        VISIT.append(address)
e.uc.hook_add(UC_HOOK_CODE, hook_code, begin=DEV_BASE, end=DEV_BASE + IMG_SIZE)

FAULT = []
def hook_mem(uc, access, address, size, value, ud):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    FAULT.append((pc, access, address, size))
    print("  FAULT pc=%#x access=%d addr=%#x size=%d" % (pc, access, address, size))
    if len(FAULT) > 8:
        uc.emu_stop()
    return False
e.uc.hook_add(UC_HOOK_MEM_UNMAPPED, hook_mem)

X1 = DEV_BASE + 0x688130
X2 = DEV_BASE + 0x688148

def call304(S, sret_hex=False):
    sret = e.alloc(0x40)
    e.wr(sret, b"\0" * 0x40)
    inp = e.mkstr(S)
    VISIT.clear()
    err = None
    try:
        e.call(DEV_BASE + 0x304eb0, (inp, X1, X2), sret=sret, timeout=60_000_000)
    except Exception as ex:
        err = repr(ex)
    out = None
    try:
        out = e.str_obj(sret)
    except Exception:
        pass
    raw = e.rd(sret, 0x30)
    print("--- S=%r ---" % (S[:60] if isinstance(S, bytes) else S[:60]))
    print("   err:", err, " visits:", len(VISIT), " last:", hex(VISIT[-1]) if VISIT else None)
    print("   tail:", [hex(v) for v in VISIT[-12:]])
    print("   sret raw:", raw.hex())
    print("   sret str:", (out[0][:200] if out else None), out[1] if out else "")
    if e.logs:
        print("   logs:", e.logs[-8:])
    e.logs.clear()
    return raw

if __name__ == "__main__":
    cands = sys.argv[1:] or ["1790618586109"]
    for c in cands:
        call304(c)
