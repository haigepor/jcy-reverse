# -*- coding: utf-8 -*-
# probe_v12.py — Emu2 (惰性真机内存) 驱动 304eb0, 带详细诊断
import os, sys, struct
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.arm64_const import *
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from emu_v12 import Emu2, DEV_BASE, IMG_SIZE

e = Emu2()
pid = e.attach_device()
print("pid", pid, flush=True)
e.fix_long_string(0x688130, b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv")

LAST = [0]
N = [0]
def hook_code(uc, address, size, ud):
    LAST[0] = address
    N[0] += 1
e.uc.hook_add(UC_HOOK_CODE, hook_code, begin=DEV_BASE, end=DEV_BASE + IMG_SIZE)

def on_unmapped(uc, access, address, size, value, ud):
    print("  UNMAPPED access=%d addr=%#x size=%d pc=%#x" % (access, address, size, uc.reg_read(UC_ARM64_REG_PC)), flush=True)
    return False
e.uc.hook_add(UC_HOOK_MEM_UNMAPPED, on_unmapped)

sret = e.alloc(0x40)
e.wr(sret, b"\0" * 0x40)
inp = e.mkstr("1790618586109")
try:
    try:
        e.call(DEV_BASE + 0x304eb0, (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148), sret=sret, timeout=180_000_000)
    except Exception as ex:
        print("ERR", repr(ex), flush=True)
    print("instrs:", N[0], "last pc:", hex(LAST[0]), "off:", hex(LAST[0] - DEV_BASE), flush=True)
    print("lazy maps:", len(e.mapped), "bytes:", e.lazy_bytes, flush=True)
    for t in e.lazy_log[:30]:
        print("   ", t, flush=True)
    print("stubs logs:", e.logs[-15:], flush=True)
    try:
        print("sret:", e.str_obj(sret))
    except Exception as ex:
        print("sret raw:", e.rd(sret, 0x30).hex())
finally:
    e.dev.close()
