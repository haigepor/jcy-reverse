# -*- coding: utf-8 -*-
# dbg_v11.py — 在 0x2e2ebc/0x2e2ecc/0x2e2ed0/0x2e2ee4/0x2e2ee8 打印寄存器
import struct, sys
from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED
from unicorn.arm64_const import *
from emu_v11 import Emu, DEV_BASE, IMG_SIZE

e = Emu()
e.fix_long_string(0x688130, b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv")

WATCH = {0x2e2eb8, 0x2e2ebc, 0x2e2ecc, 0x2e2ed0, 0x2e2ed4, 0x2e2ee4, 0x2e2ee8}

def hook_code(uc, address, size, ud):
    off = address - DEV_BASE
    if off in WATCH:
        x8 = uc.reg_read(UC_ARM64_REG_X8)
        x9 = uc.reg_read(UC_ARM64_REG_X9)
        x1 = uc.reg_read(UC_ARM64_REG_X1)
        extra = ""
        try:
            if DEV_BASE <= x8 < DEV_BASE + IMG_SIZE:
                v = struct.unpack("<Q", uc.mem_read(x8, 8))[0]
                extra = " [x8]=%#x" % v
        except Exception:
            pass
        print("  @%#x x8=%#018x x9=%#018x x1=%#018x%s" % (off, x8, x9, x1, extra))
e.uc.hook_add(UC_HOOK_CODE, hook_code, begin=DEV_BASE + 0x2e2e00, end=DEV_BASE + 0x2e2f00)

def hook_mem(uc, access, address, size, value, ud):
    pc = uc.reg_read(UC_ARM64_REG_PC)
    print("  FAULT pc=%#x access=%d addr=%#x size=%d" % (pc, access, address, size))
    return False
e.uc.hook_add(UC_HOOK_MEM_UNMAPPED, hook_mem)

# 打印关键数据
for off in (0x671ad8, 0x671ae0, 0x671ae8, 0x66efe0, 0x66efe8):
    print("  data[%#x] = %#018x" % (off, e.rd_u64(DEV_BASE + off)))

sret = e.alloc(0x40)
e.wr(sret, b"\0" * 0x40)
inp = e.mkstr("1790618586109")
try:
    e.call(DEV_BASE + 0x304eb0, (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148), sret=sret, timeout=60_000_000)
except Exception as ex:
    print("ERR", repr(ex))
print("logs:", e.logs[-10:])
