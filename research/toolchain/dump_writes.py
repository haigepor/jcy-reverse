# -*- coding: utf-8 -*-
# dump_writes.py — 记录 304eb0 期间对 HEAP 的写入, 事后聚焦输出缓冲区
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from unicorn import *
from unicorn.arm64_const import *
from v13 import Emu3, DEV_BASE, IMG_SIZE
from emu_v11 import HEAP, HEAP_SIZE

W = []
LIM = 400000


def on_write(uc, access, address, size, value, ud):
    if len(W) < LIM:
        W.append((uc.reg_read(UC_ARM64_REG_PC), address, size, value))
    return True


SRC = []


def on_code(uc, address, size, ud):
    if address == DEV_BASE + 0x2c9224:
        if len(SRC) < 4000:
            SRC.append((uc.reg_read(UC_ARM64_REG_X0), uc.reg_read(UC_ARM64_REG_X1)))


INPUT = os.environ.get("INPUT", "3.0.0.8-1790618586109-Android-1.5.8.0-16613a7076284a15bc723d018bcd67e1-default")


def main():
    e = Emu3()
    e.fix_long_string(0x688130, b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv")
    e.uc.hook_add(UC_HOOK_MEM_WRITE, on_write, begin=HEAP, end=HEAP + HEAP_SIZE)
    sret = e.alloc(0x40)
    e.wr(sret, b"\0" * 0x40)
    inp = e.mkstr(INPUT)
    err = None
    try:
        e.call(DEV_BASE + 0x304eb0, (inp, DEV_BASE + 0x688130, DEV_BASE + 0x688148),
               sret=sret, timeout=200_000_000)
    except Exception as ex:
        err = repr(ex)
    tag, ln, ptr = struct.unpack("<QQQ", e.rd(sret, 24))
    print("err:", err, "writes:", len(W))
    print("sret view: tag=%#x len=%#x ptr=%#x" % (tag, ln, ptr))
    data = e.rd(ptr, ln)
    print("out hex:", data.hex())
    print("out lat1:", data.decode("latin1"))
    print("--- writes touching [%#x,%#x) ---" % (ptr, ptr + ln))
    n = 0
    for pc, addr, size, val in W:
        if ptr <= addr < ptr + ln:
            off = addr - ptr
            if size <= 8:
                b = val.to_bytes(8, "little")[:size]
            else:
                b = b"?"
            print("  pc=%#x off=%d size=%d bytes=%s" % (pc - DEV_BASE, off, size,
                  b.hex() if isinstance(b, bytes) else b))
            n += 1
            if n > 200:
                break
    print("total touching writes:", n)


if __name__ == "__main__":
    main()
