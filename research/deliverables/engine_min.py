# -*- coding: utf-8 -*-
# engine_min.py — 最小内存引擎: 只加载 libcore + 8MB 设备数据段 + 字母表/密钥两小块
import os, sys, struct
HERE = os.path.dirname(os.path.abspath(__file__))
TOOLCHAIN = os.path.abspath(os.path.join(HERE, "..", "toolchain"))
sys.path.insert(0, TOOLCHAIN)
from unicorn import *
from unicorn.arm64_const import *
from emu_v11 import Emu, DEV_BASE, IMG_SIZE

ALPHABET = b'5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
ALPHA_ADDR = 0x737e41dc2a40          # singleton+0x18 指向的字母表
KEY_ADDR = 0x737de0fc2ce0            # 0x688130 长字符串对象的 data 指针


class EmuMin(Emu):
    """Emu + 只补两块设备内存 (字母表 64B / 密钥 32B), 不加载 regions_all。"""

    def __init__(self, *a, **kw):
        self.faults = []
        self.mem_faults = []
        super().__init__(*a, **kw)
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, self._on_unmapped)
        self._patch_min()

    def _on_unmapped(self, uc, access, address, size, value, ud):
        pc = uc.reg_read(UC_ARM64_REG_PC)
        self.faults.append((access, address, size, pc))
        self.mem_faults.append(address)
        return False

    def _patch_min(self):
        # 字母表 64B (供 cipher 的 KSA 使用)
        self._put(ALPHA_ADDR, ALPHABET)
        # 密钥字符串 32B
        self._put(KEY_ADDR, b"ziISjqkXPsGUMRNGyWigxDGtJbfTdcGv")

    def _put(self, addr, data):
        base = addr & ~0xFFF
        size = ((addr + len(data) + 0xFFF) & ~0xFFF) - base
        try:
            self.uc.mem_map(base, size, UC_PROT_ALL)
        except UcError:
            pass
        self.uc.mem_write(addr, data)


if __name__ == "__main__":
    import time
    t0 = time.time()
    e = EmuMin()
    print("EmuMin 就绪 %.1fs  faults=%d" % (time.time() - t0, len(e.faults)))
    print("字母表读回:", e.rd(ALPHA_ADDR, 64))
