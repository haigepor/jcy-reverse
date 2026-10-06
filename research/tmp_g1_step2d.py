# -*- coding: utf-8 -*-
"""tmp_g1_step2d.py — B批：工作区偏移差分 + 热点循环反汇编。

B1: 只挂 0x2d9ed0 入口（分段）+ 内存写钩子（近原生速度），
    对两个相邻块的生成器段按 x4 基址偏移比较写入值 → 每块重算的 K 常量占比。
B2: capstone 反汇编 2304 次热点循环（+0x2d2fac、+0x2d3024）及调用点 +0x2d745c。
"""
import os
import sys
import time
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from unicorn.arm64_const import UC_ARM64_REG_X4  # noqa: E402
from decrypt_e import EDecryptor  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

GEN = DEV_BASE + 0x2D9ED0
HEAP_LO = 0x50000000
K = bytes(range(0x30, 0x40))

d = EDecryptor()
d._oracle()
uc = d._uc

gseg = [0]
x4cur = [0]
wr = defaultdict(list)   # seg -> [(off_from_x4, size, value)]  (仅堆写)
x4s = {}


def on_gen(uc_, address, size, ud):
    gseg[0] += 1
    x4cur[0] = uc_.reg_read(UC_ARM64_REG_X4)
    x4s[gseg[0]] = x4cur[0]


def on_write(uc_, access, address, size, value, ud):
    if HEAP_LO <= address < 0x51000000 and gseg[0] > 0:
        wr[gseg[0]].append((address - x4cur[0], size, value & ((1 << (size * 8)) - 1)))


uc.hook_add(unicorn.UC_HOOK_CODE, on_gen, begin=GEN, end=GEN + 4)
uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, on_write)

t0 = time.time()
C, rk, CONST, Cb = d.calibrate(K, 4)
print("标定 %.1fs, 段=%d" % (time.time() - t0, gseg[0]))
print("段 x4:", {s: hex(v - 0x50000000) for s, v in sorted(x4s.items())})

# 每段指令数未知（没挂 code 计数），用段字节数与写入次数近似挑真实块段：
stats = {s: (len(wr[s]), sum(sz for _, sz, _ in wr[s]),
             max((o for o, _, _ in wr[s]), default=0)) for s in sorted(wr)}
for s in sorted(stats):
    n, byt, mx = stats[s]
    print("  段%-3d 写%5d 次 %7d 字节 最大偏移 %#x" % (s, n, byt, mx))


def wmap(seg):
    m = defaultdict(list)
    for off, sz, v in wr[seg]:
        m[(off, sz)].append(v)
    return m


# 选两个「最大偏移相近且 >0x1000」的段（真实块体）
cands = [s for s in sorted(stats) if stats[s][2] > 0x800]
if len(cands) >= 2:
    sa, sb = cands[-2], cands[-1]
else:
    sa, sb = cands[0], cands[-1]
m1, m2 = wmap(sa), wmap(sb)
common = set(m1) & set(m2)
same = [k for k in common if m1[k][-1] == m2[k][-1]]
bytes_same = sum(k[1] for k in same)
bytes_all = sum(k[1] for k in m1)
print("\n=== B1: 段%d vs 段%d（x4 偏移对齐） ===" % (sa, sb))
print("  (off,size) 键: %d vs %d, 交集 %d (%.1f%%), 末值相同 %d (%.1f%% of 交集)" % (
    len(m1), len(m2), len(common), 100.0 * len(common) / max(1, len(m1)),
    len(same), 100.0 * len(same) / max(1, len(common))))
print("  按键字节数: 相同 %d / 全部 %d = %.1f%%" % (
    bytes_same, bytes_all, 100.0 * bytes_same / max(1, bytes_all)))
for k in same[:12]:
    print("    off=%#x size=%d val=%#x (重复%d次)" % (k[0], k[1], m1[k][-1], len(m1[k])))

# === B2: capstone 反汇编热点 ===
print("\n=== B2: 反汇编 ===")
try:
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
    from emu_v11 import IMG_SIZE
    code = None
    # 从已映射内存直接读
    for (addr, size_val) in [(DEV_BASE + 0x2D2F80, 0xE0), (DEV_BASE + 0x2D7420, 0x80)]:
        print("--- +%#x ---" % (addr - DEV_BASE))
        try:
            data = uc.mem_read(addr, size_val)
            for i in md.disasm(bytes(data), addr):
                print("  +%05x  %-8s %s" % (i.address - DEV_BASE, i.mnemonic, i.op_str))
        except Exception as ex:
            print("  读取失败: %r" % ex)
except ImportError:
    print("  capstone 不可用")
