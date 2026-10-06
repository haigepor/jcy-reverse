# -*- coding: utf-8 -*-
"""tmp_g1_step4a.py — churn 热循环剖析。
隔离重放（块0快照起，跑到 4 次捕获），全程采：
  - PC 直方图（代码钩子）
  - 读/写地址直方图（mem 钩子，64B 桶）
输出 top PC / top 读 / top 写，并反汇编 top PC 邻域。
"""
import os
import sys
import time
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from unicorn.arm64_const import UC_ARM64_REG_PC  # noqa: E402
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402
from decrypt_e import EDecryptor, T  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

PREP = DEV_BASE + 0x2D9AD4
BOUND = DEV_BASE + 0x2DA498
K = bytes(range(0x30, 0x40))
NBLK = 2

d = EDecryptor()
d.calibrate(K, NBLK)
d._o = None
d._uc = None
d._oracle()
uc = d._uc

snap_ctx = [None]
snap_mem = []


def on_snap(uc_, address, size, ud):
    if snap_ctx[0] is not None:
        return
    snap_ctx[0] = uc_.context_save()
    for rbase, rend, _perms in uc_.mem_regions():
        sz = rend - rbase
        if sz > 64 * 1024 * 1024:
            continue
        try:
            snap_mem.append((rbase, sz, bytes(uc_.mem_read(rbase, sz))))
        except Exception:
            pass


h_snap = uc.hook_add(unicorn.UC_HOOK_CODE, on_snap, begin=PREP, end=PREP + 3)
d._cap.clear()
d._enc_big(bytes(16 * NBLK), K, K[::-1])
uc.hook_del(h_snap)

# ---- 剖析运行
pc_hist = Counter()
rd_hist = Counter()
wr_hist = Counter()


def on_code(uc_, address, size, ud):
    pc_hist[address] += 1


def on_rd(uc_, access, address, size, value, ud):
    rd_hist[address & ~0x3F] += 1


def on_wr(uc_, access, address, size, value, ud):
    wr_hist[address & ~0x3F] += 1


h_code = uc.hook_add(unicorn.UC_HOOK_CODE, on_code, begin=DEV_BASE,
                     end=DEV_BASE + 0x800000)
h_rd = uc.hook_add(unicorn.UC_HOOK_MEM_READ, on_rd, begin=1 << 20, end=(1 << 47) - 1)
h_wr = uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, on_wr, begin=1 << 20, end=(1 << 47) - 1)

# 恢复快照重放
uc.context_restore(snap_ctx[0])
for base, size, data in snap_mem:
    try:
        uc.mem_write(base, data)
    except Exception:
        pass
uc.ctl_flush_tb()

bound_fires = [0]


def on_stop(uc_, address, size, ud):
    bound_fires[0] += 1
    if bound_fires[0] >= 4:
        uc_.emu_stop()


h_stop = uc.hook_add(unicorn.UC_HOOK_CODE, on_stop, begin=BOUND, end=BOUND + 4)
d._cap.clear()
t0 = time.time()
uc.emu_start(uc.reg_read(UC_ARM64_REG_PC), 0, timeout=120 * 1000000, count=3_000_000)
print("[剖析] %.1fs, PC 桶=%d, 读桶=%d, 写桶=%d, 捕获=%d" % (
    time.time() - t0, len(pc_hist), len(rd_hist), len(wr_hist), len(d._cap)))

# ---- 输出
print("\n=== TOP 24 PC（域内偏移） ===")
for addr, cnt in pc_hist.most_common(24):
    print("  +%#x ×%d" % (addr - DEV_BASE, cnt))

print("\n=== TOP 20 读（64B 桶） ===")
for addr, cnt in rd_hist.most_common(20):
    print("  %#x ×%d" % (addr, cnt))

print("\n=== TOP 20 写（64B 桶） ===")
for addr, cnt in wr_hist.most_common(20):
    print("  %#x ×%d" % (addr, cnt))

# ---- 反汇编 top PC 邻域
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
code_map = {}
for base, size, data in snap_mem:
    if base <= DEV_BASE + 0x300000 <= base + size:
        code_map = (base, data)
        break

if code_map:
    b0, data = code_map

    def dis(off, before=8, after=12):
        s = max(0, off - before * 4)
        e_ = min(len(data), off + after * 4)
        out = []
        for ins in md.disasm(bytes(data[s:e_]), b0 + s):
            mark = " ←" if ins.address == b0 + off else ""
            out.append("  %#x %s %s%s" % (ins.address, ins.mnemonic, ins.op_str, mark))
        return "\n".join(out)

    print("\n=== 热点反汇编（top3） ===")
    for addr, cnt in pc_hist.most_common(3):
        print("\n-- PC +%#x ×%d --" % (addr - DEV_BASE, cnt))
        print(dis(addr - b0))
