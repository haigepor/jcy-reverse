# -*- coding: utf-8 -*-
"""tmp_g1_step3e.py — 主运行 prep b=0..3 逐块内存差分 + 寄存器跟踪。
目标：定位 (a) 块计数器内存单元 (b) 位置指针 (c) golden[b] 何时出现在内存何处
     (d) w22/x2 语义复核。
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import numpy as np  # noqa: E402
import unicorn  # noqa: E402
from unicorn.arm64_const import (  # noqa: E402
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7,
    UC_ARM64_REG_X8, UC_ARM64_REG_X9, UC_ARM64_REG_X10, UC_ARM64_REG_X11,
    UC_ARM64_REG_X12, UC_ARM64_REG_X13, UC_ARM64_REG_X14, UC_ARM64_REG_X15,
    UC_ARM64_REG_X16, UC_ARM64_REG_X17, UC_ARM64_REG_X18, UC_ARM64_REG_X19,
    UC_ARM64_REG_X20, UC_ARM64_REG_X21, UC_ARM64_REG_X22, UC_ARM64_REG_X23,
    UC_ARM64_REG_X24, UC_ARM64_REG_X25, UC_ARM64_REG_X26, UC_ARM64_REG_X27,
    UC_ARM64_REG_X28, UC_ARM64_REG_X29, UC_ARM64_REG_X30, UC_ARM64_REG_PC,
    UC_ARM64_REG_SP,
)
from decrypt_e import EDecryptor, T  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

PREP = DEV_BASE + 0x2D9AD4
K = bytes(range(0x30, 0x40))
NBLK = 4

d = EDecryptor()
_, _, CONSTg, _ = d.calibrate(K, NBLK)
golden = [bytes(c) for c in CONSTg]
iv = K[::-1]

d._o = None
d._uc = None
d._oracle()
uc = d._uc

snaps = []      # [(b, regs dict, [(base,size,bytes)])]
cur_b = [0]
XREGS = [UC_ARM64_REG_X0 + i for i in range(31)]


def on_snap(uc_, address, size, ud):
    b = cur_b[0]
    if b >= NBLK:
        return
    regs = {"x%d" % i: uc_.reg_read(XREGS[i]) for i in range(31)}
    regs["sp"] = uc_.reg_read(UC_ARM64_REG_SP)
    regs["pc"] = uc_.reg_read(UC_ARM64_REG_PC)
    mem = []
    for rbase, rend, _perms in uc_.mem_regions():
        sz = rend - rbase
        if sz > 64 * 1024 * 1024:
            continue
        try:
            mem.append((rbase, sz, bytes(uc_.mem_read(rbase, sz))))
        except Exception:
            continue
    snaps.append((b, regs, mem))
    cur_b[0] += 1
    print("[snap b=%d] 完成" % b)


h = uc.hook_add(unicorn.UC_HOOK_CODE, on_snap, begin=PREP, end=PREP + 3)
d._cap.clear()
d._enc_big(bytes(16 * NBLK), K, iv)
uc.hook_del(h)
ctd = d._enc_big(bytes(16 * NBLK), K, iv) if False else None

# ---- 寄存器跨块对比
print("\n=== 寄存器跨块差异（prep 入口） ===")
if len(snaps) >= 2:
    _, r0, _ = snaps[0]
    keys = list(r0.keys())
    for k in keys:
        vals = [s[1][k] for s in snaps]
        if len(set(vals)) > 1:
            print("  %-4s %s" % (k, " ".join("%012x" % (v & 0xFFFFFFFFFFFF) for v in vals)))

# ---- 逐块内存差分（按区域对齐）
print("\n=== 内存差分（相邻 prep 间） ===")

if len(snaps) >= 2:
    for idx in range(1, len(snaps)):
        b = snaps[idx][0]
        prev_map = {m[0]: m[2] for m in snaps[idx - 1][2]}
        cur_map = {m[0]: m[2] for m in snaps[idx][2]}
        total_changed = 0
        region_reports = []
        for rbase, cur_data in cur_map.items():
            prev_data = prev_map.get(rbase)
            if prev_data is None:
                region_reports.append((len(cur_data), rbase, None, cur_data))
                continue
            n = min(len(prev_data), len(cur_data))
            a = np.frombuffer(prev_data[:n], dtype=np.uint8)
            c = np.frombuffer(cur_data[:n], dtype=np.uint8)
            diff = np.nonzero(a != c)[0]
            if len(diff) == 0:
                continue
            total_changed += len(diff)
            regions = []
            s0 = int(diff[0])
            pv = s0
            for off in diff[1:]:
                off = int(off)
                if off - pv > 64:
                    regions.append((s0, pv))
                    s0 = off
                pv = off
            regions.append((s0, pv))
            for r0, r1 in regions:
                region_reports.append((
                    r1 - r0 + 1, rbase + r0,
                    prev_data[r0:r1 + 1], cur_data[r0:r1 + 1]))
        region_reports.sort(key=lambda t: -t[0])
        print("  b=%d→%d: 共 %d 字节变化 / %d 小区域" % (
            b - 1, b, total_changed, len(region_reports)))
        for sz, addr, o, nn in region_reports[:20]:
            os_ = o.hex()[:28] if o is not None else "新增"
            print("    %#x (%dB): %s → %s" % (addr, sz, os_, nn.hex()[:28]))
        # golden 是否已出现
        for gb in range(1, NBLK):
            for bb, sz2, data in snaps[idx][2]:
                off = data.find(golden[gb])
                if off != -1:
                    print("    [snap b=%d] golden[%d] @ %#x" % (b, gb, bb + off))
                    break
                if gb < b:
                    print("    [snap b=%d] golden[%d] 未出现!!" % (b, gb))
                    break
