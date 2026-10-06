# -*- coding: utf-8 -*-
"""tmp_g1_step3g.py — 寄存器扫描定位流水线状态。
方法：恢复 snap0（块0上下文+内存），把候选寄存器逐个设为 snap1（块1入口）的值，
     跑到 pair-1（2 次捕获）。若 cap0 ^ iv == golden[1]（或 cap0==golden[1]），
     该寄存器携带块流水线状态。
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from unicorn.arm64_const import (  # noqa: E402
    UC_ARM64_REG_X0, UC_ARM64_REG_X2, UC_ARM64_REG_X22, UC_ARM64_REG_PC,
    UC_ARM64_REG_SP,
)
from decrypt_e import EDecryptor, xr, T  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

PREP = DEV_BASE + 0x2D9AD4
BOUND = DEV_BASE + 0x2DA498
K = bytes(range(0x30, 0x40))
NBLK = 4

d = EDecryptor()
_, _, CONSTg, _ = d.calibrate(K, NBLK)
golden = [bytes(c) for c in CONSTg]
iv = K[::-1]
print("golden[1]=%s" % golden[1].hex())

d._o = None
d._uc = None
d._oracle()
uc = d._uc

snaps = []
cur_b = [0]
XREGS = [UC_ARM64_REG_X0 + i for i in range(31)]


def on_snap(uc_, address, size, ud):
    b = cur_b[0]
    if b >= 2:
        return
    regs = {i: uc_.reg_read(XREGS[i]) for i in range(31)}
    regs[100] = uc_.reg_read(UC_ARM64_REG_SP)
    ctx = uc_.context_save()
    mem = []
    for rbase, rend, _perms in uc_.mem_regions():
        sz = rend - rbase
        if sz > 64 * 1024 * 1024:
            continue
        try:
            mem.append((rbase, sz, bytes(uc_.mem_read(rbase, sz))))
        except Exception:
            continue
    snaps.append((b, regs, ctx, mem))
    cur_b[0] += 1


h = uc.hook_add(unicorn.UC_HOOK_CODE, on_snap, begin=PREP, end=PREP + 3)
d._cap.clear()
d._enc_big(bytes(16 * NBLK), K, iv)
uc.hook_del(h)

_, regs0, ctx0, mem0 = snaps[0]
_, regs1, _, _ = snaps[1]
diff_regs = [i for i in list(range(31)) + [100] if regs0[i] != regs1[i]]
print("差异寄存器: %s" % ["x%d" % i if i < 31 else "sp" for i in diff_regs])

bound_fires = [0]


def on_bound_stop(uc_, address, size, ud):
    bound_fires[0] += 1
    if bound_fires[0] >= 2:
        uc_.emu_stop()


h_stop = uc.hook_add(unicorn.UC_HOOK_CODE, on_bound_stop, begin=BOUND, end=BOUND + 4)

CANDS = [i for i in diff_regs if i not in (2, 22)]  # x2/x22 已排除


def replay(patches):
    uc.context_restore(ctx0)
    for base, size, data in mem0:
        try:
            uc.mem_write(base, data)
        except Exception:
            pass
    uc.ctl_flush_tb()
    for ri, val in patches.items():
        uc.reg_write(XREGS[ri] if ri < 31 else UC_ARM64_REG_SP, val)
    bound_fires[0] = 0
    d._cap.clear()
    uc.emu_start(uc.reg_read(UC_ARM64_REG_PC), 0, timeout=10 * 1000000,
                 count=2_000_000)
    caps = [bytes(T(list(c))) for c in d._cap]
    return caps


# 基线
caps = replay({})
print("[基线] cap0=%s" % (caps[0].hex()[:16] + ".." if caps else "无"))

for ri in CANDS:
    caps = replay({ri: regs1[ri]})
    name = "x%d" % ri if ri < 31 else "sp"
    if caps:
        hit1 = xr(caps[0], iv) == golden[1]
        hit2 = caps[0] == golden[1]
        tag = "✅✅ 命中!" if (hit1 or hit2) else ""
        print("[x%s] cap0=%s cap1=%s %s" % (
            name.lstrip("x"), caps[0].hex()[:16] + "..",
            (caps[1].hex()[:16] + "..") if len(caps) > 1 else "-", tag))
    else:
        print("[%s] 无捕获" % name)
