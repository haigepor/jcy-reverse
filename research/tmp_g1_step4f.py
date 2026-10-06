# -*- coding: utf-8 -*-
"""tmp_g1_step4f.py — churn 起始段微跟踪。
从块0快照重放，fire-2（churn 起点）后继续单步采 3000 条指令的内存读写（带值），
打印前 N 条，用于还原每字节操作 g 的数据流。
"""
import os
import sys
import struct
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from unicorn.arm64_const import UC_ARM64_REG_PC  # noqa: E402
from decrypt_e import EDecryptor  # noqa: E402
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

ctx = [None]
mem0 = []


def on_snap(uc_, address, size, ud):
    if ctx[0] is not None:
        return
    ctx[0] = uc_.context_save()
    for rbase, rend, _perms in uc_.mem_regions():
        sz = rend - rbase
        if sz > 64 * 1024 * 1024:
            continue
        try:
            mem0.append((rbase, sz, bytes(uc_.mem_read(rbase, sz))))
        except Exception:
            pass


h = uc.hook_add(unicorn.UC_HOOK_CODE, on_snap, begin=PREP, end=PREP + 3)
d._cap.clear()
d._enc_big(bytes(16 * NBLK), K, K[::-1])
uc.hook_del(h)

# 重放：fire1 过后（pair1 完成）开始记录，采 3000 条指令
uc.context_restore(ctx[0])
for base, size, data in mem0:
    try:
        uc.mem_write(base, data)
    except Exception:
        pass
uc.ctl_flush_tb()

state = {"phase": 0, "n": 0, "log": []}


def on_stop(uc_, address, size, ud):
    # fire 计数：第 2 次捕获点 = pair1 完成 → 开始记录
    state["phase"] += 1
    if state["phase"] == 2:
        state["rec"] = True


h_stop = uc.hook_add(unicorn.UC_HOOK_CODE, on_stop, begin=BOUND, end=BOUND + 4)


def on_rd(uc_, access, address, size, value, ud):
    if state.get("rec") and state["n"] < 3000:
        state["n"] += 1
        state["log"].append(("R", uc_.reg_read(UC_ARM64_REG_PC) - DEV_BASE,
                             address, size, value))


def on_wr(uc_, access, address, size, value, ud):
    if state.get("rec") and state["n"] < 3000:
        state["n"] += 1
        state["log"].append(("W", uc_.reg_read(UC_ARM64_REG_PC) - DEV_BASE,
                             address, size, value))


h_rd = uc.hook_add(unicorn.UC_HOOK_MEM_READ, on_rd, begin=1 << 20, end=(1 << 47) - 1)
h_wr = uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, on_wr, begin=1 << 20, end=(1 << 47) - 1)

d._cap.clear()
uc.emu_start(uc.reg_read(UC_ARM64_REG_PC), 0, timeout=120 * 1000000, count=1_000_000)
print("记录 %d 条内存访问" % len(state["log"]))

# 打印前 120 条
seen_tables = Counter()
for kind, pc, addr, size, val in state["log"][:120]:
    if addr >= DEV_BASE and addr - DEV_BASE < 0x800000:
        tag = "DEV+%#x" % (addr - DEV_BASE)
    else:
        tag = "%#x" % addr
    if kind == "R":
        b = val.to_bytes(8, "little")[:size] if size <= 8 else b""
        v = b.hex()
        seen_tables[tag] += 1
    else:
        v = ("%0*x" % (size * 2, val))
    print("%s pc=+%#x %s sz=%d val=%s" % (kind, pc, tag, size, v))

print("\n读写地址分布（记录段）:")
for tag, cnt in Counter(
        ("DEV+%#x" % (a - DEV_BASE)) if (a >= DEV_BASE and a - DEV_BASE < 0x800000)
        else ("%#x" % a)
        for _, _, a, _, _ in state["log"]).most_common(20):
    print("  %s ×%d" % (tag, cnt))
