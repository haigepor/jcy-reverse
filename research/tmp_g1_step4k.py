# -*- coding: utf-8 -*-
"""tmp_g1_step4k.py — churn 一轮的调用结构跟踪。
fire2 后单步采 20000 条指令：记录 blr/bl 的 (site→target) 边与每被调函数的指令数，
输出调用图摘要（被调函数 entry、次数、大小）。
"""
import os
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from unicorn.arm64_const import UC_ARM64_REG_PC  # noqa: E402
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402
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

uc.context_restore(ctx[0])
for base, size, data in mem0:
    try:
        uc.mem_write(base, data)
    except Exception:
        pass
uc.ctl_flush_tb()

st = {"phase": 0, "rec": False, "prev": 0, "n": 0, "trace": []}


def on_stop(uc_, address, size, ud):
    st["phase"] += 1
    if st["phase"] == 2:
        st["rec"] = True
    if st["phase"] >= 4:
        uc_.emu_stop()


h_stop = uc.hook_add(unicorn.UC_HOOK_CODE, on_stop, begin=BOUND, end=BOUND + 4)


def on_code(uc_, address, size, ud):
    if not st["rec"] or st["n"] >= 20000:
        return
    st["n"] += 1
    st["trace"].append(address)


h_code = uc.hook_add(unicorn.UC_HOOK_CODE, on_code, begin=DEV_BASE,
                     end=DEV_BASE + 0x800000)
d._cap.clear()
uc.emu_start(uc.reg_read(UC_ARM64_REG_PC), 0, timeout=180 * 1000000, count=3_000_000)
uc.hook_del(h_code)

trace = st["trace"]
print("跟踪 %d 条指令" % len(trace))

# 反汇编辅助（找 blr/bl）
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
code = next((bytes(data) for base, size, data in mem0
             if base <= DEV_BASE < base + size), None)


def ins_at(off):
    for i in md.disasm(code[off:off + 4], DEV_BASE + off):
        return i.mnemonic, i.op_str
    return "??", ""


# 边：trace[i] 是 bl/blr 目标入口，trace[i-1] = 调用点
edges = Counter()
body = defaultdict(int)      # entry -> 指令数（相邻两次入口之间的指令数）
entries = []
for i in range(1, len(trace)):
    prev_off = trace[i - 1] - DEV_BASE
    mn, _ = ins_at(prev_off) if 0 <= prev_off < len(code) else ("??", "")
    if mn in ("bl", "blr"):
        target = trace[i]
        edges[(trace[i - 1] - DEV_BASE, target - DEV_BASE)] += 1
        entries.append(target)

# 每个被调 entry 的体长：连续入口之间
seg = Counter()
seq = []
last = None
for t in entries:
    seq.append(t)
for a, b in zip(seq, seq[1:]):
    pass
# 统计 entry 频次与两次 entry 间指令数
cnt_entry = Counter(entries)
gaps = Counter()
for i in range(1, len(entries)):
    ia = trace.index(entries[i - 1]) if False else None
# 简化：直接给出 top 调用边 + top entry
print("\n=== TOP 调用边 (site → target) ×次数 ===")
for (s, t), c in edges.most_common(20):
    print("  +%#x → +%#x ×%d" % (s, t, c))
print("\n=== TOP 被调入口 ×次数 ===")
for t, c in cnt_entry.most_common(20):
    print("  +%#x ×%d" % (t - DEV_BASE, c))
