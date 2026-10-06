# -*- coding: utf-8 -*-
"""tmp_g1_step4i.py — churn 专属剖析：fire2→fire4 之间 PC 直方图，区分调度器/计算块。"""
import os
import sys
from collections import Counter

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

st = {"phase": 0, "rec": False}
pc_hist = Counter()


def on_stop(uc_, address, size, ud):
    st["phase"] += 1
    st["rec"] = st["phase"] >= 2      # fire2 之后开始记录
    if st["phase"] >= 4:
        uc_.emu_stop()                # fire4 停（nblk=2 全部块）


def on_code(uc_, address, size, ud):
    if st["rec"]:
        pc_hist[address] += 1


h_stop = uc.hook_add(unicorn.UC_HOOK_CODE, on_stop, begin=BOUND, end=BOUND + 4)
h_code = uc.hook_add(unicorn.UC_HOOK_CODE, on_code, begin=DEV_BASE,
                     end=DEV_BASE + 0x800000)
d._cap.clear()
uc.emu_start(uc.reg_read(UC_ARM64_REG_PC), 0, timeout=180 * 1000000, count=6_000_000)
total = sum(pc_hist.values())
print("churn 段指令数=%d, PC 桶=%d" % (total, len(pc_hist)))

# 读代码段用于反汇编
code = None
for base, size, data in mem0:
    if base == DEV_BASE or (base <= DEV_BASE < base + size):
        code = (base, bytes(data))
        break
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
cb, cd = code


def dis_at(off, n=6):
    out = []
    for ins in md.disasm(cd[off:off + n * 4], cb + off):
        out.append("%s %s" % (ins.mnemonic, ins.op_str))
    return " ; ".join(out)


# 调度器特征：csel+br / tst+lsr / movk 高位表
def is_dispatcher(off):
    txt = dis_at(off, 5)
    return "csel" in txt or "br x" in txt or "movk" in txt


print("\n=== TOP 30 PC（标注调度器/计算） ===")
nd = 0
for addr, cnt in pc_hist.most_common(60):
    off = addr - cb
    disp = is_dispatcher(off)
    tag = "DSP" if disp else "CALC"
    if not disp:
        nd += 1
    if not disp or cnt > 100000:
        print("  [{}] {} ×{} : {}".format(tag, hex(off), cnt, dis_at(off, 5)))
    if nd >= 30:
        break
