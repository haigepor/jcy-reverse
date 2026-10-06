# -*- coding: utf-8 -*-
"""tmp_g1_step3d.py — 决定性两问：
  Q1: nblk=8 时隔离重放 j=0..7 是否全部可行（调度数组是否按 nblk 预建）？
  Q2: 第一次 prep 的快照内存里是否已存在全部 CONST_b（tweak 表预生成）？
      若是 → 标定=直接读内存，微秒级。
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from unicorn.arm64_const import (  # noqa: E402
    UC_ARM64_REG_X2, UC_ARM64_REG_X22, UC_ARM64_REG_PC,
)
from decrypt_e import EDecryptor, xr, T  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

PREP = DEV_BASE + 0x2D9AD4
BOUND = DEV_BASE + 0x2DA498
K = bytes(range(0x30, 0x40))
NBLK = 8

d = EDecryptor()
C_, rk_, CONSTg, Cbg = d.calibrate(K, NBLK)
golden = [bytes(c) for c in CONSTg]
iv = K[::-1]
ctd8 = d._enc_big(bytes(16 * NBLK), K, iv)   # 串行 ct（金料链）
print("金料 CONST[0..7]:")
for b in range(NBLK):
    print("  [%d] %s" % (b, golden[b].hex()))

# 强制新会话 + 快照钩子
d._o = None
d._uc = None
d._oracle()
uc = d._uc
e = d._o.s.e

snap_ctx = [None]
snap_mem = []


def on_snap(uc_, address, size, ud):
    if snap_ctx[0] is not None:
        return
    ctx = uc_.context_save()
    mem = []
    for rbase, rend, _perms in uc_.mem_regions():
        size = rend - rbase
        if size > 64 * 1024 * 1024:
            continue
        try:
            data = bytes(uc_.mem_read(rbase, size))
        except Exception:
            continue
        mem.append((rbase, size, data))
    snap_ctx[0] = ctx
    snap_mem[:] = mem
    print("[snap] %d 区域 %.1fMB" % (len(mem), sum(s for _, s, _ in mem) / 1048576))


h_snap = uc.hook_add(unicorn.UC_HOOK_CODE, on_snap, begin=PREP, end=PREP + 4)
d._cap.clear()
d._enc_big(bytes(16 * NBLK), K, iv)
uc.hook_del(h_snap)

# ---- Q2: 快照内存全量扫 golden[1..7]（含 T 变体）
print("\n=== Q2: 快照内存扫描 golden ===")
allmem = bytearray()
ranges = []
for base, size, data in snap_mem:
    ranges.append((base, len(data)))
    allmem += data


def find_pattern(pat):
    hits = []
    i = allmem.find(pat)
    while i != -1 and len(hits) < 6:
        # 折算绝对地址
        for base, size in ranges:
            if i < size:
                hits.append(base + i)
                break
            i -= size
        i = allmem.find(pat, i + 1)
    return hits


for b in range(1, NBLK):
    for name, pat in (("raw", golden[b]), ("T", bytes(T(list(golden[b]))))):
        hits = find_pattern(pat)
        tag = "存在" if hits else "无"
        print("  CONST[%d] %s: %s %s" % (b, name, tag,
              [hex(h) for h in hits[:3]]))

# ---- Q1: 隔离重放 j=0..9
print("\n=== Q1: 隔离重放 j=0..9 ===")
bound_fires = [0]


def on_bound_stop(uc_, address, size, ud):
    bound_fires[0] += 1
    if bound_fires[0] >= 4:
        uc_.emu_stop()


h_stop = uc.hook_add(unicorn.UC_HOOK_CODE, on_bound_stop, begin=BOUND, end=BOUND + 4)

results = {}
for j in range(NBLK + 2):
    uc.context_restore(snap_ctx[0])
    for base, size, data in snap_mem:
        try:
            uc.mem_write(base, data)
        except Exception:
            pass
    uc.ctl_flush_tb()
    bound_fires[0] = 0
    d._cap.clear()
    uc.reg_write(UC_ARM64_REG_X2, j)
    uc.reg_write(UC_ARM64_REG_X22, j)
    pc0 = uc.reg_read(UC_ARM64_REG_PC)
    t0 = time.time()
    err = None
    try:
        uc.emu_start(pc0, 0, timeout=30 * 1000000, count=3_000_000)
    except Exception as exc:
        err = repr(exc)[:60]
    dt = time.time() - t0
    caps = [bytes(T(list(c))) for c in d._cap]
    results[j] = (dt, caps)
    print("[j=%d] %.0fms 捕获=%d err=%s" % (j, dt * 1000, len(caps), err))
    if len(caps) >= 4:
        print("      c0=%s c2=%s" % (caps[0].hex()[:16] + "..", caps[2].hex()))

# 差分与直接对照
print("\n=== 差分/对照 ===")
_, xs0 = results[0]
base2 = xs0[2] if len(xs0) >= 4 else None
for j in range(NBLK):
    dt, xs = results[j]
    if len(xs) < 4:
        continue
    diff = xr(xs[2], base2) if base2 else None
    hit = "✅差分" if diff == golden[j] else ""
    direct = "✅c2直读" if xs[2] == golden[j] else ""
    print("  j=%d diff=%s %s %s 金料=%s" % (
        j, diff.hex()[:16] + ".." if diff else "-", hit, direct, golden[j].hex()[:16] + ".."))
