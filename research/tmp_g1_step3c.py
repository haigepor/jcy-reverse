# -*- coding: utf-8 -*-
"""tmp_g1_step3c.py — 块级独立重放可行性验证。

流程：
  1) 先 d.calibrate(K,4) 得串行金料 CONST_golden
  2) 复刻 calibrate 主运行，在主运行第一次 prep(0x2d9ad4) 入口拍全量快照
     （UC context + 全部映射内存）
  3) 从快照恢复，对 j=0..5：设 x2=w22=j，从 prep 入口跑到下一次 prep（单块），
     收集 0x2DA498 的 x_b 捕获
  4) 用三种提取规则对照金料：
       R1: CONST_b = x'_b ^ iv          （缓冲区未被污染时 b>=2 成立）
       R2: x'_b 直接 = CONST_b
       R3: 解密用的 every-other 规则
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import struct  # noqa: E402
import unicorn  # noqa: E402
from unicorn.arm64_const import (  # noqa: E402
    UC_ARM64_REG_X2, UC_ARM64_REG_X22, UC_ARM64_REG_PC,
)
from decrypt_e import EDecryptor, xr, T  # noqa: E402
from authgen import DEV_BASE  # noqa: E402
from emu_v11 import HEAP, HEAP_SIZE  # noqa: E402

PREP = DEV_BASE + 0x2D9AD4
BOUND = DEV_BASE + 0x2DA498
K = bytes(range(0x30, 0x40))
NBLK = 4

d = EDecryptor()
d._oracle()
uc = d._uc
e = d._o.s.e

# ---- 1) 串行金料
Cg, rkg, CONSTg, Cbg = d.calibrate(K, NBLK)
golden = [bytes(c) for c in CONSTg]
iv = K[::-1]
print("金料 CONST[0..3]:")
for b in range(NBLK):
    print("  [%d] %s" % (b, golden[b].hex()))

# ---- 2) 带快照的主运行（强制新会话：上一步 calibrate 已消耗堆，避免中途重建甩掉钩子）
d._o = None
d._uc = None
d._oracle()
uc = d._uc
e = d._o.s.e

snap_ctx = [None]
snap_mem = []
prep_fires = [0]


def on_snap(uc_, address, size, ud):
    if snap_ctx[0] is not None:
        return
    prep_fires[0] += 1
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
    print("[snap] 在主运行第一次 prep 拍快照: %d 区域 %.1fMB" % (
        len(mem), sum(s for _, s, _ in mem) / 1048576))


h_snap = uc.hook_add(unicorn.UC_HOOK_CODE, on_snap, begin=PREP, end=PREP + 4)

# 复刻 calibrate 主体（_determine_C 已被上面 calibrate 跑过并缓存，不影响）
rk = rkg
dummy = bytes(16 * NBLK)
d._cap.clear()
ctd = d._enc_big(dummy, K, iv)

uc.hook_del(h_snap)
if snap_ctx[0] is None:
    print("!! 未拍到快照（主运行没有触发 prep？）")
    sys.exit(1)

# ---- 3) 隔离重放：在 0x2DA498 捕获到 x_b 后停机
bound_fires = [0]


def on_bound_stop(uc_, address, size, ud):
    bound_fires[0] += 1
    if bound_fires[0] >= 4:          # 抓 4 次看完整模式
        uc_.emu_stop()


h_stop = uc.hook_add(unicorn.UC_HOOK_CODE, on_bound_stop, begin=BOUND, end=BOUND + 4)

results = {}
ins_count = [0]


def on_count(uc_, address, size, ud):
    ins_count[0] += 1


h_count = uc.hook_add(unicorn.UC_HOOK_CODE, on_count, begin=DEV_BASE, end=DEV_BASE + 0x800000)
for j in range(NBLK + 2):
    # 恢复快照
    uc.context_restore(snap_ctx[0])
    for base, size, data in snap_mem:
        try:
            uc.mem_write(base, data)
        except Exception:
            pass
    uc.ctl_flush_tb()
    bound_fires[0] = 0
    d._cap.clear()
    ins_count[0] = 0
    uc.reg_write(UC_ARM64_REG_X2, j)
    uc.reg_write(UC_ARM64_REG_X22, j)
    pc0 = uc.reg_read(UC_ARM64_REG_PC)
    t0 = time.time()
    err = None
    try:
        uc.emu_start(pc0, 0, timeout=30 * 1000000, count=3_000_000)
    except Exception as exc:
        err = repr(exc)
    dt = time.time() - t0
    pc1 = uc.reg_read(UC_ARM64_REG_PC)
    caps = list(d._cap)
    xs = [bytes(T(list(c))) for c in caps]
    results[j] = (dt, xs)
    print("[重放 b=%d] %.0fms ins=%d pc %#x→%#x 捕获=%d err=%s faults=%d" % (
        j, dt * 1000, ins_count[0], pc0 - DEV_BASE, pc1 - DEV_BASE, len(xs), err,
        len(e.faults)))
    e.faults.clear()

for h in (h_count, h_stop):
    try:
        uc.hook_del(h)
    except KeyError:
        pass

# ---- 4) 提取规则对照
print("\n=== 各 j 的捕获对比（前 4 次, T 后） ===")
for j in range(NBLK + 2):
    dt, xs = results[j]
    if len(xs) >= 4:
        print("  b=%d c0=%s c1=%s c2=%s c3=%s" % (
            j, xs[0].hex()[:16] + "..", xs[1].hex()[:16] + "..",
            xs[2].hex()[:32], xs[3].hex()[:32]))

print("\n=== 差分假设: CONST_j =? c2(j) ^ c2(0) ===")
_, xs0 = results[0]
if len(xs0) >= 4:
    base = xs0[2]
    for j in range(1, NBLK + 2):
        dt, xs = results[j]
        if len(xs) >= 4:
            diff = xr(xs[2], base)
            ok = "✅" if (j < NBLK and diff == golden[j]) else ("—" if j >= NBLK else "❌")
            print("  %s b=%d diff=%s 金料=%s" % (
                ok, j, diff.hex()[:32], golden[j].hex()[:32] if j < NBLK else "-"))

print("\n=== 对照金料 ===")


def flat(caps_list):
    return caps_list


for j in range(NBLK):
    dt, xs = results[j]
    if not xs:
        print("b=%d: 无捕获" % j)
        continue
    for name, cand in [
        ("x'[:1]", xs[0]),
        ("x'[-1]", xs[-1]),
        ("x'[^iv]", xr(xs[0], iv)),
        ("x'[-1]^iv", xr(xs[-1], iv)),
    ]:
        if cand == golden[j]:
            print("  ✅ b=%d: %s 命中 (%.0fms)" % (j, name, dt * 1000))
            break
    else:
        print("  ❌ b=%d: 各规则均不匹配; x'[0]=%s" % (j, xs[0].hex()[:32]))
print("\n金料[1] %s" % golden[1].hex()[:32])
