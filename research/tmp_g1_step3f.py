# -*- coding: utf-8 -*-
"""tmp_g1_step3f.py — 计数器注入版隔离重放。
1) 主运行 snap@prep b=0,1,2 → 定位递增计数器单元（字节 0→1→2）
2) 隔离重放 j=0..7：恢复 b0 快照 + 计数器=j + x2/x22=j，跑到 4 次捕获
3) 对 pair 捕获测规则：直接/^iv/^ctd 切片/差分
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import numpy as np  # noqa: E402
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
_, _, CONSTg, _ = d.calibrate(K, NBLK)
golden = [bytes(c) for c in CONSTg]
iv = K[::-1]
ctd = d._enc_big(bytes(16 * NBLK), K, iv)     # 串行 ct 链
print("金料 CONST[0..7]: %s" % " ".join(g.hex()[:8] for g in golden))

# 新会话 + 快照（prep b=0,1,2）
d._o = None
d._uc = None
d._oracle()
uc = d._uc

snaps = []
cur_b = [0]


def on_snap(uc_, address, size, ud):
    b = cur_b[0]
    if b >= 6:
        return
    from unicorn.arm64_const import UC_ARM64_REG_X22 as _X22
    x22 = uc_.reg_read(_X22)
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
    snaps.append((b, x22, ctx, mem))
    cur_b[0] += 1
    print("[snap fire%d] x22=%d" % (b, x22))


h = uc.hook_add(unicorn.UC_HOOK_CODE, on_snap, begin=PREP, end=PREP + 3)
d._cap.clear()
d._enc_big(bytes(16 * NBLK), K, iv)
uc.hook_del(h)

# 定位计数器：从 fire1 起字节值 == x22 或 == x22-1（fire0 可能是初始化前垃圾）
cand = None
xs22 = [s[1] for s in snaps]
mems = [{m[0]: m[2] for m in s[3]} for s in snaps]
print("[x22 序列] %s" % xs22)
for rbase, data0 in mems[0].items():
    datas = [mm.get(rbase) for mm in mems]
    if any(dd is None for dd in datas):
        continue
    n = min(len(dd) for dd in datas)
    for i in range(n):
        vals = [dd[i] for dd in datas]
        if all(v == x for v, x in zip(vals[1:], xs22[1:])):
            cand = (rbase + i, "=x22")
        elif all(v == x - 1 for v, x in zip(vals[1:], xs22[1:])):
            cand = (rbase + i, "=x22-1")
        else:
            continue
        print("[计数器] %#x %s (值=%s, fire0=%02x)" % (
            cand[0], cand[1], vals[1:], vals[0]))
        break
    if cand:
        break
if cand is None:
    print("!! 未找到与 x22 同步的单字节单元；列出变化区域：")
    for rbase, data0 in mems[0].items():
        d1 = mems[1].get(rbase)
        if d1 is None:
            continue
        n = min(len(data0), len(d1))
        cnt = sum(1 for i in range(n) if data0[i] != d1[i])
        if cnt:
            print("   区域 %#x: %d 字节变化" % (rbase, cnt))
cand_addr = cand[0]
ctx0, mem0 = snaps[0][2], snaps[0][3]

# 隔离重放
bound_fires = [0]


def on_bound_stop(uc_, address, size, ud):
    bound_fires[0] += 1
    if bound_fires[0] >= 4:
        uc_.emu_stop()


h_stop = uc.hook_add(unicorn.UC_HOOK_CODE, on_bound_stop, begin=BOUND, end=BOUND + 4)

results = {}
for j in range(NBLK + 1):
    uc.context_restore(ctx0)
    for base, size, data in mem0:
        try:
            uc.mem_write(base, data)
        except Exception:
            pass
    uc.ctl_flush_tb()
    uc.mem_write(cand_addr, bytes([j]))
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
        err = repr(exc)[:50]
    dt = time.time() - t0
    caps = [bytes(T(list(c))) for c in d._cap]
    results[j] = (dt, caps)
    ccs = " ".join(c.hex()[:8] for c in caps[:4])
    print("[j=%d] %.0fms 捕获=%d %s err=%s" % (j, dt * 1000, len(caps), ccs, err or ""))

# 规则测试
print("\n=== 规则测试 ===")
for j in range(NBLK):
    dt, caps = results[j]
    if len(caps) < 4:
        print("  j=%d 捕获不足" % j)
        continue
    hits = []
    for ci in range(4):
        c = caps[ci]
        rules = [("direct", c), ("^iv", xr(c, iv))]
        for kb in range(min(4, NBLK)):
            rules.append(("^ct%d" % kb, xr(c, ctd[kb * 16:(kb + 1) * 16])))
        for nm, v in rules:
            if v == golden[j]:
                hits.append("cap%d:%s" % (ci, nm))
            if j + 1 < NBLK and v == golden[j + 1]:
                hits.append("cap%d:%s→g%d" % (ci, nm, j + 1))
    print("  j=%d %s" % (j, ",".join(hits) if hits else "无命中 c2=%s" % caps[2].hex()))

# 差分
print("\n=== pair2 差分 vs j=0 ===")
_, c0 = results[0]
if len(c0) >= 4:
    for j in range(1, NBLK + 1):
        dt, caps = results[j]
        if len(caps) >= 4:
            diff = xr(caps[2], c0[2])
            mark = "✅" if j < NBLK and diff == golden[j] else ""
            print("  j=%d diff=%s %s" % (j, diff.hex()[:32], mark))
