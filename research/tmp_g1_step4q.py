# -*- coding: utf-8 -*-
"""tmp_g1_step4q.py — 从乘法轨迹重建 AES 状态/轮密钥。
每块 288 乘 = 9 轮 × 4 列 × 8 乘。列内 site 顺序：
  m1=2a m2=3b m3=2b m4=3c m5=2c m6=3d m7=3a m8=2d  → 列 (a,b,c,d)（post-SB）
  out0=2a^3b^c^d  out1=a^2b^3c^d  out2=a^b^2c^3d  out3=3a^b^c^2d
轮密钥: rk[r+1] = MC_out_r ^ invSB(postSB_{r+1})
"""
import os
import sys
import json

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from unicorn.arm64_const import (  # noqa: E402
    UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
    UC_ARM64_REG_X30, UC_ARM64_REG_PC,
)
from decrypt_e import EDecryptor, expand, xr, SB, ISB  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

MUL = DEV_BASE + 0x2D2F20
PREP = DEV_BASE + 0x2D9AD4
SITES = [DEV_BASE + o for o in
         (0x2D32AC, 0x2D32D4, 0x2D3740, 0x2D38D0,
          0x2D3B9C, 0x2D3C68, 0x2D3DD8, 0x2D402C)]
K = bytes(range(0x30, 0x40))
NBLK = 3

d = EDecryptor()
_, _, CONSTg, _ = d.calibrate(K, NBLK)
golden = [bytes(c) for c in CONSTg]

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

st = {"pending": None, "trace": [], "n": 0}


def on_mul(uc_, address, size, ud):
    st["pending"] = (
        uc_.reg_read(UC_ARM64_REG_X1) & 0xFF,
        uc_.reg_read(UC_ARM64_REG_X2) & 0xFF,
    )


def on_site(uc_, address, size, ud):
    if st["pending"] is None:
        return
    w0 = uc_.reg_read(UC_ARM64_REG_X0) & 0xFF
    c, b = st["pending"]
    st["trace"].append((c, b, w0))
    st["pending"] = None
    st["n"] += 1
    if st["n"] >= 288 * NBLK:
        uc_.emu_stop()


uc.hook_add(unicorn.UC_HOOK_CODE, on_mul, begin=MUL, end=MUL + 3)
for s in SITES:
    uc.hook_add(unicorn.UC_HOOK_CODE, on_site, begin=s, end=s + 3)

d._cap.clear()
try:
    uc.emu_start(uc.reg_read(UC_ARM64_REG_PC), 0, timeout=300 * 1000000,
                 count=12_000_000)
except Exception:
    pass

TR = st["trace"]
print("乘法轨迹 %d 条 (期望 %d)" % (len(TR), 288 * NBLK))

# 每块 36 组
gf2 = lambda x: ((x << 1) & 0xFF) ^ (0x1B if x & 0x80 else 0)
gf3 = lambda x: gf2(x) ^ x

rk_extracted = {}   # r -> set of candidate 16B keys
blocks = []
for blk in range(NBLK):
    tr = TR[blk * 288:(blk + 1) * 288]
    cols = []           # 36 列, 每列 (a,b,c,d)
    for g in range(36):
        m = tr[g * 8:(g + 1) * 8]
        # m[i] = (coef, byte, result)
        by = [x[1] for x in m]
        a, b_, c_, d_ = by[0], by[1], by[3], by[5]
        # 一致性检验
        ok = (m[2][1] == b_ and m[4][1] == c_ and m[6][1] == a and m[7][1] == d_
              and m[0][0] == 2 and m[1][0] == 3 and m[6][0] == 3 and m[7][0] == 2)
        col = (a, b_, c_, d_)
        cols.append((col, ok))
    if not all(ok for _, ok in cols):
        print("块 %d: 有 %d 列模式不符" % (blk, sum(1 for _, ok in cols if not ok)))
    blocks.append(cols)

# 轮重建（块 0）
blk = blocks[0]
print("\n=== 块0 各轮 post-SB 列（列序 g0..g35） ===")
for r in range(9):
    row = []
    for cix in range(4):
        col, _ = blk[r * 4 + cix]
        row.append("".join("%02x" % v for v in col))
    print("  r%d: %s" % (r, " ".join(row)))

# 轮密钥推导（假设列 g 按顺序 = 状态列 0..3，标准布局）
print("\n=== 推导轮密钥 vs expand(K) ===")
rk = expand(K)


def mc_out(col):
    a, b, c, dd = col
    return (
        gf2(a) ^ gf3(b) ^ c ^ dd,
        a ^ gf2(b) ^ gf3(c) ^ dd,
        a ^ b ^ gf2(c) ^ gf3(dd),
        gf3(a) ^ b ^ c ^ gf2(dd),
    )


for r in range(8):
    # 本轮 MC 输出（4 列）
    mc = [mc_out(blk[r * 4 + cix][0]) for cix in range(4)]
    mc_flat = [v for col in mc for v in col]
    # 下一轮 post-SB 的 pre-SB（注意布局：先按同序试）
    nxt = [blk[(r + 1) * 4 + cix][0] for cix in range(4)]
    nxt_flat = [v for col in nxt for v in col]
    preSB = bytes(ISB(list(nxt_flat)))
    cand = xr(bytes(mc_flat), preSB)
    print("  rk[%d]提取=%s  expand=%s  %s" % (
        r + 1, cand.hex(), bytes(rk[r + 1]).hex(),
        "✅" if cand == bytes(rk[r + 1]) else "❌"))

# 初始输入
mc0 = [mc_out(blk[cix][0]) for cix in range(4)]
mc0_flat = [v for col in mc0 for v in col]
nxt = [blk[cix][0] for cix in range(4)]
nxt_flat = [v for col in nxt for v in col]
preSB = bytes(ISB(list(nxt_flat)))
rk0_cand = xr(bytes(mc0_flat), preSB)     # = state0 ^ ... 不对——
# 实际: postSB_r1 = SB(input ^ rk0) → input ^ rk0 = invSB(postSB_r1)
print("\ninvSB(postSB_r1) = %s (= input^rk0)" % preSB.hex())
print("expand rk[0]     = %s" % bytes(rk[0]).hex())
print("input = preSB ^ rk0 = %s" % xr(preSB, bytes(rk[0])).hex())
print("\ngolden[0]=%s golden[1]=%s" % (golden[0].hex(), golden[1].hex()))
