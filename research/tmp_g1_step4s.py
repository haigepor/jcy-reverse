# -*- coding: utf-8 -*-
"""tmp_g1_step4s.py — 调度公式数据驱动求解。
对 8 把金料 K：emu 收割块0的 288 乘 → 重建 postSB 列 → 提取 rk[1..8]
→ 检验调度假设（标准expand的K变体 / SB(rot(w))^rc 的 σ 表一致性）。
同时 3 块输入差分找计数器编码。
"""
import os
import sys
import json

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from unicorn.arm64_const import (  # noqa: E402
    UC_ARM64_REG_X2, UC_ARM64_REG_X30, UC_ARM64_REG_PC,
)
from decrypt_e import EDecryptor, expand, xr, T, SBOX, ISBOX, _gmul  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

MUL = DEV_BASE + 0x2D2F20
PREP = DEV_BASE + 0x2D9AD4
SITES = [DEV_BASE + o for o in
         (0x2D32AC, 0x2D32D4, 0x2D3740, 0x2D38D0,
          0x2D3B9C, 0x2D3C68, 0x2D3DD8, 0x2D402C)]


def harvest(K, nblk):
    """收割 nblk 块的乘法字节轨迹（每块 288）。返回 [byte]* (288*nblk)。"""
    d = EDecryptor()
    d.calibrate(K, nblk)
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
    d._enc_big(bytes(16 * nblk), K, K[::-1])
    uc.hook_del(h)
    uc.context_restore(ctx[0])
    for base, size, data in mem0:
        try:
            uc.mem_write(base, data)
        except Exception:
            pass
    uc.ctl_flush_tb()

    st = {"pending": None, "tr": [], "n": 0}

    def on_mul(uc_, address, size, ud):
        st["pending"] = uc_.reg_read(UC_ARM64_REG_X2) & 0xFF

    def on_site(uc_, address, size, ud):
        if st["pending"] is None:
            return
        st["tr"].append(st["pending"])
        st["pending"] = None
        st["n"] += 1
        if st["n"] >= 288 * nblk:
            uc_.emu_stop()

    uc.hook_add(unicorn.UC_HOOK_CODE, on_mul, begin=MUL, end=MUL + 3)
    for s in SITES:
        uc.hook_add(unicorn.UC_HOOK_CODE, on_site, begin=s, end=s + 3)
    d._cap.clear()
    try:
        uc.emu_start(uc.reg_read(UC_ARM64_REG_PC), 0, timeout=300 * 1000000,
                     count=15_000_000)
    except Exception:
        pass
    return st["tr"]


def cols_of(tr, blk):
    out = []
    for g in range(36):
        by = tr[blk * 288 + g * 8: blk * 288 + g * 8 + 8]
        out.append((by[0], by[1], by[3], by[5]))
    return out


def mc_out(col):
    a, b, c, dd = col
    return (
        _gmul(a, 2) ^ _gmul(b, 3) ^ c ^ dd,
        a ^ _gmul(b, 2) ^ _gmul(c, 3) ^ dd,
        a ^ b ^ _gmul(c, 2) ^ _gmul(dd, 3),
        _gmul(a, 3) ^ b ^ c ^ _gmul(dd, 2),
    )


def state_from_cols(cols, transposed):
    s = [0] * 16
    for gi, col in enumerate(cols):
        r = gi % 4
        cc = gi // 4
        if transposed:
            for k, v in enumerate(col):
                s[4 * ((r + k) % 4) + cc] = v
        else:
            for k, v in enumerate(col):
                s[4 * cc + k] = v
    return s


def extract_rks(tr, blk):
    """从块轨迹提取 rk[1..8]（列主序布局）。返回 dict r->16B。"""
    cols = cols_of(tr, blk)
    rks = {}
    for r in range(8):
        mc = [mc_out(cols[r * 4 + c]) for c in range(4)]
        mc_flat = [v for col in mc for v in col]
        nxt = [cols[(r + 1) * 4 + c] for c in range(4)]
        nxt_flat = [v for col in nxt for v in col]
        preSB = bytes(ISBOX[v] for v in nxt_flat)
        rks[r + 1] = xr(bytes(mc_flat), preSB)
    return rks


gold = json.load(open(os.path.join(HERE, "reports", "const_golden.json")))
keys = [bytes.fromhex(k) for k in gold]

# --- 3 块输入差分（K0）
K0 = keys[0]
tr3 = harvest(K0, 3)
print("=== K0 三块输入（preSB = invSB(r1 postSB)） ===")
preSBs = []
for b in range(3):
    cols = cols_of(tr3, b)
    s = bytes(v for col in cols[0:4] for v in col)
    preSB = bytes(ISBOX[v] for v in s)
    preSBs.append(preSB)
    iv = K0[::-1]
    print("  块%d preSB=%s" % (b, preSB.hex()))
    print("       ^iv   =%s" % xr(preSB, iv).hex())
print("  preSB1^preSB0 = %s" % xr(preSBs[1], preSBs[0]).hex())
print("  preSB2^preSB0 = %s" % xr(preSBs[2], preSBs[0]).hex())

# --- 8 把 K 的 rk 提取
all_rks = {}
for K in keys:
    tr = harvest(K, 1)
    all_rks[K] = extract_rks(tr, 0)
    print("K=%s rk1=%s" % (K.hex()[:8], all_rks[K][1].hex()))

# --- 调度假设检验
print("\n=== 调度 t_r = rk[r+1]^rk[r] 的 word0 与 σ(rot(rk[r][3]))^rc 一致性 ===")
sigma = {}       # byte -> set of candidates
consistent = True
samples = []
for K in keys:
    rks = all_rks[K]
    for r in range(1, 8):
        t0 = xr(rks[r + 1][:4], rks[r][:4])
        w3 = rks[r][12:16]
        # rot 变体
        for name, rot in (("l1", w3[1:] + w3[:1]), ("r1", w3[-1:] + w3[:-1]),
                          ("none", w3)):
            samples.append((name, rot, t0))
print("样本数=%d" % len(samples))

# 解 σ（假设 t0 = σ(rot) ^ rc，rc 已知 per r：r=1→01, r=2→02...）
RC = [0x01]
for _ in range(9):
    RC.append(_xt := ((RC[-1] << 1) ^ 0x1B) & 0xFF if RC[-1] & 0x80 else RC[-1] << 1)
RC = RC[:10]

for name in ("l1", "r1", "none"):
    sig = {}
    ok = True
    for r in range(1, 8):
        for K in keys:
            rks = all_rks[K]
            t0 = xr(rks[r + 1][:4], rks[r][:4])
            w3 = rks[r][12:16]
            rot = {"l1": w3[1:] + w3[:1], "r1": w3[-1:] + w3[:-1],
                   "none": w3}[name]
            for bi in range(4):
                inp, outp = rot[bi], t0[bi] ^ (RC[r] if bi == 0 else 0)
                if inp in sig and sig[inp] != outp:
                    ok = False
                sig.setdefault(inp, outp)
    print("rot=%s: σ 一致? %s (映射 %d 项)" % (name, ok, len(sig)))
    if ok:
        json.dump({"%02x" % k: "%02x" % v for k, v in sig.items()},
                  open(os.path.join(HERE, "reports", "sigma_table.json"), "w"))
        print("  σ 表已存 reports/sigma_table.json")
