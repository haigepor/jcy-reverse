# -*- coding: utf-8 -*-
"""tmp_g1_step4u.py — 在 churn 各时间点扫内存，定位轮密钥调度表。"""
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from unicorn.arm64_const import UC_ARM64_REG_X2, UC_ARM64_REG_PC  # noqa: E402
from decrypt_e import EDecryptor, xr  # noqa: E402
from authgen import DEV_BASE  # noqa: E402
from tmp_g1_step4t import harvest, cols_of, extract_rks  # noqa: E402

K = bytes(range(0x30, 0x40))
d = EDecryptor()
d.calibrate(K, 1)
d._o = None
d._uc = None
d._oracle()
uc = d._uc

tr = harvest(K, 1)  # 独立实例跑出来的轨迹，用于得到 rk1..rk8
# 但 harvest 用了新实例——这里直接从 tr 提取
rks = extract_rks(tr, 0)
for r in sorted(rks):
    print("rk%d = %s" % (r, rks[r].hex()))

# 在 d._uc 里重新收割一次并定点扫描内存
st = {"n": 0}
targets = [rks[r] for r in (1, 2, 3)]


def scan_mem(tag):
    hits = {}
    for rbase, rend, _p in uc.mem_regions():
        sz = rend - rbase
        if sz > 64 * 1024 * 1024:
            continue
        try:
            data = bytes(uc.mem_read(rbase, sz))
        except Exception:
            continue
        for t in targets:
            for alt in (t, t[3::4] + t[2::4] + t[1::4] + t[0::4]):  # 原序+4B反转
                i = data.find(alt)
                while i != -1:
                    hits.setdefault(rbase + i, []).append((tag, alt[:4].hex()))
                    i = data.find(alt, i + 1)
    return hits


snap_pts = {"prep": [], "mid": [], "end": []}


def on_events(uc_, address, size, ud):
    pass


# 定点：在 PREP（churn 前）与第 144 列（中点）与 288 列（结束）扫描
PREP = 0x2D9AD4 + 0
st["phase"] = 0
marks = []

h = uc.hook_add(unicorn.UC_HOOK_CODE, lambda u, a, s, ud: marks.append(1),
                begin=DEV_BASE + 0x2D9AD4, end=DEV_BASE + 0x2D9AD4 + 3)

hits_prep = scan_mem("before-churn")
uc.hook_del(h)
print("\n[churn 前] 命中: %s" % (hits_prep or "无"))

# churn 期间: 跑到 288 mul 结束
st2 = {"pending": None, "n": 0, "done": False}


def on_mul(uc_, address, size, ud):
    st2["pending"] = uc_.reg_read(UC_ARM64_REG_X2) & 0xFF


def on_site(uc_, address, size, ud):
    if st2["pending"] is None:
        return
    st2["pending"] = None
    st2["n"] += 1
    if st2["n"] == 144 and not st2["done"]:
        st2["done"] = True
        h_ = scan_mem("mid")
        print("[churn 中] 命中: %s" % (h_ or "无"))
    if st2["n"] >= 288:
        uc_.emu_stop()


uc.hook_add(unicorn.UC_HOOK_CODE, on_mul, begin=DEV_BASE + 0x2D2F20,
            end=DEV_BASE + 0x2D2F20 + 3)
for s in (0x2D32AC, 0x2D32D4, 0x2D3740, 0x2D38D0,
          0x2D3B9C, 0x2D3C68, 0x2D3DD8, 0x2D402C):
    uc.hook_add(unicorn.UC_HOOK_CODE, on_site, begin=DEV_BASE + s,
                end=DEV_BASE + s + 3)
d._cap.clear()
try:
    uc.emu_start(uc.reg_read(UC_ARM64_REG_PC), 0, timeout=120 * 1000000,
                 count=15_000_000)
except Exception:
    pass
h_end = scan_mem("after")
print("[churn 后] 命中: %s" % (h_end or "无"))
