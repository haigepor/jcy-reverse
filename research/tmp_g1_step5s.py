# -*- coding: utf-8 -*-
"""tmp_g1_step5s.py — 验证 preSB_b = x_b ^ u(K) 假设 (x_b = dummy_b^ct_{b-1}^CONST_b)."""
import os
import sys
import json

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from unicorn.arm64_const import UC_ARM64_REG_X2  # noqa: E402
from decrypt_e import EDecryptor, ISBOX, xr, T, _gmul  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

MUL = DEV_BASE + 0x2D2F20
SITES = [DEV_BASE + o for o in
         (0x2D32AC, 0x2D32D4, 0x2D3740, 0x2D38D0,
          0x2D3B9C, 0x2D3C68, 0x2D3DD8, 0x2D402C)]

d = EDecryptor()
d._oracle()
uc = d._uc
st = {"p": None, "tr": [], "n": 0}
uc.hook_add(unicorn.UC_HOOK_CODE,
            lambda u_, a, s, ud: st.update(p=u_.reg_read(UC_ARM64_REG_X2) & 0xFF),
            begin=MUL, end=MUL + 3)


def on_site(u_, address, size, ud):
    if st["p"] is None:
        return
    st["tr"].append(st["p"])
    st["p"] = None
    st["n"] += 1


for s in SITES:
    uc.hook_add(unicorn.UC_HOOK_CODE, on_site, begin=s, end=s + 3)

NBLK = 6
gold = json.load(open(os.path.join(HERE, "reports", "const_golden.json")))
keys = [bytes.fromhex(k) for k in list(gold)[:3]] + [bytes(range(0x30, 0x40))]

for K in keys:
    iv = K[::-1]
    st.update(p=None, tr=[], n=0)
    d._cap.clear()
    dummy = bytes(16 * NBLK)
    ctd = d._enc_big(dummy, K, iv)
    caps = d._cap
    xs = [bytes(T(list(caps[i]))) for i in range(0, len(caps), 2)]
    consts = []
    for b in range(min(NBLK, len(xs))):
        prev = ctd[b * 16 - 16:b * 16] if b else iv
        consts.append(xr(xr(xs[b], dummy[b * 16:(b + 1) * 16]), prev))
    # x_b = dummy_b ^ ct_{b-1} ^ CONST_b  (pt=0)
    print("=== K=%s ===" % K.hex()[:8])
    uset = {}
    for b in range(min(NBLK, len(xs))):
        tr = st["tr"]
        # 块 b 的 churn 列
        cols = [(tr[(b * 36 + g) * 8], tr[(b * 36 + g) * 8 + 1],
                 tr[(b * 36 + g) * 8 + 3], tr[(b * 36 + g) * 8 + 5])
                for g in range(36)]
        pre = bytes(ISBOX[v] for col in cols[0:4] for v in col)
        xb = xr(xr(dummy[b * 16:(b + 1) * 16],
                   ctd[b * 16 - 16:b * 16] if b else iv), consts[b])
        u = xr(pre, xb)
        uset[b] = u
        print("  b=%d preSB=%s" % (b, pre.hex()))
        print("      x_b  =%s" % xb.hex())
        print("      u    =%s" % u.hex())
    vals = list(uset.values())
    same = all(v == vals[0] for v in vals)
    print("  u(K) 跨块恒定?", same)
    if not same:
        print("  u0^u1 =", xr(vals[0], vals[1]).hex())
