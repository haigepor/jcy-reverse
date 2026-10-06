# -*- coding: utf-8 -*-
"""tmp_g1_step5t.py — 解 preSB_b = P(x_b) ^ u(K) 的字节置换 P."""
import os
import sys
import json

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from unicorn.arm64_const import UC_ARM64_REG_X2  # noqa: E402
from decrypt_e import EDecryptor, ISBOX, xr, T  # noqa: E402
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
keys = [bytes.fromhex(k) for k in list(gold)[:4]]

all_u = {}
xdata = {}
for K in keys:
    iv = K[::-1]
    st.update(p=None, tr=[], n=0)
    d._cap.clear()
    dummy = bytes(16 * NBLK)
    ctd = d._enc_big(dummy, K, iv)
    caps = d._cap
    xs = [bytes(T(list(caps[i]))) for i in range(0, len(caps), 2)]
    pres, xbs = [], []
    for b in range(min(NBLK, len(xs))):
        prev = ctd[b * 16 - 16:b * 16] if b else iv
        cb = xr(xr(xs[b], dummy[b * 16:(b + 1) * 16]), prev)
        tr = st["tr"]
        cols = [(tr[(b * 36 + g) * 8], tr[(b * 36 + g) * 8 + 1],
                 tr[(b * 36 + g) * 8 + 3], tr[(b * 36 + g) * 8 + 5])
                for g in range(36)]
        pres.append(bytes(ISBOX[v] for col in cols[0:4] for v in col))
        xbs.append(xr(xr(dummy[b * 16:(b + 1) * 16],
                         ctd[b * 16 - 16:b * 16] if b else iv), cb))
    # T 转置的 x
    all_u[K.hex()] = (pres, xbs, xr(pres[0], bytes(T(list(xbs[0])))))

# u 恒定? (按 T(x) 假设)
for kh, (pres, xbs, u0) in all_u.items():
    K = bytes.fromhex(kh)
    ok = all(xr(pres[b], bytes(T(list(xbs[b])))) == u0 for b in range(len(pres)))
    print("K=%s u=T(x)^preSB 恒定? %s  u=%s" % (kh[:8], ok, u0.hex()))

# 经验置换: y_b = preSB_b ^ u0;  找 p→q 使 y_b[p]==x_b[q] 全块成立
print("\n=== 置换求解 (y = P(x)) ===")
for kh, (pres, xbs, u0) in all_u.items():
    yb = [xr(pres[b], u0) for b in range(len(pres))]
    mapping = {}
    for p in range(16):
        cands = [q for q in range(16)
                 if all(yb[b][p] == xbs[b][q] for b in range(len(xbs)))]
        mapping[p] = cands
    print("K=%s: %s" % (kh[:8], [c if len(c) == 1 else "?" for c in
                                 (mapping[p] for p in range(16))]))
    if all(len(c) == 1 for c in mapping.values()):
        print("   P =", [mapping[p][0] for p in range(16)])
