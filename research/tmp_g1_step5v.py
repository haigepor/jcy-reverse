# -*- coding: utf-8 -*-
"""tmp_g1_step5v.py — 随机明文扩展差分空间, 解满秩 M."""
import os
import sys
import json
import random

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

gold = json.load(open(os.path.join(HERE, "reports", "const_golden.json")))
random.seed(31337)
keys = [bytes.fromhex(k) for k in list(gold)[:6]]
NBLK = 12

pairs = []
for K in keys:
    iv = K[::-1]
    for run in range(8):
        pt = bytes(random.randrange(256) for _ in range(16 * NBLK))
        st.update(p=None, tr=[], n=0)
        d._cap.clear()
        ctd = d._enc_big(pt, K, iv)
        caps = d._cap
        xs = [bytes(T(list(caps[i]))) for i in range(0, len(caps), 2)]
        for b in range(min(NBLK, len(xs))):
            prev = ctd[b * 16 - 16:b * 16] if b else iv
            cb = xr(xr(xs[b], pt[b * 16:(b + 1) * 16]), prev)
            tr = st["tr"]
            cols = [(tr[(b * 36 + g) * 8], tr[(b * 36 + g) * 8 + 1],
                     tr[(b * 36 + g) * 8 + 3], tr[(b * 36 + g) * 8 + 5])
                    for g in range(36)]
            pre = bytes(ISBOX[v] for col in cols[0:4] for v in col)
            xb = xr(xr(pt[b * 16:(b + 1) * 16],
                       ctd[b * 16 - 16:b * 16] if b else iv), cb)
            pairs.append((xb, pre, K, run))
print("配对数:", len(pairs))

diffs = {}
ok = True
for i in range(len(pairs)):
    for j in range(i + 1, len(pairs)):
        if pairs[i][2] != pairs[j][2]:
            continue
        dx = xr(pairs[i][0], pairs[j][0])
        dy = xr(pairs[i][1], pairs[j][1])
        v = int.from_bytes(dx, "big")
        if v == 0:
            continue
        o = int.from_bytes(dy, "big")
        if v in diffs and diffs[v] != o:
            print("M 差分矛盾!", dx.hex(), dy.hex(), diffs[v].hex())
            ok = False
            break
        diffs[v] = o
    if not ok:
        break
print("唯一差分:", len(diffs), "一致?", ok)

if ok:
    piv = {}
    for v, o in diffs.items():
        cur, ro = v, o
        for pbit, (pin, pout) in sorted(piv.items(), reverse=True):
            if cur >> pbit & 1:
                cur ^= pin
                ro ^= pout
        if cur:
            piv[cur.bit_length() - 1] = (cur, ro)
    print("秩:", len(piv))
    if len(piv) == 128:
        rows = sorted(piv.values(), key=lambda t: t[0].bit_length() - 1)
        for i in range(len(rows)):
            hb = rows[i][0].bit_length() - 1
            for j in range(len(rows)):
                if j != i and rows[j][0] >> hb & 1:
                    rows[j] = (rows[j][0] ^ rows[i][0], rows[j][1] ^ rows[i][1])
        emap = {dd.bit_length() - 1: o for dd, o in rows}

        def M(v):
            out, vv, jj = 0, v, 0
            while vv:
                if vv & 1:
                    out ^= emap.get(jj, 0)
                vv >>= 1
                jj += 1
            return out

        us = {}
        bad = 0
        for xb, pre, K, run in pairs:
            u = int.from_bytes(pre, "big") ^ M(int.from_bytes(xb, "big"))
            us.setdefault(K.hex(), set()).add(u)
        for kh, s in us.items():
            print("K=%s u 取值数: %d %s" % (kh[:8], len(s),
                  format(next(iter(s)), "x")))
        json.dump({"emap": {str(k): format(v, "x") for k, v in emap.items()},
                   "u": {kh: format(next(iter(s)), "x") for kh, s in us.items()}},
                  open(os.path.join(HERE, "reports", "gen_M.json"), "w"))
        print("已存 gen_M.json")
