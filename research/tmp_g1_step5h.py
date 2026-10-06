# -*- coding: utf-8 -*-
"""tmp_g1_step5h.py — 扩到 260 键 → 全仿射重解（preSB0 直接拟合）."""
import os
import sys
import json
import random
import time

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
OUT = os.path.join(HERE, "reports", "gen_rks3.json")
TARGET = 260

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

data = json.load(open(OUT))
random.seed(20261005)
keys = [bytes.fromhex(k) for k in data]
while len(keys) < TARGET:
    k = bytes(random.randrange(256) for _ in range(16))
    if k.hex() in data:
        continue
    keys.append(k)

t0 = time.time()
new = 0
for idx, K in enumerate(keys):
    kh = K.hex()
    if kh in data and len(data[kh].get("rks", {})) >= 8:
        continue
    st.update(p=None, tr=[], n=0)
    d._cap.clear()
    ctd = d._enc_big(bytes(32), K, K[::-1])
    tr = st["tr"][:288]
    cols = [(tr[g * 8], tr[g * 8 + 1], tr[g * 8 + 3], tr[g * 8 + 5])
            for g in range(36)]
    pre0 = bytes(ISBOX[v] for col in cols[0:4] for v in col)
    caps = d._cap
    xs = [bytes(T(list(caps[i]))) for i in range(0, len(caps), 2)]
    consts = []
    for b in range(min(2, len(xs))):
        prev = ctd[b * 16 - 16:b * 16] if b else K[::-1]
        consts.append(xr(xr(xs[b], bytes(16)), prev).hex())
    rks = {}
    for r in range(8):
        nxt = [v for col in cols[(r + 1) * 4:(r + 2) * 4] for v in col]
        preSB = bytes(ISBOX[v] for v in nxt)
        mc = []
        for c4 in range(4):
            a, b2, cc, dd = cols[r * 4 + c4]
            mc.extend((_gmul(a, 2) ^ _gmul(b2, 3) ^ cc ^ dd,
                       a ^ _gmul(b2, 2) ^ _gmul(cc, 3) ^ dd,
                       a ^ b2 ^ _gmul(cc, 2) ^ _gmul(dd, 3),
                       _gmul(a, 3) ^ b2 ^ cc ^ _gmul(dd, 2)))
        rks[r + 1] = xr(bytes(mc), preSB).hex()
    data[kh] = {"preSB0": pre0.hex(), "rks": rks, "consts": consts}
    new += 1
    if new % 50 == 0:
        json.dump(data, open(OUT, "w"), indent=1)
        print("[%d] %.3fs/键" % (len(data), (time.time() - t0) / new), flush=True)
json.dump(data, open(OUT, "w"), indent=1)
print("总键数:", len(data))

# ---- 全仿射重解 ----
aff = json.load(open(os.path.join(HERE, "reports", "gen_affine.json")))


def solve_affine(pairs, tag):
    chk = {}
    for i in range(len(pairs)):
        xi = int.from_bytes(pairs[i][0], "big")
        yi = int.from_bytes(pairs[i][1], "big")
        for j in range(i + 1, len(pairs)):
            v = xi ^ int.from_bytes(pairs[j][0], "big")
            if v == 0:
                continue
            o = yi ^ int.from_bytes(pairs[j][1], "big")
            if v in chk and chk[v] != o:
                print("  %s: 差分矛盾!" % tag)
                return None, None, -1
            chk[v] = o
    piv = {}
    for v, o in chk.items():
        cur, ro = v, o
        for pbit, (pin, pout) in sorted(piv.items(), reverse=True):
            if cur >> pbit & 1:
                cur ^= pin
                ro ^= pout
        if cur:
            piv[cur.bit_length() - 1] = (cur, ro)
    rank = len(piv)
    if rank < 128:
        print("  %s: 秩 %d/128" % (tag, rank))
        return None, None, rank
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

    x0, y0 = pairs[0][0], pairs[0][1]
    c = int.from_bytes(y0, "big") ^ M(int.from_bytes(x0, "big"))
    bad = [p[2] for p, q in zip(pairs, pairs)
           if M(int.from_bytes(p[0], "big")) ^ c != int.from_bytes(p[1], "big")]
    print("  %s: 秩%d 验证失败 %d/%d" % (tag, rank, len(bad), len(pairs)))
    if bad:
        print("    失败键:", [b[:8] for b in bad[:8]])
    return emap, c, bad


items = []
for kh, rec in data.items():
    K = bytes.fromhex(kh)
    rks = {int(r): bytes.fromhex(v) for r, v in rec["rks"].items()}
    items.append({"kh": kh, "K": K, "preSB0": bytes.fromhex(rec["preSB0"]),
                  "rks": rks,
                  "g1": bytes.fromhex(rec["consts"][1]) if len(rec["consts"]) > 1 else None})

pairs_pre = [(it["K"], it["preSB0"], it["kh"]) for it in items]
emap, c, bad = solve_affine(pairs_pre, "preSB0")
out = {}
if emap is not None:
    out["preSB0"] = {"emap": {str(k): format(v, "x") for k, v in emap.items()},
                     "c": format(c, "x")}
for r in range(1, 9):
    emap, c, bad = solve_affine([(it["K"], it["rks"][r], it["kh"]) for it in items],
                                "rk%d" % r)
    if emap is not None:
        out.setdefault("rks", {})[str(r)] = {
            "emap": {str(k): format(v, "x") for k, v in emap.items()},
            "c": format(c, "x")}


def SBf(b):
    return bytes(__import__("decrypt_e").SBOX[x] for x in b)


def iSBf(b):
    return bytes(__import__("decrypt_e").ISBOX[x] for x in b)


def MCf(x):
    out = []
    for c4 in range(4):
        a, b, cc, dd = x[4 * c4:4 * c4 + 4]
        out.extend((_gmul(a, 2) ^ _gmul(b, 3) ^ cc ^ dd,
                    a ^ _gmul(b, 2) ^ _gmul(cc, 3) ^ dd,
                    a ^ b ^ _gmul(cc, 2) ^ _gmul(dd, 3),
                    _gmul(a, 3) ^ b ^ cc ^ _gmul(dd, 2)))
    return bytes(out)


pairsW = []
for it in items:
    st_ = it["preSB0"]
    for r in range(1, 9):
        st_ = xr(MCf(SBf(st_)), it["rks"][r])
    W = xr(iSBf(it["g1"]), MCf(SBf(st_)))
    pairsW.append((it["K"], W, it["kh"]))
emap, c, bad = solve_affine(pairsW, "W")
if emap is not None:
    out["W"] = {"emap": {str(k): format(v, "x") for k, v in emap.items()},
                "c": format(c, "x")}
json.dump(out, open(os.path.join(HERE, "reports", "gen_affine.json"), "w"), indent=1)
print("已存 gen_affine.json")
