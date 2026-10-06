# -*- coding: utf-8 -*-
"""tmp_g1_step5b.py — 离线破解: preSB0 选择映射 + rk_r 仿射 + 末轮形式."""
import os
import json
import sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
from decrypt_e import xr, SBOX, ISBOX, _gmul  # noqa: E402

data = json.load(open(os.path.join(HERE, "reports", "gen_rks2.json")))
items = []
for kh, rec in data.items():
    K = bytes.fromhex(kh)
    iv = K[::-1]
    preSB0 = bytes.fromhex(rec["preSB0"])
    rks = {int(r): bytes.fromhex(v) for r, v in rec["rks"].items()}
    g1 = bytes.fromhex(rec["golden1"]) if rec.get("golden1") else None
    items.append({"K": K, "iv": iv, "preSB0": preSB0, "rks": rks, "g1": g1})
print("键数:", len(items))

# ---------- 1) preSB0 = iv ^ K[sel] 选择映射 ----------
cand = [set(range(16)) for _ in range(16)]
for it in items:
    D = xr(it["preSB0"], it["iv"])
    for p in range(16):
        cand[p] &= {j for j in range(16) if it["K"][j] == D[p]}
sel = [sorted(c) for c in cand]
print("选择映射候选:", sel)
ok = all(len(c) == 1 for c in sel)
if ok:
    sel = [c[0] for c in sel]
    bad = 0
    for it in items:
        pred = bytes(it["K"][sel[p]] ^ it["iv"][p] for p in range(16))
        if pred != it["preSB0"]:
            bad += 1
    print("preSB0 = iv ^ K[sel] 验证失败数:", bad, "/", len(items))
    json.dump(sel, open(os.path.join(HERE, "reports", "presb0_sel.json"), "w"))

# ---------- 2) rk_r(K) 仿射求解 ----------
def solve_affine(pairs):
    """pairs: [(x_bytes16, y_bytes16)] → (emap, c) 使 y = M·x ^ c; 需≥128独立差分"""
    chk = {}
    for i in range(len(pairs)):
        for j in range(i + 1, len(pairs)):
            di = xr(pairs[i][0], pairs[j][0])
            do = xr(pairs[i][1], pairs[j][1])
            v = int.from_bytes(di, "big")
            if v == 0:
                continue
            if v in chk and chk[v] != int.from_bytes(do, "big"):
                return None, None, v
            chk[v] = int.from_bytes(do, "big")
    piv = {}
    for v, o in chk.items():
        cur, ro = v, o
        for pbit, (pin, pout) in sorted(piv.items(), reverse=True):
            if cur >> pbit & 1:
                cur ^= pin
                ro ^= pout
        if cur:
            piv[cur.bit_length() - 1] = (cur, ro)
    if len(piv) < 128:
        return None, None, -len(piv)
    rows = sorted(piv.values(), key=lambda t: t[0].bit_length() - 1)
    for i in range(len(rows)):
        hb = rows[i][0].bit_length() - 1
        for j in range(len(rows)):
            if j != i and rows[j][0] >> hb & 1:
                rows[j] = (rows[j][0] ^ rows[i][0], rows[j][1] ^ rows[i][1])
    emap = {d.bit_length() - 1: o for d, o in rows}

    def M(v_int):
        out, vv, j = 0, v_int, 0
        while vv:
            if vv & 1:
                out ^= emap.get(j, 0)
            vv >>= 1
            j += 1
        return out

    x0, y0 = pairs[0]
    c = int.from_bytes(y0, "big") ^ M(int.from_bytes(x0, "big"))
    bad = sum(1 for x, y in pairs
              if M(int.from_bytes(x, "big")) ^ c != int.from_bytes(y, "big"))
    return emap, c, bad


print("\n=== rk_r(K) 仿射 ===")
aff = {}
for r in range(1, 9):
    pairs = [(it["K"], it["rks"][r]) for it in items if r in it["rks"]]
    emap, c, bad = solve_affine(pairs)
    if emap is None:
        print("  rk%d: 解失败 (信号 %s)" % (r, bad))
    else:
        print("  rk%d: 仿射成立, 验证失败 %d/%d" % (r, bad, len(pairs)))
        aff[r] = (emap, c)
json.dump({str(r): {"emap": {str(k): format(v, "x") for k, v in e.items()},
                     "c": format(c, "x")} for r, (e, c) in aff.items()},
          open(os.path.join(HERE, "reports", "gen_affine_rks.json"), "w"))

# ---------- 3) 末轮形式 H2: W = invSB(g1) ^ MC(postSB_8) ----------
def mc_all(post):
    out = []
    for c4 in range(4):
        a, b, cc, dd = post[4 * c4:4 * c4 + 4]
        out.extend((_gmul(a, 2) ^ _gmul(b, 3) ^ cc ^ dd,
                    a ^ _gmul(b, 2) ^ _gmul(cc, 3) ^ dd,
                    a ^ b ^ _gmul(cc, 2) ^ _gmul(dd, 3),
                    _gmul(a, 3) ^ b ^ cc ^ _gmul(dd, 2)))
    return bytes(out)


print("\n=== 末轮 H2 ===")
pairsW = []
for it in items:
    if it["g1"] is None or 8 not in it["rks"]:
        continue
    rk8 = it["rks"][8]
    post8 = xr(it["g1"] if False else b"", b"")  # placeholder
    # state_8 = MC(postSB_7) ^ rk8; postSB_8 = SB(state_8)
    # 需 postSB_7 → 从 rks 反推: rk7 = MC(postSB_7) ^ preSB8... 无 postSB_7
    pass
# 换路: state_8 可由 rk8 与 postSB_7 得, 但 postSB_7 未存.
# 直接用 rk8 表达: state_9 = MC(postSB_8) ^ rk9, postSB_8 = SB(state_8),
# state_8 = MC(postSB_7) ^ rk8 → 无法仅从 rks 得 postSB_8.
# ⇒ H2 改为: 存在仿射 rk9 使 g1 = SB(MC(postSB_8) ^ rk9). 先补收 postSB_8.
print("需要 postSB_8 — 由 rk 链反推缺 postSB_7, 转 step5c 补收")
