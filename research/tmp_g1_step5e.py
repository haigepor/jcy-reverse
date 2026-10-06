# -*- coding: utf-8 -*-
"""tmp_g1_step5e.py — 135 键数据质检 + 全仿射求解."""
import os
import json
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
from decrypt_e import xr, SBOX, ISBOX, _gmul, T  # noqa: E402

data = json.load(open(os.path.join(HERE, "reports", "gen_rks3.json")))
gold = json.load(open(os.path.join(HERE, "reports", "const_golden.json")))

# ---- 质检: 8 金料键的 consts[1] vs golden[1]; K=30..3f 的 preSB0 ----
print("=== 质检 ===")
K0 = bytes(range(0x30, 0x40)).hex()
if K0 in data:
    ok = data[K0]["preSB0"] == "0f0f0f0f0a000a0005050505000a000a"
    print("K=30..3f preSB0 匹配已知:", ok)
n_ok = 0
n_gold = 0
for kh, consts in ((k, data[k]["consts"]) for k in gold if k in data):
    if len(consts) > 1:
        n_gold += 1
        if consts[1] == gold[kh][1]:
            n_ok += 1
        else:
            print("  golden1 不符: K=%s got=%s want=%s"
                  % (kh[:8], consts[1][:16], gold[kh][1][:16]))
print("golden1 一致: %d/%d" % (n_ok, n_gold))

items = []
for kh, rec in data.items():
    K = bytes.fromhex(kh)
    items.append({"K": K, "iv": K[::-1],
                  "preSB0": bytes.fromhex(rec["preSB0"]),
                  "rks": {int(r): bytes.fromhex(v) for r, v in rec["rks"].items()},
                  "g1": bytes.fromhex(rec["consts"][1]) if len(rec["consts"]) > 1 else None})
print("样本:", len(items))


def solve_affine(pairs, tag):
    """y = M·x ^ c over GF(2)^128; 返回 (emap, c, bad) 或 (None,None,rank)"""
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
    if len(piv) < 128:
        print("  %s: 秩不足 %d/128" % (tag, len(piv)))
        return None, None, len(piv)
    rows = sorted(piv.values(), key=lambda t: t[0].bit_length() - 1)
    for i in range(len(rows)):
        hb = rows[i][0].bit_length() - 1
        for j in range(len(rows)):
            if j != i and rows[j][0] >> hb & 1:
                rows[j] = (rows[j][0] ^ rows[i][0], rows[j][1] ^ rows[i][1])
    emap = {d.bit_length() - 1: o for d, o in rows}

    def M(v):
        out, vv, jj = 0, v, 0
        while vv:
            if vv & 1:
                out ^= emap.get(jj, 0)
            vv >>= 1
            jj += 1
        return out

    x0i = int.from_bytes(pairs[0][0], "big")
    y0i = int.from_bytes(pairs[0][1], "big")
    c = y0i ^ M(x0i)
    bad = sum(1 for x, y in pairs
              if M(int.from_bytes(x, "big")) ^ c != int.from_bytes(y, "big"))
    print("  %s: 仿射成立, 验证失败 %d/%d" % (tag, bad, len(pairs)))
    return emap, c, bad


def SBf(b):
    return bytes(SBOX[x] for x in b)


def iSBf(b):
    return bytes(ISBOX[x] for x in b)


def MCf(x):
    out = []
    for c4 in range(4):
        a, b, cc, dd = x[4 * c4:4 * c4 + 4]
        out.extend((_gmul(a, 2) ^ _gmul(b, 3) ^ cc ^ dd,
                    a ^ _gmul(b, 2) ^ _gmul(cc, 3) ^ dd,
                    a ^ b ^ _gmul(cc, 2) ^ _gmul(dd, 3),
                    _gmul(a, 3) ^ b ^ cc ^ _gmul(dd, 2)))
    return bytes(out)


out = {}
print("\n=== D(K) = preSB0 ^ iv 仿射 ===")
emap, c, bad = solve_affine([(it["K"], xr(it["preSB0"], it["iv"])) for it in items],
                            "preSB0^iv")
if emap:
    out["preSB0"] = {"emap": {str(k): format(v, "x") for k, v in emap.items()},
                     "c": format(c ^ int.from_bytes(bytes(items[0]["iv"]), "big"), "x")}
    # 存成 preSB0 = M·K ^ c (把 iv 并入常数)
    x0, y0 = items[0]["K"], items[0]["preSB0"]
    out["preSB0"] = {"emap": {str(k): format(v, "x") for k, v in emap.items()},
                     "c": format(int.from_bytes(y0, "big")
                                 ^ sum(((int.from_bytes(y0, "big") >> 0) & 0,)), "x")}
    # 重新算: preSB0 = M·K ^ c2, c2 = preSB0_0 ^ M·K_0
    Mk0 = 0
    vv, jj = int.from_bytes(x0, "big"), 0
    while vv:
        if vv & 1:
            Mk0 ^= emap.get(jj, 0)
        vv >>= 1
        jj += 1
    out["preSB0"] = {"emap": {str(k): format(v, "x") for k, v in emap.items()},
                     "c": format(int.from_bytes(y0, "big") ^ Mk0, "x")}

print("\n=== rk_r(K) 仿射 ===")
out["rks"] = {}
for r in range(1, 9):
    emap, c, bad = solve_affine([(it["K"], it["rks"][r]) for it in items],
                                "rk%d" % r)
    if emap:
        out["rks"][str(r)] = {"emap": {str(k): format(v, "x") for k, v in emap.items()},
                              "c": format(c, "x")}

print("\n=== W(K) 末轮仿射 ===")
pairsW = []
for it in items:
    st_ = it["preSB0"]
    for r in range(1, 9):
        st_ = xr(MCf(SBf(st_)), it["rks"][r])
    post8 = SBf(st_)
    W = xr(iSBf(it["g1"]), MCf(post8))
    pairsW.append((it["K"], W))
emap, c, bad = solve_affine(pairsW, "W")
if emap:
    out["W"] = {"emap": {str(k): format(v, "x") for k, v in emap.items()},
                "c": format(c, "x")}

json.dump(out, open(os.path.join(HERE, "reports", "gen_affine.json"), "w"), indent=1)
print("\n已存 gen_affine.json:", {k: (list(v.keys()) if isinstance(v, dict) else "ok")
                                  for k, v in out.items()})
