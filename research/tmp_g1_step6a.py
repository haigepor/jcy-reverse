# -*- coding: utf-8 -*-
"""tmp_g1_step6a.py — u 空间统一仿射求解: rk_r, W ← affine(u)."""
import os
import json
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
from decrypt_e import xr, SBOX, ISBOX, _gmul  # noqa: E402

MJ = json.load(open(os.path.join(HERE, "reports", "gen_M.json")))
emapM = {int(k): int(v, 16) for k, v in MJ["emap"].items()}


def Mmap(v_int):
    out, vv, j = 0, v_int, 0
    while v_int:
        if v_int & 1:
            out ^= emapM.get(j, 0)
        v_int >>= 1
        j += 1
    return out


data = json.load(open(os.path.join(HERE, "reports", "gen_rks3.json")))


def solve_affine(pairs, tag):
    """pairs: [(x_int, y_int)] → (emap, c, bad_count, rank)"""
    chk = {}
    for i in range(len(pairs)):
        xi, yi = pairs[i]
        for j in range(i + 1, len(pairs)):
            v = xi ^ pairs[j][0]
            if v == 0:
                continue
            o = yi ^ pairs[j][1]
            if v in chk and chk[v] != o:
                print("  %s: 差分矛盾!" % tag)
                return None, None, -1, -1
            chk[v] = o
    piv = {}
    for v, o in chk.items():
        cur, ro = v, o
        for pbit in sorted(piv, reverse=True):
            if cur >> pbit & 1:
                pin, pout = piv[pbit]
                cur ^= pin
                ro ^= pout
        if cur:
            piv[cur.bit_length() - 1] = (cur, ro)
    rank = len(piv)
    if rank < 128:
        print("  %s: 秩 %d/128" % (tag, rank))
        return None, None, -1, rank
    # 完整 RREF
    rows = sorted(piv.values(), key=lambda t: t[0].bit_length() - 1)
    for i in range(len(rows)):
        hb = rows[i][0].bit_length() - 1
        for j in range(len(rows)):
            if j != i and (rows[j][0] >> hb) & 1:
                rows[j] = (rows[j][0] ^ rows[i][0], rows[j][1] ^ rows[i][1])
    emap = {dd.bit_length() - 1: o for dd, o in rows}
    assert all(dd.bit_count() == 1 for dd, _ in rows), "归约失败"

    def M(v):
        out, vv, jj = 0, v, 0
        while vv:
            if vv & 1:
                out ^= emap.get(jj, 0)
            vv >>= 1
            jj += 1
        return out

    x0, y0 = pairs[0]
    c = y0 ^ M(x0)
    bad = sum(1 for x, y in pairs if M(x) ^ c != y)
    print("  %s: 秩%d 验证失败 %d/%d" % (tag, rank, bad, len(pairs)))
    return emap, c, bad, rank


samples = []
for kh, rec in data.items():
    K = bytes.fromhex(kh)
    iv = K[::-1]
    u = int.from_bytes(xr(bytes.fromhex(rec["preSB0"]),
                          Mmap(int.from_bytes(iv, "big")).to_bytes(16, "big")),
                       "big")
    samples.append({"kh": kh, "u": u,
                    "rks": {int(r): int.from_bytes(bytes.fromhex(v), "big")
                            for r, v in rec["rks"].items()},
                    "g1": int.from_bytes(bytes.fromhex(rec["consts"][1]), "big")
                    if len(rec["consts"]) > 1 else None})
print("样本:", len(samples))


def SBi(v):
    b = v.to_bytes(16, "big")
    return int.from_bytes(bytes(SBOX[x] for x in b), "big")


def MCi(v):
    b = v.to_bytes(16, "big")
    out = []
    for c4 in range(4):
        a, bb, cc, dd = b[4 * c4:4 * c4 + 4]
        out.extend((_gmul(a, 2) ^ _gmul(bb, 3) ^ cc ^ dd,
                    a ^ _gmul(bb, 2) ^ _gmul(cc, 3) ^ dd,
                    a ^ bb ^ _gmul(cc, 2) ^ _gmul(dd, 3),
                    _gmul(a, 3) ^ bb ^ cc ^ _gmul(dd, 2)))
    return int.from_bytes(bytes(out), "big")


out = {}
for r in range(1, 9):
    emap, c, bad, rank = solve_affine([(s["u"], s["rks"][r]) for s in samples],
                                      "rk%d" % r)
    if emap is not None:
        out["rk%d" % r] = {"emap": {str(k): format(v, "x") for k, v in emap.items()},
                           "c": format(c, "x")}

# W: postSB_8 需链推进: state = preSB0; post8 = SB(MC(...)...)
pairsW = []
for s in samples:
    # preSB0 = M(iv) ^ u
    K = bytes.fromhex(s["kh"])
    pre0 = xr(Mmap(int.from_bytes(K[::-1], "big")).to_bytes(16, "big"),
              s["u"].to_bytes(16, "big"))
    st_ = int.from_bytes(pre0, "big")
    for r in range(1, 9):
        st_ = MCi(SBi(st_)) ^ s["rks"][r]
    post8 = SBi(st_)
    W = int.from_bytes(bytes(ISBOX[x] for x in s["g1"].to_bytes(16, "big")),
                       "big") ^ MCi(post8)
    pairsW.append((s["u"], W))
emap, c, bad, rank = solve_affine(pairsW, "W")
if emap is not None:
    out["W"] = {"emap": {str(k): format(v, "x") for k, v in emap.items()},
                "c": format(c, "x")}
json.dump(out, open(os.path.join(HERE, "reports", "gen_affine_u.json"), "w"),
          indent=1)
print("已存 gen_affine_u.json")
