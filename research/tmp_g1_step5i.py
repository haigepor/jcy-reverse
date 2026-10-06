# -*- coding: utf-8 -*-
"""tmp_g1_step5i.py — 分支聚类: 分组仿射求解 + 选择子定位."""
import os
import json
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
from decrypt_e import xr, SBOX, ISBOX, _gmul  # noqa: E402

data = json.load(open(os.path.join(HERE, "reports", "gen_rks3.json")))
aff = json.load(open(os.path.join(HERE, "reports", "gen_affine.json")))


def mk_M(rec):
    emap = {int(k): int(v, 16) for k, v in rec["emap"].items()}

    def M(v_int):
        out, vv, j = 0, v_int, 0
        while vv:
            if vv & 1:
                out ^= emap.get(j, 0)
            vv >>= 1
            j += 1
        return out
    return M


def solve_affine(pairs, tag):
    """pairs: [(x_int, y_int)] → (M, c, bad_idx)"""
    chk = {}
    for i in range(len(pairs)):
        xi, yi = pairs[i]
        for j in range(i + 1, len(pairs)):
            v = xi ^ pairs[j][0]
            if v == 0:
                continue
            o = yi ^ pairs[j][1]
            if v in chk and chk[v] != o:
                return None, None, None, "矛盾"
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
        return None, None, None, "秩%d" % rank
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

    x0, y0 = pairs[0]
    c = y0 ^ M(x0)
    return M, c, rank, "ok"


items = []
for kh, rec in data.items():
    K = bytes.fromhex(kh)
    rks = {int(r): bytes.fromhex(v) for r, v in rec["rks"].items()}
    items.append({"kh": kh, "K": K, "Ki": int.from_bytes(K, "big"),
                  "preSB0": bytes.fromhex(rec["preSB0"]), "rks": rks,
                  "g1": bytes.fromhex(rec["consts"][1]) if len(rec["consts"]) > 1 else None})

# --- 以 rk1 分组 ---
M1 = mk_M(aff["rks"]["1"])
c1 = int(aff["rks"]["1"]["c"], 16)
grpA = [it for it in items if (M1(it["Ki"]) ^ c1) == int.from_bytes(it["rks"][1], "big")]
grpB = [it for it in items if it not in grpA]
print("rk1 组A(拟合): %d  组B: %d" % (len(grpA), len(grpB)))

# 选择子: 哪个 bit 分离两组?
sep_bits = []
for b in range(128):
    va = {(it["Ki"] >> b) & 1 for it in grpA}
    vb = {(it["Ki"] >> b) & 1 for it in grpB}
    if va and vb and not (va & vb):
        sep_bits.append((b, va.pop(), vb.pop()))
print("完全分离的 bit:", sep_bits)

# 组B 内部差分一致? → 组B 也是仿射
Mi, ci, rank, msg = solve_affine([(it["Ki"], int.from_bytes(it["rks"][1], "big"))
                                  for it in grpB], "rk1-B")
print("组B rk1 仿射:", msg, "秩", rank)
if Mi:
    badB = [it["kh"][:8] for it in grpB
            if (Mi(it["Ki"]) ^ ci) != int.from_bytes(it["rks"][1], "big")]
    print("组B 拟合失败:", len(badB), badB[:8])

# --- 组内所有映射 ---
def solve_all(group, tag):
    outm = {}
    for r in range(1, 9):
        M, c, rank, msg = solve_affine(
            [(it["Ki"], int.from_bytes(it["rks"][r], "big")) for it in group],
            "%s-rk%d" % (tag, r))
        outm[r] = (M, c, rank, msg)
        print("  %s rk%d: %s 秩%d" % (tag, r, msg, rank))
    return outm


print("\n组B 全映射:")
mB = solve_all(grpB, "B")
print("\n组A 全映射:")
mA = solve_all(grpA, "A")

# preSB0 分组 (用组A/B 同一划分)
for tag, grp, mm in (("A", grpA, mA), ("B", grpB, mB)):
    M, c, rank, msg = solve_affine(
        [(it["Ki"], int.from_bytes(it["preSB0"], "big")) for it in grp],
        "%s-preSB0" % tag)
    print("%s preSB0: %s 秩%d" % (tag, msg, rank))
    mm["pre"] = (M, c, rank, msg)

# W 分组
def calc_W(it):
    st_ = it["preSB0"]
    for r in range(1, 9):
        a, b, cc, dd = st_[4 * 0:4], st_[4:8], st_[8:12], st_[12:16]
        mc = []
        for c4 in range(4):
            aa, bb, ccc, ddd = st_[4 * c4:4 * c4 + 4]
            mc.extend((_gmul(aa, 2) ^ _gmul(bb, 3) ^ ccc ^ ddd,
                       aa ^ _gmul(bb, 2) ^ _gmul(ccc, 3) ^ ddd,
                       aa ^ bb ^ _gmul(ccc, 2) ^ _gmul(ddd, 3),
                       _gmul(aa, 3) ^ bb ^ ccc ^ _gmul(ddd, 2)))
        st_ = xr(bytes(mc), it["rks"][r])
    post8 = bytes(SBOX[x] for x in st_)
    mcf = []
    for c4 in range(4):
        aa, bb, ccc, ddd = post8[4 * c4:4 * c4 + 4]
        mcf.extend((_gmul(aa, 2) ^ _gmul(bb, 3) ^ ccc ^ ddd,
                    aa ^ _gmul(bb, 2) ^ _gmul(ccc, 3) ^ ddd,
                    aa ^ bb ^ _gmul(ccc, 2) ^ _gmul(ddd, 3),
                    _gmul(aa, 3) ^ bb ^ ccc ^ _gmul(ddd, 2)))
    W = xr(bytes(ISBOX[x] for x in it["g1"]), bytes(mcf))
    return int.from_bytes(W, "big")


for tag, grp, mm in (("A", grpA, mA), ("B", grpB, mB)):
    M, c, rank, msg = solve_affine([(it["Ki"], calc_W(it)) for it in grp],
                                   "%s-W" % tag)
    print("%s W: %s 秩%d" % (tag, msg, rank))
    mm["W"] = (M, c, rank, msg)

# 保存
def ser(mm):
    o = {}
    for k, (M, c, rank, msg) in mm.items():
        if M is None:
            o[k] = {"err": msg}
        else:
            o[k] = {"emap": {str(j): format(M.__closure__[0].cell_contents.get(j, 0), "x")
                             for j in range(128)}, "c": format(c, "x")}
    return o


json.dump({"A": ser(mA), "B": ser(mB),
           "sep_bits": sep_bits,
           "grpA": [it["kh"] for it in grpA], "grpB": [it["kh"] for it in grpB]},
          open(os.path.join(HERE, "reports", "gen_branches.json"), "w"), indent=1)
print("已存 gen_branches.json")
