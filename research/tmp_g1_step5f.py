# -*- coding: utf-8 -*-
"""tmp_g1_step5f.py — 定位 6 个离群键: 重收两次 + 差值结构."""
import os
import json
import sys
import random

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


Mpre = mk_M(aff["preSB0"])
cpre = int(aff["preSB0"]["c"], 16)
Mrs = {r: mk_M(aff["rks"][str(r)]) for r in range(1, 9)}
crs = {r: int(aff["rks"][str(r)]["c"], 16) for r in range(1, 9)}
MW = mk_M(aff["W"])
cW = int(aff["W"]["c"], 16)

fails = []
for kh, rec in data.items():
    K = int.from_bytes(bytes.fromhex(kh), "big")
    pre0 = (Mpre(K) ^ cpre).to_bytes(16, "big")
    if pre0.hex() != rec["preSB0"]:
        fails.append(kh)
print("preSB0 离群键:", [k[:8] for k in fails], "共", len(fails))

# 与 rk/W 离群是否同一批?
for kh, rec in data.items():
    K = int.from_bytes(bytes.fromhex(kh), "big")
    bad = []
    if (Mpre(K) ^ cpre).to_bytes(16, "big").hex() != rec["preSB0"]:
        bad.append("pre")
    for r in range(1, 9):
        if (Mrs[r](K) ^ crs[r]).to_bytes(16, "big") != bytes.fromhex(rec["rks"][str(r)]):
            bad.append("rk%d" % r)
    if bad and bad != ["pre"] + ["rk%d" % r for r in range(1, 9)]:
        print("  部分离群:", kh[:8], bad)
    elif bad:
        pass
full_bad = [kh for kh, rec in data.items()
            if all((Mrs[r](int.from_bytes(bytes.fromhex(kh), "big")) ^ crs[r]
                    ).to_bytes(16, "big") != bytes.fromhex(rec["rks"][str(r)])
                   for r in range(1, 9))]
print("全映射同一批离群:", [k[:8] for k in full_bad], "共", len(full_bad))

# 重收离群键 2 次
sys.argv = ["x"]
import unicorn  # noqa: E402
from unicorn.arm64_const import UC_ARM64_REG_X2  # noqa: E402
from decrypt_e import EDecryptor, T  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

MUL = DEV_BASE + 0x2D2F20
SITES = [DEV_BASE + o for o in
         (0x2D32AC, 0x2D32D4, 0x2D3740, 0x2D38D0,
          0x2D3B9C, 0x2D3C68, 0x2D3DD8, 0x2D402C)]

d = EDecryptor()
d._oracle()
uc = d._uc
st = {"p": None, "tr": []}
uc.hook_add(unicorn.UC_HOOK_CODE,
            lambda u_, a, s, ud: st.update(p=u_.reg_read(UC_ARM64_REG_X2) & 0xFF),
            begin=MUL, end=MUL + 3)


def on_site(u_, address, size, ud):
    if st["p"] is None:
        return
    st["tr"].append(st["p"])
    st["p"] = None


for s in SITES:
    uc.hook_add(unicorn.UC_HOOK_CODE, on_site, begin=s, end=s + 3)


def lean(K):
    st.update(p=None, tr=[])
    d._cap.clear()
    ctd = d._enc_big(bytes(32), K, K[::-1])
    tr = st["tr"][:288]
    cols = []
    for g in range(36):
        by = tr[g * 8:g * 8 + 8]
        cols.append((by[0], by[1], by[3], by[5]))
    pre0 = bytes(ISBOX[v] for col in cols[0:4] for v in col)
    caps = d._cap
    xs = [bytes(T(list(caps[i]))) for i in range(0, len(caps), 2)]
    g1 = xr(xr(xs[1], bytes(16)), ctd[0:16])
    return pre0, g1


for kh in fails[:3]:
    K = bytes.fromhex(kh)
    p1, g1a = lean(K)
    p2, g1b = lean(K)
    rec = data[kh]
    print("K=%s 重收稳定? pre %s | g1 %s" %
          (kh[:8], p1.hex() == p2.hex() == rec["preSB0"],
           g1a.hex() == g1b.hex() == rec["consts"][1]))
    if p1.hex() != rec["preSB0"]:
        print("   新pre0=%s 旧pre0=%s" % (p1.hex(), rec["preSB0"]))
        print("   delta    =", xr(p1, bytes.fromhex(rec["preSB0"])).hex())
