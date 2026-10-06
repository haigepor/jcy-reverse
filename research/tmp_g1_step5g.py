# -*- coding: utf-8 -*-
"""tmp_g1_step5g.py — 修正preSB0检验 + 6离群键稳定性 + b映射收割."""
import os
import json
import sys
import random

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
from decrypt_e import xr, ISBOX, T  # noqa: E402

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

print("=== 修正后 preSB0 = M·K ^ rev(K) ^ c 检验 ===")
pre_fails = []
for kh, rec in data.items():
    Kb = bytes.fromhex(kh)
    pred = (Mpre(int.from_bytes(Kb, "big")) ^ cpre) ^ int.from_bytes(Kb[::-1], "big")
    if pred.to_bytes(16, "big").hex() != rec["preSB0"]:
        pre_fails.append(kh)
print("preSB0 真离群: %d 个 %s" % (len(pre_fails), [k[:8] for k in pre_fails]))

# ---- emu 重收器 ----
import unicorn  # noqa: E402
from unicorn.arm64_const import UC_ARM64_REG_X2  # noqa: E402
from decrypt_e import EDecryptor, _gmul  # noqa: E402
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


def lean(K, nblk=2):
    st.update(p=None, tr=[], n=0)
    d._cap.clear()
    ctd = d._enc_big(bytes(16 * nblk), K, K[::-1])
    ncol = 36 * nblk
    tr = st["tr"][:ncol * 8]
    per = []
    for b in range(nblk):
        cols = []
        for g in range(36):
            by = tr[(b * 36 + g) * 8:(b * 36 + g) * 8 + 8]
            cols.append((by[0], by[1], by[3], by[5]))
        pre0 = bytes(ISBOX[v] for col in cols[0:4] for v in col)
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
        caps = d._cap
        xs = [bytes(T(list(caps[i]))) for i in range(0, len(caps), 2)]
        consts = []
        for b2 in range(min(nblk, len(xs))):
            prev = ctd[b2 * 16 - 16:b2 * 16] if b2 else K[::-1]
            consts.append(xr(xr(xs[b2], bytes(16 * nblk)[b2 * 16:(b2 + 1) * 16]),
                             prev).hex())
        per.append({"preSB0": pre0.hex(), "rks": rks, "consts": consts})
    return per


print("\n=== 6 离群键重收稳定性 ===")
outl = ["5bb8d045", "88d85163", "323732e7", "8fe619df", "2f9f005b", "fdc99290"]
for o in outl:
    kh = next(k for k in data if k.startswith(o))
    K = bytes.fromhex(kh)
    r1 = lean(K)
    r2 = lean(K)
    same = (r1[0] == r2[0])
    match_old = (r1[0]["preSB0"] == data[kh]["preSB0"]
                 and r1[0]["rks"] == data[kh]["rks"])
    print("K=%s 两次一致=%s 与首收一致=%s" % (o, same, match_old))
    if not match_old:
        print("   首 pre:", data[kh]["preSB0"])
        print("   新 pre:", r1[0]["preSB0"])
        print("   delta :", xr(bytes.fromhex(r1[0]["preSB0"]),
                              bytes.fromhex(data[kh]["preSB0"])).hex())
        print("   首 rk1:", data[kh]["rks"]["1"])
        print("   新 rk1:", r1[0]["rks"]["1"])

print("\n=== b 映射收割: 24 键 × 8 块 ===")
random.seed(777)
bkeys = [bytes.fromhex(k) for k in list(data)[:8]]
while len(bkeys) < 24:
    k = bytes(random.randrange(256) for _ in range(16))
    if k.hex() in data:
        continue
    bkeys.append(k)
bmap = {}
for i, K in enumerate(bkeys):
    per = lean(K, 8)
    bmap[K.hex()] = per
    if i % 6 == 0:
        print("[%d/24] K=%s pre1=%s" % (i + 1, K.hex()[:8], per[1]["preSB0"][:8]),
              flush=True)
json.dump(bmap, open(os.path.join(HERE, "reports", "gen_bmap.json"), "w"), indent=1)
print("已存 gen_bmap.json")
