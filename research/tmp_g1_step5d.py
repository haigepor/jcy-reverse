# -*- coding: utf-8 -*-
"""tmp_g1_step5d.py — 精简批量收割: 单次 enc_big 直采 288 乘 + golden1. 135 键."""
import os
import sys
import json
import random
import time

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

NKEYS = int(sys.argv[1]) if len(sys.argv) > 1 else 135
NBLK = int(sys.argv[2]) if len(sys.argv) > 2 else 2
OUT = os.path.join(HERE, "reports", "gen_rks3.json")

d = EDecryptor()
d._oracle()
uc = d._uc

random.seed(20261005)
keys = []
gold = json.load(open(os.path.join(HERE, "reports", "const_golden.json")))
keys += [bytes.fromhex(k) for k in gold]
while len(keys) < NKEYS:
    k = bytes(random.randrange(256) for _ in range(16))
    if k not in keys:
        keys.append(k)

data = json.load(open(OUT)) if os.path.exists(OUT) else {}
h_mul = uc.hook_add(unicorn.UC_HOOK_CODE,
                    lambda u_, a, s, ud: st.update(p=u_.reg_read(UC_ARM64_REG_X2) & 0xFF),
                    begin=MUL, end=MUL + 3)
st = {"p": None, "tr": [], "n": 0}


def on_site(u_, address, size, ud):
    if st["p"] is None:
        return
    st["tr"].append(st["p"])
    st["p"] = None
    st["n"] += 1


h_sites = [uc.hook_add(unicorn.UC_HOOK_CODE, on_site, begin=s, end=s + 3)
           for s in SITES]

t00 = time.time()
for idx, K in enumerate(keys):
    kh = K.hex()
    if kh in data and len(data[kh].get("rks", {})) >= 8:
        continue
    st.update(p=None, tr=[], n=0)
    d._cap.clear()
    iv = K[::-1]
    dummy = bytes(16 * NBLK)
    ctd = d._enc_big(dummy, K, iv)
    tr = st["tr"][:288]
    if len(tr) < 288:
        print("[%d] K=%s 乘不足: %d" % (idx, kh[:8], len(tr)), flush=True)
        continue
    cols = []
    for g in range(36):
        by = tr[g * 8:g * 8 + 8]
        cols.append((by[0], by[1], by[3], by[5]))
    preSB0 = bytes(ISBOX[v] for col in cols[0:4] for v in col)
    caps = d._cap
    xs = [bytes(T(list(caps[i]))) for i in range(0, len(caps), 2)]
    # CONST_b = x_b ^ dummy_b ^ ct_{b-1} (ct_{-1} = iv)
    consts = []
    for b in range(min(NBLK, len(xs))):
        prev = ctd[b * 16 - 16:b * 16] if b else iv
        consts.append(xr(xr(xs[b], dummy[b * 16:(b + 1) * 16]), prev).hex())
    # rk1..rk8
    def gmul(a, b):
        return EDecryptor._gmul(a, b) if hasattr(EDecryptor, "_gmul") else _gmul(a, b)
    from decrypt_e import _gmul
    rks = {}
    st_ = preSB0
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
        rk = xr(bytes(mc), preSB)
        rks[r + 1] = rk.hex()
    data[kh] = {"preSB0": preSB0.hex(), "rks": rks, "consts": consts}
    if idx % 10 == 0 or idx == len(keys) - 1:
        json.dump(data, open(OUT, "w"), indent=1)
        el = time.time() - t00
        print("[%d/%d] K=%s %.2fs/键 预计余 %.0fs"
              % (idx + 1, len(keys), kh[:8], el / (idx + 1),
                 el / (idx + 1) * (len(keys) - idx - 1)), flush=True)

json.dump(data, open(OUT, "w"), indent=1)
print("完成: %d 键 → %s" % (len(data), OUT))
