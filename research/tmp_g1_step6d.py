# -*- coding: utf-8 -*-
"""tmp_g1_step6d.py — 全长金料验证: 8 键 × 128 块, 纯 Python 链 vs 引擎流."""
import os
import sys
import json
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from unicorn.arm64_const import UC_ARM64_REG_X2  # noqa: E402
from decrypt_e import EDecryptor, SBOX, ISBOX, _gmul, xr, T  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

MUL = DEV_BASE + 0x2D2F20
SITES = [DEV_BASE + o for o in
         (0x2D32AC, 0x2D32D4, 0x2D3740, 0x2D38D0,
          0x2D3B9C, 0x2D3C68, 0x2D3DD8, 0x2D402C)]

MJ = json.load(open(os.path.join(HERE, "reports", "gen_M.json")))
EMAP_M = {int(k): int(v, 16) for k, v in MJ["emap"].items()}


def Mmap(vb):
    v = int.from_bytes(vb, "big")
    out, j = 0, 0
    while v:
        if v & 1:
            out ^= EMAP_M.get(j, 0)
        v >>= 1
        j += 1
    return out.to_bytes(16, "big")


def SB(b):
    return bytes(SBOX[x] for x in b)


def iSB(b):
    return bytes(ISBOX[x] for x in b)


def MC(b):
    out = []
    for c in range(4):
        a, b2, cc, dd = b[4 * c:4 * c + 4]
        out.extend((_gmul(a, 2) ^ _gmul(b2, 3) ^ cc ^ dd,
                    a ^ _gmul(b2, 2) ^ _gmul(cc, 3) ^ dd,
                    a ^ b2 ^ _gmul(cc, 2) ^ _gmul(dd, 3),
                    _gmul(a, 3) ^ b2 ^ cc ^ _gmul(dd, 2)))
    return bytes(out)


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


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
data = json.load(open(os.path.join(HERE, "reports", "gen_rks3.json")))
NBLK = 128

tot_ok = tot_bad = 0
for kh in gold:
    K = bytes.fromhex(kh)
    iv = K[::-1]
    # 引擎跑 128 块 (取 ct 流 + 引擎 CONST 流)
    st.update(p=None, tr=[], n=0)
    d._cap.clear()
    t0 = time.time()
    ctd = d._enc_big(bytes(16 * NBLK), K, iv)
    caps = d._cap
    xs = [bytes(T(list(caps[i]))) for i in range(0, len(caps), 2)]
    eng_consts = [xr(xr(xs[b], bytes(16)), ctd[b * 16 - 16:b * 16] if b else iv)
                  for b in range(min(NBLK, len(xs)))]
    t_eng = time.time() - t0

    # 模型参数: rks 从 gen_rks3 (块0 收割), W 由 golden1 推
    rks = {int(r): bytes.fromhex(v) for r, v in data[kh]["rks"].items()}
    u = bytes(K[(5 * j) % 16] for j in range(16))
    pre0 = bytes.fromhex(data[kh]["preSB0"])
    stc = pre0
    for r in range(1, 9):
        stc = xor(MC(SB(stc)), rks[r])
    W = xor(iSB(eng_consts[1]), MC(SB(stc)))

    # 纯 Python 链: x_b = pt(0) ^ ct_{b-1} ^ CONST_b
    t0 = time.time()
    consts = [bytes(16)]
    prev_ct = iv
    for b in range(NBLK - 1):
        # x_b = pt_b(0) ^ ct_{b-1} ^ CONST_b  — 不含 ct_b!
        x_b = xor(prev_ct, consts[b])
        pre = xor(Mmap(x_b), u)
        stc = pre
        for r in range(1, 9):
            stc = xor(MC(SB(stc)), rks[r])
        consts.append(SB(xor(MC(SB(stc)), W)))
        prev_ct = ctd[b * 16:(b + 1) * 16]
    t_py = time.time() - t0

    bad = sum(1 for b in range(NBLK) if consts[b] != eng_consts[b])
    tot_ok += NBLK - bad
    tot_bad += bad
    print("K=%s 引擎%.2fs py链%.3fs 不符 %d/%d" % (kh[:8], t_eng, t_py, bad, NBLK))

print("\n总验证: %d ok / %d bad" % (tot_ok, tot_bad))
