# -*- coding: utf-8 -*-
"""tmp_g1_step6f.py — 按位置拆分的调度转移 + W 位置关系 (4键×128块)."""
import os
import sys
import json

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


def extract_block(tr, blk):
    cols = [(tr[(blk * 36 + g) * 8], tr[(blk * 36 + g) * 8 + 1],
             tr[(blk * 36 + g) * 8 + 3], tr[(blk * 36 + g) * 8 + 5])
            for g in range(36)]
    pre = bytes(ISBOX[v] for col in cols[0:4] for v in col)
    rks = []
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
        rks.append(xr(bytes(mc), preSB))
    return pre, rks


NBLK = 128
gold = json.load(open(os.path.join(HERE, "reports", "const_golden.json")))
keys = [bytes.fromhex(k) for k in list(gold)[:4]]

streams = {}
constsE = {}
for K in keys:
    iv = K[::-1]
    st.update(p=None, tr=[], n=0)
    d._cap.clear()
    ctd = d._enc_big(bytes(16 * NBLK), K, iv)
    caps = d._cap
    xs = [bytes(T(list(caps[i]))) for i in range(0, len(caps), 2)]
    eng = [xr(xr(xs[b], bytes(16)), ctd[b * 16 - 16:b * 16] if b else iv)
           for b in range(min(NBLK, len(xs)))]
    constsE[K.hex()] = eng
    s = [bytes(K[(5 * j) % 16] for j in range(16))]
    for b in range(NBLK):
        _, rks = extract_block(st["tr"], b)
        s.extend(rks)
    streams[K.hex()] = s
    print("K=%s 流长 %d" % (K.hex()[:8], len(s)), flush=True)

json.dump({"streams": {k: [v.hex() for v in s] for k, s in streams.items()},
           "consts": {k: [v.hex() for v in c] for k, c in constsE.items()}},
          open(os.path.join(HERE, "reports", "gen_stream.json"), "w"))

# 位置拆分转移: pos 0 = u→rk1(块0); pos 1..7 = 块内; pos 8 = 块界 rk8→rk1(下块)
print("\n=== 按位置差分一致性 ===")
for pos in range(9):
    pairs = []
    for kh, s in streams.items():
        for b in range(NBLK if pos < 8 else NBLK - 1):
            i = b * 8 + pos
            if i + 1 >= len(s):
                continue
            pairs.append((int.from_bytes(s[i], "big"),
                          int.from_bytes(s[i + 1], "big")))
    chk = {}
    contra = 0
    for i in range(len(pairs)):
        for j in range(i + 1, len(pairs)):
            v = pairs[i][0] ^ pairs[j][0]
            if v == 0:
                continue
            o = pairs[i][1] ^ pairs[j][1]
            if v in chk:
                if chk[v] != o:
                    contra += 1
            else:
                chk[v] = o
    piv = {}
    tri = 0
    for v, o in chk.items():
        cur, ro = v, o
        for pbit in sorted(list(piv), reverse=True):
            if cur >> pbit & 1:
                pin, pout = piv[pbit]
                cur ^= pin
                ro ^= pout
        if cur:
            piv[cur.bit_length() - 1] = (cur, ro)
        elif ro != 0:
            tri += 1
    print("pos%d: 样本%d 唯一差分%d 4碰撞%d 三角矛盾%d 秩%d"
          % (pos, len(pairs), len(chk), contra, tri, len(piv)))
