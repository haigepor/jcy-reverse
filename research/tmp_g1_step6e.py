# -*- coding: utf-8 -*-
"""tmp_g1_step6e.py — 调度流检验: 流提取 + W 位置 + 转移仿射."""
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


def extract_block_rks(tr, blk):
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


NBLK = 16
K = bytes.fromhex("05101b26313c47525d68737e89949faa")
iv = K[::-1]
st.update(p=None, tr=[], n=0)
d._cap.clear()
ctd = d._enc_big(bytes(16 * NBLK), K, iv)
caps = d._cap
xs = [bytes(T(list(caps[i]))) for i in range(0, len(caps), 2)]
eng_consts = [xr(xr(xs[b], bytes(16)), ctd[b * 16 - 16:b * 16] if b else iv)
              for b in range(min(NBLK, len(xs)))]

# 流: u + 每块 8 rk
stream = [bytes(K[(5 * j) % 16] for j in range(16))]
pres = []
for b in range(NBLK):
    pre, rks = extract_block_rks(st["tr"], b)
    pres.append(pre)
    stream.extend(rks)
print("流长度:", len(stream))
print("u = S[0]?", stream[0].hex())
print("块0 pre = M(iv)^u:", pres[0].hex())
print("块1 pre =            ", pres[1].hex())

# W_b: iSB(consts[b+1]) ^ MC(postSB8_b) 与流位置对比
def SBf(b):
    return bytes(SBOX[x] for x in b)


def iSB(b):
    return bytes(ISBOX[x] for x in b)


def MCf(b):
    out = []
    for c in range(4):
        a, b2, cc, dd = b[4 * c:4 * c + 4]
        out.extend((_gmul(a, 2) ^ _gmul(b2, 3) ^ cc ^ dd,
                    a ^ _gmul(b2, 2) ^ _gmul(cc, 3) ^ dd,
                    a ^ b2 ^ _gmul(cc, 2) ^ _gmul(dd, 3),
                    _gmul(a, 3) ^ b2 ^ cc ^ _gmul(dd, 2)))
    return bytes(out)


for b in range(3):
    post8 = SBf(pres[b])
    for r in range(8):
        post8 = SBf(xr(MCf(post8), stream[1 + b * 8 + r]))
    Wb = xr(iSB(eng_consts[b + 1]), MCf(post8))
    print("块%d W_b = %s" % (b, Wb.hex()))
    print("       S[%d] = %s  相等? %s"
          % (1 + b * 8 + 8, stream[1 + b * 8 + 8].hex(),
             Wb == stream[1 + b * 8 + 8]))
    print("       S[%d] = %s  相等? %s"
          % (b * 8 + 1, stream[b * 8 + 1].hex(), Wb == stream[b * 8 + 1]))

# 转移仿射: S[n+1] = A·S[n] ^ c ?
pairs = [(int.from_bytes(stream[i], "big"),
          int.from_bytes(stream[i + 1], "big")) for i in range(len(stream) - 1)]
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
print("转移差分: 唯一 %d, 4碰撞矛盾 %d" % (len(chk), contra))
piv = {}
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
        print("三角矛盾出现 (非仿射)!")
        break
else:
    print("无三角矛盾 → 转移仿射成立候选, 秩", len(piv))
