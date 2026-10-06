# -*- coding: utf-8 -*-
"""tmp_tweak2.py — CONST_b / Cb_b 结构猎取（数值法）。

思路：若 CONST_b = E(简单值)，则 E_inv(CONST_b) 应呈结构（如仅含块号、或等于小整数编码）。
同时检验是否与 AES 扩展密钥调度有关。
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
from decrypt_e import (EDecryptor, expand, F, F_inv, xr, T, SBOX,  # noqa: E402
                       _xt, _gmul)

NB = 24
K = bytes(range(16))


def aes_words(key, nwords):
    w = [list(key[i * 4:i * 4 + 4]) for i in range(4)]
    rc = 1
    for i in range(4, nwords):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[x] for x in t]
            t[0] ^= rc
            rc = _xt(rc)
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return [bytes(x) for x in w]


def main():
    d = EDecryptor()
    C, rk, CONST, Cb = d.calibrate(K, NB)
    CONST = [bytes(x) for x in CONST]
    Cb = [bytes(x) for x in Cb]
    iv = K[::-1]

    print("K   =", K.hex())
    print("iv  =", iv.hex())
    print("C(K)=", C.hex())
    print("\n b  CONST_b                                Cb_b")
    for b in range(NB):
        print("%2d  %s  %s" % (b, CONST[b].hex(), Cb[b].hex()))

    # ---- 反代回 E_inv ----
    print("\n=== A_b = E_inv(CONST_b)   B_b = E_inv(Cb_b) ===")
    for b in range(0, 8):
        Ab = F_inv(xr(CONST[b], C), rk)
        Bb = F_inv(xr(Cb[b], C), rk)
        print("b=%2d A=%s  B=%s" % (b, Ab.hex(), Bb.hex()))

    # ---- 与 AES 扩展密钥调度比对 ----
    W = aes_words(K, 4 + 4 * (NB + 16))
    print("\n=== 与扩展密钥调度比对 ===")
    for b in range(1, 10):
        rk10b = W[4 * (10 + b)] + W[4 * (10 + b) + 1] + W[4 * (10 + b) + 2] + W[4 * (10 + b) + 3]
        rkb = W[4 * (b % 11)] + W[4 * (b % 11) + 1] + W[4 * (b % 11) + 2] + W[4 * (b % 11) + 3]
        hit1 = CONST[b] == rk10b
        hit2 = CONST[b] == xr(rk10b, rk[0])
        hit3 = CONST[b] == rkb
        hit4 = Cb[b] == rk10b
        print("b=%2d  ==rk_%d:%s  ==rk_%d^rk0:%s  ==rk_%d:%s  Cb==rk_%d:%s"
              % (b, 10 + b, hit1, 10 + b, hit2, b % 11, hit3, 10 + b, hit4))

    # ---- CONST_b 是否为简单计数器编码的 E ----
    print("\n=== CONST_b == E(counter) 候选 ===")
    cands = {}
    for b in range(1, 8):
        vals = {
            "b_le64@0": b.to_bytes(8, "little") + bytes(8),
            "b_be64@0": b.to_bytes(8, "big") + bytes(8),
            "b_le64@8": bytes(8) + b.to_bytes(8, "little"),
            "b_byte0": bytes([b]) + bytes(15),
            "b_byte15": bytes(15) + bytes([b]),
            "b_xor_iv": xr(bytes([b]) + bytes(15), iv),
            "b_xor_rk0": xr(bytes([b]) + bytes(15), rk[0]),
        }
        for nm, v in vals.items():
            cands.setdefault(nm, 0)
            e = xr(F(v, rk), C)
            if e == CONST[b]:
                cands[nm] += 1
                print("  HIT b=%d %s" % (b, nm))
    print("  命中统计:", cands)

    # ---- 差分结构 ----
    print("\n=== 差分 ===")
    for b in range(1, 7):
        print("  CONST_%d^CONST_%d = %s" % (b, b + 1, xr(CONST[b], CONST[b + 1]).hex()))
        print("  Cb_%d^Cb_%d       = %s" % (b, b + 1, xr(Cb[b], Cb[b + 1]).hex()))
        print("  CONST_%d^Cb_%d    = %s" % (b, b, xr(CONST[b], Cb[b]).hex()))

    # ---- 保存 ----
    import json
    json.dump({"K": K.hex(), "iv": iv.hex(), "C": C.hex(),
               "CONST": [x.hex() for x in CONST], "Cb": [x.hex() for x in Cb]},
              open(os.path.join(HERE, "tmp_tweak2.json"), "w"), indent=1)
    print("\n已存 research/tmp_tweak2.json")


if __name__ == "__main__":
    main()
