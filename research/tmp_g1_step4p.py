# -*- coding: utf-8 -*-
"""tmp_g1_step4p.py — 用 F_inv 反推生成器 AES 的输入，识别模式。"""
import os
import sys
import json

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

from decrypt_e import expand, F, F_inv, xr, T  # noqa: E402

gold = json.load(open(os.path.join(HERE, "reports", "const_golden.json")))

for kh, consts in list(gold.items())[:2]:
    K = bytes.fromhex(kh)
    rk = expand(K)
    iv = K[::-1]
    # C 与 _determine_C 相同口径


    # 手动算 C（无 emu）: C = ct(单块0) ^ T(st10) — 需要 emu，跳过；先试不带 C 的
    consts = [bytes.fromhex(c) for c in consts][:4]
    print("=== K=%s ===" % K.hex())
    for b, tw in enumerate(consts):
        for name, w in (("raw", tw), ("T", bytes(T(list(tw))))):
            X = F_inv(w, rk)
            tag = ""
            if X == bytes(16):
                tag = " ←全零"
            elif X == iv:
                tag = " ←=iv"
            elif X == K:
                tag = " ←=K"
            print("  b=%d %s: X=%s%s" % (b, name, X.hex(), tag))
    print()
