# -*- coding: utf-8 -*-
"""tmp_pair_probe.py — 判定 tmp_bfpairs.bin 的配对语义。

候选语义:
  (A) X_i = D_k(C_i)          -> 加密预言机应满足 E_k(X_i, iv=0)[:8] == C_i
  (B) X_i = P_i ^ IV, C_i=E   -> E_k(P_i, iv=IV)[:8] == C_i  (P_i 未知，跳过)
  (C) 对合 E_k(C_i) == X_i
"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.join(HERE, "captures", "rsa_scan"),
           os.path.join(HERE, "deliverables"),
           os.path.join(HERE, "toolchain")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from e_oracle import EOracle  # noqa

BF = open(os.path.join(HERE, "tmp_bfpairs.bin"), "rb").read()
K = b"X8TEUA3DEXZNW2TN"
IV = K[::-1]

pairs = [(BF[i*16:i*16+8], BF[i*16+8:i*16+16]) for i in range(8)]
print("pairs (X_i -> C_i):")
for i, (x, c) in enumerate(pairs):
    print("  [%d] X=%s C=%s" % (i, x.hex(), c.hex()))

o = EOracle()
print("\n-- 语义 A: E_k(X_i, iv=0) 首块 ?= C_i --")
for i, (x, c) in enumerate(pairs):
    try:
        out = o.enc(x, K, b"\x00" * 8)
        got = out[:8]
        print("  [%d] %s  %s" % (i, got.hex(), "MATCH" if got == c else "no"))
    except Exception as ex:
        print("  [%d] ERR %s" % (i, ex))

print("\n-- 语义 C: E_k(C_i, iv=0) 首块 ?= X_i (对合) --")
for i, (x, c) in enumerate(pairs):
    try:
        out = o.enc(c, K, b"\x00" * 8)
        got = out[:8]
        print("  [%d] %s  %s" % (i, got.hex(), "MATCH" if got == x else "no"))
    except Exception as ex:
        print("  [%d] ERR %s" % (i, ex))
