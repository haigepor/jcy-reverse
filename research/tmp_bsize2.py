# -*- coding: utf-8 -*-
"""tmp_bsize2.py — 用完整 16B IV 判定分组大小(8 vs 16)。

判别 1: enc(P[0:8], K, IV16)[0:8] ?= h21[0:8]
        (block=8 成立则匹配)
判别 2: 耦合 —— 改 P[8:16] 是否影响 out[0:8]
        (block=8: 不影响; block=16: 影响)
"""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.join(HERE, "captures", "rsa_scan"),
           os.path.join(HERE, "deliverables"),
           os.path.join(HERE, "toolchain")):
    if _p not in sys.path:
        sys.path.insert(0, _p)
from e_oracle import EOracle  # noqa

pl = json.load(open(os.path.join(HERE, "tmp_plains.json")))
pairs = json.load(open(os.path.join(HERE, "tmp_pairs.json")))
K = b"X8TEUA3DEXZNW2TN"
IV = K[::-1]                      # 16B
P = pl[5]["text"].encode("utf-8")
h21 = [bytes.fromhex(e["p1_hex"]) for e in pairs if e.get("hit") == 21][0]

o = EOracle()

# 判别 1
out = o.enc(P[0:8], K, IV)
print("d1: enc(P[0:8],K,IV16)[0:8] =", out[:8].hex(), " h21[0:8] =", h21[0:8].hex(),
      "->", "MATCH(block=8)" if out[:8] == h21[0:8] else "no")

out2 = o.enc(P[0:16], K, IV)
print("d1b:enc(P[0:16],K,IV16)[0:16] =", out2[:16].hex(), " h21[0:16]=", h21[0:16].hex(),
      "->", "MATCH(block=16)" if out2[:16] == h21[0:16] else "no")

# 判别 2: 改第二半
A = P[0:8]
B = P[8:16]
B2 = bytes(x ^ 0xFF for x in B)
e1 = o.enc(A + B, K, IV)
e2 = o.enc(A + B2, K, IV)
print("d2: out(A||B )[0:8] =", e1[:8].hex())
print("    out(A||B')[0:8] =", e2[:8].hex())
print("    ->", "block=8 (首块独立)" if e1[:8] == e2[:8] else "block=16 (全耦合)")
