# -*- coding: utf-8 -*-
"""tmp_blocksize.py — 判定 E 的分组大小(8 vs 16)与 CBC 粒度。"""
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
IV = K[::-1]
P = pl[5]["text"].encode("utf-8")
h21 = [bytes.fromhex(e["p1_hex"]) for e in pairs if e.get("hit") == 21][0]

o = EOracle()

def run(name, pt, iv, expect):
    try:
        out = o.enc(pt, K, iv)
        n = min(len(out), len(expect))
        eq = out[:n] == expect[:n]
        print("[%s] pt=%d iv=%d out=%d  prefix_eq=%s" % (name, len(pt), len(iv), len(out), eq))
        if not eq:
            print("   out=%s" % out[:len(expect)].hex())
            print("   exp=%s" % expect.hex())
    except Exception as ex:
        print("[%s] ERR %r" % (name, ex))

# 长度探针: 16B 明文 -> 输出长度揭示分组
for L in (8, 16, 24, 32):
    try:
        out = o.enc(b"\x00" * L, K, b"\x00" * 8)
        print("lenprobe pt=%d -> out=%d (block=%s)" % (L, len(out), "8" if len(out) == (L // 8 + 1) * 8 else "16" if len(out) == (L // 16 + 1) * 16 else "?"))
    except Exception as ex:
        print("lenprobe pt=%d ERR %r" % (L, ex))

print("\n-- 8B 分组假设: E_k(P[0:8] ^ IV[0:8]) ?= h21[0:8] --")
run("blk8", P[0:8], IV[0:8], h21[0:8])

print("\n-- 16B 分组假设: E_k(P[0:16] ^ IV[0:16]) ?= h21[0:16] --")
run("blk16", P[0:16], IV[0:16], h21[0:16])

print("\n-- 32B CBC 复现 (前 32B) --")
run("cbc32", P[0:32], IV[0:16], h21[0:32])
