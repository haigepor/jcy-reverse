# -*- coding: utf-8 -*-
"""tmp_anchor.py — 用 hit21/287 锚定 E 的 CBC 语义。"""
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

# hit21 密文
h21 = None
for e in pairs:
    if e.get("hit") == 21:
        h21 = bytes.fromhex(e["p1_hex"])
print("hit21 P1 len", len(h21), h21[:32].hex())

txt = pl[5]["text"].encode("utf-8") if isinstance(pl[5]["text"], str) else pl[5]["text"]
print("plain287 len", len(txt), "tail", txt[-8:].hex())

o = EOracle()
variants = {
    "full200": txt,
    "strip_pad197": txt.rstrip(b"\x03"),
}
for name, pt in variants.items():
    try:
        out = o.enc(pt, K, IV)
        print("\n[%s] pt=%d -> out=%d" % (name, len(pt), len(out)))
        print("  out[:32] =", out[:32].hex())
        print("  h21[:32] =", h21[:32].hex())
        n = min(len(out), len(h21))
        same = sum(1 for i in range(n) if out[i] == h21[i])
        print("  match bytes %d/%d ; first64 eq=%s" % (same, n, out[:64] == h21[:64]))
    except Exception as ex:
        print("[%s] ERR %r" % (name, ex))
