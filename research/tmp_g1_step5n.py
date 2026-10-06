# -*- coding: utf-8 -*-
"""tmp_g1_step5n.py — 边频差分: 找 A/B 罕见差异边 (全局分支候选)."""
import os
import sys
import json
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from decrypt_e import EDecryptor  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

br = json.load(open(os.path.join(HERE, "reports", "gen_branches.json")))
KA = bytes.fromhex(br["grpA"][0])
KB = bytes.fromhex(br["grpB"][0])

d = EDecryptor()
d._oracle()
uc = d._uc
edges = []
prev = {"pc": None}


def tracer(u_, address, size, ud):
    pc = prev["pc"]
    if pc is not None:
        if address == pc + 4:
            prev["pc"] = address
            return
        edges.append((pc, address))
    prev["pc"] = address


h = uc.hook_add(unicorn.UC_HOOK_CODE, tracer,
                begin=DEV_BASE, end=DEV_BASE + 0x400000)


def run(K):
    edges.clear()
    prev["pc"] = None
    d._cap.clear()
    d._enc_big(bytes(32), K, K[::-1])
    return Counter(edges)


cA = run(KA)
cB = run(KB)
uc.hook_del(h)

onlyA = {e: c for e, c in cA.items() if e not in cB}
onlyB = {e: c for e, c in cB.items() if e not in cA}
print("A 独有边 %d, B 独有边 %d" % (len(onlyA), len(onlyB)))
print("\n=== 低频独有边 (计数 ≤ 8) ===")
for tag, dic in (("A", onlyA), ("B", onlyB)):
    low = sorted(((c, e) for e, c in dic.items() if c <= 8))
    for c, (s, t) in low[:20]:
        print("  %s ×%d: %#x -> %#x" % (tag, c, s, t))
    print("  (低频总数 %d)" % len(low))

# 高频但计数不同的边
print("\n=== 计数差 ≤ 32 的高频边 ===")
diffs = []
for e in set(cA) | set(cB):
    ca, cb = cA.get(e, 0), cB.get(e, 0)
    if abs(ca - cb) <= 32 and min(ca, cb) > 8:
        diffs.append((abs(ca - cb), e, ca, cb))
diffs.sort()
for d_, (s, t), ca, cb in diffs[:15]:
    print("  Δ%d: %#x -> %#x  (A=%d B=%d)" % (d_, s, t, ca, cb))
