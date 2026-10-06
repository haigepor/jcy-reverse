# -*- coding: utf-8 -*-
"""tmp_g1_step5l.py — A/B 键控制流边序列对比, 定位分支指令."""
import os
import sys
import json
import difflib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from decrypt_e import EDecryptor  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

br = json.load(open(os.path.join(HERE, "reports", "gen_branches.json")))
KA = bytes.fromhex(br["grpA"][0])
KB = bytes.fromhex(br["grpB"][0])
print("KA=%s (A)  KB=%s (B)" % (KA.hex()[:8], KB.hex()[:8]))

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
    return list(edges)


eA = run(KA)
eB = run(KB)
uc.hook_del(h)
print("边数 A=%d B=%d" % (len(eA), len(eB)))

sm = difflib.SequenceMatcher(None, eA, eB, autojunk=False)
ob = sm.get_opcodes()
shown = 0
for tag, i1, i2, j1, j2 in ob:
    if tag == "equal":
        continue
    print("[%s] A[%d:%d] B[%d:%d]" % (tag, i1, i2, j1, j2))
    for x in range(i1, min(i2, i1 + 4)):
        print("   A %#x -> %#x" % eA[x])
    for x in range(j1, min(j2, j1 + 4)):
        print("   B %#x -> %#x" % eB[x])
    shown += 1
    if shown >= 6:
        break
