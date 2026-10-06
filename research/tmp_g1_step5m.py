# -*- coding: utf-8 -*-
"""tmp_g1_step5m.py — 0x2d2f80-0x2d30e0 反汇编 + 两路径计数对比."""
import os
import sys
import json

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

# 反汇编
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
code = bytes(uc.mem_read(DEV_BASE + 0x2D2F60, 0x190))
print("=== 反汇编 0x2d2f60-0x2d30f0 ===")
for ins in md.disasm(code, DEV_BASE + 0x2D2F60):
    print("  %#x  %s %s" % (ins.address, ins.mnemonic, ins.op_str))

# 计数
cnt = {}
hits = {"a": 0, "b": 0}


def mk(site):
    def h(u_, address, size, ud):
        cnt.setdefault(site, []).append(
            tuple(u_.reg_read(r) for r in ()))
        hits[site] = hits.get(site, 0) + 1
    return h


h1 = uc.hook_add(unicorn.UC_HOOK_CODE, lambda u_, a, s, ud: hits.__setitem__("a", hits["a"] + 1),
                 begin=DEV_BASE + 0x2D30C0, end=DEV_BASE + 0x2D30C0 + 3)
h2 = uc.hook_add(unicorn.UC_HOOK_CODE, lambda u_, a, s, ud: hits.__setitem__("b", hits["b"] + 1),
                 begin=DEV_BASE + 0x2D3038, end=DEV_BASE + 0x2D3038 + 3)

for tag, K in (("A", KA), ("B", KB)):
    hits.update(a=0, b=0)
    d._cap.clear()
    d._enc_big(bytes(32), K, K[::-1])
    print("键 %s: 0x2d30c0 路径=%d  0x2d3038 路径=%d" % (tag, hits["a"], hits["b"]))
