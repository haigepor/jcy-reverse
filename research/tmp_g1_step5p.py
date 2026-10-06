# -*- coding: utf-8 -*-
"""tmp_g1_step5p.py — 找一次性 csel: 静态扫描 + 执行计数 + NZCV 抓取."""
import os
import sys
import json
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import unicorn  # noqa: E402
from unicorn.arm64_const import UC_ARM64_REG_NZCV  # noqa: E402
from decrypt_e import EDecryptor  # noqa: E402
from authgen import DEV_BASE  # noqa: E402
from capstone import Cs, CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN  # noqa: E402

br = json.load(open(os.path.join(HERE, "reports", "gen_branches.json")))
KA = bytes.fromhex(br["grpA"][0])
KB = bytes.fromhex(br["grpB"][0])

d = EDecryptor()
d._oracle()
uc = d._uc

# 静态扫描 csel 家族
md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
LO, HI = 0x2D2000, 0x2D5200
csel_pcs = []
code = bytes(uc.mem_read(DEV_BASE + LO, HI - LO))
for ins in md.disasm(code, DEV_BASE + LO):
    if ins.mnemonic in ("csel", "csinc", "csinv", "csneg"):
        csel_pcs.append(ins.address)
print("csel 家族指令数:", len(csel_pcs))

cnt = [Counter() for _ in range(1)]
evc = Counter()
flags = {}


def mk_tracer():
    def t(u_, address, size, ud):
        evc[address] += 1
    return t


h = uc.hook_add(unicorn.UC_HOOK_CODE, mk_tracer(),
                begin=DEV_BASE + LO, end=DEV_BASE + HI)
d._cap.clear()
d._enc_big(bytes(32), KA, KA[::-1])
cntA = dict(evc)
evc.clear()
d._cap.clear()
d._enc_big(bytes(32), KB, KB[::-1])
cntB = dict(evc)
uc.hook_del(h)

# csel 中执行次数少的 (调度型, 一次性)
rare = [(min(cntA.get(p, 0), cntB.get(p, 0)), p, cntA.get(p, 0), cntB.get(p, 0))
        for p in csel_pcs]
rare.sort()
print("\n=== 低执行次数 csel ===")
for m, p, a, b in rare[:25]:
    print("  %#x: A=%d B=%d" % (p, a, b))
