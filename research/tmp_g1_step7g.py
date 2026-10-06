# -*- coding: utf-8 -*-
"""tmp_g1_step7e.py — angr 反编译 v2: 强制建 churn 函数 + 运行时 blr 目标去虚拟化."""
import os
import sys
import time
import collections

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "..", "libcore.so")
OUTDIR = os.path.join(HERE, "reports", "dec")
os.makedirs(OUTDIR, exist_ok=True)

sys.path.insert(0, os.path.join(HERE, "deliverables"))
from authgen import DEV_BASE  # noqa: E402
import unicorn  # noqa: E402
from unicorn.arm64_const import UC_ARM64_REG_PC, UC_ARM64_REG_X2  # noqa: E402
from decrypt_e import EDecryptor  # noqa: E402

def log(*a):
    print(*a, flush=True)

# ---- 1) 运行时收集 blr/br 目标 (块0+块1) ----
log("收集运行时跳转目标...")
d = EDecryptor()
d._oracle()
uc = d._uc
K = bytes(range(0x05, 0x15))
pcs = collections.deque(maxlen=800000)
h_all = uc.hook_add(unicorn.UC_HOOK_CODE,
                    lambda u_, a, s, ud: pcs.append(a),
                    begin=DEV_BASE, end=DEV_BASE + 0x400000)
d._cap.clear()
d._enc_big(bytes(32), K, K[::-1])
uc.hook_del(h_all)

import capstone  # noqa: E402
b = open(SO, "rb").read()
md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
seq = list(pcs)
targets = set()
for i in range(1, len(seq)):
    prev = seq[i - 1]
    if seq[i] != prev + 4:
        off = prev - DEV_BASE
        if 0 <= off < len(b):
            ins = next(md.disasm(b[off:off + 4], prev), None)
            if ins and ins.mnemonic in ("blr", "br"):
                targets.add(seq[i] - DEV_BASE)
log("blr/br 运行时目标: %d" % len(targets))

# ---- 2) CFGFast ----
import angr  # noqa: E402
CHURN = 0x2d9ed0
t0 = time.time()
proj = angr.Project(SO, auto_load_libs=False)
log("angr 加载 %.0fs" % (time.time() - t0))
t0 = time.time()
cfg = proj.analyses.CFGFast(normalize=True, show_progressbar=False, data_references=False, function_starts=[CHURN] + sorted(targets), regions=[(DEV_BASE + 0x2c0000, DEV_BASE + 0x2f2000)], force_complete_scan=True, force_smart_scan=False)
log("CFGFast %.0fs 函数 %d" % (time.time() - t0, len(cfg.kb.functions)))

# ---- 3) ----
addrs = [CHURN] + sorted(targets)
funcs = {}
for a in addrs:
    f = cfg.kb.functions.get(a)
    if f is not None and len(f.block_addrs_set) > 0:
        funcs[a] = f
log("待反编译函数: %d" % len(funcs))

# ---- 4) 反编译 ----
t0 = time.time()
ok, fail = 0, 0
for i, (a, f) in enumerate(sorted(funcs.items())):
    tag = "churn" if a == CHURN else "tgt"
    outp = os.path.join(OUTDIR, "fn_%06x_%s.c" % (a, tag))
    try:
        dec = proj.analyses.Decompiler(f, cfg=cfg)
        txt = dec.codegen.text if dec.codegen is not None else "// 无输出"
        with open(outp, "w", encoding="utf-8", errors="replace") as fh:
            fh.write("// %s blocks=%d\n" % (f.name, len(f.block_addrs_set)))
            fh.write(txt)
        ok += 1
    except Exception as e:  # noqa: BLE001
        with open(outp + ".err", "w") as fh:
            fh.write(repr(e))
        fail += 1
    if (i + 1) % 25 == 0:
        log("  [%d/%d] %.0fs ok=%d fail=%d" % (i + 1, len(funcs), time.time() - t0, ok, fail))
log("反编译完成 ok=%d fail=%d → %s" % (ok, fail, OUTDIR))
