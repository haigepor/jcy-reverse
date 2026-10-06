# -*- coding: utf-8 -*-
"""tmp_g1_step7c.py — angr 反编译 churn (0x2d9ed0) 及热点调用图.

产出: reports/dec/ 下每个函数的伪 C + 调用图摘要.
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SO = os.path.join(HERE, "..", "libcore.so")
OUTDIR = os.path.join(HERE, "reports", "dec")
os.makedirs(OUTDIR, exist_ok=True)

sys.path.insert(0, os.path.join(HERE, "deliverables"))
from authgen import DEV_BASE  # noqa: E402

import angr  # noqa: E402

t0 = time.time()
proj = angr.Project(SO, auto_load_libs=False)
print("加载完成 %.0fs base=0x%x" % (time.time() - t0, proj.loader.main_object.mapped_base))

CHURN = 0x2d9ed0
t0 = time.time()
cfg = proj.analyses.CFGFast(normalize=True, show_progressbar=False)
print("CFGFast 完成 %.0fs 函数数 %d" % (time.time() - t0, len(cfg.kb.functions)))

# churn 函数及调用闭包 (深度 2)
fn = cfg.functions.get(CHURN)
if fn is None:
    # 找包含该地址的函数
    fn = cfg.functions.floor_func(CHURN)
print("churn 函数: %s @0x%x size=%d" % (fn.name, fn.addr, fn.block_addrs_set and len(fn.block_addrs_set) or 0))

callees = set()
for ea in fn.get_call_target_addrs():
    f2 = cfg.functions.get(ea)
    if f2 is not None:
        callees.add(f2)
lvl2 = set()
for f2 in callees:
    for ea in f2.get_call_target_addrs():
        f3 = cfg.functions.get(ea)
        if f3 is not None:
            lvl2.add(f3)

todo = [(fn, "churn")] + [(f, "callees") for f in callees] + [(f, "lvl2") for f in lvl2]
print("待反编译: churn=%d callees=%d lvl2=%d" % (1, len(callees), len(lvl2)))

t0 = time.time()
ok, fail = 0, 0
for i, (f, tag) in enumerate(todo):
    outp = os.path.join(OUTDIR, "fn_%x_%s.c" % (f.addr, tag))
    if os.path.exists(outp):
        ok += 1
        continue
    try:
        dec = proj.analyses.Decompiler(f, cfg=cfg)
        txt = dec.codegen.text if dec.codegen is not None else "// 无输出"
        with open(outp, "w", encoding="utf-8", errors="replace") as fh:
            fh.write("// %s size=%d blocks=%d\n" % (f.name, f.bytes and 0 or 0, len(f.block_addrs_set)))
            fh.write(txt)
        ok += 1
    except Exception as e:  # noqa: BLE001
        fail += 1
        with open(outp + ".err", "w") as fh:
            fh.write(str(e))
    if (i + 1) % 20 == 0:
        print("  [%d/%d] %.0fs ok=%d fail=%d" % (i + 1, len(todo), time.time() - t0, ok, fail), flush=True)

print("反编译完成 ok=%d fail=%d → %s" % (ok, fail, OUTDIR))
