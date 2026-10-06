# -*- coding: utf-8 -*-
"""npc_curve.py — 实测「单块 PC 数」随 nblk 的变化。

要回答的问题: App 端每次响应也要跑同样的引擎, 为什么它快?
关键在于 App 跑的是 **AOT 机器码**(每条 ARM64 指令 ~0.3ns),
我们跑的是 **C 转译解释器**(每条 ~2.3ns)。要拿到这个倍率, 先测出
每块的动态 PC 数, 才能算出总指令量与指令吞吐。
"""
import ctypes, os, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from c_engine import load, unload

ENG = os.path.join(HERE, "engine_c")
K = bytes(range(0x05, 0x15))

def timeit(nblk, reps=3):
    lib = load()
    img = os.path.abspath(os.path.join(ENG, "image%d.bin" % nblk))
    rc = lib.jcy_init(img.encode())
    assert rc == 0, lib.jcy_last_error().decode()
    pt = bytes(16 * nblk)
    best = None
    for _ in range(reps):
        assert lib.jcy_capture_enable(nblk) == 0
        cap = len(pt) + 80
        buf = ctypes.create_string_buffer(cap)
        t0 = time.time()
        n = lib.jcy_encrypt_ex(K, pt, len(pt), buf, cap, 1)
        dt = (time.time() - t0) * 1000
        assert n > 0, lib.jcy_last_error().decode()
        if best is None or dt < best:
            best = dt
    unload()
    return best

print("%-6s %10s %12s" % ("nblk", "耗时ms", "边际ms/块"))
prev_n = prev_t = None
rows = []
for nblk in (1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 639):
    t = timeit(nblk)
    marg = None if prev_n is None else (t - prev_t) / (nblk - prev_n)
    print("%-6d %10.2f %12s" % (nblk, t, "-" if marg is None else "%.3f" % marg))
    rows.append((nblk, t, marg))
    prev_n, prev_t = nblk, t

# 线性拟合 t = a + b*n
import statistics
ns = [r[0] for r in rows]; ts = [r[1] for r in rows]
b = (ts[-1] - ts[0]) / (ns[-1] - ns[0])
a = statistics.mean(ts) - b * statistics.mean(ns)
print()
print("拟合: t = %.1f + %.3f * nblk   (固定开销 %.1f ms)" % (a, b, a))
print("639 块纯边际: %.0f ms" % (b * 639))
