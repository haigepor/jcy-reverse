#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""scale_curve.py — 测量引擎耗时随块数的曲线, 分离固定成本与边际成本。

V22 目的: 判定 639 块 4104 ms 里"每块 6.4 ms"是否已经接近不可压缩下限。
方法: 对 nblk= 1,2,4,8,16,32,64,128,256,512,639 各跑一次 DLL 标定, 做线性拟合:
    t(n) = a + b * n
  - a = 一次性固定成本(镜像/表初始化/首次调用)
  - b = 每块边际成本
如果 b稳定, 说明每块工作量恒定 -> 唯一杠杆是"每块算得更快"。
如果 b随 n 下降, 说明存在可摊薄的共享阶段 -> 多请求/多块复用有额外空间。
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
sys.path.insert(0, HERE)

from c_engine import load  # noqa: E402


def t_for(nblk, reps=3):
    K = bytes(range(0x05, 0x15))
    pt = bytes(16 * nblk)
    best = None
    for i in range(reps):
        lib = load()
        # 首次调用必须 jcy_init(镜像) —— 只做一次, 后续复用, 否则把一次性
        # 成本算进每档就看不出真实曲线了。
        if not getattr(t_for, "_inited", False):
            img = os.path.join(HERE, "engine_c", "image639.bin")
            if not os.path.exists(img):
                raise FileNotFoundError(img)
            rc = lib.jcy_init(os.path.abspath(img).encode())
            if rc != 0:
                raise RuntimeError("jcy_init(%d): %s" % (rc, lib.jcy_last_error().decode()))
            t_for._inited = True
        rc = lib.jcy_capture_enable(nblk)
        if rc != 0:
            raise RuntimeError("capture_enable: %s" % lib.jcy_last_error().decode())
        outcap = len(pt) + 16 + 64
        buf = __import__("ctypes").create_string_buffer(outcap)
        t0 = time.time()
        n = lib.jcy_encrypt_ex(K, pt, len(pt), buf, outcap, 1)
        dt = (time.time() - t0) * 1000
        if n < 0:
            raise RuntimeError("encrypt_ex(%d): %s" % (n, lib.jcy_last_error().decode()))
        best = dt if best is None else min(best, dt)
    return best


def main():
    sizes = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 639]
    print("=== 引擎耗时 vs 块数 (取 %d 次最小值) ===" % 3)
    print("  nblk        t(ms)     t/n (ms/块)")
    rows = []
    for n in sizes:
        t = t_for(n)
        rows.append((n, t))
        print("  %5d   %9.1f   %9.3f" % (n, t, t / n))

    # 最小二乘拟合 t = a + b*n (只用 n >= 8,避开启动噪声)
    pts = [(n, t) for n, t in rows if n >= 8]
    m = len(pts)
    sx = sum(n for n, _ in pts)
    sy = sum(t for _, t in pts)
    sxx = sum(n * n for n, _ in pts)
    sxy = sum(n * t for n, t in pts)
    b = (m * sxy - sx * sy) / (m * sxx - sx * sx)
    a = (sy - b * sx) / m
    print("\n=== 线性拟合 t = %.1f + %.3f * n  (n>=8, n=%d 点) ===" % (a, b, m))
    print("  固定成本 a      = %.1f ms" % a)
    print("  边际成本 b      = %.3f ms/块" % b)
    print("  639 块预测      = %.1f ms" % (a + b * 639))
    # 残差: 拟合质量差说明不是线性, 有共享阶段
    print("\n=== 拟合残差 ===")
    for n, t in rows:
        pred = a + b * n
        print("  n=%4d  实际 %8.1f  预测 %8.1f  残差 %+7.1f (%+5.1f%%)"
              % (n, t, pred, t - pred, 100 * (t - pred) / pred if pred else 0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
