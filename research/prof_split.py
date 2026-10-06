#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""prof_split.py — 把639 块标定拆成"引擎执行" vs "Python 后处理"两段计时。

V22 要回答的唯一问题: 4142ms 里, 有多少是 C 引擎真在算, 有多少是 Python
循环在调 T()/xr()/F()?优化方向完全取决于这个比例:
  - 引擎占比高 -> 只能继续压引擎(编译/JIT/算子提取)
  - Python 占比高 -> 把后处理下沉到 C, 立刻见效, 且不碰已验证的引擎
"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

from decrypt_e import EDecryptor, T, F, xr, expand  # noqa: E402


def main(nblk=639, K=None):
    K = K or bytes(range(0x05, 0x15))
    dc = EDecryptor(backend="c")

    c = dc._c_engine()
    if c is None:
        print("C 引擎不可用")
        return 1

    # ---- 段1: 纯引擎 (encrypt_with_x 一次跑完 nblk 块) ----
    dummy = bytes(16 * nblk)
    t0 = time.time()
    ctd, xs = c.encrypt_with_x(K, dummy, nblk)
    t_engine = (time.time() - t0) * 1000

    # ---- 段1b: 引擎侧小量(1 块), 用于算"固定开销 vs 每块成本" ----
    t0 = time.time()
    c.encrypt_with_x(K, bytes(16), 1)
    t_engine_1 = (time.time() - t0) * 1000

    # ---- 段2: _determine_C_c (含一次 1 块加密) ----
    t0 = time.time()
    C = dc._determine_C_c(c, K)
    t_detC = (time.time() - t0) * 1000

    # ---- 段3: Python 后处理循环 (与 _calibrate_c 逐行一致) ----
    rk = expand(K)
    iv = K[::-1]
    t0 = time.time()
    CONST, Cb = [], []
    for b in range(nblk):
        xb = bytes(T(list(xs[b])))
        prev = ctd[b * 16 - 16:b * 16] if b else iv
        CONST.append(xr(xr(xb, dummy[b * 16:(b + 1) * 16]), prev))
        Cb.append(xr(ctd[b * 16:(b + 1) * 16], xr(F(xb, rk), C)))
    t_py = (time.time() - t0) * 1000

    total = t_engine + t_detC + t_py
    print("=== %d 块标定分段 ===" % nblk)
    print("  引擎 encrypt_with_x      %8.1f ms  (%.1f%%)" % (t_engine, 100 * t_engine / total))
    print("  _determine_C_c           %8.1f ms  (%.1f%%)" % (t_detC, 100 * t_detC / total))
    print("  Python 后处理循环        %8.1f ms  (%.1f%%)" % (t_py, 100 * t_py / total))
    print("  ------------------------------------------")
    print("  合计                    %8.1f ms" % total)
    print()
    print("  引擎 1 块基准           %8.1f ms" % t_engine_1)
    print("  引擎边际 (639-1)/638     %8.1f ms/块"
          % ((t_engine - t_engine_1) / max(1, nblk - 1)))
    print("  Python 边际             %8.1f ms/块" % (t_py / nblk))
    print()
    # 引擎固定开销占比 —— 决定并行/池化是否还有意义
    print("  引擎固定开销占比         %.1f%%" % (100 * t_engine_1 / t_engine))
    return 0


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 639
    sys.exit(main(n))
