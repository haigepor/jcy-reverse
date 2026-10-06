# -*- coding: utf-8 -*-
"""tmp_prof.py — 定位标定 0.53s/块 的耗时构成。"""
import cProfile
import os
import pstats
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
from decrypt_e import EDecryptor  # noqa: E402


def main():
    d = EDecryptor()
    t0 = time.time()
    d.calibrate(bytes(16), 4)          # 预热（含 Unicorn 初始化）
    print("预热 4 块: %.2fs" % (time.time() - t0))

    pr = cProfile.Profile()
    pr.enable()
    t0 = time.time()
    d.calibrate(b"\x01" * 16, 16)
    dt = time.time() - t0
    pr.disable()
    print("profile 16 块: %.2fs  (%.3f s/块)" % (dt, dt / 16))

    s = pstats.Stats(pr)
    s.sort_stats("tottime")
    print("\n=== 按 tottime 排序 top20 ===")
    s.print_stats(20)


if __name__ == "__main__":
    main()
