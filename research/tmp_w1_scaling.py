# -*- coding: utf-8 -*-
"""tmp_w1_scaling.py — 快/慢标定随块数的扩展性对比（同一仿真会话）。"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
sys.path.insert(0, os.path.join(HERE, "captures", "rsa_scan"))

from decrypt_e import EDecryptor, expand, xr, T  # noqa: E402
from authgen import DEV_BASE  # noqa: E402

RET = bytes.fromhex("c0035fd6")
DRIVER = DEV_BASE + 0x2DA498


def fast_run(d, K, nblk):
    o = d._oracle()
    uc = o.s.e.uc
    orig = o.s.e.rd(DRIVER, 4)
    uc.mem_write(DRIVER, RET)
    try:
        d._cap.clear()
        t0 = time.time()
        ctd = d._enc_big(bytes(16 * nblk), K, K[::-1])
        return time.time() - t0, ctd
    finally:
        uc.mem_write(DRIVER, orig)


def main():
    d = EDecryptor()
    t0 = time.time()
    d.calibrate(os.urandom(16), 2)   # 预热（含 boot）
    print("[boot+预热] %.2fs" % (time.time() - t0), flush=True)

    print("\n%-6s %-12s %-12s" % ("nblk", "慢(s/块)", "快(s/块)"))
    for n in (8, 32, 128, 512, 1024):
        K = os.urandom(16)
        t0 = time.time()
        d.calibrate(K, n)
        slow = (time.time() - t0) / n
        tf, _ = fast_run(d, K, n)
        fast = tf / n
        print("%-6d %-12.4f %-12.4f" % (n, slow, fast), flush=True)

    # 快路径大样本：594 块（视频列表 9.5KB 量级）与 2175 块（search 34KB 量级）
    for n in (594, 2175):
        K = os.urandom(16)
        tf, _ = fast_run(d, K, n)
        print("快标定 nblk=%-5d %.3fs  (%.5fs/块)" % (n, tf, tf / n), flush=True)


if __name__ == "__main__":
    main()
