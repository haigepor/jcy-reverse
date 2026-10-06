# -*- coding: utf-8 -*-
"""tmp_speed.py — 关掉逐指令 trace hook 后的标定速度对比。"""
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
from decrypt_e import EDecryptor  # noqa: E402


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 16
    d = EDecryptor()
    t0 = time.time()
    d.calibrate(bytes(16), 2)
    print("预热: %.2fs" % (time.time() - t0))

    t0 = time.time()
    C, rk, CONST, Cb = d.calibrate(b"\x01" * 16, n)
    dt = time.time() - t0
    print("标定 %d 块: %.2fs   (%.4f s/块)" % (n, dt, dt / n))

    # 纯 Python 求逆速度
    from decrypt_e import F_inv, xr
    P1 = os.urandom(16 * n)
    t0 = time.time()
    out = d.decrypt(P1, b"\x01" * 16, blocks=n)
    print("解密 %d 块(含标定缓存): %.2fs" % (n, time.time() - t0))


if __name__ == "__main__":
    main()
