# -*- coding: utf-8 -*-
"""tmp_bench_decrypt.py — 量化 E 离线解密的耗时构成与标定复杂度，并导出 CONST/Cb 样本。

目的：回答「解密为什么慢 / 能否达到 App 速度」。
  * 标定（Unicorn 仿真）与纯 Python 求逆分别计时；
  * 测 calibrate 随块数的伸缩；
  * dump 一个 K 的 CONST_b / Cb_b，供分析生成规则。
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "deliverables"))
from decrypt_e import EDecryptor, F, expand, xr, T  # noqa: E402


def main():
    d = EDecryptor()
    K0 = os.urandom(16)
    t0 = time.time()
    d.calibrate(K0, 4)
    print("[init] 首次标定(含 Unicorn 初始化, 4 块) %.2fs" % (time.time() - t0), flush=True)

    for n in (8, 16, 32, 64, 128):
        K = os.urandom(16)
        t0 = time.time()
        d.calibrate(K, n)
        dt = time.time() - t0
        print("[calibrate] nblk=%-4d %8.2fs   %.4fs/块" % (n, dt, dt / n), flush=True)

    # 纯 Python 求逆的速率（复用 128 块的标定结果，反复跑 decrypt 的循环部分）
    K = os.urandom(16)
    nblk = 128
    C, rk, CONST, Cb = d.calibrate(K, nblk)
    iv = K[::-1]
    P1 = os.urandom(16 * nblk)
    t0 = time.time()
    out = b""
    for b in range(nblk):
        ctb = P1[b * 16:(b + 1) * 16]
        from decrypt_e import F_inv
        xb = F_inv(xr(xr(ctb, C), Cb[b]), rk)
        prev = P1[b * 16 - 16:b * 16] if b else iv
        out += xr(xr(xb, prev), CONST[b])
    dt = time.time() - t0
    print("[pure-python 求逆] nblk=%-4d %8.4fs   %.6fs/块  (%.0f 块/秒)"
          % (nblk, dt, dt / nblk, nblk / dt), flush=True)

    # dump 前 8 块的 CONST/Cb，观察规律
    Kd = bytes(range(16))
    C, rk, CONST, Cb = d.calibrate(Kd, 8)
    print("\n[dump] K=%s" % Kd.hex())
    print("  C  = %s" % bytes(C).hex())
    for b in range(8):
        print("  b=%d  CONST=%s  Cb=%s" % (b, bytes(CONST[b]).hex(), bytes(Cb[b]).hex()))
    print("  校验 CONST[b+1] == CONST[b] ^ Cb[b] :",
          all(bytes(xr(CONST[b], Cb[b])) == bytes(CONST[b + 1]) for b in range(7)))
    # E(iv) 纯 Python 对照：E(x) = F(x, rk) ^ C
    print("  E(iv) 纯Python = %s" % bytes(xr(F(iv, rk), C)).hex())
    print("  CONST[0]      = %s   (CONST[0] 应 = x_0 ^ iv，x_0=iv → 应为全零? 见下)" % bytes(CONST[0]).hex())


if __name__ == "__main__":
    main()
