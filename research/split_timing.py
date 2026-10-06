# -*- coding: utf-8 -*-
"""split_timing.py — 决定性实验: 拆开「标定」与「解密」分别计时。

为什么这是决定性的
------------------
读 deliverables/decrypt_e.py 的 decrypt() 后会发现:

    C, rk, CONST, Cb = self.calibrate(K16, use)      # <- 只依赖 K 和块数
    for b in range(use):
        ctb = P1[b*16:(b+1)*16]
        xb  = F_inv(xr(xr(ctb, C), Cb[b]), rk)        # <- 只依赖 Cb[b] 和 rk
        prev = P1[b*16-16:b*16] if b else iv          # <- 前序**密文**, 非明文
        out += xr(xr(xb, prev), CONST[b])

每块的真实运算量是:2 次 xor + 1 次 AES-10 轮 F_inv + 2 次 xor
= **约 10 轮 AES 等价运算 / 16 字节**, 也就是 ~0.6 us/块 量级(C 实现)
或~30 us/块 量级(Python 实现)。

而引擎要跑 ~986,428 条 ARM64 指令/块(见 ref_trace_128blk.txt)才产出
Cb[b] / CONST[b]。也就是说:

    引擎 100 万条 ARM64 指令  ==  标定出 16 字节的 Cb[b]
    解密 16 字节本身只要 10 轮 AES

**引擎的唯一职责就是标定。** 加密引擎模拟的是 App 内部的 key schedule +
轮函数, 而这些已经被我们用 expand()/F()/MC/SR/SB 精确复刻了 —— Cb[b] 和
CONST[b] 完全可以直接算, 不必再跑一遍 ARM64。

所以「跟 app 一致的解密手段」的正确解法不是优化解释器, 而是:
  **把标定从「跑 ARM64 引擎」换成「直接算」, 让引擎彻底退出热路径。**

本脚本验证三件事:
  A. 标定 vs 解密 的时间占比(引擎开销到底在哪)
  B. 标定结果只依赖 K -> 同一 K 可跨请求复用(缓存命中率)
  C. 解密本身的极限速度(纯 C, 无引擎)
"""
import os, sys, time, hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "deliverables"))


def main():
    from decrypt_e import EDecryptor, F_inv, xr
    K = bytes(range(0x05, 0x15))

    print("=" * 68)
    print("A. 标定 vs 解密 时间拆分")
    print("=" * 68)
    print("%8s %12s %12s %12s %10s" % ("块数", "标定ms", "纯解密ms", "合计ms", "标定占比"))
    rows = []
    for nb in (1, 84, 168, 539, 639):
        P1 = bytes(16 * nb)
        d = EDecryptor(backend="c")          # 每次新实例 -> 强制冷标定
        t0 = time.time()
        C, rk, CONST, Cb = d.calibrate(K, nb)
        t_cal = (time.time() - t0) * 1000

        # 纯解密: 标定产物已就绪, 只跑 decrypt 的循环体
        iv = K[::-1]
        t0 = time.time()
        out = bytearray()
        for b in range(nb):
            ctb = P1[b * 16:(b + 1) * 16]
            xb = F_inv(xr(xr(ctb, C), Cb[b]), rk)
            prev = P1[b * 16 - 16:b * 16] if b else iv
            out += xr(xr(xb, prev), CONST[b])
        t_dec = (time.time() - t0) * 1000
        tot = t_cal + t_dec
        rows.append((nb, t_cal, t_dec, tot))
        print("%8d %12.1f %12.1f %12.1f %9.1f%%"
              % (nb, t_cal, t_dec, tot, 100.0 * t_cal / tot))

    print()
    print("=" * 68)
    print("B. 标定产物只依赖 K -> 缓存命中率决定真实速度")
    print("=" * 68)
    d = EDecryptor(backend="c")
    t0 = time.time(); d.calibrate(K, 639); t1 = (time.time() - t0) * 1000
    t0 = time.time(); d.calibrate(K, 639); t2 = (time.time() - t0) * 1000
    print("  同一 K 首次标定639 块: %8.1f ms" % t1)
    print("  同一 K 二次(命中缓存): %8.4f ms  -> %.0f 倍" % (t2, t1 / max(t2, 1e-9)))
    print("  结论: 同一 K16 重复请求, 引擎开销 = %.4f ms" % t2)
    K2 = bytes(range(0x15, 0x25))
    t0 = time.time(); d.calibrate(K2, 639); t3 = (time.time() - t0) * 1000
    print("  换 K 标定 639 块:%8.1f ms  (每个新会话一次)" % t3)

    print()
    print("=" * 68)
    print("C. 纯解密的极限速度(无引擎)")
    print("=" * 68)
    nb = 639
    C, rk, CONST, Cb = d.calibrate(K, nb)
    P1 = bytes(16 * nb)
    iv = K[::-1]
    # 预热
    for _ in range(2):
        o = bytearray()
        for b in range(nb):
            ctb = P1[b * 16:(b + 1) * 16]
            xb = F_inv(xr(xr(ctb, C), Cb[b]), rk)
            prev = P1[b * 16 - 16:b * 16] if b else iv
            o += xr(xr(xb, prev), CONST[b])
    best = 1e9
    for _ in range(3):
        t0 = time.time()
        o = bytearray()
        for b in range(nb):
            ctb = P1[b * 16:(b + 1) * 16]
            xb = F_inv(xr(xr(ctb, C), Cb[b]), rk)
            prev = P1[b * 16 - 16:b * 16] if b else iv
            o += xr(xr(xb, prev), CONST[b])
        best = min(best, (time.time() - t0) * 1000)
    app = 0.7 * 9854955 * nb / 1e6   # 旧报告口径(注意: 该系数有 10 倍口径问题)
    print("  639 块纯 Python 解密      : %8.1f ms" % best)
    print("  639 块端到端(含冷标定)    : %8.1f ms" % (rows[-1][3]))
    print()
    print("  >>> 引擎(标定) 占 %.1f%%, 真正的解密只占 %.1f%%"
          % (100.0 * rows[-1][1] / rows[-1][3], 100.0 * rows[-1][2] / rows[-1][3]))
    print("  >>> 要「跟 app 一致」, 唯一要做的是把标定打掉或缓存住。")


main()
