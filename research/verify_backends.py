#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""verify_backends.py — C 引擎后端 vs Unicorn 后端的标定量逐位对拍 + 真实样本解密.

三层验证:
  A. 标定量: 同一 K, 两条后端各自 calibrate(nblk), 比较 C / CONST[] / Cb[]
     —— 若x_b 捕获或 T() 置换有任何偏差, 这里立刻暴露。
  B. 解密: 真实 tmp_pairs.json 样本, 两条后端解出的明文必须逐字节一致。
  C. 端到端: 639 块 dummy 全链路 (标定 + 解密) 计时。

用法:
    py -3.12 verify_backends.py A <nblk>
    py -3.12 verify_backends.py B
    py -3.12 verify_backends.py C <nblk>
"""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

from decrypt_e import EDecryptor   # noqa: E402


def layer_a(nblk):
    K = bytes(range(0x05, 0x15))
    dc = EDecryptor(backend="c")
    du = EDecryptor(backend="unicorn")
    t0 = time.time()
    Cc, rkc, CONSTc, Cbc = dc.calibrate(K, nblk)
    tc = (time.time() - t0) * 1000
    t0 = time.time()
    Cu, rku, CONSTu, Cbu = du.calibrate(K, nblk)
    tu = (time.time() - t0) * 1000
    print("标定 %d 块:  C %.0f ms   Unicorn %.0f ms   加速 %.1fx"
          % (nblk, tc, tu, (tu / tc) if tc else 0))
    ok = True
    if Cc != Cu:
        print("  FAIL C 常量不同: c=%s u=%s" % (Cc.hex(), Cu.hex())); ok = False
    else:
        print("  C   常量一致")
    if rkc != rku:
        print("  FAIL rk 不同"); ok = False
    dbad = [b for b in range(nblk) if CONSTc[b] != CONSTu[b]]
    if dbad:
        print("  FAIL CONST 差异块: %s" % dbad[:8]); ok = False
    else:
        print("  CONST[%d] 全部一致" % nblk)
    cbad = [b for b in range(nblk) if Cbc[b] != Cbu[b]]
    if cbad:
        print("  FAIL Cb 差异块: %s" % cbad[:8]); ok = False
    else:
        print("  Cb[%d] 全部一致" % nblk)
    print("  C 侧不变式自检 = %s ; Unicorn 侧 = %s"
          % (dc.invariant_ok, du.invariant_ok))
    return ok


def layer_b():
    p = os.path.join(HERE, "tmp_pairs.json")
    pairs = json.load(open(p, encoding="utf-8"))
    dc = EDecryptor(backend="c")
    du = EDecryptor(backend="unicorn")
    ok = same = skip = 0
    bad = []
    for e in pairs:
        if not e.get("k16"):
            continue
        P1 = bytes.fromhex(e["p1_hex"])
        if len(P1) % 16:
            skip += 1
            continue
        K = e["k16"].encode()
        a = dc.decrypt(P1, K)
        b = du.decrypt(P1, K)
        if a == b:
            same += 1
        else:
            bad.append((e["hit"], len(a), len(b), a[:40], b[:40]))
    print("真实样本: 一致 %d / 不一致 %d / 跳过 %d" % (same, len(bad), skip))
    for h, la, lb, pa, pb in bad[:5]:
        print("  hit=%s len %d/%d\n    C  =%r\n    U  =%r" % (h, la, lb, pa, pb))
    return not bad


def layer_c(nblk):
    K = bytes(range(0x05, 0x15))
    dc = EDecryptor(backend="c")
    P1 = bytes(16 * nblk)
    t0 = time.time()
    cal = dc.calibrate(K, nblk)
    t_cal = (time.time() - t0) * 1000
    t0 = time.time()
    pt = dc.decrypt(P1, K)
    t_dec = (time.time() - t0) * 1000
    print("C 引擎 639 块全链路: 标定 %.0f ms + 解密 %.0f ms = %.0f ms"
          % (t_cal, t_dec, t_cal + t_dec))
    print("  标定量: C=%s CONST0=%s Cb0=%s"
          % (cal[0].hex()[:16], cal[2][0].hex()[:16], cal[3][0].hex()[:16]))
    return t_cal + t_dec


if __name__ == "__main__":
    lay = sys.argv[1] if len(sys.argv) > 1 else "A"
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 128
    if lay == "A":
        sys.exit(0 if layer_a(n) else 1)
    if lay == "B":
        sys.exit(0 if layer_b() else 1)
    if lay == "C":
        ms = layer_c(n)
        print("目标 <1000 ms: %s (%.0f ms)" % ("达标" if ms < 1000 else "未达标", ms))