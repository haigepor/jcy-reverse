# -*- coding: utf-8 -*-
"""verify_decrypt_c.py — 验证 C 解密主循环与 Python 逐字节一致。

背景: 2026-10-06 把 decrypt() 的主循环(F_inv 10 轮 SM4)从 Python 下沉到
C (jcy_decrypt)。这是纯性能改动, **必须证明输出一位不差**。

三档验证:
  1. F_inv 单块: jcy_finv vs Python F_inv, 随机向量对拍
  2. 整链: jcy_decrypt vs Python 循环, 1/8/128/639 块
  3. 端到端: EDecryptor.decrypt() 走C 路径 vs 强制 Python 路径

关键: 必须在**同一K** 下比,且两边用同一份标定产物(CONST/Cb),
否则比的是标定差异而非解密差异。
"""
import os, sys, random

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "deliverables"))

import c_engine
c_engine.init(os.path.join(HERE, "engine_c", "image639.bin"))

from decrypt_e import EDecryptor, F_inv, expand, xr

lib = c_engine.load()
HAS_DECRYPT = hasattr(lib, "jcy_decrypt")
HAS_FINV = hasattr(lib, "jcy_finv")
print("DLL = %s" % os.path.basename(getattr(lib, "_name", "?")))
print("jcy_decrypt 导出: %s" % ("有" if HAS_DECRYPT else "**无(将落回Python)**"))
print("jcy_finv   导出: %s" % ("有" if HAS_FINV else "**无**"))
print()

fails = 0

# ---------------------------------------------------------------- 1. F_inv 单块
print("=" * 62)
print("1. F_inv 单块对拍 (jcy_finv vs Python F_inv)")
print("=" * 62)
if HAS_FINV:
    rk = expand(bytes(range(0x05, 0x15)))
    random.seed(1234)
    bad = 0
    for i in range(2000):
        w = bytes(random.randrange(256) for _ in range(16))
        k = bytes(random.randrange(256) for _ in range(16))
        exp = F_inv(w, expand(k))
        got = c_engine.finv(w, k)
        if got != exp:
            bad += 1
            if bad <= 3:
                print("  MISMATCH w=%s k=%s\n    exp=%s\n    got=%s"
                      % (w.hex(), k.hex(), exp.hex(), got.hex()))
    print("  2000 组随机向量: %s" % ("全部一致" if bad == 0 else "**%d 组不一致**" % bad))
    fails += (bad > 0)
else:
    print("  跳过(无导出)")

# ---------------------------------------------------------------- 2. 整链对拍
print()
print("=" * 62)
print("2. 整条解密主循环对拍 (jcy_decrypt vs Python 循环)")
print("=" * 62)
if HAS_DECRYPT:
    K = bytes(range(0x05, 0x15))
    d = EDecryptor(backend="c")
    for nb in (1, 8, 128, 639):
        P1 = bytes(16 * nb)
        C, rk, CONST, Cb = d.calibrate(K, nb)
        # Python 参考
        iv = K[::-1]
        exp = bytearray()
        for b in range(nb):
            ctb = P1[b * 16:(b + 1) * 16]
            xb = F_inv(xr(xr(ctb, C), Cb[b]), rk)
            prev = P1[b * 16 - 16:b * 16] if b else iv
            exp += xr(xr(xb, prev), CONST[b])
        # C 路径
        got = c_engine.decrypt_blocks(P1, K, C, b"".join(CONST), b"".join(Cb))
        same = (got == bytes(exp))
        print("  %4d 块: %s  (C %d 字节)" % (nb, "一致" if same else "**不一致**", len(got or b"")))
        if not same:
            fails += 1
            for i in range(min(len(exp), len(got or b""))):
                if exp[i] != got[i]:
                    print("    首个差异 @%d: exp=%02x got=%02x" % (i, exp[i], got[i]))
                    break
else:
    print("  跳过(无导出)")

# ---------------------------------------------------------------- 3. 端到端
print()
print("=" * 62)
print("3. 端到端 decrypt(): C 路径 vs 强制 Python 路径")
print("=" * 62)
K = bytes(range(0x05, 0x15))
random.seed(99)
for nb in (1, 84, 639):
    P1 = bytes(random.randrange(256) for _ in range(16 * nb))
    # C 路径(默认)
    d1 = EDecryptor(backend="c")
    a = d1.decrypt(P1, K)
    # 强制 Python 路径: 屏蔽 _decrypt_c
    d2 = EDecryptor(backend="c")
    d2._decrypt_c = lambda *a, **k: None
    b = d2.decrypt(P1, K)
    same = (a == b)
    print("  %4d 块: %s  (C %d 字节 / Py %d 字节)"
          % (nb, "一致" if same else "**不一致**", len(a), len(b)))
    if not same:
        fails += 1

# ---------------------------------------------------------------- 4. 增量标定
print()
print("=" * 62)
print("4. 增量标定: 复用后小请求应零引擎开销")
print("=" * 62)
import time
K = bytes(range(0x15, 0x25))
d = EDecryptor(backend="c")
P1 = bytes(16 * 639)
t0 = time.time(); d.calibrate(K, 639); t1 = (time.time() - t0) * 1000
t0 = time.time(); d.calibrate(K, 84); t2 = (time.time() - t0) * 1000
t0 = time.time(); d.calibrate(K, 3); t3 = (time.time() - t0) * 1000
print("  首次标定 639 块 : %9.3f ms" % t1)
print("  复用标定  84 块 : %9.4f ms" % t2)
print("  复用标定   3 块 : %9.4f ms" % t3)
if t1 > 0:
    print("  复用倍率: %.0f倍 / %.0f 倍" % (t1 / max(t2, 1e-9), t1 / max(t3, 1e-9)))
# 不变式必须仍然成立
C, rk, CONST, Cb = d.calibrate(K, 639)
inv = all(Cb[b] == xr(CONST[b + 1], CONST[1]) for b in range(638))
print("  V15 不变式 (Cb_b == CONST_b+1 ^ CONST_1): %s" % ("成立" if inv else "**破坏**"))
if not inv:
    fails += 1

print()
print("=" * 62)
print("总计: %s" % ("全部通过" if fails == 0 else "**%d 项失败**" % fails))
print("=" * 62)
sys.exit(1 if fails else 0)
