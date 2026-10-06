# -*- coding: utf-8 -*-
"""tmp_tweak_hunt.py — 验证 CONST_b 能否用纯 Python 算出（= E(某纯函数(b))？）。

若成立 → 可彻底扔掉 Unicorn 标定，解密从 0.53s/块 降到 0.0017s/块（300×），
整条响应 <1s，达到 App 同级的响应速度。
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

from decrypt_e import EDecryptor, F, expand, xr, T  # noqa: E402

K = bytes(range(16))
d = EDecryptor()
C, rk, CONST, Cb = d.calibrate(K, 8)
iv = K[::-1]


def E(x):
    return xr(F(bytes(x), rk), C)


TARGET = {b: bytes(CONST[b]) for b in range(1, 8)}
print("目标 CONST_1..7:")
for b in range(1, 8):
    print("  b=%d %s" % (b, TARGET[b].hex()))

# 复现记忆中的关系
print("\n关系校验 Cb_b == CONST_b ^ CONST_{b+1} (b>=1):",
      all(bytes(xr(CONST[b], Cb[b])) == bytes(CONST[b + 1]) for b in range(1, 7)))

CAND = []


def add(name, fn):
    CAND.append((name, fn))


# --- 各类「块号编码成 16 字节」的候选
add("b BE16", lambda b: b.to_bytes(16, "big"))
add("b LE16", lambda b: b.to_bytes(16, "little"))
add("b in [0]", lambda b: bytes([b]) + bytes(15))
add("b in [15]", lambda b: bytes(15) + bytes([b]))
add("b*0x1f in [0]", lambda b: bytes([(b * 0x1f) & 0xFF]) + bytes(15))
add("b*0x1f in [15]", lambda b: bytes(15) + bytes([(b * 0x1f) & 0xFF]))
add("0x1f*b all", lambda b: bytes([(b * 0x1f) & 0xFF]) * 16)
add("1..8 *0x1f + 8零", lambda b: bytes([((i + 1) * 0x1f) & 0xFF for i in range(8)]) + bytes(8))
add("1..8 *0x1f 循环16", lambda b: bytes([((i % 8 + 1) * 0x1f) & 0xFF for i in range(16)]))
add("counter iv^b", lambda b: xr(iv, b.to_bytes(16, "big")))
add("counter K^b", lambda b: xr(K, b.to_bytes(16, "big")))
add("counter T(b BE16)", lambda b: bytes(T(list(b.to_bytes(16, "big")))))
add("b*0x1f T", lambda b: bytes(T(list(bytes([(b * 0x1f) & 0xFF]) + bytes(15)))))
add("E0=ct0 派生 b", lambda b: xr(E(iv), b.to_bytes(16, "big")))

# --- 直接对候选做 E() 后比对
hits = []
for name, fn in CAND:
    ok = []
    for b in range(1, 8):
        try:
            if E(fn(b)) == TARGET[b]:
                ok.append(b)
        except Exception:
            pass
    if ok:
        hits.append((name, ok))
    print("  %-22s 命中 b=%s" % (name, ok or "-"))

# --- 反向：TARGET[b] 是否等于 F(候选) ^ C（同上）或就是候选本身
for name, fn in CAND:
    ok = [b for b in range(1, 8) if fn(b) == TARGET[b]]
    if ok:
        hits.append((name + " (直等)", ok))

# --- 差分规律：CONST_b ^ CONST_{b+1} 是否 = E(简单值)
print("\n差分 Cb_b 观察:")
for b in range(1, 7):
    print("  Cb_%d = %s" % (b, bytes(Cb[b]).hex()))

print("\n命中总数:", len(hits))
for h in hits:
    print("  ★", h)
