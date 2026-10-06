# -*- coding: utf-8 -*-
"""tmp_preimg.py — 检查 CONST_b 的 E 原像序列 A_b = E_inv(CONST_b) 的结构。

若 A_{b+1} ^ A_b 恒定 → CONST_b = E(A_0 ^ b·c)，即「E 作用在等差计数器上」，
纯 Python 即可复现。
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
from decrypt_e import expand, F, F_inv, xr  # noqa: E402

J = json.load(open(os.path.join(HERE, "tmp_tweak2.json")))
K = bytes.fromhex(J["K"])
iv = bytes.fromhex(J["iv"])
C = bytes.fromhex(J["C"])
CONST = [bytes.fromhex(x) for x in J["CONST"]]
Cb = [bytes.fromhex(x) for x in J["Cb"]]
rk = expand(K)
E = lambda x: xr(F(x, rk), C)
Ei = lambda y: F_inv(xr(y, C), rk)

A = [Ei(x) for x in CONST]
B = [Ei(x) for x in Cb]
n = len(A)

print("=== A_b = E_inv(CONST_b) ===")
for b in range(1, 8):
    print("  A_%d = %s" % (b, A[b].hex()))

print("\n-- A_{b+1} ^ A_b --")
d = [xr(A[b], A[b + 1]) for b in range(1, n - 1)]
print("  唯一值数:", len(set(d)))
for b in range(1, 7):
    print("  b=%d  %s" % (b, d[b - 1].hex()))

print("\n-- B_b = E_inv(Cb_b) ; B_{b+1}^B_b --")
db = [xr(B[b], B[b + 1]) for b in range(1, n - 1)]
print("  唯一值数:", len(set(db)))
for b in range(1, 6):
    print("  b=%d  %s" % (b, db[b - 1].hex()))

print("\n-- 其它候选 --")
tests = {
    "A_{b+1} == E(A_b)": lambda b: A[b + 1] == E(A[b]),
    "A_{b+1} == A_b ^ iv": lambda b: A[b + 1] == xr(A[b], iv),
    "A_{b+1} == A_b ^ CONST_1": lambda b: A[b + 1] == xr(A[b], CONST[1]),
    "A_{b+1} == A_b ^ C(K)": lambda b: A[b + 1] == xr(A[b], C),
    "A_b == iv ^ b·const": None,
}
for nm, fn in tests.items():
    if fn is None:
        continue
    hit = sum(1 for b in range(1, n - 1) if fn(b))
    print("  %-28s 命中 %d/%d" % (nm, hit, n - 2))

# A_b ^ A_1 是否等于 (b-1) 倍某常量（在 GF(2) 上无意义，但检查整数差）
print("\n-- A_b ^ A_1 序列 --")
for b in range(1, 6):
    print("  b=%d  %s" % (b, xr(A[b], A[1]).hex()))

# 关键：CONST_b 是否等于 E(计数器) 且计数器 = b 的某种「乘法」编码
print("\n-- 暴力：E(x) == CONST_1 的 x 是否为简单值 --")
print("  x = A_1 =", A[1].hex(), " 非零字节数:", sum(1 for t in A[1] if t))
print("  x = A_2 =", A[2].hex(), " 非零字节数:", sum(1 for t in A[2] if t))
