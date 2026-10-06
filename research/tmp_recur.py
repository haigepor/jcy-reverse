# -*- coding: utf-8 -*-
"""tmp_recur.py — 用纯 Python E 检验 CONST/Cb 的递推结构。

已知（tmp_tweak2 实测）：Cb_b = CONST_{b+1} ^ CONST_1   (b>=0)
推论：X_{b+1} = pt_{b+1} ^ E(X_b) ^ CONST_1
本脚本检验 CONST_b 自身是否由 E 递推生成（若干候选）。
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
from decrypt_e import expand, F, F_inv, xr, T  # noqa: E402

J = json.load(open(os.path.join(HERE, "tmp_tweak2.json")))
K = bytes.fromhex(J["K"])
iv = bytes.fromhex(J["iv"])
C = bytes.fromhex(J["C"])
CONST = [bytes.fromhex(x) for x in J["CONST"]]
Cb = [bytes.fromhex(x) for x in J["Cb"]]
rk = expand(K)
E = lambda x: xr(F(x, rk), C)
Ei = lambda y: F_inv(xr(y, C), rk)

n = len(CONST)

# 0) 复核 Cb_b == CONST_{b+1} ^ CONST_1
print("=== 复核 Cb_b == CONST_{b+1} ^ CONST_1 ===")
ok = all(Cb[b] == xr(CONST[b + 1], CONST[1]) for b in range(0, n - 1))
print("  全部成立:", ok)

# 1) 对零明文 dummy 生成 X 序列，看是否等于 CONST/Cb
print("\n=== dummy 链 X_0=iv, X_{b+1}=E(X_b)^CONST_1 ===")
X = [xr(bytes(16), iv)]      # X_0 = 0 ^ iv
for b in range(n):
    X.append(xr(E(X[b]), CONST[1]))
for b in range(0, 6):
    print("  X_%d=%s  CONST_%d=%s  Cb_%d=%s"
          % (b, X[b].hex(), b, CONST[b].hex(), b, Cb[b].hex()))
print("  X_b == CONST_b ?", [X[b] == CONST[b] for b in range(1, 6)])
print("  X_b == Cb_b ?   ", [X[b] == Cb[b] for b in range(1, 6)])

# 2) 递推候选
print("\n=== CONST 递推候选 ===")


def test(name, fn):
    good = [b for b in range(1, n - 1) if fn(b)]
    print("  %-40s 命中 %d/%d" % (name, len(good), n - 2))
    return len(good)


test("CONST_{b+1} == E(CONST_b)", lambda b: CONST[b + 1] == E(CONST[b]))
test("CONST_{b+1} == E(CONST_b) ^ CONST_1", lambda b: CONST[b + 1] == xr(E(CONST[b]), CONST[1]))
test("CONST_{b+1} == E(CONST_b ^ CONST_1)", lambda b: CONST[b + 1] == E(xr(CONST[b], CONST[1])))
test("CONST_{b+1} == E(CONST_b ^ iv)", lambda b: CONST[b + 1] == E(xr(CONST[b], iv)))
test("CONST_{b+1} == E(CONST_b) ^ Cb_b", lambda b: CONST[b + 1] == xr(E(CONST[b]), Cb[b]))
test("CONST_{b+1} == E(CONST_b ^ Cb_b)", lambda b: CONST[b + 1] == E(xr(CONST[b], Cb[b])))
test("CONST_{b+1} == E(CONST_b) ^ CONST_{b} ^ CONST_1", lambda b: CONST[b + 1] == xr(xr(E(CONST[b]), CONST[b]), CONST[1]))
test("Cb_{b+1} == E(Cb_b)", lambda b: Cb[b + 1] == E(Cb[b]))
test("Cb_{b+1} == E(Cb_b ^ CONST_1)", lambda b: Cb[b + 1] == E(xr(Cb[b], CONST[1])))
test("CONST_{b+1} == E(CONST_b ^ b16)", lambda b: CONST[b + 1] == E(xr(CONST[b], b.to_bytes(16, "little"))))

# 3) CONST_1 是什么？
print("\n=== CONST_1 来源 ===")
c1 = CONST[1]
print("  CONST_1      =", c1.hex())
print("  E(0)         =", E(bytes(16)).hex())
print("  E(iv)        =", E(iv).hex())
print("  E(E(0))      =", E(E(bytes(16))).hex())
print("  E(iv)^iv     =", xr(E(iv), iv).hex())
print("  Ei(CONST_1)  =", Ei(c1).hex())
print("  Ei(CONST_1)^iv=", xr(Ei(c1), iv).hex())
print("  T(iv)        =", bytes(T(list(iv))).hex())
print("  Ei(CONST_1)^CONST_1 =", xr(Ei(c1), c1).hex())

# 4) 差分：CONST_b ^ CONST_1 是否 = 前 b-1 项某种累加
print("\n=== CONST_b ^ CONST_1 ===")
for b in range(1, 6):
    print("  b=%d  %s" % (b, xr(CONST[b], CONST[1]).hex()))
