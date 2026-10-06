# -*- coding: utf-8 -*-
"""tmp_g1_step6b.py — 矛盾类型统计 + 选择子线性可分性(感知机)."""
import os
import json
import sys
import random

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))
from decrypt_e import xr  # noqa: E402

MJ = json.load(open(os.path.join(HERE, "reports", "gen_M.json")))
emapM = {int(k): int(v, 16) for k, v in MJ["emap"].items()}


def Mmap(v):
    out, vv, j = 0, v, 0
    while v:
        if v & 1:
            out ^= emapM.get(j, 0)
        v >>= 1
        j += 1
    return out


data = json.load(open(os.path.join(HERE, "reports", "gen_rks3.json")))
br = json.load(open(os.path.join(HERE, "reports", "gen_branches.json")))
Aset = set(br["grpA"])

samples = []
for kh, rec in data.items():
    K = bytes.fromhex(kh)
    u = int.from_bytes(xr(bytes.fromhex(rec["preSB0"]),
                          Mmap(int.from_bytes(K[::-1], "big")).to_bytes(16, "big")),
                       "big")
    y = int.from_bytes(bytes.fromhex(rec["rks"]["1"]), "big")
    samples.append((u, y, 0 if kh in Aset else 1))

# --- 矛盾类型: 4-碰撞 (同输入差不同输出差) ---
raw_contra = 0
chk = {}
for i in range(len(samples)):
    for j in range(i + 1, len(samples)):
        v = samples[i][0] ^ samples[j][0]
        if v == 0:
            continue
        o = samples[i][1] ^ samples[j][1]
        if v in chk:
            if chk[v] != o:
                raw_contra += 1
        else:
            chk[v] = o
print("4-碰撞矛盾对数:", raw_contra, "(唯一差分 %d)" % len(chk))

# --- 线性可分性: s = sign(w·bits(u) + b) ---
X = [[(u >> i) & 1 for i in range(128)] for u, y, s in samples]
Y = [s for u, y, s in samples]
# 感知机 (带 margin), 多次随机重启
def perceptron(X, Y, epochs=4000, lr=0.05):
    n, d = len(X), len(X[0])
    w = [0.0] * d
    b = 0.0
    idx = list(range(n))
    for ep in range(epochs):
        random.shuffle(idx)
        errs = 0
        for i in idx:
            act = sum(wi * xi for wi, xi in zip(w, X[i])) + b
            pred = 1 if act >= 0 else 0
            if pred != Y[i]:
                errs += 1
                sgn = 1 if Y[i] == 1 else -1
                for t in range(d):
                    w[t] += lr * sgn * X[i][t]
                b += lr * sgn
        if errs == 0:
            return w, b, ep
    return w, b, -1


random.seed(42)
w, b, ep = perceptron(X, Y)
print("线性感知机:", "第 %d 轮收敛 → 线性可分!" % ep if ep >= 0 else "不可分")

# 度2特征: u bits + 对抗同字节内? 全对 128*129/2 = 8256 特征 — 稀疏感知机
def feats2(u):
    bits = [(u >> i) & 1 for i in range(128)]
    f = dict(enumerate(bits))
    k = 128
    for i in range(128):
        bi = bits[i]
        for j in range(i + 1, 128):
            if bi & bits[j]:
                f[k] = 1
            k += 1
    return f


X2 = [feats2(u) for u, y, s in samples]
w2 = {}
b2 = 0.0
for ep in range(600):
    errs = 0
    order = list(range(len(X2)))
    random.shuffle(order)
    for i in order:
        act = b2 + sum(w2.get(t, 0.0) for t in X2[i])
        pred = 1 if act >= 0 else 0
        if pred != Y[i]:
            errs += 1
            sgn = 1.0 if Y[i] == 1 else -1.0
            for t in X2[i]:
                w2[t] = w2.get(t, 0.0) + 0.05 * sgn
            b2 += 0.05 * sgn
    if errs == 0:
        print("度2感知机: 第 %d 轮收敛 → 度2可分! 非零权重 %d" % (ep, len(w2)))
        top = sorted(w2.items(), key=lambda t: -abs(t[1]))[:16]
        names = []
        for t, wv in top:
            if t < 128:
                names.append("bit%d" % t)
            else:
                k = t - 128
                # 反解 (i,j): 序号 k 对应三角枚举
                i, j, acc = 0, 0, 127
                found = None
                for ii in range(128):
                    span = 127 - ii
                    if k < acc:
                        pass
                    if k >= acc - span and k < acc:
                        found = (ii, ii + 1 + (k - (acc - span)))
                        break
                    acc -= span
                names.append(str(found))
        print("  top 特征:", names)
        break
else:
    print("度2感知机: 未收敛")
