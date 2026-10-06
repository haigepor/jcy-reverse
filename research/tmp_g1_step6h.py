# -*- coding: utf-8 -*-
"""tmp_g1_step6h.py — 流的字节级功能依赖分析 (有碰撞约束的测试)."""
import os
import json
import sys
from itertools import combinations

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

G = json.load(open(os.path.join(HERE, "reports", "gen_stream.json")))
streams = {k2: [bytes.fromhex(h) for h in s] for k2, s in G["streams"].items()}

results = {}
for kh in list(streams)[:2]:
    s = streams[kh]
    N = len(s)
    # 字节视图: B[i][j] = s[i][j], j=0..15
    B = s
    # 输出字节 j ← 输入字节候选集: {j-7..j+8 mod 16} 太大; 先测同词+相邻词 8 字节
    print("=== K=%s N=%d ===" % (kh[:8], N))
    for j in range(16):
        # 候选输入字节: 绝对索引 (n 项内), 测子集; 先测单字节、双字节、三字节
        cands = list(range(16))  # 允许任意同项字节
        hit = None
        # 单字节
        for i0 in cands:
            m = {}
            ok = True
            cnt = 0
            for n in range(N - 1):
                key = B[n][i0]
                y = B[n + 1][j]
                if key in m:
                    cnt += 1
                    if m[key] != y:
                        ok = False
                        break
                m[key] = y
            if ok and cnt >= 50:
                hit = ("1B", (i0,))
                break
        if not hit:
            # 双字节: 输出词 w=j//4 的 4 字节两两组合 + 跨词
            pairs = [(i0, i1) for i0 in cands for i1 in cands if i0 < i1]
            for i0, i1 in pairs:
                m = {}
                ok = True
                cnt = 0
                for n in range(N - 1):
                    key = (B[n][i0], B[n][i1])
                    y = B[n + 1][j]
                    if key in m:
                        cnt += 1
                        if m[key] != y:
                            ok = False
                            break
                # 完整循环
                if ok:
                    m = {}
                    cnt = 0
                    for n in range(N - 1):
                        key = (B[n][i0], B[n][i1])
                        y = B[n + 1][j]
                        if key in m:
                            cnt += 1
                            if m[key] != y:
                                ok = False
                                break
                            m[key] = y
                        else:
                            m[key] = y
                    if ok and cnt >= 50:
                        hit = ("2B", (i0, i1))
                        break
        print("out[%2d] <- %s" % (j, hit))
        results[(kh, j)] = hit
