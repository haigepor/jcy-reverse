# -*- coding: utf-8 -*-
"""tmp_g1_step6g.py — 流的字级功能依赖分析."""
import os
import json
import sys
from itertools import combinations

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "deliverables"))

G = json.load(open(os.path.join(HERE, "reports", "gen_stream.json")))
streams = {k: [bytes.fromhex(h) for h in s] for k, s in G["streams"].items()}

kh = list(streams)[0]
s = streams[kh]
N = len(s)
print("K=%s 流长 %d" % (kh[:8], N))

# 输出字 S[n+1][w] ← 输入字组合?
# 候选输入: 同词, 前 1..3 词, 加上跨块边界也统一按线性索引
def W(v, w):
    return int.from_bytes(v[4 * w:4 * w + 4], "big")


# 对每个输出字位置 w: 找最小输入字集合 (在 n 上滑动, 用所有 n=0..N-2 样本)
# 候选集合: {w-3..w} 的所有子集 (1..4 个字)
samples_n = list(range(N - 1))
for w in range(4):
    cands = []
    for r in range(1, 5):
        for combo in combinations(range(4), r):
            cands.append(combo)
    hit = None
    for combo in cands:
        m = {}
        ok = True
        for n in samples_n:
            key = tuple(W(s[n], (cw + w) % 4) for cw in combo)
            y = W(s[n + 1], w)
            if key in m and m[key] != y:
                ok = False
                break
            m[key] = y
        if ok:
            hit = combo
            break
    print("S[n+1][%d] ← 输入字(相对) %s" % (w, hit))

# 字节级: 输出字节 ← 输入字节的更细映射 (如果字级失败)
# 也测: 输出是否依赖更早的流项 (n-2, n-3)
print("\n=== 更早项依赖 (字级, 窗口 2) ===")
for w in range(4):
    for depth in (2, 3):
        m = {}
        ok = True
        for n in range(depth - 1, N - 1):
            key = tuple(W(s[n - d + 1], ww) for d in range(depth)
                        for ww in range(4))
            y = W(s[n + 1], w)
            if key in m and m[key] != y:
                ok = False
                break
            m[key] = y
        print("S[n+1][%d] ← 前 %d 项全字: 一致? %s (映射 %d)" % (w, depth, ok, len(m)))
