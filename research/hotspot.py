#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""hotspot.py — 分析单块 PC trace, 找出被反复执行最多的 PC。

用途: 判断"算子提取 / 超块 / 去重"这条路能拿走多少时间。
判据(V22):
  - 若 top PC 集中在极少数地址 (比如 Top100 占 >60%), 说明存在可整体提取的
    热点循环 -> 值得做子函数化 / 常量折叠。
  - 若 PC 分布极平 (模拟解释器的特征), 说明单个 PC 无优化空间, 唯一出路是
    把整段翻译成紧凑的顺序代码(基本块合并已做) 或换动态二进制翻译。
"""
import collections
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load_trace(path, limit=None):
    pcs = []
    with open(path, "r") as f:
        for i, line in enumerate(f):
            if limit and i >= limit:
                break
            line = line.strip()
            if line:
                pcs.append(int(line, 16))
    return pcs


def main():
    p = os.path.join(HERE, "engine_c", "out1i.bin.trace")
    if not os.path.exists(p):
        print("找不到 trace:", p)
        return 1
    pcs = load_trace(p)
    n = len(pcs)
    print("trace 总条数: %d" % n)
    if n == 0:
        return 1

    cnt = collections.Counter(pcs)
    uniq = len(cnt)
    print("唯一 PC 数:%d  (1:%.1f, 即每 PC 平均执行 %.1f 次)"
          % (uniq, n / uniq, n / uniq))

    print("\n=== Top 20 热PC ===")
    cum = 0
    for pc, c in cnt.most_common(20):
        cum += c
        print("  0x%08x  %9d 次  累计 %5.1f%%" % (pc, c, 100 * cum / n))

    for k in (10, 50, 100, 500, 1000, 5000):
        if uniq >= k:
            s = sum(c for _, c in cnt.most_common(k))
            print("  Top%-5d 累计占比 %5.1f%%" % (k, 100 * s / n))

    # 直方图: 执行次数分布
    hist = collections.Counter(cnt.values())
    print("\n=== 执行次数分布 ===")
    for times in sorted(hist)[:12]:
        pcsn = sum(1 for c in cnt.values() if c == times)
        print("  执行 %2d 次的 PC: %6d 个" % (times, pcsn))
    big = sum(c for c in cnt.values() if c >= 100)
    print("  执行 >=100 次的 PC: %d 个 (占唯一 PC %.1f%%)"
          % (big, 100 * big / uniq))
    return 0


if __name__ == "__main__":
    sys.exit(main())
