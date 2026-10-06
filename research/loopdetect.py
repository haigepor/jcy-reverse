#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""loopdetect.py — 从 PC trace 还原控制流,找出反复执行的紧循环(超块候选)。

为什么做这个(V22):
  hotspot.py 已证明 2,180,018 条执行里73.3% 集中在 6,399 个热 PC(各>=100 次)。
  要拿到 3.5-4x 提速, 必须把这些热路径变成**紧凑顺序代码**(而不是
  每次都过一遍 computed-goto dispatch)。基本块合并已经在块内做了这件事,
  但块内仍有分支回边时会跳出去。
  本脚本回答: 控制流里有几个"回边"(back edge)？每个回边构成的循环体
  有多少条指令、多被执行多少次？-> 决定能否进一步做 trace 级超块/循环展开。

输出:
  - 回边总数与位置分布
  - 每个循环的: 迭代次数(近似)、静态指令数、动态指令占比
  - 若某循环动态占比极高, 它就是下一个优化目标
"""
import collections
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEV_BASE = 0x400024a00000


def load_trace(path):
    pcs = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                pcs.append(int(line, 16))
    return pcs


def find_loops(pcs, min_len=4, max_len=20000):
    """用"回边=当前PC 在栈上出现过"识别循环。返回 [(body_start, body_len, iters)].

    这是标准的 back-edge 检测: 任一 PC 再次出现即视为一次回边,
    迭代次数 = 该 PC 的出现次数 - 1。
    """
    last_seen = {}
    loops = []
    for i, pc in enumerate(pcs):
        if pc in last_seen:
            body_start = last_seen[pc]
            body_len = i - body_start + 1
            if min_len <= body_len <= max_len:
                loops.append((body_start, body_len))
        last_seen[pc] = i
    return loops


def main():
    p = os.path.join(HERE, "engine_c", "out1i.bin.trace")
    if not os.path.exists(p):
        print("找不到 trace:", p)
        return 1
    pcs = load_trace(p)
    n = len(pcs)
    print("trace 条数: %d" % n)

    # 1) 最频繁的"回跳目标"= 循环头
    cnt = collections.Counter(pcs)
    top = cnt.most_common(15)
    print("\n=== 回跳目标 Top15 (循环头候选) ===")
    for pc, c in top:
        print("  0x%08x  出现 %6d 次 -> 迭代约 %6d 次" % (pc, c, c - 1))

    # 2) 相邻 PC 连续性: 统计动态 trace 里"顺序相邻"(pc+4) 的比例
    seq = sum(1 for a, b in zip(pcs, pcs[1:]) if b == a + 4)
    print("\n=== 顺序相邻 (fall-through) 占比 ===")
    print("  %d / %d = %.1f%%" % (seq, n - 1, 100 * seq / (n - 1)))

    # 3) 转移类型分布
    kinds = collections.Counter()
    for a, b in zip(pcs, pcs[1:]):
        d = b - a
        if d == 4:
            kinds["fallthrough"] += 1
        elif d <= 0:
            kinds["backedge"] += 1
        elif d <= 1024:
            kinds["forward_short"] += 1
        else:
            kinds["forward_far"] += 1
    print("\n=== 转移类型分布 ===")
    for k, v in kinds.most_common():
        print("  %-14s %9d  (%.1f%%)" % (k, v, 100 * v / (n - 1)))

    # 4) 识别出的循环
    loops = find_loops(pcs)
    if loops:
        # 按 body_len 聚合
        agg = collections.Counter()
        dyn = collections.Counter()
        for s, L in loops:
            agg[L] += 1
            dyn[L] += L
        print("\n=== 回边识别出的循环体长度分布 (Top15) ===")
        for L, cntn in agg.most_common(15):
            print("  体长 %6d:出现 %6d 次  累计动态 %9d 条 (%.1f%%)"
                  % (L, cntn, dyn[L], 100 * dyn[L] / n))
        print("  回边总数: %d" % len(loops))
    return 0


if __name__ == "__main__":
    sys.exit(main())
