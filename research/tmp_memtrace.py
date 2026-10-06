# -*- coding: utf-8 -*-
"""tmp_memtrace.py — 抓 0x2d9ed0 单次调用内的内存访问画像。

目的：判定该生成器是「查表型（AES 类）」还是「纯位运算型（ARX/NEON）」。
只统计 PC 落在 [0x2d9ed0, 0x2da1c8) 的访存，按 PC 聚合。
"""
import os
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.join(HERE, "captures", "rsa_scan"),
           os.path.join(HERE, "deliverables"), os.path.join(HERE, "toolchain"),
           os.path.join(HERE, "..", "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import unicorn  # noqa: E402
from unicorn.arm64_const import UC_ARM64_REG_PC  # noqa: E402
from authgen import DEV_BASE  # noqa: E402
from e_oracle import EOracle  # noqa: E402

LO, HI = 0x2D9ED0, 0x2DA1C8
STATE = {"calls": 0, "active": False}
pc_cnt = Counter()
reads = Counter()
writes = Counter()
order = []


def main():
    o = EOracle()
    e = o.s.e
    uc = e.uc
    STACK_LO, STACK_HI = 0x7000000000, 0x8000000000

    def on_entry(uc_, addr, size, ud):
        STATE["calls"] += 1
        STATE["active"] = True

    def mk(acc):
        def cb(uc_, access, address, size, value, ud):
            if not STATE["active"]:
                return
            pc = uc_.reg_read(UC_ARM64_REG_PC) - DEV_BASE
            pc_cnt[(STATE["calls"], pc)] += 1
            if acc == "r":
                reads[address] += 1
            else:
                writes[address] += 1
            if len(order) < 200:
                order.append((STATE["calls"], pc, acc, address, size, value))
        return cb

    uc.hook_add(unicorn.UC_HOOK_CODE, on_entry, begin=DEV_BASE + LO, end=DEV_BASE + LO + 4)
    uc.hook_add(unicorn.UC_HOOK_MEM_READ, mk("r"))
    uc.hook_add(unicorn.UC_HOOK_MEM_WRITE, mk("w"))

    KEY = bytes(range(16))
    pt = b"\x00" * 16
    raw = o.enc(pt, KEY, KEY[::-1])
    STATE["active"] = False
    print("密文:", raw.hex(), " 0x2d9ed0 调用次数:", STATE["calls"])

    print("\n=== 访问过的 (调用,PC) 数: %d, 总访存事件: %d ===" % (len(pc_cnt), sum(pc_cnt.values())))
    print("\n--- 各调用的 PC 分布（次数 / 不同PC数）---")
    for ci in range(1, STATE["calls"] + 1):
        evs = [(pc, c) for (i, pc), c in pc_cnt.items() if i == ci]
        print("  调用 %d: 事件 %d, 不同 PC %d" % (ci, sum(c for _, c in evs), len(evs)))
        for pc, c in sorted(evs, key=lambda t: -t[1])[:8]:
            print("     0x%06x  %d 次" % (pc, c))

    print("\n--- 读地址 (去栈) top 20 ---")
    n = 0
    for a, c in reads.most_common(60):
        if STACK_LO <= a < STACK_HI:
            continue
        print("  0x%012x  %d 次" % (a, c))
        n += 1
        if n >= 20:
            break

    print("\n--- 写地址 top 20 ---")
    n = 0
    for a, c in writes.most_common(60):
        if STACK_LO <= a < STACK_HI:
            continue
        print("  0x%012x  %d 次" % (a, c))
        n += 1
        if n >= 20:
            break

    print("\n--- 前 40 条事件 ---")
    for ci, pc, acc, a, sz, v in order[:40]:
        print("  call=%d pc=0x%06x %s addr=0x%x size=%d val=%#x" % (ci, pc, acc, a, sz, v))


if __name__ == "__main__":
    main()
