#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""diff_trace.py — C 引擎 trace vs Unicorn 参考 trace 逐条对拍.

基准: reports/ref_trace_1blk.txt (由 gen_ref_trace.py 生成, 与 golden1 逐字节同源,
      已验证 body == golden1).  **不要用 trace_py_1blk.txt** —— 它与当前
      golden1 不是同一次运行, 在 idx 252879 上走向就不同, 会报假分叉.

用法: py -3.12 diff_trace.py [c_trace_file] [nblk]
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DB = 0x400024a00000


def read_c(path):
    """支持两种格式: 文本 (每行 0x...) 或 raw (8 字节 LE 连续)"""
    with open(path, "rb") as f:
        head = f.read(64)
    txt = None
    try:
        head.decode("ascii")
        txt = True
    except UnicodeDecodeError:
        txt = False
    data = open(path, "rb").read()
    if txt:
        return [int(x, 16) for x in data.split()]
    n = len(data) // 8
    return [v - DB for v in struct.unpack("<%dQ" % n, data[:n * 8])]


def main():
    cpath = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "engine_c", "out1b.bin.trace")
    nblk = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    rpath = os.path.join(HERE, "reports", "ref_trace_%dblk.txt" % nblk)

    ref = [int(x, 16) for x in open(rpath, encoding="utf-8").read().split()]
    print("参考 (Unicorn, 与 golden%d 同源): %d 条" % (nblk, len(ref)))
    if not os.path.exists(cpath):
        print("FAIL 缺 C 侧 trace: %s" % cpath)
        return 1
    c = read_c(cpath)
    print("C 引擎:                        %d 条" % len(c))

    m = min(len(ref), len(c))
    fd = None
    for i in range(m):
        if ref[i] != c[i]:
            fd = i
            break
    if fd is None:
        if len(ref) == len(c):
            print("PASS 前 %d 条完全一致, 长度也相同" % m)
            return 0
        print("前缀 %d 条一致, 但长度不同 (ref %d / c %d)"
              % (m, len(ref), len(c)))
        print("=> 引擎在此之后**多执行或少执行**, 提前结束或死循环")
        print("ref 尾部: %s" % [hex(x) for x in ref[m:m + 6]])
        print("c   尾部: %s" % [hex(x) for x in c[m:m + 6]])
        return 1

    print("FAIL 首个不同 idx = %d" % fd)
    lo = max(0, fd - 10)
    print("--- ref (Unicorn 真值) ---")
    for i in range(lo, min(len(ref), fd + 12)):
        print("  [%6d] 0x%x%s" % (i, ref[i], "   <<<" if i == fd else ""))
    print("--- c  (C 引擎) ---")
    for i in range(lo, min(len(c), fd + 12)):
        print("  [%6d] 0x%x%s" % (i, c[i], "   <<<" if i == fd else ""))
    # 算 ref 侧经过了多少次才到这个点
    print("\nref 在 fd 之前是第 %d 次到达 0x%x" % (ref[:fd].count(ref[fd]) + 1, ref[fd]))
    return 1


if __name__ == "__main__":
    sys.exit(main())
