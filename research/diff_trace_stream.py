#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""diff_trace_stream.py — 大 trace 的流式逐条对拍 (内存恒定).

为什么不用 diff_trace.py: 128 块参考 trace 有 1.26 亿条 / 1.26 GB 文本,
`read().split()` 会把 1.26 亿个 Python int 塞进 list (约 4.5 GB 内存),
在 16 GB 机器上很容易 OOM. 本脚本按块流式读, 常驻内存 < 32 MB.

用法:
    py -3.12 diff_trace_stream.py ref.txt c_trace.txt [limit]
      ref.txt     —— 文本 trace, 每行 0x<十六进制>, 可以是完整文件也可以更长
      c_trace.txt —— C 引擎 trace (同为 0x 文本格式)
      limit       —— 只比对前 N 条 (0 = 全部)

退出码: 0 = 在比对范围内完全一致; 1 = 出现分叉或长度不同.
"""
import os
import sys

CHUNK_LINES = 1 << 20  # 每块 100 万行


def iter_hex(path):
    """逐块 yield (block_list, eof_flag), 元素为 int (0x 文本 -> so 偏移)."""
    tail = b""
    with open(path, "rb") as f:
        eof = False
        while not eof:
            buf = f.read(CHUNK_LINES * 11)
            if not buf:
                eof = True
                buf = b""
            else:
                # 若本次读到的最后一行不含换行, 保留到下一轮
                nl = buf.rfind(b"\n")
                if nl < 0:
                    tail, buf = tail + buf, b""
                    if len(tail) > 64:
                        raise ValueError("%s: 单行过长, 疑似二进制格式" % path)
                else:
                    tail = buf[nl + 1:]
                    buf = buf[:nl + 1]
            block = (tail if not buf else b"") + buf
            toks = block.split()
            yield [int(t, 16) for t in toks]
        return


def count_lines(path):
    n = 0
    with open(path, "rb") as f:
        while True:
            b = f.read(1 << 22)
            if not b:
                break
            n += b.count(b"\n")
    return n


def main():
    ref_path, c_path = sys.argv[1], sys.argv[2]
    limit = int(sys.argv[3]) if len(sys.argv) > 3 else 0

    for p in (ref_path, c_path):
        if not os.path.exists(p):
            print("FAIL 缺文件: %s" % p)
            return 1

    print("参考 (Unicorn): %s  %.2f MB" % (ref_path, os.path.getsize(ref_path) / 2 ** 20))
    print("C 引擎       : %s  %.2f MB" % (c_path, os.path.getsize(c_path) / 2 ** 20))

    ri, ci = iter_hex(ref_path), iter_hex(c_path)
    rb = cb = []
    ri_i = ci_i = 0        # 块内游标
    base = 0              # 已比对条数
    scanned_ref = scanned_c = 0

    while True:
        if ri_i >= len(rb):
            try:
                rb = next(ri)
            except StopIteration:
                rb = []
            ri_i = 0
        if ci_i >= len(cb):
            try:
                cb = next(ci)
            except StopIteration:
                cb = []
            ci_i = 0
        if not rb and not cb:
            break

        n = min(len(rb) - ri_i, len(cb) - ci_i)
        if n == 0:
            # 一边已到 EOF
            if len(rb) - ri_i == 0 and len(cb) - ci_i == 0:
                break
            break

        if limit and base + n > limit:
            n = limit - base
            if n <= 0:
                break

        a = rb[ri_i:ri_i + n]
        b = cb[ci_i:ci_i + n]
        scanned_ref += n
        scanned_c += n
        # 快路径: 整块相同则跳过逐条比较
        if a != b:
            for k in range(n):
                if a[k] != b[k]:
                    fd = base + k
                    lo = max(0, k - 8)
                    print("FAIL 首个不同 idx = %d (0x%x vs 0x%x)"
                          % (fd, a[k], b[k]))
                    print("--- 参考 (Unicorn 真值) ---")
                    for j in range(lo, min(n, k + 10)):
                        print("  [%9d] 0x%x%s" % (base + j, a[j], "   <<<" if j == k else ""))
                    print("--- C 引擎 ---")
                    for j in range(lo, min(n, k + 10)):
                        print("  [%9d] 0x%x%s" % (base + j, b[j], "   <<<" if j == k else ""))
                    return 1
        base += n
        ri_i += n
        ci_i += n
        if base % (CHUNK_LINES * 4) == 0:
            print("  ... 已比对 %d 条 (%.1f%% of %d)" % (base, 100.0 * base / max(scanned_ref, 1), scanned_ref))

    # 长度检查: 各自再数一遍总行数
    total_ref = count_lines(ref_path)
    total_c = count_lines(c_path)
    print("参考总条数: %d   C 侧总条数: %d" % (total_ref, total_c))
    if limit:
        print("limit=%d, 仅比对前 %d 条" % (limit, base))
        print("PASS 前 %d 条完全一致" % base if True else "")
        return 0
    if total_ref == total_c:
        print("PASS 全部 %d 条逐条完全一致, 长度也相同" % base)
        return 0
    print("前缀 %d 条一致, 但总长度不同 (ref %d / c %d)" % (base, total_ref, total_c))
    print("=> 引擎在此之后多执行或少执行: 提前结束或死循环")
    return 1


if __name__ == "__main__":
    sys.exit(main())