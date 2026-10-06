#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""body 差分: engine_c/out*.bin vs reports/golden*.json
用法: py -3.12 diff_body.py 1     (或 128)
退出码 0=完全一致  1=有差异
"""
import json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load_golden(n):
    g = json.load(open(os.path.join(HERE, "reports", "golden%d.json" % n), encoding="utf-8"))
    return bytes.fromhex(g["body_hex"]), g


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    outp = os.path.join(HERE, "engine_c", "out%d.bin" % n)
    want, g = load_golden(n)

    if not os.path.exists(outp):
        print("FAIL  缺产物: %s" % outp)
        return 1
    got = open(outp, "rb").read()

    print("=== %d 块差分 ===" % n)
    print("golden: %d 字节   engine: %d 字节" % (len(want), len(got)))
    if len(got) != len(want):
        print("FAIL  长度不符 (差 %d)" % (len(got) - len(want)))
        m = min(len(want), len(got))
        got = got[:m]
        want_cmp = want[:m]
    else:
        want_cmp = want

    if got == want_cmp:
        print("PASS  逐字节完全一致 (%d 字节)" % len(want_cmp))
        return 0

    diff = [i for i in range(len(want_cmp)) if got[i] != want_cmp[i]]
    print("FAIL  %d / %d 字节不同 (%.2f%%)" % (len(diff), len(want_cmp),
                                               100.0 * len(diff) / max(1, len(want_cmp))))
    print("首个差异 idx = %d" % diff[0])
    lo = max(0, diff[0] - 8)
    for i in range(lo, min(len(want_cmp), diff[0] + 24)):
        mark = " <<<" if i in diff[:1] else ""
        print("  [%5d] want %02x  got %02x%s" % (i, want_cmp[i], got[i], mark))
    print("want 段: %s" % want_cmp[lo:lo + 32].hex())
    print("got  段: %s" % got[lo:lo + 32].hex())

    runs = []
    s = p = diff[0]
    for i in diff[1:]:
        if i == p + 1:
            p = i
        else:
            runs.append((s, p))
            s = p = i
    runs.append((s, p))
    print("差异区间 %d 段, 前 12 段:" % len(runs))
    for a, b in runs[:12]:
        print("  [0x%x..0x%x] len=%d" % (a, b, b - a + 1))
    return 1


if __name__ == "__main__":
    sys.exit(main())
