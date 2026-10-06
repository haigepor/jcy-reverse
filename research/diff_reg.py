#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""diff_reg.py — 对拍 C 引擎与 Unicorn 的寄存器快照, 逐字段找第一个不同.

输入:
  ref : reports/reg_ref.txt        (py -3.12 probe_reg.py 产出)
  clog: C 侧 run*.log 里 '^R ' 开头的行
按 "组" 对齐 (组 = 从 R 0x2e2eb8 到 R 0x2e2ee8 为一次经过), 逐组逐字段比.
"""
import re
import sys

F = re.compile(r"(\w+)=0x([0-9a-f]+)")


def parse(lines):
    groups, cur = [], []
    for ln in lines:
        ln = ln.strip()
        if not ln.startswith("R "):
            continue
        d = dict((k, int(v, 16)) for k, v in F.findall(ln))
        if "R" not in d:
            continue
        d["__pc"] = d["R"]
        del d["R"]
        cur.append(d)
        if d["__pc"] == 0x2e2ee8:
            groups.append(cur)
            cur = []
    if cur:
        groups.append(cur)
    return groups


def main():
    ref = parse(open(sys.argv[1], encoding="utf-8", errors="replace").read().splitlines())
    clog = parse(open(sys.argv[2], encoding="utf-8", errors="replace").read().splitlines())
    print("ref 组数 %d, c 组数 %d" % (len(ref), len(clog)))
    if not ref or not clog:
        print("FAIL 有一侧为空")
        return 1

    ng = min(len(ref), len(clog))
    firstbad = None
    for gi in range(ng):
        gr, gc = ref[gi], clog[gi]
        for ri in range(min(len(gr), len(gc))):
            pr, pc = gr[ri], gc[ri]
            if pr["__pc"] != pc["__pc"]:
                print("组%d 行%d PC 不同: ref 0x%x / c 0x%x" % (gi, ri, pr["__pc"], pc["__pc"]))
                firstbad = (gi, ri, "PC")
                break
            for k in sorted(set(pr) | set(pc)):
                if k == "__pc":
                    continue
                a, b = pr.get(k), pc.get(k)
                if a != b:
                    print("组%d 行%d PC=0x%x  字段 %s: ref=0x%x  c=0x%x" % (gi, ri, pr["__pc"], k, a or 0, b or 0))
                    if firstbad is None:
                        firstbad = (gi, ri, k)
        if firstbad:
            break

    if not firstbad:
        print("PASS 前 %d 组全部字段一致" % ng)
        return 0
    gi, ri, k = firstbad
    print("\n首个不同: 组%d 行%d 字段 %s" % (gi, ri, k))
    print("--- ref 该行 ---")
    print(" ".join("%s=0x%x" % (kk, v) for kk, v in sorted(ref[gi][ri].items()) if kk != "__pc"))
    print("--- c 该行 ---")
    print(" ".join("%s=0x%x" % (kk, v) for kk, v in sorted(clog[gi][ri].items()) if kk != "__pc"))
    return 1


if __name__ == "__main__":
    sys.exit(main())
