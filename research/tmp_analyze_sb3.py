# -*- coding: utf-8 -*-
"""tmp_analyze_sb3.py — 提取每块的 prev_i 与 CONST_i = prev_i ^ ct_{i-1}。"""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import tmp_verify_decrypt as V  # noqa

T = lambda b: bytes(V.T(list(b)))
X = V.xr
recs = json.load(open(os.path.join(HERE, 'tmp_sbcaps2.json')))

allconst = {}
for r in recs:
    K = bytes.fromhex(r['K'])
    pt = bytes.fromhex(r['pt'])
    ct = bytes.fromhex(r['ct'])
    sb = [bytes.fromhex(h) for h in r['sb']]
    print('=== %s' % r['name'])
    for b in range(len(sb) // 10):
        inp = T(X(sb[b * 10], K))
        ptb = pt[b * 16:(b + 1) * 16] if b * 16 < len(pt) else b''
        if len(ptb) != 16:
            ptb = bytes(16)
        prev = ct[b * 16 - 16:b * 16] if b else bytes(16)
        cst = X(X(inp, ptb), prev)
        allconst.setdefault(b, set()).add((r['name'], cst.hex()))
        print('  块%d prev=%s CONST=%s' % (b, X(inp, ptb).hex(), cst.hex()))
print()
print('每块 CONST 是否唯一:')
for b in sorted(allconst):
    vals = set(v for _, v in allconst[b])
    print('  块%d: %d 个不同值 %s' % (b, len(vals), list(vals)[:3]))
