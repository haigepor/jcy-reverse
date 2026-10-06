# -*- coding: utf-8 -*-
"""tmp_check_final.py — 用 SB 轨迹精确判定最终轮输出变换是否逐块变化。
若 OUT 相同且线性, 则 ct_0 ^ ct_1 == T(a0) ^ T(a1), 其中 ai = SR(SB(A9_i))。
"""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import tmp_verify_decrypt as V  # noqa

T = lambda b: bytes(V.T(list(b)))
X = V.xr
recs = {r['name']: r for r in json.load(open(os.path.join(HERE, 'tmp_sbcaps2.json')))}

for name in ('K1_A', 'K1_D', 'K2_A'):
    r = recs[name]
    K = bytes.fromhex(r['K'])
    ct = bytes.fromhex(r['ct'])
    sb = [bytes.fromhex(h) for h in r['sb']]
    print('=== %s' % name)
    C = None
    for b in range(4):
        a = bytes(V.SR(V.SB(list(sb[b * 10 + 9]))))       # SR(SB(A9_b))
        cand = X(ct[b * 16:(b + 1) * 16], T(a))
        if C is None:
            C = cand
        print('  块%d  ct^T(a) = %s   %s' % (b, cand.hex(), '==C' if cand == C else '<-- 不同!'))
    # 差分检验
    for b in range(1, 4):
        a0 = bytes(V.SR(V.SB(list(sb[9]))))
        ab = bytes(V.SR(V.SB(list(sb[b * 10 + 9]))))
        lhs = X(ct[0:16], ct[b * 16:(b + 1) * 16])
        rhs = X(T(a0), T(ab))
        print('  ct0^ct%d == T(a0)^T(a%d): %s' % (b, b, lhs == rhs))
