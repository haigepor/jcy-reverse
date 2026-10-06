# -*- coding: utf-8 -*-
"""tmp_analyze_sb.py — 离线分析 tmp_sbcaps.json: 反推块1的加密输入。"""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import tmp_verify_decrypt as V  # noqa

K = b'X8TEUA3DEXZNW2TN'
T = lambda b: bytes(V.T(list(b)))
X = V.xr
recs = json.load(open(os.path.join(HERE, 'tmp_sbcaps.json')))

print('%-12s %-34s %-34s' % ('vec', 'ct0', 'ct1'))
for r in recs:
    pt = bytes.fromhex(r['pt'])
    ct = bytes.fromhex(r['ct'])
    sb = [bytes.fromhex(h) for h in r['sb']]
    nblk = len(pt) // 16
    P0 = pt[0:16]
    A00, A01 = sb[0], sb[10]
    input1 = T(X(A01, K))
    print('--- %s  nblk=%d' % (r['name'], nblk))
    print('  ct0      =', ct[0:16].hex())
    print('  A0_0     =', A00.hex(), ' T(P0)^K =', X(T(P0), K).hex(), ' match', A00 == X(T(P0), K))
    if nblk >= 2:
        Q = pt[16:32]
        print('  P1(plain)=', Q.hex())
        print('  A0_1     =', A01.hex())
        print('  input1   =', input1.hex(), '  (=T(A0_1^K))')
        print('  input1^P1=', X(input1, Q).hex())
        print('  ct0      =', ct[0:16].hex())
        for nm, v in (('P1^ct0', X(Q, ct[0:16])), ('P1^T(ct0)', X(Q, T(ct[0:16]))),
                      ('T(P1)^ct0', X(T(Q), ct[0:16])), ('T(P1^ct0)', T(X(Q, ct[0:16])))):
            print('    input1 == %-12s : %s' % (nm, input1 == v))
