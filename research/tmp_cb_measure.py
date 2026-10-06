# -*- coding: utf-8 -*-
"""tmp_cb_measure.py — 逐块测量 (T_b, C_b):
    A0_b = T(x_b) ^ K            (已验证: 块1+ 的 SB 轮链 = K 调度)
    ct_b = G(A0_b) ^ C_b          G(A0) = T(SR(SB(AES9(A0))))
    x_b  = pt_b ^ ct_{b-1} ^ T_b
其中 T_b = T(A0_b^K) ^ pt_b ^ ct_{b-1},  C_b = ct_b ^ G(A0_b)。
"""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from e_oracle import EOracle  # noqa
sys.path.insert(0, HERE)
import tmp_verify_decrypt as V  # noqa

T = lambda b: bytes(V.T(list(b)))
X = V.xr
Z = bytes(16)
o = EOracle()
K = b'X8TEUA3DEXZNW2TN'
C = V.determine_C(o, K)
rk = V.expand(K)


def G(A0):
    s = list(A0)
    for r in range(1, 10):
        s = V.MC(V.SR(V.SB(s)))
        s = [a ^ b for a, b in zip(s, rk[r])]
    return bytes(T(V.SR(V.SB(s))))


recs = json.load(open(os.path.join(HERE, 'tmp_sbcaps2.json')))
r = [x for x in recs if x['name'] == 'K1_D'][0]
pt = bytes.fromhex(r['pt'])
ct = bytes.fromhex(r['ct'])
sb = [bytes.fromhex(h) for h in r['sb']]
print('K=%s C=%s' % (K.decode(), C.hex()))
for b in range(len(sb) // 10):
    A0 = sb[b * 10]
    ctb = ct[b * 16:(b + 1) * 16]
    ptb = pt[b * 16:(b + 1) * 16] if b * 16 < len(pt) else bytes(16)
    prev = ct[b * 16 - 16:b * 16] if b else bytes(16)
    Tb = X(X(T(X(A0, K)), ptb), prev)
    Cb = X(ctb, G(A0))
    print('b=%d  T_b=%s' % (b, Tb.hex()))
    print('      C_b=%s   ==C? %s' % (Cb.hex(), Cb == C))
    print('      A0_b=%s' % A0.hex())
    # 若 x_b = pt^prev (纯CBC), 则 rk0_b = A0_b ^ T(x_b)
    rk0b = X(A0, T(X(ptb, prev)))
    print('      rk0_b(=A0^T(pt^prev))=%s  ==K? %s' % (rk0b.hex(), rk0b == K))
