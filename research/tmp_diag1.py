# -*- coding: utf-8 -*-
"""tmp_diag1.py — 判定多块结构: 块0是否依赖后续块? 各块间是否 ECB/CBC?
单一最有信息量的实验:
  A = enc(P)              (P 单块)
  B = enc(P+Q)            (两块)
  若 B[0:16]==A[0:16] 且 B[16:32]==enc(Q)[0:16] -> ECB (无链式)
  若 B[0:16]!=A[0:16]                          -> 整消息混合 (sponge/wide-state)
  若 B[0:16]==A[0:16] 但 B[16:32]!=enc(Q)[0:16] -> CBC 类链式
"""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from e_oracle import EOracle  # noqa
sys.path.insert(0, HERE)
import tmp_verify_decrypt as V  # noqa

K = b'X8TEUA3DEXZNW2TN'
Z = bytes(16)
o = EOracle()
C = V.determine_C(o, K)
print('C =', C.hex())

P = bytes([0x11] * 16)
Q = bytes([0x22] * 16)
R = bytes([0x33] * 16)

A = o.enc(P, K, Z)
B = o.enc(P + Q, K, Z)
Q1 = o.enc(Q, K, Z)
T3 = o.enc(P + Q + R, K, Z)

print('enc(P)      len=%d %s' % (len(A), A.hex()))
print('enc(P+Q)    len=%d %s' % (len(B), B.hex()))
print('enc(Q)      len=%d %s' % (len(Q1), Q1.hex()))
print('enc(P+Q+R)  len=%d %s' % (len(T3), T3.hex()))
print()
print('[1] 单块 P 与 两块 P+Q 的块0 相同?', A[0:16] == B[0:16], '-> 块0依赖后续块' if A[0:16] != B[0:16] else '')
print('[2] 两块 P+Q 的块1 == 单块 Q?', B[16:32] == Q1[0:16], '-> ECB' if B[16:32] == Q1[0:16] else '')
print('[3] 三块 P+Q+R 的块0 == 单块 P?', T3[0:16] == A[0:16])
print('[4] 三块 P+Q+R 的块1 == 两块 P+Q 的块1?', T3[16:32] == B[16:32])
print('[5] 三块 P+Q+R 的块2 == 单块 R?', T3[32:48] == o.enc(R, K, Z)[0:16])

# 单块 enc 与 E 模型一致性再确认 (iv=0)
print()
print('E(P)==enc(P):', V.E(P, K, C) == A[0:16])
print('E(Q)==enc(Q):', V.E(Q, K, C) == Q1[0:16])

# 若 CBC: 块1输入应为 Q^ct0 或 Q^T(ct0) 等
ct0 = B[0:16]
cands = {
    'Q^ct0': V.xr(Q, ct0),
    'Q^T(ct0)': V.xr(Q, bytes(V.T(list(ct0)))),
    'Q': Q,
}
for n, f in cands.items():
    print('B[16:32]==E(%s):' % n, V.E(f, K, C) == B[16:32])
