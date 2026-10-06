# -*- coding: utf-8 -*-
"""tmp_blk1state.py — 捕获块1的 round-1 状态 grp[10], 与候选直接比对。"""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from e_oracle import EOracle  # noqa
sys.path.insert(0, HERE)
import tmp_verify_decrypt as V  # noqa

K = b'X8TEUA3DEXZNW2TN'
Z = bytes(16)
BASE = 0x737e41c38960
o = EOracle()
uc = o.s.e.uc
C = V.determine_C(o, K)
rk = V.expand(K)
T = lambda b: bytes(V.T(list(b)))
X = V.xr

cur = {'idx': []}


def rcb(uc_, access, address, size, value, ud):
    if access == unicorn.UC_MEM_READ and BASE <= address <= BASE + 255:
        cur['idx'].append(address - BASE)


uc.hook_add(unicorn.UC_HOOK_MEM_READ, rcb, begin=BASE, end=BASE + 255)
P = bytes(range(32))
P0, P1 = P[0:16], P[16:32]
cur['idx'] = []
ct = o.enc(P, K, Z)
idx = cur['idx']
grp = [bytes(idx[40+g*16:40+(g+1)*16]) for g in range((len(idx)-40)//16)]
print('ngroups', len(grp))
A0_0 = grp[0]
A0_1 = grp[10]
print('A0_0 =', A0_0.hex(), ' T(P0)^K =', X(T(P0), rk[0]).hex())
print('A0_1 =', A0_1.hex())
ct0 = ct[0:16]
u0 = T(X(ct0, C))
print('ct0 =', ct0.hex(), 'u0=T(ct0^C) =', u0.hex())
cands = {
    'T(P1)^K': X(T(P1), rk[0]),
    'T(P1^ct0)^K': X(T(X(P1, ct0)), rk[0]),
    'T(P1)^T(ct0)^K': X(X(T(P1), T(ct0)), rk[0]),
    'T(P1)^ct0^K': X(X(T(P1), ct0), rk[0]),
    'T(P1)^u0^K': X(X(T(P1), u0), rk[0]),
    'T(P1)^u0': X(T(P1), u0),
    'T(P1)^ct0': X(T(P1), ct0),
    'T(P1)^ct0^C^K': X(X(X(T(P1), ct0), C), rk[0]),
    'T(P1)^T(ct0)': X(T(P1), T(ct0)),
    'T(P1)^T(ct0)^C': X(X(T(P1), T(ct0)), C),
    'T(P1^ct0)': T(X(P1, ct0)),
    'T(P1)^K^ct0^C': X(X(X(T(P1), rk[0]), ct0), C),
    'T(P1)^K^T(ct0)^C': X(X(X(T(P1), rk[0]), T(ct0)), C),
    'T(P1)^K^u0': X(X(T(P1), rk[0]), u0),
    'T(P1)^K^T(ct0^C)': X(X(T(P1), rk[0]), T(X(ct0, C))),
    'T(P1^ct0)^K^C': X(X(T(X(P1, ct0)), rk[0]), C),
}
for n, v in cands.items():
    if v == A0_1:
        print('  HIT:', n)
print('done')
