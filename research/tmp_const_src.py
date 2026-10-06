# -*- coding: utf-8 -*-
"""tmp_const_src.py — 1) 验证 E(T(A0^K)) == ct_b (即 rk0=K, 输入即 E 的输入)
2) 求 CONST_i 的来源: E_inv(CONST_i) / E(CONST_i) / 与轮密钥比对。"""
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
Cs = {}
for K in (b'X8TEUA3DEXZNW2TN', b'ABCDEFGHIJKLMNOP'):
    Cs[K] = V.determine_C(o, K)
    print('K=%s C=%s' % (K.decode(), Cs[K].hex()))

recs = json.load(open(os.path.join(HERE, 'tmp_sbcaps2.json')))

print()
print('--- (1) 验证 E(T(A0_b^K)) == ct_b (块 b 的输入确实直接进 E) ---')
for r in recs:
    K = bytes.fromhex(r['K'])
    C = Cs[K]
    pt = bytes.fromhex(r['pt'])
    ct = bytes.fromhex(r['ct'])
    sb = [bytes.fromhex(h) for h in r['sb']]
    res = []
    for b in range(len(sb) // 10):
        inp = T(X(sb[b * 10], K))
        res.append(V.E(inp, K, C) == ct[b * 16:(b + 1) * 16])
    print('  %-6s 各块 %s' % (r['name'], res))

print()
print('--- (2) CONST_i 来源探查 ---')
consts = {}
for r in recs:
    K = bytes.fromhex(r['K'])
    pt = bytes.fromhex(r['pt'])
    ct = bytes.fromhex(r['ct'])
    sb = [bytes.fromhex(h) for h in r['sb']]
    lst = []
    for b in range(len(sb) // 10):
        inp = T(X(sb[b * 10], K))
        ptb = pt[b * 16:(b + 1) * 16]
        if len(ptb) != 16:
            ptb = bytes(16)
        prev = ct[b * 16 - 16:b * 16] if b else bytes(16)
        lst.append(X(X(inp, ptb), prev))
    consts.setdefault(K, []).append((r['name'], lst))

for K, groups in consts.items():
    C = Cs[K]
    rk = V.expand(K)
    print('K =', K.decode())
    print('  rk0..rk4:')
    for i in range(5):
        print('    rk[%d] = %s' % (i, rk[i].hex()))
    # 取第一个 rec 的 CONST 列表 (应与其它 rec 一致)
    lst = groups[0][1]
    for i, cst in enumerate(lst):
        einv = V.E_inv(cst, K, C)
        ev = V.E(cst, K, C)
        print('  i=%d CONST=%s' % (i, cst.hex()))
        print('        E_inv(CONST)=%s' % einv.hex())
        print('        E(CONST)    =%s' % ev.hex())
        for j in range(11):
            if cst == rk[j]:
                print('        == rk[%d]' % j)
            if cst == T(rk[j]):
                print('        == T(rk[%d])' % j)
            if einv == rk[j]:
                print('        E_inv(CONST) == rk[%d]' % j)
