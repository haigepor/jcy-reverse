# -*- coding: utf-8 -*-
"""tmp_relsearch.py — 搜索 CONST_b / W_b 之间的代数关系。"""
import os, sys, json, itertools
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import tmp_verify_decrypt as V  # noqa

X = V.xr
T = lambda b: bytes(V.T(list(b)))
K1 = b'X8TEUA3DEXZNW2TN'
rk = V.expand(K1)

CONST = [bytes.fromhex(h) for h in
         '00000000000000000000000000000000 52f4c36b5f665eaafdb1cb79065d7df5 '
         '4db0d20b15d16e21e32a08179803e397 f5ff657c571843e4e6905bb0a891f099 '
         '4037d9e1ac8845aa10f8b0baa88b836d 1287ba32cacd066771bb0bd321379518 '
         'cbd9a2b286f5ff32992271c9c751c568 e3ef50b3c6bd7d046e9915c4fc2adad4 '
         '66fe91ff854455cbcc7d785b82b4a301 1b85689c43d06743c01c89b105f3c60f'.split()]
W = [bytes.fromhex(h) for h in
     '00000000000000000000000000000000 1f4411604ab7308b1e9bc36e9e5e9e62 '
     'a70ba617087e1d4e1b2190c9aecc8d6c 12c31a8af3ee1b00ed497bc3aed6fe98 '
     '4073795995ab58cd8c0ac0aa276ae8ed 992d61d9d993a1986493bab0c10cb89d '
     'b11b93d899db23ae9328debdfa77a721 340a5294da220b6131ccb32284e9def4 '
     '4971abf71cb639e93dad42c803aebbfa 965f1256789d7aac85b3feefd2b02871'.split()]

print('len', len(CONST), len(W))
for b in range(1, 10):
    print('b=%d CONST^CONST_prev=%s  W^W_prev=%s  CONST^W_prev=%s  W^CONST=%s' % (
        b, X(CONST[b], CONST[b - 1]).hex(), X(W[b], W[b - 1]).hex(),
        X(CONST[b], W[b - 1]).hex(), X(W[b], CONST[b]).hex()))

# 检查是否有任何两值相等/简单关系
names = {}
for i in range(10):
    names['C%d' % i] = CONST[i]
    names['W%d' % i] = W[i]
    names['T(C%d)' % i] = T(CONST[i])
    names['T(W%d)' % i] = T(W[i])
for i in range(11):
    names['rk%d' % i] = rk[i]

print()
print('相等对:')
ks = list(names)
for a, b in itertools.combinations(ks, 2):
    if names[a] == names[b]:
        print('  %s == %s' % (a, b))
print('XOR 关系 (差值重复出现):')
seen = {}
for a, b in itertools.combinations(ks, 2):
    d = X(names[a], names[b])
    seen.setdefault(d.hex(), []).append('%s^%s' % (a, b))
for d, lst in seen.items():
    if len(lst) > 1:
        print('  %s : %s' % (d, lst))
