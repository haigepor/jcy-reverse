# -*- coding: utf-8 -*-
"""tmp_hyp.py — 判定 CONST_b / Cb_b 的生成规律。
1) 换明文，看 CONST_b / Cb_b 是否只依赖 (K,b)。
2) 对若干代数假设做批量测试。
"""
import os, sys, struct, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from unicorn.arm64_const import UC_ARM64_REG_X1
from e_oracle import EOracle  # noqa
from authgen import DEV_BASE  # noqa
sys.path.insert(0, HERE)
import tmp_verify_decrypt as V  # noqa

A_DRV = DEV_BASE + 0x2da498
Z = bytes(16)
o = EOracle()
uc = o.s.e.uc
rd = o.s.e.rd
u64 = lambda a: struct.unpack('<Q', rd(a, 8))[0]
X = V.xr
Tb = lambda b: bytes(V.T(list(b)))

captured = []


def rows24(x):
    b = u64(x)
    return b''.join(rd(u64(b + i * 24), 4) for i in range(4))


def cb(uc_, address, size, ud):
    captured.append(rows24(uc_.reg_read(UC_ARM64_REG_X1)))


uc.hook_add(unicorn.UC_HOOK_CODE, cb, begin=A_DRV, end=A_DRV + 4)


def F(x, rk):
    s = [a ^ b for a, b in zip(V.T(list(x)), rk[0])]
    for r in range(1, 10):
        s = V.MC(V.SR(V.SB(s)))
        s = [a ^ b for a, b in zip(s, rk[r])]
    return bytes(V.T(V.SR(V.SB(s))))


def measure(K, pt):
    C = V.determine_C(o, K)
    rk = V.expand(K)
    captured.clear()
    ct = o.enc(pt, K, Z)
    xs = [captured[i] for i in range(0, len(captured), 2)]
    nblk = len(pt) // 16
    out = {}
    for b in range(nblk):
        xb = Tb(xs[b])
        prev = ct[b*16-16:b*16] if b else Z
        const = X(X(xb, pt[b*16:(b+1)*16]), prev)
        Cb = X(ct[b*16:(b+1)*16], X(F(xb, rk), C))
        out[b] = (const, Cb, xb)
    return C, rk, out


K = b'X8TEUA3DEXZNW2TN'
ptA = bytes([(0x10 + i) for i in range(10) for _ in range(16)])
ptB = bytes([(0xA0 ^ i) for i in range(10) for _ in range(16)])
CA, rkA, tA = measure(K, ptA)
CB, rkB, tB = measure(K, ptB)
print('== 明文无关性 (同 K 两种明文) ==')
for b in range(10):
    same_c = tA[b][0] == tB[b][0]
    same_w = tA[b][1] == tB[b][1]
    print('  b=%d CONST_same=%s  Cb_same=%s' % (b, same_c, same_w))

print()
print('== 假设测试 (用 ptA 的表) ==')
C = CA
rk = rkA
CONST = [tA[b][0] for b in range(10)]
W = [tA[b][1] for b in range(10)]
xs = [tA[b][2] for b in range(10)]
cts = [o.enc(ptA, K, Z)[b*16:(b+1)*16] for b in range(10)]


def show(name, ok, detail=''):
    print('  %-28s %s %s' % (name, 'HIT ' if ok else 'miss', detail))


for b in range(1, 10):
    xb = xs[b]
    prev = cts[b-1]
    show('Cb_b == F(CONST_b) b=%d' % b, W[b] == F(CONST[b], rk))
    show('Cb_b == E(CONST_b) b=%d' % b, W[b] == X(F(CONST[b], rk), C))
    show('Cb_b == F(x_b)     b=%d' % b, W[b] == F(xb, rk))
    show('Cb_b == F(prev)    b=%d' % b, W[b] == F(prev, rk))
    show('CONST_b+1==F(CONST_b) b=%d' % b, CONST[b+1] == F(CONST[b], rk))
    show('CONST_b+1==E(CONST_b) b=%d' % b, CONST[b+1] == X(F(CONST[b], rk), C))
    show('CONST_b+1==F(ct_b) b=%d' % b, CONST[b+1] == F(cts[b], rk))

# keystream 假设: CONST_b == F(iv ^ counter) 等
print()
print('== keystream 假设 ==')
iv = K[::-1]
for b in range(1, 6):
    cnt = bytes([b] + [0]*15)
    show('CONST_b == F(iv^b)   b=%d' % b, CONST[b] == F(X(iv, cnt), rk))
    show('CONST_b == E(iv^b)   b=%d' % b, CONST[b] == X(F(X(iv, cnt), rk), C))
    show('CONST_b == F(K^b)    b=%d' % b, CONST[b] == F(X(K, cnt), rk))
    show('CONST_b == E(K^b)    b=%d' % b, CONST[b] == X(F(X(K, cnt), rk), C))

# AES 密钥调度序列假设
print()
print('== AES 调度相关 ==')
for b in range(1, 6):
    show('CONST_b == rk[b mod 11] b=%d' % b, CONST[b] == rk[b % 11])
    show('CONST_b == T(rk[b mod 11]) b=%d' % b, CONST[b] == Tb(rk[b % 11]))

json.dump({'ptA': ptA.hex(), 'ptB': ptB.hex(),
           'CONST_A': [c.hex() for c in CONST], 'W_A': [w.hex() for w in W],
           'CONST_B': [tB[b][0].hex() for b in range(10)],
           'W_B': [tB[b][1].hex() for b in range(10)]},
          open(os.path.join(HERE, 'tmp_hyp.json'), 'w'))
print('\n[done] tmp_hyp.json')
