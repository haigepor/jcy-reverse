# -*- coding: utf-8 -*-
"""tmp_analyze_sb2.py — 用 SB 状态轨迹(真值)验证块1密钥调度, 并提取块2的真实输入。"""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import tmp_verify_decrypt as V  # noqa

K = b'X8TEUA3DEXZNW2TN'
T = lambda b: bytes(V.T(list(b)))
X = V.xr
rk = V.expand(K)
recs = {r['name']: r for r in json.load(open(os.path.join(HERE, 'tmp_sbcaps.json')))}


def nextstate(s, r):
    return bytes(a ^ b for a, b in zip(V.MC(V.SR(V.SB(list(s)))), rk[r]))


for name in ('P11Q22R33', 'P11Q22', 'zero2', 'PaaQbb'):
    r = recs[name]
    sb = [bytes.fromhex(h) for h in r['sb']]
    pt = bytes.fromhex(r['pt'])
    ct = bytes.fromhex(r['ct'])
    print('=== %s  nblk=%d' % (name, len(pt) // 16))
    # 验证块0的轮链: SB[0] -> SB[1..9]
    ok = True
    for k in range(9):
        exp = nextstate(sb[k], k + 1)
        if exp != sb[k + 1]:
            ok = False
            print('  块0 轮链断在 SB[%d]->SB[%d]' % (k, k + 1))
            break
    print('  块0 轮链 SB[0..9] 与标准 AES 轮 + K调度 一致:', ok)
    # 验证块1的轮链: SB[10] -> SB[11..19]
    if len(sb) >= 20:
        ok1 = True
        for k in range(10, 19):
            exp = nextstate(sb[k], k - 10 + 1)
            if exp != sb[k + 1]:
                ok1 = False
                print('  块1 轮链断在 SB[%d]->SB[%d]' % (k, k + 1))
                break
        print('  块1 轮链 SB[10..19] 与同一 K 调度一致:', ok1)
    # 提取各块真实输入
    nblk = len(pt) // 16
    for b in range(nblk):
        A0 = sb[b * 10]
        inp = T(X(A0, K))
        ptb = pt[b * 16:(b + 1) * 16]
        prev = ct[b * 16 - 16:b * 16] if b else bytes(16)
        print('  块%d: input=%s' % (b, inp.hex()))
        print('       input^pt = %s' % X(inp, ptb).hex())
        if b:
            print('       input^pt^ct_prev = %s' % X(X(inp, ptb), prev).hex())
