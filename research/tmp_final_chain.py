# -*- coding: utf-8 -*-
"""tmp_final_chain.py — 验证链式模型:
    ct_i = E(pt_i ^ prev_i),  prev_0 = iv,  prev_i = ct_{i-1} ^ CONST
并检查 CONST 是否随密钥变化、iv 是否作用于块0。
"""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, 'captures', 'rsa_scan'))
import unicorn  # noqa
from e_oracle import EOracle  # noqa
sys.path.insert(0, HERE)
import tmp_verify_decrypt as V  # noqa

Z = bytes(16)
o = EOracle()


def solve_const(o, K, iv=Z, P0=None, P1=None):
    """用 2 块预言机调用解出 C 与 CONST。"""
    C = V.determine_C(o, K)
    P0 = P0 if P0 is not None else bytes([0x11] * 16)
    P1 = P1 if P1 is not None else bytes([0x22] * 16)
    ct = o.enc(P0 + P1, K, iv)
    ct0, ct1 = ct[0:16], ct[16:32]
    x1 = V.E_inv(ct1, K, C)          # = input_1 (若块1用同一 E)
    CONST = V.xr(V.xr(x1, P1), ct0)
    # 块0: input_0 = pt0 ^ prev0
    x0 = V.E_inv(ct0, K, C)
    prev0 = V.xr(x0, P0)
    return C, CONST, prev0, ct


def enc_model(pt, K, C, CONST, iv=Z):
    prev = iv
    out = b''
    for i in range(0, len(pt), 16):
        x = V.xr(pt[i:i + 16], prev)
        ct = V.E(x, K, C)
        out += ct
        prev = V.xr(ct, CONST)
    return out


def dec_model(ct, K, C, CONST, iv=Z):
    prev = iv
    out = b''
    for i in range(0, len(ct), 16):
        blk = ct[i:i + 16]
        out += V.xr(V.E_inv(blk, K, C), prev)
        prev = V.xr(blk, CONST)
    return out


def unpad(b):
    n = b[-1]
    if 1 <= n <= 16 and b[-n:] == bytes([n]) * n:
        return b[:-n]
    return b


for K in (b'X8TEUA3DEXZNW2TN', b'ABCDEFGHIJKLMNOP'):
    print('=' * 70)
    print('K =', K)
    C, CONST, prev0, ct = solve_const(o, K)
    print('  C     =', C.hex())
    print('  CONST =', CONST.hex())
    print('  prev0 (块0链值) =', prev0.hex(), '(iv=0 -> 应为 00..00)')
    # 多块验证
    for name, pt in (('3blk', bytes([0x11] * 16) + bytes([0x22] * 16) + bytes([0x33] * 16)),
                     ('4blk', bytes(range(64))),
                     ('5blk', bytes([0x5a] * 80))):
        orc = o.enc(pt, K, Z)
        mod = enc_model(pt, K, C, CONST, Z)
        # 注意: 预言机输出含 PKCS7 补块, 只比较前 len(pt) 字节
        ok = orc[:len(pt)] == mod[:len(pt)]
        print('  %s 模型==预言机: %s' % (name, ok))
        if not ok:
            for j in range(0, len(pt), 16):
                print('    blk%d orc=%s mod=%s %s' % (
                    j // 16, orc[j:j+16].hex(), mod[j:j+16].hex(),
                    'OK' if orc[j:j+16] == mod[j:j+16] else 'XX'))
        # 解密回明文
        dec = dec_model(orc[:len(pt)], K, C, CONST, Z)
        print('      解密回明文: %s' % (dec == pt))

# iv 依赖
print('=' * 70)
K = b'X8TEUA3DEXZNW2TN'
C = V.determine_C(o, K)
for ivname, iv in (('iv=0', bytes(16)), ('iv=ff', bytes([0xff] * 16)),
                   ('iv=K', K), ('iv=revK', K[::-1])):
    P = bytes([0x11] * 16)
    ct = o.enc(P, K, iv)
    x0 = V.E_inv(ct[0:16], K, C)
    print('  %-8s E_inv(ct0)^P = %s   == iv? %s' % (ivname, V.xr(x0, P).hex(), V.xr(x0, P) == iv))
