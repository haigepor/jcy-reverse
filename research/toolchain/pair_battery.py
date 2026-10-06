#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pair_battery.py - 对确认长度配对跑全模式测试: AES-ECB/CBC/CFB/OFB/CTR + SM4, 多 key 候选"""
import base64
import hashlib
import json
import os
import re
import struct
import sys

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pair_extract import load_bodies, sm4_ecb_dec, sm4_ecb_enc, sm4_cbc_dec, PAIR  # noqa

CUS = '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
HERE = os.path.join(os.path.dirname(__file__), '..', 'captures', 'rsa_scan')
CHUNK_RE = re.compile(r'\r\n[0-9a-fA-F]{1,8}\r\n')

AESK = AES.new  # shorthand


def keycands(k16: bytes):
    md = lambda b: hashlib.md5(b).digest()
    return {
        'K16': k16,
        'rev': k16[::-1],
        'md5': md(k16),
        'md5hex16': hashlib.md5(k16).hexdigest().encode()[:16],
        'sha1_16': hashlib.sha1(k16).digest()[:16],
        'sha1hex16': hashlib.sha1(k16).hexdigest().encode()[:16],
        'sha256_16': hashlib.sha256(k16).digest()[:16],
        'sha256hex16': hashlib.sha256(k16).hexdigest().encode()[:16],
        'md5(k16+salt)': md(k16 + b'v50gjcy'),
        'md5(salt+k16)': md(b'v50gjcy' + k16),
        'md5(k16+k16)': md(k16 + k16),
        'md5hex(k16+k16)': hashlib.md5(k16 + k16).hexdigest().encode()[:16],
    }


def eq(a, b, n=32):
    return a[:n] == b[:n]


def main():
    plains = {}
    for fn in sorted(os.listdir(PAIR)):
        if fn.startswith('plain_') and fn.endswith('.bin'):
            plains[fn] = open(os.path.join(PAIR, fn), 'rb').read()
    print('plains:', {k: len(v) for k, v in plains.items()})

    bodies = load_bodies()
    print('bodies:', len(bodies))

    # 208B 组与 160B 组内部块对比 (同端点多实例: 块相等 => 静态key)
    for L in (208, 160):
        grp = [C for k, C in bodies if len(C) == L]
        if len(grp) >= 2:
            same_c0 = sum(1 for c in grp[1:] if c[:16] == grp[0][:16])
            same_all = sum(1 for c in grp[1:] if c == grp[0])
            print(f'P1len={L} 组内 {len(grp)} 条: C0 相同 {same_c0}, 整体相同 {same_all}')

    # 候选配对: plain 与等长 P1
    tests = 0
    hits = []
    for pfn, P in plains.items():
        L = len(P)
        for k16, C in bodies:
            if len(C) != 16 * ((L + 15) // 16):
                continue
            kb = k16.encode()
            for kn, key in keycands(kb).items():
                # --- ECB 全解 ---
                try:
                    d = AESK(key, AES.MODE_ECB).decrypt(C)
                    if d[:2] == P[:2] and d[3:9] == P[3:9]:
                        hits.append((pfn, 'ECB', kn, k16)); print('*** ECB HIT', pfn, kn, k16, d[:60])
                except Exception:
                    pass
                # --- CBC iv 无关块1/2 ---
                try:
                    ecb = AESK(key, AES.MODE_ECB)
                    x1 = ecb.decrypt(C[16:32])
                    if bytes(a ^ b for a, b in zip(x1, C[0:16])) == P[16:32]:
                        hits.append((pfn, 'CBC-b1', kn, k16)); print('*** CBC HIT', pfn, kn, k16)
                    x2 = ecb.decrypt(C[32:48])
                    if bytes(a ^ b for a, b in zip(x2, C[16:32])) == P[32:48]:
                        hits.append((pfn, 'CBC-b2', kn, k16)); print('*** CBC2 HIT', pfn, kn, k16)
                except Exception:
                    pass
                # --- CFB128: C_i = P_i ^ E(C_{i-1}) 整链无 IV ---
                try:
                    ecb = AESK(key, AES.MODE_ECB)
                    ks0 = ecb.encrypt(C[0:16])
                    if bytes(a ^ b for a, b in zip(ks0, C[0:16])) == P[0:16]:
                        hits.append((pfn, 'CFB-b0', kn, k16)); print('*** CFB HIT', pfn, kn, k16, P[:48])
                    ks1 = ecb.encrypt(C[16:32])
                    if bytes(a ^ b for a, b in zip(ks1, C[16:32])) == P[16:32]:
                        hits.append((pfn, 'CFB-b1', kn, k16)); print('*** CFB1 HIT', pfn, kn, k16)
                except Exception:
                    pass
                # --- CTR/OFB: KS = P^C, E(K,X)==KS0 ---
                try:
                    KS = bytes(a ^ b for a, b in zip(P, C))
                    ecb = AESK(key, AES.MODE_ECB)
                    for xn, X in {'zero': b'\x00'*16, 'K16': kb, 'one': b'\x00'*15+b'\x01',
                                  'md5k': hashlib.md5(kb).digest(), 'C0': C[:16]}.items():
                        if ecb.encrypt(X) == KS[0:16]:
                            hits.append((pfn, f'CTR/OFB-{xn}', kn, k16))
                            print(f'*** CTR/OFB HIT {pfn} key={kn} nonce={xn} K16={k16}')
                        if ecb.encrypt(KS[0:16]) == KS[16:32]:  # OFB 链
                            hits.append((pfn, 'OFB-chain', kn, k16))
                            print(f'*** OFB-chain HIT {pfn} key={kn} K16={k16}')
                        break_  # noqa
                except Exception:
                    pass
                tests += 1
            # --- SM4 ---
            try:
                d0 = sm4_ecb_dec(kb, C[0:16])
                if d0 == P[0:16]:
                    hits.append((pfn, 'SM4-ECB', 'K16', k16)); print('*** SM4-ECB HIT', pfn, k16, d0[:48])
                x1 = sm4_ecb_dec(kb, C[16:32])
                if bytes(a ^ b for a, b in zip(x1, C[0:16])) == P[16:32]:
                    hits.append((pfn, 'SM4-CBC', 'K16', k16)); print('*** SM4-CBC HIT', pfn, k16)
                d0e = sm4_ecb_enc(kb, P[0:16])
                if d0e == C[0:16]:
                    hits.append((pfn, 'SM4-ECB-enc', 'K16', k16)); print('*** SM4-ECB-enc HIT', pfn, k16)
            except Exception as e:
                print('sm4 err', e)
    print('=== 配对测试完成: 组合', tests, '命中', len(hits))


if __name__ == '__main__':
    main()
