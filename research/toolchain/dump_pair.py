#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dump_pair.py - 从内存转储自提取 内嵌密文(P0.P1) + 明文JSON, 同会话配对验证 key/iv"""
import base64
import glob
import hashlib
import json
import os
import re
import sys

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

CUS = '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
CAP = 'research/captures/rsa_scan'
DUMPDIR = f'{CAP}/livedump'
PRIV = PKCS1_v1_5.new(RSA.import_key(open(f'{CAP}/priv_from_go.pem', 'rb').read()))
B64PAT = re.compile(rb'[A-Za-z0-9+/]{330,360}\.[A-Za-z0-9+/=]{64,}', re.ASCII)


def b64dec(s, alpha=CUS):
    t = str.maketrans(alpha, STD)
    s2 = s.translate(t)
    s2 += '=' * (-len(s2) % 4)
    return base64.b64decode(s2)


def unwrap(p0):
    k = PRIV.decrypt(p0, None)
    if k and len(k) == 16:
        try:
            ks = k.decode('ascii')
            if re.fullmatch(r'[A-Za-z0-9]{16}', ks):
                return ks
        except Exception:
            pass
    return None


def extract_bodies(data, tag, found):
    for m in B64PAT.finditer(data):
        s = m.group(0)
        i = s.find(b'.')
        p0s, p1s = s[:i], s[i + 1:]
        # 去 b64 非法尾
        p0s = p0s[:344]
        if len(p0s) != 344:
            continue
        try:
            p0 = b64dec(p0s.decode('ascii'))
        except Exception:
            continue
        if len(p0) != 256:
            continue
        k16 = unwrap(p0)
        if not k16:
            continue
        try:
            p1 = b64dec(p1s.decode('ascii').rstrip('='))
        except Exception:
            continue
        if len(p1) == 0 or len(p1) % 16:
            continue
        found.append((tag, m.start(), k16, p1))


def extract_plaintexts(data, tag, found):
    start = 0
    for _ in range(200):
        i = data.find(b'{"code"', start)
        if i < 0:
            return
        start = i + 1
        try:
            obj, end = json.JSONDecoder().raw_decode(data[i:i + 400000].decode('utf-8', 'replace'))
            blob = data[i:i + end]
            if len(blob) >= 48:
                found.append((tag, i, blob))
        except Exception:
            pref = data[i:i + 64]
            if len(pref) >= 48 and pref.count(b'"') >= 2:
                found.append((tag, i, pref))


def main():
    only = sys.argv[1:] if len(sys.argv) > 1 else None
    bodies, plains = [], []
    for fp in sorted(glob.glob(f'{DUMPDIR}/*.bin')):
        base = os.path.basename(fp)
        if only and base not in only:
            continue
        sz = os.path.getsize(fp)
        if sz < 20000:
            continue
        data = open(fp, 'rb').read()
        extract_bodies(data, base, bodies)
        extract_plaintexts(data, base, plains)
    print(f'内嵌密文 {len(bodies)} 条, 明文 {len(plains)} 条')
    for t, off, k16, p1 in bodies[:12]:
        print(f'  [C] {t}@{off:#x} K16={k16} len={len(p1)}')
    for t, off, blob in plains[:12]:
        print(f'  [P] {t}@{off:#x} len={len(blob)} {blob[:56]!r}')

    # 配对
    hits = []
    for (tf, offp, blob) in plains:
        n = len(blob)
        ok_lens = {(n // 16) * 16, ((n // 16) + 1) * 16}
        for (tc, offc, k16, C) in bodies:
            if len(C) not in ok_lens:
                continue
            kb = k16.encode()
            for kn, kk in {
                'K16': kb, 'rev': kb[::-1],
                'md5_16': hashlib.md5(kb).digest()[:16],
                'sha1_16': hashlib.sha1(kb).digest()[:16],
                'sha256_16': hashlib.sha256(kb).digest()[:16],
            }.items():
                try:
                    d_c1 = AES.new(kk, AES.MODE_ECB).decrypt(C[16:32])
                    want = bytes(a ^ b for a, b in zip(blob[16:32], C[0:16]))
                    if d_c1 == want:
                        d_c0 = AES.new(kk, AES.MODE_ECB).decrypt(C[0:16])
                        iv = bytes(a ^ b for a, b in zip(d_c0, blob[0:16]))
                        msg = (f'*** KEY确认 P={tf}@{offp:#x} C={tc}@{offc:#x} '
                               f'K16={k16} key={kn} IV={iv!r} plen={n} clen={len(C)}')
                        print(msg)
                        hits.append(msg)
                except Exception:
                    continue
    if not hits:
        print('无命中')
        # 诊断: 同文件内密文与明文长度分布
        from collections import Counter
        print('密文长度分布:', Counter(len(p1) for *_, p1 in bodies).most_common(10))


if __name__ == '__main__':
    main()
