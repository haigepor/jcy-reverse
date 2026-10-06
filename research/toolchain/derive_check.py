#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""derive_check.py - 明文×密文配对: 验证 key=K16 假设并反推 IV"""
import base64
import base64 as b64lib
import hashlib
import json
import re

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

CUS = '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
CAP = 'research/captures/rsa_scan'
WP = CAP + '/watch_plain'
PRIV = PKCS1_v1_5.new(RSA.import_key(open(CAP + '/priv_from_go.pem', 'rb').read()))
CHUNK_RE = re.compile(r'\r\n[0-9a-fA-F]{1,8}\r\n')


def b64dec(s):
    s2 = str(s).translate(str.maketrans(CUS, STD))
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


def load_jsonl_bodies():
    out = []
    for line in open(CAP + '/bodies_now.jsonl', encoding='utf-8', errors='replace'):
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        body = d.get('resp_body_ascii') or d.get('resp_body') or ''
        if not isinstance(body, str) or len(body) < 400:
            continue
        body = CHUNK_RE.sub('', body).replace('\r\n', '')
        parts = body.split('.')
        if len(parts) != 2 or len(parts[0]) != 344:
            continue
        try:
            p0 = b64dec(parts[0])
        except Exception:
            continue
        k16 = unwrap(p0)
        if not k16:
            continue
        try:
            p1 = b64dec(parts[1])
        except Exception:
            continue
        if len(p1) >= 32 and len(p1) % 16 == 0:
            req = ((d.get('req') or '?').split() + ['?'])[1].split('?')[0]
            out.append((req, k16, p1))
    print('[load] jsonl bodies:', len(out))
    return out


def load_mem_plains():
    out = []
    for line in open(WP + '/hits.jsonl', encoding='utf-8'):
        try:
            d = json.loads(line)
        except Exception:
            continue
        if not d.get('pat', '').startswith('7b22636f'):
            continue
        ctx = b64lib.b64decode(d.get('ctx_b64', '') or '')
        i = ctx.find(b'{"code"')
        if i < 0 or len(ctx) - i < 48:
            continue
        blob = None
        try:
            obj, end = json.JSONDecoder().raw_decode(ctx[i:i + 20000].decode('utf-8', 'replace'))
            blob = ctx[i:i + end]
        except Exception:
            blob = ctx[i:i + 64]
        if blob and len(blob) >= 32:
            out.append((d.get('addr', '?'), blob))
    print('[load] mem plains:', len(out))
    return out


def keycands(k16):
    kb = k16.encode()
    return {
        'K16': kb,
        'rev': kb[::-1],
        'md5_16': hashlib.md5(kb).digest()[:16],
        'md5hex16': hashlib.md5(kb).hexdigest()[:16].encode(),
        'sha1_16': hashlib.sha1(kb).digest()[:16],
        'sha256_16': hashlib.sha256(kb).digest()[:16],
    }


def main():
    bodies = load_jsonl_bodies()
    plains = load_mem_plains()
    hits = []
    tested = 0
    for pa, blob in plains:
        for req, k16, C in bodies:
            for kn, kb in keycands(k16).items():
                tested += 1
                try:
                    d_c1 = AES.new(kb, AES.MODE_ECB).decrypt(C[16:32])
                    want = bytes(a ^ b for a, b in zip(blob[16:32], C[0:16]))
                    if d_c1 == want:
                        d_c0 = AES.new(kb, AES.MODE_ECB).decrypt(C[0:16])
                        iv = bytes(a ^ b for a, b in zip(d_c0, blob[0:16]))
                        print(f'*** 命中 P@{pa} req={req} K16={k16} key={kn} '
                              f'IV={iv!r} IVhex={iv.hex()} plen={len(blob)} clen={len(C)}')
                        hits.append((blob, C, kb, iv, k16))
                except Exception:
                    continue
    print(f'测试组合 {tested}, 命中 {len(hits)}')
    if hits:
        blob, C, kb, iv, k16 = hits[0]
        pt = AES.new(kb, AES.MODE_CBC, iv).decrypt(C)
        open(WP + '/first_plaintext.json', 'wb').write(pt)
        print('IV 值分布:', {iv.hex() for _, _, _, iv, _ in hits})
        print('首个完整解密 -> first_plaintext.json len=', len(pt))


if __name__ == '__main__':
    main()
