#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""decrypt_try.py - 离线撞 K16->key/iv: RSA 解 P0 拿 K16, key=K16 各派生 x 常量IV候选"""
import base64
import hashlib
import json
import sys

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

CUS = '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
PRIV = PKCS1_v1_5.new(RSA.import_key(open('research/captures/rsa_scan/priv_from_go.pem', 'rb').read()))


def b64dec(s, alpha):
    t = str.maketrans(alpha, STD)
    s2 = s.translate(t)
    s2 += '=' * (-len(s2) % 4)
    return base64.b64decode(s2)


def dechunk(s):
    """剥离 HTTP chunked 帧: size\\r\\n data\\r\\n ... 0\\r\\n"""
    if '\r\n' not in s[:20]:
        return s
    out = []
    i = 0
    while i < len(s):
        j = s.find('\r\n', i)
        if j < 0:
            break
        try:
            size = int(s[i:j], 16)
        except ValueError:
            return s
        if size == 0:
            break
        out.append(s[j + 2:j + 2 + size])
        i = j + 2 + size + 2
    return ''.join(out)


def split_body(body):
    body = dechunk(body)
    parts = body.split('.')
    if len(parts) == 2:
        return parts[0], parts[1]
    if len(parts) == 1 and len(body) > 344:
        # P0(344) + P1 无分隔拼接
        return body[:344], body[344:]
    return None, None


def load_bodies():
    out = []
    for line in open('research/captures/rsa_scan/bodies_now.jsonl', encoding='utf-8', errors='replace'):
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        body = d.get('resp_body_ascii') or d.get('resp_body') or ''
        if isinstance(body, str) and len(body) > 400:
            out.append((d.get('req', '?')[:40], body))
    return out


def unwrap_k16(p0):
    try:
        k = PRIV.decrypt(p0, b'\x02')  # PKCS1v15, type2 padding
        return k
    except Exception:
        return None


def score(b):
    if not b:
        return 0
    printable = sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13)) / len(b)
    return printable


def main():
    bodies = load_bodies()
    print(f'载入 {len(bodies)} 条响应')
    hits = []
    tried = set()
    for i, (req, body) in enumerate(bodies):
        p0s, p1s = split_body(body)
        if not p0s:
            continue
        p0 = b64dec(p0s, CUS)
        p1 = b64dec(p1s, CUS)
        if len(p0) != 256 or len(p1) == 0 or len(p1) % 16 != 0:
            continue
        k16 = unwrap_k16(p0)
        if not k16 or len(k16) != 16:
            continue
        k16s = k16.decode('latin1')
        if k16s in tried:
            continue
        tried.add(k16s)
        print(f'[{i}] {req} K16={k16s}')
        # key 候选
        keys = {
            'K16': k16,
            'rev': k16[::-1],
            'md5_16': hashlib.md5(k16).digest()[:16],
            'md5hex16': hashlib.md5(k16).hexdigest()[:16].encode(),
            'sha1_16': hashlib.sha1(k16).digest()[:16],
            'sha256_16': hashlib.sha256(k16).digest()[:16],
        }
        # IV 候选: 常量协议串 + 结构性
        ivs = {
            'zero': b'\x00' * 16,
            'p1head': p1[:16],
            'K16': k16,
            'revK16': k16[::-1],
            'p3Jd': b'p3JdVQl3q7WQJIgG',
            'qPwC': b'qPwClBj7j7ZQraSm',
            'kFGT': b'kFGTbLlOzFHQCIKp',
            'F3q2': b'F3q22XoM8l6T2Ydc',
            'md5K16': hashlib.md5(k16).digest(),
            'sha256K16': hashlib.sha256(k16).digest()[:16],
            'md5K16hex16': hashlib.md5(k16).hexdigest()[:16].encode(),
            'zeros16ascii': b'0' * 16,
        }
        for kn, kb in keys.items():
            for ivn, ivb in ivs.items():
                if len(kb) != 16 or len(ivb) != 16:
                    continue
                pt = AES.new(kb, AES.MODE_CBC, ivb).decrypt(p1)
                s = score(pt[:64])
                if s > 0.95:
                    try:
                        head = pt[:80].decode('utf-8')
                    except Exception:
                        head = pt[:80].decode('latin1', 'replace')
                    msg = f'*** HIT[{i}] {req} key={kn} iv={ivn} K16={k16s} head={head!r}'
                    print(msg)
                    hits.append(msg)
    print(f'去重 K16 {len(tried)} 个, 命中 {len(hits)}')
    if len(tried) == 0:
        print('!! 无有效 K16 — RSA 解包失败, 检查 b64/分割')


if __name__ == '__main__':
    main()
