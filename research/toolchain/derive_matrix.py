#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""derive_matrix.py - 扩大 key/iv 候选矩阵: 通道常量当 key, salt/device_id 参与派生"""
import base64
import hashlib
import json
import os
import re
import sys

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

CUS = '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
CAP = os.path.join(os.path.dirname(__file__), '..', 'captures', 'rsa_scan')
PRIV = PKCS1_v1_5.new(RSA.import_key(open(os.path.join(CAP, 'priv_from_go.pem'), 'rb').read()))
CHUNK_RE = re.compile(r'\r\n[0-9a-fA-F]{1,8}\r\n')

CH_KEY = b'qPwClBj7j7ZQraSm'
CH_IV = b'p3JdVQl3q7WQJIgG'
LD_KEY = b'kFGTbLlOzFHQCIKp'
LD_IV = b'F3q22XoM8l6T2Ydc'
SALT = b'v50gjcy'
DEVID = b'cddc4dcf-260d-4684-a8e7-463b2db261e5'


def b64dec(s):
    s2 = str(s).translate(str.maketrans(CUS, STD))
    s2 += '=' * (-len(s2) % 4)
    return base64.b64decode(s2)


def load_bodies(limit=None):
    out = []
    with open(os.path.join(CAP, 'bodies_now.jsonl'), encoding='utf-8', errors='replace') as fh:
        for line in fh:
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
                k = PRIV.decrypt(b64dec(parts[0]), None)
                k16 = k.decode('ascii')
            except Exception:
                continue
            if not re.fullmatch(r'[A-Za-z0-9]{16}', k16):
                continue
            try:
                p1 = b64dec(parts[1])
            except Exception:
                continue
            if len(p1) >= 32 and len(p1) % 16 == 0:
                out.append((k16, p1, d.get('path', '')))
            if limit and len(out) >= limit:
                break
    return out


def derive_keys(k16: bytes):
    """给定 K16 生成全部 key 候选"""
    md = lambda b: hashlib.md5(b).digest()
    sha1 = lambda b: hashlib.sha1(b).digest()
    sha256 = lambda b: hashlib.sha256(b).digest()
    hexd = lambda b: hashlib.md5(b).hexdigest().encode()
    cands = {
        'K16': k16,
        'rev': k16[::-1],
        'md5': md(k16),
        'md5hex16': hexd(k16),
        'sha1_16': sha1(k16)[:16],
        'sha1hex16': hashlib.sha1(k16).hexdigest().encode()[:16],
        'sha256_16': sha256(k16)[:16],
        'sha256hex16': hashlib.sha256(k16).hexdigest().encode()[:16],
        'md5(k16+salt)': md(k16 + SALT),
        'md5(salt+k16)': md(SALT + k16),
        'md5hex(k16+salt)': (k16 + SALT) and hashlib.md5(k16 + SALT).hexdigest().encode()[:16],
        'md5(salt+k16)hex': hashlib.md5(SALT + k16).hexdigest().encode()[:16],
        'md5(k16+devid)': md(k16 + DEVID),
        'md5(devid+k16)': md(DEVID + k16),
        'md5hex(devid+k16)': hashlib.md5(DEVID + k16).hexdigest().encode()[:16],
        'md5(k16+k16)': md(k16 + k16),
        'md5hex(k16+k16)': hashlib.md5(k16 + k16).hexdigest().encode()[:16],
        'sha256(k16+salt)': sha256(k16 + SALT)[:16],
        'md5(k16)XORsalt*3': bytes(a ^ b for a, b in zip(md(k16), (SALT * 3)[:16])),
        'CH_KEY': CH_KEY,
        'LD_KEY': LD_KEY,
        'md5(CH+K16)': md(CH_KEY + k16),
        'md5(K16+CH)': md(k16 + CH_KEY),
        'md5hex(CH+K16)': hashlib.md5(CH_KEY + k16).hexdigest().encode()[:16],
    }
    return cands


def derive_ivs(k16: bytes, C: bytes):
    md = lambda b: hashlib.md5(b).digest()
    return {
        'CH_IV': CH_IV,
        'LD_IV': LD_IV,
        'zero': b'\x00' * 16,
        'K16': k16,
        'rev': k16[::-1],
        'md5(k16)': md(k16),
        'md5hex16': hashlib.md5(k16).hexdigest().encode()[:16],
        'C[:16]': C[:16],
        'md5(k16+salt)': md(k16 + SALT),
        'md5(salt+k16)': md(SALT + k16),
        'md5(devid)': md(DEVID),
        'md5hex(devid)': hashlib.md5(DEVID).hexdigest().encode()[:16],
        'CH_KEY': CH_KEY,
        'LD_KEY': LD_KEY,
    }


def main():
    bodies = load_bodies()
    print('[load]', len(bodies))
    n_test = 0
    hits = []
    for k16, C, path in bodies:
        kb = k16.encode()
        for kname, key in derive_keys(kb).items():
            if len(key) != 16:
                continue
            for ivname, iv in derive_ivs(kb, C).items():
                if len(iv) != 16:
                    continue
                try:
                    pt = AES.new(key, AES.MODE_CBC, iv).decrypt(C)
                except Exception:
                    continue
                n_test += 1
                good = pt[:7] == b'{"code"' or pt[:1] == b'{' and pt[1:6] == b'"code'
                if good:
                    hits.append((kname, ivname, k16, path, pt[:80]))
                    print(f'*** HIT key={kname} iv={ivname} K16={k16} path={path}')
                    print('   ', pt[:96])
                elif pt[16:32].isascii() and pt[16:20] in (b'"cod', b'"dat', b'"msg', b'"suc'):
                    print(f'~ near key={kname} iv={ivname} K16={k16}: {pt[:48]!r}')
    print('测试组合:', n_test, '命中:', len(hits))


if __name__ == '__main__':
    main()
