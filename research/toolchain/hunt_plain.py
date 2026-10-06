#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""hunt_plain.py - dump 明文 × 抓包密文配对: 验证 key=K16 假设并反推 IV"""
import base64
import glob
import hashlib
import json
import os
import re

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

CUS = '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
CAP = 'research/captures/rsa_scan'
PRIV = PKCS1_v1_5.new(RSA.import_key(open(f'{CAP}/priv_from_go.pem', 'rb').read()))

DECHUNK_RE = re.compile(r'(?:^|\r\n)[0-9a-fA-F]{1,8}\r\n')


def b64dec(s, alpha=CUS):
    t = str.maketrans(alpha, STD)
    s2 = s.translate(t)
    s2 += '=' * (-len(s2) % 4)
    return base64.b64decode(s2)


def dechunk(s):
    if '\r\n' not in s[:20]:
        return s
    out, i = [], 0
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


def load_bodies():
    out = []
    seen = set()

    def add(req, body):
        body = dechunk(body)
        parts = body.split('.')
        if len(parts) == 2 and len(parts[0]) == 344:
            p0s, p1s = parts[0], parts[1]
        elif len(parts) == 1 and len(body) > 344 and len(body) % 4 == 0:
            p0s, p1s = body[:344], body[344:]
        else:
            return
        try:
            p0 = b64dec(p0s)
            p1 = b64dec(p1s)
        except Exception:
            return
        if len(p0) != 256 or len(p1) == 0 or len(p1) % 16:
            return
        k16 = PRIV.decrypt(p0, None)
        if not k16 or len(k16) != 16:
            return
        try:
            k16s = k16.decode('ascii')
        except Exception:
            return
        if not re.fullmatch(r'[A-Za-z0-9]{16}', k16s):
            return
        key = k16s
        if key in seen:
            return
        seen.add(key)
        out.append((req, k16s, p1))

    for line in open(f'{CAP}/bodies_now.jsonl', encoding='utf-8', errors='replace'):
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        body = d.get('resp_body_ascii') or d.get('resp_body') or ''
        req = (d.get('req', '?').split() + ['?'])[1].split('?')[0]
        if isinstance(body, str) and len(body) > 400:
            add(req, body)
    try:
        for line in open(f'{CAP}/responses_batch1.jsonl', encoding='utf-8', errors='replace'):
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            add(d.get('path', '?'), d.get('body', ''))
    except FileNotFoundError:
        pass
    try:
        for line in open(f'{CAP}/proxy_now.jsonl', encoding='utf-8', errors='replace'):
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except Exception:
                continue
            body = d.get('resp_body_ascii') or d.get('resp_body') or d.get('body') or ''
            req = d.get('path') or (d.get('req', '?').split() + ['?'])[1].split('?')[0]
            if isinstance(body, str) and len(body) > 400:
                add(req, body)
    except FileNotFoundError:
        pass
    return out


def find_plaintexts(dumpdir, limit_files=None):
    """在 dump 中提取明文 JSON: 定位 b'{"code":' 并 raw_decode."""
    results = []
    files = sorted(glob.glob(f'{dumpdir}/*.bin'))
    if limit_files:
        files = [f for f in files if os.path.basename(f) in limit_files]
    for fp in files:
        data = open(fp, 'rb').read()
        if b'{"code"' not in data and b'{"code":' not in data:
            continue
        start = 0
        count = 0
        while count < 400:
            i = data.find(b'{"code"', start)
            if i < 0:
                break
            start = i + 1
            # raw_decode 从 i 开始
            try:
                obj, end = json.JSONDecoder().raw_decode(data[i:].decode('utf-8', 'replace'))
                blob = data[i:i + end]
                results.append((os.path.basename(fp), i, blob))
                count += 1
            except Exception:
                # 截断/非JSON: 只留前缀作为候选
                pref = data[i:i + 64]
                if len(pref) >= 48 and pref.count(b'"') >= 2:
                    results.append((os.path.basename(fp), i, pref))
                continue
    return results


def main():
    bodies = load_bodies()
    print(f'有效 bodies: {len(bodies)} (去重后)')
    k16set = {k for _, k, _ in bodies}
    print('K16 样本:', list(k16set)[:5])

    pts = find_plaintexts(f'{CAP}/livedump', limit_files=[
        '401_737e41700000.bin', '437_737e62887000.bin', '402_737e41c00000.bin',
        '413_737e43117000.bin'])
    # 去重: 同一文件同一 JSON 只留一次 (raw_decode 可能从多个嵌套点触发)
    uniq = {}
    for f, off, blob in pts:
        sig = (f, blob[:48])
        if sig not in uniq:
            uniq[sig] = (f, off, blob)
    print(f'明文候选: {len(uniq)}')
    for (f, _), (f2, off, blob) in uniq.items():
        print(f'  {f}@{off:#x} len={len(blob)} head={blob[:60]!r}')

    # 配对: 长度过滤 + ECB 关系验证
    key_cands = {}
    for k16s in k16set:
        kb = k16s.encode()
        key_cands[k16s] = {
            'K16': kb,
            'rev': kb[::-1],
            'md5_16': hashlib.md5(kb).digest()[:16],
            'sha1_16': hashlib.sha1(kb).digest()[:16],
            'sha256_16': hashlib.sha256(kb).digest()[:16],
        }

    hits = []
    # 长度诊断
    lens = sorted({len(C) for _, _, C in bodies})
    print('密文长度种类:', lens[:20], '...' if len(lens) > 20 else '')
    for (f, _), (f2, off, blob) in uniq.items():
        n = len(blob)
        ok_lens = {(n // 16) * 16, ((n // 16) + 1) * 16, ((n // 16) + 2) * 16}
        for req, k16s, C in bodies:
            if len(C) not in ok_lens or len(C) < 32:
                continue
            for kn, kb in key_cands[k16s].items():
                # D(C1) == P'[16:32] ^ C0
                try:
                    d_c1 = AES.new(kb, AES.MODE_ECB).decrypt(C[16:32])
                    want = bytes(a ^ b for a, b in zip(blob[16:32], C[0:16]))
                    if d_c1 == want:
                        d_c0 = AES.new(kb, AES.MODE_ECB).decrypt(C[0:16])
                        iv = bytes(a ^ b for a, b in zip(d_c0, blob[0:16]))
                        msg = (f'*** KEY确认 req={req} K16={k16s} key={kn} '
                               f'IV={iv!r} plaintext_len={n} cipher_len={len(C)}')
                        print(msg)
                        hits.append(msg)
                except Exception:
                    continue
    if not hits:
        print('无命中 — 长度配对或 key 假设需调整')


if __name__ == '__main__':
    main()
