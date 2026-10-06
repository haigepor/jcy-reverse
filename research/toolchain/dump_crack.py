#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dump_crack.py - 全内存转储离线破解:
Phase A: 转储中 K16 形态字符串/md5hex → key 候选 × 全量密文 IV 无关单块测试
Phase B: 全 dump 所有 alnum-16
Phase C: K16 附近二进制窗口
命中后从 key 附近 ±4KB 提取 IV (CBC 全解 JSON 验证)
"""
import base64
import glob
import hashlib
import json
import os
import re
import struct
import sys
import time

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

CUS = '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
HERE = os.path.join(os.path.dirname(__file__), '..', 'captures', 'rsa_scan')
PRIV = PKCS1_v1_5.new(RSA.import_key(open(os.path.join(HERE, 'priv_from_go.pem'), 'rb').read()))
CHUNK_RE = re.compile(r'\r\n[0-9a-fA-F]{1,8}\r\n')

CT_RE = re.compile(rb'[A-Za-z0-9+/]{340,348}==\.[A-Za-z0-9+/]{40,}')
ALNUM16_RE = re.compile(rb'(?<![A-Za-z0-9])[A-Za-z0-9]{16}(?![A-Za-z0-9])')
HEX32_RE = re.compile(rb'(?<![0-9a-fA-F])[0-9a-f]{32}(?![0-9a-fA-F])')


def b64dec(s):
    s2 = str(s).translate(str.maketrans(CUS, STD))
    s2 += '=' * (-len(s2) % 4)
    return base64.b64decode(s2)


def load_corpus_from_jsonl():
    out = {}
    with open(os.path.join(HERE, 'bodies_now.jsonl'), encoding='utf-8', errors='replace') as fh:
        for line in fh:
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
                k = PRIV.decrypt(b64dec(parts[0]), None).decode('ascii')
                C = b64dec(parts[1])
            except Exception:
                continue
            if len(C) >= 32 and len(C) % 16 == 0:
                out.setdefault(k, C)
    return out


def load_corpus_from_dump(dumpdir, files):
    out = {}
    for fp in files:
        data = open(fp, 'rb').read()
        for m in CT_RE.finditer(data):
            s = m.group(0)
            i = s.find(b'==.')
            p0s, p1s = s[:i], s[i + 3:]
            if len(p0s) != 344:
                continue
            try:
                k = PRIV.decrypt(b64dec(p0s), None).decode('ascii')
                C = b64dec(p1s.rstrip()) if False else b64dec(p1s)
            except Exception:
                continue
            if re.fullmatch(r'[A-Za-z0-9]{16}', k) and len(C) >= 32 and len(C) % 16 == 0:
                out.setdefault(k, C)
    return out


def printable(b):
    return all(32 <= c < 127 or c in (9, 10, 13) for c in b)


def test_key(key, corpus_pairs):
    """corpus_pairs: [(C0, C1), ...]; 返回命中的 C0C1 列表"""
    try:
        ec = AES.new(key, AES.MODE_ECB)
    except Exception:
        return []
    hits = []
    for C0, C1 in corpus_pairs:
        try:
            x = ec.decrypt(C1)
        except Exception:
            return []
        p = bytes(a ^ b for a, b in zip(x, C0))
        if printable(p):
            hits.append((C0, C1, p))
    return hits


def main():
    dumpdir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, 'livedump2')
    files = sorted(glob.glob(os.path.join(dumpdir, '*.bin')))
    print('[dump] files:', len(files), 'total %.2f GB' % (
        sum(os.path.getsize(f) for f in files) / (1 << 30)))

    # --- 语料: jsonl + dump 双源 ---
    corpus = load_corpus_from_jsonl()
    print('[corpus] jsonl:', len(corpus))
    t0 = time.time()
    corpus_dump = load_corpus_from_dump(dumpdir, files)
    print('[corpus] dump 额外:', len(corpus_dump), '(%.0fs)' % (time.time() - t0))
    corpus.update(corpus_dump)
    pairs = []
    k16_of = {}
    for k16, C in corpus.items():
        pairs.append((C[:16], C[16:32]))
        k16_of[(C[:16], C[16:32])] = k16
    print('[corpus] 总密文:', len(corpus))

    # --- Phase A: 转储 K16 形态/32hex 字符串 ---
    cand = set()
    for k16 in corpus:
        cand.add(k16.encode())
    t0 = time.time()
    for fp in files:
        data = open(fp, 'rb').read()
        for m in ALNUM16_RE.finditer(data):
            cand.add(m.group(0))
        for m in HEX32_RE.finditer(data):
            h = m.group(0)
            cand.add(h[:16])
            cand.add(h[16:])
    print('[phaseA] alnum16/32hex 候选:', len(cand), '(%.0fs)' % (time.time() - t0))

    hits = []
    t0 = time.time()
    tested = 0
    for key in cand:
        h = test_key(key, pairs)
        tested += 1
        if h:
            for C0, C1, p in h:
                hits.append((key, k16_of[(C0, C1)], p))
                print('*** HIT key=%r k16=%s pt=%r' % (key, k16_of[(C0, C1)], p[:40]))
    print('[phaseA] tested', tested, '(%.0fs)' % (time.time() - t0), 'hits', len(hits))

    # --- 命中后 IV 提取 ---
    for key, k16, p in hits:
        C = corpus[k16]
        pt16 = p  # D(C1)^C0 = P[16:32]
        ivs = set([b'\x00' * 16, k16.encode(), k16.encode()[::-1],
                   hashlib.md5(k16.encode()).digest()])
        # key 串在 dump 中的位置 ±4KB 窗口
        for fp in files:
            data = open(fp, 'rb').read()
            i = data.find(key)
            if i < 0:
                continue
            lo = max(0, i - 4096)
            for j in range(lo, min(len(data) - 16, i + 4096)):
                ivs.add(data[j:j + 16])
        for iv in ivs:
            try:
                pt = AES.new(key, AES.MODE_CBC, iv).decrypt(C)
            except Exception:
                continue
            if pt[:1] == b'{':
                print('=== FULL HIT key=%r k16=%s iv=%r' % (key, k16, iv))
                print('    IV hex:', iv.hex())
                print('    ', pt[:120])
                break


if __name__ == '__main__':
    main()
