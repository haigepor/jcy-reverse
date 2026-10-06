#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sched_dump.py - numpy 向量化 AES-128 加密调度扫描全量内存转储
候选调度 → 全量密文 IV 无关验证。另含 UTF16 串候选 + K16 邻域二进制窗口。"""
import base64
import glob
import hashlib
import json
import os
import re
import struct
import sys
import time

import numpy as np

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

CUS = '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
HERE = os.path.join(os.path.dirname(__file__), '..', 'captures', 'rsa_scan')
PRIV = PKCS1_v1_5.new(RSA.import_key(open(os.path.join(HERE, 'priv_from_go.pem'), 'rb').read()))
CHUNK_RE = re.compile(r'\r\n[0-9a-fA-F]{1,8}\r\n')

SBOX_NP = np.array([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16], dtype=np.uint32)
RCON = [0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
        0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000]


def sub_rot_py(w):
    b = [(w >> 24) & 0xff, (w >> 16) & 0xff, (w >> 8) & 0xff, w & 0xff]
    b = b[1:] + b[:1]
    return (int(SBOX_NP[b[0]]) << 24) | (int(SBOX_NP[b[1]]) << 16) | \
           (int(SBOX_NP[b[2]]) << 8) | int(SBOX_NP[b[3]])


def verify_enc(words):
    for i in range(4, 44):
        if i % 4 == 0:
            exp = words[i - 4] ^ sub_rot_py(words[i - 1]) ^ RCON[i // 4 - 1]
        else:
            exp = words[i - 4] ^ words[i - 1]
        if words[i] != exp:
            return False
    return True


def b64dec(s):
    s2 = str(s).translate(str.maketrans(CUS, STD))
    s2 += '=' * (-len(s2) % 4)
    return base64.b64decode(s2)


def load_corpus():
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


def printable(b):
    return all(32 <= c < 127 or c in (9, 10, 13) for c in b)


def scan_file_sched(fp, found):
    data = open(fp, 'rb').read()
    n = len(data)
    if n < 176:
        return
    arr = np.frombuffer(data, dtype=np.uint8)
    for endian in ('>', '<'):
        for k in range(4):  # 字节对齐
            w = np.frombuffer(data[k:], dtype=endian + 'u4', count=(n - k) // 4)
            if len(w) < 12:
                continue
            w0 = w[0:-3].astype(np.uint64)
            w3 = w[3:-1].astype(np.uint64)  # W3 = words[i+3]? 错位: W0 at j, W3 at j+3, W4 at j+4
            # 实际: W4[j] = w[j+4]; W0[j] = w[j]; W3[j] = w[j+3]
            if len(w) < 5:
                continue
            W0 = w[:-4].astype(np.uint64)
            W3 = w[3:-1].astype(np.uint64)
            W4 = w[4:].astype(np.uint64)
            if endian == '>':
                b1 = (W3 >> 16) & 0xff
                b2 = (W3 >> 8) & 0xff
                b3 = W3 & 0xff
                b0 = (W3 >> 24) & 0xff
            else:
                # LE 词内字节序: byte0 最低; RotWord 在 BE 语义上需把词转成 BE
                # 统一转成 BE 语义值处理
                wb3 = ((W3 & 0xff) << 24) | ((W3 & 0xff00) << 8) | ((W3 >> 8) & 0xff00) | ((W3 >> 24) & 0xff)
                b0 = (wb3 >> 24) & 0xff
                b1 = (wb3 >> 16) & 0xff
                b2 = (wb3 >> 8) & 0xff
                b3 = wb3 & 0xff
            sr = (SBOX_NP[b1] << 24) | (SBOX_NP[b2] << 16) | (SBOX_NP[b3] << 8) | SBOX_NP[b0]
            if endian == '<':
                # 结果 sr 是 BE 语义; 转 LE 存储
                sr_le = ((sr & 0xff) << 24) | ((sr & 0xff00) << 8) | ((sr >> 8) & 0xff00) | ((sr >> 24) & 0xff)
                exp = W0 ^ sr_le ^ RCON[0]
            else:
                exp = W0 ^ sr ^ RCON[0]
            cand = np.nonzero(W4 == exp)[0]
            for ci in cand:
                off = k + int(ci) * 4
                if off + 176 > n:
                    continue
                words = list(struct.unpack_from(endian + '44I', data, off))
                if verify_enc(words):
                    key = struct.pack('>4I', *words[:4]) if endian == '>' else \
                        struct.pack('<4I', *words[:4])
                    if key not in found:
                        found[key] = (os.path.basename(fp), off, endian)
                        print('[SCHED] %s@%#x %s key=%s' % (os.path.basename(fp), off, endian, key.hex()))


def main():
    dumpdir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, 'livedump2_pull')
    files = sorted(glob.glob(os.path.join(dumpdir, '*.bin')))
    corpus = load_corpus()
    pairs = [(C[:16], C[16:32]) for C in corpus.values()]
    k16s = list(corpus.keys())
    print('[corpus]', len(corpus), 'files', len(files))

    # ---- 调度扫描 ----
    found = {}
    t0 = time.time()
    for fp in files:
        scan_file_sched(fp, found)
    print('[sched] 调度总数', len(found), '(%.0fs)' % (time.time() - t0))
    sys.stdout.flush()

    # ---- 调度 key 验证 (IV 无关) ----
    sched_hits = []
    for key in found:
        try:
            ec = AES.new(key, AES.MODE_ECB)
        except Exception:
            continue
        for C0, C1 in pairs:
            p = bytes(a ^ b for a, b in zip(ec.decrypt(C1), C0))
            if p[:1] == b'{' and printable(p):
                k16 = None
                for k, C in corpus.items():
                    if C[:16] == C0:
                        k16 = k
                        break
                sched_hits.append((key, k16))
                print('*** SCHED-KEY HIT key=%s k16=%s pt=%r' % (key.hex(), k16, p[:48]))
    print('[sched] 验证命中', len(sched_hits))

    # ---- K16 是否在场 ----
    for k in k16s:
        for fp in files:
            data = open(fp, 'rb').read()
            if k.encode() in data:
                print('[K16-in-dump]', k, os.path.basename(fp))
                break

    # ---- 结果存档 ----
    json.dump({k.hex(): v for k, v in found.items()},
              open(os.path.join(HERE, 'sched_dump_keys.json'), 'w'), indent=1)


if __name__ == '__main__':
    main()
