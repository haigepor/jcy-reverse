#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""pair_extract.py - 从 hits.jsonl 提取全部完整 JSON 明文, 与密文按长度配对, 跑全模式测试电池"""
import base64
import hashlib
import json
import os
import re
import struct

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Util import Counter
from Crypto.PublicKey import RSA

CUS = '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
STD = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
HERE = os.path.join(os.path.dirname(__file__), '..', 'captures', 'rsa_scan')
PAIR = os.path.join(HERE, 'pair')
os.makedirs(PAIR, exist_ok=True)
PRIV = PKCS1_v1_5.new(RSA.import_key(open(os.path.join(HERE, 'priv_from_go.pem'), 'rb').read()))
CHUNK_RE = re.compile(r'\r\n[0-9a-fA-F]{1,8}\r\n')

# ---------------- SM4 (纯 python, 标准实现) ----------------
SM4_SBOX = [
0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48]
FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]
CK = [0x00070e15,0x1c232a31,0x383f464d,0x545b6269,0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
      0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
      0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
      0xa0a7aeb5,0xbcc3cad1,0xdce3eaf1,0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d]


def _sm4_rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xffffffff


def _sm4_tau(a):
    return (SM4_SBOX[(a >> 24) & 0xff] << 24) | (SM4_SBOX[(a >> 16) & 0xff] << 16) | \
           (SM4_SBOX[(a >> 8) & 0xff] << 8) | SM4_SBOX[a & 0xff]


def _sm4_t_key(a):
    b = _sm4_tau(a)
    return b ^ _sm4_rotl(b, 13) ^ _sm4_rotl(b, 23)


def _sm4_t_enc(a):
    b = _sm4_tau(a)
    return b ^ _sm4_rotl(b, 2) ^ _sm4_rotl(b, 10) ^ _sm4_rotl(b, 18) ^ _sm4_rotl(b, 24)


def sm4_key_schedule(key16):
    mk = struct.unpack('>4I', key16)
    k = [mk[i] ^ FK[i] for i in range(4)]
    rk = []
    for i in range(32):
        t = k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]
        nk = k[i] ^ _sm4_t_key(t)
        k.append(nk)
        rk.append(nk)
    return rk


def _sm4_f(rk, blk):
    x = list(struct.unpack('>4I', blk))
    for i in range(32):
        x[i + 4] = x[i] ^ _sm4_t_enc(x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i])
    return struct.pack('>4I', x[35], x[34], x[33], x[32])


def sm4_ecb_enc(key16, block):
    return _sm4_f(sm4_key_schedule(key16), block)


def sm4_ecb_dec(key16, block):
    rk = sm4_key_schedule(key16)[::-1]
    return _sm4_f(rk, block)


def sm4_cbc_dec(key16, ct, iv):
    out = bytearray()
    prev = iv
    for i in range(0, len(ct), 16):
        blk = ct[i:i + 16]
        out += bytes(a ^ b for a, b in zip(sm4_ecb_dec(key16, blk), prev))
        prev = blk
    return bytes(out)


# ---------------- 数据加载 ----------------

def b64dec(s):
    s2 = str(s).translate(str.maketrans(CUS, STD))
    s2 += '=' * (-len(s2) % 4)
    return base64.b64decode(s2)


def extract_plains():
    """括号配平提取完整 JSON, 去重"""
    recs = [json.loads(l) for l in open(os.path.join(HERE, 'watch_plain', 'hits.jsonl'), encoding='utf-8') if l.strip()]
    plains = {}
    for ri, r in enumerate(recs):
        if not r.get('ctx_b64'):
            continue
        raw = base64.b64decode(r['ctx_b64'])
        for m in re.finditer(rb'\{"code"', raw):
            i = m.start()
            depth = 0
            instr = False
            esc = False
            end = None
            for j in range(i, min(i + 40000, len(raw))):
                b = raw[j]
                if esc:
                    esc = False
                elif instr and b == 0x5c:
                    esc = True
                elif b == 0x22:
                    instr = not instr
                elif not instr:
                    if b == 0x7b:
                        depth += 1
                    elif b == 0x7d:
                        depth -= 1
                        if depth == 0:
                            end = j + 1
                            break
            if end is None:
                continue
            blob = raw[i:end]
            if b'"total"' not in blob and b'"data"' not in blob:
                continue
            # 结尾必须像 JSON (防堆垃圾) — 尾字节应是 } 且串内无 \x00
            if b'\x00' in blob:
                continue
            key = blob[:80]
            if key in plains and len(plains[key][0]) >= len(blob):
                continue
            plains[key] = (blob, r.get('addr'), ri)
    out = sorted(plains.values(), key=lambda t: -len(t[0]))
    return out


def load_bodies():
    out = []
    with open(os.path.join(HERE, 'bodies_now.jsonl'), encoding='utf-8', errors='replace') as fh:
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
                if not re.fullmatch(r'[A-Za-z0-9]{16}', k16):
                    continue
                p1 = b64dec(parts[1])
            except Exception:
                continue
            if len(p1) >= 32 and len(p1) % 16 == 0:
                out.append((k16, p1))
    return out


def main():
    plains = extract_plains()
    print('=== 完整明文 JSON 数:', len(plains))
    manifest = []
    for n, (blob, addr, ri) in enumerate(plains):
        fn = f'plain_{n:03d}.bin'
        open(os.path.join(PAIR, fn), 'wb').write(blob)
        manifest.append({'file': fn, 'len': len(blob), 'addr': addr, 'rec': ri,
                         'head': blob[:60].decode('utf-8', 'replace')})
        print(f'{fn} len={len(blob)} addr={addr} {blob[:56].decode("utf-8", "replace")!r}')
    json.dump(manifest, open(os.path.join(PAIR, 'manifest.json'), 'w'), ensure_ascii=False, indent=1)

    bodies = load_bodies()
    print('=== bodies:', len(bodies))
    from collections import Counter
    print('P1 长度分布:', sorted(Counter(len(C) for _, C in bodies).items()))

    # 长度配对: P1 = 16*ceil((L+pad)/16); PKCS7 -> 16*ceil((L+1)/16)
    for k16, C in bodies:
        for blob, addr, ri in plains:
            L = len(blob)
            if len(C) in (16 * ((L + 16) // 16), 16 * ((L + 1 + 15) // 16), 16 * ((L + 15) // 16)):
                print(f'[LEN-PAIR] P1len={len(C)} plainlen={L} K16={k16} addr={addr}')


if __name__ == '__main__':
    main()
