# -*- coding: utf-8 -*-
"""tmp_p1_try.py - 判定 P1 分组密码: 解样例 P1, 试多种候选密码/布局."""
import base64
import json
import struct
import sys

sys.path.insert(0, 'src')
from jcy_protocol.auth import custom_b64d  # noqa

env = json.load(open('research/tmp_real_env.json', encoding='utf-8'))
data = env['payload']['data']
P0s, P1s = data.split('.', 1)
print('P0 chars', len(P0s), 'P1 chars', len(P1s))
P1 = custom_b64d(P1s)
print('P1 bytes', len(P1), P1[:16].hex())
K16 = b'T9Z19J7NCY9S9X58'

# ---- Blowfish 表 ----
LIB = None
for p in ('research/artifacts/device_libs/libcore.so', 'research/artifacts/libcore.so'):
    try:
        LIB = open(p, 'rb').read()
        print('lib =', p, len(LIB))
        break
    except OSError:
        pass
BASE = 0x200620
tbl = LIB[BASE:BASE + 4 * 18 + 4 * 1024]
P = list(struct.unpack('<18I', tbl[:72]))
S = list(struct.unpack('<1024I', tbl[72:72 + 4096]))
M = 0xffffffff


def bf_f(x, P, S):
    a, b, c, d = (x >> 24) & 0xff, (x >> 16) & 0xff, (x >> 8) & 0xff, x & 0xff
    return (((S[a] + S[256 + b]) & M) ^ S[512 + c]) + S[768 + d] & M


def bf_key(key, P, S):
    P = list(P); S = list(S)
    kp = 0
    for i in range(18):
        v = 0
        for _ in range(4):
            v = ((v << 8) | key[kp]) & M
            kp = (kp + 1) % len(key)
        P[i] ^= v
    l = r = 0
    for i in range(0, 18, 2):
        l, r = bf_ew(l, r, P, S); P[i], P[i + 1] = l, r
    for box in range(4):
        for i in range(0, 256, 2):
            l, r = bf_ew(l, r, P, S); S[box * 256 + i], S[box * 256 + i + 1] = l, r
    return P, S


def bf_ew(l, r, P, S):
    for i in range(16):
        l ^= P[i]; r ^= bf_f(l, P, S); l, r = r, l
    l, r = r, l
    r ^= P[16]; l ^= P[17]
    return l, r


def bf_dec_block(blk, P, S):
    l, r = struct.unpack('>2I', blk)
    l ^= P[17]; r ^= P[16]
    l, r = r, l
    for i in range(15, -1, -1):
        l, r = r, l
        r ^= bf_f(l, P, S); l ^= P[i]
    return struct.pack('>2I', l, r)


def bf_enc_block(blk, P, S):
    l, r = struct.unpack('>2I', blk)
    l, r = bf_ew(l, r, P, S)
    return struct.pack('>2I', l, r)


def cbc_dec(ct, key, iv, decfn):
    out = b''
    prev = iv
    for i in range(0, len(ct), 8):
        c = ct[i:i + 8]
        out += bytes(a ^ b for a, b in zip(decfn(c), prev))
        prev = c
    return out


Pk, Sk = bf_key(K16, P, S)
print('bf keyed.')
for name, iv in (('rev16[:8]', K16[::-1][:8]), ('K16[:8]', K16[:8]),
                 ('rev8', K16[::-1][:8])):
    pt = cbc_dec(P1, K16, iv, lambda c: bf_dec_block(c, Pk, Sk))
    print('[BF-CBC8 iv=%s] %r' % (name, pt[:80]))

# ECB
pt = b''.join(bf_dec_block(P1[i:i + 8], Pk, Sk) for i in range(0, len(P1), 8))
print('[BF-ECB] %r' % pt[:80])
