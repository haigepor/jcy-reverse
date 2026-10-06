# -*- coding: utf-8 -*-
"""tmp_ksa_aes.py — 假设 S 盒 = RC4式KSA(AES S-box, key), 轮=标准AES。对 h21 首块。"""
import os, json, itertools
HERE = os.path.dirname(os.path.abspath(__file__))
pl = json.load(open(os.path.join(HERE, "tmp_plains.json")))
pr = json.load(open(os.path.join(HERE, "tmp_pairs.json")))
K = b"X8TEUA3DEXZNW2TN"
IV = K[::-1]
P = pl[5]["text"].encode("utf-8")
h21 = [bytes.fromhex(e["p1_hex"]) for e in pr if e.get("hit") == 21][0]
EIN = bytes(a ^ b for a, b in zip(P[:16], IV))
EOUT = h21[:16]
SO = open(os.path.join(HERE, "artifacts", "libcore.so"), "rb").read()
AES = SO[0x1dfc00:0x1dfc00 + 256]

def ksa(base, key):
    S = list(base)
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xff
        S[i], S[j] = S[j], S[i]
    return bytes(S)

def xt(a):
    a <<= 1
    return (a ^ 0x1b) & 0xff if a & 0x100 else a

def gmul(a, b):
    r = 0
    for _ in range(8):
        if b & 1: r ^= a
        a = xt(a); b >>= 1
    return r

def expand(key, sbox, nk, nr):
    w = [list(key[i*4:i*4+4]) for i in range(nk)]
    rc = 1
    for i in range(nk, 4*(nr+1)):
        t = list(w[i-1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [sbox[x] for x in t]
            t[0] ^= rc; rc = xt(rc)
        elif nk > 6 and i % nk == 4:
            t = [sbox[x] for x in t]
        w.append([w[i-nk][j] ^ t[j] for j in range(4)])
    return [bytes(sum(w[4*r:4*r+4], [])) for r in range(nr+1)]

def aes_enc(pt, key, sbox, nr, nk, last_mix=False):
    rk = expand(key, sbox, nk, nr)
    s = list(bytes(a ^ b for a, b in zip(pt, rk[0])))
    def sub(s): return [sbox[x] for x in s]
    def shift(s):
        o = [0]*16
        for c in range(4):
            for r in range(4):
                o[4*c+r] = s[4*((c+r) % 4)+r]
        return o
    def mix(s):
        o = [0]*16
        for c in range(4):
            a = s[4*c:4*c+4]
            o[4*c+0] = gmul(a[0],2) ^ gmul(a[1],3) ^ a[2] ^ a[3]
            o[4*c+1] = a[0] ^ gmul(a[1],2) ^ gmul(a[2],3) ^ a[3]
            o[4*c+2] = a[0] ^ a[1] ^ gmul(a[2],2) ^ gmul(a[3],3)
            o[4*c+3] = gmul(a[0],3) ^ a[1] ^ a[2] ^ gmul(a[3],2)
        return o
    for r in range(1, nr):
        s = sub(s); s = shift(s); s = mix(s)
        s = [x ^ y for x, y in zip(s, rk[r])]
    s = sub(s); s = shift(s)
    if last_mix: s = mix(s)
    s = [x ^ y for x, y in zip(s, rk[nr])]
    return bytes(s)

keycands = {"K16": K, "rev": IV, "K16x2": K*2, "K16+0": K + b"\x00"*16}
hits = []
for kn, kk in keycands.items():
    sbox = ksa(AES, kk)
    for nr in range(1, 15):
        for nk in (4,):
            for lm in (False, True):
                try:
                    if aes_enc(EIN, K, sbox, nr, nk, lm) == EOUT:
                        hits.append((kn, nr, nk, lm))
                except Exception:
                    pass
print("hits:", hits)
print("EIN ", EIN.hex())
print("EOUT", EOUT.hex())
