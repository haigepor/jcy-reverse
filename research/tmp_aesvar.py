# -*- coding: utf-8 -*-
"""tmp_aesvar.py — 可配置 AES 变体扫描(轮数/末轮MixColumns/S盒方向) 对 h21 首块。"""
import os, json
HERE = os.path.dirname(os.path.abspath(__file__))
pl = json.load(open(os.path.join(HERE, "tmp_plains.json")))
pr = json.load(open(os.path.join(HERE, "tmp_pairs.json")))
K = b"X8TEUA3DEXZNW2TN"
IV = K[::-1]
P = pl[5]["text"].encode("utf-8")
h21 = [bytes.fromhex(e["p1_hex"]) for e in pr if e.get("hit") == 21][0]
EIN = bytes(a ^ b for a, b in zip(P[:16], IV))   # E 输入块0
EOUT = h21[:16]

_SO = open(os.path.join(HERE, "artifacts", "libcore.so"), "rb").read()
SBOX = _SO[0x1dfc00:0x1dfc00 + 256]
INV = _SO[0x1e03b0:0x1e03b0 + 256]
print("SBOX len", len(SBOX), "INV ok", len(set(SBOX)) == 256 and len(set(INV)) == 256)

def xt(a):
    a <<= 1
    return (a ^ 0x1b) & 0xff if a & 0x100 else a

def gmul(a, b):
    r = 0
    for _ in range(8):
        if b & 1: r ^= a
        a = xt(a); b >>= 1
    return r

def expand(key, nk=4, nr=10):
    w = [list(key[i*4:i*4+4]) for i in range(nk)]
    rcon = 1
    for i in range(nk, 4*(nr+1)):
        t = list(w[i-1])
        if i % nk == 0:
            t = t[1:] + t[:1]
            t = [SBOX[x] for x in t]
            t[0] ^= rcon
            rcon = xt(rcon)
        elif nk > 6 and i % nk == 4:
            t = [SBOX[x] for x in t]
        w.append([w[i-nk][j] ^ t[j] for j in range(4)])
    return [bytes(sum(w[4*r:4*r+4], [])) for r in range(nr+1)]

def aes_enc(pt, key, nr=10, nk=4, sbox=SBOX, last_mix=True, last_sbox=True):
    rk = expand(key, nk, nr)
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
    if last_sbox:
        s = sub(s)
    s = shift(s)
    if last_mix:
        s = mix(s)
    s = [x ^ y for x, y in zip(s, rk[nr])]
    return bytes(s)

print("E-in ", EIN.hex())
print("E-out", EOUT.hex())
hits = []
for nr in range(1, 15):
    for nk, key in ((4, K), (6, K + b"\x00\x00\x00\x00"), (8, K + K)):
        for sbox, sn in ((SBOX, 'S'), (INV, 'INV')):
            for lm in (True, False):
                try:
                    o = aes_enc(EIN, key, nr, nk, sbox, lm)
                    if o == EOUT:
                        hits.append((nr, nk, sn, lm))
                except Exception:
                    pass
print("hits:", hits)
