# -*- coding: utf-8 -*-
"""tmp_simon_speck.py — 测试 SIMON/SPECK (64/128 与 128/128) 是否为该密码。"""
import os, sys, json
HERE = os.path.dirname(os.path.abspath(__file__))
BF = open(os.path.join(HERE, "tmp_bfpairs.bin"), "rb").read()
pairs8 = [(BF[i*16:i*16+8], BF[i*16+8:i*16+16]) for i in range(8)]
pl = json.load(open(os.path.join(HERE, "tmp_plains.json")))
pr = json.load(open(os.path.join(HERE, "tmp_pairs.json")))
K = b"X8TEUA3DEXZNW2TN"
IV = K[::-1]
json205 = pl[5]["text"].encode("utf-8")[:205]
h21 = [bytes.fromhex(e["p1_hex"]) for e in pr if e.get("hit") == 21][0]
M = 0xFFFFFFFFFFFFFFFF
M32 = 0xFFFFFFFF

def rotl(x, r, w):
    m = (1 << w) - 1
    r %= w
    return ((x << r) | (x >> (w - r))) & m

# ---- SIMON ----
def simon_key_sched(k, word_bits, m, T, seq_z):
    # k: list of m words (little endian), z sequence bits
    w = word_bits
    mask = (1 << w) - 1
    ks = list(k)
    z = seq_z
    c = 0xFFFFFFFC
    for i in range(m, T):
        tmp = rotl(ks[i-1], -3, w)
        if m == 4:
            tmp ^= ks[i-3]
        tmp ^= rotl(tmp, -1, w)
        ks.append((c ^ ((z[(i-m) % 62]) & 1) ^ ks[i-m] ^ tmp) & mask)
    return ks

def simon_enc(blk, key, w, m, T, z):
    mask = (1 << w) - 1
    ks = simon_key_sched(list(key), w, m, T, z)
    x = int.from_bytes(blk[:w//8], 'little')
    y = int.from_bytes(blk[w//8:], 'little')
    for i in range(T):
        x, y = y ^ (rotl(x, 1, w) & rotl(x, 8, w) ^ rotl(x, 2, w) ^ ks[i]), x
    return (x.to_bytes(w//8, 'little') + y.to_bytes(w//8, 'little'))

Z = [1,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,1,0,1,1,0,0,0,0,1,1,1,0,1,1,1,0,0,1,0,1,1,1,0,1,1,0,0,1,0,0,0,0,0,0,1,0,0,0,1,1,1,1,0,0,0,1]

def speck_key_sched(key, w, m, T):
    mask = (1 << w) - 1
    l = list(key[:-1])[::-1]
    ks = [key[-1]]
    for i in range(T-1):
        li = ((rotl(l[i], -8, w) + ks[i]) & mask) ^ i
        ki = rotl(ks[i], 3, w) ^ li
        l.append(li); ks.append(ki)
    return ks

def speck_enc(blk, key, w, m, T):
    mask = (1 << w) - 1
    ks = speck_key_sched(list(key), w, m, T)
    x = int.from_bytes(blk[:w//8], 'little')
    y = int.from_bytes(blk[w//8:], 'little')
    for i in range(T):
        x = ((rotl(x, -8, w) + y) & mask) ^ ks[i]
        y = rotl(y, 3, w) ^ x
    return x.to_bytes(w//8, 'little') + y.to_bytes(w//8, 'little')

# 64/128
k4 = [int.from_bytes(K[i*4:i*4+4], 'little') for i in range(4)]
def s64(b): return simon_enc(b, k4, 32, 4, 44, Z)
def p64(b): return speck_enc(b, k4, 32, 4, 27)
# 128/128
k8 = [int.from_bytes(K[i*2:i*2+2], 'little') for i in range(8)]
k8b = [int.from_bytes(K[i*2:i*2+2], 'big') for i in range(8)]
def s128(b): return simon_enc(b, k8, 64, 2, 68, Z)
def p128(b): return speck_enc(b, k8, 64, 2, 32)

print("--- 8B pairs: E8(X)=?C ---")
for nm, f in (("SIMON64/128", s64), ("SPECK64/128", p64)):
    hit = sum(1 for x, c in pairs8 if f(x) == c)
    hit2 = sum(1 for x, c in pairs8 if f(c) == x)
    print("  %-14s E(X)=C hits=%d/8  E(C)=X hits=%d/8" % (nm, hit, hit2))

print("--- 16B anchor: CBC-E(P)=?h21 ---")
def cbc(f, pt, iv, bs=16):
    from Crypto.Util.Padding import pad
    p = pad(pt, bs)
    out = b""; prev = iv
    for i in range(0, len(p), bs):
        blk = bytes(a ^ b for a, b in zip(p[i:i+bs], prev))
        prev = f(blk)
        out += prev
    return out
for nm, f in (("SIMON128/128-LE", s128),):
    try:
        ct = cbc(f, json205, IV)
        print("  %-16s len=%d eq=%s" % (nm, len(ct), ct == h21))
    except Exception as ex:
        print(nm, "ERR", ex)
# SPECK128 用 8 word key
def s128b(b): return simon_enc(b, k8b, 64, 2, 68, Z)
for nm, f in (("SIMON128/128-BE", s128b), ("SPECK128/128", p128)):
    try:
        ct = cbc(f, json205, IV)
        print("  %-16s len=%d eq=%s" % (nm, len(ct), ct == h21))
    except Exception as ex:
        print(nm, "ERR", ex)
