# -*- coding: utf-8 -*-
"""tmp_std8.py — 把 bfpairs 当作某标准 8 字节分组密码的 (输入,输出) 对来检验。
X_i = D(C_i)  =>  候选 E8(X_i) 应 == C_i
"""
import os, sys, struct, json
HERE = os.path.dirname(os.path.abspath(__file__))
BF = open(os.path.join(HERE, "tmp_bfpairs.bin"), "rb").read()
K = b"X8TEUA3DEXZNW2TN"
pairs = [(BF[i*16:i*16+8], BF[i*16+8:i*16+16]) for i in range(8)]

M = 0xFFFFFFFF
def ror(x, n): return ((x >> n) | (x << (32 - n))) & M
def rol(x, n): return ((x << n) | (x >> (32 - n))) & M

def tea_enc(v, k, rounds=32, big=False):
    o = ">" if big else "<"
    v0, v1 = struct.unpack(o+"II", v)
    k0, k1, k2, k3 = struct.unpack(o+"IIII", k)
    s = 0; d = 0x9E3779B9
    for _ in range(rounds):
        s = (s + d) & M
        v0 = (v0 + ((((v1 << 4) & M) + k0) ^ (v1 + s) ^ ((v1 >> 5) + k1))) & M
        v1 = (v1 + ((((v0 << 4) & M) + k2) ^ (v0 + s) ^ ((v0 >> 5) + k3))) & M
    return struct.pack(o+"II", v0, v1)

def xtea_enc(v, k, rounds=32, big=False):
    o = ">" if big else "<"
    v0, v1 = struct.unpack(o+"II", v)
    k0, k1, k2, k3 = struct.unpack(o+"IIII", k)
    s = 0; d = 0x9E3779B9
    for _ in range(rounds):
        v0 = (v0 + ((((v1 << 4) & M) ^ (v1 >> 5)) + v1) ^ (s + k[(s & 3)])) & M
        s = (s + d) & M
        v1 = (v1 + ((((v0 << 4) & M) ^ (v0 >> 5)) + v0) ^ (s + k[((s >> 11) & 3)])) & M
    return struct.pack(o+"II", v0, v1)

def des_enc(blk, key):
    from Crypto.Cipher import DES
    return DES.new(key, DES.MODE_ECB).encrypt(blk)

def bf_enc(blk, key):
    from Crypto.Cipher import Blowfish
    return Blowfish.new(key, Blowfish.MODE_ECB).encrypt(blk)

cands = []
for big in (False, True):
    cands.append(("TEA-%s" % ("BE" if big else "LE"), lambda b, k, big=big: tea_enc(b, k, 32, big)))
    cands.append(("XTEA-%s" % ("BE" if big else "LE"), lambda b, k, big=big: xtea_enc(b, k, 32, big)))
    cands.append(("TEA64r-%s" % ("BE" if big else "LE"), lambda b, k, big=big: tea_enc(b, k, 64, big)))
cands.append(("DES-K16[0:8]", lambda b, k: des_enc(b, k[:8])))
cands.append(("DES-K16[8:16]", lambda b, k: des_enc(b, k[8:])))
cands.append(("DES-rev(K16)[0:8]", lambda b, k: des_enc(b, k[::-1][:8])))
cands.append(("Blowfish-K16", lambda b, k: bf_enc(b, k)))

for name, fn in cands:
    hit = 0
    for x, c in pairs:
        try:
            if fn(x, K) == c:
                hit += 1
        except Exception:
            pass
    print("%-22s hits=%d/8" % (name, hit))
