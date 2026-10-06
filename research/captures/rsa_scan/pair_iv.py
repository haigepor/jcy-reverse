# -*- coding: utf-8 -*-
# 决定性实验: 已知明文对 (pair/plain_00N.bin <-> bodies_now.jsonl rec)
# 假设 H: 响应 P1 = AES-CBC(key=K16, iv=?, JSON), K16 来自响应 P0 (priv_from_go 可解)
# 反推: IV = AES_dec(K16, C0) XOR Plain[0:16]  → 若 16B 可打印 ASCII = 模型成立且 IV 可恢复
# 同时测 ECB: AES_dec(K16, C0) == Plain[0:16]
import json, base64, sys
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA

HERE = 'C:/Users/haige/Desktop/instruct/囧次元/research/captures/rsa_scan'
CUST = '5iW7S0GX6uf1cv3ny4q8es2Q+bdkYgKOIT/tzhAxUrFlVPmow9BHCZNMDpEaJRLj'
STD  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
TR = str.maketrans(CUST, STD)

def cb64(s):
    s = s.strip()
    if s.endswith('==') or s.endswith('='):
        pad = s; core = s
    else:
        core = s
        pad = s
    t = s.translate(TR)
    return base64.b64decode(t + '=' * (-len(t) % 4))

def sb64(s):
    return base64.b64decode(s + '=' * (-len(s) % 4))

priv = RSA.import_key(open(HERE + '/priv_from_go.pem', 'rb').read())
cp = PKCS1_v1_5.new(priv)

bodies = [json.loads(l) for l in open(HERE + '/bodies_now.jsonl', encoding='utf-8')]
manifest = json.load(open(HERE + '/pair/manifest.json', encoding='utf-8'))

def printable(b):
    return all(32 <= c < 127 for c in b)

for m in manifest:
    rec, pf = m['rec'], m['file']
    plain = open(HERE + '/pair/' + pf, 'rb').read()
    rb = bytes.fromhex(bodies[rec]['resp_body_hex'])
    try:
        txt = rb.decode('ascii', 'strict')
    except Exception as e:
        print(f'[{pf}] rec{rec}: resp body not ascii: {e}'); continue
    if '.' not in txt:
        print(f'[{pf}] rec{rec}: not P0.P1 form: {txt[:60]!r}'); continue
    p0s, p1s = txt.split('.', 1)
    p0 = cb64(p0s); p1 = cb64(p1s)
    k = cp.decrypt(p0, None)
    print(f'== {pf} rec{rec} {bodies[rec]["req"][:40]}  P0={len(p0)}B P1={len(p1)}B plain={len(plain)}B')
    if not k:
        print('   K16 unwrap FAILED'); continue
    print(f'   K16 = {k!r} ({len(k)}B)')
    if len(plain) < 16 or len(p1) < 16:
        print('   too short for block1 test'); continue
    C0 = p1[:16]; Pt = plain[:16]
    # key candidates
    kcs = {'K16': k, 'K16rev': k[::-1], 'K16x2?': (k + k)[:16] if len(k) < 16 else k[:16]}
    ivs_found = {}
    for kn, kk in kcs.items():
        if len(kk) != 16: continue
        try:
            d0 = AES.new(kk, AES.MODE_ECB).decrypt(C0)
        except Exception as e:
            print(f'   [{kn}] AES err {e}'); continue
        iv = bytes(a ^ b for a, b in zip(d0, Pt))
        tag = 'PRINTABLE' if printable(iv) else '-'
        print(f'   [{kn}] ECB C0->dec==Plain? {d0 == Pt}   CBC IV = {iv!r} {tag}')
        if printable(iv):
            ivs_found[kn] = iv
    # 用反推 IV 验证整段
    for kn, iv in ivs_found.items():
        try:
            dec = AES.new(k, AES.MODE_CBC, iv).decrypt(p1)
            cut = dec[:min(len(plain), len(dec))]
            print(f'   FULL-CBC [{kn}] iv={iv!r}: match={dec[:len(plain)] == plain}  head={dec[:48]!r}')
        except Exception as e:
            print(f'   FULL-CBC err {e}')
    print()
